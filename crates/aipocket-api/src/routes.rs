use crate::{
    auth::{Auth, verify},
    error::ApiError,
    settings::{SettingsUpdate, SettingsView, persist_env},
    state::AppState,
};
use aipocket_core::{Credential, ScanMode, ScanStatus};
use aipocket_db::mask_apikey;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{
        IntoResponse, Response, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use futures::{StreamExt, stream};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, path::PathBuf, time::Duration};
use tokio_stream::wrappers::BroadcastStream;
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/auth/login", post(crate::auth::login))
        .route("/api/auth/logout", post(crate::auth::logout))
        .route("/api/runs", get(runs))
        .route("/api/runs/{id}/{kind}", get(run_results))
        .route("/api/runs/{id}/log", get(run_log))
        .route("/api/runs/{id}", axum::routing::delete(delete_run))
        .route("/api/runs/{id}/gpt-failed", get(gpt_failed))
        .route("/api/runs/{id}/retry-gpt-failed", post(retry_gpt_failed))
        .route("/api/high-value", get(high_value))
        .route("/api/high-value/reveal", post(high_value_reveal))
        .route("/api/keys/{kind}", get(all_keys))
        .route("/api/keys/status", post(transition_keys))
        .route("/api/key/models", post(key_models))
        .route("/api/key/balance", post(key_balance))
        .route("/api/keys/balance", post(keys_balance))
        .route("/api/key/chat", post(key_chat))
        .route("/api/key/reveal", post(key_reveal))
        .route("/api/export", post(export))
        .route("/api/cve", get(cves))
        .route("/api/cve/sync", post(cve_sync))
        .route("/api/cve/add", post(cve_add))
        .route(
            "/api/honeypot",
            get(honeypots)
                .post(create_honeypot)
                .patch(update_honeypot)
                .delete(delete_honeypot),
        )
        .route("/api/honeypot/bulk-delete", post(bulk_delete_honeypots))
        .route(
            "/api/manual-targets",
            get(manual_targets)
                .post(save_manual_targets)
                .delete(delete_manual_target),
        )
        .route(
            "/api/manual-targets/bulk-delete",
            post(bulk_delete_manual_targets),
        )
        .route("/api/settings", get(get_settings).put(update_settings))
        .route("/api/settings/check/fofa", post(check_fofa))
        .route("/api/settings/check/shodan", post(check_shodan))
        .route("/api/settings/check/github", post(check_github))
        .route("/api/scan/start", post(scan_start))
        .route("/api/scan/stop", post(scan_stop))
        .route("/api/scan/status", get(scan_status))
        .route("/api/scan/logs", get(scan_logs))
        .route("/api/scan/logs/stream", get(scan_stream))
        .route("/api/system/restart", post(system_restart))
}
#[derive(Deserialize)]
struct TransitionRequest {
    result_ids: Vec<i64>,
    status: String,
    #[serde(default)]
    note: String,
}
async fn transition_keys(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<TransitionRequest>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(b.status.as_str(), "valid" | "suspicious" | "unavailable") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "status must be valid, suspicious, or unavailable",
        ));
    }
    let (transitioned, skipped) = s
        .repository
        .transition_results(&b.result_ids, &b.status, &b.note)
        .await?;
    Ok(Json(json!({"transitioned":transitioned,"skipped":skipped})))
}

async fn delete_run(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    // Refuse to delete the run a scan is actively writing to: removing the row
    // cascades into its child tables while the task keeps INSERTing, corrupting
    // the run and leaving the UI stuck on a phantom run.
    let status = s.scan_manager.status().await;
    if matches!(
        status.state,
        aipocket_core::ScanState::Running | aipocket_core::ScanState::Stopping
    ) && status.run_id.as_deref() == Some(id.as_str())
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "cannot delete the run of an active scan; stop it first",
        ));
    }
    let deleted = s.repository.delete_run(&id).await?;
    let disk = s.settings.read().await.results_path().join(&id);
    let disk_removed = if disk.exists() {
        std::fs::remove_dir_all(disk).is_ok()
    } else {
        false
    };
    Ok(Json(
        json!({"run_id":id,"deleted":deleted,"disk_removed":disk_removed}),
    ))
}
async fn gpt_failed(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_run_id(&id)?;
    let root = s.settings.read().await.results_path();
    let files = inspect_failed_files(&root, &id);
    let failed_hits = files
        .iter()
        .filter_map(|file| file.get("hits").and_then(Value::as_u64))
        .sum::<u64>();
    let retry = s.retry_manager.0.lock().await.clone();
    let retry = if retry
        .get("run_id")
        .and_then(Value::as_str)
        .is_none_or(|run| run == id)
    {
        retry
    } else {
        idle_retry()
    };
    Ok(Json(
        json!({"run_id":id,"failed_files":files.len(),"failed_hits":failed_hits,"files":files,"retry":retry}),
    ))
}
async fn retry_gpt_failed(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_run_id(&id)?;
    if matches!(
        s.scan_manager.status().await.state,
        aipocket_core::ScanState::Running | aipocket_core::ScanState::Stopping
    ) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "cannot retry while a scan is running",
        ));
    }
    let run_dir = s.settings.read().await.results_path().join(&id);
    if !run_dir.is_dir() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "run directory not found",
        ));
    }
    if inspect_failed_files(&s.settings.read().await.results_path(), &id).is_empty() {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "no gpt_failed_batch_*.jsonl files to retry",
        ));
    }
    let mut status = s.retry_manager.0.lock().await;
    if status.get("state").and_then(Value::as_str) == Some("running") {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "a GPT-failed retry is already running",
        ));
    }
    let started = chrono::Utc::now().to_rfc3339();
    *status = json!({"state":"running","run_id":id,"started_at":started,"finished_at":null,"error":null,"report":null});
    let response = status.clone();
    drop(status);
    let manager = s.retry_manager.clone();
    let analyzer = aipocket_services::Analyzer::new(
        std::sync::Arc::new(s.settings.read().await.clone()),
        s.http.clone(),
    );
    let repository = s.repository.clone();
    tokio::spawn(async move {
        let outcome = analyzer.retry_failed(&id, &run_dir, &repository).await;
        let mut status = manager.0.lock().await;
        let finished = chrono::Utc::now().to_rfc3339();
        *status = match outcome {
            Ok(report) => {
                json!({"state":"finished","run_id":id,"started_at":started,"finished_at":finished,"error":null,"report":report})
            }
            Err(error) => {
                json!({"state":"error","run_id":id,"started_at":started,"finished_at":finished,"error":error.to_string(),"report":null})
            }
        };
    });
    Ok(Json(response))
}
fn idle_retry() -> Value {
    json!({"state":"idle","run_id":null,"started_at":null,"finished_at":null,"error":null,"report":null})
}

fn validate_run_id(run_id: &str) -> Result<(), ApiError> {
    let valid = regex::Regex::new(r"^run_\d{4}_\d{2}_\d{2}_\d{2}-\d{2}-\d{2}$")
        .expect("run id regex")
        .is_match(run_id);
    if valid {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid run id",
        ))
    }
}

fn inspect_failed_files(root: &std::path::Path, run_id: &str) -> Vec<Value> {
    let dir = root.join(run_id);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return vec![];
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_str()?;
            if !(name.starts_with("gpt_failed") || name.starts_with("failed_batch")) {
                return None;
            }
            let (hits, batch_idx) = parse_failed_batch(&path);
            Some(json!({"name":name,"hits":hits,"batch_idx":batch_idx}))
        })
        .collect()
}
fn parse_failed_batch(path: &std::path::Path) -> (usize, Option<i64>) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (0, None);
    };
    let mut count = 0;
    let mut batch_idx = None;
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if index == 0 && value.get("batch_idx").is_some() {
            batch_idx = value.get("batch_idx").and_then(Value::as_i64);
        } else if let Some(rows) = value.as_array() {
            count += rows.len();
        } else if value.is_object() {
            count += 1;
        }
    }
    (count, batch_idx)
}

async fn cve_sync(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let queries = [
        "latest AI infrastructure security CVE GHSA Dify LiteLLM Flowise Langflow Open WebUI",
        "latest AI gateway agent framework CVE GHSA MLflow vLLM OpenRouter FastGPT",
    ];
    let mut added = 0;
    let mut discovered = 0;
    for query in queries {
        let value = s.tavily().await.search(query).await?;
        for item in value
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for record in cve_records_from_search_item(item) {
                discovered += 1;
                if s.repository.upsert_cve(&record).await? {
                    added += 1;
                }
            }
        }
    }
    Ok(Json(json!({
        "total": s.repository.cves().await?.len(),
        "discovered": discovered,
        "added": added,
    })))
}

fn cve_records_from_search_item(item: &Value) -> Vec<Value> {
    static ADVISORY_ID: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?i)\b(?:CVE-\d{4}-\d{4,7}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})\b")
            .expect("advisory id regex")
    });
    let text = ["id", "cve_id", "advisory_id", "title", "content", "url"]
        .into_iter()
        .filter_map(|key| item.get(key).and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");
    let mut seen = std::collections::BTreeSet::new();
    ADVISORY_ID
        .find_iter(&text)
        .filter_map(|found| {
            let id = found.as_str().to_ascii_uppercase();
            if !seen.insert(id.clone()) {
                return None;
            }
            Some(json!({
                "id": id,
                "title": item.get("title"),
                "description": item.get("content"),
                "source_url": item.get("url"),
                "source": "tavily",
                "synced_at": chrono::Utc::now().to_rfc3339(),
            }))
        })
        .collect()
}
#[derive(Deserialize)]
struct CveAdd {
    url: Option<String>,
    id: Option<String>,
    product: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    description: Option<String>,
    cvss: Option<f64>,
    huntable: Option<String>,
}
async fn cve_add(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<CveAdd>,
) -> Result<Json<Value>, ApiError> {
    let id =
        b.id.or_else(|| {
            b.url.as_ref().and_then(|v| {
                regex::Regex::new(r"(?i)CVE-\d{4}-\d{4,7}")
                    .ok()?
                    .find(v)
                    .map(|m| m.as_str().to_uppercase())
            })
        })
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "bad_request", "CVE id required"))?;
    let record = json!({"id":id,"url":b.url,"product":b.product,"type":b.kind,"description":b.description,"cvss":b.cvss,"huntable":b.huntable});
    let created = s.repository.upsert_cve(&record).await?;
    Ok(Json(
        json!({"created":created,"total":s.repository.cves().await?.len(),"cve":record}),
    ))
}
async fn health() -> Json<Value> {
    Json(json!({"ok":true}))
}
async fn runs(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({"days":s.repository.list_runs().await?})))
}
async fn run_results(
    _: Auth,
    State(s): State<AppState>,
    Path((id, kind)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if !matches!(kind.as_str(), "valid" | "suspicious") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "invalid result kind",
        ));
    }
    Ok(Json(
        json!({"run_id":id,"results":s.repository.run_records(&id,&kind,true).await?}),
    ))
}
async fn run_log(
    _: Auth,
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let status = s.scan_manager.status().await;
    if status.run_id.as_deref() == Some(id.as_str()) {
        let live = s.scan_manager.log_text().await;
        if !live.is_empty() {
            return Ok(
                ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], live).into_response(),
            );
        }
    }
    let log = s
        .repository
        .run_log(&id)
        .await?
        .or_else(|| {
            std::fs::read_to_string(
                s.settings
                    .blocking_read()
                    .results_path()
                    .join(&id)
                    .join("run.log"),
            )
            .ok()
        })
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "no log for run"))?;
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], log).into_response())
}
async fn high_value(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({"results":s.repository.high_value(true).await?}),
    ))
}
#[derive(Deserialize)]
struct HighReveal {
    masked: String,
    apiurl: Option<String>,
}
async fn high_value_reveal(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HighReveal>,
) -> Result<Json<Value>, ApiError> {
    for row in s.repository.high_value(false).await? {
        let key = row
            .get("apikey")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/credential/apikey").and_then(Value::as_str))
            .unwrap_or_default();
        let url = row
            .get("apiurl")
            .and_then(Value::as_str)
            .or_else(|| row.pointer("/credential/apiurl").and_then(Value::as_str))
            .unwrap_or_default();
        if mask_apikey(key) == b.masked && b.apiurl.as_deref().is_none_or(|v| v == url) {
            return Ok(Json(json!({"apikey":key,"apiurl":url})));
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "key not found",
    ))
}
async fn all_keys(
    _: Auth,
    State(s): State<AppState>,
    Path(kind): Path<String>,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(
        json!({"kind":kind,"results":s.repository.all_records(&kind,true).await?}),
    ))
}
#[derive(Deserialize)]
struct KeyRef {
    apikey: String,
    #[serde(default)]
    apiurl: String,
    result_id: Option<i64>,
    #[serde(default)]
    high_value: bool,
}
async fn key_models(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<KeyRef>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    let probe = s
        .balance
        .probe_models(Credential {
            apikey: b.apikey,
            apiurl: b.apiurl,
            ..Default::default()
        })
        .await?;
    let expired = if probe.is_definitive_auth_rejection() {
        if let Some(result_id) = b.result_id {
            s.repository
                .mark_result_expired(
                    result_id,
                    &probe.provider,
                    probe.status_code.unwrap_or_default(),
                )
                .await?
        } else {
            false
        }
    } else {
        false
    };
    Ok(Json(json!({
        "models":probe.models,
        "status_code":probe.status_code,
        "provider":probe.provider,
        "key_state":probe.key_state,
        "error":probe.error,
        "expired":expired,
        "high_value_removed":b.high_value && expired
    })))
}
#[derive(Deserialize)]
struct BalanceRequest {
    apikey: String,
    #[serde(default)]
    apiurl: String,
    result_id: Option<i64>,
    #[serde(default)]
    high_value: bool,
}
fn definitive_expiry(probe: &aipocket_services::BalanceResult) -> Option<u16> {
    if probe.alive != Some(false) || probe.provider != "deepseek" {
        return None;
    }
    probe
        .detail
        .get("status_code")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|status| matches!(status, 401 | 403))
}

async fn probe_and_persist_balance(
    s: &AppState,
    credential: Credential,
    result_id: Option<i64>,
    high_value: bool,
) -> Result<Value, ApiError> {
    let r = s.balance.query(&credential).await?;
    let evidence = serde_json::to_value(&r).map_err(ApiError::internal)?;
    if let Some(status_code) = definitive_expiry(&r) {
        let expired = if let Some(result_id) = result_id {
            s.repository
                .mark_result_expired(result_id, &r.provider, status_code)
                .await?
        } else {
            false
        };
        return Ok(json!({
            "gateway":r.gateway,
            "balance_usd":"",
            "tier":"",
            "detail":evidence,
            "persisted":false,
            "result_id":result_id,
            "high_value_updated":false,
            "key_state":"expired",
            "expired":expired,
            "high_value_removed":high_value && expired
        }));
    }
    if !r.matched {
        return Ok(json!({
            "gateway":"unsupported",
            "balance_usd":"",
            "tier":"",
            "detail":evidence,
            "persisted":false,
            "result_id":result_id,
            "high_value_updated":false
        }));
    }
    let mut result = aipocket_core::ValidationResult {
        credential: credential.clone(),
        ..Default::default()
    };
    aipocket_services::apply_probe_result(&mut result, r.clone());
    let balance_display = result.balance;
    let (persisted, high_value_updated) = if result_id.is_some() || high_value {
        s.repository
            .persist_balance(aipocket_db::BalancePersistence {
                result_id,
                apikey: &credential.apikey,
                gateway: &r.gateway,
                balance: &balance_display,
                tier: &r.tier,
                detail: &evidence,
                high_value,
            })
            .await?
    } else {
        (false, false)
    };
    Ok(
        json!({"gateway":r.gateway,"balance_usd":balance_display,"tier":r.tier,"detail":evidence,"persisted":persisted,"result_id":result_id,"high_value_updated":high_value_updated}),
    )
}

async fn key_balance(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<BalanceRequest>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    Ok(Json(
        probe_and_persist_balance(
            &s,
            Credential {
                apikey: b.apikey,
                apiurl: b.apiurl,
                ..Default::default()
            },
            b.result_id,
            b.high_value,
        )
        .await?,
    ))
}

fn normalized_batch_provider(row: &Value) -> String {
    row.pointer("/provider_info/provider")
        .and_then(Value::as_str)
        .or_else(|| row.get("provider").and_then(Value::as_str))
        .unwrap_or("unknown")
        .trim()
        .to_ascii_lowercase()
}

const MAX_BATCH_BALANCE_KEYS: usize = 50;

#[derive(Deserialize)]
struct BatchBalanceRequest {
    result_ids: Vec<i64>,
    provider: String,
}

async fn keys_balance(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<BatchBalanceRequest>,
) -> Result<Json<Value>, ApiError> {
    if b.provider.trim().is_empty() || b.provider.trim().eq_ignore_ascii_case("all") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "select one provider before batch balance testing",
        ));
    }
    if b.result_ids.is_empty() || b.result_ids.len() > MAX_BATCH_BALANCE_KEYS {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            format!("result_ids must contain 1..={MAX_BATCH_BALANCE_KEYS} records"),
        ));
    }
    let mut unique_ids = std::collections::HashSet::with_capacity(b.result_ids.len());
    if !b.result_ids.iter().all(|id| unique_ids.insert(*id)) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "result_ids must be unique",
        ));
    }
    let rows = s.repository.records_by_ids(&b.result_ids).await?;
    let missing = b.result_ids.len().saturating_sub(rows.len());
    let requested_provider = b.provider.trim().to_ascii_lowercase();
    let concurrency = s
        .settings
        .read()
        .await
        .balance_batch_concurrency
        .clamp(1, MAX_BATCH_BALANCE_KEYS);
    let mut tasks = stream::iter(rows.into_iter().enumerate().map(|(position, row)| {
        let state = s.clone();
        let requested_provider = requested_provider.clone();
        async move {
            let result_id = row
                .get("result_id")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let provider = normalized_batch_provider(&row);
            let result = if provider != requested_provider {
                json!({"result_id":result_id,"ok":false,"error":"provider mismatch"})
            } else {
                let credential = row
                    .get("credential")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<Credential>(value).ok());
                let Some(credential) = credential.filter(|value| !value.apikey.is_empty()) else {
                    return (
                        position,
                        json!({"result_id":result_id,"ok":false,"error":"credential missing"}),
                    );
                };
                match probe_and_persist_balance(&state, credential, Some(result_id), false).await {
                    Ok(value) if value["key_state"] == "expired" => json!({
                        "result_id":result_id,
                        "ok":false,
                        "error":"credential expired or revoked"
                    }),
                    Ok(value) => json!({"result_id":result_id,"ok":true,"balance":value}),
                    Err(error) => json!({"result_id":result_id,"ok":false,"error":error.message}),
                }
            };
            (position, result)
        }
    }))
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;
    tasks.sort_unstable_by_key(|(position, _)| *position);
    let tasks = tasks
        .into_iter()
        .map(|(_, result)| result)
        .collect::<Vec<_>>();
    let succeeded = tasks.iter().filter(|item| item["ok"] == true).count();
    let failed = tasks.len().saturating_sub(succeeded) + missing;
    Ok(Json(json!({
        "requested":b.result_ids.len(),
        "succeeded":succeeded,
        "failed":failed,
        "results":tasks
    })))
}
#[derive(Deserialize)]
struct ChatRequest {
    apikey: String,
    #[serde(default)]
    apiurl: String,
    model: String,
}
async fn key_chat(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ChatRequest>,
) -> Result<Json<Value>, ApiError> {
    if b.apikey.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "apikey required",
        ));
    }
    if b.model.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "model required (pick one from /api/key/models first)",
        ));
    }
    let result = s
        .balance
        .test_chat(
            Credential {
                apikey: b.apikey,
                apiurl: b.apiurl,
                ..Default::default()
            },
            &b.model,
        )
        .await?;
    Ok(Json(json!({
        "success":result.success,
        "status_code":result.status_code,
        "model":result.model,
        "snippet":result.snippet,
        "error":result.error,
        "consumes_credit":true
    })))
}
#[derive(Deserialize)]
struct RevealRequest {
    run_id: String,
    #[serde(default = "valid_kind")]
    kind: String,
    masked: Option<String>,
    apiurl: Option<String>,
    index: Option<usize>,
}
fn valid_kind() -> String {
    "valid".into()
}
async fn key_reveal(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<RevealRequest>,
) -> Result<Json<Value>, ApiError> {
    let rows = s.repository.run_records(&b.run_id, &b.kind, false).await?;
    for (i, row) in rows.into_iter().enumerate() {
        let key = row
            .pointer("/credential/apikey")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let url = row
            .pointer("/credential/apiurl")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if b.index == Some(i)
            || (b.index.is_none()
                && b.masked.as_deref() == Some(&mask_apikey(key))
                && b.apiurl.as_deref().is_none_or(|v| v == url))
        {
            return Ok(Json(json!({"apikey":key,"apiurl":url})));
        }
    }
    Err(ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "key not found",
    ))
}
#[derive(Deserialize)]
struct ExportRequest {
    dataset: String,
    #[serde(default = "json_format")]
    format: String,
    run_id: Option<String>,
    #[serde(default = "valid_kind")]
    kind: String,
    #[serde(default)]
    keys: Vec<KeyRef>,
    #[serde(default)]
    indices: Vec<usize>,
}
fn json_format() -> String {
    "json".into()
}
async fn export(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ExportRequest>,
) -> Result<Response, ApiError> {
    let rows = match b.dataset.as_str() {
        "selected" if b.run_id.is_some() && !b.indices.is_empty() => {
            let all = s
                .repository
                .run_records(b.run_id.as_deref().unwrap_or_default(), &b.kind, false)
                .await?;
            b.indices
                .into_iter()
                .filter_map(|index| all.get(index).cloned())
                .collect()
        }
        "selected" if !b.keys.is_empty() => b
            .keys
            .into_iter()
            .map(|k| json!({"apikey":k.apikey,"apiurl":k.apiurl}))
            .collect(),
        "selected" => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "selected export requires run_id+indices or keys",
            ));
        }
        "run" if b.run_id.is_none() => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "run export requires run_id",
            ));
        }
        "run" => {
            s.repository
                .run_records(b.run_id.as_deref().unwrap_or_default(), &b.kind, false)
                .await?
        }
        "high-value" => s.repository.high_value(false).await?,
        "all" => {
            let all = s.repository.all_records(&b.kind, false).await?;
            if b.indices.is_empty() {
                all
            } else {
                b.indices
                    .into_iter()
                    .filter_map(|index| all.get(index).cloned())
                    .collect()
            }
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "unknown dataset",
            ));
        }
    };
    let (content, media, ext) = match b.format.as_str() {
        "csv" => {
            let mut w = csv::Writer::from_writer(vec![]);
            w.write_record([
                "apikey", "apiurl", "provider", "valid", "tier", "balance", "gateway",
            ])
            .map_err(ApiError::internal)?;
            for row in &rows {
                let (key, url) = export_key_url(row);
                w.write_record([
                    key,
                    url,
                    export_provider(row),
                    &row.get("valid")
                        .and_then(Value::as_bool)
                        .unwrap_or_default()
                        .to_string(),
                    row.get("tier").and_then(Value::as_str).unwrap_or_default(),
                    row.get("balance")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    row.get("gateway")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ])
                .map_err(ApiError::internal)?;
            }
            (
                w.into_inner().map_err(ApiError::internal)?,
                "text/csv",
                "csv",
            )
        }
        "sub2api" => (
            serde_json::to_vec_pretty(&sub2api_payload(&rows)).map_err(ApiError::internal)?,
            "application/json",
            "sub2api.json",
        ),
        "json" => (
            serde_json::to_vec_pretty(&rows).map_err(ApiError::internal)?,
            "application/json",
            "json",
        ),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_request",
                "format must be json, csv, or sub2api",
            ));
        }
    };
    Ok((
        [
            (header::CONTENT_TYPE, media),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"aipocket-export.{ext}\""),
            ),
        ],
        content,
    )
        .into_response())
}
fn export_key_url(row: &Value) -> (&str, &str) {
    let key = row
        .get("apikey")
        .and_then(Value::as_str)
        .or_else(|| row.pointer("/credential/apikey").and_then(Value::as_str))
        .unwrap_or_default();
    let url = row
        .get("apiurl")
        .and_then(Value::as_str)
        .or_else(|| row.pointer("/credential/apiurl").and_then(Value::as_str))
        .unwrap_or_default();
    (key, url)
}

fn export_provider(row: &Value) -> &str {
    row.pointer("/provider_info/provider")
        .and_then(Value::as_str)
        .or_else(|| row.get("provider").and_then(Value::as_str))
        .unwrap_or("openai")
}

fn sub2api_payload(rows: &[Value]) -> Value {
    let accounts = rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let (key, url) = export_key_url(row);
            if key.is_empty() {
                return None;
            }
            let provider = export_provider(row).to_ascii_lowercase();
            let platform = match provider.as_str() {
                "anthropic" => "anthropic",
                "gemini" | "google" | "vertex" => "gemini",
                "xai" | "grok" => "grok",
                _ => "openai",
            };
            let mut credentials = serde_json::Map::new();
            credentials.insert("api_key".into(), Value::String(key.into()));
            if !url.is_empty() {
                credentials.insert(
                    "base_url".into(),
                    Value::String(url.trim_end_matches('/').trim_end_matches("/v1").into()),
                );
            }
            Some(json!({
                "name": format!("AIPocket {} {}", platform, index + 1),
                "platform": platform,
                "type": "apikey",
                "credentials": credentials,
                "concurrency": 3,
                "priority": 50,
                "rate_multiplier": 1.0
            }))
        })
        .collect::<Vec<_>>();
    json!({
        "type": "sub2api-data",
        "version": 1,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "proxies": [],
        "accounts": accounts
    })
}

async fn cves(_: Auth, State(s): State<AppState>) -> Result<Json<Value>, ApiError> {
    let cves = s.repository.cves().await?;
    Ok(Json(json!({"cves":cves,"advisories":cves})))
}
#[derive(Default, Deserialize)]
struct PageQuery {
    #[serde(default)]
    q: String,
    source: Option<String>,
    enabled_only: Option<bool>,
    limit: Option<i64>,
    offset: Option<i64>,
}
async fn honeypots(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let (rows, total) = s
        .repository
        .list_honeypots(&q.q, q.source.as_deref(), limit, offset)
        .await?;
    Ok(Json(
        json!({"results":rows,"total":total,"limit":limit,"offset":offset}),
    ))
}
async fn manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let (rows, total) = s
        .repository
        .list_manual_targets(q.enabled_only.unwrap_or(false), limit, offset)
        .await?;
    Ok(Json(
        json!({"results":rows,"total":total,"limit":limit,"offset":offset}),
    ))
}
#[derive(Deserialize)]
struct HoneypotCreate {
    host: String,
    #[serde(default = "manual_reason")]
    reason: String,
    #[serde(default)]
    notes: String,
}
fn manual_reason() -> String {
    "honeypot:manual".into()
}
#[derive(Deserialize)]
struct HoneypotUpdate {
    host_key: String,
    reason: Option<String>,
    notes: Option<String>,
}
#[derive(Deserialize)]
struct HoneypotDeleteQuery {
    host_key: String,
}
#[derive(Deserialize)]
struct HoneypotBulkDelete {
    #[serde(default)]
    host_keys: Vec<String>,
}
async fn create_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotCreate>,
) -> Result<Json<Value>, ApiError> {
    let origin =
        aipocket_core::url_sanitize::sanitize_origin(&b.host).map_err(ApiError::internal)?;
    let key = aipocket_core::url_sanitize::host_key(&origin).map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::to_value(
            s.repository
                .create_honeypot(&origin, &key, &b.reason, &b.notes)
                .await?,
        )
        .map_err(ApiError::internal)?,
    ))
}
async fn update_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotUpdate>,
) -> Result<Json<Value>, ApiError> {
    let row = s
        .repository
        .update_honeypot(&b.host_key, b.reason.as_deref(), b.notes.as_deref())
        .await?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "not_found", "honeypot not found"))?;
    Ok(Json(serde_json::to_value(row).map_err(ApiError::internal)?))
}
async fn delete_honeypot(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<HoneypotDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    s.repository
        .delete_honeypots(std::slice::from_ref(&q.host_key))
        .await?;
    Ok(Json(json!({"ok":true,"host_key":q.host_key})))
}
async fn bulk_delete_honeypots(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<HoneypotBulkDelete>,
) -> Result<Json<Value>, ApiError> {
    let deleted = s.repository.delete_honeypots(&b.host_keys).await?;
    Ok(Json(json!({"deleted":deleted})))
}
#[derive(Deserialize)]
struct ManualTargetsSave {
    urls: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    replace: bool,
}
#[derive(Deserialize)]
struct ManualTargetDeleteQuery {
    url: String,
}
#[derive(Deserialize)]
struct ManualTargetsDelete {
    #[serde(default)]
    urls: Vec<String>,
}
async fn save_manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ManualTargetsSave>,
) -> Result<Json<Value>, ApiError> {
    if b.replace {
        let (existing, _) = s.repository.list_manual_targets(false, 10_000, 0).await?;
        let urls: Vec<_> = existing.into_iter().map(|target| target.url).collect();
        s.repository.delete_manual_targets(&urls).await?;
    }
    let mut targets = Vec::new();
    let mut rejected = Vec::new();
    for raw in b
        .urls
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        match aipocket_core::url_sanitize::sanitize_origin(raw) {
            Ok(origin) => {
                let parsed = url::Url::parse(&origin).map_err(ApiError::internal)?;
                let target = aipocket_core::ManualTarget {
                    url: origin.clone(),
                    host_key: aipocket_core::url_sanitize::host_key(&origin)
                        .map_err(ApiError::internal)?,
                    scheme: parsed.scheme().into(),
                    hostname: parsed.host_str().unwrap_or_default().into(),
                    port: parsed.port_or_known_default().unwrap_or(443),
                    enabled: true,
                    notes: b.notes.clone(),
                    ..Default::default()
                };
                targets.push(s.repository.upsert_manual_target(&target).await?);
            }
            Err(_) => rejected.push(raw.to_owned()),
        }
    }
    Ok(Json(
        json!({"added":targets.len(),"updated":0,"rejected":rejected,"targets":targets}),
    ))
}
async fn delete_manual_target(
    _: Auth,
    State(s): State<AppState>,
    Query(q): Query<ManualTargetDeleteQuery>,
) -> Result<Json<Value>, ApiError> {
    let url = aipocket_core::url_sanitize::sanitize_origin(&q.url).map_err(ApiError::internal)?;
    let deleted = s.repository.delete_manual_targets(&[url]).await?;
    Ok(Json(json!({"deleted":deleted})))
}
async fn bulk_delete_manual_targets(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ManualTargetsDelete>,
) -> Result<Json<Value>, ApiError> {
    let urls: Vec<_> = b
        .urls
        .iter()
        .filter_map(|url| aipocket_core::url_sanitize::sanitize_origin(url).ok())
        .collect();
    let deleted = s.repository.delete_manual_targets(&urls).await?;
    Ok(Json(json!({"deleted":deleted})))
}
async fn get_settings(_: Auth, State(s): State<AppState>) -> Json<SettingsView> {
    let settings = s.settings.read().await;
    Json(SettingsView::from_settings(&settings))
}
async fn update_settings(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<SettingsUpdate>,
) -> Result<Json<Value>, ApiError> {
    let updates = b.env_updates();
    persist_env(&PathBuf::from(".env"), &updates).map_err(ApiError::internal)?;
    let new = aipocket_core::Settings::load().map_err(ApiError::internal)?;
    *s.settings.write().await = new;
    let settings = s.settings.read().await;
    Ok(Json(
        json!({"updated":updates.keys().collect::<Vec<_>>(),"hot_reloaded":updates.keys().collect::<Vec<_>>(),"restart_required":[],"settings":SettingsView::from_settings(&settings)}),
    ))
}
async fn check_fofa(_: Auth, State(s): State<AppState>) -> Json<Value> {
    match s.fofa().await.check().await {
        Ok(_) => Json(json!({"status":"ok","message":"reachable","consumes_quota":true})),
        Err(e) => Json(json!({"status":"invalid","message":e.to_string(),"consumes_quota":true})),
    }
}
async fn check_shodan(_: Auth, State(s): State<AppState>) -> Json<Value> {
    let results = s.shodan().await.info_all().await;
    let keys:Vec<_>=results.iter().map(|(key,r)|match r{Ok(info)=>json!({"key_masked":mask_apikey(key),"plan":info.plan,"query_credits":info.query_credits,"alive":true}),Err(_)=>json!({"key_masked":mask_apikey(key),"plan":"","query_credits":0,"alive":false})}).collect();
    let total = keys
        .iter()
        .filter_map(|v| v.get("query_credits").and_then(Value::as_i64))
        .sum::<i64>();
    let dead = keys
        .iter()
        .filter(|v| v.get("alive") == Some(&Value::Bool(false)))
        .count();
    Json(
        json!({"keys":keys,"total_query_credits":total,"n_keys":results.len(),"n_dead":dead,"consumes_quota":false}),
    )
}
async fn check_github(_: Auth, State(s): State<AppState>) -> Json<Value> {
    let n = s.settings.read().await.github_token_list().len();
    if n == 0 {
        return Json(
            json!({"status":"disabled","message":"no tokens","core_remaining":null,"search_remaining":null,"code_search_remaining":null,"n_tokens":0}),
        );
    }
    match s.github().await.rate_limit().await {
        Ok(v) => Json(
            json!({"status":"ok","message":"reachable","core_remaining":v.pointer("/resources/core/remaining"),"search_remaining":v.pointer("/resources/search/remaining"),"code_search_remaining":v.pointer("/resources/code_search/remaining"),"n_tokens":n}),
        ),
        Err(e) => {
            let detail = e.to_string();

            let message = if detail.contains("Bad credentials") {
                format!("GitHub token 无效或已撤销。{detail}")
            } else if detail.contains("rate limit") || detail.contains("remaining=0") {
                format!("GitHub token 有效但额度已耗尽或触发限流。{detail}")
            } else if detail.contains("403") {
                format!(
                    "GitHub 拒绝了全部 token；可能是权限不足、账号风控或 token 已失效。{detail}"
                )
            } else {
                detail
            };
            Json(
                json!({"status":"invalid","message":message,"core_remaining":null,"search_remaining":null,"code_search_remaining":null,"n_tokens":n}),
            )
        }
    }
}
#[derive(Deserialize)]
struct ScanStart {
    #[serde(default = "all_source")]
    source: String,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    mode: ScanMode,
    #[serde(default)]
    github_pack_ids: Vec<String>,
    #[serde(default)]
    manual_enrich: Vec<String>,
    #[serde(default)]
    resume_run_id: String,
}
fn all_source() -> String {
    "all".into()
}
fn discovery_queries(
    selected_packs: &[&aipocket_discovery::packs::ProviderPack],
) -> (Vec<String>, Vec<String>) {
    let mut fofa = aipocket_discovery::legacy_queries::fofa_queries();
    fofa.extend(
        selected_packs
            .iter()
            .flat_map(|pack| pack.fofa_queries)
            .map(|query| query.to_string()),
    );
    let mut shodan = selected_packs
        .iter()
        .flat_map(|pack| pack.shodan_queries)
        .map(|query| query.to_string())
        .collect::<Vec<_>>();
    shodan.extend(aipocket_discovery::legacy_queries::shodan_product_queries());
    fofa.sort();
    fofa.dedup();
    shodan.sort();
    shodan.dedup();
    (fofa, shodan)
}

#[cfg(test)]
mod key_probe_tests {
    use super::*;

    #[test]
    fn only_definitive_deepseek_auth_rejection_expires_a_key() {
        let probe = |provider: &str, status_code: u16, alive| aipocket_services::BalanceResult {
            provider: provider.into(),
            alive,
            detail: json!({"status_code":status_code}),
            ..Default::default()
        };
        assert_eq!(
            definitive_expiry(&probe("deepseek", 401, Some(false))),
            Some(401)
        );
        assert_eq!(
            definitive_expiry(&probe("deepseek", 403, Some(false))),
            Some(403)
        );
        assert_eq!(
            definitive_expiry(&probe("deepseek", 429, Some(false))),
            None
        );
        assert_eq!(definitive_expiry(&probe("deepseek", 401, Some(true))), None);
        assert_eq!(definitive_expiry(&probe("openai", 401, Some(false))), None);
    }
}

#[cfg(test)]
mod scan_query_tests {
    use super::*;

    #[test]
    fn web_full_scan_includes_legacy_product_queries() {
        let registry = aipocket_discovery::packs::registry();
        let selected = registry.values().copied().collect::<Vec<_>>();
        let (fofa, shodan) = discovery_queries(&selected);
        assert!(fofa.len() > 60);
        assert!(fofa.iter().any(|query| query.contains("litellm_proxy")));
        assert!(fofa.iter().any(|query| query.contains("dify")));
        assert!(shodan.iter().any(|query| query == "http.html:sk-"));
        assert!(shodan.iter().any(|query| query.contains("litellm_proxy")));
    }

    #[test]
    fn cve_search_items_are_normalized_before_persistence() {
        let rows = cve_records_from_search_item(&json!({
            "title":"Dify CVE-2026-12345 and GHSA-2345-6789-cfgh",
            "content":"CVE-2026-12345",
            "url":"https://example.test/advisory"
        }));
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "CVE-2026-12345");
        assert_eq!(rows[1]["id"], "GHSA-2345-6789-CFGH");
    }

    #[test]
    fn batch_provider_normalization_is_strict_and_case_insensitive() {
        assert_eq!(
            normalized_batch_provider(&json!({"provider_info":{"provider":" OpenAI "}})),
            "openai"
        );
        assert_eq!(
            normalized_batch_provider(&json!({"provider":"ANTHROPIC"})),
            "anthropic"
        );
        assert_eq!(normalized_batch_provider(&json!({})), "unknown");
        assert_eq!(MAX_BATCH_BALANCE_KEYS, 50);
    }
}
async fn scan_start(
    _: Auth,
    State(s): State<AppState>,
    Json(b): Json<ScanStart>,
) -> Result<Json<ScanStatus>, ApiError> {
    if !b.resume_run_id.is_empty() {
        let Some((state, phase)) = s.repository.resumable_run(&b.resume_run_id).await? else {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "resume run not found",
            ));
        };
        if state == "finished" || phase == "finished" {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "conflict",
                "run already finished",
            ));
        }
    }
    let sources = if b.sources.is_empty() {
        vec![b.source.clone()]
    } else {
        b.sources.clone()
    };
    let (cancel, tx, rx, stopped) = s
        .scan_manager
        .start_channel(sources.join(","), b.mode.clone())
        .await
        .map_err(|_| ApiError::new(StatusCode::CONFLICT, "conflict", "scan already running"))?;
    s.scan_manager
        .set_options(b.github_pack_ids.clone(), b.manual_enrich.clone())
        .await;
    let manager = s.scan_manager.clone();
    let repository = s.repository.clone();
    tokio::spawn(manager.consume(rx, repository, stopped));
    let scanner = s.scanner.clone();
    let settings = s.settings.read().await.clone();
    let http = s.http.clone();
    tokio::spawn(async move {
        let registry = aipocket_discovery::packs::registry();
        let selected_packs: Vec<_> =
            if b.github_pack_ids.is_empty() || b.github_pack_ids.iter().any(|v| v == "all") {
                registry.values().copied().collect()
            } else {
                b.github_pack_ids
                    .iter()
                    .filter_map(|id| registry.get(id.as_str()).copied())
                    .collect()
            };
        let (fofa_queries, shodan_queries) = discovery_queries(&selected_packs);
        let mut discovery: Vec<std::sync::Arc<dyn aipocket_discovery::DiscoverySource>> =
            Vec::new();
        if sources.iter().any(|v| v == "all" || v == "fofa") {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::FofaSource {
                    client: aipocket_clients::FofaClient::new(http.clone(), &settings),
                    queries: fofa_queries,
                    page_size: settings.fofa_page_size,
                    max_pages: settings.fofa_max_pages,
                    page_delay: settings.fofa_page_delay,
                },
            ));
        }
        if sources.iter().any(|v| v == "all" || v == "shodan") {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ShodanSource {
                    client: aipocket_clients::ShodanClient::new(http.clone(), &settings),
                    queries: shodan_queries,
                    max_pages: settings.shodan_max_pages,
                    page_delay: settings.shodan_page_delay,
                },
            ));
        }
        if sources.iter().any(|v| v == "all" || v == "github")
            && !settings.github_token_list().is_empty()
            && settings.pg_enabled()
        {
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::GithubSource {
                    client: aipocket_clients::GithubClient::new(http.clone(), &settings),
                    queries: selected_packs
                        .iter()
                        .flat_map(|p| p.github_terms)
                        .map(|v| v.to_string())
                        .collect(),
                    per_page: settings.github_search_page_size,
                    run_id: b.resume_run_id.clone(),
                    pack_id: if b.github_pack_ids.len() == 1 {
                        b.github_pack_ids[0].clone()
                    } else {
                        String::new()
                    },
                },
            ));
        }
        if sources.iter().any(|v| v == "manual") {
            let targets = scanner.manual_targets().await.unwrap_or_default();
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ManualSource { targets },
            ));
        }
        if sources.iter().any(|v| v == "manual") && !b.manual_enrich.is_empty() {
            let targets = scanner.manual_targets().await.unwrap_or_default();
            let engines = b
                .manual_enrich
                .iter()
                .map(|engine| engine.trim().to_ascii_lowercase())
                .filter(|engine| engine == "fofa" || engine == "shodan")
                .collect::<Vec<_>>();
            discovery.push(std::sync::Arc::new(
                aipocket_discovery::sources::ManualEnrichSource {
                    targets,
                    engines,
                    fofa: aipocket_clients::FofaClient::new(http.clone(), &settings),
                    shodan: aipocket_clients::ShodanClient::new(http.clone(), &settings),
                },
            ));
        }
        let resume = (!b.resume_run_id.is_empty()).then_some(b.resume_run_id.clone());
        if let Err(error) = scanner
            .run_resumable(discovery, b.mode, resume.clone(), cancel, tx.clone())
            .await
        {
            // run_id is created inside the scanner; without resume the old path used
            // "unknown" and left the real runs row stuck in `running`.
            let run_id = if let Some(run_id) = resume {
                run_id
            } else {
                scanner
                    .latest_running_run_id()
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "unknown".into())
            };
            scanner.fail_run(&run_id, error.to_string(), &tx).await;
            // Belt-and-suspenders: error paths may drop the lease before release();
            // clear Redis so the next scan is not blocked by a stale lock.
            aipocket_db::clear_stale_scan_lock(&settings).await;
        }
    });
    Ok(Json(s.scan_manager.status().await))
}
async fn scan_stop(_: Auth, State(s): State<AppState>) -> Result<Json<ScanStatus>, ApiError> {
    if !s.scan_manager.stop().await {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "conflict",
            "no scan running",
        ));
    }
    Ok(Json(s.scan_manager.status().await))
}
async fn scan_status(_: Auth, State(s): State<AppState>) -> Json<ScanStatus> {
    Json(s.scan_manager.status().await)
}
#[derive(Default, Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
    token: Option<String>,
}
async fn scan_logs(_: Auth, State(s): State<AppState>, Query(q): Query<Since>) -> Json<Value> {
    let lines = s.scan_manager.logs_since(q.since).await;
    let last_seq = lines.last().map(|l| l.seq).unwrap_or(q.since);
    Json(json!({"lines":lines,"last_seq":last_seq}))
}
async fn scan_stream(
    State(s): State<AppState>,
    Query(q): Query<Since>,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    verify(q.token.as_deref().unwrap_or_default(), &s).await?;
    // Subscribe before replaying the buffer. Filtering by the replay high-water
    // mark closes the otherwise possible gap between replay and live subscribe.
    let receiver = s.scan_manager.subscribe();
    let replay_lines = s.scan_manager.logs_since(q.since).await;
    let replay_last = replay_lines.last().map_or(q.since, |line| line.seq);
    let replay = replay_lines.into_iter().map(|line| {
        Ok(Event::default()
            .event("log")
            .id(line.seq.to_string())
            .data(line.line))
    });
    let live = BroadcastStream::new(receiver).filter_map(move |item| async move {
        item.ok().filter(|line| line.seq > replay_last).map(|line| {
            Ok(Event::default()
                .event("log")
                .id(line.seq.to_string())
                .data(line.line))
        })
    });
    Ok(Sse::new(stream::iter(replay).chain(live))
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}
async fn system_restart(_: Auth) -> Json<Value> {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::process::exit(75)
    });
    Json(json!({"restarting":true}))
}
