use crate::{DiscoveryProgress, DiscoverySource, QueryUsage, SourceBudgets, SourceFetchResult};
use aipocket_clients::{FofaClient, GithubClient, ShodanClient};
use aipocket_core::ScanMode;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Value, json};

/// FOFA `fields` query param + dict key order. Keep in sync with Python
/// `DEFAULT_FIELDS` (`banner` not `body` — extractor scans `header`/`banner`).
pub const FOFA_FIELDS: &[&str] = &[
    "host", "ip", "port", "protocol", "title", "header", "banner", "server", "product", "link",
    "domain", "cert",
];

fn value_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn first_string(value: Option<&Value>) -> String {
    value.map(value_text).unwrap_or_default()
}

/// Map one FOFA `results[]` row (array or object) into the extractor dict shape.
pub fn normalize_fofa_row(row: &Value) -> Value {
    let mut out = match row {
        Value::Object(map) => Value::Object(map.clone()),
        Value::Array(items) => {
            let mut map = serde_json::Map::with_capacity(FOFA_FIELDS.len());
            for (i, name) in FOFA_FIELDS.iter().enumerate() {
                map.insert(
                    (*name).to_owned(),
                    items
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| Value::String(String::new())),
                );
            }
            Value::Object(map)
        }
        other => json!({ "_raw": value_text(other) }),
    };
    // Older FOFA field lists used `body`; alias into `banner` for the extractor.
    if out
        .get("banner")
        .map(value_text)
        .unwrap_or_default()
        .is_empty()
        && let Some(body) = out.get("body").cloned()
    {
        out["banner"] = body;
    }
    out
}

/// Normalize one Shodan match into FOFA-style fields the extractor expects.
/// `data` → `header`, `http.html` → `banner` (Python `map_match`).
pub fn normalize_shodan_match(m: &Value) -> Value {
    let http = m.get("http").cloned().unwrap_or_else(|| json!({}));
    let ip = {
        let ip_str = first_string(m.get("ip_str"));
        if !ip_str.is_empty() {
            ip_str
        } else {
            // String `ip` only (fixtures); ignore integer-packed Shodan `ip`.
            m.get("ip").and_then(Value::as_str).unwrap_or("").to_owned()
        }
    };
    let port = first_string(m.get("port"));
    let hostnames = m
        .get("hostnames")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let hostname0 = hostnames.first().map(value_text).filter(|s| !s.is_empty());
    let http_host = first_string(http.get("host"));
    let mut base = if let Some(h) = hostname0.clone() {
        h
    } else if !http_host.is_empty() {
        http_host
    } else if !ip.is_empty() {
        ip.clone()
    } else {
        // Fixture / already-normalized rows may carry `host` directly.
        first_string(m.get("host"))
    };
    if !base.is_empty() && !matches!(port.as_str(), "" | "80" | "443") && !base.contains(':') {
        base = format!("{base}:{port}");
    }
    let scheme = if port == "443" { "https" } else { "http" };
    let data_banner = first_string(m.get("data"));
    let html_body = first_string(http.get("html"));
    let header = if !data_banner.is_empty() {
        data_banner
    } else {
        first_string(m.get("header"))
    };
    let banner = if !html_body.is_empty() {
        html_body
    } else {
        first_string(m.get("banner"))
    };
    let title = {
        let t = first_string(http.get("title"));
        if t.is_empty() {
            first_string(m.get("title"))
        } else {
            t
        }
    };
    let cert = {
        let c = cert_to_str(m.get("ssl"));
        if c.is_empty() {
            first_string(m.get("cert"))
        } else {
            c
        }
    };
    let server = {
        let s = first_string(http.get("server"));
        if s.is_empty() {
            first_string(m.get("server"))
        } else {
            s
        }
    };
    json!({
        "host": base,
        "ip": ip,
        "port": port,
        "protocol": scheme,
        "title": title,
        "header": header,
        "banner": banner,
        "cert": cert,
        "product": first_string(m.get("product")),
        "server": server,
        "link": hostname0.unwrap_or_default(),
    })
}

fn cert_to_str(ssl: Option<&Value>) -> String {
    let Some(ssl) = ssl else {
        return String::new();
    };
    let cert = ssl.get("cert").cloned().unwrap_or_else(|| json!({}));
    let mut parts = Vec::new();
    for field in ["subject", "issuer"] {
        let node = cert.get(field).cloned().unwrap_or_else(|| json!({}));
        let nodes = match node {
            Value::Array(items) => items,
            other => vec![other],
        };
        for d in nodes {
            if let Value::Object(map) = d {
                let cn = map
                    .get("commonName")
                    .or_else(|| map.get("commonname"))
                    .map(value_text)
                    .unwrap_or_default();
                if !cn.is_empty() {
                    parts.push(cn);
                    let on = map
                        .get("organizationName")
                        .or_else(|| map.get("organizationname"))
                        .map(value_text)
                        .unwrap_or_default();
                    if !on.is_empty() {
                        parts.push(on);
                    }
                }
            }
        }
    }
    if let Some(issued) = cert.get("issued") {
        let text = value_text(issued);
        if !text.is_empty() {
            parts.push(text);
        }
    }
    parts.join(" ")
}

fn tag_hit(mut hit: Value, source: &str, query_id: &str) -> Value {
    if let Value::Object(map) = &mut hit {
        map.insert("_source".into(), Value::String(source.into()));
        if !query_id.is_empty() {
            map.insert("_query_id".into(), Value::String(query_id.into()));
        }
    }
    hit
}

fn tag_product_for_query(mut hit: Value, source: &str, query_id: &str) -> Value {
    let product = match source {
        "fofa" => crate::legacy_queries::product_for_query(query_id),
        "shodan" => crate::legacy_queries::product_for_shodan_query(query_id),
        _ => None,
    };
    if let Some(product) = product
        && let Value::Object(map) = &mut hit
    {
        map.insert("_product".into(), Value::String(product.into()));
    }
    hit
}
fn report_progress(
    budgets: &SourceBudgets,
    source: &str,
    query_index: usize,
    query_total: usize,
    page: u32,
    result: &SourceFetchResult,
) {
    if let Some(progress) = &budgets.progress {
        progress(DiscoveryProgress {
            source: source.into(),
            query_index,
            query_total,
            page,
            hits: result.host_hits.len() as u64,
            errors: result.errors.len(),
        });
    }
}

pub struct FofaSource {
    pub client: FofaClient,
    pub queries: Vec<String>,
    pub page_size: u32,
    pub max_pages: u32,
    pub page_delay: f64,
}
#[async_trait]
impl DiscoverySource for FofaSource {
    fn name(&self) -> &'static str {
        "fofa"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let limit = budgets.fofa.unwrap_or(queries.len());
        let mut result = SourceFetchResult {
            source: "fofa".into(),
            ..Default::default()
        };
        let query_total = queries.len().min(limit);
        for (query_offset, query) in queries.into_iter().take(limit).enumerate() {
            let query_index = query_offset + 1;
            report_progress(budgets, "fofa", query_index, query_total, 0, &result);
            for page in 1..=self.max_pages.max(1) {
                match self.client.search(query, page, self.page_size.max(1)).await {
                    Ok(value) => {
                        let rows = value
                            .get("results")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let count = rows.len();
                        result.host_hits.extend(rows.iter().map(|row| {
                            tag_product_for_query(
                                tag_hit(normalize_fofa_row(row), "fofa", query),
                                "fofa",
                                query,
                            )
                        }));
                        result.query_usage.push(QueryUsage {
                            source: "fofa".into(),
                            query: query.clone(),
                            page_count: 1,
                            result_count: count as u64,
                            query_id: query.clone(),
                            ..Default::default()
                        });
                        report_progress(budgets, "fofa", query_index, query_total, page, &result);
                        if count < self.page_size as usize {
                            break;
                        }
                    }
                    Err(error) => {
                        result.errors.push(error.to_string());
                        report_progress(budgets, "fofa", query_index, query_total, page, &result);
                        break;
                    }
                }
                if self.page_delay > 0.0 {
                    tokio::time::sleep(std::time::Duration::from_secs_f64(self.page_delay)).await;
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

pub struct ShodanSource {
    pub client: ShodanClient,
    pub queries: Vec<String>,
    pub max_pages: u32,
    pub page_delay: f64,
}
#[async_trait]
impl DiscoverySource for ShodanSource {
    fn name(&self) -> &'static str {
        "shodan"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let limit = budgets.shodan.unwrap_or(queries.len());
        let mut result = SourceFetchResult {
            source: "shodan".into(),
            ..Default::default()
        };
        let query_total = queries.len().min(limit);
        for (query_offset, query) in queries.into_iter().take(limit).enumerate() {
            let query_index = query_offset + 1;
            report_progress(budgets, "shodan", query_index, query_total, 0, &result);
            for page in 1..=self.max_pages.max(1) {
                match self.client.search(query, page).await {
                    Ok(value) => {
                        let rows = value
                            .get("matches")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let count = rows.len();
                        result.host_hits.extend(rows.iter().map(|row| {
                            tag_product_for_query(
                                tag_hit(normalize_shodan_match(row), "shodan", query),
                                "shodan",
                                query,
                            )
                        }));
                        result.query_usage.push(QueryUsage {
                            source: "shodan".into(),
                            query: query.clone(),
                            page_count: 1,
                            result_count: count as u64,
                            query_id: query.clone(),
                            ..Default::default()
                        });
                        report_progress(budgets, "shodan", query_index, query_total, page, &result);
                        if count < 100 {
                            break;
                        }
                    }
                    Err(error) => {
                        result.errors.push(error.to_string());
                        report_progress(budgets, "shodan", query_index, query_total, page, &result);
                        break;
                    }
                }
                if self.page_delay > 0.0 {
                    tokio::time::sleep(std::time::Duration::from_secs_f64(self.page_delay)).await;
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

pub struct GithubSource {
    pub client: GithubClient,
    pub queries: Vec<String>,
    pub per_page: usize,
    pub run_id: String,
    pub pack_id: String,
}
#[async_trait]
impl DiscoverySource for GithubSource {
    fn name(&self) -> &'static str {
        "github"
    }
    fn query_ids(&self) -> Vec<String> {
        self.queries.clone()
    }
    fn is_configured(&self) -> bool {
        !self.queries.is_empty()
    }
    async fn fetch(&self, budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let mut result = SourceFetchResult {
            source: "github".into(),
            ..Default::default()
        };
        let selected = budgets.selected_queries.as_ref();
        let queries = self
            .queries
            .iter()
            .filter(|query| selected.is_none_or(|values| values.contains(query)))
            .collect::<Vec<_>>();
        let code_limit = budgets.github_code.unwrap_or(queries.len());
        let query_total = queries.len();
        for (query_index, query) in queries.iter().copied().take(code_limit).enumerate() {
            let shard_id = checkpoint_shard_id(&self.pack_id, query, "code_snapshot");
            let start_page = budgets
                .checkpoints
                .iter()
                .find(|checkpoint| checkpoint.shard_id == shard_id)
                .and_then(|checkpoint| checkpoint.cursor_state.get("next_page"))
                .and_then(Value::as_u64)
                .unwrap_or(1) as usize;
            report_progress(budgets, "github", query_index, query_total, 0, &result);
            for page in start_page..=5 {
                let value = match self.client.search_code(query, page, self.per_page).await {
                    Ok(value) => value,
                    Err(error) => {
                        result.errors.push(error.to_string());
                        break;
                    }
                };
                let items = value
                    .get("items")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let count = items.len();
                for item in items {
                    self.process_code_item(&item, query, &mut result).await;
                    if let Some(work) = artifact_work(&item, query, "code_snapshot") {
                        result.artifact_work.push(work);
                    }
                }
                result.query_usage.push(QueryUsage {
                    source: "github".into(),
                    query: query.clone(),
                    page_count: 1,
                    result_count: count as u64,
                    query_id: query.clone(),
                    lane: "code_snapshot".into(),
                    ..Default::default()
                });
                report_progress(budgets, "github", query_index, query_total, page as u32, &result);
                if self.per_page <= 1 {
                    break;
                }
                if count < self.per_page {
                    break;
                }
            }
            result.checkpoint_updates.push(checkpoint(
                &self.pack_id,
                query,
                "code_snapshot",
                serde_json::json!({"next_page": 1}),
            ));
        }
        let commit_limit = budgets.github_commit.unwrap_or(0).min(queries.len());
        for (query_index, query) in queries.iter().copied().take(commit_limit).enumerate() {
            report_progress(budgets, "github", query_index, query_total, 0, &result);
            let value = match self.client.search_commits(query, 1, self.per_page).await {
                Ok(value) => value,
                Err(error) => {
                    result.errors.push(error.to_string());
                    continue;
                }
            };
            let items = value
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for item in &items {
                let private = item.pointer("/repository/private").and_then(Value::as_bool);
                if private != Some(false) {
                    continue;
                }
                let endpoint = item
                    .get("html_url")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let message = item
                    .pointer("/commit/message")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                for secret in crate::github_artifacts::extract_artifact_text(
                    message,
                    endpoint,
                    "commit_message",
                    "context",
                    "",
                    item.get("sha").and_then(Value::as_str).unwrap_or_default(),
                ) {
                    result.credential_observations.push(observation(
                        item,
                        secret,
                        query,
                        "commit_message",
                    ));
                }
                if let Some(work) = artifact_work(item, query, "commit_message") {
                    result.artifact_work.push(work);
                }
                result.host_hits.push(item.clone());
            }
            result.query_usage.push(QueryUsage {
                source: "github".into(),
                query: query.clone(),
                page_count: 1,
                result_count: items.len() as u64,
                query_id: query.clone(),
                lane: "commit_message".into(),
                ..Default::default()
            });
            result.checkpoint_updates.push(checkpoint(
                &self.pack_id,
                query,
                "commit_message",
                serde_json::json!({"next_page": 1}),
            ));
            report_progress(budgets, "github", query_index, query_total, 1, &result);
        }
        result.credential_observation_count = Some(result.credential_observations.len() as u64);
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

impl GithubSource {
    async fn process_code_item(&self, item: &Value, query: &str, result: &mut SourceFetchResult) {
        let public = item.pointer("/repository/private").and_then(Value::as_bool) == Some(false)
            || item
                .pointer("/repository/visibility")
                .and_then(Value::as_str)
                == Some("public");
        if !public {
            return;
        }
        let path = item.get("path").and_then(Value::as_str).unwrap_or_default();
        if crate::github_artifacts::is_noise_artifact_path(path) {
            return;
        }
        let endpoint = item
            .get("html_url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut text = item
            .get("text_matches")
            .map(Value::to_string)
            .unwrap_or_default();
        if let Some((owner, repo)) = repository_name(item)
            && let Some(sha) = item.get("sha").and_then(Value::as_str)
            && let Ok(blob) = self.client.blob(owner, repo, sha).await
            && let Some(content) = blob.get("content").and_then(Value::as_str)
        {
            use base64::Engine;
            if let Ok(decoded) =
                base64::engine::general_purpose::STANDARD.decode(content.replace('\n', ""))
                && decoded.len() <= 1_048_576
            {
                text = String::from_utf8_lossy(&decoded).into_owned();
            }
        }
        for secret in crate::github_artifacts::extract_artifact_text(
            &text,
            endpoint,
            "code_snapshot",
            "context",
            path,
            item.get("sha").and_then(Value::as_str).unwrap_or_default(),
        ) {
            result
                .credential_observations
                .push(observation(item, secret, query, "code_snapshot"));
        }
        result.host_hits.push(item.clone());
    }
}
fn checkpoint_shard_id(pack_id: &str, query: &str, lane: &str) -> String {
    use sha1::Digest;
    format!(
        "{:x}",
        sha1::Sha1::digest(format!("{lane}|{pack_id}|{query}").as_bytes())
    )
}

fn checkpoint(
    pack_id: &str,
    query: &str,
    lane: &str,
    cursor_state: Value,
) -> crate::CheckpointUpdate {
    crate::CheckpointUpdate {
        source: "github".into(),
        lane: lane.into(),
        pack_id: pack_id.into(),
        shard_id: checkpoint_shard_id(pack_id, query, lane),
        watermark: chrono::Utc::now().to_rfc3339(),
        cursor_state,
        status: "ok".into(),
        ..Default::default()
    }
}

fn artifact_work(item: &Value, query: &str, lane: &str) -> Option<crate::ArtifactWork> {
    let repository = item.get("repository")?;
    let repo_id = repository.get("id").map(ToString::to_string)?;
    let repository_full_name = repository.get("full_name")?.as_str()?.to_owned();
    let object_sha = item
        .get("sha")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let commit_sha = object_sha.clone();
    let file_path = item
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Some(crate::ArtifactWork {
        repo_id,
        repository_full_name,
        commit_sha,
        file_path,
        object_sha,
        source_kind: lane.to_owned(),
        work_status: "fetch_pending".into(),
        current_stage: "fetch_pending".into(),
        query_id: query.to_owned(),
        lane: lane.to_owned(),
        coverage_mode: "complete".into(),
        ..Default::default()
    })
}

fn repository_name(item: &Value) -> Option<(&str, &str)> {
    item.pointer("/repository/full_name")
        .and_then(Value::as_str)?
        .split_once('/')
}

fn observation(
    item: &Value,
    secret: crate::github_artifacts::ExtractedArtifactSecret,
    query: &str,
    lane: &str,
) -> crate::CredentialObservation {
    crate::CredentialObservation {
        credential: secret.credential,
        provenance: crate::ArtifactProvenance {
            repository_id: item
                .pointer("/repository/id")
                .map(ToString::to_string)
                .unwrap_or_default(),
            repository_full_name: item
                .pointer("/repository/full_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            commit_sha: item
                .get("sha")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            object_sha: secret.object_sha,
            file_path: secret.file_path,
            source_kind: secret.source_kind,
            change_side: secret.change_side,
            line_start: secret.line_start.map(u64::from),
            line_end: secret.line_end.map(u64::from),
            query_id: query.into(),
            lane: lane.into(),
            ..Default::default()
        },
        query_id: query.into(),
        lane: lane.into(),
        coverage_mode: "complete".into(),
        ..Default::default()
    }
}

pub struct ManualSource {
    pub targets: Vec<String>,
}
#[async_trait]
impl DiscoverySource for ManualSource {
    fn name(&self) -> &'static str {
        "manual"
    }
    fn query_ids(&self) -> Vec<String> {
        Vec::new()
    }
    fn is_configured(&self) -> bool {
        !self.targets.is_empty()
    }
    async fn fetch(&self, _budgets: &SourceBudgets, _mode: ScanMode) -> Result<SourceFetchResult> {
        let host_hits = self
            .targets
            .iter()
            .map(|url| serde_json::json!({"host":url,"url":url,"_source":"manual"}))
            .collect::<Vec<_>>();
        Ok(SourceFetchResult {
            source: "manual".into(),
            host_hit_count: Some(host_hits.len() as u64),
            host_hits,
            ..Default::default()
        })
    }
}

pub struct ManualEnrichSource {
    pub targets: Vec<String>,
    pub engines: Vec<String>,
    pub fofa: FofaClient,
    pub shodan: ShodanClient,
}

#[async_trait]
impl DiscoverySource for ManualEnrichSource {
    fn name(&self) -> &'static str {
        "manual_enrich"
    }
    fn is_configured(&self) -> bool {
        !self.targets.is_empty() && !self.engines.is_empty()
    }
    async fn fetch(&self, _: &SourceBudgets, _: ScanMode) -> Result<SourceFetchResult> {
        let mut result = SourceFetchResult {
            source: "manual_enrich".into(),
            ..Default::default()
        };
        for target in &self.targets {
            let normalized = if target.contains("://") {
                target.clone()
            } else {
                format!("https://{target}")
            };
            let Ok(url) = url::Url::parse(&normalized) else {
                continue;
            };
            let Some(hostname) = url.host_str() else {
                continue;
            };
            let is_ip = hostname.parse::<std::net::IpAddr>().is_ok();
            if self.engines.iter().any(|engine| engine == "fofa") {
                let query = if is_ip {
                    format!("ip=\"{hostname}\"")
                } else {
                    format!("host=\"{hostname}\" || domain=\"{hostname}\"")
                };
                match self.fofa.search(&query, 1, 50).await {
                    Ok(value) => {
                        let query_id = format!("manual-enrich:fofa:{hostname}");
                        let rows = value
                            .get("results")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let mut mapped = rows
                            .iter()
                            .map(|row| {
                                let mut hit = tag_hit(normalize_fofa_row(row), "fofa", &query_id);
                                if let Value::Object(map) = &mut hit {
                                    map.insert(
                                        "_manual_seed_host".into(),
                                        Value::String(hostname.into()),
                                    );
                                }
                                hit
                            })
                            .collect::<Vec<_>>();
                        result.query_usage.push(QueryUsage {
                            source: "fofa".into(),
                            query,
                            page_count: 1,
                            result_count: mapped.len() as u64,
                            query_id,
                            lane: "manual-enrich".into(),
                            ..Default::default()
                        });
                        result.host_hits.append(&mut mapped);
                    }
                    Err(error) => result.errors.push(format!("fofa {hostname}: {error}")),
                }
            }
            if self.engines.iter().any(|engine| engine == "shodan") {
                let query = if is_ip {
                    format!("ip:{hostname}")
                } else {
                    format!("hostname:\"{hostname}\"")
                };
                match self.shodan.search(&query, 1).await {
                    Ok(value) => {
                        let query_id = format!("manual-enrich:shodan:{hostname}");
                        let rows = value
                            .get("matches")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        let mut mapped = rows
                            .iter()
                            .map(|row| {
                                let mut hit =
                                    tag_hit(normalize_shodan_match(row), "shodan", &query_id);
                                if let Value::Object(map) = &mut hit {
                                    map.insert(
                                        "_manual_seed_host".into(),
                                        Value::String(hostname.into()),
                                    );
                                }
                                hit
                            })
                            .collect::<Vec<_>>();
                        result.query_usage.push(QueryUsage {
                            source: "shodan".into(),
                            query,
                            page_count: 1,
                            result_count: mapped.len() as u64,
                            query_id,
                            lane: "manual-enrich".into(),
                            ..Default::default()
                        });
                        result.host_hits.append(&mut mapped);
                    }
                    Err(error) => result.errors.push(format!("shodan {hostname}: {error}")),
                }
            }
        }
        result.host_hit_count = Some(result.host_hits.len() as u64);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fofa_array_row_maps_to_named_fields() {
        let row = json!([
            "api.example.com",
            "1.2.3.4",
            443,
            "https",
            "title",
            "Authorization: Bearer sk-test-abcdefghijklmnop",
            "<html>body</html>",
            "nginx",
            "OpenAI",
            "api.example.com",
            "example.com",
            "CN=example"
        ]);
        let hit = tag_hit(normalize_fofa_row(&row), "fofa", "title=\"x\"");
        assert_eq!(hit["host"], "api.example.com");
        assert_eq!(hit["ip"], "1.2.3.4");
        assert_eq!(hit["port"], 443);
        assert_eq!(
            hit["header"],
            "Authorization: Bearer sk-test-abcdefghijklmnop"
        );
        assert_eq!(hit["banner"], "<html>body</html>");
        assert_eq!(hit["_source"], "fofa");
        assert_eq!(hit["_query_id"], "title=\"x\"");
    }

    #[test]
    fn shodan_match_maps_data_to_header_and_html_to_banner() {
        let row = json!({
            "ip_str": "9.9.9.9",
            "port": 8443,
            "hostnames": ["leak.example"],
            "data": "HTTP/1.1 200\r\nAuthorization: Bearer sk-proj-abcdef",
            "http": {
                "html": "<html>OPENAI_API_KEY=sk-proj-xyz</html>",
                "title": "t",
                "host": "leak.example"
            },
            "product": "nginx"
        });
        let hit = tag_hit(
            normalize_shodan_match(&row),
            "shodan",
            "http.html:\"OPENAI\"",
        );
        assert_eq!(hit["host"], "leak.example:8443");
        assert_eq!(hit["ip"], "9.9.9.9");
        assert_eq!(hit["port"], "8443");
        assert!(hit["header"].as_str().unwrap().contains("sk-proj-abcdef"));
        assert!(hit["banner"].as_str().unwrap().contains("sk-proj-xyz"));
        assert_eq!(hit["_source"], "shodan");
    }

    #[test]
    fn fofa_body_aliases_to_banner() {
        let row = json!({"host": "h", "body": "BANNER_BODY", "header": "H"});
        let hit = normalize_fofa_row(&row);
        assert_eq!(hit["banner"], "BANNER_BODY");
    }

    #[tokio::test]
    async fn normalization_and_manual_source_cover_fallback_boundaries() {
        assert_eq!(normalize_fofa_row(&json!(true))["_raw"], "true");
        assert_eq!(
            normalize_fofa_row(&json!(["only-host"]))["host"],
            "only-host"
        );
        assert_eq!(normalize_fofa_row(&json!(["only-host"]))["ip"], "");

        let normalized = normalize_shodan_match(&json!({
            "ip": "192.0.2.10",
            "port": 443,
            "host": "fallback.example",
            "header": "fixture-header",
            "banner": "fixture-banner",
            "title": "fixture-title",
            "cert": "fixture-cert",
            "server": "fixture-server"
        }));
        assert_eq!(normalized["host"], "192.0.2.10");
        assert_eq!(normalized["protocol"], "https");
        assert_eq!(normalized["header"], "fixture-header");
        assert_eq!(normalized["banner"], "fixture-banner");
        assert_eq!(normalized["cert"], "fixture-cert");
        assert_eq!(normalized["server"], "fixture-server");

        let certificate = normalize_shodan_match(&json!({
            "ip_str": "192.0.2.11",
            "port": 80,
            "ssl": {"cert": {
                "subject": [{"commonname": "subject.example", "organizationname": "Subject Org"}],
                "issuer": {"commonName": "Fixture CA", "organizationName": "Issuer Org"},
                "issued": 123
            }}
        }));
        assert_eq!(
            certificate["cert"],
            "subject.example Subject Org Fixture CA Issuer Org 123"
        );

        let source = ManualSource {
            targets: vec!["https://one.example".into(), "two.example".into()],
        };
        assert_eq!(source.name(), "manual");
        assert!(source.query_ids().is_empty());
        assert!(source.is_configured());
        let fetched = source
            .fetch(&SourceBudgets::default(), ScanMode::Incremental)
            .await
            .unwrap();
        assert_eq!(fetched.host_hit_count, Some(2));
        assert_eq!(fetched.host_hits[1]["url"], "two.example");
        assert_eq!(fetched.host_hits[1]["_source"], "manual");
    }

    #[test]
    fn legacy_product_queries_tag_discovery_hits() {
        let hit = tag_product_for_query(
            json!({"host":"https://litellm.example"}),
            "fofa",
            "body=\"litellm\" && body=\"sk-\" && status_code=\"200\"",
        );
        assert_eq!(hit["_product"], "litellm");
    }
}
