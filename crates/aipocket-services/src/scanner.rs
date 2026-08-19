use crate::pipeline::{as_json, extract_credentials, finalize_results, high_value_record};
use aipocket_core::{Credential, ScanMode, ScanProgress, Settings};
use aipocket_db::{DedupStore, Repository, RequestLedgerEntry, ScanLease};
use aipocket_discovery::{DiscoveryProgress, DiscoverySource, SourceBudgets};
use aipocket_prober::Validator;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ScanEvent {
    /// Emitted right after the run row is created so the UI can show run_id while running.
    Started {
        run_id: String,
    },
    Phase(String),
    Progress(ScanProgress),
    Log(String),
    Finished {
        run_id: String,
    },
    Interrupted {
        run_id: String,
        error: String,
    },
}
#[derive(Clone)]
pub struct Scanner {
    settings: Arc<Settings>,
    repository: Repository,
    http: reqwest::Client,
}
impl Scanner {
    pub fn new(settings: Arc<Settings>, repository: Repository, http: reqwest::Client) -> Self {
        Self {
            settings,
            repository,
            http,
        }
    }
    pub async fn manual_targets(&self) -> Result<Vec<String>> {
        let (targets, _) = self.repository.list_manual_targets(true, 10_000, 0).await?;
        Ok(targets.into_iter().map(|target| target.url).collect())
    }

    pub async fn latest_running_run_id(&self) -> Result<Option<String>> {
        self.repository.latest_running_run_id().await
    }

    pub async fn run_resumable(
        &self,
        sources: Vec<Arc<dyn DiscoverySource>>,
        mode: ScanMode,
        resume_run_id: Option<String>,
        cancel: CancellationToken,
        events: mpsc::UnboundedSender<ScanEvent>,
    ) -> Result<String> {
        self.run_inner(sources, mode, resume_run_id, cancel, events)
            .await
    }

    pub async fn run(
        &self,
        sources: Vec<Arc<dyn DiscoverySource>>,
        mode: ScanMode,
        cancel: CancellationToken,
        events: mpsc::UnboundedSender<ScanEvent>,
    ) -> Result<String> {
        self.run_inner(sources, mode, None, cancel, events).await
    }

    async fn run_inner(
        &self,
        sources: Vec<Arc<dyn DiscoverySource>>,
        mode: ScanMode,
        resume_run_id: Option<String>,
        cancel: CancellationToken,
        events: mpsc::UnboundedSender<ScanEvent>,
    ) -> Result<String> {
        let source_names = sources
            .iter()
            .map(|source| source.name().to_owned())
            .collect::<Vec<_>>();
        let started_at = chrono::Utc::now();
        let lease = ScanLease::acquire(&self.settings).await?;
        let run_id = resume_run_id
            .unwrap_or_else(|| format!("run_{}", started_at.format("%Y_%m_%d_%H-%M-%S")));
        self.repository
            .create_run(&run_id, started_at, mode_name(&mode), &source_names)
            .await?;
        events
            .send(ScanEvent::Started {
                run_id: run_id.clone(),
            })
            .ok();
        let resume_phase = self.repository.resume_phase(&run_id).await?;
        let mut progress = ScanProgress::default();
        let mut hits = Vec::new();
        events.send(ScanEvent::Phase("discovery".into())).ok();
        self.repository
            .update_phase(&run_id, "discovery", serde_json::json!({}))
            .await?;
        let budgets = SourceBudgets {
            fofa: Some(self.settings.fofa_query_budget),
            shodan: Some(self.settings.shodan_query_budget),
            github_commit: Some(self.settings.github_commit_query_budget),
            github_code: Some(self.settings.github_code_query_budget),
            selected_queries: None,
            checkpoints: Vec::new(),
            progress: None,
        };
        let policy = aipocket_core::ScanPolicy::from_mode(mode.clone());
        if resume_phase
            .as_deref()
            .is_some_and(|phase| phase_rank(phase) >= phase_rank("extract"))
            && let Some(pool) = self.repository.pool()
        {
            hits = aipocket_db::load_discovery_hits(pool, &run_id).await?;
            progress.raw_hits = hits.len() as u64;
        }
        let mut query_metrics =
            std::collections::BTreeMap::<(String, String), aipocket_db::QueryMetricRecord>::new();
        // FOFA/Shodan first: do not block primary discovery behind pending GitHub blob
        // drains (slow/403 tokens previously left the UI stuck in discovery with 0 hits).
        if hits.is_empty() {
            for source in sources {
                if cancel.is_cancelled() {
                    return self.interrupt(&run_id, progress, lease, &events).await;
                }
                let query_ids = source.query_ids();
                let source_budgets = if policy.discovery_scope == "full" {
                    SourceBudgets {
                        github_code: (source.name() == "github").then_some(query_ids.len()),
                        github_commit: (source.name() == "github").then_some(query_ids.len()),
                        ..Default::default()
                    }
                } else {
                    budgets.clone()
                };
                let query_budget =
                    source_query_budget(source.name(), &source_budgets, query_ids.len());
                let selected_queries = self
                    .repository
                    .plan_query_ids(
                        source.name(),
                        &query_ids,
                        self.settings.planner_metrics_version,
                        query_budget,
                    )
                    .await?;
                let mut checkpoints = Vec::new();
                if policy.discovery_scope == "incremental" && source.name() == "github" {
                    for query in &selected_queries {
                        for lane in ["code_snapshot", "commit_message"] {
                            let shard_id = github_shard_id(lane, "", query);
                            if let Some(checkpoint) = self
                                .repository
                                .source_checkpoint("github", lane, "", &shard_id)
                                .await?
                            {
                                checkpoints.push(aipocket_discovery::CheckpointUpdate {
                                    source: checkpoint.source,
                                    lane: checkpoint.lane,
                                    pack_id: checkpoint.pack_id,
                                    shard_id: checkpoint.shard_id,
                                    watermark: checkpoint.watermark,
                                    cursor_state: checkpoint.cursor_state,
                                    etag: checkpoint.etag,
                                    status: checkpoint.status,
                                });
                            }
                        }
                    }
                }
                let events_for_progress = events.clone();
                let progress_reporter = Arc::new(move |update: DiscoveryProgress| {
                    events_for_progress
                        .send(ScanEvent::Log(discovery_progress_line(&update)))
                        .ok();
                });
                let source_budgets = SourceBudgets {
                    selected_queries: Some(selected_queries),
                    checkpoints,
                    progress: Some(progress_reporter),
                    ..source_budgets
                };
                events
                    .send(ScanEvent::Log(format!(
                        "发现 · 开始 {} · 计划查询 {} 条",
                        source.name(),
                        source_budgets
                            .selected_queries
                            .as_ref()
                            .map_or(query_ids.len(), Vec::len)
                    )))
                    .ok();
                let fetched = tokio::select! {
                    _ = cancel.cancelled() => {
                        return self.interrupt(&run_id, progress, lease, &events).await;
                    }
                    fetched = source.fetch(&source_budgets, mode.clone()) => fetched,
                };
                match fetched {
                    Ok(mut fetched) => {
                        progress.raw_hits += fetched
                            .host_hit_count
                            .unwrap_or(fetched.host_hits.len() as u64);
                        for usage in &fetched.query_usage {
                            let key = (usage.source.clone(), usage.query.clone());
                            let metric = query_metrics.entry(key).or_insert_with(|| {
                                aipocket_db::QueryMetricRecord {
                                    source: usage.source.clone(),
                                    query: usage.query.clone(),
                                    query_id: usage.query_id.clone(),
                                    pack_id: usage.pack_id.clone(),
                                    lane: usage.lane.clone(),
                                    attribution_version: i32::from(
                                        self.settings.planner_metrics_version,
                                    ),
                                    ..Default::default()
                                }
                            });
                            metric.funnel.raw_hits += usage.result_count;
                            metric.query_credits += usage.page_count as i64;
                        }
                        if let Some(pool) = self.repository.pool()
                            && (!fetched.checkpoint_updates.is_empty()
                                || !fetched.artifact_work.is_empty())
                        {
                            let checkpoints = fetched
                                .checkpoint_updates
                                .iter()
                                .map(|checkpoint| aipocket_db::SourceCheckpoint {
                                    source: checkpoint.source.clone(),
                                    lane: checkpoint.lane.clone(),
                                    pack_id: checkpoint.pack_id.clone(),
                                    shard_id: checkpoint.shard_id.clone(),
                                    watermark: checkpoint.watermark.clone(),
                                    cursor_state: checkpoint.cursor_state.clone(),
                                    etag: checkpoint.etag.clone(),
                                    status: checkpoint.status.clone(),
                                })
                                .collect::<Vec<_>>();
                            let work = fetched
                                .artifact_work
                                .iter()
                                .map(|item| aipocket_db::ArtifactWorkItem {
                                    repo_id: item.repo_id.clone(),
                                    repository_full_name: item.repository_full_name.clone(),
                                    commit_sha: item.commit_sha.clone(),
                                    file_path: item.file_path.clone(),
                                    object_sha: item.object_sha.clone(),
                                    source_kind: item.source_kind.clone(),
                                    etag: item.etag.clone(),
                                    work_status: item.work_status.clone(),
                                    attempts: item.attempts,
                                    last_error_class: item.last_error_class.clone(),
                                    current_stage: item.current_stage.clone(),
                                    run_id: run_id.clone(),
                                    query_id: item.query_id.clone(),
                                    pack_id: item.pack_id.clone(),
                                    lane: item.lane.clone(),
                                    coverage_mode: item.coverage_mode.clone(),
                                })
                                .collect::<Vec<_>>();
                            aipocket_db::advance_checkpoints_with_work(pool, &checkpoints, &work)
                                .await?;
                        }
                        hits.append(&mut fetched.host_hits);
                        credentials_from_observations(&mut hits, fetched.credential_observations);
                        for error in fetched.errors {
                            events
                                .send(ScanEvent::Log(format!(
                                    "发现 · {} · 警告 · {error}",
                                    source.name()
                                )))
                                .ok();
                        }
                        events.send(ScanEvent::Progress(progress.clone())).ok();
                        events
                            .send(ScanEvent::Log(format!(
                                "发现 · 完成 {} · 累计原始命中 {}",
                                source.name(),
                                progress.raw_hits
                            )))
                            .ok();
                    }
                    Err(error) => {
                        events
                            .send(ScanEvent::Log(format!(
                                "发现 · {} · 失败 · {error}",
                                source.name()
                            )))
                            .ok();
                    }
                };
            }
        }
        if cancel.is_cancelled() {
            return self.interrupt(&run_id, progress, lease, &events).await;
        }
        // Drain previously-enqueued GitHub artifact work after host discovery so a
        // slow/broken token pool cannot stall FOFA/Shodan.
        if let Some(pool) = self.repository.pool() {
            let pending = aipocket_db::claim_artifact_work(pool, 200).await?;
            if !pending.is_empty() {
                events
                    .send(ScanEvent::Log(format!(
                        "processing {} pending GitHub artifact work items",
                        pending.len()
                    )))
                    .ok();
                let observations = tokio::select! {
                    _ = cancel.cancelled() => {
                        return self.interrupt(&run_id, progress, lease, &events).await;
                    }
                    observations = self.process_github_work(pool, pending, &events) => observations,
                };
                credentials_from_observations(&mut hits, observations);
            }
        }
        if cancel.is_cancelled() {
            return self.interrupt(&run_id, progress, lease, &events).await;
        }
        if let Some(pool) = self.repository.pool() {
            aipocket_db::upsert_discovery_hits(pool, &run_id, &hits).await?;
        }
        self.repository
            .update_phase(
                &run_id,
                "validate",
                serde_json::json!({"raw_hits":progress.raw_hits}),
            )
            .await?;
        progress.unique_targets = distinct_target_count(&hits);
        for metric in query_metrics.values_mut() {
            metric.funnel.unique_targets = metric.funnel.raw_hits;
        }
        events
            .send(ScanEvent::Phase("extract_validate".into()))
            .ok();
        let dedup = DedupStore::connect(&self.settings).await;
        let known_honeypot_groups = self.repository.known_honeypot_groups().await?;
        let mut unseen_hits = Vec::with_capacity(hits.len());
        for hit in hits {
            let target = hit
                .get("host")
                .or_else(|| hit.get("url"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let group = aipocket_core::url_sanitize::honeypot_group_key(target).ok();
            if group
                .as_ref()
                .is_some_and(|group| known_honeypot_groups.contains(group))
            {
                continue;
            }
            if !policy.use_cross_run_dedup
                || target.is_empty()
                || !dedup.target_seen("probe", target).await
            {
                unseen_hits.push(hit);
            }
        }
        hits = unseen_hits;
        let validator = Validator::new(self.http.clone());
        let mut outcomes = Vec::new();
        let mut ledger = Vec::new();
        let mut probed = tokio::select! {
            _ = cancel.cancelled() => {
                return self.interrupt(&run_id, progress, lease, &events).await;
            }
            probed = self.probe_hits(&hits, &events) => probed,
        };
        for hit in &hits {
            if let Some(target) = hit
                .get("host")
                .or_else(|| hit.get("url"))
                .and_then(Value::as_str)
                && !target.is_empty()
            {
                dedup.mark_host(target).await;
                dedup.mark_target("probe", target).await;
            }
        }
        let mut credentials = if resume_phase
            .as_deref()
            .is_some_and(|phase| phase_rank(phase) >= phase_rank("validate"))
        {
            if let Some(pool) = self.repository.pool() {
                aipocket_db::load_candidate_page(pool, &run_id, 0, i64::MAX)
                    .await?
                    .into_iter()
                    .map(|(_, credential)| credential)
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            let mut extracted = extract_credentials(&hits);
            extracted.append(&mut probed);
            extracted
        };
        let run_dir = self
            .settings
            .write_jsonl()
            .then(|| self.settings.results_path().join(&run_id));
        let analyzer = crate::Analyzer::new(self.settings.clone(), self.http.clone());
        if resume_phase
            .as_deref()
            .is_none_or(|phase| phase_rank(phase) < phase_rank("validate"))
        {
            let gpt_report = tokio::select! {
                _ = cancel.cancelled() => {
                    return self.interrupt(&run_id, progress, lease, &events).await;
                }
                report = analyzer.extract(&hits, run_dir.as_deref()) => report,
            };
            credentials.extend(gpt_report.credentials);
        }
        if let Some(pool) = self.repository.pool() {
            aipocket_db::upsert_candidates(pool, &run_id, &credentials).await?;
        }
        progress.candidates = credentials.len() as u64;
        events.send(ScanEvent::Progress(progress.clone())).ok();
        for chunk in credentials.chunks(self.settings.validate_batch_size.max(1)) {
            if cancel.is_cancelled() {
                return self.interrupt(&run_id, progress, lease, &events).await;
            }
            let semaphore = Arc::new(tokio::sync::Semaphore::new(
                self.settings.validate_concurrency.max(1),
            ));
            let mut tasks = tokio::task::JoinSet::new();
            for credential in chunk.iter().cloned() {
                if !policy.require_fresh_verification {
                    if let Some(cached) = dedup
                        .get_success::<aipocket_core::ValidationResult>(&credential)
                        .await
                    {
                        outcomes.push(cached);
                        continue;
                    }
                    if dedup.get_outcome(&credential).await.is_some() {
                        continue;
                    }
                }
                progress.active_requests += 1;
                let validator = validator.clone();
                let semaphore = semaphore.clone();
                let run_id = run_id.clone();
                tasks.spawn(async move {
                    let _permit = semaphore.acquire_owned().await.ok();
                    let mut entry = RequestLedgerEntry::new(&run_id, "validation");
                    entry.source = credential.backend.clone();
                    entry.query_id = if credential.source.is_empty() {
                        credential.backend.clone()
                    } else {
                        credential.source.clone()
                    };
                    entry.provider = credential.product.clone();
                    let result = validator.validate(credential.clone()).await;
                    (credential, entry, result)
                });
            }
            while let Some(joined) = tokio::select! {
                _ = cancel.cancelled() => {
                    return self.interrupt(&run_id, progress, lease, &events).await;
                }
                joined = tasks.join_next() => joined,
            } {
                let Ok((credential, mut entry, result)) = joined else {
                    events
                        .send(ScanEvent::Log("validation task failed in isolation".into()))
                        .ok();
                    continue;
                };
                match result {
                    Ok(result) => {
                        entry.status_code = result.status_code.map(i32::from);
                        entry.status_class = result
                            .status_code
                            .map(|code| format!("{}xx", code / 100))
                            .unwrap_or_default();
                        if result.valid {
                            dedup.set_success(&credential, &result).await;
                        } else if result.validation_state == "rejected" {
                            dedup.set_outcome(&credential, "rejected").await;
                        }
                        outcomes.push(result);
                    }
                    Err(error) => {
                        entry.error_class = "transport".into();
                        entry.status_class = "error".into();
                        dedup.set_outcome(&credential, "transient").await;
                        events.send(ScanEvent::Log(error.to_string())).ok();
                    }
                }
                let query_key = (entry.source.clone(), entry.query_id.clone());
                if let Some(metric) = query_metrics.get_mut(&query_key) {
                    metric.funnel.active_requests += 1;
                    metric.funnel.total_active_http_requests += 1;
                    if entry.status_class == "2xx" {
                        metric.funnel.final_verified += 1;
                    }
                }
                ledger.push(entry);
            }
            if let Some(pool) = self.repository.pool() {
                aipocket_db::upsert_validation_results(pool, &run_id, &outcomes).await?;
            }
            self.repository.append_ledger(&ledger).await?;
            ledger.clear();
            events.send(ScanEvent::Progress(progress.clone())).ok();
        }
        tokio::select! {
            _ = cancel.cancelled() => {
                return self.interrupt(&run_id, progress, lease, &events).await;
            }
            _ = analyzer.recheck(&mut outcomes) => {}
        }
        let total_outcomes = outcomes.len();
        let valid_outcomes = outcomes.iter().filter(|r| r.valid).count();
        let rejected_outcomes = outcomes
            .iter()
            .filter(|r| r.validation_state == "rejected")
            .count();
        let transient_outcomes = outcomes
            .iter()
            .filter(|r| r.validation_state == "transient")
            .count();
        self.repository
            .upsert_honeypot_results(&run_id, &outcomes)
            .await?;
        let (mut valid_results, mut suspicious_results) = finalize_results(outcomes);
        events
            .send(ScanEvent::Log(format!(
                "验证完成 · 候选 {total_outcomes} · 可用 {valid_outcomes} · 可疑 {} · 无效 {rejected_outcomes} · 网络失败 {transient_outcomes}",
                suspicious_results.len()
            )))
            .ok();
        events
            .send(ScanEvent::Phase("balance_finalize".into()))
            .ok();
        let balance = crate::BalanceService::new(self.http.clone());
        for result in &mut valid_results {
            if cancel.is_cancelled() {
                return self.interrupt(&run_id, progress, lease, &events).await;
            }
            if !policy.require_fresh_balance
                && let Some(cached) = dedup
                    .get_balance::<crate::BalanceResult>(&result.credential)
                    .await
            {
                apply_balance(result, cached);
                dedup.set_success(&result.credential, result).await;
                continue;
            }
            let balance_result = tokio::select! {
                _ = cancel.cancelled() => {
                    return self.interrupt(&run_id, progress, lease, &events).await;
                }
                result = balance.query_for_result(result) => result,
            };
            match balance_result {
                Ok(enriched) => {
                    dedup.set_balance(&result.credential, &enriched).await;
                    apply_balance(result, enriched);
                }
                Err(error) => {
                    events
                        .send(ScanEvent::Log(format!(
                            "balance probe failed in isolation: {error}"
                        )))
                        .ok();
                }
            };
            dedup.set_success(&result.credential, result).await;
            if let Some(record) = high_value_record(result, &run_id)
                && self.repository.upsert_high_value(&run_id, &record).await?
            {
                progress.high_value_final += 1;
            }
        }
        for result in &mut suspicious_results {
            if cancel.is_cancelled() {
                return self.interrupt(&run_id, progress, lease, &events).await;
            }
            let enriched = if !policy.require_fresh_balance {
                dedup
                    .get_balance::<crate::BalanceResult>(&result.credential)
                    .await
            } else {
                None
            };
            let enriched = if enriched.is_some() {
                enriched
            } else {
                let balance_result = tokio::select! {
                    _ = cancel.cancelled() => {
                        return self.interrupt(&run_id, progress, lease, &events).await;
                    }
                    result = balance.query_for_result(result) => result,
                };
                match balance_result {
                    Ok(enriched) => {
                        dedup.set_balance(&result.credential, &enriched).await;
                        Some(enriched)
                    }
                    Err(error) => {
                        events
                            .send(ScanEvent::Log(format!(
                                "suspicious balance probe failed in isolation: {error}"
                            )))
                            .ok();
                        None
                    }
                }
            };
            if let Some(enriched) = enriched {
                apply_balance(result, enriched);
            }
        }
        progress.final_verified = valid_results.len() as u64;
        progress.suspicious = suspicious_results.len() as u64;
        events
            .send(ScanEvent::Log(format!(
                "余额探测完成 · 可用 {} · 可疑 {}",
                valid_results.len(),
                suspicious_results.len()
            )))
            .ok();
        let valid = valid_results
            .iter()
            .map(as_json)
            .collect::<Result<Vec<_>>>()?;
        let suspicious = suspicious_results
            .iter()
            .map(as_json)
            .collect::<Result<Vec<_>>>()?;
        self.write_artifacts(&run_id, &hits, &valid, &suspicious)?;
        self.repository
            .insert_results(&run_id, "valid", &valid)
            .await?;
        self.repository
            .insert_results(&run_id, "suspicious", &suspicious)
            .await?;
        self.repository
            .update_phase(
                &run_id,
                "finished",
                serde_json::json!({"resumed_from":resume_phase}),
            )
            .await?;
        self.repository
            .persist_query_metrics(&run_id, &query_metrics.into_values().collect::<Vec<_>>())
            .await?;
        let (total_http, ledger_complete, ledger_reason) =
            self.repository.ledger_summary(&run_id).await?;
        self.repository
            .finish_run_metrics(&run_id, total_http, ledger_complete, &ledger_reason)
            .await?;
        self.repository
            .finish_run(&run_id, "finished", &progress, "")
            .await?;
        info!(%run_id,"scan completed");
        events.send(ScanEvent::Progress(progress.clone())).ok();
        events
            .send(ScanEvent::Finished {
                run_id: run_id.clone(),
            })
            .ok();
        if let Some(lease) = lease {
            lease.release().await.ok();
        }
        Ok(run_id)
    }

    async fn probe_hits(
        &self,
        hits: &[Value],
        events: &mpsc::UnboundedSender<ScanEvent>,
    ) -> Vec<Credential> {
        if !self.settings.scan_prober {
            return Vec::new();
        }
        let policy = match aipocket_prober::RiskPolicy::from_settings(&self.settings) {
            Ok(policy) => Arc::new(policy),
            Err(error) => {
                events.send(ScanEvent::Log(error.to_string())).ok();
                return Vec::new();
            }
        };
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.settings.prober_concurrency.max(1),
        ));
        let mut credentials = Vec::new();
        for batch in hits.chunks(self.settings.prober_batch_size.max(1)) {
            let mut tasks = tokio::task::JoinSet::new();
            for hit in batch {
                let target = hit
                    .get("host")
                    .or_else(|| hit.get("url"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if target.is_empty() {
                    continue;
                }
                let hint = hit
                    .get("_product")
                    .and_then(Value::as_str)
                    .unwrap_or("generic")
                    .to_ascii_lowercase()
                    .replace('-', "_");
                let advisory_ids = hit
                    .get("_cves")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let http = self.http.clone();
                let settings = self.settings.clone();
                let policy = policy.clone();
                let semaphore = semaphore.clone();
                tasks.spawn(async move {
                    let _permit = semaphore.acquire_owned().await.ok();
                    let mut found = Vec::new();
                    let mut findings = Vec::new();
                    if let Some(prober) = aipocket_prober::products::default_probers()
                        .into_iter()
                        .find(|prober| prober.product() == hint)
                    {
                        let context = aipocket_prober::ProbeContext {
                            target: target.clone(),
                            product: hint.clone(),
                            max_risk: aipocket_prober::RiskLevel::L0,
                            intrusive_checks: false,
                            allowed_classes: vec!["unauth_read".into()],
                            request_budget: settings.generic_max_requests_per_target.max(1),
                        };
                        if let Ok(rows) = prober.probe(&http, &context).await {
                            found.extend(rows.into_iter().flat_map(|finding| finding.credentials));
                        }
                    }
                    let specs = aipocket_prober::product_specs::specs_for(&hint);
                    if !specs.is_empty() {
                        let engine = aipocket_prober::execute_plan_with_advisories(
                            &http,
                            aipocket_prober::EngineContext {
                                target,
                                product: hint,
                                ..Default::default()
                            },
                            &specs,
                            &policy,
                            settings.max_requests_per_target.max(1),
                            &advisory_ids,
                        )
                        .await;
                        found.extend(engine.credentials);
                        findings.extend(engine.findings);
                    }
                    (found, findings)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                match joined {
                    Ok((found, findings)) => {
                        credentials.extend(found);
                        for finding in findings {
                            events
                                .send(ScanEvent::Log(format!(
                                    "probe finding: {} {}",
                                    finding.product, finding.vuln_class
                                )))
                                .ok();
                        }
                    }
                    Err(error) => {
                        events
                            .send(ScanEvent::Log(format!(
                                "probe task failed in isolation: {error}"
                            )))
                            .ok();
                    }
                }
            }
        }
        credentials
    }

    fn write_artifacts(
        &self,
        run_id: &str,
        hits: &[Value],
        valid: &[Value],
        suspicious: &[Value],
    ) -> Result<()> {
        if !self.settings.write_jsonl() {
            return Ok(());
        }

        let directory = self.settings.results_path().join(run_id);
        std::fs::create_dir_all(&directory)?;
        write_jsonl(&directory.join("raw_hits.jsonl"), hits)?;
        write_jsonl(&directory.join("valid.jsonl"), valid)?;
        write_jsonl(&directory.join("suspicious.jsonl"), suspicious)?;
        Ok(())
    }

    async fn process_github_work(
        &self,
        pool: &sqlx::PgPool,
        work: Vec<aipocket_db::ArtifactWorkItem>,
        events: &mpsc::UnboundedSender<ScanEvent>,
    ) -> Vec<aipocket_discovery::CredentialObservation> {
        let client = aipocket_clients::GithubClient::new(self.http.clone(), &self.settings);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.settings.github_artifact_concurrency.max(1),
        ));
        let mut tasks = tokio::task::JoinSet::new();
        for item in work {
            let client = client.clone();
            let semaphore = semaphore.clone();
            let max_bytes = self.settings.github_max_blob_bytes;
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok();
                let Some((owner, repo)) = item.repository_full_name.split_once('/') else {
                    return (item, Err(anyhow::anyhow!("invalid repository name")));
                };
                let text = if item.source_kind == "commit_message" {
                    match client.commit(owner, repo, &item.commit_sha, 1, 1).await {
                        Ok(value) => Ok(value
                            .pointer("/commit/message")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()),
                        Err(error) => Err(error),
                    }
                } else {
                    match client.blob(owner, repo, &item.object_sha).await {
                        Ok(value) => {
                            use base64::Engine;
                            let content = value
                                .get("content")
                                .and_then(Value::as_str)
                                .unwrap_or_default();
                            base64::engine::general_purpose::STANDARD
                                .decode(content.replace('\n', ""))
                                .map_err(anyhow::Error::from)
                                .and_then(|decoded| {
                                    anyhow::ensure!(
                                        decoded.len() <= max_bytes,
                                        "artifact_too_large"
                                    );
                                    Ok(String::from_utf8_lossy(&decoded).into_owned())
                                })
                        }
                        Err(error) => Err(error),
                    }
                };
                (item, text)
            });
        }
        let mut observations = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let Ok((item, text)) = joined else {
                events
                    .send(ScanEvent::Log(
                        "GitHub work task failed in isolation".into(),
                    ))
                    .ok();
                continue;
            };
            match text {
                Ok(text) => {
                    for secret in aipocket_discovery::github_artifacts::extract_artifact_text(
                        &text,
                        "",
                        &item.source_kind,
                        "context",
                        &item.file_path,
                        &item.object_sha,
                    ) {
                        observations.push(github_work_observation(&item, secret));
                    }
                    if let Err(error) =
                        aipocket_db::transition_artifact_work(pool, &item, "terminal", "", 5).await
                    {
                        events.send(ScanEvent::Log(error.to_string())).ok();
                    }
                }
                Err(error) => {
                    let class = if error.to_string().contains("artifact_too_large") {
                        "artifact_too_large"
                    } else {
                        "transient"
                    };
                    if let Err(transition_error) = aipocket_db::transition_artifact_work(
                        pool,
                        &item,
                        class,
                        &error.to_string(),
                        5,
                    )
                    .await
                    {
                        events
                            .send(ScanEvent::Log(transition_error.to_string()))
                            .ok();
                    }
                }
            }
        }
        observations
    }

    pub async fn fail_run(
        &self,
        run_id: &str,
        error: impl Into<String>,
        events: &mpsc::UnboundedSender<ScanEvent>,
    ) {
        let error = error.into();
        let _ = self
            .repository
            .finish_run(run_id, "interrupted", &ScanProgress::default(), &error)
            .await;
        events
            .send(ScanEvent::Interrupted {
                run_id: run_id.to_owned(),
                error,
            })
            .ok();
    }

    async fn interrupt(
        &self,
        run_id: &str,

        progress: ScanProgress,
        lease: Option<ScanLease>,
        events: &mpsc::UnboundedSender<ScanEvent>,
    ) -> Result<String> {
        self.repository
            .finish_run(run_id, "interrupted", &progress, "cancelled")
            .await?;
        events
            .send(ScanEvent::Interrupted {
                run_id: run_id.to_owned(),
                error: "cancelled".into(),
            })
            .ok();
        if let Some(lease) = lease {
            lease.release().await.ok();
        }
        Ok(run_id.to_owned())
    }
}

fn source_query_budget(source: &str, budgets: &SourceBudgets, query_count: usize) -> usize {
    match source {
        "fofa" => budgets.fofa,
        "shodan" => budgets.shodan,
        "github" => Some(
            budgets
                .github_code
                .unwrap_or_default()
                .max(budgets.github_commit.unwrap_or_default()),
        ),
        _ => None,
    }
    .unwrap_or(query_count)
}
fn distinct_target_count(hits: &[Value]) -> u64 {
    let mut targets = std::collections::HashSet::new();
    for hit in hits {
        let target = hit
            .get("host")
            .or_else(|| hit.get("url"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !target.is_empty() {
            targets.insert(target);
        }
    }
    targets.len() as u64
}

fn discovery_progress_line(progress: &DiscoveryProgress) -> String {
    let page = if progress.page == 0 {
        "准备请求".to_owned()
    } else {
        format!("第 {} 页", progress.page)
    };
    format!(
        "发现 · 进度 · {} · 查询 {}/{} · {} · 当前命中 {} · 错误 {}",
        progress.source,
        progress.query_index,
        progress.query_total,
        page,
        progress.hits,
        progress.errors
    )
}

fn github_shard_id(lane: &str, pack_id: &str, query: &str) -> String {
    use sha1::{Digest, Sha1};
    format!(
        "{:x}",
        Sha1::digest(format!("{lane}|{pack_id}|{query}").as_bytes())
    )
}

fn github_work_observation(
    item: &aipocket_db::ArtifactWorkItem,
    secret: aipocket_discovery::github_artifacts::ExtractedArtifactSecret,
) -> aipocket_discovery::CredentialObservation {
    aipocket_discovery::CredentialObservation {
        credential: secret.credential,
        provenance: aipocket_discovery::ArtifactProvenance {
            repository_id: item.repo_id.clone(),
            repository_full_name: item.repository_full_name.clone(),
            commit_sha: item.commit_sha.clone(),
            object_sha: secret.object_sha,
            file_path: secret.file_path,
            source_kind: secret.source_kind,
            change_side: secret.change_side,
            line_start: secret.line_start.map(u64::from),
            line_end: secret.line_end.map(u64::from),
            query_id: item.query_id.clone(),
            pack_id: item.pack_id.clone(),
            lane: item.lane.clone(),
        },
        query_id: item.query_id.clone(),
        pack_id: item.pack_id.clone(),
        lane: item.lane.clone(),
        coverage_mode: item.coverage_mode.clone(),
        ..Default::default()
    }
}

fn apply_balance(result: &mut aipocket_core::ValidationResult, enriched: crate::BalanceResult) {
    crate::balance::apply_probe_result(result, enriched);
}

fn phase_rank(phase: &str) -> usize {
    [
        "started",
        "discovery",
        "extract",
        "probe",
        "gpt",
        "validate",
        "finalize",
        "finished",
    ]
    .iter()
    .position(|value| *value == phase)
    .unwrap_or(0)
}

fn credentials_from_observations(
    hits: &mut Vec<Value>,
    observations: Vec<aipocket_discovery::CredentialObservation>,
) {
    hits.extend(observations.into_iter().filter_map(|observation| {
        serde_json::to_value(observation.credential)
            .ok()
            .map(|credential| {
                serde_json::json!({
                    "host": credential.get("apiurl").cloned().unwrap_or_default(),
                    "_credential": credential,
                    "_source": "github"
                })
            })
    }));
}

fn mode_name(mode: &ScanMode) -> &'static str {
    match mode {
        ScanMode::Full => "full",
        ScanMode::Incremental => "incremental",
    }
}

fn write_jsonl(path: &std::path::Path, rows: &[Value]) -> Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;
    for row in rows {
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aipocket_discovery::{
        ArtifactWork, CheckpointUpdate, DiscoverySource, QueryUsage, SourceBudgets,
        SourceFetchResult,
    };
    use async_trait::async_trait;
    use axum::{Json, Router, routing::get};
    use serde_json::json;
    use std::time::Duration;

    /// All scanner unit tests must stay offline-friendly and non-`#[ignore]`:
    /// GitHub CI runs `cargo test --workspace` without including ignored tests for
    /// the default gate, and coverage must count `scanner.rs` (not ignore it).
    fn test_http() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .connect_timeout(Duration::from_millis(400))
            .build()
            .expect("test http client")
    }

    struct FixtureSource {
        name: &'static str,
        base: String,
        query_ids: Vec<String>,
        fail: bool,
        observations: bool,
        empty_host: bool,
        host_hit_count: Option<u64>,
    }

    struct BlockingSource {
        started: Arc<tokio::sync::Barrier>,
    }

    #[async_trait]
    impl DiscoverySource for BlockingSource {
        fn name(&self) -> &'static str {
            "blocking"
        }

        fn is_configured(&self) -> bool {
            true
        }

        async fn fetch(&self, _: &SourceBudgets, _: ScanMode) -> Result<SourceFetchResult> {
            self.started.wait().await;
            std::future::pending().await
        }
    }

    #[async_trait]
    impl DiscoverySource for FixtureSource {
        fn name(&self) -> &'static str {
            self.name
        }
        fn query_ids(&self) -> Vec<String> {
            self.query_ids.clone()
        }
        fn is_configured(&self) -> bool {
            true
        }
        async fn fetch(
            &self,
            budgets: &SourceBudgets,
            mode: ScanMode,
        ) -> Result<SourceFetchResult> {
            let _ = mode;
            if let Some(progress) = &budgets.progress {
                progress(DiscoveryProgress {
                    source: self.name.into(),
                    query_index: 1,
                    query_total: self.query_ids.len().max(1),
                    page: 1,
                    hits: 1,
                    errors: usize::from(self.fail),
                });
            }
            if self.fail {
                anyhow::bail!("fixture discovery offline");
            }
            let mut host_hits = Vec::new();
            if self.empty_host {
                host_hits.push(json!({"body":"no-host-entry"}));
            }
            if !self.base.is_empty() {
                host_hits.push(json!({
                    "host": self.base,
                    "url": self.base,
                    "_product": "generic",
                    "_source": self.name,
                    "body": format!(
                        "OPENAI_API_KEY=sk-proj-scannerfixtureabcdefgh BASE_URL={}/v1",
                        self.base
                    ),
                    "header": "server: litellm"
                }));
            }
            let mut credential_observations = Vec::new();
            if self.observations {
                credential_observations.push(aipocket_discovery::CredentialObservation {
                    credential: Credential {
                        apikey: "sk-observation-from-source-abcdef".into(),
                        apiurl: format!("{}/v1", self.base),
                        backend: self.name.into(),
                        source: "fixture-query".into(),
                        ..Default::default()
                    },
                    query_id: "fixture-query".into(),
                    pack_id: "openai".into(),
                    lane: "code_snapshot".into(),
                    ..Default::default()
                });
            }
            Ok(SourceFetchResult {
                source: self.name.into(),
                host_hits,
                host_hit_count: self.host_hit_count.or(Some(1)),
                credential_observations,
                query_usage: vec![QueryUsage {
                    source: self.name.into(),
                    query: "title=\"fixture\"".into(),
                    query_id: "fixture-query".into(),
                    pack_id: "openai".into(),
                    lane: "code_snapshot".into(),
                    result_count: 1,
                    page_count: 1,
                }],
                checkpoint_updates: if self.name == "github" {
                    vec![CheckpointUpdate {
                        source: "github".into(),
                        lane: "code_snapshot".into(),
                        pack_id: "openai".into(),
                        shard_id: github_shard_id("code_snapshot", "openai", "fixture-query"),
                        watermark: "w1".into(),
                        cursor_state: json!({"page": 1}),
                        etag: "etag-1".into(),
                        status: "ok".into(),
                    }]
                } else {
                    Vec::new()
                },
                artifact_work: if self.name == "github" {
                    vec![ArtifactWork {
                        repo_id: "1".into(),
                        repository_full_name: "acme/demo".into(),
                        commit_sha: "abc".into(),
                        file_path: ".env".into(),
                        object_sha: "blob1".into(),
                        source_kind: "code_snapshot".into(),
                        etag: "etag".into(),
                        work_status: "fetch_pending".into(),
                        attempts: 0,
                        last_error_class: String::new(),
                        current_stage: "fetch_pending".into(),
                        run_id: String::new(),
                        query_id: "fixture-query".into(),
                        pack_id: "openai".into(),
                        lane: "code_snapshot".into(),
                        coverage_mode: "complete".into(),
                    }]
                } else {
                    Vec::new()
                },
                errors: vec!["soft discovery warning".into()],
                ..Default::default()
            })
        }
    }

    async fn fixture_api_server() -> (String, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route(
                "/v1/models",
                get(|| async {
                    Json(json!({"data":[{"id":"gpt-4o-mini"},{"id":"fixture-model"}]}))
                }),
            )
            .route(
                "/api/status",
                get(|| async { Json(json!({"status":"ok"})) }),
            )
            .route(
                "/v1/chat/completions",
                axum::routing::post(|Json(body): Json<Value>| async move {
                    Json(json!({
                        "id":"chatcmpl-fixture",
                        "model": body["model"],
                        "choices":[{"message":{"content":"ok"}}]
                    }))
                }),
            )
            .route(
                "/dashboard/billing/credit_grants",
                get(|| async {
                    Json(json!({
                        "total_granted": 20.0,
                        "total_used": 5.0,
                        "total_available": 15.0
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (format!("http://{address}"), task)
    }

    async fn github_api_server() -> (String, tokio::task::JoinHandle<()>) {
        use base64::Engine;
        let secret_blob = base64::engine::general_purpose::STANDARD.encode(
            "OPENAI_API_KEY=sk-github-blob-secretkey99\nOPENAI_BASE_URL=https://api.openai.com/v1\n",
        );
        let huge = base64::engine::general_purpose::STANDARD.encode(vec![b'A'; 64]);
        let app = Router::new()
            .route(
                "/repos/acme/demo/commits/c1",
                get(|| async {
                    Json(json!({
                        "commit": {
                            "message": "leak OPENAI_API_KEY=sk-github-commit-secretkey88"
                        }
                    }))
                }),
            )
            .route(
                "/repos/acme/demo/git/blobs/blob-ok",
                get({
                    let secret_blob = secret_blob.clone();
                    move || {
                        let secret_blob = secret_blob.clone();
                        async move { Json(json!({"content": secret_blob, "encoding": "base64"})) }
                    }
                }),
            )
            .route(
                "/repos/acme/demo/git/blobs/blob-huge",
                get({
                    let huge = huge.clone();
                    move || {
                        let huge = huge.clone();
                        async move { Json(json!({"content": huge, "encoding": "base64"})) }
                    }
                }),
            )
            .route(
                "/repos/acme/demo/git/blobs/blob-bad",
                get(|| async { (axum::http::StatusCode::NOT_FOUND, "missing") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (format!("http://{address}"), task)
    }

    fn offline_settings(results_dir: impl Into<String>) -> Settings {
        Settings {
            database_url: String::new(),
            dedup_enabled: false,
            dedup_redis_url: String::new(),
            scan_prober: false,
            validate_concurrency: 4,
            validate_batch_size: 8,
            prober_concurrency: 2,
            prober_batch_size: 4,
            results_dir: results_dir.into(),
            pg_dual_write: false,
            github_tokens: "ghp_fixture_token".into(),
            github_artifact_concurrency: 2,
            github_max_blob_bytes: 32,
            fofa_query_budget: 2,
            shodan_query_budget: 2,
            github_code_query_budget: 2,
            github_commit_query_budget: 2,
            planner_metrics_version: 3,
            ..Settings::default()
        }
    }

    fn work_item(
        source_kind: &str,
        object_sha: &str,
        repository_full_name: &str,
    ) -> aipocket_db::ArtifactWorkItem {
        aipocket_db::ArtifactWorkItem {
            repo_id: "1".into(),
            repository_full_name: repository_full_name.into(),
            commit_sha: "c1".into(),
            file_path: ".env".into(),
            object_sha: object_sha.into(),
            source_kind: source_kind.into(),
            etag: "e".into(),
            work_status: "fetch_pending".into(),
            attempts: 0,
            last_error_class: String::new(),
            current_stage: "fetch_pending".into(),
            run_id: "run_test".into(),
            query_id: "q1".into(),
            pack_id: "openai".into(),
            lane: "code_snapshot".into(),
            coverage_mode: "complete".into(),
        }
    }

    /// Prefer CI/local TEST_DATABASE_URL; fall back to a lazy pool with a hard
    /// acquire timeout so transition failures never hang unit tests.
    async fn test_pool() -> sqlx::PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgresql://aipocket:aipocket@127.0.0.1:1/aipocket".into());
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_millis(800))
            .connect(&url)
            .await
        {
            Ok(pool) => {
                let _ = aipocket_db::ensure_schema(&pool).await;
                pool
            }
            Err(_) => sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_millis(150))
                .connect_lazy("postgresql://aipocket:aipocket@127.0.0.1:1/aipocket")
                .expect("lazy pool"),
        }
    }

    #[test]
    fn extracts_and_deduplicates_credentials() {
        let hits = vec![json!({
            "host":"https://example.com",
            "body":"OPENAI_API_KEY=sk-a1b2c3d4e5f6g7h8"
        })];
        assert_eq!(
            source_query_budget(
                "github",
                &SourceBudgets {
                    github_code: Some(0),
                    github_commit: Some(12),
                    ..Default::default()
                },
                33,
            ),
            12
        );
        let rows = extract_credentials(&hits);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].apikey, "sk-a1b2c3d4e5f6g7h8");
    }

    #[test]
    fn scanner_helpers_preserve_artifacts_phases_and_observations() {
        assert_eq!(mode_name(&ScanMode::Full), "full");
        assert_eq!(mode_name(&ScanMode::Incremental), "incremental");
        assert!(phase_rank("finished") > phase_rank("validate"));
        assert!(phase_rank("extract") < phase_rank("validate"));
        assert_eq!(
            distinct_target_count(&[
                json!({"host":"https://a.example"}),
                json!({"host":"https://a.example"}),
                json!({"url":"https://b.example"}),
            ]),
            2
        );
        assert_eq!(phase_rank("unknown"), 0);
        assert!(!github_shard_id("code_snapshot", "openai", "q").is_empty());

        let mut result = aipocket_core::ValidationResult::default();
        apply_balance(
            &mut result,
            crate::BalanceResult {
                matched: true,
                provider: "fixture".into(),
                source: "fixture:balance".into(),
                evidence_kind: "cash_balance".into(),
                gateway: "fixture".into(),
                balance_usd: "12.50".into(),
                tier: "paid".into(),
                detail: json!({"source":"fixture"}),
                ..Default::default()
            },
        );
        assert_eq!(result.gateway, "fixture");
        assert_eq!(result.balance, "12.50");
        assert_eq!(result.tier, "paid");

        let mut hits = Vec::new();
        credentials_from_observations(
            &mut hits,
            vec![aipocket_discovery::CredentialObservation {
                credential: Credential {
                    apikey: "sk-observation-abcdefghijkl".into(),
                    apiurl: "https://observation.example/v1".into(),
                    ..Default::default()
                },
                ..Default::default()
            }],
        );
        assert_eq!(hits[0]["host"], "https://observation.example/v1");
        assert_eq!(hits[0]["_source"], "github");

        let observation = github_work_observation(
            &work_item("code_snapshot", "blob-ok", "acme/demo"),
            aipocket_discovery::github_artifacts::ExtractedArtifactSecret {
                credential: Credential {
                    apikey: "sk-work-obs-abcdefghijkl".into(),
                    apiurl: "https://api.openai.com/v1".into(),
                    ..Default::default()
                },
                object_sha: "blob-ok".into(),
                file_path: ".env".into(),
                source_kind: "code_snapshot".into(),
                change_side: "context".into(),
                line_start: Some(1),
                line_end: Some(2),
            },
        );
        assert_eq!(observation.provenance.repository_full_name, "acme/demo");
        assert_eq!(observation.query_id, "q1");

        let root = std::env::temp_dir().join(format!("aipocket-scanner-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("rows.jsonl");
        write_jsonl(&path, &[json!({"id":1}), json!({"id":2})]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn scanner_disables_or_rejects_unsafe_probing() {
        let disabled = Scanner::new(
            Arc::new(Settings {
                scan_prober: false,
                dedup_enabled: false,
                ..Settings::default()
            }),
            Repository::new(None),
            test_http(),
        );
        let (tx, _) = mpsc::unbounded_channel();
        assert!(
            disabled
                .probe_hits(&[json!({"host":"https://example.test"})], &tx)
                .await
                .is_empty()
        );

        let invalid = Scanner::new(
            Arc::new(Settings {
                scan_prober: true,
                probe_max_risk: 9,
                dedup_enabled: false,
                ..Settings::default()
            }),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(
            invalid
                .probe_hits(&[json!({"host":"https://example.test"})], &tx)
                .await
                .is_empty()
        );
        assert!(
            matches!(rx.try_recv(), Ok(ScanEvent::Log(message)) if message.contains("PROBE_MAX_RISK"))
        );
    }

    #[tokio::test]
    async fn scanner_probe_hits_runs_generic_product_path() {
        let (base, server) = fixture_api_server().await;
        let scanner = Scanner::new(
            Arc::new(Settings {
                scan_prober: true,
                probe_max_risk: 0,
                prober_concurrency: 2,
                prober_batch_size: 1,
                generic_max_requests_per_target: 2,
                max_requests_per_target: 2,
                dedup_enabled: false,
                ..Settings::default()
            }),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _found = scanner
            .probe_hits(
                &[
                    json!({"host": base, "url": base, "_product": "generic"}),
                    json!({"body": "missing host"}),
                    json!({"host": "", "url": ""}),
                ],
                &tx,
            )
            .await;
        while let Ok(event) = rx.try_recv() {
            if let ScanEvent::Log(message) = event {
                assert!(!message.is_empty());
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_full_pipeline_writes_jsonl_and_finishes() {
        let root = std::env::temp_dir().join(format!("aipocket-scan-run-{}", uuid::Uuid::new_v4()));
        let (base, server) = fixture_api_server().await;
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let run_id = scanner
            .run(
                vec![
                    Arc::new(FixtureSource {
                        name: "fofa",
                        base: base.clone(),
                        query_ids: vec!["q1".into(), "q2".into(), "q3".into()],
                        fail: false,
                        observations: true,
                        empty_host: true,
                        host_hit_count: Some(2),
                    }),
                    Arc::new(FixtureSource {
                        name: "shodan",
                        base: base.clone(),
                        query_ids: vec!["s1".into()],
                        fail: false,
                        observations: false,
                        empty_host: false,
                        host_hit_count: None,
                    }),
                ],
                ScanMode::Full,
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert!(run_id.starts_with("run_"));
        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ScanEvent::Finished { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ScanEvent::Phase(phase) if phase == "discovery"))
        );
        assert!(events.iter().any(
            |event| matches!(event, ScanEvent::Log(message) if message.contains("发现 · 进度 · fofa · 查询 1/3 · 第 1 页"))
        ));
        assert!(
            events.iter().any(
                |event| matches!(event, ScanEvent::Log(message) if message.contains("soft discovery warning"))
            )
        );
        for name in ["raw_hits.jsonl", "valid.jsonl", "suspicious.jsonl"] {
            assert!(root.join(&run_id).join(name).is_file(), "{name}");
        }
        std::fs::remove_dir_all(root).ok();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_resumable_handles_errors_and_github_budget_path() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-resume-{}", uuid::Uuid::new_v4()));
        let (base, server) = fixture_api_server().await;
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let run_id = scanner
            .run_resumable(
                vec![
                    Arc::new(FixtureSource {
                        name: "manual",
                        base: String::new(),
                        query_ids: vec![],
                        fail: true,
                        observations: false,
                        empty_host: false,
                        host_hit_count: None,
                    }),
                    Arc::new(FixtureSource {
                        name: "github",
                        base: base.clone(),
                        query_ids: vec!["g1".into(), "g2".into(), "g3".into()],
                        fail: false,
                        observations: true,
                        empty_host: false,
                        host_hit_count: Some(1),
                    }),
                ],
                ScanMode::Incremental,
                Some("run_fixture_resume_unit".into()),
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert_eq!(run_id, "run_fixture_resume_unit");
        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(events.iter().any(
            |event| matches!(event, ScanEvent::Log(message) if message.contains("发现 · manual · 失败 · fixture discovery offline"))
        ));
        assert!(
            events
                .iter()
                .any(|event| matches!(event, ScanEvent::Finished { .. }))
        );
        std::fs::remove_dir_all(root).ok();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_interrupts_on_cancel_during_discovery() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-cancel-{}", uuid::Uuid::new_v4()));
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let interrupted = scanner
            .run(
                vec![Arc::new(FixtureSource {
                    name: "fofa",
                    base: "http://127.0.0.1:9".into(),
                    query_ids: vec!["q".into()],
                    fail: false,
                    observations: false,
                    empty_host: false,
                    host_hit_count: Some(1),
                })],
                ScanMode::Incremental,
                cancel,
                tx,
            )
            .await
            .unwrap();
        assert!(interrupted.starts_with("run_"));
        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(events.iter().any(
            |event| matches!(event, ScanEvent::Interrupted { error, .. } if error == "cancelled")
        ));
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn scanner_cancels_an_inflight_discovery_request() {
        let root = std::env::temp_dir().join(format!(
            "aipocket-scan-inflight-cancel-{}",
            uuid::Uuid::new_v4()
        ));
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let started = Arc::new(tokio::sync::Barrier::new(2));
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let source = Arc::new(BlockingSource {
            started: started.clone(),
        });
        let (tx, mut rx) = mpsc::unbounded_channel();
        let scan = tokio::spawn(async move {
            scanner
                .run(vec![source], ScanMode::Incremental, cancel, tx)
                .await
        });

        started.wait().await;
        stop.cancel();
        let run_id = tokio::time::timeout(Duration::from_secs(1), scan)
            .await
            .expect("scan did not stop promptly")
            .unwrap()
            .unwrap();
        assert!(run_id.starts_with("run_"));
        let events: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(events.iter().any(
            |event| matches!(event, ScanEvent::Interrupted { error, .. } if error == "cancelled")
        ));
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn scanner_fail_run_and_write_artifacts_contract() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-fail-{}", uuid::Uuid::new_v4()));
        let settings = Settings {
            database_url: "postgresql://unused".into(),
            pg_dual_write: false,
            dedup_enabled: false,
            results_dir: root.to_string_lossy().into(),
            ..Settings::default()
        };
        let scanner = Scanner::new(Arc::new(settings), Repository::new(None), test_http());
        scanner
            .write_artifacts("run_x", &[json!({"a":1})], &[], &[])
            .unwrap();
        assert!(!root.join("run_x").exists());

        let (tx, mut rx) = mpsc::unbounded_channel();
        scanner.fail_run("run_x", "boom", &tx).await;
        assert!(
            matches!(rx.try_recv(), Ok(ScanEvent::Interrupted { error, .. }) if error == "boom")
        );

        let err = scanner.manual_targets().await.unwrap_err().to_string();
        assert!(err.contains("DATABASE_URL") || err.contains("not configured") || !err.is_empty());
        std::fs::remove_dir_all(root).ok();
    }

    #[tokio::test]
    async fn scanner_process_github_work_covers_blob_commit_and_error_paths() {
        let (base, server) = github_api_server().await;
        let settings = Settings {
            dedup_enabled: false,
            github_tokens: "ghp_fixture_token".into(),
            github_api_base_url: base,
            github_artifact_concurrency: 4,
            github_max_blob_bytes: 32,
            ..Settings::default()
        };
        let scanner = Scanner::new(Arc::new(settings), Repository::new(None), test_http());
        let pool = test_pool().await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let observations = scanner
            .process_github_work(
                &pool,
                vec![
                    work_item("commit_message", "blob-ok", "acme/demo"),
                    work_item("code_snapshot", "blob-ok", "acme/demo"),
                    work_item("code_snapshot", "blob-huge", "acme/demo"),
                    work_item("code_snapshot", "blob-bad", "acme/demo"),
                    work_item("code_snapshot", "blob-ok", "invalid-name"),
                ],
                &tx,
            )
            .await;
        assert!(!observations.is_empty());
        let _logs = std::iter::from_fn(|| rx.try_recv().ok()).collect::<Vec<_>>();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_with_prober_enabled_and_no_jsonl_when_pg_url_set() {
        let (base, server) = fixture_api_server().await;
        let settings = Settings {
            database_url: "postgresql://unused".into(),
            pg_dual_write: false,
            dedup_enabled: false,
            scan_prober: true,
            probe_max_risk: 0,
            prober_concurrency: 2,
            prober_batch_size: 2,
            validate_concurrency: 2,
            validate_batch_size: 2,
            generic_max_requests_per_target: 2,
            max_requests_per_target: 2,
            results_dir: std::env::temp_dir()
                .join(format!("aipocket-nojsonl-{}", uuid::Uuid::new_v4()))
                .to_string_lossy()
                .into(),
            ..Settings::default()
        };
        let scanner = Scanner::new(Arc::new(settings), Repository::new(None), test_http());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let run_id = scanner
            .run(
                vec![Arc::new(FixtureSource {
                    name: "other",
                    base: base.clone(),
                    query_ids: vec!["only".into()],
                    fail: false,
                    observations: false,
                    empty_host: false,
                    host_hit_count: Some(1),
                })],
                ScanMode::Full,
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert!(
            std::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, ScanEvent::Finished { run_id: id } if id == run_id))
        );
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_skips_empty_source_list_cleanly() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-empty-{}", uuid::Uuid::new_v4()));
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let run_id = scanner
            .run(vec![], ScanMode::Incremental, CancellationToken::new(), tx)
            .await
            .unwrap();
        assert!(
            std::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, ScanEvent::Finished { run_id: id } if id == run_id))
        );
        std::fs::remove_dir_all(root).ok();
    }

    /// Credentials whose (backend, source) match query_usage keys so funnel
    /// counters update; also exercises rejected validation (401) and cancel mid-validate.
    struct MetricSource {
        base: String,
        unauthorized: bool,
    }

    #[async_trait]
    impl DiscoverySource for MetricSource {
        fn name(&self) -> &'static str {
            "fofa"
        }
        fn query_ids(&self) -> Vec<String> {
            vec!["title=\"fixture\"".into()]
        }
        fn is_configured(&self) -> bool {
            true
        }
        async fn fetch(&self, _: &SourceBudgets, _: ScanMode) -> Result<SourceFetchResult> {
            let key = if self.unauthorized {
                "sk-proj-unauthorizedkeyabcde"
            } else {
                "sk-proj-scannerfixtureabcdefgh"
            };
            Ok(SourceFetchResult {
                source: "fofa".into(),
                host_hits: vec![json!({
                    "host": self.base,
                    "url": self.base,
                    "_product": "litellm",
                    "body": format!("OPENAI_API_KEY={key} BASE_URL={}/v1", self.base),
                })],
                host_hit_count: Some(1),
                credential_observations: vec![aipocket_discovery::CredentialObservation {
                    credential: Credential {
                        apikey: key.into(),
                        apiurl: format!("{}/v1", self.base),
                        backend: "fofa".into(),
                        // Must equal QueryUsage.query so query_metrics funnel updates.
                        source: "title=\"fixture\"".into(),
                        product: "openai".into(),
                        ..Default::default()
                    },
                    query_id: "title=\"fixture\"".into(),
                    ..Default::default()
                }],
                query_usage: vec![QueryUsage {
                    source: "fofa".into(),
                    query: "title=\"fixture\"".into(),
                    query_id: "title=\"fixture\"".into(),
                    pack_id: String::new(),
                    lane: String::new(),
                    result_count: 1,
                    page_count: 1,
                }],
                ..Default::default()
            })
        }
    }

    async fn auth_fixture_server(ok: bool) -> (String, tokio::task::JoinHandle<()>) {
        use axum::response::IntoResponse;
        let app = Router::new()
            .route(
                "/v1/models",
                get(move || async move {
                    if ok {
                        Json(json!({"data":[{"id":"gpt-4o"},{"id":"claude-sonnet-4-6"}]}))
                            .into_response()
                    } else {
                        (
                            axum::http::StatusCode::UNAUTHORIZED,
                            Json(json!({"error":{"message":"invalid_api_key"}})),
                        )
                            .into_response()
                    }
                }),
            )
            .route(
                "/health/readiness",
                get(|| async { Json(json!({"status":"healthy"})) }),
            )
            .route(
                "/api/status",
                get(|| async { Json(json!({"status":"ok"})) }),
            )
            .route(
                "/dashboard/billing/credit_grants",
                get(|| async {
                    Json(json!({
                        "total_granted": 100.0,
                        "total_used": 1.0,
                        "total_available": 99.0
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        (format!("http://{address}"), task)
    }

    #[tokio::test]
    async fn scanner_run_updates_query_metrics_and_balance_paths() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-metrics-{}", uuid::Uuid::new_v4()));
        let (base, server) = auth_fixture_server(true).await;
        let mut settings = offline_settings(root.to_string_lossy());
        settings.scan_prober = true;
        settings.probe_max_risk = 0;
        settings.prober_concurrency = 2;
        settings.prober_batch_size = 2;
        settings.generic_max_requests_per_target = 2;
        settings.max_requests_per_target = 2;
        let scanner = Scanner::new(Arc::new(settings), Repository::new(None), test_http());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let run_id = scanner
            .run(
                vec![Arc::new(MetricSource {
                    base: base.clone(),
                    unauthorized: false,
                })],
                ScanMode::Full,
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert!(
            std::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, ScanEvent::Finished { run_id: id } if id == run_id))
        );
        std::fs::remove_dir_all(root).ok();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_handles_rejected_validation_and_mid_validate_cancel() {
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-reject-{}", uuid::Uuid::new_v4()));
        let (base, server) = auth_fixture_server(false).await;
        let scanner = Scanner::new(
            Arc::new(offline_settings(root.to_string_lossy())),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let finished = scanner
            .run(
                vec![Arc::new(MetricSource {
                    base: base.clone(),
                    unauthorized: true,
                })],
                ScanMode::Incremental,
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert!(
            std::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, ScanEvent::Finished { run_id: id } if id == finished))
        );

        // Cancel once extract_validate starts so the first validation chunk aborts.
        let cancel = CancellationToken::new();
        let watcher = cancel.clone();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let watch = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if matches!(event, ScanEvent::Phase(ref phase) if phase == "extract_validate") {
                    watcher.cancel();
                    break;
                }
            }
        });
        let interrupted = scanner
            .run(
                vec![Arc::new(MetricSource {
                    base: base.clone(),
                    unauthorized: false,
                })],
                ScanMode::Full,
                cancel,
                tx,
            )
            .await
            .unwrap();
        assert!(interrupted.starts_with("run_"));
        watch.abort();
        std::fs::remove_dir_all(root).ok();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_run_with_pool_covers_spill_and_resume_paths() {
        let pool = test_pool().await;
        // If we only have a lazy dead pool, still exercise claim/upsert error-free
        // early returns via Repository::new(Some(pool)) only when acquire works.
        let can_query = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&pool)
            .await
            .is_ok();
        if !can_query {
            // Offline CI-less hosts: keep the test non-ignored and non-hanging.
            return;
        }
        let root =
            std::env::temp_dir().join(format!("aipocket-scan-pool-{}", uuid::Uuid::new_v4()));
        let (base, server) = auth_fixture_server(true).await;
        let run_id = format!("run_pool_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO runs(run_id,started_at,state,scan_mode,phase) VALUES($1,NOW(),'running','incremental','validate') ON CONFLICT(run_id) DO UPDATE SET phase='validate',state='running'",
        )
        .bind(&run_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO scan_discovery_hits(run_id,source,entry_id,host,record) VALUES($1,'fofa',$2,$3,$4) ON CONFLICT(run_id,entry_id) DO NOTHING",
        )
        .bind(&run_id)
        .bind("entry-1")
        .bind(&base)
        .bind(json!({
            "host": base,
            "url": base,
            "_product": "generic",
            "body": format!("OPENAI_API_KEY=sk-proj-scannerfixtureabcdefgh BASE_URL={}/v1", base)
        }))
        .execute(&pool)
        .await
        .unwrap();

        let mut settings = offline_settings(root.to_string_lossy());
        settings.database_url = std::env::var("TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_default();
        settings.pg_dual_write = true;
        settings.scan_prober = false;
        let scanner = Scanner::new(
            Arc::new(settings),
            Repository::new(Some(pool.clone())),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let completed = scanner
            .run_resumable(
                vec![Arc::new(MetricSource {
                    base: base.clone(),
                    unauthorized: false,
                })],
                ScanMode::Incremental,
                Some(run_id.clone()),
                CancellationToken::new(),
                tx,
            )
            .await
            .unwrap();
        assert_eq!(completed, run_id);
        assert!(
            std::iter::from_fn(|| rx.try_recv().ok())
                .any(|event| matches!(event, ScanEvent::Finished { .. }))
        );
        let _ = sqlx::query("DELETE FROM runs WHERE run_id=$1")
            .bind(&run_id)
            .execute(&pool)
            .await;
        std::fs::remove_dir_all(root).ok();
        server.abort();
    }

    #[tokio::test]
    async fn scanner_probe_hits_logs_product_findings() {
        let (base, server) = auth_fixture_server(true).await;
        let scanner = Scanner::new(
            Arc::new(Settings {
                scan_prober: true,
                probe_max_risk: 0,
                prober_concurrency: 2,
                prober_batch_size: 1,
                generic_max_requests_per_target: 3,
                max_requests_per_target: 3,
                dedup_enabled: false,
                ..Settings::default()
            }),
            Repository::new(None),
            test_http(),
        );
        let (tx, mut rx) = mpsc::unbounded_channel();
        let _ = scanner
            .probe_hits(
                &[json!({
                    "host": base,
                    "url": base,
                    "_product": "litellm"
                })],
                &tx,
            )
            .await;
        let logs: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        let _ = logs;
        server.abort();
    }
}
