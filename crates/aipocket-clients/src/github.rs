use aipocket_core::Settings;
use anyhow::{Context, Result};
use reqwest::{Client, StatusCode, header};
use serde_json::Value;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[derive(Clone)]
pub struct GithubClient {
    http: Client,
    base_url: String,
    version: String,
    tokens: Vec<String>,
    next_token: Arc<AtomicUsize>,
    max_rate_limit_wait: Duration,
}
impl GithubClient {
    pub fn new(http: Client, settings: &Settings) -> Self {
        Self {
            http,
            base_url: settings.github_api_base_url.trim_end_matches('/').into(),
            version: settings.github_api_version.clone(),
            tokens: settings
                .github_token_list()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            next_token: Arc::new(AtomicUsize::new(0)),
            max_rate_limit_wait: Duration::from_secs_f64(
                settings.github_rate_limit_max_wait_seconds.max(0.0),
            ),
        }
    }
    fn request_with_token(&self, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{}", self.base_url, path))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("X-GitHub-Api-Version", &self.version)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header(header::USER_AGENT, "aipocket/0.1.0")
    }

    fn request(&self, path: &str) -> Result<reqwest::RequestBuilder> {
        let token = self
            .tokens
            .first()
            .context("GITHUB_TOKENS not configured")?;
        Ok(self.request_with_token(path, token))
    }

    async fn search(&self, path: &str, query: &str, page: usize, per_page: usize) -> Result<Value> {
        let token_count = self.tokens.len();
        anyhow::ensure!(token_count > 0, "GITHUB_TOKENS not configured");
        let start = self.next_token.fetch_add(1, Ordering::Relaxed) % token_count;
        let mut waited = false;
        'attempt: loop {
            let mut last_error = None;
            let mut final_wait = 0;
            for offset in 0..token_count {
                let token = &self.tokens[(start + offset) % token_count];
                let response = self
                    .request_with_token(path, token)
                    .query(&[
                        ("q", query),
                        ("page", &page.to_string()),
                        ("per_page", &per_page.to_string()),
                    ])
                    .send()
                    .await?;
                let status = response.status();
                let remaining = header_u64(&response, "x-ratelimit-remaining");
                let reset = header_u64(&response, "x-ratelimit-reset");
                let retry_after = header_u64(&response, "retry-after");
                let bytes = response.bytes().await?;
                if status.is_success() {
                    return serde_json::from_slice(&bytes).context("github search JSON");
                }
                let detail = response_preview(&bytes);
                last_error = Some(anyhow::anyhow!(
                    "github search status={status} remaining={} reset={} response={detail}",
                    remaining.map_or_else(|| "unknown".into(), |value| value.to_string()),
                    reset.map_or_else(|| "unknown".into(), |value| value.to_string()),
                ));
                if status != StatusCode::FORBIDDEN && status != StatusCode::TOO_MANY_REQUESTS {
                    break;
                }
                final_wait = retry_after
                    .or_else(|| reset.map(|value| value.saturating_sub(unix_now())))
                    .unwrap_or(0);
            }
            if !waited && final_wait > 0 {
                let duration = Duration::from_secs(final_wait.saturating_add(1));
                if duration <= self.max_rate_limit_wait {
                    tokio::time::sleep(duration).await;
                    waited = true;
                    continue 'attempt;
                }
            }
            return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("github search failed")));
        }
    }
    pub async fn rate_limit(&self) -> Result<Value> {
        let token_count = self.tokens.len();
        anyhow::ensure!(token_count > 0, "GITHUB_TOKENS not configured");
        let start = self.next_token.fetch_add(1, Ordering::Relaxed) % token_count;
        let mut failures = Vec::with_capacity(token_count);
        for offset in 0..token_count {
            let response = self
                .request_with_token("/rate_limit", &self.tokens[(start + offset) % token_count])
                .send()
                .await?;
            let status = response.status();
            let remaining = header_u64(&response, "x-ratelimit-remaining");
            let bytes = response.bytes().await?;
            if status.is_success() {
                return serde_json::from_slice(&bytes).context("github rate-limit JSON");
            }
            failures.push(format!(
                "token {}: status={status} remaining={} response={}",
                offset + 1,
                remaining.map_or_else(|| "unknown".into(), |value| value.to_string()),
                response_preview(&bytes)
            ));
        }
        anyhow::bail!(
            "github rate-limit check failed for all {token_count} token(s): {}",
            failures.join("; ")
        )
    }
    pub async fn search_code(&self, query: &str, page: usize, per_page: usize) -> Result<Value> {
        self.search("/search/code", query, page, per_page).await
    }
    pub async fn search_commits(&self, query: &str, page: usize, per_page: usize) -> Result<Value> {
        self.search("/search/commits", query, page, per_page).await
    }
    pub async fn commit(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        page: usize,
        per_page: usize,
    ) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/commits/{sha}"))?
            .query(&[
                ("page", page.to_string()),
                ("per_page", per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn blob(&self, owner: &str, repo: &str, sha: &str) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/git/blobs/{sha}"))?
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
    pub async fn file_history(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        page: usize,
        per_page: usize,
    ) -> Result<Value> {
        Ok(self
            .request(&format!("/repos/{owner}/{repo}/commits"))?
            .query(&[
                ("path", path),
                ("page", &page.to_string()),
                ("per_page", &per_page.to_string()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

fn header_u64(response: &reqwest::Response, name: &str) -> Option<u64> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn response_preview(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .take(500)
        .collect::<String>()
        .replace(['\r', '\n'], " ")
}
