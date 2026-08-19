use aipocket_core::Credential;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchSide {
    Added,
    Removed,
    Context,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchHunkLine {
    pub side: PatchSide,
    pub text: String,
    pub new_lineno: Option<u32>,
    pub old_lineno: Option<u32>,
}
pub fn parse_unified_patch(patch: &str) -> Vec<PatchHunkLine> {
    let hunk = Regex::new(r"^@@\s+-(\d+)(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@").unwrap();
    let mut old = None;
    let mut new = None;
    let mut out = Vec::new();
    for raw in patch.lines() {
        if raw.starts_with("---")
            || raw.starts_with("+++")
            || raw.starts_with("diff ")
            || raw.starts_with("index ")
            || raw.starts_with('\\')
        {
            continue;
        }
        if let Some(c) = hunk.captures(raw) {
            old = c.get(1).and_then(|v| v.as_str().parse().ok());
            new = c.get(2).and_then(|v| v.as_str().parse().ok());
            continue;
        }
        let (prefix, text) = raw
            .chars()
            .next()
            .map(|prefix| (prefix, &raw[prefix.len_utf8()..]))
            .unwrap_or((' ', ""));
        match prefix {
            '+' => {
                out.push(PatchHunkLine {
                    side: PatchSide::Added,
                    text: text.into(),
                    new_lineno: new,
                    old_lineno: None,
                });
                new = new.map(|v| v + 1)
            }
            '-' => {
                out.push(PatchHunkLine {
                    side: PatchSide::Removed,
                    text: text.into(),
                    new_lineno: None,
                    old_lineno: old,
                });
                old = old.map(|v| v + 1)
            }
            ' ' => {
                out.push(PatchHunkLine {
                    side: PatchSide::Context,
                    text: text.into(),
                    new_lineno: new,
                    old_lineno: old,
                });
                new = new.map(|v| v + 1);
                old = old.map(|v| v + 1)
            }
            _ => {}
        }
    }
    out
}
pub fn is_noise_artifact_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    let basename = p.rsplit('/').next().unwrap_or_default();
    if basename.starts_with(".env") {
        return false;
    }
    let dirs = [
        "/examples/",
        "/example/",
        "/samples/",
        "/sample/",
        "/fixtures/",
        "/fixture/",
        "/testdata/",
        "/test-data/",
        "/test_data/",
        "/mocks/",
        "/mock/",
        "/docs/",
        "/documentation/",
        "/changelog/",
    ];
    let padded = format!("/{}/", p.trim_matches('/'));
    dirs.iter().any(|marker| padded.contains(marker))
        || [
            "provider-catalog",
            "official-external-provider",
            "openclaw.plugin.json",
            "catalog.json",
            "catalog.toml",
        ]
        .iter()
        .any(|marker| p.contains(marker))
        || basename.ends_with(".md")
        || ["readme", "changelog", "license", "contributing"]
            .iter()
            .any(|name| basename.starts_with(name))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubLane {
    CommitMessage,
    CodeSnapshot,
    SeededFileHistory,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GithubQueryShard {
    pub lane: GithubLane,
    pub pack_id: String,
    pub query_id: String,
    pub anchor: String,
    pub qualifiers: Vec<String>,
    pub page_budget: usize,
    pub shard_id: String,
    pub coverage_mode: String,
    pub owner: String,
    pub repo: String,
    pub file_path: String,
}
impl GithubQueryShard {
    pub fn build_q(&self) -> String {
        if self.lane == GithubLane::SeededFileHistory {
            return String::new();
        }
        let mut parts = vec![self.anchor.clone()];
        parts.extend(self.qualifiers.clone());
        if self.lane == GithubLane::CommitMessage && !parts.iter().any(|v| v == "is:public") {
            parts.push("is:public".into())
        }
        parts
            .into_iter()
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
    pub fn assert_invariants(&self) -> anyhow::Result<()> {
        let q = self.build_q().to_ascii_lowercase();
        if self.lane == GithubLane::CommitMessage
            && [
                "path:",
                "filename:",
                "extension:",
                "language:",
                "is:private",
            ]
            .iter()
            .any(|v| q.contains(v))
        {
            anyhow::bail!("invalid commit-message qualifier")
        };
        Ok(())
    }
}
pub fn code_shards(
    pack: &str,
    anchors: &[&str],
    groups: &[&[&str]],
    page_budget: usize,
) -> Vec<GithubQueryShard> {
    let groups = if groups.is_empty() {
        vec![&[][..]]
    } else {
        groups.to_vec()
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for anchor in anchors.iter().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        for group in &groups {
            let key = format!("{}|{}", anchor.to_ascii_lowercase(), group.join("|"));
            if !seen.insert(key.clone()) {
                continue;
            }
            let hash = format!("{:x}", Sha1::digest(format!("cs|{pack}|{key}").as_bytes()));
            out.push(GithubQueryShard {
                lane: GithubLane::CodeSnapshot,
                pack_id: pack.into(),
                query_id: format!("cs-{}", &hash[..16]),
                anchor: anchor.into(),
                qualifiers: group.iter().map(|v| (*v).into()).collect(),
                page_budget,
                shard_id: format!("csshard-{}", &hash[..16]),
                coverage_mode: "complete".into(),
                owner: String::new(),
                repo: String::new(),
                file_path: String::new(),
            });
        }
    }
    out
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractedArtifactSecret {
    pub credential: Credential,
    pub source_kind: String,
    pub change_side: String,
    pub file_path: String,
    pub object_sha: String,
    pub line_start: Option<u32>,
    pub line_end: Option<u32>,
}
fn provider_endpoint(text: &str, key: &str) -> &'static str {
    if key.starts_with("xai-") {
        "https://api.x.ai/v1"
    } else if key.starts_with("ksk_") {
        "https://app.kiro.dev"
    } else if key.starts_with("crsr_") {
        "https://api.cursor.com"
    } else if key.starts_with("pt-") {
        "https://api.qoder.com"
    } else if key.starts_with("ABSK") {
        "https://bedrock.us-east-1.amazonaws.com"
    } else if key.starts_with("AIza") {
        "https://generativelanguage.googleapis.com"
    } else if key.starts_with("sk-ant-") {
        "https://api.anthropic.com/v1"
    } else if key.starts_with("sk-proj-") || key.starts_with("sk-or-v1-") || key.starts_with("sk-svcacct-") {
        "https://api.openai.com/v1"
    } else if key.starts_with("sk-moonshot-") || key.starts_with("sk-kimi-") {
        "https://api.moonshot.cn/v1"
    } else if key.starts_with("sk-zai-") {
        "https://api.z.ai/api/paas/v4"
    } else if key.starts_with("gsk_") {
        "https://api.groq.com/openai/v1"
    } else if key.starts_with("nvapi-") {
        "https://api.nvidia.com/v1"
    } else if key.starts_with("r8_") {
        "https://api.replicate.com/v1"
    } else if key.starts_with("pplx-") {
        "https://api.perplexity.ai"
    } else {
        let lowered = text.to_ascii_lowercase();
        if lowered.contains("windsurf_service_key") || lowered.contains("codeium_service_key") {
            "https://server.codeium.com/api/v1"
        } else {
            ""
        }
    }
}

pub fn extract_artifact_text(
    text: &str,
    endpoint: &str,
    source_kind: &str,
    change_side: &str,
    file_path: &str,
    object_sha: &str,
) -> Vec<ExtractedArtifactSecret> {
    let pattern=Regex::new(r"(?:sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{16,}|nvapi-[A-Za-z0-9_-]{16,}|r8_[A-Za-z0-9_-]{16,}|xai-[A-Za-z0-9_-]{16,}|ksk_[A-Za-z0-9_-]{16,}|crsr_[A-Za-z0-9_-]{32,}|pt-[A-Za-z0-9_-]{16,}|ABSK[A-Za-z0-9_+=/.-]{20,})").unwrap();
    let mut seen = HashSet::new();
    pattern
        .find_iter(text)
        .filter(|item| seen.insert(item.as_str().to_owned()))
        .map(|item| {
            // Prefer the provider API inferred from the key prefix (that is what
            // validation probes); keep the GitHub URL as provenance in `host`.
            let apiurl = {
                let inferred = provider_endpoint(text, item.as_str());
                if inferred.is_empty() {
                    endpoint.into()
                } else {
                    inferred.into()
                }
            };
            ExtractedArtifactSecret {
                credential: Credential {
                    apikey: item.as_str().into(),
                    apiurl,
                    host: endpoint.into(),
                    source: "github".into(),
                    source_type: source_kind.into(),
                    backend: "github".into(),
                    raw_context: text.chars().take(2048).collect(),
                    ..Default::default()
                },
                source_kind: source_kind.into(),
                change_side: change_side.into(),
                file_path: file_path.into(),
                object_sha: object_sha.into(),
                line_start: None,
                line_end: None,
            }
        })
        .collect()
}
pub fn extract_patch(
    patch: &str,
    endpoint: &str,
    file_path: &str,
    object_sha: &str,
) -> Vec<ExtractedArtifactSecret> {
    let lines = parse_unified_patch(patch);
    let mut out = Vec::new();
    for side in [PatchSide::Added, PatchSide::Removed, PatchSide::Context] {
        let selected = lines
            .iter()
            .filter(|line| line.side == side)
            .collect::<Vec<_>>();
        let text = selected
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let mut secrets = extract_artifact_text(
            &text,
            endpoint,
            "patch",
            match side {
                PatchSide::Added => "added",
                PatchSide::Removed => "removed",
                PatchSide::Context => "context",
            },
            file_path,
            object_sha,
        );
        let numbers = selected
            .iter()
            .filter_map(|line| {
                if side == PatchSide::Removed {
                    line.old_lineno
                } else {
                    line.new_lineno
                }
            })
            .collect::<Vec<_>>();
        for secret in &mut secrets {
            secret.line_start = numbers.iter().min().copied();
            secret.line_end = numbers.iter().max().copied();
        }
        out.extend(secrets);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_patch_without_headers_and_keeps_env_examples() {
        let rows =
            parse_unified_patch("@@ -1,1 +1,1 @@\n-old\n+OPENAI_API_KEY=sk-abcdefghijklmnop");
        assert_eq!(rows.len(), 2);
        assert!(!is_noise_artifact_path("backend/.env.example"));
        assert!(is_noise_artifact_path("docs/example.md"));
        assert_eq!(
            extract_patch(
                "@@ -1 +1 @@\n+x=sk-abcdefghijklmnop",
                "https://api.openai.com",
                ".env",
                "x"
            )
            .len(),
            1
        );
    }
    #[test]
    fn artifact_apiurl_prefers_inferred_provider_endpoint() {
        // sk-ant- keys probe Anthropic, not the GitHub provenance URL.
        let secrets = extract_artifact_text(
            "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz1234",
            "https://github.com/owner/repo/blob/abc123/.env",
            "code",
            "added",
            ".env",
            "abc123",
        );
        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets[0].credential.apiurl,
            "https://api.anthropic.com/v1"
        );
        assert_eq!(
            secrets[0].credential.host,
            "https://github.com/owner/repo/blob/abc123/.env"
        );
        // Generic sk- keys have no known provider; fall back to provenance URL.
        let generic = extract_artifact_text(
            "KEY=sk-abcdefghijklmnop",
            "https://github.com/o/r/blob/s/f",
            "code",
            "added",
            "f",
            "s",
        );
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].credential.apiurl, "https://github.com/o/r/blob/s/f");
    }
    #[test]
    fn shards_filters_and_secret_extraction_cover_boundaries() {
        let shards = code_shards(
            "openai",
            &["sk-proj", "sk-proj"],
            &[&["filename:.env"], &["path:config"]],
            3,
        );
        assert_eq!(shards.len(), 2);
        assert!(shards.iter().all(|shard| shard.assert_invariants().is_ok()));
        let commit = GithubQueryShard {
            lane: GithubLane::CommitMessage,
            pack_id: "p".into(),
            query_id: "q".into(),
            anchor: "secret".into(),
            qualifiers: vec!["is:private".into()],
            page_budget: 1,
            shard_id: "s".into(),
            coverage_mode: "complete".into(),
            owner: String::new(),
            repo: String::new(),
            file_path: String::new(),
        };
        assert!(commit.assert_invariants().is_err());
        assert!(is_noise_artifact_path("docs/guide.md"));
        assert!(!is_noise_artifact_path("backend/.env.example"));
        let text =
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz\nAPI_URL=https://api.openai.com/v1";
        let secrets = extract_artifact_text(
            text,
            "https://github.example/item",
            "blob",
            "context",
            ".env",
            "sha",
        );
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].credential.apiurl, "https://github.example/item");
        let expanded = extract_artifact_text(
            "XAI_API_KEY=xai-abcdefghijklmnop\nKIRO_API_KEY=ksk_abcdefghijklmnop\nCURSOR_API_KEY=crsr_abcdefghijklmnopqrstuvwxyz123456\nQODER_PAT=pt-abcdefghijklmnop\nAWS_BEARER_TOKEN_BEDROCK=ABSKabcdefghijklmnopqrstuvwxyz",
            "",
            "blob",
            "context",
            ".env",
            "sha",
        );
        assert_eq!(expanded.len(), 5);
        assert_eq!(expanded[0].credential.apiurl, "https://api.x.ai/v1");
        assert_eq!(expanded[1].credential.apiurl, "https://app.kiro.dev");
        assert_eq!(expanded[2].credential.apiurl, "https://api.cursor.com");
        assert_eq!(expanded[3].credential.apiurl, "https://api.qoder.com");
        assert_eq!(
            expanded[4].credential.apiurl,
            "https://bedrock.us-east-1.amazonaws.com"
        );

        assert_eq!(secrets[0].source_kind, "blob");
        let patch = parse_unified_patch("@@ -1,2 +1,2 @@\n-old\n+new\n same");
        assert_eq!(patch.len(), 3);
        assert_eq!(patch[0].side, PatchSide::Removed);
        assert_eq!(patch[1].new_lineno, Some(1));
    }
}
