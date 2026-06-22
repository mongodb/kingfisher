use anyhow::{Context, Result, bail};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Clone, Default)]
pub struct PostmanSelectors {
    pub workspaces: Vec<String>,
    pub collections: Vec<String>,
    pub environments: Vec<String>,
    pub all: bool,
    pub include_mocks_monitors: bool,
}

impl PostmanSelectors {
    pub fn is_empty(&self) -> bool {
        !self.all
            && self.workspaces.is_empty()
            && self.collections.is_empty()
            && self.environments.is_empty()
    }
}

#[derive(Debug, Deserialize)]
struct WorkspacesEnvelope {
    #[serde(default)]
    workspaces: Vec<WorkspaceSummary>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceSummary {
    id: String,
}

#[derive(Debug, Deserialize)]
struct WorkspaceDetailEnvelope {
    workspace: WorkspaceDetail,
}

#[derive(Debug, Deserialize)]
struct WorkspaceDetail {
    id: String,
    #[serde(default)]
    collections: Vec<RefItem>,
    #[serde(default)]
    environments: Vec<RefItem>,
    #[serde(default)]
    mocks: Vec<RefItem>,
    #[serde(default)]
    monitors: Vec<RefItem>,
}

#[derive(Debug, Deserialize)]
struct RefItem {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    uid: Option<String>,
}

impl RefItem {
    fn pick(&self) -> Option<&str> {
        self.uid.as_deref().or(self.id.as_deref())
    }
}

const MAX_RETRIES: usize = 5;

fn token_from_env() -> Result<String> {
    if let Ok(t) = std::env::var("KF_POSTMAN_TOKEN")
        && !t.is_empty()
    {
        return Ok(t);
    }
    if let Ok(t) = std::env::var("POSTMAN_API_KEY")
        && !t.is_empty()
    {
        return Ok(t);
    }
    bail!("KF_POSTMAN_TOKEN (or POSTMAN_API_KEY) environment variable must be set");
}

/// Best-effort UID extraction. Accepts:
/// - bare UID strings (returned unchanged)
/// - Postman web URLs of the form `.../{workspace,collection,environment,mock,monitor}[s]/<uid>[/<suffix>]`:
///   the UID following the type marker is preferred. Falls back to the last
///   non-suffix path segment if no type marker is present.
fn resolve_uid(input: &str) -> String {
    if !input.starts_with("http://") && !input.starts_with("https://") {
        return input.to_string();
    }
    let Ok(parsed) = Url::parse(input) else {
        return input.to_string();
    };
    let Some(segs) = parsed.path_segments() else {
        return input.to_string();
    };
    let segs: Vec<&str> = segs.filter(|s| !s.is_empty()).collect();

    // Prefer the segment immediately after the *last* known type marker.
    // Postman web URLs commonly nest workspace + collection + suffix; the deepest
    // type marker is the one the user pasted the URL to scan.
    const TYPE_MARKERS: &[&str] = &[
        "workspace",
        "workspaces",
        "collection",
        "collections",
        "environment",
        "environments",
        "mock",
        "mocks",
        "monitor",
        "monitors",
    ];
    if let Some(window) = segs.windows(2).rev().find(|w| TYPE_MARKERS.contains(&w[0])) {
        return window[1].to_string();
    }

    // Fall back to the last segment that is not a known terminal suffix
    // (e.g. /overview, /edit, /run on Postman web URLs).
    const TERMINAL_SUFFIXES: &[&str] = &[
        "overview",
        "edit",
        "run",
        "documentation",
        "info",
        "history",
        "tests",
        "request",
        "fork",
        "watch",
        "comments",
    ];
    if let Some(last) = segs.iter().rev().find(|s| !TERMINAL_SUFFIXES.contains(s)) {
        return last.to_string();
    }
    input.to_string()
}

async fn get_with_retries(
    client: &Client,
    url: Url,
    token: &str,
) -> Result<Option<serde_json::Value>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let resp = client
            .get(url.clone())
            .header("X-Api-Key", token)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("Failed to send Postman request to {}", url))?;

        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS && attempt <= MAX_RETRIES {
            let retry_after = resp
                .headers()
                .get("X-RateLimit-RetryAfter")
                .or_else(|| resp.headers().get("Retry-After"))
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1);
            warn!(
                "Postman API rate-limited at {} (attempt {}). Sleeping {}s",
                url, attempt, retry_after
            );
            sleep(Duration::from_secs(retry_after)).await;
            continue;
        }
        if status == StatusCode::NOT_FOUND || status == StatusCode::FORBIDDEN {
            debug!("Postman API returned {} for {} (skipping)", status, url);
            return Ok(None);
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("Postman API request to {} failed with status {}: {}", url, status, body);
        }
        let value: serde_json::Value =
            resp.json().await.with_context(|| format!("Failed to parse JSON from {}", url))?;
        return Ok(Some(value));
    }
}

fn web_url_for_collection(uid: &str) -> String {
    format!("https://go.postman.co/collection/{}", uid)
}

fn web_url_for_environment(uid: &str) -> String {
    format!("https://go.postman.co/environments/{}", uid)
}

fn web_url_for_workspace(id: &str) -> String {
    format!("https://go.postman.co/workspace/{}", id)
}

fn web_url_for_mock(uid: &str) -> String {
    format!("https://go.postman.co/mock/{}", uid)
}

fn web_url_for_monitor(uid: &str) -> String {
    format!("https://go.postman.co/monitor/{}", uid)
}

async fn fetch_workspace_ids(client: &Client, api_url: &Url, token: &str) -> Result<Vec<String>> {
    let url = api_url.join("workspaces").context("Failed to build workspaces URL")?;
    let Some(value) = get_with_retries(client, url, token).await? else {
        return Ok(Vec::new());
    };
    let envelope: WorkspacesEnvelope =
        serde_json::from_value(value).context("Failed to parse Postman workspaces response")?;
    Ok(envelope.workspaces.into_iter().map(|w| w.id).collect())
}

async fn fetch_workspace_detail(
    client: &Client,
    api_url: &Url,
    token: &str,
    id: &str,
) -> Result<Option<(serde_json::Value, WorkspaceDetail)>> {
    let url = api_url
        .join(&format!("workspaces/{}", id))
        .with_context(|| format!("Failed to build workspace URL for {}", id))?;
    let Some(value) = get_with_retries(client, url, token).await? else {
        return Ok(None);
    };
    let envelope: WorkspaceDetailEnvelope = serde_json::from_value(value.clone())
        .with_context(|| format!("Failed to parse workspace {} response", id))?;
    Ok(Some((value, envelope.workspace)))
}

async fn fetch_resource(
    client: &Client,
    api_url: &Url,
    token: &str,
    path: &str,
) -> Result<Option<serde_json::Value>> {
    let url = api_url.join(path).with_context(|| format!("Failed to build URL for {}", path))?;
    get_with_retries(client, url, token).await
}

async fn write_json(dir: &Path, name: &str, value: &serde_json::Value) -> Result<PathBuf> {
    tokio::fs::create_dir_all(dir).await?;
    let path = dir.join(name);
    tokio::fs::write(&path, serde_json::to_vec_pretty(value)?).await?;
    Ok(path)
}

pub async fn download_postman_to_dir(
    api_url: Url,
    selectors: PostmanSelectors,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &Path,
) -> Result<Vec<(PathBuf, String)>> {
    let token = token_from_env()?;
    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;

    tokio::fs::create_dir_all(output_dir).await?;

    let mut paths: Vec<(PathBuf, String)> = Vec::new();

    // Track UIDs we've already fetched to avoid duplicate API calls when
    // the same collection/environment is referenced from multiple workspaces.
    let mut seen_collections = std::collections::HashSet::new();
    let mut seen_environments = std::collections::HashSet::new();
    let mut seen_mocks = std::collections::HashSet::new();
    let mut seen_monitors = std::collections::HashSet::new();
    let mut seen_workspaces = std::collections::HashSet::new();

    // Resolve workspace selectors (explicit list and/or --all)
    let mut workspace_ids: Vec<String> =
        selectors.workspaces.iter().map(|s| resolve_uid(s)).collect();
    if selectors.all {
        let listed = fetch_workspace_ids(&client, &api_url, &token).await?;
        for id in listed {
            if !workspace_ids.contains(&id) {
                workspace_ids.push(id);
            }
        }
    }

    // Walk workspaces -> collect collection/environment/mock/monitor UIDs
    let mut collection_uids: Vec<String> =
        selectors.collections.iter().map(|s| resolve_uid(s)).collect();
    let mut environment_uids: Vec<String> =
        selectors.environments.iter().map(|s| resolve_uid(s)).collect();
    let mut mock_uids: Vec<String> = Vec::new();
    let mut monitor_uids: Vec<String> = Vec::new();

    for ws_id in workspace_ids {
        if !seen_workspaces.insert(ws_id.clone()) {
            continue;
        }
        let Some((raw, detail)) = fetch_workspace_detail(&client, &api_url, &token, &ws_id).await?
        else {
            continue;
        };
        let path = write_json(output_dir, &format!("workspace_{}.json", detail.id), &raw).await?;
        paths.push((path, web_url_for_workspace(&detail.id)));

        for c in detail.collections {
            if let Some(uid) = c.pick() {
                let uid = uid.to_string();
                if !collection_uids.contains(&uid) {
                    collection_uids.push(uid);
                }
            }
        }
        for e in detail.environments {
            if let Some(uid) = e.pick() {
                let uid = uid.to_string();
                if !environment_uids.contains(&uid) {
                    environment_uids.push(uid);
                }
            }
        }
        if selectors.include_mocks_monitors {
            for m in detail.mocks {
                if let Some(uid) = m.pick() {
                    mock_uids.push(uid.to_string());
                }
            }
            for m in detail.monitors {
                if let Some(uid) = m.pick() {
                    monitor_uids.push(uid.to_string());
                }
            }
        }
    }

    let limit_hit = |paths: &Vec<(PathBuf, String)>| max_results > 0 && paths.len() >= max_results;

    for uid in collection_uids {
        if limit_hit(&paths) {
            break;
        }
        if !seen_collections.insert(uid.clone()) {
            continue;
        }
        let Some(value) =
            fetch_resource(&client, &api_url, &token, &format!("collections/{}", uid)).await?
        else {
            continue;
        };
        let path = write_json(output_dir, &format!("collection_{}.json", uid), &value).await?;
        paths.push((path, web_url_for_collection(&uid)));
    }

    for uid in environment_uids {
        if limit_hit(&paths) {
            break;
        }
        if !seen_environments.insert(uid.clone()) {
            continue;
        }
        let Some(value) =
            fetch_resource(&client, &api_url, &token, &format!("environments/{}", uid)).await?
        else {
            continue;
        };
        let path = write_json(output_dir, &format!("environment_{}.json", uid), &value).await?;
        paths.push((path, web_url_for_environment(&uid)));
    }

    for uid in mock_uids {
        if limit_hit(&paths) {
            break;
        }
        if !seen_mocks.insert(uid.clone()) {
            continue;
        }
        let Some(value) =
            fetch_resource(&client, &api_url, &token, &format!("mocks/{}", uid)).await?
        else {
            continue;
        };
        let path = write_json(output_dir, &format!("mock_{}.json", uid), &value).await?;
        paths.push((path, web_url_for_mock(&uid)));
    }

    for uid in monitor_uids {
        if limit_hit(&paths) {
            break;
        }
        if !seen_monitors.insert(uid.clone()) {
            continue;
        }
        let Some(value) =
            fetch_resource(&client, &api_url, &token, &format!("monitors/{}", uid)).await?
        else {
            continue;
        };
        let path = write_json(output_dir, &format!("monitor_{}.json", uid), &value).await?;
        paths.push((path, web_url_for_monitor(&uid)));
    }

    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_uid_passes_through_bare_ids() {
        assert_eq!(resolve_uid("12345-abc"), "12345-abc");
        assert_eq!(
            resolve_uid("11111111-2222-3333-4444-555555555555"),
            "11111111-2222-3333-4444-555555555555"
        );
    }

    #[test]
    fn resolve_uid_extracts_uid_after_type_marker() {
        assert_eq!(
            resolve_uid("https://www.postman.com/team/workspace/abc-uid-123"),
            "abc-uid-123"
        );
        // Terminal `/overview` must not be mistaken for the UID.
        assert_eq!(
            resolve_uid("https://www.postman.com/team/workspace/abc-uid-123/overview"),
            "abc-uid-123"
        );
        // Type marker preference: the segment after `collection/` is the UID, not the trailing segment.
        assert_eq!(
            resolve_uid("https://go.postman.co/workspace/wks-1/collection/col-9/run"),
            "col-9"
        );
        assert_eq!(resolve_uid("https://go.postman.co/workspace/wks-1/environment/env-9"), "env-9");
    }

    #[test]
    fn selectors_is_empty_by_default() {
        assert!(PostmanSelectors::default().is_empty());
        let sel = PostmanSelectors { workspaces: vec!["a".into()], ..PostmanSelectors::default() };
        assert!(!sel.is_empty());
    }
}
