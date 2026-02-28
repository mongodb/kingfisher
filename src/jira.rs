use anyhow::{Context, Result};
use gouqi::{r#async::Jira, Credentials, SearchOptions};
use reqwest::Client;
use std::path::PathBuf;
use url::Url;

// Re-export the Issue type from gouqi so callers don't depend on the crate directly.
pub use gouqi::Issue as JiraIssue;

/// Maximum comments fetched per issue in a single request (Jira API default cap).
const JIRA_COMMENTS_MAX_RESULTS: u32 = 1000;

/// Build a bare reqwest Client with the given TLS settings.
/// Shared by both the gouqi wrapper and the direct REST fallback.
fn build_http_client(ignore_certs: bool) -> Result<Client> {
    Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")
}

/// Return a `Bearer <token>` Authorization header value if `KF_JIRA_TOKEN` is set,
/// or `None` to send the request without authentication (anonymous access).
fn jira_auth_header() -> Option<String> {
    std::env::var("KF_JIRA_TOKEN")
        .ok()
        .map(|token| format!("Bearer {}", token))
}

fn build_jira_client(jira_url: &Url, ignore_certs: bool) -> Result<Jira> {
    let base = jira_url.as_str().trim_end_matches('/');
    let client = build_http_client(ignore_certs)?;
    let credentials = match std::env::var("KF_JIRA_TOKEN") {
        Ok(token) => Credentials::Bearer(token),
        Err(_) => Credentials::Anonymous,
    };
    Ok(Jira::from_client(base.to_string(), credentials, client)?)
}

pub async fn fetch_issues(
    jira_url: &Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<JiraIssue>> {
    let jira = build_jira_client(jira_url, ignore_certs)?;

    let search_options = SearchOptions::builder().max_results(max_results as u64).build();

    let results = jira.search().list(jql, &search_options).await?;
    Ok(results.issues)
}

pub async fn download_issues_to_dir(
    jira_url: &Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
    output_dir: &PathBuf,
) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(output_dir)?;

    let issues = fetch_issues(jira_url, jql, max_results, ignore_certs).await?;

    let mut paths = Vec::new();
    for issue in issues {
        let file = output_dir.join(format!("{}.json", issue.key));
        std::fs::write(&file, serde_json::to_vec(&issue)?)?;
        paths.push(file);
    }

    Ok(paths)
}

/// Fallback: fetch comments via the dedicated REST endpoint.
///
/// `issue.comments()` may return `None` on Jira servers that omit the `self`
/// link in the embedded `fields.comment` wrapper, causing `gouqi::Comments`
/// deserialization to fail silently. This function hits the dedicated endpoint
/// directly and parses the response as raw JSON to avoid that constraint.
///
/// Uses GET /rest/api/2/issue/{key}/comment.
/// Note: fetches up to `JIRA_COMMENTS_MAX_RESULTS` comments; no pagination.
pub async fn fetch_comments(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<Vec<serde_json::Value>> {
    // Validate issue_key to prevent URL path injection.
    if !issue_key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("Invalid Jira issue key: {issue_key}");
    }

    let url = jira_url
        .join(&format!(
            "/rest/api/2/issue/{issue_key}/comment?maxResults={JIRA_COMMENTS_MAX_RESULTS}"
        ))
        .context("Failed to construct Jira comments URL")?;

    let client = build_http_client(ignore_certs)?;
    let mut request = client.get(url);
    if let Some(auth) = jira_auth_header() {
        request = request.header("Authorization", auth);
    }

    let response = request.send().await.context("Failed to fetch Jira comments")?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Jira comments API returned HTTP {status}: {}",
            body.chars().take(500).collect::<String>()
        );
    }

    let resp = response.text().await.context("Failed to read Jira comments response")?;
    let json: serde_json::Value =
        serde_json::from_str(&resp).context("Failed to parse Jira comments JSON")?;
    let comments = json
        .get("comments")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    Ok(comments)
}

/// Fetch changelog for a specific Jira issue
pub async fn fetch_changelog(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<gouqi::Changelog> {
    let jira = build_jira_client(jira_url, ignore_certs)?;
    let changelog = jira.issues().changelog(issue_key).await?;
    Ok(changelog)
}
