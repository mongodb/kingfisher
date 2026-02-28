use anyhow::{Context, Result};
use gouqi::{r#async::Jira, Credentials, SearchOptions};
use reqwest::Client;
use std::path::PathBuf;
use url::Url;

// Re-export the Issue type from gouqi so callers don't depend on the crate directly.
pub use gouqi::Issue as JiraIssue;

fn build_jira_client(jira_url: &Url, ignore_certs: bool) -> Result<Jira> {
    let base = jira_url.as_str().trim_end_matches('/');
    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;
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

/// Fetch comments for a specific Jira issue via the dedicated comments API endpoint.
///
/// This is a fallback for Jira servers that omit the `self` link in the embedded
/// `fields.comment` wrapper, which causes `gouqi::Comments` deserialization to fail.
/// Prefer calling `issue.comments()` first; use this only when it returns `None`.
///
/// Uses GET /rest/api/2/issue/{key}/comment directly and returns raw comment bodies
/// as a Vec of serde_json::Value.
pub async fn fetch_comments(
    jira_url: &Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<Vec<serde_json::Value>> {
    let token = std::env::var("KF_JIRA_TOKEN").unwrap_or_default();
    let url = format!(
        "{}/rest/api/2/issue/{}/comment?maxResults=1000",
        jira_url.as_str().trim_end_matches('/'),
        issue_key
    );
    let client = Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .build()
        .context("Failed to build HTTP client")?;
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("Failed to fetch Jira comments")?
        .text()
        .await
        .context("Failed to read Jira comments response")?;
    let json: serde_json::Value = serde_json::from_str(&resp).context("Failed to parse Jira comments JSON")?;
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
