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
    jira_url: Url,
    jql: &str,
    max_results: usize,
    ignore_certs: bool,
) -> Result<Vec<JiraIssue>> {
    let jira = build_jira_client(&jira_url, ignore_certs)?;

    let search_options = SearchOptions::builder().max_results(max_results as u64).build();

    let results = jira.search().list(jql, &search_options).await?;
    Ok(results.issues)
}

pub async fn download_issues_to_dir(
    jira_url: Url,
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

/// Fetch comments for a specific Jira issue
pub async fn fetch_comments(
    jira_url: Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<Vec<gouqi::Comment>> {
    let jira = build_jira_client(&jira_url, ignore_certs)?;
    let issue = jira.issues().get(issue_key).await?;
    let comments = issue.comments().map(|c| c.comments).unwrap_or_default();
    Ok(comments)
}

/// Fetch changelog for a specific Jira issue
pub async fn fetch_changelog(
    jira_url: Url,
    issue_key: &str,
    ignore_certs: bool,
) -> Result<gouqi::Changelog> {
    let jira = build_jira_client(&jira_url, ignore_certs)?;
    let changelog = jira.issues().changelog(issue_key).await?;
    Ok(changelog)
}
