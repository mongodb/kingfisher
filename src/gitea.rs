use std::{collections::HashSet, env, str::FromStr, time::Duration};

use anyhow::{Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::StatusCode;
use serde::Deserialize;
use tracing::warn;
use url::Url;

use crate::{git_host, git_url::GitUrl, validation::GLOBAL_USER_AGENT};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoType {
    All,
    Source,
    Fork,
}

impl RepoType {
    fn allows(self, is_fork: bool) -> bool {
        match self {
            RepoType::All => true,
            RepoType::Source => !is_fork,
            RepoType::Fork => is_fork,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub organization: Vec<String>,
    pub all_organizations: bool,
    pub repo_filter: RepoType,
    pub exclude_repos: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.organization.is_empty() && !self.all_organizations
    }
}

#[derive(Debug, Deserialize)]
struct GiteaRepository {
    full_name: String,
    clone_url: String,
    #[serde(default)]
    fork: bool,
}

#[derive(Debug, Deserialize)]
struct GiteaOrganization {
    username: String,
}

fn normalize_repo_identifier(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let without_git = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let mut parts = without_git.split('/').filter(|segment| !segment.is_empty());
    let owner = parts.next()?;
    let repo = parts.next()?;
    Some(format!("{}/{}", owner.to_lowercase(), repo.to_lowercase()))
}

fn parse_excluded_repo(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(url) = Url::parse(trimmed)
        && let Some(name) = normalize_repo_identifier(url.path())
    {
        return Some(name);
    }

    if let Some(idx) = trimmed.rfind(':')
        && let Some(name) = normalize_repo_identifier(&trimmed[idx + 1..])
    {
        return Some(name);
    }

    normalize_repo_identifier(trimmed)
}

fn build_exclude_matcher(exclude_repos: &[String]) -> git_host::ExcludeMatcher {
    git_host::build_exclude_matcher(exclude_repos, parse_excluded_repo, "Gitea")
}

fn should_exclude_repo(repo: &GiteaRepository, excludes: &git_host::ExcludeMatcher) -> bool {
    if excludes.is_empty() {
        return false;
    }
    excludes.matches(&repo.full_name.to_lowercase())
}

async fn fetch_paginated_repos(
    client: &reqwest::Client,
    token: Option<&str>,
    mut url: Url,
    repo_filter: RepoType,
    excludes: &git_host::ExcludeMatcher,
    progress: Option<&ProgressBar>,
) -> Result<Vec<String>> {
    let mut page = 1u32;
    let mut repos = Vec::new();
    loop {
        url.query_pairs_mut()
            .clear()
            .append_pair("page", &page.to_string())
            .append_pair("limit", "50");
        if let Some(pb) = progress {
            pb.set_message(format!("Fetching Gitea repositories (page {page})"));
        }
        let mut req = client.get(url.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        if let Some(token) = token {
            req = req.header("Authorization", format!("token {token}"));
        }
        let resp = req.send().await?;
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => {
                warn!("Gitea endpoint {} returned 404", url);
                break;
            }
            status => {
                return Err(anyhow!("Failed to fetch repositories from {} (status {status})", url));
            }
        }
        let page_repos: Vec<GiteaRepository> = resp.json().await?;
        if page_repos.is_empty() {
            break;
        }
        for repo in page_repos {
            if !repo_filter.allows(repo.fork) {
                continue;
            }
            if should_exclude_repo(&repo, excludes) {
                continue;
            }
            repos.push(repo.clone_url);
        }
        page += 1;
    }
    Ok(repos)
}

async fn fetch_user_repos(
    client: &reqwest::Client,
    token: Option<&str>,
    api_url: &Url,
    username: &str,
    repo_filter: RepoType,
    excludes: &git_host::ExcludeMatcher,
    progress: Option<&ProgressBar>,
) -> Result<Vec<String>> {
    let endpoint = format!("users/{}/repos", username);
    let url = api_url.join(&endpoint)?;
    fetch_paginated_repos(client, token, url, repo_filter, excludes, progress).await
}

async fn fetch_org_repos(
    client: &reqwest::Client,
    token: Option<&str>,
    api_url: &Url,
    org: &str,
    repo_filter: RepoType,
    excludes: &git_host::ExcludeMatcher,
    progress: Option<&ProgressBar>,
) -> Result<Vec<String>> {
    let endpoint = format!("orgs/{}/repos", org);
    let url = api_url.join(&endpoint)?;
    fetch_paginated_repos(client, token, url, repo_filter, excludes, progress).await
}

async fn fetch_authenticated_orgs(
    client: &reqwest::Client,
    token: Option<&str>,
    api_url: &Url,
) -> Result<Vec<String>> {
    let Some(token) = token else {
        return Err(anyhow!("KF_GITEA_TOKEN must be set to enumerate all organizations"));
    };
    let url = api_url.join("user/orgs")?;
    let resp = client
        .get(url.clone())
        .header("User-Agent", GLOBAL_USER_AGENT.as_str())
        .header("Authorization", format!("token {token}"))
        .send()
        .await?;
    match resp.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => {
            warn!("Gitea endpoint {} returned 404", url);
            return Ok(Vec::new());
        }
        status => {
            return Err(anyhow!(
                "Failed to enumerate organizations from {} (status {status})",
                url
            ));
        }
    }
    let orgs: Vec<GiteaOrganization> = resp.json().await?;
    Ok(orgs.into_iter().map(|org| org.username).collect())
}

pub async fn enumerate_repo_urls(
    specifiers: &RepoSpecifiers,
    api_url: Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let excludes = build_exclude_matcher(&specifiers.exclude_repos);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(ignore_certs)
        .build()?;
    let token = env::var("KF_GITEA_TOKEN").ok().filter(|t| !t.is_empty());

    let mut repos = Vec::new();
    let mut seen = HashSet::new();

    for user in &specifiers.user {
        if let Some(pb) = progress.as_mut() {
            pb.set_message(format!("Enumerating Gitea user {user}"));
        }
        match fetch_user_repos(
            &client,
            token.as_deref(),
            &api_url,
            user,
            specifiers.repo_filter,
            &excludes,
            progress.as_deref(),
        )
        .await
        {
            Ok(mut urls) => {
                for url in urls.drain(..) {
                    if seen.insert(url.clone()) {
                        repos.push(url);
                    }
                }
            }
            Err(err) => {
                warn!("Failed to enumerate Gitea repositories for user {user}: {err}");
            }
        }
    }

    let mut organizations = specifiers.organization.clone();
    if specifiers.all_organizations {
        match fetch_authenticated_orgs(&client, token.as_deref(), &api_url).await {
            Ok(mut orgs) => organizations.append(&mut orgs),
            Err(err) => warn!("Failed to enumerate Gitea organizations: {err}"),
        }
    }
    organizations.sort();
    organizations.dedup();

    for org in organizations {
        if let Some(pb) = progress.as_mut() {
            pb.set_message(format!("Enumerating Gitea organization {org}"));
        }
        match fetch_org_repos(
            &client,
            token.as_deref(),
            &api_url,
            &org,
            specifiers.repo_filter,
            &excludes,
            progress.as_deref(),
        )
        .await
        {
            Ok(mut urls) => {
                for url in urls.drain(..) {
                    if seen.insert(url.clone()) {
                        repos.push(url);
                    }
                }
            }
            Err(err) => {
                warn!("Failed to enumerate Gitea repositories for organization {org}: {err}");
            }
        }
    }

    repos.sort();
    repos.dedup();
    Ok(repos)
}

#[allow(clippy::too_many_arguments)]
pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    orgs: &[String],
    all_orgs: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let specifiers = RepoSpecifiers {
        user: users.to_vec(),
        organization: orgs.to_vec(),
        all_organizations: all_orgs,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };

    let urls = enumerate_repo_urls(&specifiers, api_url, ignore_certs, Some(&mut progress)).await?;
    for url in urls {
        println!("{}", url);
    }
    progress.finish_and_clear();
    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url.host_str()?.to_string();
    let mut segments = url.path_segments()?;
    let owner = segments.next()?.to_string();
    let mut repo = segments.next()?.to_string();
    if let Some(stripped) = repo.strip_suffix(".git") {
        repo = stripped.to_string();
    }
    Some((host, owner, repo))
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let (host, owner, repo) = parse_repo(repo_url)?;
    let url = format!("https://{host}/{owner}/{repo}.wiki.git");
    GitUrl::from_str(&url).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_excluded_repo_variants() {
        assert_eq!(parse_excluded_repo("Owner/Repo").as_deref(), Some("owner/repo"));
        assert_eq!(
            parse_excluded_repo("https://gitea.example.com/Owner/Repo.git").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(
            parse_excluded_repo("ssh://git@exmple.com:3000/Owner/Repo.git").as_deref(),
            Some("owner/repo")
        );
    }

    #[test]
    fn normalize_repo_identifier_handles_git_suffix() {
        assert_eq!(normalize_repo_identifier("owner/repo.git"), Some("owner/repo".into()));
    }
}
