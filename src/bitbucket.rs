use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::git_host;
use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

use crate::{findings_store, git_url::GitUrl, validation::GLOBAL_USER_AGENT};

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub bearer_token: Option<String>,
}

pub(crate) fn is_bitbucket_access_token(token: &str) -> bool {
    token.len() > 40 && token.starts_with("AT") && token.contains('_')
}

impl AuthConfig {
    pub fn from_options(
        username: Option<String>,
        password: Option<String>,
        bearer_token: Option<String>,
    ) -> Self {
        fn normalized(value: Option<String>) -> Option<String> {
            value.and_then(|v| {
                let trimmed = v.trim();
                if trimmed.is_empty() {
                    None
                } else if trimmed.len() == v.len() {
                    Some(v)
                } else {
                    Some(trimmed.to_owned())
                }
            })
        }

        fn env_var(name: &str) -> Option<String> {
            normalized(env::var(name).ok())
        }

        let username = normalized(username).or_else(|| env_var("KF_BITBUCKET_USERNAME"));
        let password = normalized(password)
            .or_else(|| env_var("KF_BITBUCKET_APP_PASSWORD"))
            .or_else(|| env_var("KF_BITBUCKET_TOKEN"))
            .or_else(|| env_var("KF_BITBUCKET_PASSWORD"));
        let mut bearer_token =
            normalized(bearer_token).or_else(|| env_var("KF_BITBUCKET_OAUTH_TOKEN"));

        if bearer_token.is_none()
            && let Some(password) = &password
            && is_bitbucket_access_token(password)
        {
            bearer_token = Some(password.clone());
        }
        Self { username, password, bearer_token }
    }

    pub fn from_env() -> Self {
        Self::from_options(None, None, None)
    }

    fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.bearer_token {
            request.bearer_auth(token)
        } else if let (Some(username), Some(password)) = (&self.username, &self.password) {
            request.basic_auth(username, Some(password))
        } else {
            request
        }
    }
}

#[derive(Debug)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub workspace: Vec<String>,
    pub project: Vec<String>,
    pub all_workspaces: bool,
    pub repo_filter: RepoType,
    pub exclude_repos: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
            && self.workspace.is_empty()
            && self.project.is_empty()
            && !self.all_workspaces
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BitbucketKind {
    Cloud,
    Server,
}

impl BitbucketKind {
    fn from_url(api_url: &Url) -> Self {
        let host = api_url.host_str().unwrap_or_default();
        if host.eq_ignore_ascii_case("api.bitbucket.org") || api_url.path().contains("/2.0") {
            BitbucketKind::Cloud
        } else {
            BitbucketKind::Server
        }
    }
}

fn normalize_repo_identifier(owner: &str, repo: &str) -> Option<String> {
    let owner = owner.trim().trim_matches('/');
    let repo = repo.trim().trim_matches('/');
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{}/{}", owner.to_lowercase(), repo.to_lowercase()))
}

fn parse_repo_name_from_path(path: &str) -> Option<String> {
    let parts: Vec<&str> =
        path.trim_matches('/').split('/').filter(|segment| !segment.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    let repo = parts.last().unwrap();
    let owner = parts.get(parts.len() - 2).unwrap();
    normalize_repo_identifier(owner, repo)
}

fn parse_repo_name_from_url(repo_url: &str) -> Option<String> {
    let url = Url::parse(repo_url).ok()?;
    parse_repo_name_from_path(url.path())
}

fn parse_excluded_repo(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(name) = parse_repo_name_from_url(trimmed) {
        return Some(name);
    }

    if let Some(idx) = trimmed.rfind(':')
        && let Some(name) = parse_repo_name_from_path(&trimmed[idx + 1..])
    {
        return Some(name);
    }

    parse_repo_name_from_path(trimmed)
}

fn build_exclude_matcher(exclude_repos: &[String]) -> git_host::ExcludeMatcher {
    git_host::build_exclude_matcher(exclude_repos, parse_excluded_repo, "Bitbucket")
}

fn should_exclude_repo(clone_url: &str, excludes: &git_host::ExcludeMatcher) -> bool {
    git_host::should_exclude_repo(clone_url, excludes, parse_repo_name_from_url)
}

fn repo_clone_url_from_links(links: &[CloneLink]) -> Option<String> {
    links
        .iter()
        .find(|link| link.name.as_deref().map(|n| n.eq_ignore_ascii_case("https")).unwrap_or(false))
        .or_else(|| links.first())
        .map(|link| link.href.clone())
}

#[derive(Deserialize)]
struct CloneLink {
    href: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct CloudRepoLinks {
    #[serde(default)]
    clone: Vec<CloneLink>,
}

#[derive(Deserialize)]
struct CloudRepo {
    links: CloudRepoLinks,
    #[serde(default)]
    parent: Option<Value>,
}

#[derive(Deserialize)]
struct CloudRepoList {
    values: Vec<CloudRepo>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct CloudWorkspaceList {
    values: Vec<CloudWorkspace>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct CloudWorkspace {
    slug: String,
}

#[derive(Deserialize)]
struct ServerRepo {
    links: CloudRepoLinks,
    #[serde(default)]
    origin: Option<Value>,
}

#[derive(Deserialize)]
struct ServerRepoList {
    values: Vec<ServerRepo>,
    #[serde(default, rename = "isLastPage")]
    is_last_page: bool,
    #[serde(default, rename = "nextPageStart")]
    next_page_start: Option<u64>,
}

#[derive(Deserialize)]
struct ServerProjectList {
    values: Vec<ServerProject>,
    #[serde(default, rename = "isLastPage")]
    is_last_page: bool,
    #[serde(default, rename = "nextPageStart")]
    next_page_start: Option<u64>,
}

#[derive(Deserialize)]
struct ServerProject {
    key: String,
}

async fn fetch_cloud_repositories(
    client: &reqwest::Client,
    base: &Url,
    owner: &str,
    auth: &AuthConfig,
    repo_filter: RepoType,
    excludes: &git_host::ExcludeMatcher,
    results: &mut Vec<String>,
) -> Result<()> {
    let mut next = base
        .join(&format!("repositories/{owner}?pagelen=100"))
        .context("failed to construct Bitbucket API URL")?;

    loop {
        let mut req = client.get(next.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        req = auth.apply(req);
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            break;
        }
        let resp = resp.error_for_status()?;
        let payload: CloudRepoList = resp.json().await?;
        for repo in payload.values {
            let is_fork = repo.parent.is_some();
            if !repo_filter.allows(is_fork) {
                continue;
            }
            if let Some(clone) = repo_clone_url_from_links(&repo.links.clone) {
                if should_exclude_repo(&clone, excludes) {
                    continue;
                }
                results.push(clone);
            }
        }
        if let Some(next_url) = payload.next {
            next = Url::parse(&next_url)?;
        } else {
            break;
        }
    }

    Ok(())
}

async fn fetch_server_repositories(
    client: &reqwest::Client,
    base: &Url,
    path: &str,
    auth: &AuthConfig,
    repo_filter: RepoType,
    excludes: &git_host::ExcludeMatcher,
    results: &mut Vec<String>,
) -> Result<()> {
    let mut start = 0u64;
    loop {
        let api_path = if path.contains('?') {
            format!("{path}&start={start}")
        } else {
            format!("{path}?limit=100&start={start}")
        };
        let mut req = client
            .get(base.join(&api_path).context("failed to build Bitbucket Server URL")?)
            .header("User-Agent", GLOBAL_USER_AGENT.as_str());
        req = auth.apply(req);
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            break;
        }
        let resp = resp.error_for_status()?;
        let payload: ServerRepoList = resp.json().await?;
        for repo in payload.values {
            let is_fork = repo.origin.is_some();
            if !repo_filter.allows(is_fork) {
                continue;
            }
            if let Some(clone) = repo_clone_url_from_links(&repo.links.clone) {
                if should_exclude_repo(&clone, excludes) {
                    continue;
                }
                results.push(clone);
            }
        }
        if payload.is_last_page {
            break;
        }
        start = payload.next_page_start.unwrap_or_else(|| start + 100);
    }
    Ok(())
}

async fn list_cloud_workspaces(
    client: &reqwest::Client,
    base: &Url,
    auth: &AuthConfig,
) -> Result<Vec<String>> {
    let mut workspaces = Vec::new();
    let mut next = base
        .join("workspaces?role=member&pagelen=100")
        .context("failed to build Bitbucket workspace URL")?;
    loop {
        let mut req = client.get(next.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        req = auth.apply(req);
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            break;
        }
        let resp = resp.error_for_status()?;
        let payload: CloudWorkspaceList = resp.json().await?;
        for ws in payload.values {
            workspaces.push(ws.slug);
        }
        if let Some(next_url) = payload.next {
            next = Url::parse(&next_url)?;
        } else {
            break;
        }
    }
    Ok(workspaces)
}

async fn list_server_projects(
    client: &reqwest::Client,
    base: &Url,
    auth: &AuthConfig,
) -> Result<Vec<String>> {
    let mut projects = Vec::new();
    let mut start = 0u64;
    loop {
        let mut req = client
            .get(
                base.join(&format!("projects?limit=100&start={start}"))
                    .context("failed to build Bitbucket projects URL")?,
            )
            .header("User-Agent", GLOBAL_USER_AGENT.as_str());
        req = auth.apply(req);
        let resp = req.send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            break;
        }
        let resp = resp.error_for_status()?;
        let payload: ServerProjectList = resp.json().await?;
        for project in payload.values {
            projects.push(project.key);
        }
        if payload.is_last_page {
            break;
        }
        start = payload.next_page_start.unwrap_or_else(|| start + 100);
    }
    Ok(projects)
}

pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    api_url: Url,
    auth: &AuthConfig,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .timeout(Duration::from_secs(30))
        .build()?;
    let kind = BitbucketKind::from_url(&api_url);
    let excludes = build_exclude_matcher(&repo_specifiers.exclude_repos);
    let mut repo_urls = Vec::new();

    match kind {
        BitbucketKind::Cloud => {
            let mut owners: HashSet<String> = HashSet::new();
            owners.extend(repo_specifiers.user.iter().cloned());
            owners.extend(repo_specifiers.workspace.iter().cloned());
            owners.extend(repo_specifiers.project.iter().cloned());
            if repo_specifiers.all_workspaces {
                match list_cloud_workspaces(&client, &api_url, auth).await {
                    Ok(ws) => owners.extend(ws),
                    Err(err) => warn!("Failed to enumerate Bitbucket workspaces: {err:#}"),
                }
            }
            for owner in owners {
                if let Err(err) = fetch_cloud_repositories(
                    &client,
                    &api_url,
                    &owner,
                    auth,
                    repo_specifiers.repo_filter,
                    &excludes,
                    &mut repo_urls,
                )
                .await
                {
                    warn!("Failed to fetch Bitbucket repositories for '{owner}': {err:#}");
                }
                if let Some(progress) = progress.as_mut() {
                    progress.inc(1);
                }
            }
        }
        BitbucketKind::Server => {
            let mut projects: HashSet<String> = HashSet::new();
            projects.extend(repo_specifiers.workspace.iter().cloned());
            projects.extend(repo_specifiers.project.iter().cloned());
            if repo_specifiers.all_workspaces {
                match list_server_projects(&client, &api_url, auth).await {
                    Ok(p) => projects.extend(p),
                    Err(err) => warn!("Failed to enumerate Bitbucket projects: {err:#}"),
                }
            }
            for user in &repo_specifiers.user {
                if let Err(err) = fetch_server_repositories(
                    &client,
                    &api_url,
                    &format!("users/{user}/repos?limit=100"),
                    auth,
                    repo_specifiers.repo_filter,
                    &excludes,
                    &mut repo_urls,
                )
                .await
                {
                    warn!("Failed to fetch Bitbucket repositories for user '{user}': {err:#}");
                }
                if let Some(progress) = progress.as_mut() {
                    progress.inc(1);
                }
            }
            for project in projects {
                if let Err(err) = fetch_server_repositories(
                    &client,
                    &api_url,
                    &format!("projects/{project}/repos"),
                    auth,
                    repo_specifiers.repo_filter,
                    &excludes,
                    &mut repo_urls,
                )
                .await
                {
                    warn!(
                        "Failed to fetch Bitbucket repositories for project '{project}': {err:#}"
                    );
                }
                if let Some(progress) = progress.as_mut() {
                    progress.inc(1);
                }
            }
        }
    }

    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

#[allow(clippy::too_many_arguments)]
pub async fn list_repositories(
    api_url: Url,
    auth: AuthConfig,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    workspaces: &[String],
    projects: &[String],
    all_workspaces: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Fetching Bitbucket repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        workspace: workspaces.to_vec(),
        project: projects.to_vec(),
        all_workspaces,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };
    let repos =
        enumerate_repo_urls(&repo_specifiers, api_url, &auth, ignore_certs, Some(&mut progress))
            .await?;
    for repo in repos {
        println!("{repo}");
    }
    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url.host_str()?.to_string();
    let parts: Vec<&str> = url
        .path_segments()
        .map(|segments| segments.filter(|s| !s.is_empty()).collect::<Vec<_>>())?;
    if parts.len() < 2 {
        return None;
    }
    let repo = parts.last()?.trim_end_matches(".git").to_string();
    let owner = parts.get(parts.len() - 2)?.to_string();
    Some((host, owner, repo))
}

pub fn wiki_url(_repo_url: &GitUrl) -> Option<GitUrl> {
    None
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    api_base: &Url,
    auth: &AuthConfig,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (_host, owner, repo) = parse_repo(repo_url).context("invalid Bitbucket repo URL")?;

    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;

    let mut dirs = Vec::new();
    let issues_dir = output_root.join("bitbucket_issues").join(format!("{owner}_{repo}"));
    fs::create_dir_all(&issues_dir)?;
    let kind = BitbucketKind::from_url(api_base);
    let mut next = match kind {
        BitbucketKind::Cloud => api_base
            .join(&format!("repositories/{owner}/{repo}/issues?pagelen=50"))
            .context("failed to construct Bitbucket Cloud issues URL")?,
        BitbucketKind::Server => api_base
            .join(&format!("projects/{owner}/repos/{repo}/issues?limit=50"))
            .context("failed to construct Bitbucket Server issues URL")?,
    };
    let mut any_issue = false;
    loop {
        let mut req = client.get(next.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        req = auth.apply(req);
        let resp = req.send().await?;
        if resp.status().is_client_error() {
            break;
        }
        let payload: Value = resp.json().await?;
        if payload.get("type").and_then(|v| v.as_str()) == Some("error") {
            break;
        }
        let Some(values) = payload.get("values").and_then(|v| v.as_array()) else {
            break;
        };
        if values.is_empty() {
            break;
        }
        for issue in values {
            let id = issue.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let title = issue.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = issue
                .get("content")
                .and_then(|v| v.get("raw"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content = format!("# {title}\n\n{body}");
            let file_path = issues_dir.join(format!("issue_{id}.md"));
            fs::write(&file_path, content)?;
            if matches!(kind, BitbucketKind::Cloud) {
                let url = format!("https://bitbucket.org/{owner}/{repo}/issues/{id}");
                let mut ds = datastore.lock().unwrap();
                ds.register_repo_link(file_path, url);
            }
            any_issue = true;
        }
        if let Some(next_url) = payload.get("next").and_then(|v| v.as_str()) {
            next = Url::parse(next_url)?;
        } else {
            break;
        }
    }
    if any_issue {
        dirs.push(issues_dir);
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_excluded_repo_variants() {
        assert_eq!(parse_excluded_repo("workspace/repo").as_deref(), Some("workspace/repo"));
        assert_eq!(parse_excluded_repo("workspace/repo.git").as_deref(), Some("workspace/repo"));
        assert_eq!(
            parse_excluded_repo("https://bitbucket.org/workspace/repo.git").as_deref(),
            Some("workspace/repo")
        );
        assert_eq!(
            parse_excluded_repo("ssh://git@bitbucket.example.com/scm/WS/repo.git").as_deref(),
            Some("ws/repo")
        );
    }

    #[test]
    fn auth_config_ignores_empty_environment_values() {
        temp_env::with_vars(
            [
                ("KF_BITBUCKET_USERNAME", Some("")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("")),
                ("KF_BITBUCKET_OAUTH_TOKEN", Some("   ")),
            ],
            || {
                let auth = AuthConfig::from_env();
                assert!(auth.username.is_none());
                assert!(auth.password.is_none());
                assert!(auth.bearer_token.is_none());
            },
        );
    }

    #[test]
    fn auth_config_prefers_basic_auth_when_bearer_is_empty() {
        temp_env::with_vars(
            [
                ("KF_BITBUCKET_USERNAME", Some("user")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("pass")),
                ("KF_BITBUCKET_OAUTH_TOKEN", Some("")),
            ],
            || {
                let auth = AuthConfig::from_env();
                assert_eq!(auth.username.as_deref(), Some("user"));
                assert_eq!(auth.password.as_deref(), Some("pass"));
                assert!(auth.bearer_token.is_none());
            },
        );
    }

    #[test]
    fn auth_config_trims_environment_whitespace() {
        temp_env::with_vars(
            [
                ("KF_BITBUCKET_USERNAME", Some("  user  ")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("  pass\n")),
            ],
            || {
                let auth = AuthConfig::from_env();
                assert_eq!(auth.username.as_deref(), Some("user"));
                assert_eq!(auth.password.as_deref(), Some("pass"));
            },
        );
    }

    #[test]
    fn auth_config_treats_access_token_as_bearer() {
        let token = "AT1234567890_ACCESS_TOKEN_EXAMPLE_WITH_UNDERSCORE";
        temp_env::with_vars(
            [("KF_BITBUCKET_USERNAME", Some("user")), ("KF_BITBUCKET_TOKEN", Some(token))],
            || {
                let auth = AuthConfig::from_env();
                assert_eq!(auth.username.as_deref(), Some("user"));
                assert_eq!(auth.password.as_deref(), Some(token));
                assert_eq!(auth.bearer_token.as_deref(), Some(token));
            },
        );
    }
}
