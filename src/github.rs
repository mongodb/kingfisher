use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};
use url::Url;

use crate::{
    findings_store, git_url::GitUrl, github_auth::GitHubAuth, validation::GLOBAL_USER_AGENT,
};
use std::str::FromStr;

pub(crate) mod retry;

#[derive(Deserialize)]
struct GitHubContributor {
    login: Option<String>,
}

#[derive(Deserialize)]
struct GitHubRepo {
    #[serde(default)]
    id: Option<u64>,
    clone_url: String,
    fork: bool,
}

#[derive(Deserialize)]
struct GitHubGist {
    git_pull_url: String,
}

#[derive(Deserialize)]
struct GitHubOrg {
    login: String,
}

#[derive(Deserialize)]
struct GitHubEvent {
    #[serde(rename = "type")]
    event_type: String,
    repo: GitHubEventRepo,
    payload: Value,
    created_at: String,
}

#[derive(Deserialize)]
struct GitHubEventRepo {
    #[serde(default)]
    id: Option<u64>,
    name: String,
}

#[derive(Deserialize)]
struct GitHubPushPayload {
    #[serde(default)]
    commits: Vec<GitHubPushCommit>,
    #[serde(default)]
    head: Option<String>,
}

#[derive(Deserialize)]
struct GitHubPushCommit {
    sha: String,
}

#[derive(Deserialize)]
struct GitHubCreatePayload {
    ref_type: Option<String>,
    #[serde(rename = "ref")]
    ref_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GitHubEventScanTarget {
    pub repo_url: GitUrl,
    pub selector: GitHubEventScanSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum GitHubEventScanSelector {
    Repository,
    Branch(String),
    Commit(String),
}

#[derive(Debug)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub include_gists: bool,
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
#[derive(Debug, Clone)]
pub enum RepoType {
    All,
    Source,
    Fork,
}
impl RepoType {
    fn user_query_value(&self) -> &'static str {
        match self {
            RepoType::All => "all",
            RepoType::Source => "owner",
            RepoType::Fork => "member",
        }
    }

    fn org_query_value(&self) -> &'static str {
        match self {
            RepoType::All => "all",
            RepoType::Source => "sources",
            RepoType::Fork => "forks",
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
    let trimmed = path.trim().trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let mut parts = trimmed.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
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

use crate::git_host;

fn build_exclude_matcher(exclude_repos: &[String]) -> git_host::ExcludeMatcher {
    git_host::build_exclude_matcher(exclude_repos, parse_excluded_repo, "GitHub")
}

fn should_exclude_repo(clone_url: &str, excludes: &git_host::ExcludeMatcher) -> bool {
    git_host::should_exclude_repo(clone_url, excludes, parse_repo_name_from_url)
}

fn clean_ref_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return None;
    }
    Some(trimmed.to_string())
}

fn clean_commit_sha(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if (7..=64).contains(&trimmed.len()) && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn clone_host_for_api(api_url: &Url) -> Option<String> {
    let host = match api_url.host_str()?.to_ascii_lowercase().as_str() {
        "api.github.com" => "github.com".to_string(),
        other => other.to_string(),
    };
    Some(match api_url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn repo_clone_url_from_event(api_base: &Url, repo_name: &str) -> Option<GitUrl> {
    let repo = parse_repo_name_from_path(repo_name)?;
    let host = clone_host_for_api(api_base)?;
    GitUrl::from_str(&format!("{}://{host}/{repo}.git", api_base.scheme())).ok()
}

fn event_created_at(event: &GitHubEvent) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(&event.created_at).ok().map(|dt| dt.with_timezone(&Utc))
}

fn targets_from_event(api_base: &Url, event: GitHubEvent) -> Vec<GitHubEventScanTarget> {
    let Some(repo_url) = repo_clone_url_from_event(api_base, &event.repo.name) else {
        return Vec::new();
    };

    let mut selectors = Vec::new();
    match event.event_type.as_str() {
        "PushEvent" => {
            if let Ok(payload) = serde_json::from_value::<GitHubPushPayload>(event.payload.clone())
            {
                for commit in payload.commits {
                    if let Some(sha) = clean_commit_sha(&commit.sha) {
                        selectors.push(GitHubEventScanSelector::Commit(sha));
                    }
                }
                if selectors.is_empty()
                    && let Some(head) = payload.head.as_deref().and_then(clean_commit_sha)
                {
                    selectors.push(GitHubEventScanSelector::Commit(head));
                }
            }
        }
        "CreateEvent" => {
            if let Ok(payload) =
                serde_json::from_value::<GitHubCreatePayload>(event.payload.clone())
            {
                match payload.ref_type.as_deref() {
                    Some("repository") => selectors.push(GitHubEventScanSelector::Repository),
                    Some("branch") => {
                        if let Some(ref_name) = payload.ref_name.as_deref().and_then(clean_ref_name)
                        {
                            selectors.push(GitHubEventScanSelector::Branch(ref_name));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }

    selectors
        .into_iter()
        .map(|selector| GitHubEventScanTarget { repo_url: repo_url.clone(), selector })
        .collect()
}

fn collapse_redundant_event_targets(
    targets: Vec<GitHubEventScanTarget>,
) -> Vec<GitHubEventScanTarget> {
    let mut by_repo: BTreeMap<GitUrl, Vec<GitHubEventScanSelector>> = BTreeMap::new();
    for target in targets {
        by_repo.entry(target.repo_url).or_default().push(target.selector);
    }

    let mut collapsed = Vec::new();
    for (repo_url, mut selectors) in by_repo {
        selectors.sort();
        selectors.dedup();
        if selectors.iter().any(|selector| matches!(selector, GitHubEventScanSelector::Repository))
        {
            collapsed.push(GitHubEventScanTarget {
                repo_url,
                selector: GitHubEventScanSelector::Repository,
            });
        } else {
            collapsed.extend(
                selectors
                    .into_iter()
                    .map(|selector| GitHubEventScanTarget { repo_url: repo_url.clone(), selector }),
            );
        }
    }
    collapsed.sort();
    collapsed
}
fn create_github_client(ignore_certs: bool) -> Result<Arc<reqwest::Client>> {
    let mut client_builder = reqwest::Client::builder();
    if ignore_certs {
        client_builder = client_builder.danger_accept_invalid_certs(ignore_certs);
    }

    Ok(Arc::new(client_builder.build().context("Failed to build HTTP client")?))
}

fn normalize_api_base(api_url: &Url) -> Url {
    let mut base = api_url.clone();
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}

pub(crate) async fn github_get(
    client: &reqwest::Client,
    url: Url,
    auth: &GitHubAuth,
    action: &str,
) -> Result<reqwest::Response> {
    retry::send_with_request(
        || async {
            // A quota reset can outlast an installation token. Resolve authentication
            // for every attempt so a resumed request never replays an expired token.
            let token = auth.token(client).await?;
            let req = client.get(url.clone()).header("User-Agent", GLOBAL_USER_AGENT.as_str());
            Ok(if let Some(token) = token { req.bearer_auth(token) } else { req })
        },
        action,
    )
    .await
}

async fn ensure_github_success(
    mut resp: reqwest::Response,
    action: &str,
) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }

    let status = resp.status();
    let url = resp.url().clone();
    warn_on_rate_limit("GitHub", status, action);

    let mut body = match retry::read_body_prefix(&mut resp, 512).await {
        Ok(body) => String::from_utf8_lossy(&body).into_owned(),
        Err(error) => format!("<cannot read response body: {error}>"),
    };
    if body.len() > 512 {
        let mut end = 512;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    anyhow::bail!("GitHub API request failed while {action}: HTTP {status} ({url}): {body}");
}

fn is_github_soft_limit_status(status: StatusCode) -> bool {
    matches!(status, StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS)
}

fn github_next_link(headers: &HeaderMap) -> Option<Url> {
    let raw = headers.get(reqwest::header::LINK)?.to_str().ok()?;
    raw.split(',').find_map(|part| {
        let (url_part, params) = part.trim().split_once(';')?;
        if !params.split(';').any(|param| param.trim() == "rel=\"next\"") {
            return None;
        }
        let url = url_part.trim().strip_prefix('<')?.strip_suffix('>')?;
        Url::parse(url).ok()
    })
}

fn check_github_pagination(
    api_base: &Url,
    url: &Url,
    seen_pages: &mut HashSet<String>,
    resource: &str,
) -> Result<()> {
    anyhow::ensure!(
        url.origin() == api_base.origin() && url.username().is_empty() && url.password().is_none(),
        "GitHub {resource} pagination points to a different origin"
    );
    anyhow::ensure!(
        seen_pages.insert(url.to_string()),
        "GitHub {resource} pagination repeated a page"
    );
    Ok(())
}

async fn fetch_github_orgs(
    client: &reqwest::Client,
    api_base: &Url,
    auth: &GitHubAuth,
) -> Result<Vec<String>> {
    let mut orgs = Vec::new();
    let mut seen_pages = HashSet::new();
    let mut next_url = {
        let mut url = api_base.join("organizations").context("Failed to build GitHub orgs URL")?;
        url.query_pairs_mut().append_pair("per_page", "100");
        Some(url)
    };

    while let Some(url) = next_url {
        check_github_pagination(api_base, &url, &mut seen_pages, "organizations")?;
        let resp = ensure_github_success(
            github_get(client, url, auth, "listing organizations").await?,
            "listing organizations",
        )
        .await?;
        next_url = github_next_link(resp.headers());
        let page_orgs: Vec<GitHubOrg> = resp.json().await?;
        if page_orgs.is_empty() {
            break;
        }
        orgs.extend(page_orgs.into_iter().map(|org| org.login));
    }

    Ok(orgs)
}

#[allow(clippy::too_many_arguments)]
async fn fetch_github_repos(
    client: &reqwest::Client,
    api_base: &Url,
    path: &str,
    repo_type: &str,
    auth: &GitHubAuth,
    action: &str,
    on_repo: &mut (dyn FnMut(&str, Option<u64>) -> Result<()> + Send),
) -> Result<Vec<GitHubRepo>> {
    let mut repos = Vec::new();
    let mut page = 1;

    loop {
        let mut url = api_base.join(path).context("Failed to build GitHub repositories URL")?;
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string())
            .append_pair("type", repo_type)
            .append_pair("sort", "created")
            .append_pair("direction", "desc");
        let resp =
            ensure_github_success(github_get(client, url, auth, action).await?, action).await?;
        let page_repos: Vec<GitHubRepo> = resp.json().await?;
        if page_repos.is_empty() {
            break;
        }
        for repo in &page_repos {
            on_repo(&repo.clone_url, repo.id)?;
        }
        repos.extend(page_repos);
        page += 1;
    }

    Ok(repos)
}

/// Enumerate clone URLs so gists use the same history scanner as repositories.
async fn fetch_github_gist_urls(
    client: &reqwest::Client,
    api_base: &Url,
    username: &str,
    auth: &GitHubAuth,
    on_repo: &mut (dyn FnMut(&str, Option<u64>) -> Result<()> + Send),
) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    let mut seen_pages = HashSet::new();
    let mut next_url = {
        let mut url = api_base
            .join(&format!("users/{username}/gists"))
            .context("Failed to build GitHub user gists URL")?;
        url.query_pairs_mut().append_pair("per_page", "100");
        Some(url)
    };
    while let Some(url) = next_url {
        check_github_pagination(api_base, &url, &mut seen_pages, "gists")?;
        let resp = ensure_github_success(
            github_get(client, url, auth, "listing user gists").await?,
            "listing user gists",
        )
        .await?;
        next_url = github_next_link(resp.headers());
        let gists: Vec<GitHubGist> = resp.json().await?;
        if gists.is_empty() {
            break;
        }
        for gist in gists {
            on_repo(&gist.git_pull_url, None)?;
            urls.push(gist.git_pull_url);
        }
    }
    Ok(urls)
}

pub async fn enumerate_contributor_repo_urls(
    repo_url: &GitUrl,
    github_api_url: &Url,
    ignore_certs: bool,
    exclude_repos: &[String],
    repo_clone_limit: Option<usize>,
    progress_enabled: bool,
    repo_filter: RepoType,
) -> Result<Vec<String>> {
    enumerate_contributor_repo_urls_with_metadata(
        repo_url,
        github_api_url,
        ignore_certs,
        exclude_repos,
        repo_clone_limit,
        progress_enabled,
        repo_filter,
        &mut |_, _| Ok(()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn enumerate_contributor_repo_urls_with_metadata(
    repo_url: &GitUrl,
    github_api_url: &Url,
    ignore_certs: bool,
    exclude_repos: &[String],
    repo_clone_limit: Option<usize>,
    progress_enabled: bool,
    repo_filter: RepoType,
    on_repo: &mut (dyn FnMut(&str, Option<u64>) -> Result<()> + Send),
) -> Result<Vec<String>> {
    let (_, owner, repo) = parse_repo(repo_url).context("invalid GitHub repo URL")?;
    let exclude_set = build_exclude_matcher(exclude_repos);
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;
    let auth = GitHubAuth::from_env(github_api_url, ignore_certs)?;
    let api_base = normalize_api_base(github_api_url);

    let mut contributor_logins = Vec::new();
    let mut seen_contributors = HashSet::new();
    let mut page = 1;
    loop {
        let mut url = api_base
            .join(&format!("repos/{owner}/{repo}/contributors"))
            .context("Failed to build GitHub contributors URL")?;
        url.query_pairs_mut().append_pair("per_page", "100").append_pair("page", &page.to_string());
        let resp = github_get(&client, url, &auth, "listing contributors").await?;
        if is_github_soft_limit_status(resp.status()) {
            warn_on_rate_limit("GitHub", resp.status(), "listing contributors");
            break;
        }
        let resp = ensure_github_success(resp, "listing contributors").await?;
        let contributors: Vec<GitHubContributor> = resp.json().await?;
        if contributors.is_empty() {
            break;
        }
        for contributor in contributors {
            if let Some(login) = contributor.login
                && seen_contributors.insert(login.clone())
            {
                contributor_logins.push(login);
            }
        }
        page += 1;
    }

    let (per_user_limit, total_limit) =
        determine_contributor_repo_limits(repo_clone_limit, contributor_logins.len(), "GitHub");
    let progress = build_contributor_progress_bar(
        progress_enabled,
        contributor_logins.len() as u64,
        "Enumerating GitHub contributor repositories...",
    );

    let mut repo_urls = Vec::new();
    let mut repository_ids = BTreeMap::new();
    let mut total_repo_count = 0usize;
    for login in contributor_logins {
        if let Some(total_limit) = total_limit
            && total_repo_count >= total_limit
        {
            break;
        }
        let mut user_repo_count = 0usize;
        page = 1;
        loop {
            if let Some(per_user_limit) = per_user_limit
                && user_repo_count >= per_user_limit
            {
                break;
            }
            if let Some(total_limit) = total_limit
                && total_repo_count >= total_limit
            {
                break;
            }
            let mut url = api_base
                .join(&format!("users/{login}/repos"))
                .context("Failed to build GitHub user repos URL")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string())
                .append_pair("type", "all")
                .append_pair("sort", "updated")
                .append_pair("direction", "desc");
            let resp = github_get(&client, url, &auth, "listing user repositories").await?;
            if is_github_soft_limit_status(resp.status()) {
                warn_on_rate_limit("GitHub", resp.status(), "listing user repositories");
                break;
            }
            let resp = ensure_github_success(resp, "listing user repositories").await?;
            let repos: Vec<GitHubRepo> = resp.json().await?;
            if repos.is_empty() {
                break;
            }
            for repo in repos {
                if let Some(per_user_limit) = per_user_limit
                    && user_repo_count >= per_user_limit
                {
                    break;
                }
                if let Some(total_limit) = total_limit
                    && total_repo_count >= total_limit
                {
                    break;
                }
                let excluded_by_repo_type = match repo_filter {
                    RepoType::Source => repo.fork,
                    RepoType::Fork => !repo.fork,
                    RepoType::All => false,
                };
                if excluded_by_repo_type {
                    continue;
                }
                if should_exclude_repo(&repo.clone_url, &exclude_set) {
                    continue;
                }
                if let Some(id) = repo.id {
                    repository_ids.insert(repo.clone_url.clone(), id);
                }
                repo_urls.push(repo.clone_url);
                user_repo_count += 1;
                total_repo_count += 1;
            }
            page += 1;
        }
        progress.inc(1);
    }

    repo_urls.sort();
    repo_urls.dedup();
    progress.finish_and_clear();
    for url in &repo_urls {
        on_repo(url, repository_ids.get(url).copied())?;
    }
    Ok(repo_urls)
}

fn warn_on_rate_limit(service: &str, status: StatusCode, action: &str) {
    if status == StatusCode::FORBIDDEN || status == StatusCode::TOO_MANY_REQUESTS {
        warn!("{service} API rate limit or access restriction while {action}: HTTP {status}");
    }
}

fn determine_contributor_repo_limits(
    repo_clone_limit: Option<usize>,
    user_count: usize,
    service: &str,
) -> (Option<usize>, Option<usize>) {
    let Some(limit) = repo_clone_limit else {
        return (None, None);
    };
    if user_count == 0 {
        return (Some(0), Some(limit));
    }
    if user_count > limit {
        let per_user_limit = std::cmp::max(1, limit / 100);
        info!(
            "Found {user_count} {service} contributors which exceeds repo-clone-limit {limit}. \
Consider increasing repo-clone-limit; sampling {per_user_limit} repos per user until the limit is reached."
        );
        return (Some(per_user_limit), Some(limit));
    }
    let per_user_limit = std::cmp::max(1, limit / user_count);
    (Some(per_user_limit), Some(limit))
}

fn build_contributor_progress_bar(
    progress_enabled: bool,
    length: u64,
    message: &str,
) -> ProgressBar {
    if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new(length).with_style(style).with_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    }
}

pub async fn enumerate_public_event_targets(
    users: &[String],
    lookback_hours: u64,
    github_url: Url,
    ignore_certs: bool,
    exclude_repos: &[String],
    repo_clone_limit: Option<usize>,
    progress: Option<&mut ProgressBar>,
) -> Result<Vec<GitHubEventScanTarget>> {
    enumerate_public_event_targets_with_metadata(
        users,
        lookback_hours,
        github_url,
        ignore_certs,
        exclude_repos,
        repo_clone_limit,
        progress,
        &mut |_, _| Ok(()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn enumerate_public_event_targets_with_metadata(
    users: &[String],
    lookback_hours: u64,
    github_url: Url,
    ignore_certs: bool,
    exclude_repos: &[String],
    repo_clone_limit: Option<usize>,
    mut progress: Option<&mut ProgressBar>,
    on_repository_id: &mut (dyn FnMut(&GitUrl, u64) -> Result<()> + Send),
) -> Result<Vec<GitHubEventScanTarget>> {
    if users.is_empty() {
        return Ok(Vec::new());
    }

    let client = create_github_client(ignore_certs)?;
    let api_base = normalize_api_base(&github_url);
    let auth = GitHubAuth::from_env(&github_url, ignore_certs)?;
    let exclude_set = build_exclude_matcher(exclude_repos);
    let cutoff = Utc::now() - ChronoDuration::hours(lookback_hours.min(i64::MAX as u64) as i64);
    let mut targets = Vec::new();
    let mut repository_ids = BTreeMap::new();

    for username in users {
        let mut seen_pages = HashSet::new();
        let mut next_url = {
            let mut url = api_base
                .join(&format!("users/{username}/events/public"))
                .context("Failed to build GitHub public events URL")?;
            url.query_pairs_mut().append_pair("per_page", "100");
            Some(url)
        };

        while let Some(url) = next_url {
            check_github_pagination(&api_base, &url, &mut seen_pages, "public events")?;
            let resp = ensure_github_success(
                github_get(&client, url, &auth, "listing public user events").await?,
                "listing public user events",
            )
            .await?;
            next_url = github_next_link(resp.headers());
            let events: Vec<GitHubEvent> = resp.json().await?;
            if events.is_empty() {
                break;
            }

            let mut reached_cutoff = false;
            for event in events {
                if let Some(created_at) = event_created_at(&event)
                    && created_at < cutoff
                {
                    reached_cutoff = true;
                    break;
                }

                let repository_id = event.repo.id;
                for target in targets_from_event(&api_base, event) {
                    if should_exclude_repo(target.repo_url.as_str(), &exclude_set) {
                        continue;
                    }
                    if let Some(id) = repository_id {
                        repository_ids.insert(target.repo_url.clone(), id);
                    }
                    targets.push(target);
                }
            }

            if reached_cutoff {
                break;
            }
        }

        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }

    let mut targets = collapse_redundant_event_targets(targets);
    if let Some(limit) = repo_clone_limit {
        let mut seen_repos = BTreeSet::new();
        targets.retain(|target| {
            if seen_repos.contains(&target.repo_url) {
                return true;
            }
            if seen_repos.len() >= limit {
                return false;
            }
            seen_repos.insert(target.repo_url.clone());
            true
        });
    }

    let mut emitted_repositories = BTreeSet::new();
    for target in &targets {
        if emitted_repositories.insert(&target.repo_url)
            && let Some(id) = repository_ids.get(&target.repo_url)
        {
            on_repository_id(&target.repo_url, *id)?;
        }
    }

    Ok(targets)
}

pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    enumerate_repo_urls_streaming(repo_specifiers, github_url, ignore_certs, progress, &mut |_| {
        Ok(())
    })
    .await
}

/// Emit repositories as API pages arrive, before discovery of subsequent sources.
pub async fn enumerate_repo_urls_streaming(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    progress: Option<&mut ProgressBar>,
    on_repo: &mut (dyn FnMut(&str) -> Result<()> + Send),
) -> Result<Vec<String>> {
    enumerate_repo_urls_with_metadata(
        repo_specifiers,
        github_url,
        ignore_certs,
        progress,
        &mut |url, _| on_repo(url),
    )
    .await
}

/// Preserve repository IDs from the same API page that supplies each clone URL.
pub(crate) async fn enumerate_repo_urls_with_metadata(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
    on_repo: &mut (dyn FnMut(&str, Option<u64>) -> Result<()> + Send),
) -> Result<Vec<String>> {
    let client = create_github_client(ignore_certs)?;
    let mut repo_urls = Vec::new();
    let exclude_set = build_exclude_matcher(&repo_specifiers.exclude_repos);
    let api_base = normalize_api_base(&github_url);
    let auth = GitHubAuth::from_env(&github_url, ignore_certs)?;
    let mut emit = |url: &str, id: Option<u64>| {
        if should_exclude_repo(url, &exclude_set) { Ok(()) } else { on_repo(url, id) }
    };
    for username in &repo_specifiers.user {
        let repos = fetch_github_repos(
            &client,
            &api_base,
            &format!("users/{username}/repos"),
            repo_specifiers.repo_filter.user_query_value(),
            &auth,
            "listing user repositories",
            &mut emit,
        )
        .await?;
        repo_urls.extend(repos.into_iter().filter_map(|repo| {
            let clone_url = repo.clone_url;
            if should_exclude_repo(&clone_url, &exclude_set) { None } else { Some(clone_url) }
        }));
        if repo_specifiers.include_gists {
            repo_urls.extend(
                fetch_github_gist_urls(&client, &api_base, username, &auth, &mut emit).await?,
            );
        }
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    let orgs = if repo_specifiers.all_organizations {
        fetch_github_orgs(&client, &api_base, &auth).await?
    } else {
        repo_specifiers.organization.clone()
    };
    for org_name in orgs {
        let repos = fetch_github_repos(
            &client,
            &api_base,
            &format!("orgs/{org_name}/repos"),
            repo_specifiers.repo_filter.org_query_value(),
            &auth,
            "listing organization repositories",
            &mut emit,
        )
        .await?;
        repo_urls.extend(repos.into_iter().filter_map(|repo| {
            let clone_url = repo.clone_url;
            if should_exclude_repo(&clone_url, &exclude_set) { None } else { Some(clone_url) }
        }));
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}
#[allow(clippy::too_many_arguments)]
pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    include_gists: bool,
    orgs: &[String],
    all_orgs: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        include_gists,
        organization: orgs.to_vec(),
        all_organizations: all_orgs,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let repo_urls =
        enumerate_repo_urls(&repo_specifiers, api_url, ignore_certs, Some(&mut progress)).await?;
    // Print repositories
    for url in repo_urls {
        println!("{}", url);
    }
    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<(String, String, String)> {
    let url = Url::parse(repo_url.as_str()).ok()?;
    let host = url[url::Position::BeforeHost..url::Position::AfterPort].to_string();
    let mut segments = url.path_segments()?;
    let owner = segments.next()?.to_string();
    let mut repo = segments.next()?.to_string();
    if let Some(stripped) = repo.strip_suffix(".git") {
        repo = stripped.to_string();
    }
    Some((host, owner, repo))
}

fn repository_id_lookup_url(repo_url: &GitUrl, api_url: &Url) -> Option<(String, Url)> {
    let repo = Url::parse(repo_url.as_str()).ok()?;
    let host = repo[url::Position::BeforeHost..url::Position::AfterPort].to_ascii_lowercase();
    let configured_host = clone_host_for_api(api_url)?;
    if !host.eq_ignore_ascii_case(&configured_host) {
        return None;
    }

    let segments = repo.path_segments()?.collect::<Vec<_>>();
    // Accept a trailing slash, but never resolve a file, issue, or other nested URL.
    let (owner, name) = match segments.as_slice() {
        [owner, name] | [owner, name, ""] => (*owner, *name),
        _ => return None,
    };
    let name = name.strip_suffix(".git").unwrap_or(name);
    if owner.is_empty()
        || !owner.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || name.is_empty()
        || matches!(name, "." | "..")
        || name.ends_with(".wiki")
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return None;
    }

    let url = normalize_api_base(api_url).join(&format!("repos/{owner}/{name}")).ok()?;
    Some((host, url))
}

/// Best-effort enrichment for explicitly requested repositories. Discovery already
/// supplies IDs from its listing responses and needs no additional API requests.
pub(crate) async fn fetch_repository_id(
    repo_url: &GitUrl,
    github_api_url: &Url,
    ignore_certs: bool,
) -> Result<Option<u64>> {
    let Some((host, url)) = repository_id_lookup_url(repo_url, github_api_url) else {
        return Ok(None);
    };
    let timeout = Duration::from_secs(5);
    tokio::time::timeout(timeout, async {
        let auth = GitHubAuth::from_env(github_api_url, ignore_certs)?;
        if !auth.allows_clone_host(&host) {
            return Ok(None);
        }
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ignore_certs)
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("Failed to build GitHub repository metadata client")?;
        let token = auth.token(&client).await?;
        let request = client.get(url).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        let request = if let Some(token) = token { request.bearer_auth(token) } else { request };
        // Optional metadata must not inherit the discovery retry/rate-limit wait budget.
        Ok(match crate::git_host::repository_id_response(request, "id").await? {
            Some(crate::git_host::RepositoryId::Numeric(id)) => Some(id),
            _ => None,
        })
    })
    .await
    .context("GitHub repository metadata lookup timed out")?
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let (host, owner, repo) = parse_repo(repo_url)?;
    let wiki = format!("https://{host}/{owner}/{repo}.wiki.git");
    GitUrl::from_str(&wiki).ok()
}

fn artifact_html_url(value: &Value, fallback: String) -> String {
    value
        .get("html_url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())
        .map(str::to_string)
        .unwrap_or(fallback)
}

fn fallback_gist_url(host: &str, id: &str) -> String {
    if host.eq_ignore_ascii_case("github.com") {
        format!("https://gist.github.com/{id}")
    } else {
        format!("https://{host}/gist/{id}")
    }
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    github_api_url: &Url,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (host, owner, repo) = parse_repo(repo_url).context("invalid GitHub repo URL")?;
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;
    let api_base = normalize_api_base(github_api_url);
    let auth = GitHubAuth::from_env(github_api_url, ignore_certs)?;

    let mut dirs = Vec::new();

    // Issues
    let issues_dir = output_root.join("github_issues").join(&owner).join(&repo);
    fs::create_dir_all(&issues_dir)?;
    let mut page = 1;
    loop {
        let mut url = api_base
            .join(&format!("repos/{owner}/{repo}/issues"))
            .context("Failed to build GitHub issues URL")?;
        url.query_pairs_mut()
            .append_pair("state", "all")
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let resp = github_get(&client, url, &auth, "listing repository issues").await?;
        if !resp.status().is_success() {
            break;
        }
        let issues: Vec<Value> = resp.json().await?;
        if issues.is_empty() {
            break;
        }
        for issue in issues {
            let number = issue.get("number").and_then(|v| v.as_u64()).unwrap_or(0);
            let title = issue.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = issue.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let content = format!("# {title}\n\n{body}");
            let file_path = issues_dir.join(format!("issue_{number}.md"));
            fs::write(&file_path, content)?;
            let url =
                artifact_html_url(&issue, format!("https://{host}/{owner}/{repo}/issues/{number}"));
            let mut ds = datastore.lock().unwrap();
            ds.register_repo_link(file_path, url);
        }
        page += 1;
    }
    if issues_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(issues_dir);
    }

    // Gists
    let gists_dir = output_root.join("github_gists").join(&owner);
    fs::create_dir_all(&gists_dir)?;
    let mut seen = HashSet::new();

    // Public gists for the owner
    page = 1;
    loop {
        let mut url = api_base
            .join(&format!("users/{owner}/gists"))
            .context("Failed to build GitHub user gists URL")?;
        url.query_pairs_mut().append_pair("per_page", "100").append_pair("page", &page.to_string());
        let resp = github_get(&client, url, &auth, "listing user gists").await?;
        if !resp.status().is_success() {
            break;
        }
        let gists: Vec<Value> = resp.json().await?;
        if gists.is_empty() {
            break;
        }
        for gist in gists {
            if let Some(id) = gist.get("id").and_then(|v| v.as_str())
                && seen.insert(id.to_string())
            {
                let url = api_base
                    .join(&format!("gists/{id}"))
                    .context("Failed to build GitHub gist URL")?;
                let detail: Value =
                    github_get(&client, url, &auth, "fetching gist").await?.json().await?;
                let gist_url = artifact_html_url(&detail, fallback_gist_url(&host, id));
                if let Some(files) = detail.get("files").and_then(|v| v.as_object()) {
                    let gist_dir = gists_dir.join(id);
                    fs::create_dir_all(&gist_dir)?;
                    for (fname, fobj) in files {
                        if let Some(content) = fobj.get("content").and_then(|v| v.as_str()) {
                            let file_path = gist_dir.join(fname);
                            fs::write(&file_path, content)?;
                            let mut ds = datastore.lock().unwrap();
                            ds.register_repo_link(file_path, gist_url.clone());
                        }
                    }
                }
            }
        }
        page += 1;
    }

    // Private gists for authenticated user if they own the repo
    if auth.token(&client).await?.is_some() {
        page = 1;
        loop {
            let mut url =
                api_base.join("gists").context("Failed to build authenticated GitHub gists URL")?;
            url.query_pairs_mut()
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let resp = github_get(&client, url, &auth, "listing authenticated gists").await?;
            if !resp.status().is_success() {
                break;
            }
            let gists: Vec<Value> = resp.json().await?;
            if gists.is_empty() {
                break;
            }
            for gist in gists {
                let owner_login =
                    gist.get("owner").and_then(|o| o.get("login")).and_then(|v| v.as_str());
                if owner_login == Some(owner.as_str())
                    && let Some(id) = gist.get("id").and_then(|v| v.as_str())
                    && seen.insert(id.to_string())
                {
                    let url = api_base
                        .join(&format!("gists/{id}"))
                        .context("Failed to build GitHub gist URL")?;
                    let detail: Value =
                        github_get(&client, url, &auth, "fetching gist").await?.json().await?;
                    let gist_url = artifact_html_url(&detail, fallback_gist_url(&host, id));
                    if let Some(files) = detail.get("files").and_then(|v| v.as_object()) {
                        let gist_dir = gists_dir.join(id);
                        fs::create_dir_all(&gist_dir)?;
                        for (fname, fobj) in files {
                            if let Some(content) = fobj.get("content").and_then(|v| v.as_str()) {
                                let file_path = gist_dir.join(fname);
                                fs::write(&file_path, content)?;
                                let mut ds = datastore.lock().unwrap();
                                ds.register_repo_link(file_path, gist_url.clone());
                            }
                        }
                    }
                }
            }
            page += 1;
        }
    }

    if gists_dir.read_dir().ok().and_then(|mut d| d.next()).is_some() {
        dirs.push(gists_dir);
    }

    Ok(dirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repository_ids_preserve_numeric_values_and_allow_missing_metadata() {
        let id = 9_007_199_254_740_993_u64;
        let repo: GitHubRepo = serde_json::from_value(json!({
            "id": id,
            "clone_url": "https://github.com/acme/repo.git",
            "fork": true,
            "parent": {"id": 123}
        }))
        .unwrap();
        assert_eq!(repo.id, Some(id));
        let repo: GitHubRepo = serde_json::from_value(json!({
            "clone_url": "https://github.com/acme/repo.git", "fork": false
        }))
        .unwrap();
        assert_eq!(repo.id, None);
        let event_repo: GitHubEventRepo =
            serde_json::from_value(json!({"id": id, "name": "acme/repo"})).unwrap();
        assert_eq!(event_repo.id, Some(id));
    }

    #[test]
    fn repository_id_lookup_requires_a_trusted_repository_url() {
        let public_api = Url::parse("https://api.github.com/").unwrap();
        let enterprise_api = Url::parse("https://ghe.example.com:8443/api/v3").unwrap();
        for repo_url in ["https://github.com/Acme/repo.git", "https://github.com/Acme/repo/"] {
            let (_, url) =
                repository_id_lookup_url(&GitUrl::from_str(repo_url).unwrap(), &public_api)
                    .unwrap();
            assert_eq!(url.as_str(), "https://api.github.com/repos/Acme/repo");
        }
        let (host, url) = repository_id_lookup_url(
            &GitUrl::from_str("https://ghe.example.com:8443/acme/my_repo.git").unwrap(),
            &enterprise_api,
        )
        .unwrap();
        assert_eq!(host, "ghe.example.com:8443");
        assert_eq!(url.as_str(), "https://ghe.example.com:8443/api/v3/repos/acme/my_repo");
        assert!(
            repository_id_lookup_url(
                &GitUrl::from_str("https://github.com/acme/repo.git").unwrap(),
                &enterprise_api,
            )
            .is_none()
        );

        for repo_url in [
            "https://example.com/acme/repo.git",
            "https://gist.github.com/acme/123456.git",
            "https://api.github.com/acme/repo.git",
            "https://github.com:8443/acme/repo.git",
            "https://github.com/acme/repo/tree/main",
            "https://github.com/acme/repo.wiki.git",
            "https://github.com/acme/",
            "https://github.com/acme/repo//",
            "https://github.com/acme/repo%2Fother.git",
        ] {
            assert!(
                repository_id_lookup_url(&GitUrl::from_str(repo_url).unwrap(), &public_api)
                    .is_none(),
                "unexpected lookup for {repo_url}"
            );
        }
    }

    #[tokio::test]
    async fn repository_metadata_lookup_is_authenticated_and_does_not_retry_optional_failures() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path},
        };
        temp_env::async_with_vars(
            [
                ("KF_GITHUB_TOKEN", Some("repository-secret")),
                ("KF_GITHUB_APP_ID", None),
                ("KF_GITHUB_APP_INSTALLATION_ID", None),
                ("KF_GITHUB_APP_PRIVATE_KEY", None),
                ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
            ],
            async {
                for (status, body, expected) in [
                    (200, json!({"id": 9_007_199_254_740_993_u64}), Some(9_007_199_254_740_993)),
                    (200, json!({}), None),
                    (200, json!({"id": 123, "padding": "x".repeat(1024 * 1024)}), None),
                    (404, json!({"message": "Not Found"}), None),
                    (429, json!({"message": "Rate limit exceeded"}), None),
                    (503, json!({"message": "Unavailable"}), None),
                ] {
                    let server = MockServer::start().await;
                    Mock::given(method("GET"))
                        .and(path("/api/v3/repos/acme/repo"))
                        .and(header("authorization", "Bearer repository-secret"))
                        .respond_with(
                            ResponseTemplate::new(status)
                                .insert_header("retry-after", "600")
                                .set_body_json(body),
                        )
                        .expect(1)
                        .mount(&server)
                        .await;
                    let api = Url::parse(&format!("{}/api/v3/", server.uri())).unwrap();
                    let repo =
                        GitUrl::from_str(&format!("{}/acme/repo.git", server.uri())).unwrap();
                    let id = tokio::time::timeout(
                        Duration::from_secs(2),
                        fetch_repository_id(&repo, &api, false),
                    )
                    .await
                    .expect("optional metadata must not wait for a rate-limit reset")
                    .unwrap();
                    assert_eq!(id, expected);
                }
            },
        )
        .await;
    }

    #[tokio::test]
    async fn repository_metadata_lookup_does_not_follow_redirects() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", other.uri()))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 123})))
            .expect(0)
            .mount(&other)
            .await;
        let repo = GitUrl::from_str(&format!("{}/acme/repo.git", server.uri())).unwrap();
        let id = temp_env::async_with_vars(
            [
                ("KF_GITHUB_TOKEN", Some("repository-secret")),
                ("KF_GITHUB_APP_ID", None),
                ("KF_GITHUB_APP_INSTALLATION_ID", None),
                ("KF_GITHUB_APP_PRIVATE_KEY", None),
                ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
            ],
            fetch_repository_id(&repo, &Url::parse(&server.uri()).unwrap(), false),
        )
        .await
        .unwrap();
        assert_eq!(id, None);
        assert!(other.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn repository_listing_emits_ids_and_leaves_gists_without_numeric_ids() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path, query_param},
        };
        let server = MockServer::start().await;
        let first_page = json!([
            {"id": 123, "clone_url": "https://github.com/acme/keep.git", "fork": false},
            {"id": 456, "clone_url": "https://github.com/acme/skip.git", "fork": false}
        ]);
        for (page_number, body) in [("1", first_page), ("2", json!([]))] {
            Mock::given(method("GET"))
                .and(path("/users/alice/repos"))
                .and(query_param("page", page_number))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/users/alice/gists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!([{"git_pull_url": "https://gist.github.com/012345abcdef.git"}]),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let specs = RepoSpecifiers {
            user: vec!["alice".into()],
            include_gists: true,
            organization: vec![],
            all_organizations: false,
            repo_filter: RepoType::All,
            exclude_repos: vec!["acme/skip".into()],
        };
        let mut emitted = Vec::new();
        let urls = temp_env::async_with_vars(
            [
                ("KF_GITHUB_TOKEN", None::<&str>),
                ("KF_GITHUB_APP_ID", None),
                ("KF_GITHUB_APP_INSTALLATION_ID", None),
                ("KF_GITHUB_APP_PRIVATE_KEY", None),
                ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
            ],
            enumerate_repo_urls_with_metadata(
                &specs,
                Url::parse(&server.uri()).unwrap(),
                false,
                None,
                &mut |url, id| {
                    emitted.push((url.to_string(), id));
                    Ok(())
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            emitted,
            [
                ("https://github.com/acme/keep.git".into(), Some(123)),
                ("https://gist.github.com/012345abcdef.git".into(), None),
            ]
        );
        assert_eq!(urls.len(), 2);
    }

    #[tokio::test]
    async fn public_events_emit_ids_only_for_selected_repositories() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let events = [("acme/first", 123), ("acme/second", 456), ("acme/excluded", 789)]
            .into_iter()
            .map(|(name, id)| {
                json!({
                    "type": "CreateEvent", "repo": {"name": name, "id": id},
                    "payload": {"ref_type": "repository"},
                    "created_at": Utc::now().to_rfc3339()
                })
            })
            .collect::<Vec<_>>();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(events))
            .expect(1)
            .mount(&server)
            .await;
        let mut emitted = Vec::new();
        let targets = temp_env::async_with_vars(
            [
                ("KF_GITHUB_TOKEN", None::<&str>),
                ("KF_GITHUB_APP_ID", None),
                ("KF_GITHUB_APP_INSTALLATION_ID", None),
                ("KF_GITHUB_APP_PRIVATE_KEY", None),
                ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
            ],
            enumerate_public_event_targets_with_metadata(
                &["alice".into()],
                24,
                Url::parse(&server.uri()).unwrap(),
                false,
                &["acme/excluded".into()],
                Some(1),
                None,
                &mut |repo, id| {
                    emitted.push((repo.to_string(), id));
                    Ok(())
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(emitted, [(format!("{}/acme/first.git", server.uri()), 123)]);
    }

    async fn fetch_test_orgs(
        client: &reqwest::Client,
        base: &Url,
        token: Option<&str>,
    ) -> Result<Vec<String>> {
        temp_env::async_with_vars(
            [
                ("KF_GITHUB_TOKEN", token),
                ("KF_GITHUB_APP_ID", None),
                ("KF_GITHUB_APP_INSTALLATION_ID", None),
                ("KF_GITHUB_APP_PRIVATE_KEY", None),
                ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
            ],
            async {
                let auth = GitHubAuth::from_env(base, false)?;
                fetch_github_orgs(client, base, &auth).await
            },
        )
        .await
    }

    #[tokio::test]
    async fn organization_and_event_pagination_reject_cross_origin_links_and_cycles() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        for events in [false, true] {
            for cross_origin in [false, true] {
                let server = MockServer::start().await;
                let other = MockServer::start().await;
                let endpoint = if events { "users/alice/events/public" } else { "organizations" };
                let origin = if cross_origin { other.uri() } else { server.uri() };
                let next = format!("<{origin}/api/v3/{endpoint}?per_page=100>; rel=\"next\"");
                let body = if events {
                    json!([{"type":"CreateEvent", "repo":{"name":"alice/repo"},
                        "payload":{"ref_type":"repository"}, "created_at": Utc::now().to_rfc3339()}])
                } else {
                    json!([{"login":"acme"}])
                };
                Mock::given(method("GET"))
                    .respond_with(
                        ResponseTemplate::new(200)
                            .insert_header("link", next.as_str())
                            .set_body_json(body),
                    )
                    .expect(1)
                    .mount(&server)
                    .await;
                Mock::given(method("GET"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                    .expect(0)
                    .mount(&other)
                    .await;
                let base = Url::parse(&format!("{}/api/v3/", server.uri())).unwrap();
                let result = if events {
                    temp_env::async_with_vars(
                        [
                            ("KF_GITHUB_TOKEN", Some("pagination-secret")),
                            ("KF_GITHUB_APP_ID", None),
                            ("KF_GITHUB_APP_INSTALLATION_ID", None),
                            ("KF_GITHUB_APP_PRIVATE_KEY", None),
                            ("KF_GITHUB_APP_PRIVATE_KEY_PATH", None),
                        ],
                        enumerate_public_event_targets(
                            &["alice".into()],
                            24,
                            base,
                            false,
                            &[],
                            None,
                            None,
                        ),
                    )
                    .await
                    .map(|_| ())
                } else {
                    fetch_test_orgs(&reqwest::Client::new(), &base, Some("pagination-secret"))
                        .await
                        .map(|_| ())
                };
                let error = result.unwrap_err();
                let expected = if cross_origin { "different origin" } else { "repeated a page" };
                assert!(error.to_string().contains(expected), "{error}");
                assert!(other.received_requests().await.unwrap().is_empty());
                let requests = server.received_requests().await.unwrap();
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].headers["authorization"], "Bearer pagination-secret");
            }
        }
    }

    #[tokio::test]
    async fn organizations_follow_same_origin_pagination() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, query_param, query_param_is_missing},
        };
        let server = MockServer::start().await;
        let next = format!("<{}/api/v3/organizations?since=42>; rel=\"next\"", server.uri());
        Mock::given(method("GET"))
            .and(query_param_is_missing("since"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("link", next.as_str())
                    .set_body_json(json!([{"login":"first"}])),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("since", "42"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"login":"second"}])))
            .expect(1)
            .mount(&server)
            .await;
        let base = Url::parse(&format!("{}/api/v3/", server.uri())).unwrap();
        let organizations = fetch_test_orgs(&reqwest::Client::new(), &base, None).await.unwrap();
        assert_eq!(organizations, ["first", "second"]);
    }

    #[test]
    fn pagination_guard_checks_scheme_port_and_embedded_credentials() {
        let base = Url::parse("https://api.github.com/").unwrap();
        for next in [
            "http://api.github.com/organizations",
            "https://api.github.com:444/organizations",
            "https://user:password@api.github.com/organizations",
        ] {
            assert!(
                check_github_pagination(
                    &base,
                    &Url::parse(next).unwrap(),
                    &mut HashSet::new(),
                    "test"
                )
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn api_error_reporting_stops_at_its_body_prefix_without_draining_the_stream() {
        use futures::StreamExt;
        let stream =
            futures::stream::once(std::future::ready(Ok::<_, std::io::Error>(vec![b'x'; 513])))
                .chain(futures::stream::pending());
        let response = http::Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(reqwest::Body::wrap_stream(stream))
            .unwrap()
            .into();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            ensure_github_success(response, "testing bounded error reporting"),
        )
        .await
        .expect("error reporting must not drain an infinite body")
        .unwrap_err();
        assert!(error.to_string().contains("HTTP 400"));
        assert!(error.to_string().ends_with(&"x".repeat(512)));
    }

    #[tokio::test]
    async fn api_error_body_is_truncated_at_a_utf8_boundary() {
        let response = http::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(format!("{}é", "x".repeat(511)))
            .unwrap()
            .into();
        let error = ensure_github_success(response, "testing error reporting").await.unwrap_err();
        assert!(error.to_string().ends_with(&"x".repeat(511)));
    }

    fn public_event(event_type: &str, payload: Value) -> GitHubEvent {
        GitHubEvent {
            event_type: event_type.to_string(),
            repo: GitHubEventRepo { id: None, name: "Owner/Repo".to_string() },
            payload,
            created_at: "2026-06-25T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn parse_excluded_repo_variants() {
        assert_eq!(parse_excluded_repo("Owner/Repo").as_deref(), Some("owner/repo"));
        assert_eq!(parse_excluded_repo("owner/repo.git").as_deref(), Some("owner/repo"));
        assert_eq!(
            parse_excluded_repo("https://github.com/Owner/Repo.git").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(
            parse_excluded_repo("git@github.com:Owner/Repo.git").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(
            parse_excluded_repo("ssh://git@github.example.com/Owner/Repo.git").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(
            parse_excluded_repo("  https://github.com/Owner/Repo  ").as_deref(),
            Some("owner/repo")
        );
        assert_eq!(parse_excluded_repo("not-a-repo"), None);
    }

    #[test]
    fn should_exclude_repo_matches_normalized_names() {
        let excludes = build_exclude_matcher(&["Owner/Repo".to_string()]);
        assert!(should_exclude_repo("https://github.com/owner/repo.git", &excludes));
        assert!(!should_exclude_repo("https://github.com/owner/other.git", &excludes));
    }

    #[test]
    fn should_exclude_repo_matches_ssh_urls() {
        let excludes = build_exclude_matcher(&["owner/repo".to_string()]);
        assert!(should_exclude_repo("ssh://git@github.example.com/owner/repo.git", &excludes));
    }

    #[test]
    fn should_exclude_repo_matches_globs() {
        let excludes = build_exclude_matcher(&["owner/*-archive".to_string()]);
        assert!(should_exclude_repo("https://github.com/owner/project-archive.git", &excludes));
        assert!(!should_exclude_repo("https://github.com/owner/project.git", &excludes));
    }

    #[test]
    fn artifact_links_preserve_github_enterprise_hosts() {
        let issue = json!({ "html_url": "https://ghe.example.com/acme/widgets/issues/7" });
        assert_eq!(
            artifact_html_url(&issue, "https://github.com/acme/widgets/issues/7".to_string()),
            "https://ghe.example.com/acme/widgets/issues/7"
        );
        assert_eq!(
            fallback_gist_url("ghe.example.com", "abc123"),
            "https://ghe.example.com/gist/abc123"
        );
        assert_eq!(fallback_gist_url("github.com", "abc123"), "https://gist.github.com/abc123");
    }

    #[test]
    fn github_enterprise_urls_preserve_non_default_ports() {
        let repo_url = GitUrl::from_str("https://ghe.example.com:8443/acme/widgets.git").unwrap();

        assert_eq!(
            parse_repo(&repo_url),
            Some(("ghe.example.com:8443".to_string(), "acme".to_string(), "widgets".to_string(),))
        );
        assert_eq!(
            wiki_url(&repo_url).unwrap().as_str(),
            "https://ghe.example.com:8443/acme/widgets.wiki.git"
        );
        assert_eq!(
            fallback_gist_url("ghe.example.com:8443", "abc123"),
            "https://ghe.example.com:8443/gist/abc123"
        );
    }

    #[test]
    fn github_next_link_parses_next_relation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            r#"<https://api.github.com/organizations?since=42>; rel="next", <https://api.github.com/organizations?since=1>; rel="first""#
                .parse()
                .unwrap(),
        );

        let next = github_next_link(&headers).unwrap();
        assert_eq!(next.as_str(), "https://api.github.com/organizations?since=42");
    }

    #[test]
    fn github_next_link_returns_none_without_next_relation() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::LINK,
            r#"<https://api.github.com/organizations?since=1>; rel="first""#.parse().unwrap(),
        );

        assert!(github_next_link(&headers).is_none());
    }

    #[test]
    fn public_push_event_targets_each_commit() {
        let api_base = Url::parse("https://api.github.com/").unwrap();
        let first = "0123456789abcdef0123456789abcdef01234567";
        let second = "89abcdef0123456789abcdef0123456789abcdef";
        let targets = targets_from_event(
            &api_base,
            public_event(
                "PushEvent",
                json!({
                    "commits": [
                        { "sha": first },
                        { "sha": second }
                    ],
                    "head": second
                }),
            ),
        );

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].repo_url.as_str(), "https://github.com/owner/repo.git");
        assert_eq!(targets[0].selector, GitHubEventScanSelector::Commit(first.to_string()));
        assert_eq!(targets[1].selector, GitHubEventScanSelector::Commit(second.to_string()));
    }

    #[test]
    fn public_create_event_targets_branch_or_repository() {
        let api_base = Url::parse("https://api.github.com/").unwrap();
        let branch_targets = targets_from_event(
            &api_base,
            public_event(
                "CreateEvent",
                json!({
                    "ref_type": "branch",
                    "ref": "feature/secrets"
                }),
            ),
        );
        let repo_targets = targets_from_event(
            &api_base,
            public_event("CreateEvent", json!({ "ref_type": "repository", "ref": null })),
        );

        assert_eq!(branch_targets.len(), 1);
        assert_eq!(
            branch_targets[0].selector,
            GitHubEventScanSelector::Branch("feature/secrets".to_string())
        );
        assert_eq!(repo_targets.len(), 1);
        assert_eq!(repo_targets[0].selector, GitHubEventScanSelector::Repository);
    }

    #[test]
    fn repository_event_target_supersedes_narrower_targets() {
        let repo_url = GitUrl::from_str("https://github.com/owner/repo.git").unwrap();
        let targets = collapse_redundant_event_targets(vec![
            GitHubEventScanTarget {
                repo_url: repo_url.clone(),
                selector: GitHubEventScanSelector::Commit(
                    "0123456789abcdef0123456789abcdef01234567".to_string(),
                ),
            },
            GitHubEventScanTarget {
                repo_url: repo_url.clone(),
                selector: GitHubEventScanSelector::Branch("main".to_string()),
            },
            GitHubEventScanTarget { repo_url, selector: GitHubEventScanSelector::Repository },
        ]);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].selector, GitHubEventScanSelector::Repository);
    }
}
