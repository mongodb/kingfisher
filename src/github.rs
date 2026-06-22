use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};
use url::Url;

use crate::{findings_store, git_url::GitUrl, validation::GLOBAL_USER_AGENT};
use std::str::FromStr;

#[derive(Deserialize)]
struct GitHubContributor {
    login: Option<String>,
}

#[derive(Deserialize)]
struct GitHubRepo {
    clone_url: String,
    fork: bool,
}

#[derive(Deserialize)]
struct GitHubOrg {
    login: String,
}

#[derive(Debug)]
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

fn github_token() -> Option<String> {
    env::var("KF_GITHUB_TOKEN").ok().filter(|t| !t.is_empty())
}

fn github_get(client: &reqwest::Client, url: Url, token: Option<&str>) -> reqwest::RequestBuilder {
    let req = client.get(url).header("User-Agent", GLOBAL_USER_AGENT.as_str());
    if let Some(token) = token { req.bearer_auth(token) } else { req }
}

async fn ensure_github_success(resp: reqwest::Response, action: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }

    let status = resp.status();
    let url = resp.url().clone();
    warn_on_rate_limit("GitHub", status, action);

    let mut body = resp.text().await.unwrap_or_default();
    if body.len() > 512 {
        body.truncate(512);
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

async fn fetch_github_orgs(
    client: &reqwest::Client,
    api_base: &Url,
    token: Option<&str>,
) -> Result<Vec<String>> {
    let mut orgs = Vec::new();
    let mut next_url = {
        let mut url = api_base.join("organizations").context("Failed to build GitHub orgs URL")?;
        url.query_pairs_mut().append_pair("per_page", "100");
        Some(url)
    };

    while let Some(url) = next_url {
        let resp = ensure_github_success(
            github_get(client, url, token).send().await?,
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

async fn fetch_github_repos(
    client: &reqwest::Client,
    api_base: &Url,
    path: &str,
    repo_type: &str,
    token: Option<&str>,
    action: &str,
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
            ensure_github_success(github_get(client, url, token).send().await?, action).await?;
        let page_repos: Vec<GitHubRepo> = resp.json().await?;
        if page_repos.is_empty() {
            break;
        }
        repos.extend(page_repos);
        page += 1;
    }

    Ok(repos)
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
    let (_, owner, repo) = parse_repo(repo_url).context("invalid GitHub repo URL")?;
    let exclude_set = build_exclude_matcher(exclude_repos);
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;
    let token = github_token();
    let api_base = normalize_api_base(github_api_url);

    let mut contributor_logins = Vec::new();
    let mut seen_contributors = HashSet::new();
    let mut page = 1;
    loop {
        let mut url = api_base
            .join(&format!("repos/{owner}/{repo}/contributors"))
            .context("Failed to build GitHub contributors URL")?;
        url.query_pairs_mut().append_pair("per_page", "100").append_pair("page", &page.to_string());
        let resp = github_get(&client, url, token.as_deref()).send().await?;
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
            let resp = github_get(&client, url, token.as_deref()).send().await?;
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
pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = create_github_client(ignore_certs)?;
    let mut repo_urls = Vec::new();
    let exclude_set = build_exclude_matcher(&repo_specifiers.exclude_repos);
    let api_base = normalize_api_base(&github_url);
    let token = github_token();
    for username in &repo_specifiers.user {
        let repos = fetch_github_repos(
            &client,
            &api_base,
            &format!("users/{username}/repos"),
            repo_specifiers.repo_filter.user_query_value(),
            token.as_deref(),
            "listing user repositories",
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
    let orgs = if repo_specifiers.all_organizations {
        fetch_github_orgs(&client, &api_base, token.as_deref()).await?
    } else {
        repo_specifiers.organization.clone()
    };
    for org_name in orgs {
        let repos = fetch_github_repos(
            &client,
            &api_base,
            &format!("orgs/{org_name}/repos"),
            repo_specifiers.repo_filter.org_query_value(),
            token.as_deref(),
            "listing organization repositories",
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
    orgs: &[String],
    all_orgs: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        organization: orgs.to_vec(),
        all_organizations: all_orgs,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };
    // Create a progress bar just for displaying status
    // let mut progress = ProgressBar::new_spinner("Fetching repositories...",
    // true,);
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
    let wiki = format!("https://{host}/{owner}/{repo}.wiki.git");
    GitUrl::from_str(&wiki).ok()
}

pub async fn fetch_repo_items(
    repo_url: &GitUrl,
    ignore_certs: bool,
    output_root: &Path,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let (_, owner, repo) = parse_repo(repo_url).context("invalid GitHub repo URL")?;
    let client = reqwest::Client::builder().danger_accept_invalid_certs(ignore_certs).build()?;

    let mut dirs = Vec::new();

    // Issues
    let issues_dir = output_root.join("github_issues").join(&owner).join(&repo);
    fs::create_dir_all(&issues_dir)?;
    let mut page = 1;
    loop {
        let url = format!(
            "https://api.github.com/repos/{owner}/{repo}/issues?state=all&per_page=100&page={page}"
        );
        let mut req = client.get(&url).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        if let Ok(token) = env::var("KF_GITHUB_TOKEN")
            && !token.is_empty()
        {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
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
            let url = format!("https://github.com/{owner}/{repo}/issues/{number}");
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
        let url = format!("https://api.github.com/users/{owner}/gists?per_page=100&page={page}");
        let mut req = client.get(&url).header("User-Agent", GLOBAL_USER_AGENT.as_str());
        if let Ok(token) = env::var("KF_GITHUB_TOKEN")
            && !token.is_empty()
        {
            req = req.bearer_auth(&token);
        }
        let resp = req.send().await?;
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
                let mut req_g = client
                    .get(format!("https://api.github.com/gists/{id}"))
                    .header("User-Agent", GLOBAL_USER_AGENT.as_str());
                if let Ok(token) = env::var("KF_GITHUB_TOKEN")
                    && !token.is_empty()
                {
                    req_g = req_g.bearer_auth(&token);
                }
                let detail: Value = req_g.send().await?.json().await?;
                if let Some(files) = detail.get("files").and_then(|v| v.as_object()) {
                    let gist_dir = gists_dir.join(id);
                    fs::create_dir_all(&gist_dir)?;
                    for (fname, fobj) in files {
                        if let Some(content) = fobj.get("content").and_then(|v| v.as_str()) {
                            let file_path = gist_dir.join(fname);
                            fs::write(&file_path, content)?;
                            let url = format!("https://gist.github.com/{id}");
                            let mut ds = datastore.lock().unwrap();
                            ds.register_repo_link(file_path, url);
                        }
                    }
                }
            }
        }
        page += 1;
    }

    // Private gists for authenticated user if they own the repo
    if let Ok(token) = env::var("KF_GITHUB_TOKEN")
        && !token.is_empty()
    {
        page = 1;
        loop {
            let url = format!("https://api.github.com/gists?per_page=100&page={page}");
            let resp = client
                .get(&url)
                .header("User-Agent", GLOBAL_USER_AGENT.as_str())
                .bearer_auth(&token)
                .send()
                .await?;
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
                    let detail: Value = client
                        .get(format!("https://api.github.com/gists/{id}"))
                        .header("User-Agent", GLOBAL_USER_AGENT.as_str())
                        .bearer_auth(&token)
                        .send()
                        .await?
                        .json()
                        .await?;
                    if let Some(files) = detail.get("files").and_then(|v| v.as_object()) {
                        let gist_dir = gists_dir.join(id);
                        fs::create_dir_all(&gist_dir)?;
                        for (fname, fobj) in files {
                            if let Some(content) = fobj.get("content").and_then(|v| v.as_str()) {
                                let file_path = gist_dir.join(fname);
                                fs::write(&file_path, content)?;
                                let url = format!("https://gist.github.com/{id}");
                                let mut ds = datastore.lock().unwrap();
                                ds.register_repo_link(file_path, url);
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
}
