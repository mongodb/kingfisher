use std::{
    collections::{HashMap, HashSet},
    env,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

// NOTE: We continue to issue the small number of Azure DevOps Git REST calls we need
// directly through `reqwest` instead of depending on the `azure_devops_rust_api`
// crate. The SDK does not yet expose stable coverage for wiki repositories or the
// preview API surfaces we rely on, while the raw requests keep the binary lean and
// let us opt into newer API versions as Microsoft rolls them out.

use anyhow::{Context, Result, anyhow};
use indicatif::{ProgressBar, ProgressStyle};
use serde::Deserialize;
use tracing::warn;
use url::{Url, form_urlencoded};

use crate::{findings_store, git_host, git_url::GitUrl};

const API_VERSION: &str = "7.1-preview.1";

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
    pub organization: Vec<String>,
    pub project: Vec<String>,
    pub all_projects: bool,
    pub repo_filter: RepoType,
    pub exclude_repos: Vec<String>,
}

impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.organization.is_empty() && self.project.is_empty()
    }
}

fn encode_segment(segment: &str) -> String {
    form_urlencoded::byte_serialize(segment.as_bytes()).collect::<String>()
}

fn normalize_repo_identifier(parts: &[String]) -> Option<String> {
    if parts.len() < 3 {
        return None;
    }
    let repo = parts.last()?.trim().trim_matches('/');
    let project = parts.get(parts.len() - 2)?.trim().trim_matches('/');
    if repo.is_empty() || project.is_empty() {
        return None;
    }
    let owner_segments = &parts[..parts.len() - 2];
    let mut normalized: Vec<String> =
        owner_segments.iter().map(|s| s.trim().trim_matches('/').to_lowercase()).collect();
    normalized.retain(|s| !s.is_empty());
    normalized.push(project.to_lowercase());
    normalized.push(repo.trim_end_matches(".git").to_lowercase());
    if normalized.is_empty() { None } else { Some(normalized.join("/")) }
}

fn parse_repo_identifier_from_path(path: &str) -> Option<String> {
    let segments: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if segments.is_empty() {
        return None;
    }

    if segments.len() == 2 {
        let org = segments.first()?.trim().trim_matches('/');
        let project = segments.last()?.trim().trim_matches('/');
        if org.is_empty() || project.is_empty() {
            return None;
        }

        let org = org.to_lowercase();
        let project_raw = project.to_string();
        if git_host::looks_like_glob(&project_raw) {
            let pattern = format!("{org}/{}/**", project_raw.to_lowercase());
            return Some(pattern);
        }

        let project_normalized = project_raw.trim_end_matches(".git").to_lowercase();
        let repo = project_normalized.clone();
        return Some(format!("{org}/{project_normalized}/{repo}"));
    }

    if segments.len() < 3 {
        return None;
    }

    // Case 1: Azure URL-style with "_git" marker: .../<project>/_git/<repo>
    if segments[segments.len().saturating_sub(2)] == "_git" {
        let mut trimmed = segments.clone();
        let repo = trimmed.pop()?; // <repo>
        trimmed.pop()?; // drop "_git"
        trimmed.push(repo); // .../<project>/<repo>
        return normalize_repo_identifier(&trimmed);
    }

    // Case 2: Simple path (and glob-friendly): .../<project>/<repo>
    // Accept as-is so things like "org/*/repo" work.
    normalize_repo_identifier(&segments)
}

fn parse_repo_identifier_from_url(remote_url: &str) -> Option<String> {
    let url = Url::parse(remote_url).ok()?;
    if let Some(path) = url.path_segments() {
        let segments: Vec<String> =
            path.filter(|segment| !segment.is_empty()).map(|segment| segment.to_string()).collect();
        if segments.len() < 3 {
            return None;
        }
        let mut trimmed = segments.clone();
        let repo = trimmed.pop()?;
        let marker = trimmed.pop()?;
        if marker != "_git" {
            return None;
        }
        trimmed.push(repo);
        normalize_repo_identifier(&trimmed)
    } else {
        None
    }
}

fn parse_excluded_repo(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some(name) = parse_repo_identifier_from_url(trimmed) {
        return Some(name);
    }

    if let Some(idx) = trimmed.rfind(':')
        && let Some(name) = parse_repo_identifier_from_path(&trimmed[idx + 1..])
    {
        return Some(name);
    }

    parse_repo_identifier_from_path(trimmed)
}

fn build_exclude_matcher(exclude_repos: &[String]) -> git_host::ExcludeMatcher {
    git_host::build_exclude_matcher(
        exclude_repos,
        |raw| parse_excluded_repo(raw).map(|name| name.to_lowercase()),
        "Azure",
    )
}

fn should_exclude_repo(repo_url: &str, excludes: &git_host::ExcludeMatcher) -> bool {
    git_host::should_exclude_repo(repo_url, excludes, parse_repo_identifier_from_url)
}

#[derive(Debug, Deserialize, Default)]
struct AzureRepository {
    #[serde(rename = "remoteUrl")]
    remote_url: Option<String>,
    #[serde(rename = "webUrl")]
    web_url: Option<String>,
    #[serde(rename = "isFork", default)]
    is_fork: bool,
    #[serde(default)]
    project: AzureProjectRef,
}

#[derive(Debug, Deserialize, Default)]
struct AzureProjectRef {
    name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AzureListResponse<T> {
    value: Vec<T>,
}

struct AzureAuth {
    username: Option<String>,
    token: Option<String>,
}

impl AzureAuth {
    fn from_environment() -> Self {
        let token = env::var("KF_AZURE_TOKEN").or_else(|_| env::var("KF_AZURE_PAT")).ok();
        let username = env::var("KF_AZURE_USERNAME").ok();
        Self { username, token }
    }

    fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.token {
            let username = self.username.as_deref().unwrap_or("pat");
            request.basic_auth(username, Some(token))
        } else {
            request
        }
    }
}

fn sanitize_remote_url(raw: &str) -> Option<String> {
    let mut url = Url::parse(raw).ok()?;
    if !url.username().is_empty() {
        url.set_username("").ok()?;
    }
    if url.password().is_some() {
        url.set_password(None).ok()?;
    }
    Some(url.to_string())
}

async fn fetch_repositories_for_org(
    client: &reqwest::Client,
    base_url: &Url,
    organization: &str,
    auth: &AzureAuth,
) -> Result<Vec<AzureRepository>> {
    let base = base_url.as_str().trim_end_matches('/');
    let encoded_org = encode_segment(organization);
    let url = format!("{base}/{encoded_org}/_apis/git/repositories?api-version={API_VERSION}");
    let request = auth.apply(client.get(&url));
    let response = request.send().await?;
    let status = response.status();
    let headers = response.headers().clone();
    let body_bytes = response.bytes().await?;

    if !status.is_success() {
        let body = String::from_utf8_lossy(&body_bytes).trim().to_string();
        let auth_hint = if matches!(
            status,
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
        ) {
            if auth.token.is_some() {
                "Verify that the Azure token or PAT has access to the requested organization and has not expired."
            } else {
                "Set KF_AZURE_TOKEN or KF_AZURE_PAT with an Azure DevOps Personal Access Token that can read repositories."
            }
        } else {
            ""
        };

        let mut message = format!(
            "Azure Repos API request failed for organization '{organization}' ({status}): {body}"
        );
        if !auth_hint.is_empty() {
            message.push_str(&format!("\n{auth_hint}"));
        }
        return Err(anyhow!(message));
    }

    let is_json = headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json")
        })
        .unwrap_or(false);

    if !is_json {
        let body = String::from_utf8_lossy(&body_bytes);
        return Err(anyhow!(
            "Azure Repos API response for organization '{organization}' did not include JSON: {body}"
        ));
    }

    let payload: AzureListResponse<AzureRepository> = serde_json::from_slice(&body_bytes)?;
    Ok(payload.value)
}

fn parse_project_specifiers(projects: &[String]) -> HashMap<String, HashSet<String>> {
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for raw in projects {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split('/').filter(|segment| !segment.is_empty()).collect();
        if parts.len() < 2 {
            warn!(
                "Ignoring Azure project specifier '{raw}' (expected format ORGANIZATION/PROJECT)"
            );
            continue;
        }
        let project = parts.last().unwrap().to_lowercase();
        let organization = parts[..parts.len() - 1].join("/").to_lowercase();
        map.entry(organization).or_default().insert(project);
    }
    map
}

fn canonicalize_organizations(spec: &RepoSpecifiers) -> HashMap<String, String> {
    let mut org_lookup: HashMap<String, String> = HashMap::new();
    for org in &spec.organization {
        let key = org.to_lowercase();
        org_lookup.entry(key).or_insert_with(|| org.clone());
    }
    let project_map = parse_project_specifiers(&spec.project);
    for (org_lower, _projects) in project_map {
        org_lookup.entry(org_lower.clone()).or_insert(org_lower);
    }
    org_lookup
}

pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    base_url: Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let auth = AzureAuth::from_environment();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .timeout(Duration::from_secs(30))
        .build()?;

    let exclude_matcher = build_exclude_matcher(&repo_specifiers.exclude_repos);
    let project_filters = parse_project_specifiers(&repo_specifiers.project);
    let has_project_filters = !project_filters.is_empty();

    let org_lookup = canonicalize_organizations(repo_specifiers);
    if org_lookup.is_empty() {
        return Ok(Vec::new());
    }

    let mut organizations: Vec<String> = org_lookup.values().cloned().collect();
    organizations.sort();
    organizations.dedup();

    let mut repo_urls = Vec::new();

    for org in organizations {
        if let Some(pb) = &mut progress {
            pb.set_message(format!("Fetching Azure repositories for {org}..."));
        }
        let repos =
            fetch_repositories_for_org(&client, &base_url, &org, &auth).await.with_context(
                || format!("Failed to fetch repositories for Azure organization '{org}'"),
            )?;

        let org_key = org.to_lowercase();
        let project_filter = project_filters.get(&org_key);

        for repo in repos {
            if !repo_specifiers.repo_filter.allows(repo.is_fork) {
                continue;
            }

            let project_name = repo
                .project
                .name
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("");

            if !repo_specifiers.all_projects {
                if let Some(filters) = project_filter {
                    if project_name.is_empty() || !filters.contains(&project_name.to_lowercase()) {
                        continue;
                    }
                } else if has_project_filters
                    && !repo_specifiers
                        .organization
                        .iter()
                        .any(|candidate| candidate.eq_ignore_ascii_case(&org))
                {
                    // Organization derived solely from project filters without an explicit match
                    continue;
                }
            }

            let remote = repo
                .remote_url
                .as_deref()
                .or(repo.web_url.as_deref())
                .ok_or_else(|| anyhow!("Missing remote URL for Azure repository"))?;
            let sanitized = match sanitize_remote_url(remote) {
                Some(url) => url,
                None => {
                    warn!("Skipping Azure repository with unparsable URL: {remote}");
                    continue;
                }
            };
            if should_exclude_repo(&sanitized, &exclude_matcher) {
                continue;
            }
            repo_urls.push(sanitized);
        }
    }

    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

#[allow(clippy::too_many_arguments)]
pub async fn list_repositories(
    base_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    organizations: &[String],
    projects: &[String],
    all_projects: bool,
    exclude_repos: &[String],
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        organization: organizations.to_vec(),
        project: projects.to_vec(),
        all_projects,
        repo_filter,
        exclude_repos: exclude_repos.to_vec(),
    };

    if repo_specifiers.is_empty() {
        anyhow::bail!("Provide at least one --organization or --project to enumerate Azure Repos");
    }

    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Fetching Azure repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let repo_urls =
        enumerate_repo_urls(&repo_specifiers, base_url, ignore_certs, Some(&mut progress)).await?;

    for url in repo_urls {
        println!("{}", url);
    }

    Ok(())
}

fn parse_repo(repo_url: &GitUrl) -> Option<Url> {
    Url::parse(repo_url.as_str()).ok()
}

pub fn wiki_url(repo_url: &GitUrl) -> Option<GitUrl> {
    let url = parse_repo(repo_url)?;
    let mut segments: Vec<String> = url
        .path_segments()
        .map(|segments| segments.filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())
        .unwrap_or_default();
    if segments.len() < 3 {
        return None;
    }
    let mut repo_name = segments.pop()?;
    if repo_name.ends_with(".wiki") {
        return None;
    }
    let marker = segments.pop()?;
    if marker != "_git" {
        return None;
    }
    repo_name.push_str(".wiki");
    segments.push("_git".to_string());
    segments.push(repo_name);
    let mut new_url = url.clone();
    {
        let mut path_segments = new_url.path_segments_mut().ok()?;
        path_segments.clear();
        for segment in segments {
            path_segments.push(&segment);
        }
    }
    GitUrl::try_from(new_url).ok()
}

pub async fn fetch_repo_items(
    _repo_url: &GitUrl,
    _ignore_certs: bool,
    _output_root: &Path,
    _datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    // Azure DevOps exposes work items and wiki content via additional APIs. For now we
    // skip fetching extra artifacts and simply return an empty set so callers can rely
    // on the function existing just like the other git host modules.
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn sanitize_remote_url_strips_username() {
        let raw = "https://example@dev.azure.com/example/project/_git/repo";
        let sanitized = sanitize_remote_url(raw).expect("sanitize");
        assert_eq!(sanitized, "https://dev.azure.com/example/project/_git/repo");
    }

    #[test]
    fn parse_repo_identifier_from_url_handles_basic_path() {
        let remote = "https://dev.azure.com/org/project/_git/repo";
        let ident = parse_repo_identifier_from_url(remote).expect("identifier");
        assert_eq!(ident, "org/project/repo");
    }

    #[test]
    fn parse_repo_identifier_from_url_handles_nested_org() {
        let remote = "https://ado.example.com/collection/team/project/_git/repo";
        let ident = parse_repo_identifier_from_url(remote).expect("identifier");
        assert_eq!(ident, "collection/team/project/repo");
    }

    #[test]
    fn parse_excluded_repo_accepts_url() {
        let raw = "https://dev.azure.com/org/project/_git/repo";
        let ident = parse_excluded_repo(raw).expect("identifier");
        assert_eq!(ident, "org/project/repo");
    }

    #[test]
    fn parse_excluded_repo_accepts_path() {
        let raw = "org/project/repo";
        let ident = parse_excluded_repo(raw).expect("identifier");
        assert_eq!(ident, "org/project/repo");
    }

    #[test]
    fn parse_excluded_repo_allows_project_alias() {
        let raw = "Org/Project";
        let ident = parse_excluded_repo(raw).expect("identifier");
        assert_eq!(ident, "org/project/project");
    }

    #[test]
    fn parse_excluded_repo_allows_project_glob() {
        let raw = "org/*";
        let ident = parse_excluded_repo(raw).expect("identifier");
        assert_eq!(ident, "org/*/**");
    }

    #[test]
    fn exclude_matcher_matches_glob() {
        let matcher = build_exclude_matcher(&["org/*/repo".to_string()]);
        assert!(should_exclude_repo("https://dev.azure.com/org/project/_git/repo", &matcher));
    }

    #[test]
    fn exclude_matcher_matches_project_alias() {
        let matcher = build_exclude_matcher(&["org/project".to_string()]);
        assert!(should_exclude_repo("https://dev.azure.com/org/project/_git/project", &matcher));
    }

    #[test]
    fn exclude_matcher_matches_project_glob() {
        let matcher = build_exclude_matcher(&["org/*".to_string()]);
        assert!(should_exclude_repo("https://dev.azure.com/org/project/_git/repo", &matcher));
    }

    #[test]
    fn exclude_matcher_is_case_insensitive_for_exact_matches() {
        let matcher = build_exclude_matcher(&["Org/Project/Repo".to_string()]);
        assert!(should_exclude_repo("https://dev.azure.com/org/project/_git/repo", &matcher));
    }

    #[test]
    fn exclude_matcher_is_case_insensitive_for_globs() {
        let matcher = build_exclude_matcher(&["ORG/*".to_string()]);
        assert!(should_exclude_repo("https://dev.azure.com/org/project/_git/repo", &matcher));
    }

    #[test]
    fn wiki_url_appends_suffix() {
        let url = GitUrl::from_str("https://dev.azure.com/org/project/_git/repo").unwrap();
        let wiki = wiki_url(&url).expect("wiki url");
        assert_eq!(wiki.as_str(), "https://dev.azure.com/org/project/_git/repo.wiki");
    }
}
