//! Shared utilities for Git hosting platform integrations.
//!
//! This module provides the `ExcludeMatcher` struct and related helpers
//! used across all platform integration modules (GitHub, GitLab, Azure,
//! Bitbucket, Gitea).

use std::collections::HashSet;

use globset::{Glob, GlobSet, GlobSetBuilder};
use tracing::warn;

/// A host-issued repository identity, not a repository name or content hash.
/// Keep numeric IDs lossless, while allowing providers that issue UUIDs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum RepositoryId {
    Numeric(u64),
    Opaque(String),
}

impl From<u64> for RepositoryId {
    fn from(id: u64) -> Self {
        Self::Numeric(id)
    }
}

impl From<String> for RepositoryId {
    fn from(id: String) -> Self {
        Self::Opaque(id)
    }
}

/// Only enrich repositories on the explicitly configured provider instance.
/// API credentials are never sent to a host taken from a repository URL.
pub(crate) fn repository_path(
    repo_url: &crate::git_url::GitUrl,
    api_url: &url::Url,
    public_host: &str,
    api_suffix: &str,
) -> Option<String> {
    let repo = url::Url::parse(repo_url.as_str()).ok()?;
    let configured_host = repo.host_str() == api_url.host_str()
        && (repo.port_or_known_default() == api_url.port_or_known_default()
            || repo.port().is_none() && api_url.port().is_none());
    // Public clone/API hosts can differ (e.g. bitbucket.org/api.bitbucket.org),
    // but that mapping is valid only when the configured API is public too.
    let public_api_host = format!("api.{public_host}");
    let public_host = repo.host_str() == Some(public_host)
        && repo.port().is_none()
        && matches!(api_url.host_str(), Some(host) if host == public_host || host == public_api_host)
        && api_url.port().is_none();
    if !configured_host && !public_host {
        return None;
    }
    let prefix = api_url.path().trim_end_matches('/');
    let prefix = prefix.strip_suffix(api_suffix).unwrap_or(prefix);
    let path = if configured_host && !prefix.is_empty() {
        repo.path().strip_prefix(&format!("{prefix}/"))?
    } else {
        repo.path().trim_start_matches('/')
    };
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    if path.ends_with(".wiki")
        || path.split('/').any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return None;
    }
    Some(path.to_owned())
}

pub(crate) fn repository_metadata_client(ignore_certs: bool) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .danger_accept_invalid_certs(ignore_certs)
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(crate::validation::GLOBAL_USER_AGENT.as_str())
        .build()?)
}

pub(crate) async fn repository_id_response(
    request: reqwest::RequestBuilder,
    field: &str,
) -> anyhow::Result<Option<RepositoryId>> {
    const MAX_METADATA_BYTES: usize = 1024 * 1024;
    let mut response = request.send().await?;
    if !response.status().is_success() {
        return Ok(None);
    }
    if response.content_length().is_some_and(|size| size > MAX_METADATA_BYTES as u64) {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > MAX_METADATA_BYTES.saturating_sub(bytes.len()) {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk);
    }
    let body: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(body.get(field).and_then(|id| {
        id.as_u64().map(RepositoryId::Numeric).or_else(|| {
            id.as_str().filter(|id| !id.is_empty()).map(|id| RepositoryId::Opaque(id.to_owned()))
        })
    }))
}

// -------------------------------------------------------------------------------------------------
// ExcludeMatcher
// -------------------------------------------------------------------------------------------------

/// Matches repository names against exact strings and glob patterns.
///
/// Used by all platform integrations to filter out excluded repositories.
pub struct ExcludeMatcher {
    exact: HashSet<String>,
    globs: Option<GlobSet>,
}

impl ExcludeMatcher {
    /// Returns `true` if no exclusion patterns are configured.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_none()
    }

    /// Returns `true` if the given name matches any exclusion pattern.
    pub fn matches(&self, name: &str) -> bool {
        if self.exact.contains(name) {
            return true;
        }
        if let Some(globs) = &self.globs {
            return globs.is_match(name);
        }
        false
    }
}

/// Returns `true` if the pattern contains glob metacharacters.
pub fn looks_like_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// Builds an `ExcludeMatcher` from a list of exclusion patterns.
///
/// The `parse_fn` transforms each raw pattern string into a normalized
/// repository name (e.g., `"owner/repo"` or `"group/project"`). It returns
/// `None` if the pattern is invalid.
///
/// The `platform_name` is used in warning messages (e.g., `"GitHub"`,
/// `"GitLab"`).
pub fn build_exclude_matcher(
    exclude_repos: &[String],
    parse_fn: impl Fn(&str) -> Option<String>,
    platform_name: &str,
) -> ExcludeMatcher {
    let mut exact = HashSet::new();
    let mut glob_builder = GlobSetBuilder::new();
    let mut has_glob = false;

    for raw in exclude_repos {
        match parse_fn(raw) {
            Some(name) => {
                if looks_like_glob(&name) {
                    match Glob::new(&name) {
                        Ok(glob) => {
                            glob_builder.add(glob);
                            has_glob = true;
                        }
                        Err(err) => {
                            warn!(
                                "Ignoring invalid {platform_name} exclusion pattern '{raw}': {err}"
                            );
                            exact.insert(name);
                        }
                    }
                } else {
                    exact.insert(name);
                }
            }
            None => {
                warn!("Ignoring invalid {platform_name} exclusion '{raw}'");
            }
        }
    }

    let globs = if has_glob {
        match glob_builder.build() {
            Ok(set) => Some(set),
            Err(err) => {
                warn!("Failed to build {platform_name} exclusion patterns: {err}");
                None
            }
        }
    } else {
        None
    };

    ExcludeMatcher { exact, globs }
}

/// Checks whether a repository URL should be excluded.
///
/// The `extract_name` function extracts a normalized repository identifier
/// from the URL (e.g., `"owner/repo"` from `"https://github.com/owner/repo.git"`).
pub fn should_exclude_repo(
    repo_url: &str,
    excludes: &ExcludeMatcher,
    extract_name: impl Fn(&str) -> Option<String>,
) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if let Some(name) = extract_name(repo_url) {
        return excludes.matches(&name);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git_url::GitUrl;
    use url::Url;

    #[test]
    fn metadata_paths_require_a_known_host_and_preserve_self_hosted_prefixes() {
        for (api, repo, suffix, expected) in [
            (
                "https://gitlab.example.com/gitlab/",
                "https://gitlab.example.com/gitlab/acme/sub/repo.git",
                "/api/v4",
                Some("acme/sub/repo"),
            ),
            (
                "https://gitea.example.com/gitea/api/v1/",
                "https://gitea.example.com/gitea/acme/repo.git",
                "/api/v1",
                Some("acme/repo"),
            ),
            (
                "https://bitbucket.example.com/bitbucket/rest/api/1.0/",
                "https://bitbucket.example.com/bitbucket/scm/acme/repo.git",
                "/rest/api/1.0",
                Some("scm/acme/repo"),
            ),
            (
                "https://dev.azure.com/",
                "https://dev.azure.com/acme/project/_git/repo",
                "",
                Some("acme/project/_git/repo"),
            ),
            ("https://gitlab.example.com/", "https://gitlab.com/acme/repo.git", "/api/v4", None),
            (
                "https://gitlab.com/",
                "https://gitlab.com/acme/repo.git",
                "/api/v4",
                Some("acme/repo"),
            ),
            (
                "http://gitlab.example.com/",
                "https://gitlab.example.com/acme/repo.git",
                "/api/v4",
                Some("acme/repo"),
            ),
            (
                "https://gitlab.example.com:8443/",
                "https://gitlab.example.com:8443/acme/repo.git",
                "/api/v4",
                Some("acme/repo"),
            ),
            (
                "https://gitlab.example.com:8443/",
                "https://gitlab.example.com/acme/repo.git",
                "/api/v4",
                None,
            ),
            (
                "https://gitlab.example.com/",
                "https://gitlab.example.com.attacker.test/acme/repo.git",
                "/api/v4",
                None,
            ),
            (
                "https://gitlab.example.com/",
                "https://gitlab.example.com/acme/repo.wiki.git",
                "/api/v4",
                None,
            ),
        ] {
            let path = repository_path(
                &repo.parse::<GitUrl>().unwrap(),
                &Url::parse(api).unwrap(),
                "gitlab.com",
                suffix,
            );
            assert_eq!(path.as_deref(), expected, "{repo}");
        }
    }

    #[tokio::test]
    async fn oversized_repository_metadata_is_ignored() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 123, "padding": "x".repeat(1024 * 1024),
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = repository_metadata_client(false).unwrap();
        assert_eq!(repository_id_response(client.get(server.uri()), "id").await.unwrap(), None);
    }

    #[tokio::test]
    async fn repository_metadata_size_cap_also_applies_without_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let read = connection.read(&mut request).await.unwrap();
            assert!(read > 0);
            connection.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n").await.unwrap();
            let body = serde_json::to_vec(&serde_json::json!({
                "id": 123, "padding": "x".repeat(1024 * 1024),
            }))
            .unwrap();
            // The bounded reader may close the connection before all bytes are written.
            let _ = connection.write_all(&body).await;
        });
        let client = repository_metadata_client(false).unwrap();
        assert_eq!(
            repository_id_response(client.get(format!("http://{address}")), "id").await.unwrap(),
            None
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn optional_metadata_is_lossless_and_never_follows_redirects() {
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };
        let server = MockServer::start().await;
        let other = MockServer::start().await;
        let client = repository_metadata_client(false).unwrap();
        for (index, (body, expected)) in [
            (
                json!({"id": 9_007_199_254_740_993_u64}),
                Some(RepositoryId::Numeric(9_007_199_254_740_993)),
            ),
            (json!({"id": "{uuid}"}), Some(RepositoryId::Opaque("{uuid}".into()))),
            (json!({}), None),
            (json!({"id": null}), None),
            (json!({"id": ""}), None),
            (json!({"id": {"unexpected": true}}), None),
        ]
        .into_iter()
        .enumerate()
        {
            Mock::given(method("GET"))
                .and(path(format!("/{index}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
            assert_eq!(
                repository_id_response(client.get(format!("{}/{index}", server.uri())), "id")
                    .await
                    .unwrap(),
                expected
            );
        }
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .respond_with(ResponseTemplate::new(302).insert_header("location", other.uri()))
            .expect(1)
            .mount(&server)
            .await;
        assert_eq!(
            repository_id_response(
                client.get(format!("{}/redirect", server.uri())).bearer_auth("secret"),
                "id"
            )
            .await
            .unwrap(),
            None
        );
        assert!(other.received_requests().await.unwrap().is_empty());
    }
}
