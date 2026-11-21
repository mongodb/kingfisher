use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITEA_API: &str = "https://gitea.com/api/v1/";
const LAST_USED_SOURCE: &str = "Gitea access token activity";
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ACTIVITY_PAGES: u32 = 5;
const ACTIVITY_PAGE_SIZE: usize = 50;
const MAX_ACTIVITY_RESPONSE_BYTES: usize = 128 * 1024;

#[derive(Deserialize)]
struct GiteaCredentialFile {
    token: String,
    api_endpoint: Option<String>,
    activity: Option<GiteaActivityCredential>,
}

#[derive(Deserialize)]
struct GiteaActivityCredential {
    username: String,
    token_id: u64,
    audit_username: String,
    audit_password: String,
}

#[derive(Deserialize)]
struct GiteaListedToken {
    id: u64,
    created_at: Option<String>,
    last_used_at: Option<String>,
    token_last_eight: Option<String>,
}

#[derive(Deserialize)]
struct GiteaUser {
    login: String,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    created: Option<String>,
}

#[derive(Deserialize)]
struct GiteaRepo {
    full_name: String,
    private: bool,
    #[serde(default)]
    permissions: Option<GiteaRepoPermissions>,
}

#[derive(Clone, Deserialize)]
struct GiteaRepoPermissions {
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    push: bool,
    #[serde(default)]
    pull: bool,
}

#[derive(Deserialize)]
struct GiteaOrg {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    full_name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("Gitea access-map requires a validated token from scan results"))?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Gitea token from {}", path.display()))?;
    let (token, api_url, activity) = parse_gitea_credentials(raw.trim())?;
    map_access_with_options(&token, &api_url, activity.as_ref()).await
}

fn parse_gitea_credentials(raw: &str) -> Result<(String, Url, Option<GiteaActivityCredential>)> {
    let credential: GiteaCredentialFile = if raw.starts_with('{') {
        serde_json::from_str(raw).map_err(|_| {
            anyhow!("Invalid Gitea credential JSON; expected token and optional activity")
        })?
    } else {
        GiteaCredentialFile { token: raw.into(), api_endpoint: None, activity: None }
    };
    let endpoint = credential.api_endpoint.as_deref().filter(|value| !value.trim().is_empty());
    let api_url = crate::provider_endpoints::access_map_api_url(
        "gitea",
        endpoint.unwrap_or(DEFAULT_GITEA_API),
    )?;
    if let Some(activity) = &credential.activity {
        ensure!(
            endpoint.is_some() && api_url.scheme() == "https",
            "Gitea activity requires an explicit HTTPS api_endpoint"
        );
        ensure!(
            !matches!(activity.username.trim(), "" | "." | "..")
                && activity.token_id > 0
                && !activity.audit_username.trim().is_empty()
                && !activity.audit_username.contains(':')
                && !activity.audit_password.is_empty(),
            "Gitea activity requires username, a positive token_id, audit_username, and audit_password"
        );
    }
    Ok((credential.token.trim().to_owned(), api_url, credential.activity))
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, DEFAULT_GITEA_API).await
}

pub async fn map_access_from_token_at(token: &str, api_endpoint: &str) -> Result<AccessMapResult> {
    let api_url = crate::provider_endpoints::access_map_api_url("gitea", api_endpoint)?;
    map_access_with_options(token, &api_url, None).await
}

async fn map_access_with_options(
    token: &str,
    api_url: &Url,
    activity: Option<&GiteaActivityCredential>,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Gitea HTTP client")?;

    let observed_last_used =
        if let Some(config) = activity.filter(|config| config.audit_password != token) {
            // Gitea updates the PAT's usage during authentication, including mapper requests.
            fetch_token_last_used(&client, api_url, token, config).await
        } else {
            None
        };

    let user_resp = client
        .get(api_url.join("user")?)
        .header(header::AUTHORIZATION, format!("token {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Gitea access-map: failed to fetch user info")?;

    if !user_resp.status().is_success() {
        return Err(anyhow!(
            "Gitea access-map: user lookup failed with HTTP {}",
            user_resp.status()
        ));
    }

    let user: GiteaUser = user_resp.json().await.context("Gitea access-map: invalid user JSON")?;
    let last_used_at = observed_last_used.filter(|_| {
        activity.is_some_and(|config| user.login.eq_ignore_ascii_case(&config.username))
    });
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some(LAST_USED_SOURCE.into()),
        ..ProviderMetadata::default()
    });

    let identity = AccessSummary {
        id: user.login.clone(),
        access_type: if user.is_admin { "admin".into() } else { "user".into() },
        project: None,
        tenant: None,
        account_id: None,
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    if user.is_admin {
        roles.push(RoleBinding {
            name: "site_admin".into(),
            source: "gitea".into(),
            permissions: vec!["site:admin".to_string()],
        });
        permissions.admin.push("site:admin".to_string());
        risk_notes.push("Token belongs to a Gitea site administrator".into());
    }

    // Enumerate organizations.
    let orgs = list_user_orgs(&client, api_url, token).await.unwrap_or_else(|err| {
        warn!("Gitea access-map: org enumeration failed: {err}");
        Vec::new()
    });

    for org in &orgs {
        let org_name = org
            .username
            .clone()
            .or_else(|| org.full_name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name,
            permissions: vec!["org:member".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Organization membership available to the token".into(),
        });
    }

    // Enumerate accessible repositories.
    let repos = list_accessible_repos(&client, api_url, token).await?;

    for repo in &repos {
        let perms = repo.permissions.clone().unwrap_or(GiteaRepoPermissions {
            admin: false,
            push: false,
            pull: true,
        });

        let mut repo_perms = Vec::new();
        if perms.admin {
            repo_perms.push("repo:admin".to_string());
        }
        if perms.push {
            repo_perms.push("repo:write".to_string());
        }
        if perms.pull {
            repo_perms.push("repo:read".to_string());
        }

        let risk = if perms.admin {
            Severity::High
        } else if perms.push {
            Severity::Medium
        } else {
            Severity::Low
        };

        let reason = if repo.private {
            "Accessible private repository".to_string()
        } else {
            "Accessible public repository".to_string()
        };

        resources.push(ResourceExposure {
            resource_type: "repository".into(),
            name: repo.full_name.clone(),
            permissions: repo_perms.clone(),
            risk: severity_to_str(risk).to_string(),
            reason,
        });

        if perms.admin {
            permissions.admin.push("repo:admin".to_string());
        } else if perms.push {
            permissions.risky.push("repo:write".to_string());
        } else if perms.pull {
            permissions.read_only.push("repo:read".to_string());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&user, &repos);

    if repos.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: user.login.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Gitea account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any repositories".into());
    }

    let user_display_name = user
        .full_name
        .clone()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| Some(user.login.clone()));

    Ok(AccessMapResult {
        cloud: "gitea".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user_display_name,
            username: Some(user.login.clone()),
            account_type: Some(if user.is_admin {
                "admin".to_string()
            } else {
                "user".to_string()
            }),
            company: None,
            location: None,
            email: user.email.clone().filter(|v| !v.trim().is_empty()),
            url: user.avatar_url.clone().filter(|v| !v.trim().is_empty()),
            token_type: None,
            created_at: user.created.clone(),
            last_used_at,
            expires_at: None,
            user_id: Some(user.login),
            scopes: Vec::new(),
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn fetch_token_last_used(
    client: &Client,
    api_url: &Url,
    token: &str,
    config: &GiteaActivityCredential,
) -> Option<String> {
    match tokio::time::timeout(
        ACTIVITY_TIMEOUT,
        read_token_activity(client, api_url, token, config),
    )
    .await
    {
        Ok(Ok(last_used_at)) => last_used_at,
        Ok(Err(err)) => {
            debug!("Gitea access-map: token activity unavailable: {err}");
            None
        }
        Err(_) => {
            debug!("Gitea access-map: token activity lookup timed out");
            None
        }
    }
}

async fn read_token_activity(
    client: &Client,
    api_url: &Url,
    token: &str,
    config: &GiteaActivityCredential,
) -> Result<Option<String>> {
    let mut endpoint = api_url.clone();
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow!("Invalid Gitea activity endpoint"))?
        .pop_if_empty()
        .extend(["users", &config.username, "tokens"]);

    let mut entries_seen = 0;
    for page in 1..=MAX_ACTIVITY_PAGES {
        let mut response = client
            .get(endpoint.clone())
            .query(&[("limit", ACTIVITY_PAGE_SIZE.to_string()), ("page", page.to_string())])
            .basic_auth(&config.audit_username, Some(&config.audit_password))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Gitea token activity request failed")?;
        let status = response.status();
        ensure!(status.is_success(), "Gitea token activity lookup returned HTTP {status}");

        let total = response
            .headers()
            .get("x-total-count")
            .and_then(|value| value.to_str().ok().and_then(|value| value.parse::<usize>().ok()));
        let mut bytes = Vec::new();
        while let Some(chunk) =
            response.chunk().await.context("Could not read Gitea token activity")?
        {
            ensure!(
                chunk.len() <= MAX_ACTIVITY_RESPONSE_BYTES.saturating_sub(bytes.len()),
                "Gitea token activity response exceeded its size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let entries: Vec<GiteaListedToken> =
            serde_json::from_slice(&bytes).context("Invalid Gitea token activity JSON")?;
        if let Some(entry) = entries.iter().find(|entry| entry.id == config.token_id) {
            return Ok(gitea_last_used(entry, token));
        }
        entries_seen += entries.len();
        if entries.is_empty()
            || total.map_or(entries.len() < ACTIVITY_PAGE_SIZE, |total| entries_seen >= total)
        {
            break;
        }
    }
    Ok(None)
}

fn gitea_last_used(entry: &GiteaListedToken, token: &str) -> Option<String> {
    // Verify the suffix when present, but never use a suffix to select an inventory row.
    if entry
        .token_last_eight
        .as_deref()
        .filter(|suffix| !suffix.is_empty())
        .is_some_and(|suffix| suffix.len() != 8 || !token.ends_with(suffix))
    {
        return None;
    }
    let last_used = DateTime::parse_from_rfc3339(entry.last_used_at.as_deref()?).ok()?;
    let created =
        entry.created_at.as_deref().and_then(|date| DateTime::parse_from_rfc3339(date).ok());
    // Gitea initializes the token's updated time at creation, before any use.
    if last_used.timestamp() <= 0 || created.is_some_and(|created| last_used <= created) {
        return None;
    }
    Some(last_used.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

async fn list_accessible_repos(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GiteaRepo>> {
    let mut repos = Vec::new();
    let mut page = 1u32;
    let per_page = 50u32;

    loop {
        let mut url = api_url.join("user/repos")?;
        url.query_pairs_mut()
            .append_pair("limit", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Gitea access-map: failed to list repositories")?;

        if !resp.status().is_success() {
            warn!("Gitea access-map: repo enumeration failed with HTTP {}", resp.status());
            break;
        }

        let mut page_repos: Vec<GiteaRepo> =
            resp.json().await.context("Gitea access-map: invalid repository JSON")?;
        let count = page_repos.len();
        repos.append(&mut page_repos);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(repos)
}

async fn list_user_orgs(client: &Client, api_url: &Url, token: &str) -> Result<Vec<GiteaOrg>> {
    let mut orgs = Vec::new();
    let mut page = 1u32;
    let per_page = 50u32;

    loop {
        let mut url = api_url.join("user/orgs")?;
        url.query_pairs_mut()
            .append_pair("limit", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Gitea access-map: failed to list organizations")?;

        if !resp.status().is_success() {
            warn!("Gitea access-map: org enumeration failed with HTTP {}", resp.status());
            break;
        }

        let mut page_orgs: Vec<GiteaOrg> =
            resp.json().await.context("Gitea access-map: invalid org JSON")?;
        let count = page_orgs.len();
        orgs.append(&mut page_orgs);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(orgs)
}

fn derive_severity(user: &GiteaUser, repos: &[GiteaRepo]) -> Severity {
    if user.is_admin {
        return Severity::Critical;
    }

    let mut severity = Severity::Low;
    for repo in repos {
        let perms = repo.permissions.as_ref();
        if perms.is_some_and(|p| p.admin) {
            return Severity::High;
        }
        if perms.is_some_and(|p| p.push) {
            severity = Severity::Medium;
        }
    }
    severity
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    #[tokio::test]
    async fn enterprise_mapping_keeps_the_api_prefix() {
        let server = MockServer::start().await;
        for (resource, body) in [
            ("user", json!({ "login": "member" })),
            ("user/repos", json!([])),
            ("user/orgs", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/team/api/v1/{resource}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let result =
            map_access_from_token_at("test-token", &format!("{}/team/api/v1", server.uri()))
                .await
                .unwrap();
        assert_eq!(result.identity.id, "member");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[test]
    fn observer_credentials_require_an_explicit_https_instance() {
        let activity = json!({
            "username": "member", "token_id": 42,
            "audit_username": "observer", "audit_password": "abc"
        });
        for (endpoint, enabled) in [
            (None, false),
            (Some("http://gitea.example.test"), false),
            (Some("https://gitea.example.test/team"), true),
        ] {
            let raw =
                json!({"token": "test-token", "api_endpoint": endpoint, "activity": activity});
            let parsed = parse_gitea_credentials(&raw.to_string());
            if enabled {
                assert!(parsed.unwrap().2.is_some());
            } else {
                assert!(
                    matches!(parsed, Err(err) if err.to_string().contains("explicit HTTPS api_endpoint"))
                );
            }
        }
        let (token, _, config) = parse_gitea_credentials("test-token").unwrap();
        assert_eq!(token, "test-token");
        assert!(config.is_none());
    }

    #[test]
    fn rejects_malformed_activity_configuration() {
        for activity in [
            json!("malformed"),
            json!({
                "username": "member", "token_id": 0,
                "audit_username": "observer", "audit_password": "abc"
            }),
        ] {
            let raw = json!({
                "token": "test-token",
                "api_endpoint": "https://gitea.example.test",
                "activity": activity,
            });
            assert!(parse_gitea_credentials(&raw.to_string()).is_err());
        }
    }

    #[tokio::test]
    async fn reads_exact_token_before_mapping_and_checks_the_owner() {
        let config = GiteaActivityCredential {
            username: "member".into(),
            token_id: 42,
            audit_username: "observer".into(),
            audit_password: "abc".into(),
        };
        let readout = |last_used: &str| {
            ResponseTemplate::new(200).set_body_json(json!([
                {"id": 41, "token_last_eight": "12345678", "last_used_at": "2025-03-01T00:00:00Z"},
                {"id": 42, "token_last_eight": "12345678", "created_at": "2025-01-01T00:00:00Z", "last_used_at": last_used},
            ]))
        };
        let date = "2025-02-01T08:00:00+02:00";
        let activity_path = "/team/api/v1/users/member/tokens";
        for (owner, response, expected) in [
            ("Member", readout(date), Some("2025-02-01T06:00:00Z")),
            ("unrelated-user", readout(date), None),
            ("Member", readout("2025-01-01T00:00:00Z"), None),
            ("Member", ResponseTemplate::new(403), None),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(activity_path))
                .and(header("authorization", "Basic b2JzZXJ2ZXI6YWJj"))
                .and(query_param("page", "1"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            for (route, value) in [
                ("user", json!({ "login": owner })),
                ("user/orgs", json!([])),
                ("user/repos", json!([])),
            ] {
                Mock::given(method("GET"))
                    .and(path(format!("/team/api/v1/{route}")))
                    .and(header("authorization", "token fake-token-12345678"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(value))
                    .expect(1)
                    .mount(&server)
                    .await;
            }
            let api_url = Url::parse(&format!("{}/team/api/v1/", server.uri())).unwrap();
            let result = map_access_with_options("fake-token-12345678", &api_url, Some(&config))
                .await
                .unwrap();
            assert_eq!(result.identity.id, owner);
            assert_eq!(result.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                result
                    .provider_metadata
                    .and_then(|metadata| metadata.credential_last_used_source)
                    .as_deref(),
                expected.map(|_| LAST_USED_SOURCE)
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests[0].url.path(), activity_path);
            assert_eq!(requests[1].url.path(), "/team/api/v1/user");
        }
    }
}
