use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, Url, header::HeaderValue};
use serde::Deserialize;
use tracing::debug;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITLAB_HOST: &str = "gitlab.com";
const ACTIVITY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct GitLabCredentialFile {
    token: String,
    #[serde(alias = "base_url")]
    api_endpoint: String,
    audit_token: Option<String>,
}

#[derive(Deserialize)]
struct GitLabTokenActivity {
    last_used_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    visibility: String,
    permissions: Option<GitLabProjectPermissions>,
}

#[derive(Deserialize)]
struct GitLabUser {
    id: u64,
    username: String,
    name: String,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Clone, Deserialize)]
struct GitLabProjectPermissions {
    project_access: Option<GitLabAccess>,
    group_access: Option<GitLabAccess>,
}

#[derive(Clone, Deserialize)]
struct GitLabAccess {
    access_level: u32,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("GitLab access-map requires a validated token from scan results"))?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read GitLab token from {}", path.display()))?;
    let raw = raw.trim();
    if raw.starts_with('{') {
        let credential: GitLabCredentialFile = serde_json::from_str(raw).map_err(|_| {
            anyhow!("Invalid GitLab credential JSON; expected token and api_endpoint")
        })?;
        let api_url =
            crate::provider_endpoints::access_map_api_url("gitlab", &credential.api_endpoint)?;
        let token = credential.token.trim();
        let audit_token = credential.audit_token.as_deref().map(str::trim);
        if let Some(audit_token) = audit_token {
            if api_url.scheme() != "https" || api_url.host_str() == Some(DEFAULT_GITLAB_HOST) {
                return Err(anyhow!("GitLab audit_token requires an HTTPS self-managed instance"));
            }
            if audit_token.is_empty() || audit_token == token {
                return Err(anyhow!("GitLab audit_token must be a separate administrator token"));
            }
        }
        return map_access_with_client(&gitlab_client()?, &api_url, token, Utc::now(), audit_token)
            .await;
    }

    map_access_from_token(raw).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, DEFAULT_GITLAB_HOST).await
}

pub async fn map_access_from_token_at(token: &str, api_endpoint: &str) -> Result<AccessMapResult> {
    map_access_from_token_at_before(token, api_endpoint, Utc::now()).await
}

pub(super) async fn map_access_from_token_before(
    token: &str,
    activity_before: DateTime<Utc>,
) -> Result<AccessMapResult> {
    map_access_from_token_at_before(token, DEFAULT_GITLAB_HOST, activity_before).await
}

pub(super) async fn map_access_from_token_at_before(
    token: &str,
    api_endpoint: &str,
    activity_before: DateTime<Utc>,
) -> Result<AccessMapResult> {
    let api_url = crate::provider_endpoints::access_map_api_url("gitlab", api_endpoint)?;
    map_access_with_client(&gitlab_client()?, &api_url, token, activity_before, None).await
}

fn gitlab_client() -> Result<Client> {
    Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .context("Failed to build GitLab access-map client")
}

async fn map_access_with_client(
    client: &Client,
    api_url: &Url,
    token: &str,
    activity_before: DateTime<Utc>,
    audit_token: Option<&str>,
) -> Result<AccessMapResult> {
    let last_use = fetch_last_use(client, api_url, token, audit_token, activity_before).await;

    // GitLab REST API: current user and membership-project listings.
    // https://docs.gitlab.com/api/users/#retrieve-the-current-user
    // https://docs.gitlab.com/api/projects/#list-all-projects
    // The full authenticated project representation is intentional: simple=true omits the
    // permissions object used to report direct and inherited access.
    let user = fetch_current_user(client, api_url, token).await?;

    let identity = AccessSummary {
        id: user.username.clone(),
        access_type: "user_token".into(),
        project: None,
        tenant: None,
        account_id: Some(user.id.to_string()),
    };

    let mut risk_notes = vec!["Project permissions describe principal membership; token scopes may further restrict effective access".into()];
    let projects = match list_accessible_projects(client, api_url, token, &mut risk_notes).await {
        Ok(projects) => projects,
        Err(err) => {
            risk_notes.push(format!("Project enumeration failed: {err}"));
            Vec::new()
        }
    };
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();

    for project in &projects {
        let access_level =
            project.permissions.as_ref().map(effective_access_level).unwrap_or_default();
        let (perm_label, severity) = access_level_to_risk(access_level);

        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: project.path_with_namespace.clone(),
            permissions: vec![perm_label.to_string()],
            risk: severity_to_str(severity).to_string(),
            reason: format!("Accessible {} project", project.visibility),
        });

        match severity {
            Severity::High | Severity::Critical => permissions.admin.push(perm_label.to_string()),
            Severity::Medium => permissions.risky.push(perm_label.to_string()),
            Severity::Unknown => {}
            Severity::Low => permissions.read_only.push(perm_label.to_string()),
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&projects);

    let roles = vec![RoleBinding {
        name: "gitlab_user".into(),
        source: "users/current".into(),
        permissions: vec!["projects:membership:list".into()],
    }];

    if projects.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: identity.id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "GitLab account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any projects".into());
    }

    let token_details = Some(AccessTokenDetails {
        name: Some(user.name),
        username: Some(user.username),
        account_type: None,
        company: None,
        location: None,
        email: user.email,
        url: None,
        token_type: Some("gitlab_user_token".into()),
        created_at: None,
        last_used_at: last_use.map(|(date, _)| date.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        expires_at: None,
        user_id: Some(user.id.to_string()),
        scopes: Vec::new(),
    });

    Ok(AccessMapResult {
        cloud: "gitlab".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details,
        provider_metadata: last_use.map(|(_, source)| ProviderMetadata {
            credential_last_used_source: Some(source.into()),
            ..ProviderMetadata::default()
        }),
        fingerprint: None,
    })
}

async fn fetch_last_use(
    client: &Client,
    api_url: &Url,
    token: &str,
    audit_token: Option<&str>,
    activity_before: DateTime<Utc>,
) -> Option<(DateTime<Utc>, &'static str)> {
    let (request, authorization, source) = if let Some(audit_token) = audit_token {
        (
            client
                .post(api_url.join("admin/token").ok()?)
                .json(&serde_json::json!({"token": token})),
            audit_token,
            "GitLab administrator token inspection",
        )
    } else {
        (
            client.get(api_url.join("personal_access_tokens/self").ok()?),
            token,
            "GitLab personal access token activity",
        )
    };
    let mut header = HeaderValue::from_str(authorization).ok()?;
    header.set_sensitive(true);
    let response = request
        .header("PRIVATE-TOKEN", header)
        .timeout(ACTIVITY_TIMEOUT)
        .send()
        .await
        .inspect_err(|err| debug!(status = ?err.status(), "GitLab token activity lookup failed"))
        .ok()?;
    if !response.status().is_success() {
        debug!(status = %response.status(), "GitLab token activity lookup failed");
        return None;
    }
    let timestamp = response.json::<GitLabTokenActivity>().await.ok()?.last_used_at?;
    // A PAT-authenticated request can refresh GitLab's stored activity before the
    // endpoint reads it. Exclude even the cutoff's second for coarse server clocks.
    (timestamp.timestamp() < activity_before.timestamp()).then_some((timestamp, source))
}

async fn fetch_current_user(client: &Client, api_url: &Url, token: &str) -> Result<GitLabUser> {
    let response = client.get(api_url.join("user")?).header("PRIVATE-TOKEN", token).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "GitLab access-map: user lookup failed with HTTP {}",
            response.status()
        ));
    }
    response.json().await.context("GitLab access-map: invalid current-user JSON")
}

async fn list_accessible_projects(
    client: &Client,
    api_url: &Url,
    token: &str,
    limitations: &mut Vec<String>,
) -> Result<Vec<GitLabProject>> {
    const MAX_PAGES: u32 = 100;
    let mut projects = Vec::new();
    for page in 1..=MAX_PAGES {
        let mut url = api_url.join("projects")?;
        url.query_pairs_mut()
            .append_pair("membership", "true")
            .append_pair("simple", "false")
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string());
        let response = match client.get(url).header("PRIVATE-TOKEN", token).send().await {
            Ok(response) => response,
            Err(_) if page == 1 => {
                return Err(anyhow!("GitLab project enumeration failed: request failed on page 1"));
            }
            Err(_) => {
                limitations.push(format!(
                    "GitLab project enumeration is partial: request failed on page {page}"
                ));
                return Ok(projects);
            }
        };
        if !response.status().is_success() {
            if page == 1 {
                return Err(anyhow!(
                    "GitLab project enumeration failed: HTTP {}",
                    response.status()
                ));
            }
            limitations
                .push(format!("GitLab project enumeration is partial: HTTP {}", response.status()));
            return Ok(projects);
        }
        // A full final page is still complete. GitLab's explicit empty
        // X-Next-Page header is authoritative even at the page-work limit.
        let last_page = response
            .headers()
            .get("x-next-page")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.trim().is_empty());
        let items: Vec<GitLabProject> = match response.json().await {
            Ok(items) => items,
            Err(_) if page == 1 => {
                return Err(anyhow!(
                    "GitLab project enumeration failed: invalid response on page 1"
                ));
            }
            Err(_) => {
                limitations.push(format!(
                    "GitLab project enumeration is partial: invalid response on page {page}"
                ));
                return Ok(projects);
            }
        };
        let count = items.len();
        projects.extend(items);
        if count < 100 || last_page {
            return Ok(projects);
        }
    }
    limitations.push(format!("GitLab project enumeration was capped at {MAX_PAGES} pages"));
    Ok(projects)
}

fn effective_access_level(perms: &GitLabProjectPermissions) -> u32 {
    let project_level = perms.project_access.as_ref().map(|access| access.access_level);
    let group_level = perms.group_access.as_ref().map(|access| access.access_level);
    project_level.max(group_level).unwrap_or_default()
}

fn access_level_to_risk(access_level: u32) -> (&'static str, Severity) {
    match access_level {
        50 => ("project:owner", Severity::High),
        40 => ("project:maintainer", Severity::High),
        30 => ("project:developer", Severity::Medium),
        20 => ("project:reporter", Severity::Low),
        10 => ("project:guest", Severity::Low),
        _ => ("project:access", Severity::Low),
    }
}

fn derive_severity(projects: &[GitLabProject]) -> Severity {
    let mut severity = Severity::Low;
    for project in projects {
        let access_level =
            project.permissions.as_ref().map(effective_access_level).unwrap_or_default();
        let (_, project_severity) = access_level_to_risk(access_level);
        match project_severity {
            Severity::High | Severity::Critical => return Severity::High,
            Severity::Medium => severity = Severity::Medium,
            Severity::Unknown | Severity::Low => {}
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn enterprise_mapping_keeps_token_authentication_on_its_instance() {
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method, path, query_param},
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/team/api/v4/personal_access_tokens/self"))
            .and(header("PRIVATE-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/team/api/v4/user"))
            .and(header("PRIVATE-TOKEN", "test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "id": 1, "name": "Member", "username": "member" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/team/api/v4/projects"))
            .and(query_param("membership", "true")).and(query_param("simple", "false"))
            .and(header("PRIVATE-TOKEN", "test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "path_with_namespace": "group/repo", "visibility": "private", "permissions": { "project_access": { "access_level": 20 }, "group_access": { "access_level": 40 } } }])))
            .expect(1).mount(&server).await;
        let result =
            map_access_from_token_at("test-token", &format!("{}/team/api/v4", server.uri()))
                .await
                .unwrap();
        assert_eq!(result.identity.id, "member");
        assert_eq!(result.resources[0].permissions, vec!["project:maintainer"]);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn token_history_uses_the_exact_credential_and_excludes_scan_activity() {
        use serde_json::json;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{body_json, header, method, path},
        };

        let server = MockServer::start().await;
        let cutoff = "2026-01-02T03:04:05.500Z".parse::<DateTime<Utc>>().unwrap();
        let api_url = Url::parse(&format!("{}/api/v4/", server.uri())).unwrap();
        let client = gitlab_client().unwrap();

        for (timestamp, expected) in [
            ("2026-01-02T03:04:00Z", Some("GitLab personal access token activity")),
            ("2026-01-02T03:04:05Z", None),
            ("2026-01-02T03:04:06Z", None),
        ] {
            let _mock = Mock::given(method("GET"))
                .and(path("/api/v4/personal_access_tokens/self"))
                .and(header("PRIVATE-TOKEN", "test-token"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"last_used_at": timestamp})),
                )
                .expect(1)
                .mount_as_scoped(&server)
                .await;
            let activity = fetch_last_use(&client, &api_url, "test-token", None, cutoff).await;
            assert_eq!(activity.map(|(_, source)| source), expected);
        }

        Mock::given(method("POST"))
            .and(path("/api/v4/admin/token"))
            .and(header("PRIVATE-TOKEN", "audit-token"))
            .and(body_json(json!({"token": "test-token"})))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"last_used_at": "2026-01-01T01:02:03Z"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (date, source) =
            fetch_last_use(&client, &api_url, "test-token", Some("audit-token"), cutoff)
                .await
                .unwrap();
        assert_eq!(date.to_rfc3339_opts(SecondsFormat::Secs, true), "2026-01-01T01:02:03Z");
        assert_eq!(source, "GitLab administrator token inspection");
    }

    #[tokio::test]
    async fn token_header_is_never_forwarded_to_a_redirect() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/user", destination.uri())),
            )
            .mount(&server)
            .await;
        assert!(map_access_from_token_at("test-token", &server.uri()).await.is_err());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn later_page_transport_failure_preserves_fetched_projects() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::query_param};
        let server = MockServer::start().await;
        let projects = vec![
            serde_json::json!({"path_with_namespace": "group/repo", "visibility": "private"});
            100
        ];
        Mock::given(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(projects))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(2))
                    .set_body_json(serde_json::json!([])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let client = Client::builder().timeout(std::time::Duration::from_secs(1)).build().unwrap();
        let mut notes = Vec::new();
        let projects = list_accessible_projects(
            &client,
            &Url::parse(&format!("{}/", server.uri())).unwrap(),
            "synthetic-token",
            &mut notes,
        )
        .await
        .unwrap();
        assert_eq!(projects.len(), 100);
        assert!(notes.iter().any(|note| note.contains("request failed on page 2")));
        assert!(notes.iter().all(|note| !note.contains("synthetic-token")));
    }

    #[tokio::test]
    async fn first_page_failure_is_not_reported_as_partial_enumeration() {
        use wiremock::{Mock, MockServer, ResponseTemplate};
        for response in [
            ResponseTemplate::new(503),
            ResponseTemplate::new(200).set_body_string("invalid JSON"),
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([]))
                .set_delay(std::time::Duration::from_secs(2)),
        ] {
            let server = MockServer::start().await;
            Mock::given(wiremock::matchers::method("GET"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let client =
                Client::builder().timeout(std::time::Duration::from_secs(1)).build().unwrap();
            let mut notes = Vec::new();
            let error = list_accessible_projects(
                &client,
                &Url::parse(&format!("{}/", server.uri())).unwrap(),
                "synthetic-token",
                &mut notes,
            )
            .await
            .err()
            .expect("a first-page failure cannot return partial projects");
            assert!(error.to_string().contains("enumeration failed"));
            assert!(!error.to_string().contains("synthetic-token"));
            assert!(notes.is_empty());
        }
    }

    #[tokio::test]
    async fn full_final_page_does_not_falsely_report_a_pagination_cap() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};
        for additional_page in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(move |request: &wiremock::Request| {
                    let page = request
                        .url
                        .query_pairs()
                        .find(|(key, _)| key == "page")
                        .unwrap()
                        .1
                        .parse::<u32>()
                        .unwrap();
                    let next = if page == 100 && !additional_page {
                        String::new()
                    } else {
                        (page + 1).to_string()
                    };
                    ResponseTemplate::new(200).insert_header("x-next-page", next).set_body_json(
                        vec![
                            serde_json::json!({
                                "path_with_namespace": "group/repo", "visibility": "private"
                            });
                            100
                        ],
                    )
                })
                .expect(100)
                .mount(&server)
                .await;
            let mut notes = Vec::new();
            let projects = list_accessible_projects(
                &Client::new(),
                &Url::parse(&format!("{}/", server.uri())).unwrap(),
                "synthetic-token",
                &mut notes,
            )
            .await
            .unwrap();
            assert_eq!(projects.len(), 10_000);
            assert_eq!(notes.iter().any(|note| note.contains("capped")), additional_page);
        }
    }

    #[test]
    fn inherited_group_access_contributes_to_effective_level() {
        let permissions = GitLabProjectPermissions {
            project_access: Some(GitLabAccess { access_level: 20 }),
            group_access: Some(GitLabAccess { access_level: 40 }),
        };
        assert_eq!(effective_access_level(&permissions), 40);
        assert_eq!(access_level_to_risk(40).0, "project:maintainer");
    }
}
