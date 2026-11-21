use std::{collections::HashSet, time::Duration};

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::join_all;
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const BUILDKITE_API: &str = "https://api.buildkite.com/v2";
const BUILDKITE_GRAPHQL: &str = "https://graphql.buildkite.com/v1";
const TOKEN_AUDIT_QUERY: &str = "query TokenActivity($slug: ID!, $after: String) {
    organization(slug: $slug) {
        apiAccessTokens(first: 50, after: $after) {
            nodes { uuid lastAccessedAt }
            pageInfo { hasNextPage endCursor }
        }
    }
}";
const MAX_TOKEN_AUDIT_ORGANIZATIONS: usize = 4;
const MAX_TOKEN_AUDIT_PAGES: usize = 3;
const MAX_TOKEN_AUDIT_RESPONSE_BYTES: usize = 128 * 1024;
const TOKEN_AUDIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct BuildkiteAccessToken {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct BuildkiteUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct BuildkiteOrganization {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Deserialize)]
struct BuildkitePipeline {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Buildkite token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Buildkite access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_before(token, Utc::now()).await
}

pub(crate) async fn map_access_from_token_before(
    token: &str,
    activity_before: DateTime<Utc>,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Buildkite HTTP client")?;

    let token_info = fetch_access_token(&client, token).await?;

    let user = fetch_user(&client, token).await.unwrap_or_else(|err| {
        warn!("Buildkite access-map: user lookup failed: {err}");
        BuildkiteUser { id: None, name: None, email: None, created_at: None }
    });

    let username = user
        .name
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "buildkite_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "user".into(),
        project: None,
        tenant: None,
        account_id: user.id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    for scope in &token_info.scopes {
        let role = RoleBinding {
            name: format!("scope:{scope}"),
            source: "buildkite".into(),
            permissions: vec![scope.clone()],
        };
        roles.push(role);

        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    let orgs = list_organizations(&client, token).await.unwrap_or_else(|err| {
        warn!("Buildkite access-map: organization enumeration failed: {err}");
        Vec::new()
    });
    let last_used_at =
        find_token_activity(&client, BUILDKITE_GRAPHQL, token, &token_info, &orgs, activity_before)
            .await
            .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true));
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some("Buildkite organization token activity".into()),
        ..ProviderMetadata::default()
    });

    for org in &orgs {
        let org_name = org
            .slug
            .clone()
            .or_else(|| org.name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name.clone(),
            permissions: token_info.scopes.clone(),
            risk: severity_to_str(if has_admin_scope(&token_info.scopes) {
                Severity::High
            } else {
                Severity::Medium
            })
            .to_string(),
            reason: "Organization accessible with this token".to_string(),
        });

        let pipelines = list_pipelines(&client, token, &org_name).await.unwrap_or_else(|err| {
            warn!("Buildkite access-map: pipeline enumeration for {org_name} failed: {err}");
            Vec::new()
        });

        for pipeline in &pipelines {
            let pipeline_name = pipeline
                .name
                .clone()
                .or_else(|| pipeline.slug.clone())
                .unwrap_or_else(|| "unknown_pipeline".to_string());

            let is_private = pipeline.visibility.as_deref() != Some("public");

            let (risk, perm_label) = if is_private {
                (Severity::Medium, "pipeline:private")
            } else {
                (Severity::Low, "pipeline:public")
            };

            resources.push(ResourceExposure {
                resource_type: "pipeline".into(),
                name: format!("{org_name}/{pipeline_name}"),
                permissions: vec![perm_label.to_string()],
                risk: severity_to_str(risk).to_string(),
                reason: if is_private {
                    "Accessible private pipeline".to_string()
                } else {
                    "Accessible public pipeline".to_string()
                },
            });
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&token_info.scopes, &orgs);

    if orgs.is_empty() && token_info.scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Buildkite account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any organizations or scopes".into());
    }

    Ok(AccessMapResult {
        cloud: "buildkite".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.name.clone(),
            username: user.email.clone(),
            account_type: None,
            company: None,
            location: None,
            email: user.email.clone(),
            url: None,
            token_type: None,
            created_at: user.created_at.clone(),
            last_used_at,
            expires_at: None,
            user_id: user.id.or(token_info.uuid),
            scopes: token_info.scopes,
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn find_token_activity(
    client: &Client,
    graphql_endpoint: &str,
    token: &str,
    token_info: &BuildkiteAccessToken,
    orgs: &[BuildkiteOrganization],
    activity_before: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let token_id = uuid::Uuid::parse_str(token_info.uuid.as_deref()?).ok()?;
    if !token_info.scopes.iter().any(|scope| scope.eq_ignore_ascii_case("graphql")) {
        return None;
    }

    let mut seen = HashSet::new();
    // The REST list is limited to organizations available to this credential. GraphQL applies
    // its own authorization for the audit inventory within each organization.
    let requests = orgs
        .iter()
        .filter_map(|org| org.slug.as_deref().filter(|slug| !slug.is_empty()))
        .filter(|slug| seen.insert(*slug))
        .take(MAX_TOKEN_AUDIT_ORGANIZATIONS)
        .map(|slug| query_org_token_activity(client, graphql_endpoint, token, slug, token_id));
    join_all(requests).await.into_iter().flatten().max().filter(|timestamp| {
        // This API only gives the current last-use time. When our own requests may have replaced
        // it, the pre-scan value is unavailable.
        timestamp.timestamp() < activity_before.timestamp()
    })
}

async fn query_org_token_activity(
    client: &Client,
    graphql_endpoint: &str,
    token: &str,
    slug: &str,
    token_id: uuid::Uuid,
) -> Option<DateTime<Utc>> {
    let mut after: Option<String> = None;
    let mut seen = HashSet::new();
    for _ in 0..MAX_TOKEN_AUDIT_PAGES {
        let request = client
            .post(graphql_endpoint)
            .bearer_auth(token)
            .timeout(TOKEN_AUDIT_REQUEST_TIMEOUT)
            .json(&json!({ "query": TOKEN_AUDIT_QUERY, "variables": { "slug": slug, "after": after }}));
        let mut response = request.send().await.ok()?;
        if !response.status().is_success() {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if chunk.len() > MAX_TOKEN_AUDIT_RESPONSE_BYTES.saturating_sub(body.len()) {
                return None;
            }
            body.extend_from_slice(&chunk);
        }

        let payload: Value = serde_json::from_slice(&body).ok()?;
        let connection = &payload["data"]["organization"]["apiAccessTokens"];
        for node in connection["nodes"].as_array()? {
            if node["uuid"].as_str().and_then(|value| uuid::Uuid::parse_str(value).ok())
                == Some(token_id)
            {
                return DateTime::parse_from_rfc3339(node["lastAccessedAt"].as_str()?)
                    .ok()
                    .map(|timestamp| timestamp.with_timezone(&Utc));
            }
        }
        let page_info = &connection["pageInfo"];
        if page_info["hasNextPage"] != true {
            break;
        }
        let cursor = page_info["endCursor"].as_str()?.to_owned();
        if cursor.is_empty() || !seen.insert(cursor.clone()) {
            break;
        }
        after = Some(cursor);
    }
    None
}

async fn fetch_access_token(client: &Client, token: &str) -> Result<BuildkiteAccessToken> {
    let resp = client
        .get(format!("{BUILDKITE_API}/access-token"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to fetch access-token info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Buildkite access-map: access-token lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Buildkite access-map: invalid access-token JSON")
}

async fn fetch_user(client: &Client, token: &str) -> Result<BuildkiteUser> {
    let resp = client
        .get(format!("{BUILDKITE_API}/user"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to fetch user info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Buildkite access-map: user lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Buildkite access-map: invalid user JSON")
}

async fn list_organizations(client: &Client, token: &str) -> Result<Vec<BuildkiteOrganization>> {
    let resp = client
        .get(format!("{BUILDKITE_API}/organizations"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to list organizations")?;

    if !resp.status().is_success() {
        warn!("Buildkite access-map: organization enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Buildkite access-map: invalid organizations JSON")
}

async fn list_pipelines(
    client: &Client,
    token: &str,
    org_slug: &str,
) -> Result<Vec<BuildkitePipeline>> {
    let mut pipelines = Vec::new();
    let mut page = 1;

    loop {
        let resp = client
            .get(format!(
                "{BUILDKITE_API}/organizations/{org_slug}/pipelines?per_page=100&page={page}"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Buildkite access-map: failed to list pipelines")?;

        if !resp.status().is_success() {
            warn!("Buildkite access-map: pipeline enumeration failed with HTTP {}", resp.status());
            break;
        }

        let batch: Vec<BuildkitePipeline> =
            resp.json().await.context("Buildkite access-map: invalid pipelines JSON")?;

        if batch.is_empty() {
            break;
        }

        pipelines.extend(batch);
        page += 1;
    }

    Ok(pipelines)
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "write_organizations" | "write_teams" => ScopeRisk::Admin,
        "write_pipelines"
        | "write_builds"
        | "write_agents"
        | "write_artifacts"
        | "write_build_logs"
        | "write_notification_services"
        | "write_suites"
        | "write_test_plan"
        | "write_user"
        | "write_registries"
        | "write_clusters"
        | "write_cluster_tokens"
        | "write_rule" => ScopeRisk::Write,
        _ if scope.starts_with("write_") => ScopeRisk::Write,
        _ => ScopeRisk::Read,
    }
}

fn has_admin_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| matches!(s.as_str(), "write_organizations" | "write_teams"))
}

fn derive_severity(scopes: &[String], orgs: &[BuildkiteOrganization]) -> Severity {
    if has_admin_scope(scopes) {
        return Severity::High;
    }

    let has_write = scopes.iter().any(|s| s.starts_with("write_"));
    if has_write && !orgs.is_empty() {
        return Severity::Medium;
    }

    if !orgs.is_empty() {
        return Severity::Low;
    }

    Severity::Low
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
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn audit_activity_matches_the_exact_uuid_and_excludes_scan_time() {
        const TOKEN_ID: &str = "b63254c0-3271-4a98-8270-7cfbd6c2f14e";
        const OTHER_ID: &str = "b63254c0-3271-4a98-8270-7cfbd6c2f141";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1"))
            .and(header("authorization", "Bearer provided-token"))
            .respond_with(|request: &Request| {
                let payload: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(payload["query"], TOKEN_AUDIT_QUERY);
                let connection = match (
                    payload["variables"]["slug"].as_str(),
                    payload["variables"]["after"].as_str(),
                ) {
                    (Some("denied"), None) => return ResponseTemplate::new(403),
                    (Some("visible"), None) => json!({
                        "nodes": [{ "uuid": OTHER_ID, "lastAccessedAt": "2026-01-01T16:00:00Z" }],
                        "pageInfo": { "hasNextPage": true, "endCursor": "page-two" }
                    }),
                    (Some("visible"), Some("page-two")) => json!({
                        "nodes": [{ "uuid": TOKEN_ID, "lastAccessedAt": "2026-01-01T10:00:00-05:00" }],
                        "pageInfo": { "hasNextPage": false }
                    }),
                    _ => panic!("unexpected audit request"),
                };
                ResponseTemplate::new(200).set_body_json(json!({
                    "data": { "organization": { "apiAccessTokens": connection } }
                }))
            })
            .expect(6)
            .mount(&server)
            .await;

        let token =
            BuildkiteAccessToken { uuid: Some(TOKEN_ID.into()), scopes: vec!["graphql".into()] };
        let orgs = ["denied", "visible", "visible"]
            .map(|slug| BuildkiteOrganization { name: None, slug: Some(slug.into()) });
        let endpoint = format!("{}/v1", server.uri());
        let client = Client::new();
        let expected = "2026-01-01T15:00:00Z".parse::<DateTime<Utc>>().unwrap();

        for (cutoff, result) in
            [("2026-01-01T17:00:00Z", Some(expected)), ("2026-01-01T15:00:00.500Z", None)]
        {
            let latest = find_token_activity(
                &client,
                &endpoint,
                "provided-token",
                &token,
                &orgs,
                cutoff.parse().unwrap(),
            )
            .await;
            assert_eq!(latest, result);
        }
    }

    #[tokio::test]
    async fn audit_activity_skips_missing_id_or_graphql_scope() {
        let server = MockServer::start().await;
        let orgs = [BuildkiteOrganization { name: None, slug: Some("visible".into()) }];
        for token in [
            BuildkiteAccessToken { uuid: None, scopes: vec!["graphql".into()] },
            BuildkiteAccessToken {
                uuid: Some("b63254c0-3271-4a98-8270-7cfbd6c2f14e".into()),
                scopes: vec!["read_organizations".into()],
            },
        ] {
            assert_eq!(
                find_token_activity(
                    &Client::new(),
                    &server.uri(),
                    "provided-token",
                    &token,
                    &orgs,
                    Utc::now(),
                )
                .await,
                None,
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
