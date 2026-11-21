use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const KEY_USAGE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_USAGE_SOURCE: &str = "Zendesk current OAuth token";

#[derive(Deserialize)]
struct ZendeskTokenResponse {
    token: ZendeskTokenUsage,
}

#[derive(Deserialize)]
struct ZendeskTokenUsage {
    used_at: Option<String>,
}

#[derive(Deserialize)]
struct ZendeskUserResponse {
    user: ZendeskUser,
}

#[derive(Deserialize)]
struct ZendeskUser {
    id: Option<u64>,
    email: Option<String>,
    name: Option<String>,
    role: Option<String>,
    active: Option<bool>,
}

#[derive(Deserialize)]
struct ZendeskCountResponse {
    count: Option<ZendeskCount>,
}

#[derive(Deserialize)]
struct ZendeskCount {
    value: Option<u64>,
}

#[derive(Deserialize)]
struct ZendeskGroupsResponse {
    groups: Option<Vec<ZendeskGroup>>,
}

#[derive(Deserialize)]
struct ZendeskGroup {
    #[expect(dead_code)]
    id: Option<u64>,
    name: Option<String>,
}

/// Entry point when invoked via the CLI `access-map zendesk` subcommand.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Zendesk access-map requires a credential file with token and subdomain")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Zendesk credential file from {}", path.display())
    })?;
    let (token, subdomain) = parse_zendesk_credentials(&raw)?;
    map_access_from_token_and_subdomain(&token, &subdomain).await
}

/// Maps a Zendesk API token and subdomain to an access profile.
pub async fn map_access_from_token_and_subdomain(
    token: &str,
    subdomain: &str,
) -> Result<AccessMapResult> {
    let subdomain = subdomain.trim().trim_matches('/').to_ascii_lowercase();
    if !(1..=63).contains(&subdomain.len())
        || subdomain.starts_with('-')
        || subdomain.ends_with('-')
        || !subdomain.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(anyhow!("Zendesk access-map requires a valid Zendesk subdomain"));
    }

    let base_url = format!("https://{subdomain}.zendesk.com");
    map_access_from_token_at(token, &subdomain, &base_url).await
}

async fn map_access_from_token_at(
    token: &str,
    subdomain: &str,
    base_url: &str,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Zendesk HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Query the supplied OAuth token's own activity before the other authenticated probes.
    let last_used_at = fetch_token_last_used(&client, token, base_url).await;
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some(KEY_USAGE_SOURCE.into()),
        ..ProviderMetadata::default()
    });

    // Fetch current user info
    let user = fetch_current_user(&client, token, base_url).await?;

    let user_id = user.id.map(|id| id.to_string()).unwrap_or_default();
    let user_email = user.email.clone();
    let user_name = user.name.clone();
    let role = user.role.clone().unwrap_or_else(|| "unknown".to_string());
    let active = user.active.unwrap_or(false);

    if !active {
        risk_notes.push("User account is inactive / suspended".to_string());
    }

    // Classify by role
    let severity = match role.as_str() {
        "admin" => {
            permissions.admin.push("account:admin".to_string());
            permissions.admin.push("users:manage".to_string());
            permissions.admin.push("tickets:manage".to_string());
            permissions.admin.push("groups:manage".to_string());
            permissions.risky.push("settings:manage".to_string());
            risk_notes.push("Admin role grants full account management".to_string());
            Severity::Critical
        }
        "agent" => {
            permissions.risky.push("tickets:read".to_string());
            permissions.risky.push("tickets:write".to_string());
            permissions.read_only.push("users:read".to_string());
            risk_notes.push("Agent role provides ticket read/write access".to_string());
            Severity::Medium
        }
        "end-user" | "end_user" => {
            permissions.read_only.push("tickets:own".to_string());
            Severity::Low
        }
        _ => {
            permissions.read_only.push(format!("role:{role}"));
            risk_notes.push(format!("Unknown Zendesk role: {role}"));
            Severity::Medium
        }
    };

    // Probe ticket count
    let ticket_count = fetch_ticket_count(&client, token, base_url).await;
    match ticket_count {
        Ok(Some(count)) => {
            permissions.read_only.push("tickets:count".to_string());
            risk_notes.push(format!("Ticket count accessible: {count} tickets"));
        }
        Ok(None) => {}
        Err(err) => {
            warn!("Zendesk access-map: ticket count probe failed: {err}");
        }
    }

    // Probe groups
    let groups = fetch_groups(&client, token, base_url).await.unwrap_or_else(|err| {
        warn!("Zendesk access-map: groups probe failed: {err}");
        Vec::new()
    });

    if !groups.is_empty() {
        permissions.read_only.push("groups:list".to_string());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let roles = vec![RoleBinding {
        name: format!("zendesk_role:{role}"),
        source: "zendesk".into(),
        permissions: permissions
            .admin
            .iter()
            .chain(permissions.risky.iter())
            .chain(permissions.read_only.iter())
            .cloned()
            .collect(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "zendesk_instance".into(),
        name: subdomain.to_owned(),
        permissions: vec![format!("role:{role}")],
        risk: severity_to_str(severity).to_string(),
        reason: "Zendesk instance accessible with this token".to_string(),
    }];

    for group in &groups {
        if let Some(name) = &group.name {
            resources.push(ResourceExposure {
                resource_type: "zendesk_group".into(),
                name: name.clone(),
                permissions: vec!["group:member".into()],
                risk: severity_to_str(Severity::Low).to_string(),
                reason: "Group visible to this token".to_string(),
            });
        }
    }

    let identity_id = user_email
        .clone()
        .or_else(|| user_name.clone())
        .unwrap_or_else(|| format!("zendesk_user:{user_id}"));

    Ok(AccessMapResult {
        cloud: "zendesk".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: role.clone(),
            project: Some(subdomain.to_owned()),
            tenant: None,
            account_id: Some(user_id.clone()),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user_name,
            username: None,
            account_type: Some(role),
            company: None,
            location: None,
            email: user_email,
            url: Some(base_url.to_owned()),
            token_type: Some("bearer_token".into()),
            created_at: None,
            last_used_at,
            expires_at: None,
            user_id: Some(user_id),
            scopes: Vec::new(),
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn fetch_token_last_used(client: &Client, token: &str, base_url: &str) -> Option<String> {
    let response = client
        .get(format!("{base_url}/api/v2/oauth/tokens/current"))
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json")
        .timeout(KEY_USAGE_LOOKUP_TIMEOUT)
        .send()
        .await;
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            debug!(status = %response.status(), "Zendesk access-map: current OAuth token usage unavailable");
            return None;
        }
        Err(_) => {
            debug!("Zendesk access-map: current OAuth token usage request failed");
            return None;
        }
    };
    let usage: ZendeskTokenResponse = response
        .json()
        .await
        .inspect_err(|_| debug!("Zendesk access-map: invalid current OAuth token usage response"))
        .ok()?;
    let date = DateTime::parse_from_rfc3339(usage.token.used_at.as_deref()?).ok()?;
    Some(date.to_utc().to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

fn parse_zendesk_credentials(raw: &str) -> Result<(String, String)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .or_else(|| json.get("api_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let subdomain = json
            .get("subdomain")
            .or_else(|| json.get("domain"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        if let (Some(token), Some(subdomain)) = (token, subdomain) {
            return Ok((token, subdomain));
        }
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() >= 2 {
        return Ok((lines[0].to_string(), lines[1].to_string()));
    }

    Err(anyhow!(
        "Zendesk credential format not recognized. Provide JSON with token + subdomain, or two lines (token, subdomain)."
    ))
}

async fn fetch_current_user(client: &Client, token: &str, base_url: &str) -> Result<ZendeskUser> {
    let resp = client
        .get(format!("{base_url}/api/v2/users/me.json"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Zendesk access-map: failed to query users/me endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Zendesk access-map: users/me endpoint returned HTTP {}",
            resp.status()
        ));
    }

    let user_resp: ZendeskUserResponse =
        resp.json().await.context("Zendesk access-map: invalid users/me JSON")?;
    Ok(user_resp.user)
}

async fn fetch_ticket_count(client: &Client, token: &str, base_url: &str) -> Result<Option<u64>> {
    let resp = client
        .get(format!("{base_url}/api/v2/tickets/count.json"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Zendesk access-map: failed to query tickets/count endpoint")?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let count_resp: ZendeskCountResponse =
        resp.json().await.context("Zendesk access-map: invalid tickets/count JSON")?;
    Ok(count_resp.count.and_then(|c| c.value))
}

async fn fetch_groups(client: &Client, token: &str, base_url: &str) -> Result<Vec<ZendeskGroup>> {
    let resp = client
        .get(format!("{base_url}/api/v2/groups.json"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Zendesk access-map: failed to query groups endpoint")?;

    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let groups_resp: ZendeskGroupsResponse =
        resp.json().await.context("Zendesk access-map: invalid groups JSON")?;
    Ok(groups_resp.groups.unwrap_or_default())
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
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    #[tokio::test]
    async fn current_oauth_token_usage_is_looked_up_first_and_is_optional() {
        const TOKEN: &str = "test-zendesk-token";
        const TOKEN_PATH: &str = "/api/v2/oauth/tokens/current";
        const UNUSED_RESPONSE_SECRET: &str = "test-refresh-token-not-for-reporting";
        let other = MockServer::start().await;
        Mock::given(path("/redirected"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&other)
            .await;
        for (response, expected) in [
            (
                ResponseTemplate::new(200).set_body_json(json!({"token": {
                    "used_at": "2025-01-02T03:04:05+01:00",
                    "refresh_token": UNUSED_RESPONSE_SECRET,
                }})),
                Some("2025-01-02T02:04:05Z"),
            ),
            (ResponseTemplate::new(200).set_body_json(json!({"token":{"used_at":null}})), None),
            (ResponseTemplate::new(403), None),
            (
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/redirected", other.uri())),
                None,
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(TOKEN_PATH))
                .and(header("authorization", format!("Bearer {TOKEN}")))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/api/v2/users/me.json"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"user": {
                    "id": 123, "name": "Zendesk user", "role": "agent", "active": true,
                }})))
                .mount(&server)
                .await;

            let mapped = map_access_from_token_at(TOKEN, "example", &server.uri()).await.unwrap();
            assert_eq!(mapped.identity.id, "Zendesk user");
            assert!(!serde_json::to_string(&mapped).unwrap().contains(UNUSED_RESPONSE_SECRET));
            assert_eq!(mapped.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                mapped.provider_metadata.and_then(|metadata| metadata.credential_last_used_source),
                expected.map(|_| KEY_USAGE_SOURCE.to_owned()),
            );
            assert_eq!(server.received_requests().await.unwrap()[0].url.path(), TOKEN_PATH);
        }
    }

    #[tokio::test]
    async fn rejects_subdomains_that_could_send_tokens_to_another_host() {
        for subdomain in ["", "example.test/path", "example.test#", "example.test?", "user@"] {
            let error =
                map_access_from_token_and_subdomain("test-token", subdomain).await.unwrap_err();
            assert!(error.to_string().contains("valid Zendesk subdomain"));
        }
    }
}
