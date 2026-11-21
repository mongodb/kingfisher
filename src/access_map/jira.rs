use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::cli::commands::access_map::AccessMapArgs;
use crate::validation::GLOBAL_USER_AGENT;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

// ─── API response types ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JiraUser {
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    #[serde(rename = "emailAddress")]
    email_address: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    active: bool,
    #[serde(rename = "accountType")]
    account_type: Option<String>,
}

#[derive(Deserialize)]
struct JiraPermissionsResponse {
    permissions: std::collections::HashMap<String, JiraPermissionEntry>,
}

#[derive(Deserialize)]
struct JiraPermissionEntry {
    #[serde(rename = "havePermission")]
    have_permission: bool,
}

#[derive(Deserialize)]
struct JiraProject {
    #[expect(dead_code)]
    id: Option<String>,
    key: String,
    name: String,
    #[serde(rename = "projectTypeKey")]
    project_type_key: Option<String>,
}

#[derive(Deserialize)]
struct JiraCredentialFile {
    #[serde(alias = "api_token", alias = "apiToken")]
    token: String,
    #[serde(alias = "baseUrl", alias = "url", alias = "domain")]
    base_url: String,
    activity: Option<JiraActivityCredentials>,
}

#[derive(Deserialize)]
struct JiraActivityCredentials {
    account_id: String,
    token_id: String,
    audit_token: String,
}

#[derive(Deserialize)]
struct AtlassianTokenActivity {
    id: String,
    #[serde(rename = "lastAccess")]
    last_access: Option<DateTime<Utc>>,
}

// ─── Permission classification ──────────────────────────────────────────────

const ADMIN_PERMISSIONS: &[&str] = &["SYSTEM_ADMIN", "ADMINISTER_PROJECTS"];
const RISKY_PERMISSIONS: &[&str] =
    &["DELETE_ISSUES", "EDIT_ISSUES", "CREATE_ISSUES", "MANAGE_WATCHERS"];
const READ_PERMISSIONS: &[&str] = &["BROWSE_PROJECTS"];

const CHECKED_PERMISSIONS: &str = "BROWSE_PROJECTS,CREATE_ISSUES,EDIT_ISSUES,DELETE_ISSUES,MANAGE_WATCHERS,ADMINISTER_PROJECTS,SYSTEM_ADMIN";

// ─── Public entry points ────────────────────────────────────────────────────

/// Entry point when invoked via `kingfisher access-map jira <CREDENTIAL>`.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Jira access-map requires a credential file containing the token and base URL")
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Jira credential from {}", path.display()))?;

    let credential = parse_jira_credentials(&raw)?;
    let activity = match credential.activity.as_ref() {
        Some(config) => {
            lookup_atlassian_activity(config).await.map(|date| (config.account_id.as_str(), date))
        }
        None => None,
    };
    map_access_with_client(&jira_client()?, &credential.token, &credential.base_url, activity).await
}

/// Map access for a Jira token + base URL discovered during scanning.
pub async fn map_access_from_token_and_url(token: &str, base_url: &str) -> Result<AccessMapResult> {
    map_access_with_client(&jira_client()?, token, base_url, None).await
}

fn jira_client() -> Result<Client> {
    Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .context("Failed to build Jira HTTP client")
}

async fn map_access_with_client(
    client: &Client,
    token: &str,
    base_url: &str,
    activity: Option<(&str, DateTime<Utc>)>,
) -> Result<AccessMapResult> {
    let base_url = base_url.trim_end_matches('/');

    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // ── 1. Identity ─────────────────────────────────────────────────────────
    let user = fetch_myself(client, token, base_url).await?;
    let last_used_at = activity
        .filter(|(account_id, _)| Some(*account_id) == user.account_id.as_deref())
        .map(|(_, date)| date.to_rfc3339_opts(SecondsFormat::AutoSi, true));
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some("Atlassian Cloud managed-account token activity".into()),
        ..ProviderMetadata::default()
    });

    let identity_id = user
        .email_address
        .clone()
        .or_else(|| user.account_id.clone())
        .unwrap_or_else(|| "unknown_jira_user".to_string());

    if !user.active {
        risk_notes.push("Jira account is marked as inactive".to_string());
    }

    // ── 2. Permissions ──────────────────────────────────────────────────────
    let granted_perms = fetch_permissions(client, token, base_url).await.unwrap_or_else(|err| {
        warn!("Jira access-map: permission check failed: {err}");
        risk_notes.push(format!("Permission enumeration failed: {err}"));
        Vec::new()
    });

    for perm in &granted_perms {
        if ADMIN_PERMISSIONS.contains(&perm.as_str()) {
            permissions.admin.push(perm.clone());
        } else if RISKY_PERMISSIONS.contains(&perm.as_str()) {
            permissions.risky.push(perm.clone());
        } else if READ_PERMISSIONS.contains(&perm.as_str()) {
            permissions.read_only.push(perm.clone());
        }
    }

    // ── 3. Projects (resources) ─────────────────────────────────────────────
    let projects = fetch_projects(client, token, base_url).await.unwrap_or_else(|err| {
        warn!("Jira access-map: project enumeration failed: {err}");
        risk_notes.push(format!("Project enumeration failed: {err}"));
        Vec::new()
    });

    // ── Build roles ─────────────────────────────────────────────────────────
    let roles = vec![RoleBinding {
        name: format!("jira_user:{}", user.account_type.as_deref().unwrap_or("unknown")),
        source: "jira".into(),
        permissions: granted_perms.clone(),
    }];

    // ── Build resources ─────────────────────────────────────────────────────
    let mut resources: Vec<ResourceExposure> = Vec::new();
    for proj in &projects {
        let has_write = granted_perms.iter().any(|p| {
            ADMIN_PERMISSIONS.contains(&p.as_str()) || RISKY_PERMISSIONS.contains(&p.as_str())
        });
        let risk = if has_write { "medium" } else { "low" };
        resources.push(ResourceExposure {
            resource_type: "jira_project".into(),
            name: format!("{} ({})", proj.name, proj.key),
            permissions: granted_perms.clone(),
            risk: risk.into(),
            reason: format!(
                "Jira {} project accessible by this token",
                proj.project_type_key.as_deref().unwrap_or("unknown")
            ),
        });
    }

    // ── Severity ────────────────────────────────────────────────────────────
    let severity = derive_severity(&permissions);

    // ── Risk notes ──────────────────────────────────────────────────────────
    if permissions.admin.contains(&"SYSTEM_ADMIN".to_string()) {
        risk_notes
            .push("Token has SYSTEM_ADMIN privilege — full Jira administration access".into());
    }
    if permissions.admin.contains(&"ADMINISTER_PROJECTS".to_string()) {
        risk_notes.push("Token can administer projects — project configuration access".into());
    }

    Ok(AccessMapResult {
        cloud: "jira".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: user.account_type.unwrap_or_else(|| "token".into()),
            project: None,
            tenant: None,
            account_id: user.account_id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.display_name,
            username: None,
            account_type: Some("api_token".into()),
            company: None,
            location: None,
            email: user.email_address,
            url: Some(base_url.to_string()),
            token_type: Some("bearer".into()),
            created_at: None,
            last_used_at,
            expires_at: None,
            user_id: user.account_id,
            scopes: granted_perms,
        }),
        provider_metadata,
        fingerprint: None,
    })
}

// ─── API helpers ────────────────────────────────────────────────────────────

async fn lookup_atlassian_activity(config: &JiraActivityCredentials) -> Option<DateTime<Utc>> {
    let observer = jira_client().ok()?;
    let base = Url::parse("https://api.atlassian.com").expect("valid Atlassian Cloud API URL");
    fetch_last_use(&observer, base, config).await
}

async fn fetch_last_use(
    client: &Client,
    mut base: Url,
    activity: &JiraActivityCredentials,
) -> Option<DateTime<Utc>> {
    // Documentation: https://developer.atlassian.com/cloud/admin/user-management/rest/api-group-api-tokens/
    base.path_segments_mut().ok()?.extend(["users", &activity.account_id, "manage", "api-tokens"]);
    let response = client
        .get(base)
        .bearer_auth(&activity.audit_token)
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .inspect_err(
            |err| debug!(status = ?err.status(), "Atlassian Cloud token activity lookup failed"),
        )
        .ok()?;
    if !response.status().is_success() {
        debug!(status = %response.status(), "Atlassian Cloud token activity lookup failed");
        return None;
    }
    response
        .json::<Vec<AtlassianTokenActivity>>()
        .await
        .ok()?
        .into_iter()
        .find(|record| record.id == activity.token_id)?
        .last_access
}

async fn fetch_myself(client: &Client, token: &str, base_url: &str) -> Result<JiraUser> {
    let resp = client
        .get(format!("{base_url}/rest/api/3/myself"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Jira access-map: failed to query myself endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Jira access-map: myself endpoint returned HTTP {}", resp.status()));
    }

    resp.json::<JiraUser>().await.context("Jira access-map: invalid myself JSON response")
}

async fn fetch_permissions(client: &Client, token: &str, base_url: &str) -> Result<Vec<String>> {
    let url = format!("{base_url}/rest/api/3/mypermissions?permissions={CHECKED_PERMISSIONS}");
    let resp = client
        .get(&url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Jira access-map: failed to query mypermissions endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Jira access-map: mypermissions endpoint returned HTTP {}",
            resp.status()
        ));
    }

    let body: JiraPermissionsResponse =
        resp.json().await.context("Jira access-map: invalid mypermissions JSON response")?;

    let granted: Vec<String> = body
        .permissions
        .into_iter()
        .filter(|(_, entry)| entry.have_permission)
        .map(|(name, _)| name)
        .collect();

    Ok(granted)
}

async fn fetch_projects(client: &Client, token: &str, base_url: &str) -> Result<Vec<JiraProject>> {
    let resp = client
        .get(format!("{base_url}/rest/api/3/project?maxResults=50"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Jira access-map: failed to query project endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Jira access-map: project endpoint returned HTTP {}", resp.status()));
    }

    resp.json::<Vec<JiraProject>>().await.context("Jira access-map: invalid project JSON response")
}

// ─── Credential parsing ─────────────────────────────────────────────────────

fn parse_jira_credentials(raw: &str) -> Result<JiraCredentialFile> {
    if raw.trim_start().starts_with('{') {
        let mut credential: JiraCredentialFile = serde_json::from_str(raw)
            .map_err(|_| anyhow!("Invalid Jira credential JSON; expected token and base_url"))?;
        credential.token = credential.token.trim().to_owned();
        credential.base_url = credential.base_url.trim().to_owned();
        if let Some(activity) = &mut credential.activity {
            activity.account_id = activity.account_id.trim().to_owned();
            activity.token_id = activity.token_id.trim().to_owned();
            activity.audit_token = activity.audit_token.trim().to_owned();
            if activity.account_id.is_empty()
                || activity.account_id.len() > 128
                || !activity
                    .account_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_'))
                || activity.token_id.is_empty()
                || activity.token_id.len() > 128
                || activity.audit_token.is_empty()
                || activity.audit_token == credential.token
            {
                return Err(anyhow!(
                    "Jira activity requires account_id, token_id, and a separate audit_token"
                ));
            }
        }
        return Ok(credential);
    }

    // Fall back to line-based: first line = token, second line = base_url
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() >= 2 {
        return Ok(JiraCredentialFile {
            token: lines[0].into(),
            base_url: lines[1].into(),
            activity: None,
        });
    }

    Err(anyhow!(
        "Jira credential format not recognized. Provide JSON with token + base_url, or two lines (token, base_url)."
    ))
}

// ─── Severity derivation ────────────────────────────────────────────────────

fn derive_severity(permissions: &PermissionSummary) -> Severity {
    if permissions.admin.iter().any(|p| p == "SYSTEM_ADMIN") {
        Severity::Critical
    } else if permissions.admin.iter().any(|p| p == "ADMINISTER_PROJECTS") {
        Severity::High
    } else if !permissions.risky.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test]
    async fn atlassian_activity_matches_the_token_id_and_authenticated_account() {
        let server = MockServer::start().await;
        let credential = parse_jira_credentials(
            r#"{
            "token": "target", "base_url": "https://example.invalid",
            "activity": {"account_id": "account-1", "token_id": "target-id", "audit_token": "audit"}
        }"#,
        )
        .unwrap();
        let activity = credential.activity.unwrap();
        Mock::given(method("GET"))
            .and(path("/users/account-1/manage/api-tokens"))
            .and(header("authorization", "Bearer audit"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id":"other-id","lastAccess":"2026-01-03T01:02:03Z"},
                {"id":"target-id","lastAccess":"2026-01-02T01:02:03Z"}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        for (endpoint, body) in [
            ("/rest/api/3/myself", json!({"accountId": "account-1", "active": true})),
            ("/rest/api/3/mypermissions", json!({"permissions": {}})),
            ("/rest/api/3/project", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(header("authorization", "Bearer target"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(2)
                .mount(&server)
                .await;
        }
        let client = Client::new();
        let base = server.uri();
        let date = fetch_last_use(&client, base.parse().unwrap(), &activity).await.unwrap();
        for (account, expected) in
            [("account-1", Some("2026-01-02T01:02:03Z")), ("different-account", None)]
        {
            let mapped =
                map_access_with_client(&client, &credential.token, &base, Some((account, date)))
                    .await
                    .unwrap();
            assert_eq!(mapped.token_details.unwrap().last_used_at.as_deref(), expected);
        }
    }
}
