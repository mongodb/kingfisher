use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::cli::commands::access_map::AccessMapArgs;
use crate::validation::GLOBAL_USER_AGENT;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
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

    let (token, base_url) = parse_jira_credentials(&raw)?;
    map_access_from_token_and_url(&token, &base_url).await
}

/// Map access for a Jira token + base URL discovered during scanning.
pub async fn map_access_from_token_and_url(token: &str, base_url: &str) -> Result<AccessMapResult> {
    let base_url = base_url.trim_end_matches('/');

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Jira HTTP client")?;

    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // ── 1. Identity ─────────────────────────────────────────────────────────
    let user = fetch_myself(&client, token, base_url).await?;

    let identity_id = user
        .email_address
        .clone()
        .or_else(|| user.account_id.clone())
        .unwrap_or_else(|| "unknown_jira_user".to_string());

    if !user.active {
        risk_notes.push("Jira account is marked as inactive".to_string());
    }

    // ── 2. Permissions ──────────────────────────────────────────────────────
    let granted_perms = fetch_permissions(&client, token, base_url).await.unwrap_or_else(|err| {
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
    let projects = fetch_projects(&client, token, base_url).await.unwrap_or_else(|err| {
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
        mapping_error: None,
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
            last_used_at: None,
            expires_at: None,
            user_id: user.account_id,
            scopes: granted_perms,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ─── API helpers ────────────────────────────────────────────────────────────

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

fn parse_jira_credentials(raw: &str) -> Result<(String, String)> {
    // Try JSON first
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(raw) {
        let token = json
            .get("token")
            .or_else(|| json.get("api_token"))
            .or_else(|| json.get("apiToken"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let base_url = json
            .get("base_url")
            .or_else(|| json.get("baseUrl"))
            .or_else(|| json.get("url"))
            .or_else(|| json.get("domain"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        if let (Some(token), Some(base_url)) = (token, base_url) {
            return Ok((token, base_url));
        }
    }

    // Fall back to line-based: first line = token, second line = base_url
    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() >= 2 {
        return Ok((lines[0].to_string(), lines[1].to_string()));
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
