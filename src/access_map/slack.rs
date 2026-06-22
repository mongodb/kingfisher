use anyhow::{Result, anyhow};
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use super::{
    AccessMapArgs, AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary,
    ProviderMetadata, ResourceExposure, RoleBinding, Severity, build_recommendations,
};

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    // For CLI usage, we might expect a token via env var or file, strictly speaking
    // the CLI usually takes a file path for credentials.
    // For Slack, it's just a token string.
    // We'll assume the file contains the token, or if it's not a file, maybe it's the token itself?
    // But consistency with other providers suggests reading from file.
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("Slack access-map requires a file path containing the token"))?;
    let token = std::fs::read_to_string(path)?.trim().to_string();
    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = reqwest::Client::new();
    let resp = client
        .post("https://slack.com/api/auth.test")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await?;

    let headers = resp.headers().clone();
    let scopes_header =
        headers.get("x-oauth-scopes").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();

    let body = resp.bytes().await?;
    let json: AuthTestResponse = serde_json::from_slice(&body)?;

    if !json.ok {
        return Err(anyhow!("Slack auth.test failed: {}", json.error.unwrap_or_default()));
    }

    let user_id = json.user_id.unwrap_or_default();
    let team_id = json.team_id.unwrap_or_default();
    let team = json.team.unwrap_or_default();
    let user = json.user.unwrap_or_default();
    let url = json.url.unwrap_or_default();

    let scopes: Vec<String> =
        scopes_header.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    let identity = AccessSummary {
        id: format!("{}@{}", user, team),
        access_type: "user".into(), // Could be bot, but auth.test doesn't strictly say. xoxb is bot.
        project: Some(team.clone()),
        tenant: Some(team_id.clone()),
        account_id: Some(user_id.clone()),
    };

    let mut roles = Vec::new();
    // Treat scopes as permissions in a "Scopes" role
    let mut expanded_permissions = Vec::new();

    if !scopes.is_empty() {
        roles.push(RoleBinding {
            name: "OAuth Scopes".into(),
            source: "token".into(),
            permissions: scopes.clone(),
        });
        expanded_permissions.extend(scopes.clone());
    }

    let permissions = classify_permissions(&scopes);
    let severity = derive_severity(&permissions);

    let resources = vec![ResourceExposure {
        resource_type: "workspace".into(),
        name: team,
        permissions: scopes.clone(),
        risk: "medium".into(),
        reason: "Token has access to this workspace".into(),
    }];

    let recommendations = build_recommendations(severity);

    let token_details = AccessTokenDetails {
        name: Some(user.clone()),
        username: Some(user),
        user_id: Some(user_id),
        url: Some(url),
        scopes,
        ..Default::default()
    };

    Ok(AccessMapResult {
        cloud: "slack".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations,
        risk_notes: Vec::new(),
        token_details: Some(token_details),
        provider_metadata: Some(ProviderMetadata { version: None, enterprise: None }),
        fingerprint: None,
    })
}

#[derive(Deserialize)]
struct AuthTestResponse {
    ok: bool,
    error: Option<String>,
    url: Option<String>,
    team: Option<String>,
    user: Option<String>,
    team_id: Option<String>,
    user_id: Option<String>,
}

fn classify_permissions(scopes: &[String]) -> PermissionSummary {
    let mut admin = Vec::new();
    let privilege_escalation = Vec::new();
    let mut risky = Vec::new();
    let mut read_only = Vec::new();

    for scope in scopes {
        if scope.starts_with("admin") {
            admin.push(scope.clone());
        } else if scope.contains("write") || scope.contains("manage") || scope.contains("remove") {
            risky.push(scope.clone());
        } else {
            read_only.push(scope.clone());
        }
    }

    PermissionSummary { admin, privilege_escalation, risky, read_only }
}

fn derive_severity(permissions: &PermissionSummary) -> Severity {
    if !permissions.admin.is_empty() {
        Severity::Critical
    } else if !permissions.risky.is_empty() {
        Severity::High
    } else {
        Severity::Medium
    }
}
