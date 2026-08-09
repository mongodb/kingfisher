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

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
struct Auth0Client {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    app_type: String,
}

#[derive(Debug, Deserialize)]
struct Auth0ResourceServer {
    #[serde(default)]
    identifier: String,
    #[serde(default)]
    name: String,
}

// ---------------------------------------------------------------------------
// Scope classification
// ---------------------------------------------------------------------------

fn classify_scope(scope: &str) -> ScopeCategory {
    if scope.starts_with("create:") || scope.starts_with("delete:") {
        return ScopeCategory::Admin;
    }
    if scope == "update:users" || scope == "update:clients" {
        return ScopeCategory::Admin;
    }
    if scope.starts_with("read:users")
        || scope.starts_with("read:clients")
        || scope.starts_with("update:")
    {
        return ScopeCategory::Risky;
    }
    if scope.starts_with("read:stats") || scope.starts_with("read:logs") {
        return ScopeCategory::Read;
    }
    // Default: treat unknown read: as read, unknown others as risky
    if scope.starts_with("read:") { ScopeCategory::Read } else { ScopeCategory::Risky }
}

enum ScopeCategory {
    Admin,
    Risky,
    Read,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!(
            "Auth0 access-map requires a credential file with client_id, client_secret, and domain"
        )
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Auth0 credential file from {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw).context(
        "Auth0 credential file must be valid JSON with client_id, client_secret, and domain",
    )?;

    let client_id = json
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Auth0 credential JSON missing 'client_id'"))?;
    let client_secret = json
        .get("client_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Auth0 credential JSON missing 'client_secret'"))?;
    let domain = json
        .get("domain")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Auth0 credential JSON missing 'domain'"))?;

    map_access_from_credentials(client_id, client_secret, domain).await
}

pub async fn map_access_from_credentials(
    client_id: &str,
    client_secret: &str,
    domain: &str,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Auth0 HTTP client")?;

    let domain = normalize_domain(domain);
    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Step 1: exchange credentials for management API token
    let token_resp = fetch_token(&client, client_id, client_secret, &domain).await?;
    let scopes: Vec<String> =
        token_resp.scope.split_whitespace().map(String::from).filter(|s| !s.is_empty()).collect();

    // Classify scopes
    for scope in &scopes {
        match classify_scope(scope) {
            ScopeCategory::Admin => permissions.admin.push(scope.clone()),
            ScopeCategory::Risky => permissions.risky.push(scope.clone()),
            ScopeCategory::Read => permissions.read_only.push(scope.clone()),
        }
    }

    // Step 2: list clients
    let clients =
        fetch_clients(&client, &token_resp.access_token, &domain).await.unwrap_or_else(|err| {
            warn!("Auth0 access-map: client listing failed: {err}");
            risk_notes.push(format!("Client listing failed: {err}"));
            Vec::new()
        });

    // Step 3: list resource servers
    let resource_servers = fetch_resource_servers(&client, &token_resp.access_token, &domain)
        .await
        .unwrap_or_else(|err| {
            warn!("Auth0 access-map: resource server listing failed: {err}");
            risk_notes.push(format!("Resource server listing failed: {err}"));
            Vec::new()
        });

    // Determine severity
    let has_admin = !permissions.admin.is_empty();
    let has_risky = !permissions.risky.is_empty();
    let severity = if has_admin {
        Severity::Critical
    } else if has_risky {
        Severity::High
    } else {
        Severity::Medium
    };

    if !clients.is_empty() {
        risk_notes.push(format!("Management API can enumerate {} client(s)", clients.len()));
    }

    let roles = vec![RoleBinding {
        name: "auth0_client_credentials".into(),
        source: "auth0".into(),
        permissions: scopes.clone(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "auth0_tenant".into(),
        name: domain.clone(),
        permissions: scopes.clone(),
        risk: severity_to_str(severity).to_string(),
        reason: "Auth0 tenant reachable with these client credentials".to_string(),
    }];

    for c in &clients {
        resources.push(ResourceExposure {
            resource_type: "auth0_client".into(),
            name: if c.name.is_empty() { c.client_id.clone() } else { c.name.clone() },
            permissions: vec![format!("app_type:{}", c.app_type)],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Auth0 client application visible to management API".to_string(),
        });
    }

    for rs in &resource_servers {
        resources.push(ResourceExposure {
            resource_type: "auth0_resource_server".into(),
            name: if rs.name.is_empty() { rs.identifier.clone() } else { rs.name.clone() },
            permissions: vec!["resource_server:visible".into()],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Auth0 resource server (API) visible to management API".to_string(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "auth0".into(),
        identity: AccessSummary {
            id: format!("{client_id}@{domain}"),
            access_type: "client_credentials".into(),
            project: None,
            tenant: Some(domain.clone()),
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: Some(client_id.to_string()),
            token_type: Some(token_resp.token_type),
            scopes,
            expires_at: if token_resp.expires_in > 0 {
                Some(format!("{}s from issuance", token_resp.expires_in))
            } else {
                None
            },
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

fn normalize_domain(domain: &str) -> String {
    let mut d = domain.trim().trim_matches('/').to_string();
    if d.starts_with("https://") {
        d = d.trim_start_matches("https://").to_string();
    } else if d.starts_with("http://") {
        d = d.trim_start_matches("http://").to_string();
    }
    d = d.split('/').next().unwrap_or_default().to_string();
    d
}

async fn fetch_token(
    client: &Client,
    client_id: &str,
    client_secret: &str,
    domain: &str,
) -> Result<TokenResponse> {
    let body = serde_json::json!({
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": format!("https://{domain}/api/v2/"),
        "grant_type": "client_credentials",
    });

    let resp = client
        .post(format!("https://{domain}/oauth/token"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .context("Auth0 access-map: failed to exchange client credentials")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Auth0 access-map: token exchange failed with HTTP {}", resp.status()));
    }

    resp.json::<TokenResponse>().await.context("Auth0 access-map: invalid token response JSON")
}

async fn fetch_clients(
    client: &Client,
    access_token: &str,
    domain: &str,
) -> Result<Vec<Auth0Client>> {
    let resp = client
        .get(format!("https://{domain}/api/v2/clients"))
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Auth0 access-map: failed to list clients")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Auth0 access-map: client listing returned HTTP {}", resp.status()));
    }

    resp.json::<Vec<Auth0Client>>().await.context("Auth0 access-map: invalid client list JSON")
}

async fn fetch_resource_servers(
    client: &Client,
    access_token: &str,
    domain: &str,
) -> Result<Vec<Auth0ResourceServer>> {
    let resp = client
        .get(format!("https://{domain}/api/v2/resource-servers"))
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Auth0 access-map: failed to list resource servers")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Auth0 access-map: resource server listing returned HTTP {}",
            resp.status()
        ));
    }

    resp.json::<Vec<Auth0ResourceServer>>()
        .await
        .context("Auth0 access-map: invalid resource server list JSON")
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
