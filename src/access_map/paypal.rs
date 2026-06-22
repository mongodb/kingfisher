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
    app_id: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    expires_in: i64,
    #[expect(dead_code)]
    #[serde(default)]
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct UserInfo {
    #[serde(default)]
    user_id: String,
    #[serde(default)]
    name: String,
    #[serde(default, rename = "payer_id")]
    payer_id: String,
}

// ---------------------------------------------------------------------------
// Scope classification
// ---------------------------------------------------------------------------

fn classify_scope(scope: &str) -> ScopeCategory {
    if scope == "openid" || scope.contains("/services/identity/management") {
        return ScopeCategory::Admin;
    }
    if scope.contains("/services/payments/") || scope.contains("/services/disputes/") {
        return ScopeCategory::Risky;
    }
    if scope.contains("/services/reporting/") {
        return ScopeCategory::Read;
    }
    // Default: treat unknown URI scopes as risky
    ScopeCategory::Risky
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
        anyhow!("PayPal access-map requires a credential file with client_id and client_secret")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read PayPal credential file from {}", path.display())
    })?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .context("PayPal credential file must be valid JSON with client_id and client_secret")?;

    let client_id = json
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("PayPal credential JSON missing 'client_id'"))?;
    let client_secret = json
        .get("client_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("PayPal credential JSON missing 'client_secret'"))?;

    map_access_from_credentials(client_id, client_secret).await
}

pub async fn map_access_from_credentials(
    client_id: &str,
    client_secret: &str,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build PayPal HTTP client")?;

    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Try live first, then sandbox
    let (token_resp, is_sandbox) =
        match fetch_token(&client, client_id, client_secret, "api-m.paypal.com").await {
            Ok(resp) => (resp, false),
            Err(_live_err) => {
                let sandbox_resp =
                    fetch_token(&client, client_id, client_secret, "api-m.sandbox.paypal.com")
                        .await
                        .context(
                            "PayPal access-map: token exchange failed for both live and sandbox",
                        )?;
                risk_notes.push("Credentials are for the PayPal sandbox environment".to_string());
                (sandbox_resp, true)
            }
        };

    let base_host = if is_sandbox { "api-m.sandbox.paypal.com" } else { "api-m.paypal.com" };

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

    // Fetch user info
    let user_info =
        fetch_user_info(&client, &token_resp.access_token, base_host).await.unwrap_or_else(|err| {
            warn!("PayPal access-map: user info lookup failed: {err}");
            risk_notes.push(format!("User info lookup failed: {err}"));
            UserInfo { user_id: String::new(), name: String::new(), payer_id: String::new() }
        });

    // Determine severity
    let has_payment_scopes = scopes.iter().any(|s| s.contains("/services/payments/"));
    let severity = if is_sandbox {
        Severity::Medium
    } else if has_payment_scopes {
        Severity::Critical
    } else {
        Severity::High // live read-only is still High
    };

    let environment = if is_sandbox { "sandbox" } else { "live" };
    risk_notes.push(format!("PayPal environment: {environment}"));

    if !token_resp.app_id.is_empty() {
        risk_notes.push(format!("PayPal app_id: {}", token_resp.app_id));
    }

    let identity_id = if !user_info.payer_id.is_empty() {
        user_info.payer_id.clone()
    } else if !token_resp.app_id.is_empty() {
        token_resp.app_id.clone()
    } else {
        client_id.to_string()
    };

    let roles = vec![RoleBinding {
        name: format!("paypal_client_credentials_{environment}"),
        source: "paypal".into(),
        permissions: scopes.clone(),
    }];

    let resources = vec![ResourceExposure {
        resource_type: "paypal_account".into(),
        name: identity_id.clone(),
        permissions: scopes.clone(),
        risk: severity_to_str(severity).to_string(),
        reason: format!("PayPal {environment} account reachable with these credentials"),
    }];

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    Ok(AccessMapResult {
        cloud: "paypal".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: "client_credentials".into(),
            project: if token_resp.app_id.is_empty() { None } else { Some(token_resp.app_id) },
            tenant: None,
            account_id: if user_info.payer_id.is_empty() { None } else { Some(user_info.payer_id) },
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: if user_info.name.is_empty() { None } else { Some(user_info.name) },
            token_type: Some(token_resp.token_type),
            scopes,
            expires_at: if token_resp.expires_in > 0 {
                Some(format!("{}s from issuance", token_resp.expires_in))
            } else {
                None
            },
            user_id: if user_info.user_id.is_empty() { None } else { Some(user_info.user_id) },
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async fn fetch_token(
    client: &Client,
    client_id: &str,
    client_secret: &str,
    host: &str,
) -> Result<TokenResponse> {
    let resp = client
        .post(format!("https://{host}/v1/oauth2/token"))
        .basic_auth(client_id, Some(client_secret))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body("grant_type=client_credentials")
        .send()
        .await
        .with_context(|| {
            format!("PayPal access-map: failed to exchange credentials with {host}")
        })?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "PayPal access-map: token exchange failed with HTTP {} on {host}",
            resp.status()
        ));
    }

    resp.json::<TokenResponse>().await.context("PayPal access-map: invalid token response JSON")
}

async fn fetch_user_info(client: &Client, access_token: &str, host: &str) -> Result<UserInfo> {
    let resp = client
        .get(format!("https://{host}/v1/identity/oauth2/userinfo?schema=paypalv1.1"))
        .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("PayPal access-map: failed to fetch user info")?;

    if !resp.status().is_success() {
        return Err(anyhow!("PayPal access-map: user info returned HTTP {}", resp.status()));
    }

    resp.json::<UserInfo>().await.context("PayPal access-map: invalid user info JSON")
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
