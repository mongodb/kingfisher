use anyhow::{Context, Result, anyhow};
use reqwest::{Client, StatusCode, header};
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
struct InstitutionsResponse {
    #[serde(default)]
    total: i64,
}

// ---------------------------------------------------------------------------
// Environment detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum PlaidEnvironment {
    Production,
    Development,
    Sandbox,
}

impl PlaidEnvironment {
    fn host(self) -> &'static str {
        match self {
            PlaidEnvironment::Production => "production.plaid.com",
            PlaidEnvironment::Development => "development.plaid.com",
            PlaidEnvironment::Sandbox => "sandbox.plaid.com",
        }
    }

    fn label(self) -> &'static str {
        match self {
            PlaidEnvironment::Production => "production",
            PlaidEnvironment::Development => "development",
            PlaidEnvironment::Sandbox => "sandbox",
        }
    }

    fn severity(self) -> Severity {
        match self {
            PlaidEnvironment::Production => Severity::Critical,
            PlaidEnvironment::Development => Severity::High,
            PlaidEnvironment::Sandbox => Severity::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Plaid access-map requires a credential file with client_id and secret")
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Plaid credential file from {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .context("Plaid credential file must be valid JSON with client_id and secret")?;

    let client_id = json
        .get("client_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Plaid credential JSON missing 'client_id'"))?;
    let secret = json
        .get("secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Plaid credential JSON missing 'secret'"))?;

    map_access_from_credentials(client_id, secret).await
}

pub async fn map_access_from_credentials(client_id: &str, secret: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Plaid HTTP client")?;

    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Detect environment by trying production -> development -> sandbox
    let (env, institutions_total) = detect_environment(&client, client_id, secret).await?;

    risk_notes.push(format!("Plaid environment: {}", env.label()));

    if let Some(total) = institutions_total {
        risk_notes.push(format!("Institutions available: {total}"));
    }

    // Classify permissions based on environment
    match env {
        PlaidEnvironment::Production => {
            permissions.admin.push("production:api_access".to_string());
            permissions.admin.push("production:real_financial_data".to_string());
        }
        PlaidEnvironment::Development => {
            permissions.risky.push("development:api_access".to_string());
            permissions.risky.push("development:test_financial_data".to_string());
        }
        PlaidEnvironment::Sandbox => {
            permissions.read_only.push("sandbox:api_access".to_string());
            permissions.read_only.push("sandbox:mock_data".to_string());
        }
    }

    // Try item/get (will likely fail without an access_token, but that's fine)
    match try_item_get(&client, client_id, secret, env).await {
        Ok(()) => {
            risk_notes.push("item/get endpoint is reachable".to_string());
        }
        Err(err) => {
            // Expected to fail without access_token - not an error
            warn!("Plaid access-map: item/get probe (expected to fail): {err}");
        }
    }

    let severity = env.severity();

    let roles = vec![RoleBinding {
        name: format!("plaid_api_key_{}", env.label()),
        source: "plaid".into(),
        permissions: permissions
            .admin
            .iter()
            .chain(permissions.risky.iter())
            .chain(permissions.read_only.iter())
            .cloned()
            .collect(),
    }];

    let resources = vec![ResourceExposure {
        resource_type: "plaid_account".into(),
        name: format!("{client_id}@{}", env.label()),
        permissions: vec![format!("{}:api_access", env.label())],
        risk: severity_to_str(severity).to_string(),
        reason: format!("Plaid {} API access with real financial data implications", env.label()),
    }];

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "plaid".into(),
        identity: AccessSummary {
            id: client_id.to_string(),
            access_type: "api_key".into(),
            project: Some(env.label().to_string()),
            tenant: None,
            account_id: Some(client_id.to_string()),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: Some(format!("plaid_{}", env.label())),
            token_type: Some("client_credentials".into()),
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async fn detect_environment(
    client: &Client,
    client_id: &str,
    secret: &str,
) -> Result<(PlaidEnvironment, Option<i64>)> {
    // Try production first
    if let Ok(resp) =
        try_institutions_get(client, client_id, secret, PlaidEnvironment::Production).await
    {
        return Ok((PlaidEnvironment::Production, Some(resp.total)));
    }

    // Try development
    if let Ok(resp) =
        try_institutions_get(client, client_id, secret, PlaidEnvironment::Development).await
    {
        return Ok((PlaidEnvironment::Development, Some(resp.total)));
    }

    // Try sandbox
    if let Ok(resp) =
        try_institutions_get(client, client_id, secret, PlaidEnvironment::Sandbox).await
    {
        return Ok((PlaidEnvironment::Sandbox, Some(resp.total)));
    }

    Err(anyhow!("Plaid access-map: credentials not valid for production, development, or sandbox"))
}

async fn try_institutions_get(
    client: &Client,
    client_id: &str,
    secret: &str,
    env: PlaidEnvironment,
) -> Result<InstitutionsResponse> {
    let body = serde_json::json!({
        "client_id": client_id,
        "secret": secret,
        "count": 1,
        "offset": 0,
        "country_codes": ["US"],
    });

    let resp = client
        .post(format!("https://{}/institutions/get", env.host()))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .with_context(|| {
            format!("Plaid access-map: failed to query institutions/get on {}", env.host())
        })?;

    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "Plaid access-map: institutions/get returned HTTP {} on {}",
            resp.status(),
            env.host()
        ));
    }

    resp.json::<InstitutionsResponse>()
        .await
        .context("Plaid access-map: invalid institutions/get JSON")
}

async fn try_item_get(
    client: &Client,
    client_id: &str,
    secret: &str,
    env: PlaidEnvironment,
) -> Result<()> {
    let body = serde_json::json!({
        "client_id": client_id,
        "secret": secret,
        "access_token": "",
    });

    let resp = client
        .post(format!("https://{}/item/get", env.host()))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .context("Plaid access-map: failed to query item/get")?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(anyhow!("Plaid access-map: item/get returned HTTP {}", resp.status()))
    }
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
