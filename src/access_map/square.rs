use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const SQUARE_API: &str = "https://connect.squareup.com";
const SQUARE_VERSION: &str = "2024-01-18";

#[derive(Deserialize)]
struct SquareMerchantResponse {
    #[serde(default)]
    merchant: Vec<SquareMerchant>,
}

#[derive(Deserialize)]
struct SquareMerchant {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    business_name: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[expect(dead_code)]
    #[serde(default)]
    currency: Option<String>,
    #[expect(dead_code)]
    #[serde(default)]
    status: Option<String>,
}

#[derive(Deserialize)]
struct SquareLocationsResponse {
    #[serde(default)]
    locations: Vec<SquareLocation>,
}

#[derive(Deserialize)]
struct SquareLocation {
    #[expect(dead_code)]
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default, rename = "type")]
    location_type: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Square token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Square access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Square HTTP client")?;

    let key_type = classify_key_type(token);

    let merchant_resp = fetch_merchant(&client, token).await?;
    let merchant = merchant_resp.merchant.first();

    let merchant_id = merchant.and_then(|m| m.id.clone()).unwrap_or_else(|| "unknown".to_string());
    let business_name = merchant.and_then(|m| m.business_name.clone());
    let display_name = business_name.clone().unwrap_or_else(|| merchant_id.clone());

    let identity = AccessSummary {
        id: display_name.clone(),
        access_type: key_type.label.to_string(),
        project: None,
        tenant: merchant.and_then(|m| m.country.clone()),
        account_id: merchant.and_then(|m| m.id.clone()),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Merchant-level resource.
    permissions.admin.push("merchant:read".to_string());
    detected_scopes.push("merchant:read".to_string());

    // Enumerate locations.
    let locations = list_locations(&client, token).await.unwrap_or_else(|err| {
        warn!("Square access-map: locations enumeration failed: {err}");
        Vec::new()
    });

    if !locations.is_empty() {
        permissions.read_only.push("locations:read".to_string());
        detected_scopes.push("locations:read".to_string());
    }

    for loc in &locations {
        let loc_name = loc.name.clone().unwrap_or_else(|| "unknown_location".to_string());
        let loc_type = loc.location_type.clone().unwrap_or_default();
        let loc_status = loc.status.clone().unwrap_or_default();
        let has_cc = loc.capabilities.iter().any(|c| c == "CREDIT_CARD_PROCESSING");

        resources.push(ResourceExposure {
            resource_type: "location".into(),
            name: loc_name,
            permissions: loc.capabilities.clone(),
            risk: severity_to_str(if has_cc { Severity::Medium } else { Severity::Low })
                .to_string(),
            reason: format!(
                "Square location ({}, {}){}",
                loc_type,
                loc_status,
                if has_cc { " with credit card processing" } else { "" }
            ),
        });
    }

    // Probe additional capabilities.
    let probes: &[(&str, &str, ScopeRisk)] = &[
        ("/v2/customers?limit=1", "customers:read", ScopeRisk::Risky),
        ("/v2/payments?limit=1", "payments:read", ScopeRisk::Risky),
        ("/v2/catalog/list?limit=1", "catalog:read", ScopeRisk::Read),
    ];

    for (endpoint, scope_name, risk) in probes {
        match probe_endpoint(&client, token, endpoint).await {
            Ok(true) => {
                detected_scopes.push(scope_name.to_string());
                match risk {
                    ScopeRisk::Admin => permissions.admin.push(scope_name.to_string()),
                    ScopeRisk::Risky => permissions.risky.push(scope_name.to_string()),
                    ScopeRisk::Read => permissions.read_only.push(scope_name.to_string()),
                }
            }
            Ok(false) => {}
            Err(err) => {
                warn!("Square access-map: probe for {scope_name} failed: {err}");
            }
        }
    }

    roles.push(RoleBinding {
        name: format!("key_type:{}", key_type.label),
        source: "square".into(),
        permissions: detected_scopes.clone(),
    });

    // Account resource.
    let has_payments = detected_scopes.iter().any(|s| s == "payments:read");
    let has_customers = detected_scopes.iter().any(|s| s == "customers:read");

    resources.push(ResourceExposure {
        resource_type: "merchant".into(),
        name: merchant_id.clone(),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(if has_payments || has_customers {
            Severity::High
        } else {
            Severity::Medium
        })
        .to_string(),
        reason: format!("Square merchant accessible via {} token", key_type.label),
    });

    if has_payments {
        risk_notes.push("Token can access payment data (financial transactions)".into());
    }
    if has_customers {
        risk_notes.push("Token can access customer data (PII)".into());
    }
    if key_type.is_oauth {
        risk_notes.push("OAuth token — may have broad scopes granted during authorization".into());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(has_payments, has_customers, &detected_scopes);

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "square".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: business_name,
            username: None,
            account_type: Some(key_type.label.to_string()),
            company: merchant.and_then(|m| m.business_name.clone()),
            location: merchant.and_then(|m| m.country.clone()),
            email: None,
            url: None,
            token_type: Some(key_type.label.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: merchant.and_then(|m| m.id.clone()),
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_merchant(client: &Client, token: &str) -> Result<SquareMerchantResponse> {
    let resp = client
        .get(format!("{SQUARE_API}/v2/merchants/me"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("Square-Version", SQUARE_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Square access-map: failed to fetch merchant info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Square access-map: merchant lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Square access-map: invalid merchant JSON")
}

async fn list_locations(client: &Client, token: &str) -> Result<Vec<SquareLocation>> {
    let resp = client
        .get(format!("{SQUARE_API}/v2/locations"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("Square-Version", SQUARE_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Square access-map: failed to list locations")?;

    if !resp.status().is_success() {
        warn!("Square access-map: locations enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: SquareLocationsResponse =
        resp.json().await.context("Square access-map: invalid locations JSON")?;
    Ok(body.locations)
}

async fn probe_endpoint(client: &Client, token: &str, endpoint: &str) -> Result<bool> {
    let resp = client
        .get(format!("{SQUARE_API}{endpoint}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("Square-Version", SQUARE_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Square access-map: probe request failed")?;

    Ok(resp.status().is_success())
}

struct KeyClassification {
    label: &'static str,
    is_oauth: bool,
}

fn classify_key_type(token: &str) -> KeyClassification {
    if token.starts_with("EAAA") {
        KeyClassification { label: "oauth_token", is_oauth: true }
    } else if token.starts_with("sq0atp-") {
        KeyClassification { label: "personal_access_token", is_oauth: false }
    } else {
        KeyClassification { label: "unknown_token", is_oauth: false }
    }
}

enum ScopeRisk {
    #[expect(dead_code)]
    Admin,
    Risky,
    Read,
}

fn derive_severity(has_payments: bool, has_customers: bool, scopes: &[String]) -> Severity {
    if has_payments || has_customers {
        return Severity::High;
    }

    let has_catalog = scopes.iter().any(|s| s == "catalog:read");
    let has_locations = scopes.iter().any(|s| s == "locations:read");

    if has_catalog || has_locations {
        return Severity::Medium;
    }

    Severity::Low
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
