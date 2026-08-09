use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const STRIPE_API: &str = "https://api.stripe.com";

#[derive(Deserialize)]
struct StripeBusinessProfile {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct StripeAccount {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    business_profile: Option<StripeBusinessProfile>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    charges_enabled: Option<bool>,
    #[serde(default)]
    payouts_enabled: Option<bool>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Stripe token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Stripe access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Stripe HTTP client")?;

    let key_type = classify_key_prefix(token);

    let account = fetch_account(&client, token).await?;

    let account_id = account.id.clone().unwrap_or_else(|| "unknown".to_string());
    let business_name = account.business_profile.as_ref().and_then(|bp| bp.name.clone());
    let display_name = business_name
        .clone()
        .or_else(|| account.email.clone())
        .unwrap_or_else(|| account_id.clone());

    let identity = AccessSummary {
        id: display_name.clone(),
        access_type: key_type.label.to_string(),
        project: None,
        tenant: account.country.clone(),
        account_id: account.id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Full secret keys have unrestricted access.
    if key_type.is_full_secret {
        permissions.admin.push("full_api_access".to_string());
        detected_scopes.push("full_api_access".to_string());
        roles.push(RoleBinding {
            name: format!("key_type:{}", key_type.label),
            source: "stripe".into(),
            permissions: vec!["full_api_access".to_string()],
        });

        if key_type.is_live {
            risk_notes.push("Live secret key grants unrestricted access to all Stripe API resources including charges, refunds, and customer PII".into());
        }
    } else if key_type.is_restricted {
        // Probe individual capabilities for restricted keys.
        let probes: &[(&str, &str)] = &[
            ("/v1/balance", "balance:read"),
            ("/v1/charges?limit=1", "charges:read"),
            ("/v1/customers?limit=1", "customers:read"),
            ("/v1/payment_intents?limit=1", "payment_intents:read"),
            ("/v1/subscriptions?limit=1", "subscriptions:read"),
            ("/v1/products?limit=1", "products:read"),
        ];

        for (endpoint, scope_name) in probes {
            match probe_endpoint(&client, token, endpoint).await {
                Ok(true) => {
                    detected_scopes.push(scope_name.to_string());
                    let risk = classify_scope(scope_name);
                    match risk {
                        ScopeRisk::Admin => permissions.admin.push(scope_name.to_string()),
                        ScopeRisk::Risky => permissions.risky.push(scope_name.to_string()),
                        ScopeRisk::Read => permissions.read_only.push(scope_name.to_string()),
                    }
                }
                Ok(false) => {}
                Err(err) => {
                    warn!("Stripe access-map: probe for {scope_name} failed: {err}");
                }
            }
        }

        roles.push(RoleBinding {
            name: format!("key_type:{}", key_type.label),
            source: "stripe".into(),
            permissions: detected_scopes.clone(),
        });

        if key_type.is_live && !detected_scopes.is_empty() {
            risk_notes.push(format!(
                "Restricted live key with {} accessible scope(s)",
                detected_scopes.len()
            ));
        }
    } else if key_type.is_publishable {
        permissions.read_only.push("publishable_key".to_string());
        detected_scopes.push("publishable_key".to_string());
        roles.push(RoleBinding {
            name: format!("key_type:{}", key_type.label),
            source: "stripe".into(),
            permissions: vec!["publishable_key".to_string()],
        });
        risk_notes
            .push("Publishable key — intended for client-side use, limited capabilities".into());
    }

    // Account-level resource.
    resources.push(ResourceExposure {
        resource_type: "account".into(),
        name: account_id.clone(),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(if key_type.is_full_secret && key_type.is_live {
            Severity::Critical
        } else if key_type.is_live {
            Severity::High
        } else {
            Severity::Low
        })
        .to_string(),
        reason: format!("Stripe account accessible via {} key", key_type.label),
    });

    if account.charges_enabled == Some(true) {
        resources.push(ResourceExposure {
            resource_type: "capability".into(),
            name: "charges_enabled".into(),
            permissions: vec!["charges".to_string()],
            risk: severity_to_str(if key_type.is_live { Severity::High } else { Severity::Low })
                .to_string(),
            reason: "Account can process charges".into(),
        });
    }

    if account.payouts_enabled == Some(true) {
        resources.push(ResourceExposure {
            resource_type: "capability".into(),
            name: "payouts_enabled".into(),
            permissions: vec!["payouts".to_string()],
            risk: severity_to_str(if key_type.is_live { Severity::High } else { Severity::Low })
                .to_string(),
            reason: "Account can process payouts".into(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&key_type, &detected_scopes);

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "stripe".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: business_name,
            username: account.email.clone(),
            account_type: Some(key_type.label.to_string()),
            company: None,
            location: account.country,
            email: account.email,
            url: None,
            token_type: Some(key_type.label.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: account.id,
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_account(client: &Client, token: &str) -> Result<StripeAccount> {
    let resp = client
        .get(format!("{STRIPE_API}/v1/account"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Stripe access-map: failed to fetch account info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Stripe access-map: account lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Stripe access-map: invalid account JSON")
}

async fn probe_endpoint(client: &Client, token: &str, endpoint: &str) -> Result<bool> {
    let resp = client
        .get(format!("{STRIPE_API}{endpoint}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Stripe access-map: probe request failed")?;

    Ok(resp.status().is_success())
}

struct KeyType {
    label: &'static str,
    is_live: bool,
    is_full_secret: bool,
    is_restricted: bool,
    is_publishable: bool,
}

fn classify_key_prefix(token: &str) -> KeyType {
    if token.starts_with("sk_live_") {
        KeyType {
            label: "live_secret_key",
            is_live: true,
            is_full_secret: true,
            is_restricted: false,
            is_publishable: false,
        }
    } else if token.starts_with("sk_test_") {
        KeyType {
            label: "test_secret_key",
            is_live: false,
            is_full_secret: true,
            is_restricted: false,
            is_publishable: false,
        }
    } else if token.starts_with("rk_live_") {
        KeyType {
            label: "live_restricted_key",
            is_live: true,
            is_full_secret: false,
            is_restricted: true,
            is_publishable: false,
        }
    } else if token.starts_with("rk_test_") {
        KeyType {
            label: "test_restricted_key",
            is_live: false,
            is_full_secret: false,
            is_restricted: true,
            is_publishable: false,
        }
    } else if token.starts_with("pk_live_") {
        KeyType {
            label: "live_publishable_key",
            is_live: true,
            is_full_secret: false,
            is_restricted: false,
            is_publishable: true,
        }
    } else {
        KeyType {
            label: "unknown_key",
            is_live: false,
            is_full_secret: false,
            is_restricted: false,
            is_publishable: false,
        }
    }
}

enum ScopeRisk {
    #[expect(dead_code)]
    Admin,
    Risky,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "charges:read" | "payment_intents:read" | "customers:read" => ScopeRisk::Risky,
        "balance:read" | "products:read" | "subscriptions:read" => ScopeRisk::Read,
        _ => ScopeRisk::Read,
    }
}

fn derive_severity(key_type: &KeyType, scopes: &[String]) -> Severity {
    if key_type.is_full_secret && key_type.is_live {
        return Severity::Critical;
    }

    if key_type.is_restricted && key_type.is_live {
        let has_risky = scopes.iter().any(|s| {
            matches!(s.as_str(), "charges:read" | "payment_intents:read" | "customers:read")
        });
        if has_risky {
            return Severity::High;
        }
        return Severity::Medium;
    }

    // Test keys and publishable keys are low severity.
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
