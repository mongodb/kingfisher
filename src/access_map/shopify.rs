use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const SHOPIFY_API_VERSION: &str = "2024-10";

#[derive(Deserialize)]
struct ShopResponse {
    shop: ShopInfo,
}

#[derive(Deserialize)]
struct ShopInfo {
    id: Option<u64>,
    name: Option<String>,
    email: Option<String>,
    domain: Option<String>,
    plan_name: Option<String>,
}

/// Entry point when invoked via the CLI `access-map shopify` subcommand.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Shopify access-map requires a credential file with token and subdomain")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Shopify credential file from {}", path.display())
    })?;
    let (token, subdomain) = parse_shopify_credentials(&raw)?;
    map_access_from_token_and_subdomain(&token, &subdomain).await
}

/// Maps a Shopify access token and store subdomain to an access profile.
pub async fn map_access_from_token_and_subdomain(
    token: &str,
    subdomain: &str,
) -> Result<AccessMapResult> {
    let subdomain = subdomain.trim().trim_matches('/').to_ascii_lowercase();
    if subdomain.is_empty() {
        return Err(anyhow!("Shopify access-map requires a non-empty store subdomain"));
    }

    let base_url = format!("https://{subdomain}.myshopify.com");
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Shopify HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Fetch shop info
    let shop = fetch_shop(&client, token, &base_url).await?;

    let shop_id = shop.id.map(|id| id.to_string()).unwrap_or_default();
    let shop_name = shop.name.clone().unwrap_or_default();
    let shop_email = shop.email.clone();
    let shop_domain = shop.domain.clone();
    let _plan_name = shop.plan_name.clone();

    // Probe endpoints to detect scopes
    let probes =
        [("orders", "read_orders"), ("customers", "read_customers"), ("products", "read_products")];

    for (resource, scope) in &probes {
        match probe_endpoint(&client, token, &base_url, resource).await {
            Ok(true) => {
                detected_scopes.push(scope.to_string());
            }
            Ok(false) => {}
            Err(err) => {
                warn!("Shopify access-map: probe for {resource} failed: {err}");
            }
        }
    }

    // Classify scopes
    let admin_scopes = ["write_customers", "write_orders", "write_products", "write_script_tags"];
    let risky_scopes = ["read_customers", "read_orders", "write_products"];
    let read_scopes = ["read_products", "read_inventory"];

    for scope in &detected_scopes {
        if admin_scopes.contains(&scope.as_str()) {
            permissions.admin.push(scope.clone());
        } else if risky_scopes.contains(&scope.as_str()) {
            permissions.risky.push(scope.clone());
        } else if read_scopes.contains(&scope.as_str()) {
            permissions.read_only.push(scope.clone());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    // Determine severity
    let has_customer_order_write =
        detected_scopes.iter().any(|s| s == "write_customers" || s == "write_orders");
    let has_customer_order_read =
        detected_scopes.iter().any(|s| s == "read_customers" || s == "read_orders");

    let severity = if has_customer_order_write {
        Severity::Critical
    } else if has_customer_order_read {
        Severity::High
    } else {
        Severity::Medium
    };

    if has_customer_order_write {
        risk_notes.push("Token has write access to customer or order data".to_string());
    }
    if has_customer_order_read {
        risk_notes.push("Token can read customer PII or financial order data".to_string());
    }

    let roles = vec![RoleBinding {
        name: "shopify_access_token".into(),
        source: "shopify".into(),
        permissions: detected_scopes.clone(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "shopify_store".into(),
        name: shop_name.clone(),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(severity).to_string(),
        reason: "Shopify store accessible with this token".to_string(),
    }];

    if detected_scopes.iter().any(|s| s == "read_customers") {
        resources.push(ResourceExposure {
            resource_type: "customer_data".into(),
            name: format!("{subdomain} customers"),
            permissions: vec!["read_customers".into()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "Customer PII is accessible".to_string(),
        });
    }
    if detected_scopes.iter().any(|s| s == "read_orders") {
        resources.push(ResourceExposure {
            resource_type: "order_data".into(),
            name: format!("{subdomain} orders"),
            permissions: vec!["read_orders".into()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "Financial order data is accessible".to_string(),
        });
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "shopify".into(),
        identity: AccessSummary {
            id: shop_email.clone().unwrap_or_else(|| shop_name.clone()),
            access_type: "token".into(),
            project: Some(subdomain.clone()),
            tenant: shop_domain,
            account_id: Some(shop_id.clone()),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: Some(shop_name),
            username: None,
            account_type: Some("shopify_access_token".into()),
            company: None,
            location: None,
            email: shop_email,
            url: Some(base_url),
            token_type: Some("access_token".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: Some(shop_id),
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

fn parse_shopify_credentials(raw: &str) -> Result<(String, String)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .or_else(|| json.get("shopify_token"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let subdomain = json
            .get("subdomain")
            .or_else(|| json.get("store"))
            .or_else(|| json.get("shop"))
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
        "Shopify credential format not recognized. Provide JSON with token + subdomain, or two lines (token, subdomain)."
    ))
}

async fn fetch_shop(client: &Client, token: &str, base_url: &str) -> Result<ShopInfo> {
    let resp = client
        .get(format!("{base_url}/admin/api/{SHOPIFY_API_VERSION}/shop.json"))
        .header("X-Shopify-Access-Token", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Shopify access-map: failed to query shop endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Shopify access-map: shop endpoint returned HTTP {}", resp.status()));
    }

    let shop_resp: ShopResponse =
        resp.json().await.context("Shopify access-map: invalid shop JSON")?;
    Ok(shop_resp.shop)
}

async fn probe_endpoint(
    client: &Client,
    token: &str,
    base_url: &str,
    resource: &str,
) -> Result<bool> {
    let resp = client
        .get(format!("{base_url}/admin/api/{SHOPIFY_API_VERSION}/{resource}.json?limit=1"))
        .header("X-Shopify-Access-Token", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Shopify access-map: probe request failed")?;

    Ok(resp.status().is_success())
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
