use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const FASTLY_API: &str = "https://api.fastly.com";

#[derive(Deserialize)]
struct FastlyUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    customer_id: Option<String>,
}

#[derive(Deserialize)]
struct FastlyService {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type", default)]
    service_type: Option<String>,
    #[expect(dead_code)]
    #[serde(default)]
    customer_id: Option<String>,
}

#[derive(Deserialize)]
struct FastlyCustomer {
    #[expect(dead_code)]
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Fastly token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Fastly access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Fastly HTTP client")?;

    let user = fetch_current_user(&client, token).await?;

    let username = user
        .login
        .clone()
        .or_else(|| user.name.clone())
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "fastly_user".to_string());

    let role = user.role.clone().unwrap_or_else(|| "unknown".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "user".into(),
        project: None,
        tenant: user.customer_id.clone(),
        account_id: user.id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // Classify role
    let role_binding = RoleBinding {
        name: format!("role:{role}"),
        source: "fastly".into(),
        permissions: role_permissions(&role),
    };
    roles.push(role_binding);

    match classify_role(&role) {
        RoleRisk::Superuser => {
            permissions.admin.push(format!("role:{role}"));
            risk_notes.push("Superuser role grants full platform access".into());
        }
        RoleRisk::Engineer => {
            permissions.risky.push(format!("role:{role}"));
        }
        RoleRisk::Billing => {
            permissions.risky.push(format!("role:{role}"));
            risk_notes.push("Billing role grants access to financial data".into());
        }
        RoleRisk::ReadOnly => {
            permissions.read_only.push(format!("role:{role}"));
        }
    }

    // If superuser, try to fetch customer details
    if role == "superuser"
        && let Some(customer_id) = &user.customer_id
    {
        let customer = fetch_customer(&client, token, customer_id).await.unwrap_or_else(|err| {
            warn!("Fastly access-map: customer lookup failed: {err}");
            None
        });

        if let Some(cust) = customer {
            let cust_name = cust.name.unwrap_or_else(|| customer_id.clone());
            resources.push(ResourceExposure {
                resource_type: "customer".into(),
                name: cust_name,
                permissions: vec!["customer:admin".to_string()],
                risk: severity_to_str(Severity::Critical).to_string(),
                reason: "Full customer account access via superuser role".to_string(),
            });
        }
    }

    // Enumerate services
    let services = list_services(&client, token).await.unwrap_or_else(|err| {
        warn!("Fastly access-map: service enumeration failed: {err}");
        Vec::new()
    });

    for service in &services {
        let service_name = service
            .name
            .clone()
            .or_else(|| service.id.clone())
            .unwrap_or_else(|| "unknown_service".to_string());

        let svc_type = service.service_type.as_deref().unwrap_or("unknown");

        let risk = match classify_role(&role) {
            RoleRisk::Superuser => Severity::Critical,
            RoleRisk::Engineer => Severity::High,
            RoleRisk::Billing => Severity::Medium,
            RoleRisk::ReadOnly => Severity::Low,
        };

        resources.push(ResourceExposure {
            resource_type: "service".into(),
            name: service_name.clone(),
            permissions: vec![format!("service:{svc_type}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("Fastly service ({svc_type}) accessible with {role} role"),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&role);

    if services.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Fastly account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any services".into());
    }

    Ok(AccessMapResult {
        cloud: "fastly".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.name.clone(),
            username: user.login.clone(),
            account_type: Some(role.clone()),
            company: None,
            location: None,
            email: user.email.clone(),
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: user.id,
            scopes: vec![role],
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_current_user(client: &Client, token: &str) -> Result<FastlyUser> {
    let resp = client
        .get(format!("{FASTLY_API}/current_user"))
        .header("Fastly-Key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Fastly access-map: failed to fetch current user")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Fastly access-map: current_user lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Fastly access-map: invalid current_user JSON")
}

async fn list_services(client: &Client, token: &str) -> Result<Vec<FastlyService>> {
    let resp = client
        .get(format!("{FASTLY_API}/service"))
        .header("Fastly-Key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Fastly access-map: failed to list services")?;

    if !resp.status().is_success() {
        warn!("Fastly access-map: service enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Fastly access-map: invalid services JSON")
}

async fn fetch_customer(
    client: &Client,
    token: &str,
    customer_id: &str,
) -> Result<Option<FastlyCustomer>> {
    let resp = client
        .get(format!("{FASTLY_API}/customer/{customer_id}"))
        .header("Fastly-Key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Fastly access-map: failed to fetch customer")?;

    if !resp.status().is_success() {
        warn!("Fastly access-map: customer lookup failed with HTTP {}", resp.status());
        return Ok(None);
    }

    let customer: FastlyCustomer =
        resp.json().await.context("Fastly access-map: invalid customer JSON")?;
    Ok(Some(customer))
}

enum RoleRisk {
    Superuser,
    Engineer,
    Billing,
    ReadOnly,
}

fn classify_role(role: &str) -> RoleRisk {
    match role {
        "superuser" => RoleRisk::Superuser,
        "engineer" => RoleRisk::Engineer,
        "billing" => RoleRisk::Billing,
        _ => RoleRisk::ReadOnly,
    }
}

fn role_permissions(role: &str) -> Vec<String> {
    match role {
        "superuser" => vec![
            "service:create".to_string(),
            "service:delete".to_string(),
            "service:configure".to_string(),
            "service:purge".to_string(),
            "customer:admin".to_string(),
            "user:manage".to_string(),
        ],
        "engineer" => vec![
            "service:configure".to_string(),
            "service:purge".to_string(),
            "service:deploy".to_string(),
        ],
        "billing" => vec!["billing:read".to_string(), "billing:write".to_string()],
        _ => vec!["service:read".to_string()],
    }
}

fn derive_severity(role: &str) -> Severity {
    match classify_role(role) {
        RoleRisk::Superuser => Severity::Critical,
        RoleRisk::Engineer => Severity::High,
        RoleRisk::Billing => Severity::Medium,
        RoleRisk::ReadOnly => Severity::Low,
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
