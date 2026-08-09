use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const HUBSPOT_API: &str = "https://api.hubapi.com";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HubSpotAccountInfo {
    #[serde(default)]
    portal_id: Option<u64>,
    #[serde(default)]
    account_type: Option<String>,
    #[serde(default)]
    time_zone: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    company_currency: Option<String>,
    #[serde(default)]
    ui_domain: Option<String>,
}

#[derive(Deserialize)]
struct HubSpotOwner {
    #[serde(default)]
    #[expect(dead_code)]
    id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(rename = "firstName", default)]
    first_name: Option<String>,
    #[serde(rename = "lastName", default)]
    last_name: Option<String>,
}

#[derive(Deserialize)]
struct HubSpotOwnersResponse {
    #[serde(default)]
    results: Vec<HubSpotOwner>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read HubSpot token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("HubSpot access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build HubSpot HTTP client")?;

    let account_info = fetch_account_info(&client, token).await?;

    let portal_id_str = account_info
        .portal_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown_portal".to_string());

    let identity = AccessSummary {
        id: portal_id_str.clone(),
        access_type: account_info.account_type.clone().unwrap_or_else(|| "api_key".into()),
        project: None,
        tenant: account_info.ui_domain.clone(),
        account_id: Some(portal_id_str.clone()),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Probe CRM resources to determine accessible scopes
    let contacts_accessible = probe_crm_object(&client, token, "contacts").await;
    let deals_accessible = probe_crm_object(&client, token, "deals").await;
    let companies_accessible = probe_crm_object(&client, token, "companies").await;

    if contacts_accessible {
        detected_scopes.push("crm.objects.contacts.read".into());
        detected_scopes.push("crm.objects.contacts.write".into());
    }
    if deals_accessible {
        detected_scopes.push("crm.objects.deals.read".into());
        detected_scopes.push("crm.objects.deals.write".into());
    }
    if companies_accessible {
        detected_scopes.push("crm.objects.companies.read".into());
        detected_scopes.push("crm.objects.companies.write".into());
    }

    // Fetch owners to check account management access
    let owners = fetch_owners(&client, token).await.unwrap_or_else(|err| {
        warn!("HubSpot access-map: owners lookup failed: {err}");
        Vec::new()
    });

    if !owners.is_empty() {
        detected_scopes.push("crm.objects.owners.read".into());
        risk_notes.push(format!("Token can enumerate {} CRM owners", owners.len()));
    }

    // Check if account info was accessible (indicates account management access)
    if account_info.portal_id.is_some() {
        detected_scopes.push("account-info.security.read".into());
    }

    for scope in &detected_scopes {
        let role = RoleBinding {
            name: format!("scope:{scope}"),
            source: "hubspot".into(),
            permissions: vec![scope.clone()],
        };
        roles.push(role);

        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    // Add resource exposures
    resources.push(ResourceExposure {
        resource_type: "account".into(),
        name: portal_id_str.clone(),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(if has_write_scope(&detected_scopes) {
            Severity::High
        } else {
            Severity::Medium
        })
        .to_string(),
        reason: "HubSpot portal accessible with this token".to_string(),
    });

    if contacts_accessible {
        resources.push(ResourceExposure {
            resource_type: "crm_object".into(),
            name: "contacts".into(),
            permissions: vec![
                "crm.objects.contacts.read".into(),
                "crm.objects.contacts.write".into(),
            ],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "CRM contacts accessible - contains customer PII".to_string(),
        });
    }

    if deals_accessible {
        resources.push(ResourceExposure {
            resource_type: "crm_object".into(),
            name: "deals".into(),
            permissions: vec!["crm.objects.deals.read".into(), "crm.objects.deals.write".into()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "CRM deals accessible - contains business-sensitive data".to_string(),
        });
    }

    if companies_accessible {
        resources.push(ResourceExposure {
            resource_type: "crm_object".into(),
            name: "companies".into(),
            permissions: vec![
                "crm.objects.companies.read".into(),
                "crm.objects.companies.write".into(),
            ],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "CRM companies accessible".to_string(),
        });
    }

    for owner in &owners {
        let owner_name = owner
            .first_name
            .as_deref()
            .map(|f| {
                let last = owner.last_name.as_deref().unwrap_or("");
                format!("{f} {last}").trim().to_string()
            })
            .or_else(|| owner.email.clone())
            .unwrap_or_else(|| "unknown_owner".to_string());

        resources.push(ResourceExposure {
            resource_type: "owner".into(),
            name: owner_name,
            permissions: vec!["crm.objects.owners.read".into()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "CRM owner enumerable with this token".to_string(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&detected_scopes, contacts_accessible || deals_accessible);

    if detected_scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: portal_id_str.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "HubSpot account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any CRM resources or scopes".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "hubspot".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: None,
            username: None,
            account_type: account_info.account_type,
            company: None,
            location: account_info.time_zone,
            email: None,
            url: account_info.ui_domain.map(|d| format!("https://{d}")),
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: account_info.portal_id.map(|id| id.to_string()),
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_account_info(client: &Client, token: &str) -> Result<HubSpotAccountInfo> {
    let resp = client
        .get(format!("{HUBSPOT_API}/account-info/v3/details"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("HubSpot access-map: failed to fetch account info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "HubSpot access-map: account info lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("HubSpot access-map: invalid account info JSON")
}

async fn fetch_owners(client: &Client, token: &str) -> Result<Vec<HubSpotOwner>> {
    let resp = client
        .get(format!("{HUBSPOT_API}/crm/v3/owners/"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("HubSpot access-map: failed to fetch owners")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "HubSpot access-map: owners lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let body: HubSpotOwnersResponse =
        resp.json().await.context("HubSpot access-map: invalid owners JSON")?;
    Ok(body.results)
}

async fn probe_crm_object(client: &Client, token: &str, object_type: &str) -> bool {
    let resp = client
        .get(format!("{HUBSPOT_API}/crm/v3/objects/{object_type}?limit=1"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await;

    match resp {
        Ok(r) => r.status().is_success(),
        Err(err) => {
            warn!("HubSpot access-map: {object_type} probe failed: {err}");
            false
        }
    }
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "account-info.security.read" => ScopeRisk::Admin,
        s if s.contains(".write") => ScopeRisk::Write,
        _ => ScopeRisk::Read,
    }
}

fn has_write_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s.contains(".write"))
}

fn derive_severity(scopes: &[String], has_crm_write: bool) -> Severity {
    if has_crm_write && has_write_scope(scopes) {
        return Severity::High;
    }

    let has_read = scopes.iter().any(|s| s.contains(".read"));
    if has_read {
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
