use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const IBM_IAM_API: &str = "https://iam.cloud.ibm.com";
const IBM_RESOURCE_API: &str = "https://resource-controller.cloud.ibm.com";

#[derive(Deserialize)]
struct IbmApiKeyDetails {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    entity_tag: Option<String>,
    #[serde(default)]
    iam_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    description: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    modified_at: Option<String>,
}

#[derive(Deserialize)]
struct IbmTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    token_type: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Deserialize)]
struct IbmResourceInstance {
    #[serde(default)]
    #[expect(dead_code)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    resource_plan_id: Option<String>,
    #[serde(default)]
    region_id: Option<String>,
}

#[derive(Deserialize)]
struct IbmResourceListResponse {
    #[serde(default)]
    resources: Vec<IbmResourceInstance>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read IBM Cloud API key from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("IBM Cloud access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build IBM Cloud HTTP client")?;

    let api_key_details = fetch_api_key_details(&client, token).await?;

    let key_name = api_key_details.name.clone().unwrap_or_else(|| "ibm_cloud_apikey".to_string());

    let account_id = api_key_details.account_id.clone();

    let identity = AccessSummary {
        id: api_key_details.iam_id.clone().unwrap_or_else(|| key_name.clone()),
        access_type: "apikey".into(),
        project: None,
        tenant: None,
        account_id: account_id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Exchange API key for IAM token
    let iam_token = exchange_token(&client, token).await;

    let resource_instances = match &iam_token {
        Ok(token_resp) => {
            if let Some(ref access_token) = token_resp.access_token {
                if let Some(ref scope) = token_resp.scope {
                    for s in scope.split_whitespace() {
                        detected_scopes.push(s.to_string());
                    }
                }
                fetch_resource_instances(&client, access_token).await.unwrap_or_else(|err| {
                    warn!("IBM Cloud access-map: resource enumeration failed: {err}");
                    Vec::new()
                })
            } else {
                warn!("IBM Cloud access-map: token exchange returned no access_token");
                Vec::new()
            }
        }
        Err(err) => {
            warn!("IBM Cloud access-map: token exchange failed: {err}");
            risk_notes.push("IAM token exchange failed; resource enumeration skipped".into());
            Vec::new()
        }
    };

    // Add IAM-level role
    roles.push(RoleBinding {
        name: "apikey".into(),
        source: "ibm_cloud".into(),
        permissions: detected_scopes.clone(),
    });

    for scope in &detected_scopes {
        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    // Add account-level resource
    resources.push(ResourceExposure {
        resource_type: "account".into(),
        name: account_id.clone().unwrap_or_else(|| "unknown_account".to_string()),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(if resource_instances.len() > 10 {
            Severity::Critical
        } else if !resource_instances.is_empty() {
            Severity::High
        } else {
            Severity::Medium
        })
        .to_string(),
        reason: "IBM Cloud account accessible with this API key".to_string(),
    });

    for instance in &resource_instances {
        let instance_name = instance.name.clone().unwrap_or_else(|| "unknown_resource".to_string());

        let region = instance.region_id.clone().unwrap_or_else(|| "global".to_string());
        let plan = instance.resource_plan_id.clone().unwrap_or_else(|| "unknown_plan".to_string());

        resources.push(ResourceExposure {
            resource_type: "resource_instance".into(),
            name: format!("{instance_name} ({region})"),
            permissions: vec![format!("plan:{plan}")],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Resource instance accessible via IAM token".to_string(),
        });
    }

    if !resource_instances.is_empty() {
        risk_notes
            .push(format!("Token can enumerate {} resource instances", resource_instances.len()));
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&resource_instances);

    if resource_instances.is_empty() && detected_scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: key_name.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "IBM Cloud API key with no enumerable resources".into(),
        });
        risk_notes.push("API key did not enumerate any resource instances".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "ibm_cloud".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: api_key_details.name,
            username: api_key_details.iam_id,
            account_type: None,
            company: None,
            location: None,
            email: None,
            url: None,
            token_type: Some("apikey".into()),
            created_at: api_key_details.created_at,
            last_used_at: api_key_details.modified_at,
            expires_at: None,
            user_id: api_key_details.id,
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_api_key_details(client: &Client, api_key: &str) -> Result<IbmApiKeyDetails> {
    let resp = client
        .post(format!("{IBM_IAM_API}/v1/apikeys/details"))
        .header("IAM-Apikey", api_key)
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_LENGTH, "0")
        .send()
        .await
        .context("IBM Cloud access-map: failed to fetch API key details")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "IBM Cloud access-map: API key details lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("IBM Cloud access-map: invalid API key details JSON")
}

async fn exchange_token(client: &Client, api_key: &str) -> Result<IbmTokenResponse> {
    let resp = client
        .post(format!("{IBM_IAM_API}/identity/token"))
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey={api_key}"))
        .send()
        .await
        .context("IBM Cloud access-map: failed to exchange token")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "IBM Cloud access-map: token exchange failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("IBM Cloud access-map: invalid token exchange JSON")
}

async fn fetch_resource_instances(
    client: &Client,
    iam_token: &str,
) -> Result<Vec<IbmResourceInstance>> {
    let resp = client
        .get(format!("{IBM_RESOURCE_API}/v2/resource_instances"))
        .header(header::AUTHORIZATION, format!("Bearer {iam_token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("IBM Cloud access-map: failed to list resource instances")?;

    if !resp.status().is_success() {
        warn!(
            "IBM Cloud access-map: resource instance enumeration failed with HTTP {}",
            resp.status()
        );
        return Ok(Vec::new());
    }

    let body: IbmResourceListResponse =
        resp.json().await.context("IBM Cloud access-map: invalid resource instances JSON")?;
    Ok(body.resources)
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "ibm" => ScopeRisk::Admin,
        "openid" => ScopeRisk::Read,
        _ => ScopeRisk::Write,
    }
}

fn derive_severity(resource_instances: &[IbmResourceInstance]) -> Severity {
    if resource_instances.len() > 10 {
        return Severity::Critical;
    }

    if !resource_instances.is_empty() {
        return Severity::High;
    }

    Severity::Medium
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
