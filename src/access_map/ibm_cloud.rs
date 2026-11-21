use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
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
}

#[derive(Deserialize)]
struct IbmApiKeyActivityDetails {
    activity: Option<IbmApiKeyActivity>,
}

#[derive(Deserialize)]
struct IbmApiKeyActivity {
    last_authn: Option<String>,
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
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .context("Failed to build IBM Cloud HTTP client")?;
    let iam_api = Url::parse(IBM_IAM_API).expect("valid IBM IAM URL");
    let resource_api = Url::parse(IBM_RESOURCE_API).expect("valid IBM Resource Controller URL");
    map_access_with_client(&client, &iam_api, &resource_api, token).await
}

async fn map_access_with_client(
    client: &Client,
    iam_api: &Url,
    resource_api: &Url,
    token: &str,
) -> Result<AccessMapResult> {
    let iam_token = exchange_token(client, iam_api, token).await?;
    let access_token = iam_token
        .access_token
        .as_deref()
        .context("IBM Cloud access-map: IAM token exchange did not return an access token")?;
    let api_key_details = fetch_api_key_details(client, iam_api, token, access_token).await?;

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
    let detected_scopes: Vec<_> = iam_token
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();

    let last_used_at = match api_key_details.id.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => {
            fetch_api_key_last_used(client, iam_api, id, access_token).await.unwrap_or_else(|err| {
                debug!("IBM Cloud access-map: API key activity unavailable: {err}");
                None
            })
        }
        None => None,
    };
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some("IBM IAM API key activity".into()),
        ..ProviderMetadata::default()
    });
    let resource_instances =
        fetch_resource_instances(client, resource_api, access_token).await.unwrap_or_else(|err| {
            warn!("IBM Cloud access-map: resource enumeration failed: {err}");
            Vec::new()
        });

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
            last_used_at,
            expires_at: None,
            user_id: api_key_details.id,
            scopes: detected_scopes,
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn fetch_api_key_details(
    client: &Client,
    iam_api: &Url,
    api_key: &str,
    iam_token: &str,
) -> Result<IbmApiKeyDetails> {
    let mut api_key = header::HeaderValue::from_str(api_key)
        .context("IBM Cloud access-map: invalid API key header")?;
    api_key.set_sensitive(true);
    let resp = client
        .get(iam_api.join("/v1/apikeys/details")?)
        .bearer_auth(iam_token)
        .header("IAM-Apikey", api_key)
        .header(header::ACCEPT, "application/json")
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

// The by-value endpoint resolves the key ID. Only the by-ID endpoint accepts include_activity.
// https://cloud.ibm.com/docs/apis/iam-identity-token-api
async fn fetch_api_key_last_used(
    client: &Client,
    iam_api: &Url,
    api_key_id: &str,
    iam_token: &str,
) -> Result<Option<String>> {
    let mut url = iam_api.join("/v1/apikeys/")?;
    url.path_segments_mut()
        .map_err(|()| anyhow!("IBM Cloud access-map: invalid IAM base URL"))?
        .pop_if_empty()
        .push(api_key_id);
    let response = client
        .get(url)
        .query(&[("include_activity", "true")])
        .bearer_auth(iam_token)
        .header(header::ACCEPT, "application/json")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .context("IBM Cloud access-map: failed to fetch API key activity")?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "IBM Cloud access-map: API key activity lookup failed with HTTP {status}"
        ));
    }
    let details = response
        .json::<IbmApiKeyActivityDetails>()
        .await
        .context("IBM Cloud access-map: invalid API key activity JSON")?;

    Ok(details.activity.and_then(|activity| activity.last_authn).and_then(|timestamp| {
        DateTime::parse_from_rfc3339(&timestamp)
            .or_else(|_| DateTime::parse_from_str(&timestamp, "%Y-%m-%dT%H:%M:%S%.f%z"))
            .or_else(|_| DateTime::parse_from_str(&timestamp, "%Y-%m-%dT%H:%M%z"))
            .ok()
            .map(|date| date.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }))
}

async fn exchange_token(client: &Client, iam_api: &Url, api_key: &str) -> Result<IbmTokenResponse> {
    let resp = client
        .post(iam_api.join("/identity/token")?)
        .header(header::ACCEPT, "application/json")
        .form(&[("grant_type", "urn:ibm:params:oauth:grant-type:apikey"), ("apikey", api_key)])
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
    resource_api: &Url,
    iam_token: &str,
) -> Result<Vec<IbmResourceInstance>> {
    let resp = client
        .get(resource_api.join("/v2/resource_instances")?)
        .bearer_auth(iam_token)
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
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::*;

    #[tokio::test]
    async fn reports_only_authentication_activity_for_the_resolved_key() {
        for (activity_response, expected) in [
            (
                ResponseTemplate::new(200).set_body_json(json!({
                    "activity": { "last_authn": "2025-10-06T17:58+0000", "authn_count": 12 }
                })),
                Some("2025-10-06T17:58:00Z"),
            ),
            (ResponseTemplate::new(200).set_body_json(json!({ "activity": null })), None),
            (ResponseTemplate::new(403), None),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/identity/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token": "test-iam-token",
                    "scope": "openid"
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/apikeys/details"))
                .and(header("authorization", "Bearer test-iam-token"))
                .and(header("iam-apikey", "test-api-key"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "id": "test-key-id",
                    "iam_id": "test-principal-id",
                    "modified_at": "2025-10-02T11:00:00Z"
                })))
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1/apikeys/test-key-id"))
                .and(query_param("include_activity", "true"))
                .and(header("authorization", "Bearer test-iam-token"))
                .respond_with(activity_response)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v2/resource_instances"))
                .and(header("authorization", "Bearer test-iam-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "resources": [{"name": "test-resource"}]
                })))
                .expect(1)
                .mount(&server)
                .await;

            let url = Url::parse(&server.uri()).unwrap();
            let result =
                map_access_with_client(&Client::new(), &url, &url, "test-api-key").await.unwrap();
            assert_eq!(result.identity.id, "test-principal-id");
            assert_eq!(result.resources[1].name, "test-resource (global)");
            assert_eq!(result.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                result.provider_metadata.and_then(|metadata| metadata.credential_last_used_source),
                expected.map(|_| "IBM IAM API key activity".to_owned())
            );
            let requests = server.received_requests().await.unwrap();
            assert!(requests.iter().all(|request| request.url.path() == "/v1/apikeys/details"
                || !request.headers.contains_key("iam-apikey")));
        }
    }
}
