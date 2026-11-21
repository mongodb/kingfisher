use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const FASTLY_API: &str = "https://api.fastly.com";
const KEY_USAGE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_USAGE_SOURCE: &str = "Fastly current user token";

#[derive(Deserialize)]
struct FastlyTokenUsage {
    last_used_at: Option<String>,
}

/// A completed validation lookup can return either a date or no history.
#[derive(Clone, Debug)]
pub(crate) struct FastlyValidationActivity {
    pub last_used_at: Option<String>,
}

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
    map_access_from_token_with_activity(token, None).await
}

pub(crate) async fn map_access_from_token_with_activity(
    token: &str,
    activity: Option<FastlyValidationActivity>,
) -> Result<AccessMapResult> {
    map_access_from_token_at(token, FASTLY_API, activity).await
}

async fn map_access_from_token_at(
    token: &str,
    api_base: &str,
    activity: Option<FastlyValidationActivity>,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Fastly HTTP client")?;

    // Keep the first validation response even if Fastly supplied no timestamp.
    let timestamp = match activity {
        Some(activity) => activity.last_used_at,
        None => fetch_token_last_used(&client, token, api_base).await,
    };
    let last_used_at = timestamp
        .as_deref()
        .and_then(|date| DateTime::parse_from_rfc3339(date).ok())
        .map(|date| date.to_utc().to_rfc3339_opts(SecondsFormat::AutoSi, true));
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some(KEY_USAGE_SOURCE.into()),
        ..ProviderMetadata::default()
    });
    let user = fetch_current_user(&client, token, api_base).await?;

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
        let customer =
            fetch_customer(&client, token, api_base, customer_id).await.unwrap_or_else(|err| {
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
    let services = list_services(&client, token, api_base).await.unwrap_or_else(|err| {
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
            last_used_at,
            expires_at: None,
            user_id: user.id,
            scopes: vec![role],
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn fetch_token_last_used(client: &Client, token: &str, api_base: &str) -> Option<String> {
    let response = client
        .get(format!("{api_base}/tokens/self"))
        .header("Fastly-Key", token)
        .header(header::ACCEPT, "application/json")
        .timeout(KEY_USAGE_LOOKUP_TIMEOUT)
        .send()
        .await;
    let response = match response {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            debug!(status = %response.status(), "Fastly access-map: current token usage unavailable");
            return None;
        }
        Err(_) => {
            debug!("Fastly access-map: current token usage request failed");
            return None;
        }
    };
    let usage: FastlyTokenUsage = response
        .json()
        .await
        .inspect_err(|_| debug!("Fastly access-map: invalid current token usage response"))
        .ok()?;
    usage.last_used_at
}

async fn fetch_current_user(client: &Client, token: &str, api_base: &str) -> Result<FastlyUser> {
    let resp = client
        .get(format!("{api_base}/current_user"))
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

async fn list_services(client: &Client, token: &str, api_base: &str) -> Result<Vec<FastlyService>> {
    let resp = client
        .get(format!("{api_base}/service"))
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
    api_base: &str,
    customer_id: &str,
) -> Result<Option<FastlyCustomer>> {
    let resp = client
        .get(format!("{api_base}/customer/{customer_id}"))
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
        matchers::{header, method, path},
    };

    use super::*;

    #[tokio::test]
    async fn previously_checked_usage_skips_the_mapper_lookup() {
        for (timestamp, expected) in [
            (Some("2025-01-02T03:04:05.123+01:00"), Some("2025-01-02T02:04:05.123Z")),
            (Some("invalid"), None),
            (None, None),
        ] {
            let server = MockServer::start().await;
            Mock::given(path("/tokens/self"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(path("/current_user"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"login":"user"})))
                .mount(&server)
                .await;
            Mock::given(path("/service"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&server)
                .await;
            let result = map_access_from_token_at(
                "test-fastly-token",
                &server.uri(),
                Some(FastlyValidationActivity { last_used_at: timestamp.map(str::to_owned) }),
            )
            .await
            .unwrap();
            assert_eq!(result.token_details.unwrap().last_used_at.as_deref(), expected);
        }
    }

    #[tokio::test]
    async fn current_token_usage_is_looked_up_first_and_is_optional() {
        const TOKEN: &str = "test-fastly-token";
        let other = MockServer::start().await;
        Mock::given(path("/redirected"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&other)
            .await;
        for (response, expected) in [
            (
                ResponseTemplate::new(200)
                    .set_body_json(json!({"last_used_at": "2025-01-02T03:04:05+01:00"})),
                Some("2025-01-02T02:04:05Z"),
            ),
            (ResponseTemplate::new(200).set_body_json(json!({"last_used_at": null})), None),
            (ResponseTemplate::new(403), None),
            (
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/redirected", other.uri())),
                None,
            ),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/tokens/self"))
                .and(header("Fastly-Key", TOKEN))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(path("/current_user"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"login":"user"})))
                .mount(&server)
                .await;
            Mock::given(path("/service"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&server)
                .await;

            let mapped = map_access_from_token_at(TOKEN, &server.uri(), None).await.unwrap();
            assert_eq!(mapped.identity.id, "user");
            assert_eq!(mapped.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                mapped.provider_metadata.and_then(|metadata| metadata.credential_last_used_source),
                expected.map(|_| KEY_USAGE_SOURCE.to_owned()),
            );
            assert_eq!(server.received_requests().await.unwrap()[0].url.path(), "/tokens/self");
        }
    }
}
