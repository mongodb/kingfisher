use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_MODEL_RESOURCES: usize = 50;

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicModelsResponse {
    #[serde(default)]
    data: Vec<AnthropicModel>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicModel {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicApiKey {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicApiKeysResponse {
    #[serde(default)]
    data: Vec<AnthropicApiKey>,
}

#[derive(Debug, Default, Clone)]
struct KeyIntrospection {
    permissions: Vec<String>,
    id: Option<String>,
    name: Option<String>,
    created_at: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Anthropic token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Anthropic access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, ANTHROPIC_API).await
}

async fn map_access_from_token_at(token: &str, api_base: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Anthropic HTTP client")?;

    map_access_with_client(&client, token, api_base).await
}

async fn map_access_with_client(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<AccessMapResult> {
    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let key_info = fetch_key_permissions(client, token, api_base).await.unwrap_or_else(|err| {
        warn!("Anthropic access-map: key permission lookup failed: {err}");
        risk_notes.push(format!("Current key identity and permissions are unknown: {err}"));
        KeyIntrospection::default()
    });
    let visible_api_keys = list_api_keys(client, token, api_base).await.unwrap_or_else(|err| {
        warn!("Anthropic access-map: API key inventory lookup failed: {err}");
        Vec::new()
    });
    let mut token_scopes = key_info.permissions.clone();

    let models = match list_models(client, token, api_base).await {
        Ok(models) => {
            permissions.read_only.push("models:list".to_string());
            models
        }
        Err(err) => {
            warn!("Anthropic access-map: model enumeration failed: {err}");
            risk_notes.push(format!("Model-list capability is unknown: {err}"));
            Vec::new()
        }
    };

    let token_kind = detect_token_type(token);
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "anthropic".into(),
        permissions: vec![format!("token:{token_kind}")],
    });

    token_scopes.sort();
    token_scopes.dedup();
    for scope in &token_scopes {
        roles.push(RoleBinding {
            name: format!("permission:{scope}"),
            source: "anthropic".into(),
            permissions: vec![format!("key:{scope}")],
        });
        match scope.as_str() {
            "full_access" => permissions.admin.push("key:full_access".to_string()),
            _ => permissions.risky.push(format!("key:{scope}")),
        }
    }
    for model in models.iter().take(MAX_MODEL_RESOURCES) {
        let model_name = model
            .id
            .clone()
            .or_else(|| model.display_name.clone())
            .unwrap_or_else(|| "unknown_model".to_string());
        resources.push(ResourceExposure {
            resource_type: "model".into(),
            name: model_name,
            permissions: vec!["model:read".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Model accessible to this Anthropic key".to_string(),
        });
    }

    let can_administer_keys = token_scopes.iter().any(|scope| scope == "full_access");
    for api_key in &visible_api_keys {
        let key_name = api_key
            .name
            .clone()
            .or_else(|| api_key.id.clone())
            .unwrap_or_else(|| "unknown_api_key".to_string());
        let mut key_permissions = vec!["api_key:read".to_string()];
        if can_administer_keys {
            key_permissions.push("api_key:manage".to_string());
        }

        resources.push(ResourceExposure {
            resource_type: "api_key".into(),
            name: key_name,
            permissions: key_permissions,
            risk: if can_administer_keys { "high".into() } else { "medium".into() },
            reason: if can_administer_keys {
                "Organization API key visible to a full-access Anthropic key".to_string()
            } else {
                "Organization API key visible to this Anthropic key".to_string()
            },
        });
    }

    if models.len() > MAX_MODEL_RESOURCES {
        risk_notes.push(format!(
            "Model resource list truncated to first {MAX_MODEL_RESOURCES} entries ({} total models visible)",
            models.len()
        ));
    }
    if !visible_api_keys.is_empty() {
        permissions.read_only.push("api_keys:list".to_string());
        if can_administer_keys {
            risk_notes.push("Key can enumerate organization API keys".to_string());
        }
    }

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: "anthropic_api_key".into(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Anthropic account associated with this API key".to_string(),
        });
        risk_notes.push("No models were enumerable for this key".to_string());
    }

    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&permissions);

    Ok(AccessMapResult {
        cloud: "anthropic".into(),
        identity: AccessSummary {
            id: "anthropic_api_key".into(),
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: key_info.name,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: None,
            url: Some("https://console.anthropic.com/settings/keys".into()),
            token_type: Some(token_kind.to_string()),
            created_at: key_info.created_at,
            last_used_at: None,
            expires_at: None,
            user_id: key_info.id,
            scopes: token_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_models(client: &Client, token: &str, api_base: &str) -> Result<Vec<AnthropicModel>> {
    let resp = client
        .get(format!("{api_base}/models"))
        .header("x-api-key", token)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Anthropic access-map: failed to list models")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Anthropic access-map: model listing failed with HTTP {}",
            resp.status()
        ));
    }

    let body: AnthropicModelsResponse =
        resp.json().await.context("Anthropic access-map: invalid model list JSON")?;
    Ok(body.data)
}

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("sk-ant-admin") {
        "admin_api_key"
    } else if token.starts_with("sk-ant-api") {
        "api_key"
    } else {
        "unknown_api_key"
    }
}

async fn fetch_key_permissions(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<KeyIntrospection> {
    if let Ok(Some(key)) = fetch_permissions_from_endpoint(
        client,
        token,
        &format!("{api_base}/organizations/api_keys/me"),
    )
    .await
    {
        return Ok(KeyIntrospection {
            permissions: key.permissions,
            id: key.id,
            name: key.name,
            created_at: key.created_at,
        });
    }

    if let Ok(Some(key)) =
        fetch_permissions_from_endpoint(client, token, &format!("{api_base}/api_keys/me")).await
    {
        return Ok(KeyIntrospection {
            permissions: key.permissions,
            id: key.id,
            name: key.name,
            created_at: key.created_at,
        });
    }

    // Organization inventory is not caller introspection: even one visible key can
    // belong to another user or service account. Keep it as inventory only.
    Err(anyhow!(
        "no current-key endpoint returned permission metadata; organization key inventory does not identify the supplied credential"
    ))
}

async fn list_api_keys(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<AnthropicApiKey>> {
    let resp = client
        .get(format!("{api_base}/organizations/api_keys"))
        .header("x-api-key", token)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Anthropic access-map: failed to list organization API keys")?;

    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let body: AnthropicApiKeysResponse = resp
        .json()
        .await
        .context("Anthropic access-map: invalid organization API key list JSON")?;
    Ok(body.data)
}

async fn fetch_permissions_from_endpoint(
    client: &Client,
    token: &str,
    url: &str,
) -> Result<Option<AnthropicApiKey>> {
    let resp = client
        .get(url)
        .header("x-api-key", token)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("Anthropic access-map: failed to query {url}"))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body: AnthropicApiKey = resp
        .json()
        .await
        .with_context(|| format!("Anthropic access-map: invalid API key JSON from {url}"))?;

    if body.permissions.is_empty() { Ok(None) } else { Ok(Some(body)) }
}

fn derive_severity(permissions: &PermissionSummary) -> Severity {
    if !permissions.admin.is_empty() {
        return Severity::High;
    }
    if !permissions.risky.is_empty() {
        return Severity::Medium;
    }
    Severity::Low
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
    #[tokio::test]
    async fn token_header_is_never_forwarded_to_a_redirect() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method},
        };
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("x-api-key", "test-token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", destination.uri().replace("127.0.0.1", "localhost")),
            )
            .mount(&server)
            .await;
        // Anthropic retains a partial result when optional inventory calls fail.
        super::map_access_from_token_at("test-token", &server.uri()).await.unwrap();
        assert!(!server.received_requests().await.unwrap().is_empty());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    use super::*;

    async fn mount_get(server: &MockServer, endpoint: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(header("x-api-key", "test-key"))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }

    async fn inventory_server(models: ResponseTemplate, keys: serde_json::Value) -> MockServer {
        let server = MockServer::start().await;
        for endpoint in ["/organizations/api_keys/me", "/api_keys/me"] {
            mount_get(&server, endpoint, ResponseTemplate::new(404)).await;
        }
        mount_get(
            &server,
            "/organizations/api_keys",
            ResponseTemplate::new(200).set_body_json(keys),
        )
        .await;
        mount_get(&server, "/models", models).await;
        server
    }

    #[tokio::test]
    async fn failed_model_requests_do_not_grant_list_permission() {
        for response in [
            ResponseTemplate::new(403),
            ResponseTemplate::new(500),
            ResponseTemplate::new(200).set_body_string("invalid JSON"),
        ] {
            let server = inventory_server(response, json!({"data": []})).await;
            let result =
                map_access_with_client(&Client::new(), "test-key", &server.uri()).await.unwrap();

            assert!(!result.permissions.read_only.iter().any(|value| value == "models:list"));
            assert!(!result.resources.iter().any(|resource| resource.resource_type == "model"));
            assert!(
                result
                    .risk_notes
                    .iter()
                    .any(|note| note.contains("Model-list capability is unknown"))
            );
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn successful_empty_model_list_proves_list_without_model_exposure() {
        let server = inventory_server(
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            json!({"data": []}),
        )
        .await;
        let result =
            map_access_with_client(&Client::new(), "test-key", &server.uri()).await.unwrap();

        assert!(result.permissions.read_only.iter().any(|value| value == "models:list"));
        assert!(!result.resources.iter().any(|resource| resource.resource_type == "model"));
        assert!(
            !result.risk_notes.iter().any(|note| note.contains("Model-list capability is unknown"))
        );
        server.verify().await;
    }

    #[tokio::test]
    async fn sole_visible_key_is_inventory_not_caller_identity_or_permissions() {
        let server = inventory_server(
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            json!({"data": [{
                "id": "another-key",
                "name": "another principal's key",
                "created_at": "2026-01-01T00:00:00Z",
                "permissions": ["full_access"]
            }]}),
        )
        .await;
        let result =
            map_access_with_client(&Client::new(), "test-key", &server.uri()).await.unwrap();

        let token = result.token_details.as_ref().unwrap();
        assert!(token.user_id.is_none());
        assert!(token.name.is_none());
        assert!(token.created_at.is_none());
        assert!(token.scopes.is_empty());
        assert!(result.permissions.admin.is_empty());
        assert!(result.permissions.risky.is_empty());
        assert!(
            result
                .risk_notes
                .iter()
                .any(|note| note.contains("Current key identity and permissions are unknown"))
        );
        let inventory =
            result.resources.iter().find(|resource| resource.resource_type == "api_key").unwrap();
        assert_eq!(inventory.name, "another principal's key");
        assert_eq!(inventory.permissions, ["api_key:read"]);
        server.verify().await;
    }

    #[tokio::test]
    async fn current_key_response_is_kept_separate_from_organization_inventory() {
        let server = MockServer::start().await;
        mount_get(
            &server,
            "/organizations/api_keys/me",
            ResponseTemplate::new(200).set_body_json(json!({
                "id": "current-key",
                "name": "current key",
                "permissions": ["full_access"]
            })),
        )
        .await;
        mount_get(
            &server,
            "/organizations/api_keys",
            ResponseTemplate::new(200).set_body_json(json!({"data": [{
                "id": "another-key", "permissions": ["read"]
            }]})),
        )
        .await;
        mount_get(
            &server,
            "/models",
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
        )
        .await;
        let result =
            map_access_with_client(&Client::new(), "test-key", &server.uri()).await.unwrap();

        let token = result.token_details.as_ref().unwrap();
        assert_eq!(token.user_id.as_deref(), Some("current-key"));
        assert_eq!(token.scopes, ["full_access"]);
        assert_eq!(result.permissions.admin, ["key:full_access"]);
        assert!(!result.permissions.risky.iter().any(|value| value == "key:read"));
        server.verify().await;
    }
}
