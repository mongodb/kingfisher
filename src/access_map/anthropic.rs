use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use reqwest::{Client, header};
use serde::{Deserialize, de::DeserializeOwned};
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const AUDIT_API_VERSION: &str = "2026-10-21";
const USAGE_API_BETA: &str = "analytics-usage-cost-2026-08-24";
const AUDIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_AUDIT_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_MODEL_RESOURCES: usize = 50;

struct UsageBucket {
    width: &'static str,
    duration: TimeDelta,
    source: &'static str,
}

const HOURLY_USAGE: UsageBucket = UsageBucket {
    width: "1h",
    duration: TimeDelta::hours(1),
    source: "Anthropic API usage (1-hour bucket start)",
};
const MINUTE_USAGE: UsageBucket = UsageBucket {
    width: "1m",
    duration: TimeDelta::minutes(1),
    source: "Anthropic API usage (1-minute bucket start)",
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnthropicCredentialFile {
    token: String,
    key_id: Option<String>,
    audit_token: Option<String>,
}

struct AnthropicKeyHistory<'a> {
    key_id: &'a str,
    audit_token: &'a str,
}

#[derive(Deserialize)]
struct AnthropicAuditKey {
    id: String,
    partial_key_hint: Option<String>,
}

impl AnthropicCredentialFile {
    fn key_history(&self) -> Result<Option<AnthropicKeyHistory<'_>>> {
        if self.token.trim().is_empty() {
            return Err(anyhow!("Anthropic credential JSON requires a non-empty token"));
        }
        if self.key_id.is_none() && self.audit_token.is_none() {
            return Ok(None);
        }
        let key_id = self
            .key_id
            .as_deref()
            .filter(|id| {
                id.len() <= 256
                    && id.strip_prefix("apikey_").is_some_and(|suffix| {
                        !suffix.is_empty()
                            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
            })
            .context("Anthropic key history requires a valid key_id")?;
        let audit_token = self
            .audit_token
            .as_deref()
            .map(str::trim)
            .filter(|token| {
                token.strip_prefix("sk-ant-admin01-").is_some_and(|suffix| !suffix.is_empty())
            })
            .context(
                "Anthropic key history requires an organization Admin API key as audit_token",
            )?;
        if audit_token == self.token.trim() {
            return Err(anyhow!(
                "Anthropic key history requires an audit_token distinct from the target token"
            ));
        }
        Ok(Some(AnthropicKeyHistory { key_id, audit_token }))
    }
}

#[derive(Deserialize)]
struct AnthropicUsageResponse {
    data: Vec<AnthropicUsageRow>,
}

#[derive(Deserialize)]
struct AnthropicUsageRow {
    starting_at: String,
    ending_at: String,
    group: AnthropicUsageGroup,
    usage: AnthropicUsageMetrics,
}

#[derive(Deserialize)]
struct AnthropicUsageGroup {
    api_key_id: Option<String>,
}

#[derive(Deserialize)]
struct AnthropicUsageMetrics {
    requests: Option<u64>,
}

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
    let path = args.credential_path.as_deref().context(
        "Anthropic access-map requires a credential file or a validated token from scan results",
    )?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read Anthropic token from {}", path.display()))?;
    map_access_from_credential_at(&raw, ANTHROPIC_API).await
}

async fn map_access_from_credential_at(raw: &str, api_base: &str) -> Result<AccessMapResult> {
    let raw = raw.trim();
    if !raw.starts_with('{') {
        return map_access_from_token_at(raw, None, api_base).await;
    }
    let credential: AnthropicCredentialFile = serde_json::from_str(raw).map_err(|_| {
        anyhow!("Invalid Anthropic credential JSON; expected a token and optional audit fields")
    })?;
    map_access_from_token_at(credential.token.trim(), credential.key_history()?, api_base).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, None, ANTHROPIC_API).await
}

async fn map_access_from_token_at(
    token: &str,
    key_history: Option<AnthropicKeyHistory<'_>>,
    api_base: &str,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Anthropic HTTP client")?;

    let usage = match &key_history {
        Some(history) => fetch_recent_key_usage(&client, api_base, token, history).await,
        None => None,
    };
    let mut result = map_access_with_client(&client, token, api_base).await?;
    if let (Some(history), Some((bucket_start, source)), Some(details)) =
        (key_history, usage, &mut result.token_details)
        && details.user_id.as_deref().is_none_or(|id| id == history.key_id)
    {
        details.last_used_at = Some(bucket_start.to_rfc3339_opts(SecondsFormat::Secs, true));
        result
            .provider_metadata
            .get_or_insert_with(ProviderMetadata::default)
            .credential_last_used_source = Some(source.into());
    }
    Ok(result)
}

async fn fetch_recent_key_usage(
    client: &Client,
    api_base: &str,
    token: &str,
    history: &AnthropicKeyHistory<'_>,
) -> Option<(DateTime<Utc>, &'static str)> {
    let mut audit_token = header::HeaderValue::from_str(history.audit_token).ok()?;
    audit_token.set_sensitive(true);
    // Minute queries are limited to one day, and the analytics data can take up to
    // 24 hours to refresh. Locate the latest recorded hour first, then refine it.
    let hour_seconds = HOURLY_USAGE.duration.num_seconds();
    let ending_at = DateTime::from_timestamp(
        Utc::now().timestamp().div_euclid(hour_seconds) * hour_seconds,
        0,
    )?;
    let starting_at = ending_at - TimeDelta::days(30);
    // The caller supplies the key ID. Bind it to the target using the Admin API's
    // redacted hint before requesting usage, even if the target cannot identify itself.
    let response = client
        .get(format!("{api_base}/organizations/api_keys/{}", history.key_id))
        .header("x-api-key", audit_token.clone())
        .header("anthropic-version", AUDIT_API_VERSION)
        .timeout(AUDIT_REQUEST_TIMEOUT)
        .send()
        .await
        .ok()?;
    let key: AnthropicAuditKey = read_audit_response(response).await?;
    let (prefix, suffix) = key.partial_key_hint.as_deref()?.split_once("...")?;
    if key.id != history.key_id
        || prefix.is_empty()
        || suffix.is_empty()
        || prefix.len() + suffix.len() >= token.len()
        || !token.starts_with(prefix)
        || !token.ends_with(suffix)
    {
        return None;
    }

    let hour = fetch_usage_bucket(
        client,
        api_base,
        &audit_token,
        history.key_id,
        starting_at,
        ending_at,
        &HOURLY_USAGE,
    )
    .await?;
    let minute = fetch_usage_bucket(
        client,
        api_base,
        &audit_token,
        history.key_id,
        hour,
        hour + HOURLY_USAGE.duration,
        &MINUTE_USAGE,
    )
    .await;
    Some(minute.map_or((hour, HOURLY_USAGE.source), |start| (start, MINUTE_USAGE.source)))
}

async fn fetch_usage_bucket(
    client: &Client,
    api_base: &str,
    audit_token: &header::HeaderValue,
    key_id: &str,
    starting_at: DateTime<Utc>,
    ending_at: DateTime<Utc>,
    bucket: &UsageBucket,
) -> Option<DateTime<Utc>> {
    let response = client
        .get(format!("{api_base}/organizations/analytics/usage"))
        .header("x-api-key", audit_token.clone())
        .header("anthropic-version", AUDIT_API_VERSION)
        .header("anthropic-beta", USAGE_API_BETA)
        .timeout(AUDIT_REQUEST_TIMEOUT)
        .query(&[
            ("api_key_ids[]", key_id),
            ("group_by[]", "api_key_id"),
            ("starting_at", &starting_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            ("ending_at", &ending_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
            ("time_bucket_width", bucket.width),
            ("order_by", "time"),
            ("order", "desc"),
            ("limit", "1"),
        ])
        .send()
        .await
        .ok()?;
    let report: AnthropicUsageResponse = read_audit_response(response).await?;
    let [row] = report.data.as_slice() else { return None };
    let bucket_start: DateTime<Utc> = row.starting_at.parse().ok()?;
    let bucket_end: DateTime<Utc> = row.ending_at.parse().ok()?;
    // The provider sorts across all matching buckets newest first. The one-row
    // response must still identify the requested key and a populated UTC bucket.
    (row.group.api_key_id.as_deref() == Some(key_id)
        && row.usage.requests.is_some_and(|requests| requests > 0)
        && bucket_start >= starting_at
        && bucket_end <= ending_at
        && bucket_end - bucket_start == bucket.duration
        && bucket_start.timestamp().rem_euclid(bucket.duration.num_seconds()) == 0
        && bucket_start.timestamp_subsec_nanos() == 0)
        .then_some(bucket_start)
}

async fn read_audit_response<T: DeserializeOwned>(mut response: reqwest::Response) -> Option<T> {
    if !response.status().is_success() {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len().saturating_add(chunk.len()) > MAX_AUDIT_RESPONSE_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).ok()
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
        super::map_access_from_token_at("test-token", None, &server.uri()).await.unwrap();
        assert!(!server.received_requests().await.unwrap().is_empty());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
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

    const TEST_KEY_ID: &str = "apikey_Test123";
    const TEST_AUDIT_TOKEN: &str = "sk-ant-admin01-test-audit";

    async fn mount_audit_key(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(format!("/organizations/api_keys/{TEST_KEY_ID}")))
            .and(header("x-api-key", TEST_AUDIT_TOKEN))
            .and(header("anthropic-version", AUDIT_API_VERSION))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }

    fn matching_audit_key() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_json(json!({"id": TEST_KEY_ID, "partial_key_hint": "tes...key"}))
    }

    async fn mount_usage(server: &MockServer, width: &str, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path("/organizations/analytics/usage"))
            .and(header("x-api-key", TEST_AUDIT_TOKEN))
            .and(header("anthropic-version", AUDIT_API_VERSION))
            .and(header("anthropic-beta", USAGE_API_BETA))
            .and(query_param("api_key_ids[]", TEST_KEY_ID))
            .and(query_param("group_by[]", "api_key_id"))
            .and(query_param("time_bucket_width", width))
            .and(query_param("order_by", "time"))
            .and(query_param("order", "desc"))
            .and(query_param("limit", "1"))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }

    fn usage_row(
        id: &str,
        start: DateTime<Utc>,
        bucket: &UsageBucket,
        requests: u64,
    ) -> serde_json::Value {
        json!({
            "data": [{
                "starting_at": start.to_rfc3339_opts(SecondsFormat::Secs, true),
                "ending_at": (start + bucket.duration).to_rfc3339_opts(SecondsFormat::Secs, true),
                "group": {"api_key_id": id},
                "usage": {"requests": requests}
            }]
        })
    }

    fn recent_hour() -> DateTime<Utc> {
        let seconds = HOURLY_USAGE.duration.num_seconds();
        DateTime::from_timestamp(Utc::now().timestamp().div_euclid(seconds) * seconds, 0).unwrap()
            - TimeDelta::hours(10)
    }

    #[tokio::test]
    async fn observes_only_the_exact_key_and_reports_the_latest_minute_bucket_start() {
        let server = inventory_server(
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            json!({"data": []}),
        )
        .await;
        mount_audit_key(&server, matching_audit_key()).await;
        let hour = recent_hour();
        let minute = hour + TimeDelta::minutes(43);
        mount_usage(
            &server,
            "1h",
            ResponseTemplate::new(200).set_body_json(usage_row(
                TEST_KEY_ID,
                hour,
                &HOURLY_USAGE,
                2,
            )),
        )
        .await;
        mount_usage(
            &server,
            "1m",
            ResponseTemplate::new(200).set_body_json(usage_row(
                TEST_KEY_ID,
                minute,
                &MINUTE_USAGE,
                1,
            )),
        )
        .await;
        let raw =
            json!({"token": "test-key", "key_id": TEST_KEY_ID, "audit_token": TEST_AUDIT_TOKEN});
        let result = map_access_from_credential_at(&raw.to_string(), &server.uri()).await.unwrap();
        assert_eq!(
            result.token_details.as_ref().unwrap().last_used_at.as_deref(),
            Some(minute.to_rfc3339_opts(SecondsFormat::Secs, true).as_str())
        );
        assert_eq!(
            result.provider_metadata.as_ref().unwrap().credential_last_used_source.as_deref(),
            Some(MINUTE_USAGE.source)
        );
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests[0].url.path(), format!("/organizations/api_keys/{TEST_KEY_ID}"));
        for request in &requests[1..3] {
            assert_eq!(request.url.path(), "/organizations/analytics/usage");
        }
        let minute_query =
            requests[2].url.query_pairs().collect::<std::collections::HashMap<_, _>>();
        assert_eq!(minute_query["starting_at"], hour.to_rfc3339_opts(SecondsFormat::Secs, true));
        assert_eq!(
            minute_query["ending_at"],
            (hour + HOURLY_USAGE.duration).to_rfc3339_opts(SecondsFormat::Secs, true)
        );
        let report = serde_json::to_string(&result).unwrap();
        assert!(!report.contains("test-key"));
        assert!(!report.contains(TEST_AUDIT_TOKEN));
        server.verify().await;
    }

    #[tokio::test]
    async fn keeps_inventory_when_usage_is_denied_empty_or_for_another_key() {
        let hour = recent_hour();
        for response in [
            ResponseTemplate::new(403),
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            ResponseTemplate::new(200).set_body_json(usage_row(
                "apikey_Other",
                hour,
                &HOURLY_USAGE,
                3,
            )),
            ResponseTemplate::new(200).set_body_json(usage_row(
                TEST_KEY_ID,
                hour,
                &HOURLY_USAGE,
                0,
            )),
        ] {
            let server = inventory_server(
                ResponseTemplate::new(200).set_body_json(json!({"data": [{"id":"test-model"}]})),
                json!({"data": []}),
            )
            .await;
            mount_audit_key(&server, matching_audit_key()).await;
            mount_usage(&server, "1h", response).await;
            let raw = json!({"token": "test-key", "key_id": TEST_KEY_ID, "audit_token": TEST_AUDIT_TOKEN});
            let result =
                map_access_from_credential_at(&raw.to_string(), &server.uri()).await.unwrap();
            assert!(result.token_details.unwrap().last_used_at.is_none());
            assert!(result.provider_metadata.is_none());
            assert!(result.resources.iter().any(|resource| resource.name == "test-model"));
            assert_eq!(server.received_requests().await.unwrap().len(), 6);
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn unverified_target_never_queries_usage() {
        for response in [
            ResponseTemplate::new(403),
            ResponseTemplate::new(200).set_body_json(json!({"id": TEST_KEY_ID})),
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": "apikey_Other", "partial_key_hint": "tes...key"})),
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": TEST_KEY_ID, "partial_key_hint": "tes...other"})),
            ResponseTemplate::new(200)
                .set_body_json(json!({"id": TEST_KEY_ID, "partial_key_hint": "...key"})),
        ] {
            let server = inventory_server(
                ResponseTemplate::new(200).set_body_json(json!({"data": [{"id":"test-model"}]})),
                json!({"data": [{"id": TEST_KEY_ID}]}),
            )
            .await;
            mount_audit_key(&server, response).await;
            Mock::given(path("/organizations/analytics/usage"))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let raw = json!({"token": "test-key", "key_id": TEST_KEY_ID, "audit_token": TEST_AUDIT_TOKEN});
            let result =
                map_access_from_credential_at(&raw.to_string(), &server.uri()).await.unwrap();
            let token = result.token_details.unwrap();
            assert!(token.user_id.is_none());
            assert!(token.last_used_at.is_none());
            assert!(result.provider_metadata.is_none());
            assert!(result.resources.iter().any(|resource| resource.name == "test-model"));
            server.verify().await;
        }
    }

    #[tokio::test]
    async fn plaintext_credential_never_queries_usage() {
        let server = inventory_server(
            ResponseTemplate::new(200).set_body_json(json!({"data": []})),
            json!({"data": []}),
        )
        .await;
        let result = map_access_from_credential_at("test-key\n", &server.uri()).await.unwrap();
        assert!(result.token_details.unwrap().last_used_at.is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
        server.verify().await;
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
