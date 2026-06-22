use anyhow::{Context, Result, anyhow};
use regex::Regex;
use reqwest::{Client, StatusCode, header};
use serde_json::Value;
use std::sync::LazyLock;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const SALESFORCE_API_VERSION: &str = "v60.0";
const MAX_OBJECT_RESOURCES: usize = 100;

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?xi)\b(00[A-Z0-9]{13}![A-Z0-9._-]{80,260})\b")
        .expect("valid salesforce token regex")
});
static INSTANCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?xi)\b([A-Z0-9-]{5,128})\.my\.salesforce\.com\b")
        .expect("valid salesforce instance regex")
});

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Salesforce access-map requires a credential file with token and instance")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Salesforce credential file from {}", path.display())
    })?;
    let (token, instance) = parse_salesforce_credentials(&raw)?;
    map_access_from_token_and_instance(&token, &instance).await
}

pub async fn map_access_from_token_and_instance(
    token: &str,
    instance: &str,
) -> Result<AccessMapResult> {
    let instance = normalize_instance(instance)
        .ok_or_else(|| anyhow!("Salesforce access-map requires a valid instance domain"))?;
    let base_url = format!("https://{instance}.my.salesforce.com");

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Salesforce HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();
    permissions.read_only.push("limits:read".to_string());

    let limits = fetch_limits(&client, token, &base_url).await?;
    let user_info = fetch_user_info(&client, token, &base_url).await.unwrap_or_else(|err| {
        warn!("Salesforce access-map: userinfo lookup failed: {err}");
        risk_notes.push(format!("Identity lookup failed: {err}"));
        Value::Null
    });
    let objects = list_sobjects(&client, token, &base_url).await.unwrap_or_else(|err| {
        warn!("Salesforce access-map: sobject enumeration failed: {err}");
        risk_notes.push(format!("Object enumeration failed: {err}"));
        Vec::new()
    });

    if !objects.is_empty() {
        permissions.read_only.push("sobjects:list".to_string());
    }
    permissions.risky.push("rest_api:access".to_string());
    permissions.read_only.sort();
    permissions.read_only.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();

    let organization_id =
        value_as_string(&user_info, &["organization_id", "organizationId", "org_id", "orgId"]);
    let user_id = value_as_string(&user_info, &["user_id", "userId", "sub", "id"]);
    let username =
        value_as_string(&user_info, &["preferred_username", "preferredUsername", "email", "name"]);

    let identity_id = username
        .clone()
        .or_else(|| user_id.clone())
        .or_else(|| organization_id.clone())
        .unwrap_or_else(|| "salesforce_access_token".to_string());

    let roles = vec![RoleBinding {
        name: "token_type:access_token".into(),
        source: "salesforce".into(),
        permissions: vec!["rest_api:access".into()],
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "salesforce_org".into(),
        name: organization_id.clone().unwrap_or_else(|| instance.clone()),
        permissions: vec!["limits:read".into()],
        risk: severity_to_str(Severity::Medium).to_string(),
        reason: "Salesforce org reachable with this access token".to_string(),
    }];

    for object_name in objects.iter().take(MAX_OBJECT_RESOURCES) {
        resources.push(ResourceExposure {
            resource_type: "sobject".into(),
            name: object_name.clone(),
            permissions: vec!["object:read_metadata".into()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Object metadata visible to this token".to_string(),
        });
    }
    if objects.len() > MAX_OBJECT_RESOURCES {
        risk_notes.push(format!(
            "Object resource list truncated to first {MAX_OBJECT_RESOURCES} entries ({} total objects visible)",
            objects.len()
        ));
    }

    if !limits.is_object() {
        risk_notes.push("Salesforce limits response was not a JSON object".to_string());
    }

    let severity = Severity::Medium;
    Ok(AccessMapResult {
        cloud: "salesforce".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: "token".into(),
            project: organization_id.clone(),
            tenant: None,
            account_id: organization_id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: username,
            username: None,
            account_type: Some("access_token".into()),
            company: None,
            location: None,
            email: None,
            url: Some(base_url),
            token_type: Some("access_token".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

fn parse_salesforce_credentials(raw: &str) -> Result<(String, String)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = value_as_string(&json, &["token", "access_token", "salesforce_token"]);
        let instance =
            value_as_string(&json, &["instance", "instance_url", "instanceUrl", "domain", "host"]);

        if let (Some(token), Some(instance)) = (token, instance) {
            let normalized = normalize_instance(&instance).ok_or_else(|| {
                anyhow!("Credential JSON contains an invalid Salesforce instance")
            })?;
            return Ok((token, normalized));
        }
    }

    let token = TOKEN_RE.captures(raw).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    let instance =
        INSTANCE_RE.captures(raw).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));

    if let (Some(token), Some(instance)) = (token, instance) {
        return Ok((token, instance));
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() >= 2
        && let Some(instance) = normalize_instance(lines[1])
    {
        return Ok((lines[0].to_string(), instance));
    }

    Err(anyhow!(
        "Salesforce credential format not recognized. Provide JSON with token + instance_url, or text containing both."
    ))
}

fn normalize_instance(raw: &str) -> Option<String> {
    let mut value = raw.trim().trim_matches('/').to_ascii_lowercase();
    if value.starts_with("https://") {
        value = value.trim_start_matches("https://").to_string();
    } else if value.starts_with("http://") {
        value = value.trim_start_matches("http://").to_string();
    }
    if let Some(rest) = value.strip_suffix(".my.salesforce.com") {
        value = rest.to_string();
    }
    value = value.split('/').next().unwrap_or_default().to_string();

    if value.len() < 5 || value.len() > 128 {
        return None;
    }
    if !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    Some(value)
}

async fn fetch_limits(client: &Client, token: &str, base_url: &str) -> Result<Value> {
    let resp = client
        .get(format!("{base_url}/services/data/{SALESFORCE_API_VERSION}/limits"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Salesforce access-map: failed to query limits endpoint")?;

    if resp.status() != StatusCode::OK {
        return Err(anyhow!(
            "Salesforce access-map: limits endpoint failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Salesforce access-map: invalid limits JSON")
}

async fn fetch_user_info(client: &Client, token: &str, base_url: &str) -> Result<Value> {
    let resp = client
        .get(format!("{base_url}/services/oauth2/userinfo"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Salesforce access-map: failed to query userinfo endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Salesforce access-map: userinfo lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Salesforce access-map: invalid userinfo JSON")
}

async fn list_sobjects(client: &Client, token: &str, base_url: &str) -> Result<Vec<String>> {
    let resp = client
        .get(format!("{base_url}/services/data/{SALESFORCE_API_VERSION}/sobjects"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Salesforce access-map: failed to query sobjects endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Salesforce access-map: sobjects listing failed with HTTP {}",
            resp.status()
        ));
    }

    let body: Value = resp.json().await.context("Salesforce access-map: invalid sobjects JSON")?;
    let mut names = Vec::new();
    if let Some(arr) = body.get("sobjects").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(name) = value_as_string(item, &["name", "label"])
                && !name.is_empty()
            {
                names.push(name);
            }
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn value_as_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = value.get(*key).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
