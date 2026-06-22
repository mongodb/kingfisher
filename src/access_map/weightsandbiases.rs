use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::json;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const WANDB_API: &str = "https://api.wandb.ai/graphql";

#[derive(Debug, Deserialize, Default, Clone)]
struct GraphQlError {
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct GraphQlResponse<T> {
    #[serde(default)]
    data: Option<T>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ViewerData {
    #[serde(default)]
    viewer: Option<Viewer>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct Viewer {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!("Failed to read Weights & Biases token from {}", path.display())
        })?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "Weights & Biases access-map requires a validated token from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Weights & Biases HTTP client")?;

    let viewer = fetch_viewer(&client, token).await?;
    let token_kind = detect_token_type(token).to_string();

    let identity_id = viewer
        .email
        .clone()
        .or_else(|| viewer.username.clone())
        .or_else(|| viewer.name.clone())
        .or_else(|| viewer.id.clone())
        .unwrap_or_else(|| "wandb_user".to_string());

    let mut permissions = PermissionSummary::default();
    permissions.risky.push("workspace:api_access".to_string());
    permissions.read_only.push("viewer:read".to_string());

    let mut roles = Vec::new();
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "weightsandbiases".into(),
        permissions: vec![format!("token:{token_kind}")],
    });

    let resources = vec![ResourceExposure {
        resource_type: "account".into(),
        name: identity_id.clone(),
        permissions: vec!["viewer:read".to_string(), "workspace:api_access".to_string()],
        risk: severity_to_str(Severity::Medium).to_string(),
        reason: "W&B account reachable with this API key".to_string(),
    }];

    let risk_notes = vec![
        "W&B does not expose fine-grained token scopes in this introspection path".to_string(),
    ];
    let severity = Severity::Medium;

    Ok(AccessMapResult {
        cloud: "weightsandbiases".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: viewer.id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: viewer.name,
            username: viewer.username,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: viewer.email,
            url: Some("https://wandb.ai/settings".into()),
            token_type: Some(token_kind),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: viewer.id,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_viewer(client: &Client, token: &str) -> Result<Viewer> {
    let resp = client
        .post(WANDB_API)
        .basic_auth("api", Some(token))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&json!({
            "query": "query { viewer { id username email name } }"
        }))
        .send()
        .await
        .context("Weights & Biases access-map: failed to query viewer")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Weights & Biases access-map: viewer lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let body: GraphQlResponse<ViewerData> =
        resp.json().await.context("Weights & Biases access-map: invalid GraphQL response JSON")?;

    if !body.errors.is_empty() {
        let msg =
            body.errors.iter().filter_map(|e| e.message.as_deref()).collect::<Vec<_>>().join("; ");
        if body.data.as_ref().and_then(|d| d.viewer.as_ref()).is_none() {
            return Err(anyhow!("Weights & Biases access-map: GraphQL returned errors: {msg}"));
        }
    }

    body.data
        .and_then(|d| d.viewer)
        .ok_or_else(|| anyhow!("Weights & Biases access-map: viewer data not present"))
}

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("wandb_v1_") {
        "wandb_v1"
    } else if token.len() == 40 && token.chars().all(|c| c.is_ascii_hexdigit()) {
        "legacy_api_key"
    } else {
        "api_key"
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
