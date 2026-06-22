use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const PINECONE_API: &str = "https://api.pinecone.io";

#[derive(Deserialize, Default)]
struct PineconeIndexList {
    #[serde(default)]
    indexes: Vec<PineconeIndex>,
}

#[derive(Deserialize, Default, Clone)]
struct PineconeIndex {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    dimension: Option<u64>,
    #[serde(default)]
    metric: Option<String>,
    #[serde(default)]
    status: Option<PineconeIndexStatus>,
    #[serde(default)]
    spec: Option<PineconeIndexSpec>,
    #[serde(default)]
    deletion_protection: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct PineconeIndexStatus {
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct PineconeIndexSpec {
    #[serde(default)]
    serverless: Option<PineconeServerless>,
    #[serde(default)]
    pod: Option<PineconePod>,
}

#[derive(Deserialize, Default, Clone)]
struct PineconeServerless {
    #[serde(default)]
    cloud: Option<String>,
    #[serde(default)]
    region: Option<String>,
}

#[derive(Deserialize, Default, Clone)]
struct PineconePod {
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    pod_type: Option<String>,
    #[serde(default)]
    pods: Option<u64>,
}

#[derive(Deserialize, Default)]
struct PineconeCollectionList {
    #[serde(default)]
    collections: Vec<PineconeCollection>,
}

#[derive(Deserialize, Default)]
struct PineconeCollection {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Pinecone token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Pinecone access-map requires a validated API key from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .context("Failed to build Pinecone HTTP client")?;

    let indexes = fetch_indexes(&client, token).await?;
    let collections = fetch_collections(&client, token).await.unwrap_or_else(|err| {
        warn!("Pinecone access-map: collection enumeration failed: {err}");
        Vec::new()
    });

    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let mut risk_notes = Vec::new();

    roles.push(RoleBinding {
        name: "api_key_holder".into(),
        source: "pinecone".into(),
        permissions: vec![
            "index:list".into(),
            "index:describe".into(),
            "index:upsert".into(),
            "index:query".into(),
            "index:delete".into(),
        ],
    });
    permissions.risky.push("index:upsert".into());
    permissions.risky.push("index:delete".into());
    permissions.read_only.push("index:list".into());
    permissions.read_only.push("index:describe".into());
    permissions.read_only.push("index:query".into());

    let mut serverless_count = 0usize;
    let mut pod_count = 0usize;

    for index in &indexes {
        let name = index.name.clone().unwrap_or_else(|| "unknown".to_string());
        let metric = index.metric.as_deref().unwrap_or("unknown");
        let dimension =
            index.dimension.map(|d| d.to_string()).unwrap_or_else(|| "unknown".to_string());
        let ready = index.status.as_ref().and_then(|s| s.ready).unwrap_or(false);
        let state = index
            .status
            .as_ref()
            .and_then(|s| s.state.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let deletion_protection = index.deletion_protection.as_deref().unwrap_or("disabled");

        let mut perm_labels = vec![
            format!("metric:{metric}"),
            format!("dimension:{dimension}"),
            format!("state:{state}"),
            format!("deletion_protection:{deletion_protection}"),
        ];

        let mut location = String::new();
        if let Some(spec) = &index.spec {
            if let Some(serverless) = &spec.serverless {
                serverless_count += 1;
                let cloud = serverless.cloud.as_deref().unwrap_or("unknown");
                let region = serverless.region.as_deref().unwrap_or("unknown");
                perm_labels.push(format!("serverless:{cloud}/{region}"));
                location = format!("serverless {cloud}/{region}");
            } else if let Some(pod) = &spec.pod {
                pod_count += 1;
                let env = pod.environment.as_deref().unwrap_or("unknown");
                let pod_type = pod.pod_type.as_deref().unwrap_or("unknown");
                let pods = pod.pods.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
                perm_labels.push(format!("pod:{env}/{pod_type}/{pods}"));
                location = format!("pod {env}/{pod_type}");
            }
        }

        let host_suffix = index.host.as_ref().map(|h| format!(" ({h})")).unwrap_or_default();
        let location_suffix =
            if location.is_empty() { String::new() } else { format!(" — {location}") };
        let ready_marker = if ready { "ready" } else { "not ready" };

        resources.push(ResourceExposure {
            resource_type: "index".into(),
            name: name.clone(),
            permissions: perm_labels,
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: format!(
                "Pinecone index {name}{location_suffix}{host_suffix} accessible with this key ({ready_marker})"
            ),
        });
    }

    for collection in &collections {
        let name = collection.name.clone().unwrap_or_else(|| "unknown".to_string());
        let env = collection.environment.as_deref().unwrap_or("unknown");
        let status = collection.status.as_deref().unwrap_or("unknown");
        resources.push(ResourceExposure {
            resource_type: "collection".into(),
            name: name.clone(),
            permissions: vec![format!("environment:{env}"), format!("status:{status}")],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: format!(
                "Pinecone collection {name} in {env} accessible with this key ({status})"
            ),
        });
    }

    if indexes.is_empty() && collections.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: "pinecone_project".into(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Pinecone API key validated but no indexes or collections were enumerated"
                .into(),
        });
        risk_notes.push("Token did not enumerate any indexes or collections".into());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&indexes, &collections);

    if serverless_count > 0 && pod_count > 0 {
        risk_notes.push(format!(
            "Token reaches both serverless ({serverless_count}) and pod-based ({pod_count}) indexes"
        ));
    }

    Ok(AccessMapResult {
        cloud: "pinecone".into(),
        identity: AccessSummary {
            id: "pinecone_api_key".into(),
            access_type: "api_key".into(),
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
            name: None,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: None,
            url: Some("https://app.pinecone.io".into()),
            token_type: Some("pinecone_api_key".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_indexes(client: &Client, token: &str) -> Result<Vec<PineconeIndex>> {
    let url = format!("{PINECONE_API}/indexes");
    let resp = client
        .get(url)
        .header("Api-Key", token)
        .header(header::ACCEPT, "application/json")
        .header("X-Pinecone-API-Version", "2025-10")
        .send()
        .await
        .context("Pinecone access-map: failed to GET /indexes")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Pinecone access-map: /indexes lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let list: PineconeIndexList =
        resp.json().await.context("Pinecone access-map: invalid /indexes JSON")?;
    Ok(list.indexes)
}

async fn fetch_collections(client: &Client, token: &str) -> Result<Vec<PineconeCollection>> {
    let url = format!("{PINECONE_API}/collections");
    let resp = client
        .get(url)
        .header("Api-Key", token)
        .header(header::ACCEPT, "application/json")
        .header("X-Pinecone-API-Version", "2025-10")
        .send()
        .await
        .context("Pinecone access-map: failed to GET /collections")?;

    if !resp.status().is_success() {
        warn!("Pinecone access-map: /collections returned HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let list: PineconeCollectionList =
        resp.json().await.context("Pinecone access-map: invalid /collections JSON")?;
    Ok(list.collections)
}

fn derive_severity(indexes: &[PineconeIndex], collections: &[PineconeCollection]) -> Severity {
    let index_count = indexes.len();
    let collection_count = collections.len();
    let total = index_count + collection_count;
    let any_unprotected =
        indexes.iter().any(|i| i.deletion_protection.as_deref().unwrap_or("disabled") != "enabled");

    if index_count > 10 {
        return Severity::High;
    }
    if index_count > 0 && any_unprotected {
        return Severity::Medium;
    }
    if total > 0 {
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
