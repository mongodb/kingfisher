use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::cli::commands::access_map::AccessMapArgs;
use crate::validation::GLOBAL_USER_AGENT;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

// ---------------------------------------------------------------------------
// API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AlgoliaKeyInfo {
    #[expect(dead_code)]
    #[serde(default)]
    value: String,
    #[serde(default)]
    acl: Vec<String>,
    #[serde(default)]
    indexes: Vec<String>,
    #[serde(default)]
    validity: i64,
    #[serde(default)]
    description: String,
}

#[derive(Debug, Deserialize)]
struct AlgoliaIndexList {
    #[serde(default)]
    items: Vec<AlgoliaIndex>,
}

#[derive(Debug, Deserialize)]
struct AlgoliaIndex {
    #[serde(default)]
    name: String,
}

// ---------------------------------------------------------------------------
// ACL classification
// ---------------------------------------------------------------------------

fn classify_acl(acl: &str) -> AclCategory {
    match acl {
        "admin" | "editSettings" | "listIndexes" | "deleteIndex" => AclCategory::Admin,
        "addObject" | "deleteObject" | "browse" => AclCategory::Risky,
        "search" | "analytics" | "recommendation" | "usage" => AclCategory::Read,
        _ => AclCategory::Read,
    }
}

enum AclCategory {
    Admin,
    Risky,
    Read,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Algolia access-map requires a credential file with app_id and api_key")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Algolia credential file from {}", path.display())
    })?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .context("Algolia credential file must be valid JSON with app_id and api_key")?;

    let app_id = json
        .get("app_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Algolia credential JSON missing 'app_id'"))?;
    let api_key = json
        .get("api_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Algolia credential JSON missing 'api_key'"))?;

    map_access_from_credentials(app_id, api_key).await
}

pub async fn map_access_from_credentials(app_id: &str, api_key: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Algolia HTTP client")?;

    let base = format!("https://{app_id}-dsn.algolia.net");
    let mut risk_notes: Vec<String> = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Fetch key info
    let key_info = fetch_key_info(&client, &base, app_id, api_key).await?;

    // Classify ACLs
    for acl in &key_info.acl {
        match classify_acl(acl) {
            AclCategory::Admin => permissions.admin.push(format!("acl:{acl}")),
            AclCategory::Risky => permissions.risky.push(format!("acl:{acl}")),
            AclCategory::Read => permissions.read_only.push(format!("acl:{acl}")),
        }
    }

    // Fetch indexes
    let indexes = fetch_indexes(&client, &base, app_id, api_key).await.unwrap_or_else(|err| {
        warn!("Algolia access-map: index listing failed: {err}");
        risk_notes.push(format!("Index listing failed: {err}"));
        Vec::new()
    });

    // Determine severity
    let has_admin = !permissions.admin.is_empty();
    let has_risky = !permissions.risky.is_empty();
    let severity = if has_admin {
        Severity::Critical
    } else if has_risky {
        Severity::High
    } else {
        Severity::Medium
    };

    let wildcard_indexes = key_info.indexes.contains(&"*".to_string());
    if wildcard_indexes {
        risk_notes.push("API key has wildcard index access (all indexes)".to_string());
    }
    if key_info.validity == 0 {
        risk_notes.push("API key has no validity limit (does not expire)".to_string());
    }

    let roles = vec![RoleBinding {
        name: "algolia_api_key".into(),
        source: "algolia".into(),
        permissions: key_info.acl.iter().map(|a| format!("acl:{a}")).collect(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "algolia_application".into(),
        name: app_id.to_string(),
        permissions: key_info.acl.iter().map(|a| format!("acl:{a}")).collect(),
        risk: severity_to_str(severity).to_string(),
        reason: "Algolia application reachable with this API key".to_string(),
    }];

    for idx in &indexes {
        resources.push(ResourceExposure {
            resource_type: "algolia_index".into(),
            name: idx.clone(),
            permissions: vec!["index:accessible".into()],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Index accessible via this API key".to_string(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "algolia".into(),
        identity: AccessSummary {
            id: format!("{app_id}:{}", &api_key[..api_key.len().min(8)]),
            access_type: "api_key".into(),
            project: Some(app_id.to_string()),
            tenant: None,
            account_id: Some(app_id.to_string()),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: if key_info.description.is_empty() { None } else { Some(key_info.description) },
            token_type: Some("api_key".into()),
            scopes: key_info.acl,
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async fn fetch_key_info(
    client: &Client,
    base: &str,
    app_id: &str,
    api_key: &str,
) -> Result<AlgoliaKeyInfo> {
    let resp = client
        .get(format!("{base}/1/keys/{api_key}"))
        .header("X-Algolia-Application-Id", app_id)
        .header("X-Algolia-API-Key", api_key)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Algolia access-map: failed to query key info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Algolia access-map: key info endpoint returned HTTP {}",
            resp.status()
        ));
    }

    resp.json::<AlgoliaKeyInfo>().await.context("Algolia access-map: invalid key info JSON")
}

async fn fetch_indexes(
    client: &Client,
    base: &str,
    app_id: &str,
    api_key: &str,
) -> Result<Vec<String>> {
    let resp = client
        .get(format!("{base}/1/indexes"))
        .header("X-Algolia-Application-Id", app_id)
        .header("X-Algolia-API-Key", api_key)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Algolia access-map: failed to list indexes")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Algolia access-map: index listing returned HTTP {}", resp.status()));
    }

    let body: AlgoliaIndexList =
        resp.json().await.context("Algolia access-map: invalid index list JSON")?;

    Ok(body.items.into_iter().map(|i| i.name).filter(|n| !n.is_empty()).collect())
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
