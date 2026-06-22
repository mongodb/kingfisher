use anyhow::{Context, Result, anyhow};
use reqwest::{Client, StatusCode, header};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const HARNESS_API: &str = "https://app.harness.io";

#[derive(Debug, Deserialize, Default, Clone)]
struct HarnessOrg {
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "accountIdentifier")]
    account_identifier: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct HarnessProject {
    #[serde(default)]
    identifier: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Harness token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Harness access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Harness HTTP client")?;

    let aggregate = fetch_api_key_aggregate(&client, token).await?;
    let discovered_scopes = extract_first_string_vec(
        aggregate.as_ref(),
        &["data.scopes", "scopes", "data.permissions", "permissions"],
    );

    let token_name = extract_first_string(
        aggregate.as_ref(),
        &["data.name", "name", "data.identifier", "identifier"],
    );
    let token_id =
        extract_first_string(aggregate.as_ref(), &["data.id", "id", "data.uuid", "uuid"]);
    let account_id = extract_first_string(
        aggregate.as_ref(),
        &["data.accountIdentifier", "accountIdentifier", "data.accountId", "accountId"],
    );

    let mut risk_notes = Vec::new();
    let orgs = list_organizations(&client, token).await.unwrap_or_else(|err| {
        warn!("Harness access-map: organization enumeration failed: {err}");
        risk_notes.push(format!("Organization enumeration failed: {err}"));
        Vec::new()
    });

    let mut resources = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut total_projects = 0usize;

    for scope in &discovered_scopes {
        roles.push(RoleBinding {
            name: format!("scope:{scope}"),
            source: "harness".into(),
            permissions: vec![scope.clone()],
        });

        let scope_lc = scope.to_ascii_lowercase();
        if scope_lc.contains("admin") || scope_lc.contains("manage") || scope_lc.contains("owner") {
            permissions.admin.push(scope.clone());
        } else if scope_lc.contains("write")
            || scope_lc.contains("create")
            || scope_lc.contains("update")
            || scope_lc.contains("delete")
            || scope_lc.contains("execute")
        {
            permissions.risky.push(scope.clone());
        } else {
            permissions.read_only.push(scope.clone());
        }
    }

    for org in &orgs {
        let org_name = org
            .identifier
            .clone()
            .or_else(|| org.name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name.clone(),
            permissions: vec!["organization:read".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Organization visible to this API key".to_string(),
        });

        let projects = list_projects(&client, token, &org_name).await.unwrap_or_else(|err| {
            warn!("Harness access-map: project enumeration for {org_name} failed: {err}");
            risk_notes.push(format!("Project enumeration for org {org_name} failed: {err}"));
            Vec::new()
        });

        total_projects += projects.len();
        for project in &projects {
            let project_name = project
                .identifier
                .clone()
                .or_else(|| project.name.clone())
                .unwrap_or_else(|| "unknown_project".to_string());

            resources.push(ResourceExposure {
                resource_type: "project".into(),
                name: format!("{org_name}/{project_name}"),
                permissions: vec!["project:read".to_string()],
                risk: severity_to_str(Severity::Medium).to_string(),
                reason: "Project visible to this API key".to_string(),
            });
        }
    }

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: account_id.clone().unwrap_or_else(|| "harness_account".to_string()),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Harness account associated with this API key".into(),
        });
        risk_notes.push(
            "No organizations/projects were enumerable with this key (scope-limited or API access restricted)"
                .into(),
        );
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&permissions, total_projects);
    let identity_label = token_name.unwrap_or_else(|| "harness_api_key".to_string());

    Ok(AccessMapResult {
        cloud: "harness".into(),
        identity: AccessSummary {
            id: identity_label,
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: account_id
                .or_else(|| orgs.iter().find_map(|o| o.account_identifier.clone())),
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
            url: Some("https://app.harness.io/".into()),
            token_type: Some("pat".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: token_id,
            scopes: discovered_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_api_key_aggregate(client: &Client, token: &str) -> Result<Option<Value>> {
    let resp = client
        .get(format!("{HARNESS_API}/ng/api/apikey/aggregate"))
        .header("x-api-key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Harness access-map: failed to query API key aggregate endpoint")?;

    match resp.status() {
        StatusCode::OK | StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN => {
            let json = resp
                .json::<Value>()
                .await
                .context("Harness access-map: invalid JSON from aggregate endpoint")?;
            Ok(Some(json))
        }
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("Harness access-map: token rejected with HTTP 401"))
        }
        status => {
            warn!("Harness access-map: aggregate endpoint returned HTTP {}", status);
            Ok(None)
        }
    }
}

async fn list_organizations(client: &Client, token: &str) -> Result<Vec<HarnessOrg>> {
    let mut orgs = Vec::new();
    let mut page = 1usize;

    loop {
        let resp = client
            .get(format!("{HARNESS_API}/v1/orgs?limit=100&page={page}"))
            .header("x-api-key", token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Harness access-map: failed to list organizations")?;

        match resp.status() {
            StatusCode::OK => {
                let json: Value =
                    resp.json().await.context("Harness access-map: invalid organizations JSON")?;
                let batch: Vec<HarnessOrg> = parse_collection(json);
                if batch.is_empty() {
                    break;
                }
                orgs.extend(batch);
                page += 1;
            }
            StatusCode::UNAUTHORIZED => {
                return Err(anyhow!("Harness access-map: organization listing unauthorized (401)"));
            }
            StatusCode::FORBIDDEN => break,
            status => {
                warn!("Harness access-map: org enumeration returned HTTP {}", status);
                break;
            }
        }
    }

    Ok(orgs)
}

async fn list_projects(client: &Client, token: &str, org: &str) -> Result<Vec<HarnessProject>> {
    let mut projects = Vec::new();
    let mut page = 1usize;

    loop {
        let resp = client
            .get(format!("{HARNESS_API}/v1/orgs/{org}/projects?limit=100&page={page}"))
            .header("x-api-key", token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Harness access-map: failed to list projects")?;

        match resp.status() {
            StatusCode::OK => {
                let json: Value =
                    resp.json().await.context("Harness access-map: invalid projects JSON")?;
                let batch: Vec<HarnessProject> = parse_collection(json);
                if batch.is_empty() {
                    break;
                }
                projects.extend(batch);
                page += 1;
            }
            StatusCode::UNAUTHORIZED => {
                return Err(anyhow!("Harness access-map: project listing unauthorized (401)"));
            }
            StatusCode::FORBIDDEN => break,
            status => {
                warn!(
                    "Harness access-map: project enumeration for org {org} returned HTTP {}",
                    status
                );
                break;
            }
        }
    }

    Ok(projects)
}

fn parse_collection<T: DeserializeOwned>(value: Value) -> Vec<T> {
    if let Ok(items) = serde_json::from_value::<Vec<T>>(value.clone()) {
        return items;
    }

    if let Some(data) = value.get("data") {
        if let Ok(items) = serde_json::from_value::<Vec<T>>(data.clone()) {
            return items;
        }
        if let Some(content) = data.get("content")
            && let Ok(items) = serde_json::from_value::<Vec<T>>(content.clone())
        {
            return items;
        }
        if let Some(items) = data.get("items")
            && let Ok(items) = serde_json::from_value::<Vec<T>>(items.clone())
        {
            return items;
        }
    }

    if let Some(content) = value.get("content")
        && let Ok(items) = serde_json::from_value::<Vec<T>>(content.clone())
    {
        return items;
    }

    Vec::new()
}

fn extract_first_string(value: Option<&Value>, paths: &[&str]) -> Option<String> {
    let value = value?;
    for path in paths {
        if let Some(v) = value_at_path(value, path)
            && let Some(s) = v.as_str()
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

fn extract_first_string_vec(value: Option<&Value>, paths: &[&str]) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };

    for path in paths {
        if let Some(v) = value_at_path(value, path)
            && let Some(arr) = v.as_array()
        {
            let mut out: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .filter(|s| !s.is_empty())
                .collect();
            out.sort();
            out.dedup();
            if !out.is_empty() {
                return out;
            }
        }
    }

    Vec::new()
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn derive_severity(permissions: &PermissionSummary, total_projects: usize) -> Severity {
    if !permissions.admin.is_empty() {
        return Severity::High;
    }

    if !permissions.risky.is_empty() || total_projects > 0 {
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
