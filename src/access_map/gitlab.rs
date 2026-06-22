use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITLAB_API: &str = "https://gitlab.com/api/v4/";

#[derive(Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    visibility: String,
    permissions: Option<GitLabProjectPermissions>,
}

#[derive(Clone, Deserialize)]
struct GitLabProjectPermissions {
    project_access: Option<GitLabAccess>,
    group_access: Option<GitLabAccess>,
}

#[derive(Clone, Deserialize)]
struct GitLabAccess {
    access_level: u32,
}

#[derive(Deserialize)]
struct GitLabTokenInfo {
    _id: Option<u64>,
    name: Option<String>,
    created_at: Option<String>,
    last_used_at: Option<String>,
    expires_at: Option<String>,
    scopes: Option<Vec<String>>,
    user_id: Option<u64>,
}

#[derive(Deserialize)]
struct GitLabMetadata {
    version: Option<String>,
    enterprise: Option<bool>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read GitLab token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("GitLab access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let api_url = Url::parse(DEFAULT_GITLAB_API).expect("valid GitLab API URL");
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build GitLab HTTP client")?;

    let token_info = fetch_token_info(&client, &api_url, token).await;
    let identity_label = token_info
        .as_ref()
        .and_then(|info| info.name.clone())
        .or_else(|| {
            token_info
                .as_ref()
                .and_then(|info| info.user_id)
                .map(|user_id| format!("gitlab_user_{user_id}"))
        })
        .unwrap_or_else(|| "gitlab_token".to_string());

    let identity = AccessSummary {
        id: identity_label,
        access_type: "token".into(),
        project: None,
        tenant: None,
        account_id: None,
    };

    let scopes = token_info.as_ref().and_then(|info| info.scopes.clone());
    let projects = list_accessible_projects(&client, &api_url, token).await?;
    let metadata = fetch_instance_metadata(&client, &api_url, token).await;
    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();

    for project in &projects {
        let access_level =
            project.permissions.as_ref().map(effective_access_level).unwrap_or_default();
        let (perm_label, severity) = access_level_to_risk(access_level);

        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: project.path_with_namespace.clone(),
            permissions: vec![perm_label.to_string()],
            risk: severity_to_str(severity).to_string(),
            reason: format!("Accessible {} project", project.visibility),
        });

        match severity {
            Severity::High | Severity::Critical => permissions.admin.push(perm_label.to_string()),
            Severity::Medium => permissions.risky.push(perm_label.to_string()),
            Severity::Low => permissions.read_only.push(perm_label.to_string()),
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&projects);

    let mut roles = Vec::new();
    if let Some(ref scopes) = scopes
        && !scopes.is_empty()
    {
        roles.push(RoleBinding {
            name: "token_scopes".into(),
            source: "gitlab".into(),
            permissions: scopes.clone(),
        });
    }

    if projects.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: token_info
                .as_ref()
                .and_then(|info| info.name.clone())
                .unwrap_or_else(|| identity.id.clone()),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "GitLab account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any projects".into());
    }

    if roles.is_empty() {
        risk_notes.push("GitLab did not report token scopes".into());
    }

    let token_details = token_info.as_ref().map(|info| AccessTokenDetails {
        name: info.name.clone(),
        username: None,
        account_type: None,
        company: None,
        location: None,
        email: None,
        url: None,
        token_type: None,
        created_at: info.created_at.clone(),
        last_used_at: info.last_used_at.clone(),
        expires_at: info.expires_at.clone(),
        user_id: info.user_id.map(|user_id| user_id.to_string()),
        scopes: scopes.clone().unwrap_or_default(),
    });

    Ok(AccessMapResult {
        cloud: "gitlab".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details,
        provider_metadata: metadata
            .map(|info| ProviderMetadata { version: info.version, enterprise: info.enterprise }),
        fingerprint: None,
    })
}

async fn fetch_token_info(client: &Client, api_url: &Url, token: &str) -> Option<GitLabTokenInfo> {
    let resp = client
        .get(api_url.join("personal_access_tokens/self").ok()?)
        .header("PRIVATE-TOKEN", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json().await.ok()
}

async fn fetch_instance_metadata(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Option<GitLabMetadata> {
    let resp = client
        .get(api_url.join("metadata").ok()?)
        .header("PRIVATE-TOKEN", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    resp.json().await.ok()
}

async fn list_accessible_projects(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GitLabProject>> {
    let mut projects = Vec::new();
    let mut page = 1u32;
    let per_page = 100u32;

    loop {
        let mut url = api_url.join("projects")?;
        url.query_pairs_mut()
            .append_pair("min_access_level", "10")
            .append_pair("per_page", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header("PRIVATE-TOKEN", token)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("GitLab access-map: failed to list projects")?;

        if !resp.status().is_success() {
            warn!("GitLab access-map: project enumeration failed with HTTP {}", resp.status());
            break;
        }

        let next_page = resp
            .headers()
            .get("x-next-page")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u32>().ok());

        let mut page_projects: Vec<GitLabProject> =
            resp.json().await.context("GitLab access-map: invalid project JSON")?;
        let count = page_projects.len();
        projects.append(&mut page_projects);

        if count < per_page as usize || next_page.is_none() {
            break;
        }
        page = next_page.unwrap_or(page + 1);
    }

    Ok(projects)
}

fn effective_access_level(perms: &GitLabProjectPermissions) -> u32 {
    let project_level = perms.project_access.as_ref().map(|access| access.access_level);
    let group_level = perms.group_access.as_ref().map(|access| access.access_level);
    project_level.max(group_level).unwrap_or_default()
}

fn access_level_to_risk(access_level: u32) -> (&'static str, Severity) {
    match access_level {
        50 => ("project:owner", Severity::High),
        40 => ("project:maintainer", Severity::High),
        30 => ("project:developer", Severity::Medium),
        20 => ("project:reporter", Severity::Low),
        10 => ("project:guest", Severity::Low),
        _ => ("project:access", Severity::Low),
    }
}

fn derive_severity(projects: &[GitLabProject]) -> Severity {
    let mut severity = Severity::Low;
    for project in projects {
        let access_level =
            project.permissions.as_ref().map(effective_access_level).unwrap_or_default();
        let (_, project_severity) = access_level_to_risk(access_level);
        match project_severity {
            Severity::High | Severity::Critical => return Severity::High,
            Severity::Medium => severity = Severity::Medium,
            Severity::Low => {}
        }
    }
    severity
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
