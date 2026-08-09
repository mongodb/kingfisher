use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const ASANA_API: &str = "https://app.asana.com/api/1.0";

#[derive(Deserialize)]
struct AsanaEnvelope<T> {
    #[serde(default)]
    data: Option<T>,
}

#[derive(Deserialize, Default)]
struct AsanaUser {
    #[serde(default)]
    gid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    resource_type: Option<String>,
    #[serde(default)]
    workspaces: Vec<AsanaWorkspace>,
}

#[derive(Deserialize, Default, Clone)]
struct AsanaWorkspace {
    #[serde(default)]
    gid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    is_organization: Option<bool>,
}

#[derive(Deserialize, Default)]
struct AsanaProject {
    #[serde(default)]
    gid: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    privacy_setting: Option<String>,
    #[serde(default)]
    archived: Option<bool>,
}

#[derive(Deserialize, Default)]
struct AsanaTeam {
    #[serde(default)]
    gid: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Asana token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Asana access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Asana HTTP client")?;

    let user = fetch_me(&client, token).await?;

    let username = user
        .name
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "asana_user".to_string());

    let workspaces = user.workspaces.clone();
    let primary_workspace = workspaces.first().cloned();

    let identity = AccessSummary {
        id: username.clone(),
        access_type: user.resource_type.clone().unwrap_or_else(|| "user".to_string()),
        project: primary_workspace.as_ref().and_then(|ws| ws.name.clone()),
        tenant: primary_workspace.as_ref().and_then(|ws| ws.gid.clone()),
        account_id: user.gid.clone(),
    };

    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let mut risk_notes = Vec::new();

    roles.push(RoleBinding {
        name: "workspace_member".into(),
        source: "asana".into(),
        permissions: vec!["workspace:member".into()],
    });
    permissions.risky.push("workspace:member".into());

    for workspace in &workspaces {
        let ws_gid = workspace.gid.clone().unwrap_or_else(|| "unknown".into());
        let ws_name = workspace.name.clone().unwrap_or_else(|| ws_gid.clone());
        let is_org = workspace.is_organization.unwrap_or(false);
        let resource_label = if is_org { "organization" } else { "workspace" };

        resources.push(ResourceExposure {
            resource_type: resource_label.into(),
            name: ws_name.clone(),
            permissions: vec![format!("{resource_label}:member")],
            risk: severity_to_str(if is_org { Severity::Medium } else { Severity::Low })
                .to_string(),
            reason: if is_org {
                format!("Asana organization {ws_name} accessible with this token")
            } else {
                format!("Asana workspace {ws_name} accessible with this token")
            },
        });

        let projects = list_projects(&client, token, &ws_gid).await.unwrap_or_else(|err| {
            warn!("Asana access-map: project enumeration failed for workspace {ws_gid}: {err}");
            Vec::new()
        });

        for project in &projects {
            let project_name = project
                .name
                .clone()
                .or_else(|| project.gid.clone())
                .unwrap_or_else(|| "unknown_project".to_string());
            let privacy = project.privacy_setting.as_deref().unwrap_or("unknown");
            let archived = project.archived.unwrap_or(false);

            let risk = match privacy {
                "public_to_workspace" => Severity::Medium,
                "private_to_team" => Severity::Low,
                _ => Severity::Low,
            };

            let mut perm_labels = vec![format!("project:{privacy}")];
            if archived {
                perm_labels.push("archived".into());
            }

            resources.push(ResourceExposure {
                resource_type: "project".into(),
                name: format!("{ws_name}/{project_name}"),
                permissions: perm_labels,
                risk: severity_to_str(risk).to_string(),
                reason: format!(
                    "Asana project in workspace {ws_name} accessible with this token ({privacy})"
                ),
            });
        }

        if is_org {
            let teams = list_teams(&client, token, &ws_gid).await.unwrap_or_else(|err| {
                warn!("Asana access-map: team enumeration failed for workspace {ws_gid}: {err}");
                Vec::new()
            });

            for team in &teams {
                let team_name = team
                    .name
                    .clone()
                    .or_else(|| team.gid.clone())
                    .unwrap_or_else(|| "unknown_team".to_string());
                roles.push(RoleBinding {
                    name: format!("team:{team_name}"),
                    source: "asana".into(),
                    permissions: Vec::new(),
                });
            }
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&workspaces, &resources);

    if workspaces.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Asana account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any workspaces".into());
    }

    let token_type = classify_token(token);

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "asana".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.name.clone(),
            username: user.email.clone(),
            account_type: user.resource_type.clone(),
            company: primary_workspace.as_ref().and_then(|ws| ws.name.clone()),
            location: None,
            email: user.email.clone(),
            url: Some("https://app.asana.com".into()),
            token_type: Some(token_type.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: user.gid.clone(),
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_me(client: &Client, token: &str) -> Result<AsanaUser> {
    let url = format!(
        "{ASANA_API}/users/me?opt_fields=gid,name,email,resource_type,workspaces.gid,workspaces.name,workspaces.is_organization,workspaces.resource_type"
    );

    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Asana access-map: failed to fetch /users/me")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Asana access-map: /users/me lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let envelope: AsanaEnvelope<AsanaUser> =
        resp.json().await.context("Asana access-map: invalid /users/me JSON")?;
    envelope.data.ok_or_else(|| anyhow!("Asana access-map: /users/me returned no data"))
}

async fn list_projects(
    client: &Client,
    token: &str,
    workspace_gid: &str,
) -> Result<Vec<AsanaProject>> {
    let url = format!(
        "{ASANA_API}/projects?workspace={workspace_gid}&limit=50&opt_fields=gid,name,privacy_setting,archived"
    );

    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Asana access-map: failed to list projects")?;

    if !resp.status().is_success() {
        warn!("Asana access-map: project enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let envelope: AsanaEnvelope<Vec<AsanaProject>> =
        resp.json().await.context("Asana access-map: invalid projects JSON")?;
    Ok(envelope.data.unwrap_or_default())
}

async fn list_teams(client: &Client, token: &str, workspace_gid: &str) -> Result<Vec<AsanaTeam>> {
    let url =
        format!("{ASANA_API}/users/me/teams?organization={workspace_gid}&opt_fields=gid,name");

    let resp = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Asana access-map: failed to list teams")?;

    if !resp.status().is_success() {
        warn!("Asana access-map: team enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let envelope: AsanaEnvelope<Vec<AsanaTeam>> =
        resp.json().await.context("Asana access-map: invalid teams JSON")?;
    Ok(envelope.data.unwrap_or_default())
}

fn classify_token(token: &str) -> &'static str {
    if token.starts_with("2/") {
        "personal_access_token_v2"
    } else if token.starts_with("1/") {
        "personal_access_token_v1"
    } else if token.starts_with("0/") {
        "oauth_or_legacy_pat"
    } else {
        "asana_token"
    }
}

fn derive_severity(workspaces: &[AsanaWorkspace], resources: &[ResourceExposure]) -> Severity {
    let has_org = workspaces.iter().any(|ws| ws.is_organization.unwrap_or(false));
    let project_count = resources.iter().filter(|r| r.resource_type == "project").count();

    if has_org && project_count > 20 {
        return Severity::High;
    }
    if has_org || project_count > 5 {
        return Severity::Medium;
    }
    if !workspaces.is_empty() {
        return Severity::Low;
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
