use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const BITBUCKET_API: &str = "https://api.bitbucket.org/2.0";

#[derive(Deserialize)]
struct BitbucketUser {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    nickname: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default, rename = "type")]
    account_type: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketPaginatedRepos {
    #[serde(default)]
    values: Vec<BitbucketRepo>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketRepo {
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    is_private: bool,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketWorkspace {
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketPaginatedPermissions {
    #[serde(default)]
    values: Vec<BitbucketWorkspacePermission>,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
struct BitbucketWorkspacePermission {
    #[serde(default)]
    permission: Option<String>,
    #[serde(default)]
    workspace: Option<BitbucketWorkspace>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Bitbucket token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Bitbucket access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Bitbucket HTTP client")?;

    let user_resp = client
        .get(format!("{BITBUCKET_API}/user"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Bitbucket access-map: failed to fetch user info")?;

    if !user_resp.status().is_success() {
        return Err(anyhow!(
            "Bitbucket access-map: user lookup failed with HTTP {}",
            user_resp.status()
        ));
    }

    let user: BitbucketUser =
        user_resp.json().await.context("Bitbucket access-map: invalid user JSON")?;

    let username = user
        .username
        .clone()
        .or_else(|| user.nickname.clone())
        .unwrap_or_else(|| "bitbucket_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: user.account_type.clone().unwrap_or_else(|| "user".into()).to_lowercase(),
        project: None,
        tenant: None,
        account_id: user.account_id.clone().or_else(|| user.uuid.clone()),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // Enumerate workspace memberships and permissions.
    let workspace_perms = list_workspace_permissions(&client, token).await.unwrap_or_else(|err| {
        warn!("Bitbucket access-map: workspace permission enumeration failed: {err}");
        Vec::new()
    });

    for wp in &workspace_perms {
        let ws_name = wp
            .workspace
            .as_ref()
            .and_then(|w| w.slug.clone().or_else(|| w.name.clone()))
            .unwrap_or_else(|| "unknown_workspace".to_string());
        let permission = wp.permission.clone().unwrap_or_else(|| "member".to_string());

        let risk = match permission.as_str() {
            "owner" => Severity::High,
            "collaborator" => Severity::Medium,
            _ => Severity::Low,
        };

        roles.push(RoleBinding {
            name: format!("workspace:{ws_name}"),
            source: "bitbucket".into(),
            permissions: vec![format!("workspace:{permission}")],
        });

        resources.push(ResourceExposure {
            resource_type: "workspace".into(),
            name: ws_name,
            permissions: vec![format!("workspace:{permission}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("Workspace membership with {permission} permission"),
        });

        match permission.as_str() {
            "owner" => permissions.admin.push(format!("workspace:{permission}")),
            "collaborator" => permissions.risky.push(format!("workspace:{permission}")),
            _ => permissions.read_only.push(format!("workspace:{permission}")),
        }
    }

    // Enumerate accessible repositories.
    let repos = list_accessible_repos(&client, token).await?;

    for repo in &repos {
        let repo_name = repo
            .full_name
            .clone()
            .or_else(|| repo.slug.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let (risk, perm_label) = if repo.is_private {
            (Severity::Medium, "repo:private")
        } else {
            (Severity::Low, "repo:public")
        };

        resources.push(ResourceExposure {
            resource_type: "repository".into(),
            name: repo_name,
            permissions: vec![perm_label.to_string()],
            risk: severity_to_str(risk).to_string(),
            reason: if repo.is_private {
                "Accessible private repository".to_string()
            } else {
                "Accessible public repository".to_string()
            },
        });

        if repo.is_private {
            permissions.risky.push(perm_label.to_string());
        } else {
            permissions.read_only.push(perm_label.to_string());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&workspace_perms, &repos);

    if repos.is_empty() && workspace_perms.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Bitbucket account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any repositories or workspaces".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "bitbucket".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.display_name.clone(),
            username: user.username.clone().or_else(|| user.nickname.clone()),
            account_type: user.account_type.clone(),
            company: None,
            location: None,
            email: None,
            url: user.username.as_ref().map(|u| format!("https://bitbucket.org/{u}/")),
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: user.account_id.or(user.uuid),
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_accessible_repos(client: &Client, token: &str) -> Result<Vec<BitbucketRepo>> {
    let mut repos = Vec::new();
    let mut url = Some(format!("{BITBUCKET_API}/repositories?role=member&pagelen=100"));

    while let Some(page_url) = url.take() {
        let resp = client
            .get(&page_url)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Bitbucket access-map: failed to list repositories")?;

        if !resp.status().is_success() {
            warn!("Bitbucket access-map: repo enumeration failed with HTTP {}", resp.status());
            break;
        }

        let page: BitbucketPaginatedRepos =
            resp.json().await.context("Bitbucket access-map: invalid repository JSON")?;
        repos.extend(page.values);
        url = page.next;
    }

    Ok(repos)
}

async fn list_workspace_permissions(
    client: &Client,
    token: &str,
) -> Result<Vec<BitbucketWorkspacePermission>> {
    let mut perms = Vec::new();
    let mut url = Some(format!("{BITBUCKET_API}/user/permissions/workspaces?pagelen=100"));

    while let Some(page_url) = url.take() {
        let resp = client
            .get(&page_url)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Bitbucket access-map: failed to list workspace permissions")?;

        if !resp.status().is_success() {
            warn!(
                "Bitbucket access-map: workspace permission enumeration failed with HTTP {}",
                resp.status()
            );
            break;
        }

        let page: BitbucketPaginatedPermissions = resp
            .json()
            .await
            .context("Bitbucket access-map: invalid workspace permissions JSON")?;
        perms.extend(page.values);
        url = page.next;
    }

    Ok(perms)
}

fn derive_severity(
    workspace_perms: &[BitbucketWorkspacePermission],
    repos: &[BitbucketRepo],
) -> Severity {
    // Owner of any workspace is high severity.
    if workspace_perms.iter().any(|wp| wp.permission.as_deref() == Some("owner")) {
        return Severity::High;
    }

    if repos.iter().any(|r| r.is_private) {
        return Severity::Medium;
    }

    if workspace_perms.iter().any(|wp| wp.permission.as_deref() == Some("collaborator")) {
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
