use anyhow::{Context, Result, anyhow};
use gitlab::{
    AsyncGitlab, GitlabBuilder,
    api::{self, AsyncQuery, Pagination, projects::Projects, users::CurrentUser},
};
use serde::Deserialize;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITLAB_HOST: &str = "gitlab.com";

#[derive(Deserialize)]
struct GitLabProject {
    path_with_namespace: String,
    visibility: String,
    permissions: Option<GitLabProjectPermissions>,
}

#[derive(Deserialize)]
struct GitLabUser {
    id: u64,
    username: String,
    name: String,
    #[serde(default)]
    email: Option<String>,
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
    let mut builder = GitlabBuilder::new(DEFAULT_GITLAB_HOST, token);
    builder.user_agent(GLOBAL_USER_AGENT.as_str());
    let client = builder.build_async().await.context("Failed to authenticate GitLab client")?;

    // GitLab REST API: current user and membership-project listings.
    // https://docs.gitlab.com/api/users/#retrieve-the-current-user
    // https://docs.gitlab.com/api/projects/#list-all-projects
    // The full authenticated project representation is intentional: simple=true omits the
    // permissions object used to report direct and inherited access.
    let user = fetch_current_user(&client).await?;

    let identity = AccessSummary {
        id: user.username.clone(),
        access_type: "user_token".into(),
        project: None,
        tenant: None,
        account_id: Some(user.id.to_string()),
    };

    let mut risk_notes = Vec::new();
    let projects = match list_accessible_projects(&client).await {
        Ok(projects) => projects,
        Err(err) => {
            risk_notes.push(format!("Project enumeration failed: {err}"));
            Vec::new()
        }
    };
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

    let roles = vec![RoleBinding {
        name: "gitlab_user".into(),
        source: "users/current".into(),
        permissions: vec!["projects:membership:list".into()],
    }];

    if projects.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: identity.id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "GitLab account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any projects".into());
    }

    let token_details = Some(AccessTokenDetails {
        name: Some(user.name),
        username: Some(user.username),
        account_type: None,
        company: None,
        location: None,
        email: user.email,
        url: None,
        token_type: Some("gitlab_user_token".into()),
        created_at: None,
        last_used_at: None,
        expires_at: None,
        user_id: Some(user.id.to_string()),
        scopes: Vec::new(),
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
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_current_user(client: &AsyncGitlab) -> Result<GitLabUser> {
    let endpoint = CurrentUser::builder()
        .build()
        .context("GitLab access-map: failed to build current-user query")?;
    endpoint.query_async(client).await.context("GitLab access-map: failed to resolve current user")
}

async fn list_accessible_projects(client: &AsyncGitlab) -> Result<Vec<GitLabProject>> {
    let endpoint = Projects::builder()
        .membership(true)
        .simple(false)
        .build()
        .context("GitLab access-map: failed to build project query")?;
    api::paged(endpoint, Pagination::All)
        .query_async(client)
        .await
        .context("GitLab access-map: failed to list projects")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_group_access_contributes_to_effective_level() {
        let permissions = GitLabProjectPermissions {
            project_access: Some(GitLabAccess { access_level: 20 }),
            group_access: Some(GitLabAccess { access_level: 40 }),
        };
        assert_eq!(effective_access_level(&permissions), 40);
        assert_eq!(access_level_to_risk(40).0, "project:maintainer");
    }
}
