use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITEA_API: &str = "https://gitea.com/api/v1/";

#[derive(Deserialize)]
struct GiteaUser {
    login: String,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    created: Option<String>,
}

#[derive(Deserialize)]
struct GiteaRepo {
    full_name: String,
    private: bool,
    #[serde(default)]
    permissions: Option<GiteaRepoPermissions>,
}

#[derive(Clone, Deserialize)]
struct GiteaRepoPermissions {
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    push: bool,
    #[serde(default)]
    pull: bool,
}

#[derive(Deserialize)]
struct GiteaOrg {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    full_name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Gitea token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Gitea access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let api_url = Url::parse(DEFAULT_GITEA_API).expect("valid Gitea API URL");
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Gitea HTTP client")?;

    let user_resp = client
        .get(api_url.join("user")?)
        .header(header::AUTHORIZATION, format!("token {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Gitea access-map: failed to fetch user info")?;

    if !user_resp.status().is_success() {
        return Err(anyhow!(
            "Gitea access-map: user lookup failed with HTTP {}",
            user_resp.status()
        ));
    }

    let user: GiteaUser = user_resp.json().await.context("Gitea access-map: invalid user JSON")?;

    let identity = AccessSummary {
        id: user.login.clone(),
        access_type: if user.is_admin { "admin".into() } else { "user".into() },
        project: None,
        tenant: None,
        account_id: None,
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    if user.is_admin {
        roles.push(RoleBinding {
            name: "site_admin".into(),
            source: "gitea".into(),
            permissions: vec!["site:admin".to_string()],
        });
        permissions.admin.push("site:admin".to_string());
        risk_notes.push("Token belongs to a Gitea site administrator".into());
    }

    // Enumerate organizations.
    let orgs = list_user_orgs(&client, &api_url, token).await.unwrap_or_else(|err| {
        warn!("Gitea access-map: org enumeration failed: {err}");
        Vec::new()
    });

    for org in &orgs {
        let org_name = org
            .username
            .clone()
            .or_else(|| org.full_name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name,
            permissions: vec!["org:member".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Organization membership available to the token".into(),
        });
    }

    // Enumerate accessible repositories.
    let repos = list_accessible_repos(&client, &api_url, token).await?;

    for repo in &repos {
        let perms = repo.permissions.clone().unwrap_or(GiteaRepoPermissions {
            admin: false,
            push: false,
            pull: true,
        });

        let mut repo_perms = Vec::new();
        if perms.admin {
            repo_perms.push("repo:admin".to_string());
        }
        if perms.push {
            repo_perms.push("repo:write".to_string());
        }
        if perms.pull {
            repo_perms.push("repo:read".to_string());
        }

        let risk = if perms.admin {
            Severity::High
        } else if perms.push {
            Severity::Medium
        } else {
            Severity::Low
        };

        let reason = if repo.private {
            "Accessible private repository".to_string()
        } else {
            "Accessible public repository".to_string()
        };

        resources.push(ResourceExposure {
            resource_type: "repository".into(),
            name: repo.full_name.clone(),
            permissions: repo_perms.clone(),
            risk: severity_to_str(risk).to_string(),
            reason,
        });

        if perms.admin {
            permissions.admin.push("repo:admin".to_string());
        } else if perms.push {
            permissions.risky.push("repo:write".to_string());
        } else if perms.pull {
            permissions.read_only.push("repo:read".to_string());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&user, &repos);

    if repos.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: user.login.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Gitea account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any repositories".into());
    }

    let user_display_name = user
        .full_name
        .clone()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| Some(user.login.clone()));

    Ok(AccessMapResult {
        cloud: "gitea".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user_display_name,
            username: Some(user.login.clone()),
            account_type: Some(if user.is_admin {
                "admin".to_string()
            } else {
                "user".to_string()
            }),
            company: None,
            location: None,
            email: user.email.clone().filter(|v| !v.trim().is_empty()),
            url: user.avatar_url.clone().filter(|v| !v.trim().is_empty()),
            token_type: None,
            created_at: user.created.clone(),
            last_used_at: None,
            expires_at: None,
            user_id: Some(user.login),
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_accessible_repos(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GiteaRepo>> {
    let mut repos = Vec::new();
    let mut page = 1u32;
    let per_page = 50u32;

    loop {
        let mut url = api_url.join("user/repos")?;
        url.query_pairs_mut()
            .append_pair("limit", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Gitea access-map: failed to list repositories")?;

        if !resp.status().is_success() {
            warn!("Gitea access-map: repo enumeration failed with HTTP {}", resp.status());
            break;
        }

        let mut page_repos: Vec<GiteaRepo> =
            resp.json().await.context("Gitea access-map: invalid repository JSON")?;
        let count = page_repos.len();
        repos.append(&mut page_repos);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(repos)
}

async fn list_user_orgs(client: &Client, api_url: &Url, token: &str) -> Result<Vec<GiteaOrg>> {
    let mut orgs = Vec::new();
    let mut page = 1u32;
    let per_page = 50u32;

    loop {
        let mut url = api_url.join("user/orgs")?;
        url.query_pairs_mut()
            .append_pair("limit", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Gitea access-map: failed to list organizations")?;

        if !resp.status().is_success() {
            warn!("Gitea access-map: org enumeration failed with HTTP {}", resp.status());
            break;
        }

        let mut page_orgs: Vec<GiteaOrg> =
            resp.json().await.context("Gitea access-map: invalid org JSON")?;
        let count = page_orgs.len();
        orgs.append(&mut page_orgs);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(orgs)
}

fn derive_severity(user: &GiteaUser, repos: &[GiteaRepo]) -> Severity {
    if user.is_admin {
        return Severity::Critical;
    }

    let mut severity = Severity::Low;
    for repo in repos {
        let perms = repo.permissions.as_ref();
        if perms.is_some_and(|p| p.admin) {
            return Severity::High;
        }
        if perms.is_some_and(|p| p.push) {
            severity = Severity::Medium;
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
