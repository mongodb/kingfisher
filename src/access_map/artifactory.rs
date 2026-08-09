use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const MAX_REPO_RESOURCES: usize = 100;

#[derive(Deserialize)]
struct ArtifactoryUser {
    name: Option<String>,
    email: Option<String>,
    admin: Option<bool>,
    #[expect(dead_code)]
    #[serde(rename = "profileUpdatable")]
    profile_updatable: Option<bool>,
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Deserialize)]
struct ArtifactoryRepo {
    key: Option<String>,
    #[serde(rename = "type")]
    repo_type: Option<String>,
    #[serde(rename = "packageType")]
    package_type: Option<String>,
}

/// Entry point when invoked via the CLI `access-map jfrog-art` subcommand.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!(
            "Artifactory access-map requires a credential file with token (and optionally base_url)"
        )
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Artifactory credential file from {}", path.display())
    })?;
    let (token, base_url) = parse_artifactory_credentials(&raw)?;
    match base_url {
        Some(url) => map_access_from_token_and_url(&token, &url).await,
        None => map_access_from_token(&token).await,
    }
}

/// Maps an Artifactory token without a known base URL.
/// Attempts common JFrog cloud URL patterns.
pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    // Without a base URL we cannot discover the instance.
    // Build a minimal result indicating the token is valid but instance unknown.
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Artifactory HTTP client")?;

    // Try the JFrog cloud ping endpoint as a basic validation
    let ping_ok = ping_artifactory(&client, token, "https://access.jfrog.io").await;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    if ping_ok {
        permissions.read_only.push("system:ping".to_string());
        risk_notes.push(
            "Token responded to JFrog cloud ping; base_url unknown so full mapping not possible"
                .to_string(),
        );
    } else {
        risk_notes.push(
            "Token did not respond to JFrog cloud ping; provide base_url for full mapping"
                .to_string(),
        );
    }

    let severity = Severity::Medium;
    Ok(AccessMapResult {
        // Nothing was resolved when the ping failed: the identity below is a
        // placeholder, so this must not read as confirmed impact.
        mapping_error: (!ping_ok).then(|| {
            "Artifactory identity mapping failed: token did not respond to the JFrog cloud ping"
                .to_string()
        }),
        cloud: "artifactory".into(),
        identity: AccessSummary {
            id: "unknown_artifactory_user".into(),
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles: Vec::new(),
        permissions,
        resources: Vec::new(),
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            token_type: Some("bearer_token".into()),
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

/// Maps an Artifactory token with a known base URL to an access profile.
pub async fn map_access_from_token_and_url(token: &str, base_url: &str) -> Result<AccessMapResult> {
    let base_url = base_url.trim().trim_end_matches('/');
    if base_url.is_empty() {
        return Err(anyhow!("Artifactory access-map requires a non-empty base URL"));
    }

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Artifactory HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Fetch current user info
    let user = fetch_current_user(&client, token, base_url).await?;

    let username = user.name.clone().unwrap_or_default();
    let user_email = user.email.clone();
    let is_admin = user.admin.unwrap_or(false);
    let groups = user.groups.clone();

    let has_deployer = groups.iter().any(|g| g.to_lowercase().contains("deploy"));

    // Classify
    if is_admin {
        permissions.admin.push("artifactory:admin".to_string());
        permissions.admin.push("repositories:manage".to_string());
        permissions.admin.push("security:manage".to_string());
        permissions.admin.push("system:configure".to_string());
        risk_notes.push("Admin flag is set - full Artifactory control".to_string());
    }

    if has_deployer {
        permissions.risky.push("artifacts:deploy".to_string());
        permissions.risky.push("artifacts:delete".to_string());
        risk_notes.push("User is in a deployer group - supply chain risk".to_string());
    }

    for group in &groups {
        permissions.read_only.push(format!("group:{group}"));
    }

    // Fetch repositories
    let repos = fetch_repositories(&client, token, base_url).await.unwrap_or_else(|err| {
        warn!("Artifactory access-map: repository listing failed: {err}");
        risk_notes.push(format!("Repository listing failed: {err}"));
        Vec::new()
    });

    if !repos.is_empty() {
        permissions.read_only.push("repositories:list".to_string());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = if is_admin {
        Severity::Critical
    } else if has_deployer {
        Severity::High
    } else {
        Severity::Medium
    };

    let roles = vec![RoleBinding {
        name: if is_admin { "artifactory:admin".into() } else { "artifactory:user".into() },
        source: "artifactory".into(),
        permissions: groups.iter().map(|g| format!("group:{g}")).collect(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "artifactory_instance".into(),
        name: base_url.to_string(),
        permissions: if is_admin { vec!["admin".into()] } else { vec!["authenticated".into()] },
        risk: severity_to_str(severity).to_string(),
        reason: "Artifactory instance accessible with this token".to_string(),
    }];

    for repo in repos.iter().take(MAX_REPO_RESOURCES) {
        let repo_key = repo.key.clone().unwrap_or_default();
        let repo_type = repo.repo_type.clone().unwrap_or_default();
        let pkg_type = repo.package_type.clone().unwrap_or_default();

        let repo_risk = if has_deployer || is_admin { Severity::High } else { Severity::Low };

        resources.push(ResourceExposure {
            resource_type: format!("repository:{repo_type}"),
            name: repo_key,
            permissions: vec![format!("package_type:{pkg_type}")],
            risk: severity_to_str(repo_risk).to_string(),
            reason: if has_deployer || is_admin {
                "Repository with deploy/admin access - supply chain risk".to_string()
            } else {
                "Repository visible to this token".to_string()
            },
        });
    }

    if repos.len() > MAX_REPO_RESOURCES {
        risk_notes.push(format!(
            "Repository list truncated to first {MAX_REPO_RESOURCES} entries ({} total)",
            repos.len()
        ));
    }

    let identity_id = user_email.clone().unwrap_or_else(|| username.clone());

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "artifactory".into(),
        identity: AccessSummary {
            id: if identity_id.is_empty() { "artifactory_token".to_string() } else { identity_id },
            access_type: if is_admin { "admin".into() } else { "user".into() },
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
            name: Some(username),
            username: None,
            account_type: Some(if is_admin { "admin".into() } else { "user".into() }),
            company: None,
            location: None,
            email: user_email,
            url: Some(base_url.to_string()),
            token_type: Some("bearer_token".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes: groups,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

fn parse_artifactory_credentials(raw: &str) -> Result<(String, Option<String>)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .or_else(|| json.get("api_key"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let base_url = json
            .get("base_url")
            .or_else(|| json.get("url"))
            .or_else(|| json.get("instance_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        if let Some(token) = token {
            return Ok((token, base_url));
        }
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    match lines.len() {
        1 => Ok((lines[0].to_string(), None)),
        n if n >= 2 => Ok((lines[0].to_string(), Some(lines[1].to_string()))),
        _ => Err(anyhow!(
            "Artifactory credential format not recognized. Provide JSON with token (+ optional base_url), or lines."
        )),
    }
}

async fn ping_artifactory(client: &Client, token: &str, base_url: &str) -> bool {
    let resp = client
        .get(format!("{base_url}/artifactory/api/system/ping"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await;

    matches!(resp, Ok(r) if r.status().is_success())
}

async fn fetch_current_user(
    client: &Client,
    token: &str,
    base_url: &str,
) -> Result<ArtifactoryUser> {
    let resp = client
        .get(format!("{base_url}/artifactory/api/security/current"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Artifactory access-map: failed to query security/current endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Artifactory access-map: security/current endpoint returned HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Artifactory access-map: invalid security/current JSON")
}

async fn fetch_repositories(
    client: &Client,
    token: &str,
    base_url: &str,
) -> Result<Vec<ArtifactoryRepo>> {
    let resp = client
        .get(format!("{base_url}/artifactory/api/repositories"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Artifactory access-map: failed to query repositories endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Artifactory access-map: repositories endpoint returned HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Artifactory access-map: invalid repositories JSON")
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
