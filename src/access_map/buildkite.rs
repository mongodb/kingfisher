use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const BUILDKITE_API: &str = "https://api.buildkite.com/v2";

#[derive(Deserialize)]
struct BuildkiteAccessToken {
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct BuildkiteUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct BuildkiteOrganization {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Deserialize)]
struct BuildkitePipeline {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Buildkite token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Buildkite access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Buildkite HTTP client")?;

    let token_info = fetch_access_token(&client, token).await?;

    let user = fetch_user(&client, token).await.unwrap_or_else(|err| {
        warn!("Buildkite access-map: user lookup failed: {err}");
        BuildkiteUser { id: None, name: None, email: None, created_at: None }
    });

    let username = user
        .name
        .clone()
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "buildkite_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "user".into(),
        project: None,
        tenant: None,
        account_id: user.id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    for scope in &token_info.scopes {
        let role = RoleBinding {
            name: format!("scope:{scope}"),
            source: "buildkite".into(),
            permissions: vec![scope.clone()],
        };
        roles.push(role);

        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    let orgs = list_organizations(&client, token).await.unwrap_or_else(|err| {
        warn!("Buildkite access-map: organization enumeration failed: {err}");
        Vec::new()
    });

    for org in &orgs {
        let org_name = org
            .slug
            .clone()
            .or_else(|| org.name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name.clone(),
            permissions: token_info.scopes.clone(),
            risk: severity_to_str(if has_admin_scope(&token_info.scopes) {
                Severity::High
            } else {
                Severity::Medium
            })
            .to_string(),
            reason: "Organization accessible with this token".to_string(),
        });

        let pipelines = list_pipelines(&client, token, &org_name).await.unwrap_or_else(|err| {
            warn!("Buildkite access-map: pipeline enumeration for {org_name} failed: {err}");
            Vec::new()
        });

        for pipeline in &pipelines {
            let pipeline_name = pipeline
                .name
                .clone()
                .or_else(|| pipeline.slug.clone())
                .unwrap_or_else(|| "unknown_pipeline".to_string());

            let is_private = pipeline.visibility.as_deref() != Some("public");

            let (risk, perm_label) = if is_private {
                (Severity::Medium, "pipeline:private")
            } else {
                (Severity::Low, "pipeline:public")
            };

            resources.push(ResourceExposure {
                resource_type: "pipeline".into(),
                name: format!("{org_name}/{pipeline_name}"),
                permissions: vec![perm_label.to_string()],
                risk: severity_to_str(risk).to_string(),
                reason: if is_private {
                    "Accessible private pipeline".to_string()
                } else {
                    "Accessible public pipeline".to_string()
                },
            });
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&token_info.scopes, &orgs);

    if orgs.is_empty() && token_info.scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Buildkite account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any organizations or scopes".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "buildkite".into(),
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
            account_type: None,
            company: None,
            location: None,
            email: user.email.clone(),
            url: None,
            token_type: None,
            created_at: user.created_at.clone(),
            last_used_at: None,
            expires_at: None,
            user_id: user.id.or(token_info.uuid),
            scopes: token_info.scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_access_token(client: &Client, token: &str) -> Result<BuildkiteAccessToken> {
    let resp = client
        .get(format!("{BUILDKITE_API}/access-token"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to fetch access-token info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Buildkite access-map: access-token lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Buildkite access-map: invalid access-token JSON")
}

async fn fetch_user(client: &Client, token: &str) -> Result<BuildkiteUser> {
    let resp = client
        .get(format!("{BUILDKITE_API}/user"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to fetch user info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Buildkite access-map: user lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Buildkite access-map: invalid user JSON")
}

async fn list_organizations(client: &Client, token: &str) -> Result<Vec<BuildkiteOrganization>> {
    let resp = client
        .get(format!("{BUILDKITE_API}/organizations"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Buildkite access-map: failed to list organizations")?;

    if !resp.status().is_success() {
        warn!("Buildkite access-map: organization enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Buildkite access-map: invalid organizations JSON")
}

async fn list_pipelines(
    client: &Client,
    token: &str,
    org_slug: &str,
) -> Result<Vec<BuildkitePipeline>> {
    let mut pipelines = Vec::new();
    let mut page = 1;

    loop {
        let resp = client
            .get(format!(
                "{BUILDKITE_API}/organizations/{org_slug}/pipelines?per_page=100&page={page}"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .context("Buildkite access-map: failed to list pipelines")?;

        if !resp.status().is_success() {
            warn!("Buildkite access-map: pipeline enumeration failed with HTTP {}", resp.status());
            break;
        }

        let batch: Vec<BuildkitePipeline> =
            resp.json().await.context("Buildkite access-map: invalid pipelines JSON")?;

        if batch.is_empty() {
            break;
        }

        pipelines.extend(batch);
        page += 1;
    }

    Ok(pipelines)
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "write_organizations" | "write_teams" => ScopeRisk::Admin,
        "write_pipelines"
        | "write_builds"
        | "write_agents"
        | "write_artifacts"
        | "write_build_logs"
        | "write_notification_services"
        | "write_suites"
        | "write_test_plan"
        | "write_user"
        | "write_registries"
        | "write_clusters"
        | "write_cluster_tokens"
        | "write_rule" => ScopeRisk::Write,
        _ if scope.starts_with("write_") => ScopeRisk::Write,
        _ => ScopeRisk::Read,
    }
}

fn has_admin_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| matches!(s.as_str(), "write_organizations" | "write_teams"))
}

fn derive_severity(scopes: &[String], orgs: &[BuildkiteOrganization]) -> Severity {
    if has_admin_scope(scopes) {
        return Severity::High;
    }

    let has_write = scopes.iter().any(|s| s.starts_with("write_"));
    if has_write && !orgs.is_empty() {
        return Severity::Medium;
    }

    if !orgs.is_empty() {
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
