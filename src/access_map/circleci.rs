use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const CIRCLECI_API: &str = "https://circleci.com";

#[derive(Deserialize)]
struct CircleCiUser {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    login: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct CircleCiCollaboration {
    #[serde(default)]
    vcs_type: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Deserialize)]
struct CircleCiPipelineResponse {
    #[serde(default)]
    items: Vec<CircleCiPipeline>,
}

#[derive(Deserialize)]
struct CircleCiPipeline {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    project_slug: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    created_at: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read CircleCI token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("CircleCI access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build CircleCI HTTP client")?;

    let user = fetch_user(&client, token).await?;

    let username = user
        .login
        .clone()
        .or_else(|| user.name.clone())
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "circleci_user".to_string());

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

    let collaborations = list_collaborations(&client, token).await.unwrap_or_else(|err| {
        warn!("CircleCI access-map: collaboration enumeration failed: {err}");
        Vec::new()
    });

    for collab in &collaborations {
        let org_name = collab
            .slug
            .clone()
            .or_else(|| collab.name.clone())
            .unwrap_or_else(|| "unknown_org".to_string());

        let vcs = collab.vcs_type.as_deref().unwrap_or("unknown");

        let role = RoleBinding {
            name: format!("collaborator:{org_name}"),
            source: "circleci".into(),
            permissions: vec![format!("vcs:{vcs}"), "collaboration:member".to_string()],
        };
        roles.push(role);

        permissions.risky.push(format!("collaboration:{org_name}"));

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name.clone(),
            permissions: vec![format!("vcs:{vcs}"), "collaboration:member".to_string()],
            risk: severity_to_str(if collaborations.len() > 3 {
                Severity::High
            } else {
                Severity::Medium
            })
            .to_string(),
            reason: format!("CircleCI organization collaboration via {vcs}"),
        });
    }

    let pipelines = list_pipelines(&client, token).await.unwrap_or_else(|err| {
        warn!("CircleCI access-map: pipeline enumeration failed: {err}");
        Vec::new()
    });

    for pipeline in &pipelines {
        let pipeline_name = pipeline
            .project_slug
            .clone()
            .or_else(|| pipeline.id.clone())
            .unwrap_or_else(|| "unknown_pipeline".to_string());

        resources.push(ResourceExposure {
            resource_type: "pipeline".into(),
            name: pipeline_name.clone(),
            permissions: vec!["pipeline:read".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Recent pipeline accessible with this token".to_string(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&collaborations);

    if collaborations.is_empty() && pipelines.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "CircleCI account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any collaborations or pipelines".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "circleci".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user.name.clone(),
            username: user.login.clone(),
            account_type: None,
            company: None,
            location: None,
            email: user.email.clone(),
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: user.id,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_user(client: &Client, token: &str) -> Result<CircleCiUser> {
    let resp = client
        .get(format!("{CIRCLECI_API}/api/v2/me"))
        .header("Circle-Token", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("CircleCI access-map: failed to fetch user info")?;

    if !resp.status().is_success() {
        return Err(anyhow!("CircleCI access-map: user lookup failed with HTTP {}", resp.status()));
    }

    resp.json().await.context("CircleCI access-map: invalid user JSON")
}

async fn list_collaborations(client: &Client, token: &str) -> Result<Vec<CircleCiCollaboration>> {
    let resp = client
        .get(format!("{CIRCLECI_API}/api/v2/me/collaborations"))
        .header("Circle-Token", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("CircleCI access-map: failed to list collaborations")?;

    if !resp.status().is_success() {
        warn!("CircleCI access-map: collaboration enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("CircleCI access-map: invalid collaborations JSON")
}

async fn list_pipelines(client: &Client, token: &str) -> Result<Vec<CircleCiPipeline>> {
    let resp = client
        .get(format!("{CIRCLECI_API}/api/v2/pipeline?mine=true"))
        .header("Circle-Token", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("CircleCI access-map: failed to list pipelines")?;

    if !resp.status().is_success() {
        warn!("CircleCI access-map: pipeline enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: CircleCiPipelineResponse =
        resp.json().await.context("CircleCI access-map: invalid pipelines JSON")?;
    Ok(body.items)
}

fn derive_severity(collaborations: &[CircleCiCollaboration]) -> Severity {
    if collaborations.len() > 5 {
        return Severity::High;
    }

    if !collaborations.is_empty() {
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
