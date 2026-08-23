use anyhow::{Context, Result, anyhow};
use async_openai::{
    Client as AsyncOpenAiClient,
    config::OpenAIConfig,
    error::OpenAIError,
    traits::RequestOptionsBuilder,
    types::{
        admin::{invites::ProjectMembership, projects::Project},
        files::{OpenAIFile, OpenAIFilePurpose},
        finetuning::{FineTuningJob, FineTuningJobStatus},
        models::Model,
    },
};
use reqwest::{Client as HttpClient, StatusCode, header};
use serde::Deserialize;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const OPENAI_API: &str = "https://api.openai.com/v1";
const MAX_OPENAI_SERVICE_RESOURCES: usize = 50;
type OpenAiClient = AsyncOpenAiClient<OpenAIConfig>;

// ---------------------------------------------------------------------------
// Deserialization types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct OpenAiProjectModelPermissions {
    #[serde(default)]
    mode: String,
    #[serde(default)]
    model_ids: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct OpenAiHostedToolPermission {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
struct OpenAiHostedToolPermissions {
    #[serde(default)]
    file_search: OpenAiHostedToolPermission,
    #[serde(default)]
    web_search: OpenAiHostedToolPermission,
    #[serde(default)]
    image_generation: OpenAiHostedToolPermission,
    #[serde(default)]
    mcp: OpenAiHostedToolPermission,
    #[serde(default)]
    code_interpreter: OpenAiHostedToolPermission,
}

enum Inventory<T> {
    Accessible(Vec<T>),
    Denied,
}

#[derive(Debug, Deserialize)]
struct OpenAiAssistantsResponse {
    data: Vec<OpenAiAssistant>,
}

#[derive(Debug, Deserialize)]
struct OpenAiAssistant {
    id: String,
    name: Option<String>,
    model: String,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read OpenAI token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("OpenAI access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let http_client = HttpClient::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build OpenAI HTTP client")?;
    let config = OpenAIConfig::new().with_api_key(token);
    let client = OpenAiClient::with_config(config).with_http_client(http_client.clone());

    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let mut observed_access = Vec::new();

    let token_kind = detect_token_type(token);
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "openai".into(),
        permissions: vec![format!("token:{token_kind}")],
    });

    // OpenAI API reference: https://platform.openai.com/docs/api-reference/projects/list
    match list_projects(&client).await {
        Ok(Inventory::Accessible(projects)) => {
            observed_access.push("organization_projects:list".to_string());
            permissions.admin.push("organization_projects:list".to_string());
            for project in &projects {
                let project_name = project.name.clone().unwrap_or_else(|| project.id.clone());
                let risk = if project.status.as_deref() == Some("archived") {
                    Severity::Low
                } else {
                    Severity::High
                };
                resources.push(ResourceExposure {
                    resource_type: "project".into(),
                    name: project_name,
                    permissions: vec!["organization_project:read".to_string()],
                    risk: severity_to_str(risk).to_string(),
                    reason: "Project returned by the OpenAI organization administration API"
                        .to_string(),
                });

                if let Err(err) = enumerate_project_administration(
                    &client,
                    &http_client,
                    token,
                    &project.id,
                    &mut resources,
                    &mut permissions,
                )
                .await
                {
                    risk_notes.push(format!(
                        "Administrative inventory failed for project {}: {err}",
                        project.id
                    ));
                }
            }
        }
        Ok(Inventory::Denied) => {}
        Err(err) => risk_notes.push(format!("Project enumeration failed: {err}")),
    }

    match list_models(&client).await {
        Ok(Inventory::Accessible(models)) => {
            observed_access.push("models:list".to_string());
            permissions.read_only.push("models:list".to_string());
            let truncated = models.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for model in models.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let reason = format!("Model readable via this API key (owner: {})", model.owned_by);

                resources.push(ResourceExposure {
                    resource_type: "model".into(),
                    name: model.id,
                    permissions: vec!["model:read".to_string()],
                    risk: severity_to_str(Severity::Low).to_string(),
                    reason,
                });
            }
            if truncated {
                risk_notes.push(format!(
                    "Model resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
                ));
            }
        }
        Ok(Inventory::Denied) => {}
        Err(err) => risk_notes.push(format!("Model enumeration failed: {err}")),
    }

    match list_files(&client).await {
        Ok(Inventory::Accessible(files)) => {
            observed_access.push("files:list".to_string());
            permissions.read_only.push("files:list".to_string());
            let truncated = files.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for file in files.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let reason = format!(
                    "File visible to this API key (purpose: {})",
                    file_purpose_to_str(file.purpose)
                );

                resources.push(ResourceExposure {
                    resource_type: "file".into(),
                    name: file.filename,
                    permissions: vec!["file:metadata:read".to_string()],
                    risk: "medium".into(),
                    reason,
                });
            }
            if truncated {
                risk_notes.push(format!(
                    "File resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
                ));
            }
        }
        Ok(Inventory::Denied) => {}
        Err(err) => risk_notes.push(format!("File enumeration failed: {err}")),
    }

    match list_assistants(&client).await {
        Ok(Inventory::Accessible(assistants)) => {
            observed_access.push("assistants:list".to_string());
            permissions.read_only.push("assistants:list".to_string());
            let truncated = assistants.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for assistant in assistants.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let assistant_name = assistant.name.unwrap_or_else(|| assistant.id.clone());
                let reason =
                    format!("Assistant visible to this API key (model: {})", assistant.model);

                resources.push(ResourceExposure {
                    resource_type: "assistant".into(),
                    name: assistant_name,
                    permissions: vec!["assistant:read".to_string()],
                    risk: "low".into(),
                    reason,
                });
            }
            if truncated {
                risk_notes.push(format!(
                    "Assistant resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
                ));
            }
        }
        Ok(Inventory::Denied) => {}
        Err(err) => risk_notes.push(format!("Assistant enumeration failed: {err}")),
    }

    match list_fine_tuning_jobs(&client).await {
        Ok(Inventory::Accessible(jobs)) => {
            observed_access.push("fine_tuning_jobs:list".to_string());
            permissions.read_only.push("fine_tuning_jobs:list".to_string());
            let truncated = jobs.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for job in jobs.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let job_name = job.fine_tuned_model.clone().unwrap_or_else(|| job.id.clone());
                let reason = format!(
                    "Fine-tuning job visible to this API key (base model: {}, status: {})",
                    job.model,
                    fine_tuning_status_to_str(job.status)
                );

                resources.push(ResourceExposure {
                    resource_type: "fine_tuning_job".into(),
                    name: job_name,
                    permissions: vec!["fine_tuning_job:read".to_string()],
                    risk: "medium".into(),
                    reason,
                });
            }
            if truncated {
                risk_notes.push(format!(
                    "Fine-tuning resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
                ));
            }
        }
        Ok(Inventory::Denied) => {}
        Err(err) => risk_notes.push(format!("Fine-tuning job enumeration failed: {err}")),
    }

    // -- Identity --
    let identity_id = format!("openai_{token_kind}");

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: identity_id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "OpenAI account associated with this API key".to_string(),
        });
    }

    if observed_access.is_empty() {
        risk_notes.push("No documented OpenAI list endpoint was accessible to this key".into());
    }

    // -- Severity --
    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&permissions, &resources);

    Ok(AccessMapResult {
        cloud: "openai".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: token_kind.into(),
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
            name: None,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: None,
            url: Some("https://platform.openai.com/".into()),
            token_type: Some(token_kind.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes: observed_access,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/projects/list
async fn list_projects(client: &OpenAiClient) -> Result<Inventory<Project>> {
    match client.admin().projects().list().await {
        Ok(response) => Ok(Inventory::Accessible(response.data)),
        Err(err) if is_access_denied(&err) => Ok(Inventory::Denied),
        Err(err) => Err(err).context("OpenAI access-map: failed to list organization projects"),
    }
}

async fn enumerate_project_administration(
    client: &OpenAiClient,
    http_client: &HttpClient,
    token: &str,
    project_id: &str,
    resources: &mut Vec<ResourceExposure>,
    permissions: &mut PermissionSummary,
) -> Result<()> {
    let base = format!("{OPENAI_API}/organization/projects/{project_id}");
    let admin = client.admin();
    let projects = admin.projects();

    let api_keys = projects
        .api_keys(project_id)
        .query(&[("limit", "100"), ("owner_project_access", "any")])?
        .list()
        .await
        .with_context(|| format!("OpenAI access-map: failed to list API keys for {project_id}"))?;
    for key in api_keys.data {
        resources.push(ResourceExposure {
            resource_type: "project_api_key".into(),
            name: if key.name.is_empty() { key.id } else { key.name },
            permissions: vec!["project_api_key:read".into()],
            risk: "high".into(),
            reason: format!("Project API key visible to this admin key ({})", key.redacted_value),
        });
    }

    let service_accounts = projects
        .service_accounts(project_id)
        .query(&[("limit", "100")])?
        .list()
        .await
        .with_context(|| {
            format!("OpenAI access-map: failed to list service accounts for {project_id}")
        })?;
    for account in service_accounts.data {
        resources.push(ResourceExposure {
            resource_type: "service_account".into(),
            name: if account.name.is_empty() { account.id } else { account.name },
            permissions: vec![format!("project_role:{}", project_role_to_str(account.role))],
            risk: "high".into(),
            reason: "Service account assigned to this OpenAI project".into(),
        });
    }

    let users = projects
        .users(project_id)
        .query(&[("limit", "100")])?
        .list()
        .await
        .with_context(|| format!("OpenAI access-map: failed to list users for {project_id}"))?;
    for user in users.data {
        let role = project_role_to_str(user.role);
        resources.push(ResourceExposure {
            resource_type: "project_user".into(),
            name: user.name.unwrap_or(user.id),
            permissions: vec![format!("project_role:{role}")],
            risk: if role == "owner" { "high" } else { "medium" }.into(),
            reason: "User assigned to this OpenAI project".into(),
        });
    }

    let model_permissions: OpenAiProjectModelPermissions =
        get_admin_json(http_client, token, &format!("{base}/model_permissions")).await?;
    resources.push(ResourceExposure {
        resource_type: "model_policy".into(),
        name: project_id.to_string(),
        permissions: model_permissions.model_ids,
        risk: "medium".into(),
        reason: format!("Project model policy mode: {}", model_permissions.mode),
    });

    let tools: OpenAiHostedToolPermissions =
        get_admin_json(http_client, token, &format!("{base}/hosted_tool_permissions")).await?;
    let enabled_tools = [
        ("file_search", tools.file_search.enabled),
        ("web_search", tools.web_search.enabled),
        ("image_generation", tools.image_generation.enabled),
        ("mcp", tools.mcp.enabled),
        ("code_interpreter", tools.code_interpreter.enabled),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name.to_string()))
    .collect::<Vec<_>>();
    resources.push(ResourceExposure {
        resource_type: "hosted_tools".into(),
        name: project_id.to_string(),
        permissions: enabled_tools,
        risk: "medium".into(),
        reason: "Hosted tools enabled for this OpenAI project".into(),
    });

    let rate_limits =
        projects.rate_limits(project_id).query(&[("limit", "100")])?.list().await.with_context(
            || format!("OpenAI access-map: failed to list rate limits for {project_id}"),
        )?;
    for limit in rate_limits.data {
        resources.push(ResourceExposure {
            resource_type: "model_rate_limit".into(),
            name: if limit.model.is_empty() { "unknown_model".into() } else { limit.model },
            permissions: vec![
                format!("requests_per_minute:{}", limit.max_requests_per_1_minute),
                format!("tokens_per_minute:{}", limit.max_tokens_per_1_minute),
            ],
            risk: "low".into(),
            reason: "Configured project rate limit".into(),
        });
    }

    permissions.admin.push(format!("project:{project_id}:administration:read"));
    Ok(())
}

async fn get_admin_json<T: for<'de> Deserialize<'de>>(
    client: &HttpClient,
    token: &str,
    url: &str,
) -> Result<T> {
    let response = client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("OpenAI access-map: request failed for {url}"))?;
    if !response.status().is_success() {
        return Err(anyhow!("OpenAI access-map: {url} failed with HTTP {}", response.status()));
    }
    response.json().await.with_context(|| format!("OpenAI access-map: invalid JSON from {url}"))
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/models/list
async fn list_models(client: &OpenAiClient) -> Result<Inventory<Model>> {
    match client.models().list().await {
        Ok(response) => Ok(Inventory::Accessible(response.data)),
        Err(err) if is_access_denied(&err) => Ok(Inventory::Denied),
        Err(err) => Err(err).context("OpenAI access-map: failed to list models"),
    }
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/files/list
async fn list_files(client: &OpenAiClient) -> Result<Inventory<OpenAIFile>> {
    match client.files().list().await {
        Ok(response) => Ok(Inventory::Accessible(response.data)),
        Err(err) if is_access_denied(&err) => Ok(Inventory::Denied),
        Err(err) => Err(err).context("OpenAI access-map: failed to list files"),
    }
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/assistants/listAssistants
#[allow(deprecated)]
async fn list_assistants(client: &OpenAiClient) -> Result<Inventory<OpenAiAssistant>> {
    match client
        .assistants()
        .header("OpenAI-Beta", "assistants=v2")?
        .list_byot::<OpenAiAssistantsResponse>()
        .await
    {
        Ok(response) => Ok(Inventory::Accessible(response.data)),
        Err(err) if is_access_denied(&err) => Ok(Inventory::Denied),
        Err(err) => Err(err).context("OpenAI access-map: failed to list assistants"),
    }
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/fine-tuning/list
async fn list_fine_tuning_jobs(client: &OpenAiClient) -> Result<Inventory<FineTuningJob>> {
    match client.fine_tuning().list_paginated().await {
        Ok(response) => Ok(Inventory::Accessible(response.data)),
        Err(err) if is_access_denied(&err) => Ok(Inventory::Denied),
        Err(err) => Err(err).context("OpenAI access-map: failed to list fine-tuning jobs"),
    }
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

fn is_access_denied(err: &OpenAIError) -> bool {
    matches!(
        err,
        OpenAIError::ApiError(response)
            if matches!(
                response.status_code,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
            )
    )
}

fn project_role_to_str(role: ProjectMembership) -> &'static str {
    match role {
        ProjectMembership::Owner => "owner",
        ProjectMembership::Member => "member",
    }
}

fn file_purpose_to_str(purpose: OpenAIFilePurpose) -> &'static str {
    match purpose {
        OpenAIFilePurpose::Assistants => "assistants",
        OpenAIFilePurpose::AssistantsOutput => "assistants_output",
        OpenAIFilePurpose::Batch => "batch",
        OpenAIFilePurpose::BatchOutput => "batch_output",
        OpenAIFilePurpose::FineTune => "fine-tune",
        OpenAIFilePurpose::FineTuneResults => "fine-tune-results",
        OpenAIFilePurpose::Vision => "vision",
        OpenAIFilePurpose::UserData => "user_data",
    }
}

fn fine_tuning_status_to_str(status: FineTuningJobStatus) -> &'static str {
    match status {
        FineTuningJobStatus::ValidatingFiles => "validating_files",
        FineTuningJobStatus::Queued => "queued",
        FineTuningJobStatus::Running => "running",
        FineTuningJobStatus::Succeeded => "succeeded",
        FineTuningJobStatus::Failed => "failed",
        FineTuningJobStatus::Cancelled => "cancelled",
    }
}

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("sk-proj-") {
        "project_api_key"
    } else if token.starts_with("sk-svcacct-") {
        "service_account_api_key"
    } else if token.starts_with("sk-None-") {
        "legacy_api_key"
    } else {
        "api_key"
    }
}

fn derive_severity(permissions: &PermissionSummary, resources: &[ResourceExposure]) -> Severity {
    let sensitive_resources = resources
        .iter()
        .any(|resource| matches!(resource.resource_type.as_str(), "file" | "fine_tuning_job"));

    if !permissions.admin.is_empty() {
        return Severity::High;
    }
    if sensitive_resources || !permissions.risky.is_empty() {
        return Severity::Medium;
    }
    if !permissions.read_only.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::{PermissionSummary, ResourceExposure, Severity, derive_severity};

    #[test]
    fn observed_sensitive_resources_raise_severity_without_write_probes() {
        let resources = vec![ResourceExposure {
            resource_type: "file".into(),
            name: "example.jsonl".into(),
            permissions: vec!["file:metadata:read".into()],
            risk: "medium".into(),
            reason: "Visible file metadata".into(),
        }];
        assert!(matches!(
            derive_severity(&PermissionSummary::default(), &resources),
            Severity::Medium
        ));
    }

    #[test]
    fn organization_project_listing_is_high_severity() {
        let mut permissions = PermissionSummary::default();
        permissions.admin.push("organization_projects:list".into());
        assert!(matches!(derive_severity(&permissions, &[]), Severity::High));
    }
}
