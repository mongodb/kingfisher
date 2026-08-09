use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Method, StatusCode, header};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const OPENAI_API: &str = "https://api.openai.com/v1";
const MAX_OPENAI_SERVICE_RESOURCES: usize = 50;

// ---------------------------------------------------------------------------
// Deserialization types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiMe {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    role: Option<String>,
    #[serde(default)]
    orgs: Option<OpenAiOrgsData>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiOrgsData {
    #[serde(default)]
    data: Vec<OpenAiOrg>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiOrg {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    personal: Option<bool>,
    #[serde(default)]
    is_default: Option<bool>,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiProjectsResponse {
    #[serde(default)]
    data: Vec<OpenAiProject>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiProject {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    archived: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiModelsResponse {
    #[serde(default)]
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiModel {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    owned_by: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiFilesResponse {
    #[serde(default)]
    data: Vec<OpenAiFile>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiFile {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    purpose: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiAssistantsResponse {
    #[serde(default)]
    data: Vec<OpenAiAssistant>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiAssistant {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiFineTuningJobsResponse {
    #[serde(default)]
    data: Vec<OpenAiFineTuningJob>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiFineTuningJob {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    fine_tuned_model: Option<String>,
}

// ---------------------------------------------------------------------------
// Scope probing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ScopeResult {
    /// Human-readable scope name (e.g. "/v1/models").
    scope: &'static str,
    /// Individual endpoints covered by this scope.
    endpoints: Vec<&'static str>,
    /// "Read", "Write", or "Read & Write".
    permission: &'static str,
}

struct EndpointProbe {
    path: &'static str,
    method: Method,
    body: Option<serde_json::Value>,
}

/// Returns true when the status indicates the scope is **not** granted.
fn is_scope_denied(status: StatusCode) -> bool {
    status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED
}

async fn probe_endpoint(client: &Client, token: &str, probe: &EndpointProbe) -> bool {
    let url = format!("{OPENAI_API}{}", probe.path);
    let mut req = client
        .request(probe.method.clone(), &url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json");

    if let Some(body) = &probe.body {
        req = req.header(header::CONTENT_TYPE, "application/json").json(body);
    }

    match req.send().await {
        Ok(resp) => !is_scope_denied(resp.status()),
        Err(_) => false,
    }
}

async fn probe_api_scopes(client: &Client, token: &str) -> (Vec<ScopeResult>, bool) {
    let mut scopes = Vec::new();
    let mut any_denied = false;

    // -- /v1/models (Read) --
    let models_ok = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/models", method: Method::GET, body: None },
    )
    .await;
    if models_ok {
        scopes.push(ScopeResult {
            scope: "/v1/models",
            endpoints: vec!["/v1/models"],
            permission: "Read",
        });
    } else {
        any_denied = true;
    }

    // -- Model capabilities (Write) – one probe covers the whole scope --
    let chat_ok = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/chat/completions",
            method: Method::POST,
            body: Some(json!({"model": "_probe_"})),
        },
    )
    .await;
    if chat_ok {
        scopes.push(ScopeResult {
            scope: "/v1/model_capabilities",
            endpoints: vec![
                "/v1/audio",
                "/v1/chat/completions",
                "/v1/embeddings",
                "/v1/images",
                "/v1/moderations",
            ],
            permission: "Write",
        });
    } else {
        any_denied = true;
    }

    // -- /v1/assistants (Read & Write) --
    let assist_read = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/assistants", method: Method::GET, body: None },
    )
    .await;
    let assist_write = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/assistants",
            method: Method::POST,
            body: Some(json!({"model": "_probe_"})),
        },
    )
    .await;
    push_rw_scope(
        &mut scopes,
        &mut any_denied,
        "/v1/assistants",
        &["/v1/assistants"],
        assist_read,
        assist_write,
    );

    // -- /v1/threads (Read & Write) – read via fake thread GET --
    let threads_read = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/threads/thread_00000000000000000000000000",
            method: Method::GET,
            body: None,
        },
    )
    .await;
    let threads_write = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/threads",
            method: Method::POST,
            body: Some(json!({"metadata": {"_probe": "1"}})),
        },
    )
    .await;
    push_rw_scope(
        &mut scopes,
        &mut any_denied,
        "/v1/threads",
        &["/v1/threads"],
        threads_read,
        threads_write,
    );

    // -- /v1/fine_tuning (Read & Write) --
    let ft_read = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/fine_tuning/jobs", method: Method::GET, body: None },
    )
    .await;
    let ft_write = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/fine_tuning/jobs",
            method: Method::POST,
            body: Some(json!({"model": "_probe_", "training_file": "_probe_"})),
        },
    )
    .await;
    push_rw_scope(
        &mut scopes,
        &mut any_denied,
        "/v1/fine_tuning",
        &["/v1/fine_tuning"],
        ft_read,
        ft_write,
    );

    // -- /v1/files (Read & Write) – write needs multipart so only probe read --
    let files_read = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/files", method: Method::GET, body: None },
    )
    .await;
    push_rw_scope(
        &mut scopes,
        &mut any_denied,
        "/v1/files",
        &["/v1/files"],
        files_read,
        files_read,
    );

    // -- /v1/evals (Read & Write) --
    let evals_read = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/evals", method: Method::GET, body: None },
    )
    .await;
    let evals_write = probe_endpoint(
        client,
        token,
        &EndpointProbe { path: "/evals", method: Method::POST, body: Some(json!({})) },
    )
    .await;
    push_rw_scope(
        &mut scopes,
        &mut any_denied,
        "/v1/evals",
        &["/v1/evals"],
        evals_read,
        evals_write,
    );

    // -- /v1/responses (Write) --
    let responses_ok = probe_endpoint(
        client,
        token,
        &EndpointProbe {
            path: "/responses",
            method: Method::POST,
            body: Some(json!({"model": "_probe_", "input": "x"})),
        },
    )
    .await;
    if responses_ok {
        scopes.push(ScopeResult {
            scope: "/v1/responses",
            endpoints: vec!["/v1/responses"],
            permission: "Write",
        });
    } else {
        any_denied = true;
    }

    (scopes, any_denied)
}

fn push_rw_scope(
    scopes: &mut Vec<ScopeResult>,
    any_denied: &mut bool,
    scope: &'static str,
    endpoints: &[&'static str],
    read: bool,
    write: bool,
) {
    let permission = match (read, write) {
        (true, true) => "Read & Write",
        (true, false) => "Read",
        (false, true) => "Write",
        (false, false) => {
            *any_denied = true;
            return;
        }
    };
    if !read || !write {
        *any_denied = true;
    }
    scopes.push(ScopeResult { scope, endpoints: endpoints.to_vec(), permission });
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
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build OpenAI HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();

    // -- Identity & organizations (/v1/me) --
    let me = fetch_me(&client, token).await.unwrap_or_else(|err| {
        warn!("OpenAI access-map: /me lookup failed: {err}");
        risk_notes
            .push(format!("Identity lookup failed (key may be a restricted project key): {err}"));
        OpenAiMe::default()
    });

    let token_kind = detect_token_type(token);
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "openai".into(),
        permissions: vec![format!("token:{token_kind}")],
    });

    let orgs = me.orgs.as_ref().map(|o| o.data.clone()).unwrap_or_default();

    for org in &orgs {
        let org_id = org.id.as_deref().unwrap_or("unknown");
        let org_title = org.title.as_deref().or(org.name.as_deref()).unwrap_or("unknown");
        let org_role = org.role.as_deref().unwrap_or("unknown");
        let is_default = org.is_default.unwrap_or(false);
        let is_personal = org.personal.unwrap_or(false);

        let label =
            if is_personal { format!("{org_title} (Personal)") } else { org_title.to_string() };

        let risk = match org_role {
            "owner" => Severity::High,
            "reader" => Severity::Low,
            _ => Severity::Medium,
        };

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: format!("{org_id} — {label}"),
            permissions: vec![format!("role:{org_role}"), format!("default:{is_default}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("Organization membership with {org_role} role"),
        });

        if org_role == "owner" {
            permissions.admin.push(format!("org:{org_id}:owner"));
        }
    }

    // -- Projects --
    let projects = list_projects(&client, token).await.unwrap_or_else(|err| {
        warn!("OpenAI access-map: project enumeration failed: {err}");
        risk_notes.push(format!("Project enumeration failed: {err}"));
        Vec::new()
    });

    for project in &projects {
        let project_name = project
            .name
            .clone()
            .or_else(|| project.id.clone())
            .unwrap_or_else(|| "unknown_project".to_string());
        let risk = if project.archived { Severity::Low } else { Severity::Medium };
        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: project_name,
            permissions: vec!["project:read".to_string()],
            risk: severity_to_str(risk).to_string(),
            reason: "Project visible to this OpenAI key".to_string(),
        });
    }

    if !projects.is_empty() {
        permissions.read_only.push("projects:list".to_string());
    }

    // -- API key scope probing --
    let (scope_results, is_restricted) = probe_api_scopes(&client, token).await;

    if is_restricted {
        risk_notes.push("Restricted API key — limited permissions available".into());
    } else if !scope_results.is_empty() {
        risk_notes.push("Unrestricted API key — all scopes available".into());
    }

    let mut scope_labels = Vec::new();
    let has_model_capabilities = scope_results.iter().any(|s| s.scope == "/v1/model_capabilities");

    for sr in &scope_results {
        let scope_tag =
            format!("{}:{}", sr.scope, sr.permission.to_lowercase().replace(" & ", "_"));
        scope_labels.push(scope_tag.clone());

        for ep in &sr.endpoints {
            resources.push(ResourceExposure {
                resource_type: "api_scope".into(),
                name: ep.to_string(),
                permissions: vec![sr.permission.to_string()],
                risk: if sr.permission.contains("Write") { "medium".into() } else { "low".into() },
                reason: format!("Endpoint accessible under scope {}", sr.scope),
            });
        }

        match sr.permission {
            "Read" => permissions.read_only.push(scope_tag),
            "Write" => permissions.risky.push(scope_tag),
            "Read & Write" => {
                permissions.read_only.push(format!("{}:read", sr.scope));
                permissions.risky.push(format!("{}:write", sr.scope));
            }
            _ => {}
        }
    }

    if scope_has_read_access(&scope_results, "/v1/models") {
        let models = list_models(&client, token).await.unwrap_or_else(|err| {
            warn!("OpenAI access-map: model enumeration failed: {err}");
            risk_notes.push(format!("Model enumeration failed: {err}"));
            Vec::new()
        });

        let truncated = models.len() > MAX_OPENAI_SERVICE_RESOURCES;
        for model in models.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
            let model_id = model.id.unwrap_or_else(|| "unknown_model".to_string());
            let reason = match model.owned_by.as_deref() {
                Some(owner) if !owner.is_empty() => {
                    format!("Model readable via this API key (owner: {owner})")
                }
                _ => "Model readable via this API key".to_string(),
            };

            resources.push(ResourceExposure {
                resource_type: "model".into(),
                name: model_id,
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

    if scope_has_read_access(&scope_results, "/v1/files") {
        let files = list_files(&client, token).await.unwrap_or_else(|err| {
            warn!("OpenAI access-map: file enumeration failed: {err}");
            risk_notes.push(format!("File enumeration failed: {err}"));
            Vec::new()
        });

        let truncated = files.len() > MAX_OPENAI_SERVICE_RESOURCES;
        let can_write_files = scope_has_write_access(&scope_results, "/v1/files");

        for file in files.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
            let file_name =
                file.filename.or(file.id.clone()).unwrap_or_else(|| "unknown_file".to_string());
            let mut file_permissions = vec!["file:read".to_string()];
            if can_write_files {
                file_permissions.push("file:write".to_string());
            }

            let reason = match (file.purpose.as_deref(), file.status.as_deref()) {
                (Some(purpose), Some(status)) if !purpose.is_empty() && !status.is_empty() => {
                    format!("File visible to this API key (purpose: {purpose}, status: {status})")
                }
                (Some(purpose), _) if !purpose.is_empty() => {
                    format!("File visible to this API key (purpose: {purpose})")
                }
                _ => "File visible to this API key".to_string(),
            };

            resources.push(ResourceExposure {
                resource_type: "file".into(),
                name: file_name,
                permissions: file_permissions,
                risk: if can_write_files { "high".into() } else { "medium".into() },
                reason,
            });
        }
        if truncated {
            risk_notes.push(format!(
                "File resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
            ));
        }
    }

    if scope_has_read_access(&scope_results, "/v1/assistants") {
        let assistants = list_assistants(&client, token).await.unwrap_or_else(|err| {
            warn!("OpenAI access-map: assistant enumeration failed: {err}");
            risk_notes.push(format!("Assistant enumeration failed: {err}"));
            Vec::new()
        });

        let truncated = assistants.len() > MAX_OPENAI_SERVICE_RESOURCES;
        let can_write_assistants = scope_has_write_access(&scope_results, "/v1/assistants");

        for assistant in assistants.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
            let assistant_name = assistant
                .name
                .or(assistant.id.clone())
                .unwrap_or_else(|| "unknown_assistant".to_string());
            let mut assistant_permissions = vec!["assistant:read".to_string()];
            if can_write_assistants {
                assistant_permissions.push("assistant:write".to_string());
            }

            let reason = match assistant.model.as_deref() {
                Some(model) if !model.is_empty() => {
                    format!("Assistant visible to this API key (model: {model})")
                }
                _ => "Assistant visible to this API key".to_string(),
            };

            resources.push(ResourceExposure {
                resource_type: "assistant".into(),
                name: assistant_name,
                permissions: assistant_permissions,
                risk: if can_write_assistants { "medium".into() } else { "low".into() },
                reason,
            });
        }
        if truncated {
            risk_notes.push(format!(
                "Assistant resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
            ));
        }
    }

    if scope_has_read_access(&scope_results, "/v1/fine_tuning") {
        let jobs = list_fine_tuning_jobs(&client, token).await.unwrap_or_else(|err| {
            warn!("OpenAI access-map: fine-tuning job enumeration failed: {err}");
            risk_notes.push(format!("Fine-tuning job enumeration failed: {err}"));
            Vec::new()
        });

        let truncated = jobs.len() > MAX_OPENAI_SERVICE_RESOURCES;
        let can_write_fine_tuning = scope_has_write_access(&scope_results, "/v1/fine_tuning");

        for job in jobs.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
            let job_name = job
                .fine_tuned_model
                .clone()
                .or(job.id.clone())
                .unwrap_or_else(|| "unknown_fine_tuning_job".to_string());
            let mut job_permissions = vec!["fine_tuning:read".to_string()];
            if can_write_fine_tuning {
                job_permissions.push("fine_tuning:write".to_string());
            }

            let reason = match (job.model.as_deref(), job.status.as_deref()) {
                (Some(model), Some(status)) if !model.is_empty() && !status.is_empty() => {
                    format!(
                        "Fine-tuning job visible to this API key (base model: {model}, status: {status})"
                    )
                }
                (Some(model), _) if !model.is_empty() => {
                    format!("Fine-tuning job visible to this API key (base model: {model})")
                }
                _ => "Fine-tuning job visible to this API key".to_string(),
            };

            resources.push(ResourceExposure {
                resource_type: "fine_tuning_job".into(),
                name: job_name,
                permissions: job_permissions,
                risk: if can_write_fine_tuning { "high".into() } else { "medium".into() },
                reason,
            });
        }
        if truncated {
            risk_notes.push(format!(
                "Fine-tuning resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
            ));
        }
    }

    // -- Identity --
    let identity_id = me
        .email
        .clone()
        .or_else(|| me.name.clone())
        .or_else(|| me.id.clone())
        .unwrap_or_else(|| "openai_api_key".to_string());

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: identity_id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "OpenAI account associated with this API key".to_string(),
        });
    }

    // -- Risk notes --
    if has_model_capabilities {
        risk_notes.push(
            "Key can make inference requests (chat completions, embeddings, images, audio, moderations)"
                .into(),
        );
    }
    if scope_results.iter().any(|s| s.scope == "/v1/fine_tuning" && s.permission.contains("Write"))
    {
        risk_notes
            .push("Key can create fine-tuning jobs (potential training data exfiltration)".into());
    }
    if scope_results.iter().any(|s| s.scope == "/v1/files" && s.permission.contains("Write")) {
        risk_notes.push("Key can upload files".into());
    }

    // -- Severity --
    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&permissions, &orgs, has_model_capabilities);

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "openai".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: token_kind.into(),
            project: None,
            tenant: None,
            account_id: me.id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: me.name,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: me.email,
            url: Some("https://platform.openai.com/".into()),
            token_type: Some(token_kind.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: me.id,
            scopes: scope_labels,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async fn fetch_me(client: &Client, token: &str) -> Result<OpenAiMe> {
    let resp = client
        .get(format!("{OPENAI_API}/me"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to query /me")?;

    if !resp.status().is_success() {
        return Err(anyhow!("OpenAI access-map: /me failed with HTTP {}", resp.status()));
    }

    resp.json().await.context("OpenAI access-map: invalid /me JSON")
}

async fn list_projects(client: &Client, token: &str) -> Result<Vec<OpenAiProject>> {
    let resp = client
        .get(format!("{OPENAI_API}/organization/projects"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list organization projects")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiProjectsResponse =
                resp.json().await.context("OpenAI access-map: invalid projects JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: project listing unauthorized (401)"))
        }
        status => Err(anyhow!("OpenAI access-map: project listing failed with HTTP {status}")),
    }
}

async fn list_models(client: &Client, token: &str) -> Result<Vec<OpenAiModel>> {
    let resp = client
        .get(format!("{OPENAI_API}/models"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list models")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiModelsResponse =
                resp.json().await.context("OpenAI access-map: invalid models JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: model listing unauthorized (401)"))
        }
        status => Err(anyhow!("OpenAI access-map: model listing failed with HTTP {status}")),
    }
}

async fn list_files(client: &Client, token: &str) -> Result<Vec<OpenAiFile>> {
    let resp = client
        .get(format!("{OPENAI_API}/files"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list files")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiFilesResponse =
                resp.json().await.context("OpenAI access-map: invalid files JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: file listing unauthorized (401)"))
        }
        status => Err(anyhow!("OpenAI access-map: file listing failed with HTTP {status}")),
    }
}

async fn list_assistants(client: &Client, token: &str) -> Result<Vec<OpenAiAssistant>> {
    let resp = client
        .get(format!("{OPENAI_API}/assistants"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .header("OpenAI-Beta", "assistants=v2")
        .send()
        .await
        .context("OpenAI access-map: failed to list assistants")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiAssistantsResponse =
                resp.json().await.context("OpenAI access-map: invalid assistants JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: assistant listing unauthorized (401)"))
        }
        status => Err(anyhow!("OpenAI access-map: assistant listing failed with HTTP {status}")),
    }
}

async fn list_fine_tuning_jobs(client: &Client, token: &str) -> Result<Vec<OpenAiFineTuningJob>> {
    let resp = client
        .get(format!("{OPENAI_API}/fine_tuning/jobs"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list fine-tuning jobs")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiFineTuningJobsResponse =
                resp.json().await.context("OpenAI access-map: invalid fine-tuning jobs JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: fine-tuning job listing unauthorized (401)"))
        }
        status => {
            Err(anyhow!("OpenAI access-map: fine-tuning job listing failed with HTTP {status}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

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

fn scope_has_read_access(scopes: &[ScopeResult], scope: &str) -> bool {
    scopes.iter().any(|sr| sr.scope == scope && matches!(sr.permission, "Read" | "Read & Write"))
}

fn scope_has_write_access(scopes: &[ScopeResult], scope: &str) -> bool {
    scopes.iter().any(|sr| sr.scope == scope && matches!(sr.permission, "Write" | "Read & Write"))
}

fn derive_severity(
    permissions: &PermissionSummary,
    orgs: &[OpenAiOrg],
    has_model_capabilities: bool,
) -> Severity {
    let is_org_owner = orgs.iter().any(|o| o.role.as_deref() == Some("owner"));

    if !permissions.admin.is_empty() || is_org_owner {
        return Severity::High;
    }
    if has_model_capabilities || !permissions.risky.is_empty() {
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
    use super::{ScopeResult, scope_has_read_access, scope_has_write_access};

    #[test]
    fn scope_helpers_track_read_and_write_access_independently() {
        let scopes = vec![
            ScopeResult { scope: "/v1/models", endpoints: vec!["/v1/models"], permission: "Read" },
            ScopeResult {
                scope: "/v1/files",
                endpoints: vec!["/v1/files"],
                permission: "Read & Write",
            },
            ScopeResult {
                scope: "/v1/responses",
                endpoints: vec!["/v1/responses"],
                permission: "Write",
            },
        ];

        assert!(scope_has_read_access(&scopes, "/v1/models"));
        assert!(!scope_has_write_access(&scopes, "/v1/models"));
        assert!(scope_has_read_access(&scopes, "/v1/files"));
        assert!(scope_has_write_access(&scopes, "/v1/files"));
        assert!(!scope_has_read_access(&scopes, "/v1/responses"));
        assert!(scope_has_write_access(&scopes, "/v1/responses"));
    }
}
