use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, SecondsFormat};
use kingfisher_scanner::validation::limits::{NetworkLimits, ResourceTimeout};
use reqwest::{Client as HttpClient, StatusCode, header};
use serde::{Deserialize, de::DeserializeOwned};
use tracing::debug;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const OPENAI_API: &str = "https://api.openai.com/v1";
const MAX_OPENAI_SERVICE_RESOURCES: usize = 50;
const MAX_OPENAI_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const KEY_USAGE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const KEY_USAGE_SOURCE: &str = "OpenAI API key metadata";
const ADMIN_KEY_OBJECT: &str = "organization.admin_api_key";
const PROJECT_KEY_OBJECT: &str = "organization.project.api_key";

struct OpenAiClient {
    http_client: HttpClient,
    api_base: String,
    headers: header::HeaderMap,
}

impl OpenAiClient {
    fn new(
        http_client: HttpClient,
        token: &str,
        api_base: &str,
        organization: &str,
        project: &str,
    ) -> Result<Self> {
        let mut headers = header::HeaderMap::new();
        let mut authorization = header::HeaderValue::from_str(&format!("Bearer {token}"))
            .context("Invalid OpenAI authorization header")?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        for (name, value) in [("openai-organization", organization), ("openai-project", project)] {
            if !value.is_empty() {
                headers.insert(
                    name,
                    header::HeaderValue::from_str(value)
                        .with_context(|| format!("Invalid OpenAI {name} header"))?,
                );
            }
        }
        Ok(Self { http_client, api_base: api_base.trim_end_matches('/').to_string(), headers })
    }

    // Only metadata GETs: never probe write permissions, download content, or follow cursors.
    async fn get<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<Option<T>> {
        let mut request = self
            .http_client
            .get(format!("{}{path}", self.api_base))
            .headers(self.headers.clone())
            .resource_timeout(Duration::from_secs(30));
        if !query.is_empty() {
            request = request.query(query);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut response = request.send().await.context("OpenAI metadata request failed")?;
        let status = response.status();
        if matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            return Ok(None);
        }
        if !status.is_success() {
            // Error bodies may be HTML or contain sensitive data; classify by status only.
            return Err(anyhow!("OpenAI metadata request failed (HTTP {status})"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.context("Failed to read OpenAI response")? {
            if !NetworkLimits::current().unlimited_response
                && body.len().saturating_add(chunk.len()) > MAX_OPENAI_RESPONSE_BYTES
            {
                return Err(anyhow!("OpenAI metadata response exceeded size limit"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).context("Failed to parse OpenAI metadata response").map(Some)
    }
}

// ---------------------------------------------------------------------------
// Deserialization types: retain only fields consumed by the read-only inventory.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OpenAiListResponse<T> {
    data: Vec<T>,
    /// Single-page administrative listings report, rather than follow, later pages.
    #[serde(default)]
    has_more: bool,
}

#[derive(Debug, Deserialize)]
struct Project {
    id: String,
    name: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Model {
    id: String,
    owned_by: String,
}

// Enumerated API values are kept as strings: OpenAI adds new values (for example,
// file purposes and roles) over time, and one unknown value must not make a whole
// inventory page fail to parse.
#[derive(Debug, Deserialize)]
struct OpenAIFile {
    filename: String,
    purpose: String,
}

#[derive(Debug, Deserialize)]
struct FineTuningJob {
    id: String,
    fine_tuned_model: Option<String>,
    model: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiProjectApiKey {
    id: String,
    name: String,
    redacted_value: String,
}

#[derive(Deserialize)]
struct OpenAiKeyUsage {
    id: String,
    object: String,
    redacted_value: String,
    last_used_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct OpenAiServiceAccount {
    id: String,
    name: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiProjectUser {
    id: String,
    name: Option<String>,
    role: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiRateLimit {
    model: String,
    max_requests_per_1_minute: i64,
    max_tokens_per_1_minute: i64,
}

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
struct OpenAiAssistant {
    id: String,
    name: Option<String>,
    model: String,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!(
            "OpenAI access-map requires a credential file or a validated token from scan results"
        )
    })?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read OpenAI credential from {}", path.display()))?;
    let raw = raw.trim();
    if !raw.starts_with('{') {
        return map_access_from_token(raw).await;
    }

    let credential: OpenAiCredentialFile = serde_json::from_str(raw).map_err(|_| {
        anyhow!("Invalid OpenAI credential JSON; expected a token and optional audit fields")
    })?;
    map_access_from_token_at(credential.token.trim(), credential.key_lookup()?, OPENAI_API).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiCredentialFile {
    token: String,
    key_id: Option<String>,
    project_id: Option<String>,
    audit_token: Option<String>,
}

struct OpenAiKeyLookup<'a> {
    audit_token: &'a str,
    key_id: &'a str,
    path: String,
    object: &'static str,
}

impl OpenAiCredentialFile {
    fn key_lookup(&self) -> Result<Option<OpenAiKeyLookup<'_>>> {
        if self.token.trim().is_empty() {
            return Err(anyhow!("OpenAI credential JSON requires a non-empty token"));
        }
        let (audit_token, key_id, project_id) = (
            self.audit_token.as_deref().map(str::trim),
            self.key_id.as_deref(),
            self.project_id.as_deref(),
        );
        if audit_token.is_none() && key_id.is_none() && project_id.is_none() {
            return Ok(None);
        }
        let audit_token = audit_token
            .filter(|token| token.starts_with("sk-admin-") && token.len() > "sk-admin-".len())
            .context("OpenAI key history requires an organization Admin API key as audit_token")?;
        if audit_token == self.token.trim() {
            return Err(anyhow!(
                "OpenAI key history requires an audit_token distinct from the target token"
            ));
        }
        let key_id = key_id
            .filter(|id| valid_lookup_id(id, "key_"))
            .context("OpenAI key history requires a valid key_id")?;
        let (path, object) = if detect_token_type(self.token.trim()) == "admin_api_key" {
            if project_id.is_some() {
                return Err(anyhow!("OpenAI admin key history must omit project_id"));
            }
            (format!("/organization/admin_api_keys/{key_id}"), ADMIN_KEY_OBJECT)
        } else {
            let project_id = project_id
                .filter(|id| valid_lookup_id(id, "proj_"))
                .context("OpenAI project key history requires a valid project_id")?;
            (format!("/organization/projects/{project_id}/api_keys/{key_id}"), PROJECT_KEY_OBJECT)
        };
        Ok(Some(OpenAiKeyLookup { audit_token, key_id, path, object }))
    }
}

fn valid_lookup_id(id: &str, prefix: &str) -> bool {
    id.len() <= 256
        && id.strip_prefix(prefix).is_some_and(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

fn http_client_builder() -> reqwest::ClientBuilder {
    HttpClient::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_at(token, None, OPENAI_API).await
}

async fn map_access_from_token_at(
    token: &str,
    key_lookup: Option<OpenAiKeyLookup<'_>>,
    api_base: &str,
) -> Result<AccessMapResult> {
    let http_client =
        http_client_builder().build().context("Failed to build OpenAI HTTP client")?;
    // The token was found by a scan, so it belongs to someone else's organization.
    // Never apply the operator's own OPENAI_BASE_URL/OPENAI_ORG_ID/OPENAI_PROJECT_ID:
    // they would send the key to another endpoint or add mismatched headers that
    // OpenAI rejects, making an accessible key look denied.
    let client = OpenAiClient::new(http_client.clone(), token, api_base, "", "")?;
    let last_used_at = match key_lookup {
        Some(lookup) => fetch_key_last_used(http_client, api_base, token, lookup).await,
        None => None,
    };

    let mut result = map_access_with_client(&client, token).await?;
    if let Some(timestamp) = last_used_at
        && let Some(details) = &mut result.token_details
    {
        details.last_used_at = Some(timestamp);
        result
            .provider_metadata
            .get_or_insert_with(ProviderMetadata::default)
            .credential_last_used_source = Some(KEY_USAGE_SOURCE.into());
    }
    Ok(result)
}

async fn fetch_key_last_used(
    http_client: HttpClient,
    api_base: &str,
    token: &str,
    lookup: OpenAiKeyLookup<'_>,
) -> Option<String> {
    // Use the explicit auditor for this fixed-origin lookup only. The target credential
    // is reserved for inventory probes so they cannot contaminate the returned snapshot.
    let client = OpenAiClient::new(http_client, lookup.audit_token, api_base, "", "")
        .inspect_err(|_| debug!("OpenAI access-map: invalid key activity audit header"))
        .ok()?;
    let key = match tokio::time::timeout(
        KEY_USAGE_LOOKUP_TIMEOUT,
        client.get::<OpenAiKeyUsage>(&lookup.path, &[], &[]),
    )
    .await
    {
        Ok(Ok(Some(key))) => key,
        _ => {
            debug!("OpenAI access-map: key activity lookup unavailable");
            return None;
        }
    };
    let matching_redaction =
        key.redacted_value.split_once("...").is_some_and(|(prefix, suffix)| {
            !prefix.is_empty()
                && !suffix.is_empty()
                && token.starts_with(prefix)
                && token.ends_with(suffix)
        });
    if key.id != lookup.key_id || key.object != lookup.object || !matching_redaction {
        debug!("OpenAI access-map: activity record does not match supplied key metadata");
        return None;
    }
    let date = DateTime::from_timestamp(key.last_used_at?, 0)?;
    Some(date.to_rfc3339_opts(SecondsFormat::Secs, true))
}

async fn map_access_with_client(client: &OpenAiClient, token: &str) -> Result<AccessMapResult> {
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
    match list_projects(client).await {
        Ok(Some(OpenAiListResponse { data: projects, has_more })) => {
            observed_access.push("organization_projects:list".to_string());
            permissions.admin.push("organization_projects:list".to_string());
            if has_more {
                risk_notes.push(format!(
                    "Project list truncated to the first {} projects returned by the API",
                    projects.len()
                ));
            }
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
                    client,
                    &project.id,
                    &mut resources,
                    &mut permissions,
                    &mut risk_notes,
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
        Ok(None) => {}
        Err(err) => risk_notes.push(format!("Project enumeration failed: {err}")),
    }

    match list_models(client).await {
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

    match list_files(client).await {
        Ok(Inventory::Accessible(files)) => {
            observed_access.push("files:list".to_string());
            permissions.read_only.push("files:list".to_string());
            let truncated = files.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for file in files.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let reason = format!("File visible to this API key (purpose: {})", file.purpose);

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

    match list_assistants(client).await {
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

    match list_fine_tuning_jobs(client).await {
        Ok(Inventory::Accessible(jobs)) => {
            observed_access.push("fine_tuning_jobs:list".to_string());
            permissions.read_only.push("fine_tuning_jobs:list".to_string());
            let truncated = jobs.len() > MAX_OPENAI_SERVICE_RESOURCES;
            for job in jobs.into_iter().take(MAX_OPENAI_SERVICE_RESOURCES) {
                let job_name = job.fine_tuned_model.clone().unwrap_or_else(|| job.id.clone());
                let reason = format!(
                    "Fine-tuning job visible to this API key (base model: {}, status: {})",
                    job.model, job.status
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

async fn list_inventory<T: DeserializeOwned>(
    client: &OpenAiClient,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> Result<Inventory<T>> {
    match client.get::<OpenAiListResponse<T>>(path, query, headers).await? {
        Some(response) => Ok(Inventory::Accessible(response.data)),
        None => Ok(Inventory::Denied),
    }
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/projects/list
async fn list_projects(client: &OpenAiClient) -> Result<Option<OpenAiListResponse<Project>>> {
    client
        .get(PROJECTS_PATH, &[], &[])
        .await
        .context("OpenAI access-map: failed to list organization projects")
}

const PROJECTS_PATH: &str = "/organization/projects";

/// Note a project sub-inventory that has more entries than its single page shows.
fn note_truncated_page<T>(
    page: &Option<OpenAiListResponse<T>>,
    project_id: &str,
    kind: &str,
    risk_notes: &mut Vec<String>,
) {
    if let Some(page) = page
        && page.has_more
    {
        risk_notes.push(format!(
            "Project {project_id} {kind} list truncated to the first {} entries",
            page.data.len()
        ));
    }
}

/// Records a failed project sub-inventory as a risk note and continues with the
/// rest. A denied (`None`) or failed inventory marks administration as incomplete.
fn tolerate<T>(
    result: Result<Option<T>>,
    complete: &mut bool,
    risk_notes: &mut Vec<String>,
) -> Option<T> {
    match result {
        Ok(value) => {
            *complete &= value.is_some();
            value
        }
        Err(error) => {
            *complete = false;
            risk_notes.push(format!("{error:#}"));
            None
        }
    }
}

async fn enumerate_project_administration(
    client: &OpenAiClient,
    project_id: &str,
    resources: &mut Vec<ResourceExposure>,
    permissions: &mut PermissionSummary,
    risk_notes: &mut Vec<String>,
) -> Result<()> {
    let base = format!("{PROJECTS_PATH}/{project_id}");
    let api_keys = client
        .get::<OpenAiListResponse<OpenAiProjectApiKey>>(
            &format!("{base}/api_keys"),
            &[("limit", "100"), ("owner_project_access", "any")],
            &[],
        )
        .await
        .with_context(|| format!("OpenAI access-map: failed to list API keys for {project_id}"));
    // A denied or failed inventory (rate limit, server error, unexpected response) must
    // not hide the project's other metadata, nor imply full administration access.
    let mut complete = true;
    let api_keys = tolerate(api_keys, &mut complete, risk_notes);
    note_truncated_page(&api_keys, project_id, "API key", risk_notes);
    for key in api_keys.into_iter().flat_map(|page| page.data) {
        resources.push(ResourceExposure {
            resource_type: "project_api_key".into(),
            name: if key.name.is_empty() { key.id } else { key.name },
            permissions: vec!["project_api_key:read".into()],
            risk: "high".into(),
            reason: format!("Project API key visible to this admin key ({})", key.redacted_value),
        });
    }

    let service_accounts = client
        .get::<OpenAiListResponse<OpenAiServiceAccount>>(
            &format!("{base}/service_accounts"),
            &[("limit", "100")],
            &[],
        )
        .await
        .with_context(|| {
            format!("OpenAI access-map: failed to list service accounts for {project_id}")
        });
    let service_accounts = tolerate(service_accounts, &mut complete, risk_notes);
    note_truncated_page(&service_accounts, project_id, "service account", risk_notes);
    for account in service_accounts.into_iter().flat_map(|page| page.data) {
        resources.push(ResourceExposure {
            resource_type: "service_account".into(),
            name: if account.name.is_empty() { account.id } else { account.name },
            permissions: vec![format!("project_role:{}", account.role)],
            risk: "high".into(),
            reason: "Service account assigned to this OpenAI project".into(),
        });
    }

    let users = client
        .get::<OpenAiListResponse<OpenAiProjectUser>>(
            &format!("{base}/users"),
            &[("limit", "100")],
            &[],
        )
        .await
        .with_context(|| format!("OpenAI access-map: failed to list users for {project_id}"));
    let users = tolerate(users, &mut complete, risk_notes);
    note_truncated_page(&users, project_id, "user", risk_notes);
    for user in users.into_iter().flat_map(|page| page.data) {
        let role = user.role;
        resources.push(ResourceExposure {
            resource_type: "project_user".into(),
            name: user.name.unwrap_or(user.id),
            permissions: vec![format!("project_role:{role}")],
            risk: if role == "owner" { "high" } else { "medium" }.into(),
            reason: "User assigned to this OpenAI project".into(),
        });
    }

    let model_permissions = client
        .get::<OpenAiProjectModelPermissions>(
            &format!("{base}/model_permissions"),
            &[],
            &[("Accept", "application/json")],
        )
        .await
        .with_context(|| {
            format!("OpenAI access-map: failed to read model permissions for {project_id}")
        });
    let model_permissions = tolerate(model_permissions, &mut complete, risk_notes);
    if let Some(model_permissions) = model_permissions {
        resources.push(ResourceExposure {
            resource_type: "model_policy".into(),
            name: project_id.to_string(),
            permissions: model_permissions.model_ids,
            risk: "medium".into(),
            reason: format!("Project model policy mode: {}", model_permissions.mode),
        });
    }

    let tools = client
        .get::<OpenAiHostedToolPermissions>(
            &format!("{base}/hosted_tool_permissions"),
            &[],
            &[("Accept", "application/json")],
        )
        .await
        .with_context(|| {
            format!("OpenAI access-map: failed to read hosted tool permissions for {project_id}")
        });
    let tools = tolerate(tools, &mut complete, risk_notes);
    if let Some(tools) = tools {
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
    }

    let rate_limits = client
        .get::<OpenAiListResponse<OpenAiRateLimit>>(
            &format!("{base}/rate_limits"),
            &[("limit", "100")],
            &[],
        )
        .await
        .with_context(|| format!("OpenAI access-map: failed to list rate limits for {project_id}"));
    let rate_limits = tolerate(rate_limits, &mut complete, risk_notes);
    note_truncated_page(&rate_limits, project_id, "rate limit", risk_notes);
    for limit in rate_limits.into_iter().flat_map(|page| page.data) {
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

    if complete {
        permissions.admin.push(format!("project:{project_id}:administration:read"));
    }
    Ok(())
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/models/list
async fn list_models(client: &OpenAiClient) -> Result<Inventory<Model>> {
    list_inventory(client, "/models", &[], &[])
        .await
        .context("OpenAI access-map: failed to list models")
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/files/list
async fn list_files(client: &OpenAiClient) -> Result<Inventory<OpenAIFile>> {
    // One extra entry detects truncation without fetching the API's 10,000-file
    // default page, which can exceed our metadata response cap.
    let limit = (MAX_OPENAI_SERVICE_RESOURCES + 1).to_string();
    list_inventory(client, "/files", &[("limit", &limit)], &[])
        .await
        .context("OpenAI access-map: failed to list files")
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/assistants/listAssistants
async fn list_assistants(client: &OpenAiClient) -> Result<Inventory<OpenAiAssistant>> {
    let limit = (MAX_OPENAI_SERVICE_RESOURCES + 1).to_string();
    list_inventory(client, "/assistants", &[("limit", &limit)], &[("OpenAI-Beta", "assistants=v2")])
        .await
        .context("OpenAI access-map: failed to list assistants")
}

/// OpenAI API reference: https://platform.openai.com/docs/api-reference/fine-tuning/list
async fn list_fine_tuning_jobs(client: &OpenAiClient) -> Result<Inventory<FineTuningJob>> {
    let limit = (MAX_OPENAI_SERVICE_RESOURCES + 1).to_string();
    list_inventory(client, "/fine_tuning/jobs", &[("limit", &limit)], &[])
        .await
        .context("OpenAI access-map: failed to list fine-tuning jobs")
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("sk-admin-") {
        "admin_api_key"
    } else if token.starts_with("sk-proj-") {
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
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use kingfisher_scanner::validation::limits::NetworkLimits;
    use serde_json::{Value, json};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    use super::*;

    const TEST_TOKEN: &str = "sk-proj-test-only";

    fn test_client(server: &MockServer) -> OpenAiClient {
        OpenAiClient::new(
            http_client_builder().no_proxy().build().unwrap(),
            TEST_TOKEN,
            &format!("{}/v1", server.uri()),
            "org-test",
            "proj-test",
        )
        .unwrap()
    }

    async fn mock_json(server: &MockServer, endpoint: &str, query: &[(&str, &str)], body: Value) {
        let query_count = query.len();
        let mut mock = Mock::given(method("GET"))
            .and(path(format!("/v1{endpoint}")))
            .and(header("authorization", format!("Bearer {TEST_TOKEN}")))
            // User-Agent is not a comma-separated list. The generic header
            // matcher splits the browser comment at "(KHTML, like Gecko)".
            .and(|request: &wiremock::Request| {
                let values = request.headers.get_all("user-agent");
                let mut values = values.iter();
                values.next().is_some_and(|value| value.as_bytes() == GLOBAL_USER_AGENT.as_bytes())
                    && values.next().is_none()
            })
            .and(header("openai-organization", "org-test"))
            .and(header("openai-project", "proj-test"))
            .and(move |request: &wiremock::Request| {
                request.url.query_pairs().count() == query_count
            });
        for (key, value) in query {
            mock = mock.and(query_param(*key, *value));
        }
        if endpoint == "/assistants" {
            mock = mock.and(header("openai-beta", "assistants=v2"));
        }
        if endpoint.ends_with("/model_permissions")
            || endpoint.ends_with("/hosted_tool_permissions")
        {
            mock = mock.and(header("accept", "application/json"));
        }
        mock.respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    fn page(data: Value) -> Value {
        // These endpoints were single-page SDK calls, even when more pages exist.
        json!({"object": "list", "data": data, "has_more": true, "last_id": "next-page"})
    }

    fn last_page(data: Value) -> Value {
        json!({"object": "list", "data": data, "has_more": false})
    }

    #[test]
    fn default_headers_are_minimal_and_invalid_credentials_are_rejected_locally() {
        let http = http_client_builder().no_proxy().build().unwrap();
        let client = OpenAiClient::new(http.clone(), TEST_TOKEN, OPENAI_API, "", "").unwrap();
        assert!(client.headers[header::AUTHORIZATION].is_sensitive());
        assert!(!client.headers.contains_key("openai-organization"));
        assert!(!client.headers.contains_key("openai-project"));
        assert!(OpenAiClient::new(http, "bad\r\ntoken", OPENAI_API, "", "").is_err());
    }

    #[test]
    fn key_history_requires_an_explicit_credential_id_and_selects_the_exact_endpoint() {
        let mut credential: OpenAiCredentialFile =
            serde_json::from_value(json!({"token":"sk-proj-target-secret"})).unwrap();
        assert!(credential.key_lookup().unwrap().is_none());

        credential.audit_token = Some("sk-admin-audit-secret".into());
        assert!(credential.key_lookup().is_err());
        credential.key_id = Some("key_a".into());
        assert!(credential.key_lookup().is_err());
        credential.project_id = Some("proj_a".into());
        let lookup = credential.key_lookup().unwrap().unwrap();
        assert_eq!(lookup.path, "/organization/projects/proj_a/api_keys/key_a");
        assert_eq!(lookup.object, PROJECT_KEY_OBJECT);

        credential.token = "sk-admin-target-secret".into();
        assert!(credential.key_lookup().is_err());
        credential.project_id = None;
        let lookup = credential.key_lookup().unwrap().unwrap();
        assert_eq!(lookup.path, "/organization/admin_api_keys/key_a");
        assert_eq!(lookup.object, ADMIN_KEY_OBJECT);

        credential.audit_token = Some(credential.token.clone());
        assert!(credential.key_lookup().is_err());
        credential.audit_token = Some("sk-admin-audit-secret".into());
        credential.key_id = Some("key_a/../../other".into());
        assert!(credential.key_lookup().is_err());
    }

    #[tokio::test]
    async fn key_history_is_read_only_exact_and_separate_from_inventory() {
        const TARGET: &str = "sk-proj-target-secret";
        const AUDIT: &str = "sk-admin-audit-secret";
        const HISTORY_PATH: &str = "/organization/projects/proj_a/api_keys/key_a";
        let credential: OpenAiCredentialFile = serde_json::from_value(json!({
            "token": TARGET, "audit_token": AUDIT, "project_id": "proj_a", "key_id": "key_a",
        }))
        .unwrap();
        let record = |id: &str, redacted: &str, last_used_at: Option<i64>| {
            ResponseTemplate::new(200).set_body_json(json!({
                "object": PROJECT_KEY_OBJECT,
                "id": id,
                "redacted_value": redacted,
                "last_used_at": last_used_at,
            }))
        };
        for (response, expected) in [
            (record("key_a", "sk-proj...cret", Some(1_735_689_600)), Some("2025-01-01T00:00:00Z")),
            (record("key_b", "sk-proj...cret", Some(1_735_689_600)), None),
            (record("key_a", "sk-proj...else", Some(1_735_689_600)), None),
            (record("key_a", "sk-proj...cret", None), None),
            (ResponseTemplate::new(403), None),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(HISTORY_PATH))
                .and(header("authorization", format!("Bearer {AUDIT}")))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/models"))
                .and(header("authorization", format!("Bearer {TARGET}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(last_page(json!([]))))
                .expect(1)
                .mount(&server)
                .await;

            let mapped =
                map_access_from_token_at(TARGET, credential.key_lookup().unwrap(), &server.uri())
                    .await
                    .unwrap();
            let report = serde_json::to_string(&mapped).unwrap();
            assert!(!report.contains(TARGET) && !report.contains(AUDIT));
            assert_eq!(mapped.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                mapped.provider_metadata.and_then(|metadata| metadata.credential_last_used_source),
                expected.map(|_| KEY_USAGE_SOURCE.to_owned()),
            );
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests[0].url.path(), HISTORY_PATH);
            let target_header = format!("Bearer {TARGET}");
            assert!(requests[1..].iter().all(|request| {
                request
                    .headers
                    .get("authorization")
                    .is_some_and(|header| header.as_bytes() == target_header.as_bytes())
            }));
        }
    }

    #[test]
    fn response_dtos_keep_wire_fields_and_nullable_names() {
        let models: OpenAiListResponse<Model> = serde_json::from_value(page(json!([{
            "id": "gpt-example", "object": "model", "created": 1700000000,
            "owned_by": "organization", "future_field": true
        }])))
        .unwrap();
        assert_eq!(models.data[0].id, "gpt-example");
        assert_eq!(models.data[0].owned_by, "organization");

        let projects: OpenAiListResponse<Project> = serde_json::from_value(page(json!([{
            "id": "proj-archived", "name": null, "status": "archived",
            "object": "organization.project", "created_at": 1700000000
        }])))
        .unwrap();
        assert_eq!(projects.data[0].id, "proj-archived");
        assert_eq!(projects.data[0].name, None);
        assert_eq!(projects.data[0].status.as_deref(), Some("archived"));
        assert!(serde_json::from_value::<OpenAiListResponse<Model>>(json!({})).is_err());
        assert!(serde_json::from_value::<Model>(json!({"id": "missing-owner"})).is_err());
    }

    #[test]
    fn response_enum_values_keep_api_spellings_and_accept_new_values() {
        // Known and future values (e.g. a newly documented "evals" purpose) must
        // both parse, so one new value never drops a whole inventory page.
        let files = serde_json::from_value::<OpenAiListResponse<OpenAIFile>>(json!({"data": [
            {"filename": "train.jsonl", "purpose": "fine-tune"},
            {"filename": "eval.jsonl", "purpose": "evals"}
        ]}))
        .unwrap();
        let purposes: Vec<_> = files.data.iter().map(|file| file.purpose.as_str()).collect();
        assert_eq!(purposes, ["fine-tune", "evals"]);
        let job = serde_json::from_value::<FineTuningJob>(json!({
            "id": "ftjob", "fine_tuned_model": null, "model": "base", "status": "pausing"
        }))
        .unwrap();
        assert_eq!(job.status, "pausing");
        let user = serde_json::from_value::<OpenAiProjectUser>(json!({
            "id": "user", "name": null, "role": "viewer"
        }))
        .unwrap();
        assert_eq!(user.role, "viewer");
        let account = serde_json::from_value::<OpenAiServiceAccount>(json!({
            "id": "svc", "name": "bot", "role": "owner"
        }))
        .unwrap();
        assert_eq!(account.role, "owner");
    }

    #[tokio::test]
    async fn read_only_inventory_preserves_headers_queries_names_and_result_shape() {
        let server = MockServer::start().await;
        mock_json(
            &server,
            "/organization/projects",
            &[],
            last_page(json!([{"id": "proj-1", "name": "Production", "status": "active"}])),
        )
        .await;
        let base = "/organization/projects/proj-1";
        mock_json(
            &server,
            &format!("{base}/api_keys"),
            &[("limit", "100"), ("owner_project_access", "any")],
            last_page(json!([
                {"id": "key-1", "name": "", "redacted_value": "sk-...one"},
                {"id": "key-2", "name": "CI", "redacted_value": "sk-...two"}
            ])),
        )
        .await;
        mock_json(
            &server,
            &format!("{base}/service_accounts"),
            &[("limit", "100")],
            last_page(json!([
                {"id": "svc-1", "name": "", "role": "member"},
                {"id": "svc-2", "name": "Automation", "role": "owner"}
            ])),
        )
        .await;
        mock_json(
            &server,
            &format!("{base}/users"),
            &[("limit", "100")],
            last_page(json!([
                {"id": "user-1", "name": null, "role": "owner"},
                {"id": "user-2", "name": "Reader", "role": "member"}
            ])),
        )
        .await;
        mock_json(
            &server,
            &format!("{base}/model_permissions"),
            &[],
            json!({"mode": "allow", "model_ids": ["gpt-example"]}),
        )
        .await;
        mock_json(
            &server,
            &format!("{base}/hosted_tool_permissions"),
            &[],
            json!({"file_search": {"enabled": true}, "web_search": {"enabled": true}}),
        )
        .await;
        mock_json(
            &server,
            &format!("{base}/rate_limits"),
            &[("limit", "100")],
            last_page(json!([
                {"model": "", "max_requests_per_1_minute": 10, "max_tokens_per_1_minute": 20},
                {"model": "gpt-example", "max_requests_per_1_minute": 30,
                 "max_tokens_per_1_minute": 40}
            ])),
        )
        .await;
        mock_json(
            &server,
            "/models",
            &[],
            page(json!([{"id": "gpt-example", "owned_by": "organization"}])),
        )
        .await;
        mock_json(
            &server,
            "/files",
            &[("limit", "51")],
            page(json!([{"filename": "training.jsonl", "purpose": "fine-tune"}])),
        )
        .await;
        mock_json(
            &server,
            "/assistants",
            &[("limit", "51")],
            page(json!([
                {"id": "asst-1", "name": null, "model": "gpt-example"},
                {"id": "asst-2", "name": "Helper", "model": "gpt-example"}
            ])),
        )
        .await;
        mock_json(
            &server,
            "/fine_tuning/jobs",
            &[("limit", "51")],
            page(json!([
                {"id": "ft-1", "fine_tuned_model": null, "model": "gpt-example", "status": "queued"},
                {"id": "ft-2", "fine_tuned_model": "ft:gpt-example", "model": "gpt-example",
                 "status": "succeeded"}
            ])),
        )
        .await;

        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        let shaped: Vec<_> = result
            .resources
            .iter()
            .map(|resource| {
                (resource.resource_type.as_str(), resource.name.as_str(), resource.risk.as_str())
            })
            .collect();
        assert_eq!(
            shaped,
            [
                ("project", "Production", "high"),
                ("project_api_key", "key-1", "high"),
                ("project_api_key", "CI", "high"),
                ("service_account", "svc-1", "high"),
                ("service_account", "Automation", "high"),
                ("project_user", "user-1", "high"),
                ("project_user", "Reader", "medium"),
                ("model_policy", "proj-1", "medium"),
                ("hosted_tools", "proj-1", "medium"),
                ("model_rate_limit", "unknown_model", "low"),
                ("model_rate_limit", "gpt-example", "low"),
                ("model", "gpt-example", "low"),
                ("file", "training.jsonl", "medium"),
                ("assistant", "asst-1", "low"),
                ("assistant", "Helper", "low"),
                ("fine_tuning_job", "ft-1", "medium"),
                ("fine_tuning_job", "ft:gpt-example", "medium"),
            ]
        );
        assert_eq!(result.resources[3].permissions, ["project_role:member"]);
        assert_eq!(result.resources[4].permissions, ["project_role:owner"]);
        assert_eq!(result.resources[7].permissions, ["gpt-example"]);
        assert_eq!(result.resources[8].permissions, ["file_search", "web_search"]);
        assert_eq!(
            result.resources[9].permissions,
            ["requests_per_minute:10", "tokens_per_minute:20"]
        );
        assert!(result.resources[12].reason.ends_with("(purpose: fine-tune)"));
        assert!(result.resources[15].reason.ends_with("status: queued)"));
        assert!(result.resources[16].reason.ends_with("status: succeeded)"));
        assert_eq!(
            result.permissions.admin,
            ["organization_projects:list", "project:proj-1:administration:read"]
        );
        assert!(result.permissions.risky.is_empty());
        assert!(matches!(result.severity, Severity::High));
        assert_eq!(result.identity.id, "openai_project_api_key");
        assert_eq!(result.identity.access_type, "project_api_key");
        assert_eq!(result.roles[0].permissions, ["token:project_api_key"]);
        let details = result.token_details.unwrap();
        assert_eq!(details.account_type.as_deref(), Some("api_key"));
        assert_eq!(details.token_type.as_deref(), Some("project_api_key"));
        assert_eq!(
            details.scopes,
            [
                "organization_projects:list",
                "models:list",
                "files:list",
                "assistants:list",
                "fine_tuning_jobs:list"
            ]
        );
        assert!(result.risk_notes.is_empty());
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 11);
        assert!(requests.iter().all(|request| request.method == "GET" && request.body.is_empty()));
        assert!(requests.iter().all(|request| !request.headers.contains_key("content-type")));
        assert_eq!(
            requests.iter().filter(|request| request.headers.contains_key("openai-beta")).count(),
            1
        );
    }

    #[tokio::test]
    async fn bounded_file_inventory_preserves_resources_truncation_and_severity() {
        let server = MockServer::start().await;
        let files: Vec<_> = (0..=MAX_OPENAI_SERVICE_RESOURCES)
            .map(|index| {
                json!({
                    "filename": format!("{index}-{}.jsonl", "x".repeat(1024)),
                    "purpose": "fine-tune"
                })
            })
            .collect();
        // The API's default 10,000-file page with these filenames exceeds 4 MiB.
        assert!(serde_json::to_vec(&files[0]).unwrap().len() * 10_000 > MAX_OPENAI_RESPONSE_BYTES);
        mock_json(&server, "/files", &[("limit", "51")], page(json!(files))).await;

        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        assert_eq!(result.resources.len(), MAX_OPENAI_SERVICE_RESOURCES);
        assert!(result.resources.iter().all(|resource| resource.resource_type == "file"));
        assert_eq!(result.permissions.read_only, ["files:list"]);
        assert!(matches!(result.severity, Severity::Medium));
        assert_eq!(
            result.risk_notes,
            [format!(
                "File resource list truncated to first {MAX_OPENAI_SERVICE_RESOURCES} visible entries"
            )]
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn denied_statuses_do_not_require_an_openai_error_body() {
        for status in [401, 403, 404] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1/models"))
                .respond_with(ResponseTemplate::new(status).set_body_string("<html>denied</html>"))
                .expect(1)
                .mount(&server)
                .await;
            assert!(matches!(list_models(&test_client(&server)).await.unwrap(), Inventory::Denied));
        }
        for status in [400, 429, 500, 503] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1/models"))
                .respond_with(ResponseTemplate::new(status).set_body_string("sensitive-error-body"))
                .expect(1)
                .mount(&server)
                .await;
            let error = list_models(&test_client(&server)).await.err().unwrap();
            let message = format!("{error:#}");
            assert!(message.contains(&status.to_string()));
            assert!(!message.contains("sensitive-error-body"));
        }
    }

    #[tokio::test]
    async fn inventory_errors_preserve_successful_permissions_and_token_fallbacks() {
        let server = MockServer::start().await;
        mock_json(&server, "/models", &[], page(json!([]))).await;
        Mock::given(method("GET"))
            .and(path("/v1/files"))
            .respond_with(ResponseTemplate::new(500).set_body_string("private-server-detail"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/assistants"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not JSON"))
            .expect(1)
            .mount(&server)
            .await;
        let result =
            map_access_with_client(&test_client(&server), "sk-svcacct-test").await.unwrap();
        assert_eq!(result.permissions.read_only, ["models:list"]);
        assert!(result.permissions.admin.is_empty());
        assert_eq!(result.resources.len(), 1);
        assert_eq!(result.resources[0].resource_type, "account");
        assert_eq!(result.resources[0].name, "openai_service_account_api_key");
        assert!(matches!(result.severity, Severity::Low));
        assert_eq!(result.token_details.unwrap().scopes, ["models:list"]);
        assert_eq!(result.risk_notes.len(), 2);
        assert!(result.risk_notes[0].starts_with("File enumeration failed:"));
        assert!(result.risk_notes[1].starts_with("Assistant enumeration failed:"));
        assert!(!result.risk_notes.join(" ").contains("private-server-detail"));
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
        assert_eq!(detect_token_type("sk-None-example"), "legacy_api_key");
        assert_eq!(detect_token_type("sk-example"), "api_key");
    }

    #[tokio::test]
    async fn truncated_project_listings_are_reported_without_following_pages() {
        let server = MockServer::start().await;
        mock_json(&server, "/organization/projects", &[], page(json!([{"id": "proj-1"}]))).await;
        let base = "/organization/projects/proj-1";
        mock_json(
            &server,
            &format!("{base}/api_keys"),
            &[("limit", "100"), ("owner_project_access", "any")],
            page(json!([{"id": "key-1", "name": "", "redacted_value": "sk-...one"}])),
        )
        .await;
        mock_json(&server, &format!("{base}/users"), &[("limit", "100")], last_page(json!([])))
            .await;
        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        assert_eq!(
            result.risk_notes,
            [
                "Project list truncated to the first 1 projects returned by the API",
                "Project proj-1 API key list truncated to the first 1 entries",
            ]
        );
        assert!(result.resources.iter().any(|resource| resource.resource_type == "project"));
    }

    #[tokio::test]
    async fn denied_project_inventory_does_not_hide_other_administrative_metadata() {
        let server = MockServer::start().await;
        mock_json(
            &server,
            "/organization/projects",
            &[],
            last_page(json!([{"id": "proj-archived", "name": null, "status": "archived"}])),
        )
        .await;
        mock_json(
            &server,
            "/organization/projects/proj-archived/users",
            &[("limit", "100")],
            last_page(json!([{"id": "user-1", "role": "member"}])),
        )
        .await;
        mock_json(
            &server,
            "/organization/projects/proj-archived/hosted_tool_permissions",
            &[],
            json!({}),
        )
        .await;
        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        assert_eq!(result.resources[0].name, "proj-archived");
        assert_eq!(result.resources[0].risk, "low");
        assert!(result.resources.iter().any(|resource| resource.resource_type == "project_user"));
        assert!(
            result.resources.iter().any(|resource| resource.resource_type == "hosted_tools"
                && resource.permissions.is_empty())
        );
        assert_eq!(result.permissions.admin, ["organization_projects:list"]);
        assert!(result.risk_notes.is_empty());
    }

    #[tokio::test]
    async fn failed_project_sub_inventory_does_not_skip_the_rest_of_the_project() {
        let server = MockServer::start().await;
        mock_json(
            &server,
            "/organization/projects",
            &[],
            last_page(json!([{"id": "proj-busy", "name": "busy", "status": "active"}])),
        )
        .await;
        // The first sub-inventory is rate limited; later ones must still be read.
        Mock::given(method("GET"))
            .and(path("/v1/organization/projects/proj-busy/api_keys"))
            .respond_with(ResponseTemplate::new(429).set_body_string("slow down"))
            .expect(1)
            .mount(&server)
            .await;
        mock_json(
            &server,
            "/organization/projects/proj-busy/users",
            &[("limit", "100")],
            last_page(json!([{"id": "user-1", "role": "owner"}])),
        )
        .await;
        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        assert!(result.resources.iter().any(|resource| resource.resource_type == "project_user"
            && resource.risk == "high"));
        assert!(
            result
                .risk_notes
                .iter()
                .any(|note| note.contains("failed to list API keys for proj-busy")),
            "{:?}",
            result.risk_notes
        );
        assert!(
            !result.risk_notes.iter().any(|note| note.contains("Administrative inventory failed"))
        );
        assert_eq!(result.permissions.admin, ["organization_projects:list"]);
    }

    #[tokio::test]
    async fn service_inventory_remains_single_page_and_truncates_visible_resources() {
        let server = MockServer::start().await;
        let entries: Vec<_> = (0..=MAX_OPENAI_SERVICE_RESOURCES)
            .map(|index| {
                json!({
                    "id": format!("resource-{index}"), "owned_by": "organization",
                    "filename": format!("file-{index}"), "purpose": "user_data",
                    "name": null, "model": "gpt-example", "status": "running",
                    "fine_tuned_model": null
                })
            })
            .collect();
        for endpoint in ["/models", "/files", "/assistants", "/fine_tuning/jobs"] {
            let query: &[(&str, &str)] =
                if endpoint == "/models" { &[] } else { &[("limit", "51")] };
            mock_json(&server, endpoint, query, page(json!(entries))).await;
        }
        let result = map_access_with_client(&test_client(&server), TEST_TOKEN).await.unwrap();
        assert_eq!(result.resources.len(), 4 * MAX_OPENAI_SERVICE_RESOURCES);
        assert_eq!(result.risk_notes.len(), 4);
        assert!(result.risk_notes.iter().all(|note| note.contains("truncated to first 50")));
        assert!(matches!(result.severity, Severity::Medium));
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn read_only_helpers_do_not_follow_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/unexpected", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(list_models(&test_client(&server)).await.is_err());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn response_body_budget_honors_the_shared_unlimited_response_policy() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{"id": "gpt-example", "owned_by": "organization"}],
                "padding": "x".repeat(MAX_OPENAI_RESPONSE_BYTES)
            })))
            .expect(2)
            .mount(&server)
            .await;
        let client = test_client(&server);
        assert!(list_models(&client).await.is_err());
        let inventory = NetworkLimits { unlimited_response: true, ..Default::default() }
            .scope(list_models(&client))
            .await
            .unwrap();
        assert!(matches!(inventory, Inventory::Accessible(models) if models.len() == 1));
    }

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
