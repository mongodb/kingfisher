use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tracing::warn;

macro_rules! verbose_warn {
    ($($arg:tt)*) => {
        if tracing::level_enabled!(tracing::Level::DEBUG) {
            warn!($($arg)*);
        }
    };
}

use crate::validation::gcp::GcpValidator;

#[derive(Debug, Clone)]
struct Ancestor {
    kind: String,
    id: String,
}

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_default_resource, build_recommendations,
};

pub async fn map_access(credential_path: Option<&Path>) -> Result<AccessMapResult> {
    let path = credential_path.ok_or_else(|| anyhow!("GCP access-map requires a key.json path"))?;
    let data = std::fs::read_to_string(path).context("Failed to read credential file")?;
    map_access_from_json(&data).await
}

pub async fn map_access_from_json(data: &str) -> Result<AccessMapResult> {
    let validator = GcpValidator::global()?;
    let token_context = validator
        .get_access_token_from_sa_json(data)
        .await
        .context("Failed to mint GCP access token")?;
    let http_client = validator.client().clone();

    let access_token = token_context.access_token;
    let client_email = token_context.client_email;
    let mut project_id =
        if token_context.project_id.is_empty() { None } else { Some(token_context.project_id) };

    let sa_metadata =
        match fetch_service_account_metadata(&http_client, &access_token, &client_email).await {
            Ok(meta) => meta,
            Err(err) => {
                verbose_warn!("GCP access-map: failed to fetch service account metadata: {err}");
                ServiceAccountMetadata::default()
            }
        };

    if project_id.is_none() {
        project_id = sa_metadata.project_id.clone();
    }

    let mut roles = Vec::new();
    let mut role_entries: Vec<(String, String)> = Vec::new();

    let policy = fetch_project_policy(&http_client, &access_token, project_id.as_deref()).await?;
    if let Some(policy) = policy.as_ref() {
        collect_roles(policy, &client_email, "project", &mut role_entries);
    }

    if let Some(project) = project_id.as_deref() {
        let ancestors = fetch_project_ancestry(&http_client, &access_token, project)
            .await
            .unwrap_or_else(|e| {
                verbose_warn!("GCP access-map: failed to fetch project ancestry: {e}");
                Vec::new()
            });

        for ancestor in ancestors {
            if let Some(policy) =
                fetch_ancestor_policy(&http_client, &access_token, &ancestor).await?
            {
                let source = match ancestor.kind.as_str() {
                    "organization" => format!("org:{}", ancestor.id),
                    "folder" => format!("folder:{}", ancestor.id),
                    _ => ancestor.kind.clone(),
                };
                collect_roles(&policy, &client_email, &source, &mut role_entries);
            }
        }
    }

    let mut seen = HashSet::new();
    for (role_name, source) in role_entries {
        if !seen.insert((role_name.clone(), source.clone())) {
            continue;
        }

        let permissions = fetch_role_permissions(&http_client, &access_token, &role_name)
            .await
            .unwrap_or_else(|e| {
                verbose_warn!("Failed to expand permissions for {role_name}: {e}");
                Vec::new()
            });

        roles.push(RoleBinding { name: role_name, source, permissions });
    }

    if roles.is_empty()
        && let Some(project) = project_id.as_deref()
    {
        let mut tested_permissions = test_project_permissions(&http_client, &access_token, project)
            .await
            .unwrap_or_else(|e| {
                verbose_warn!("GCP access-map: failed testIamPermissions fallback: {e}");
                Vec::new()
            });

        if tested_permissions.is_empty() {
            tested_permissions = test_service_account_permissions(
                &http_client,
                &access_token,
                project,
                &client_email,
            )
            .await
            .unwrap_or_else(|e| {
                verbose_warn!(
                    "GCP access-map: failed serviceAccount testIamPermissions fallback: {e}"
                );
                Vec::new()
            });
        }

        if !tested_permissions.is_empty() {
            roles.push(RoleBinding {
                name: "testIamPermissions".into(),
                source: "project".into(),
                permissions: tested_permissions,
            });
        }
    }

    let impersonation_notes = if let Some(project) = project_id.as_deref() {
        match fetch_service_account_iam_policy(&http_client, &access_token, project, &client_email)
            .await
        {
            Ok(Some(policy)) => extract_impersonation_notes(&policy),
            Ok(None) => Vec::new(),
            Err(err) => {
                verbose_warn!("GCP access-map: failed to fetch service account IAM policy: {err}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    let permissions = classify_permissions(&roles);
    let severity = derive_severity(&permissions);

    let mut resources = Vec::new();
    if let Some(project) = project_id.as_deref() {
        let mut enumerated =
            enumerate_resources(&http_client, &access_token, project, &permissions, &roles)
                .await
                .unwrap_or_else(|e| {
                    verbose_warn!("GCP access-map: failed resource enumeration: {e}");
                    Vec::new()
                });
        resources.append(&mut enumerated);
    }

    if resources.is_empty() {
        resources.push(build_default_resource(project_id.as_deref(), severity));
    }

    let identity = AccessSummary {
        id: client_email.clone(),
        access_type: "service_account".into(),
        project: project_id.clone(),
        tenant: None,
        account_id: None,
    };

    let mut risk_notes = derive_risk_notes(&roles, &permissions);
    risk_notes.extend(impersonation_notes);
    if sa_metadata.is_disabled {
        risk_notes.push("Service account is disabled but key is still valid".into());
    }

    let recommendations = build_recommendations(severity);

    let token_details = Some(AccessTokenDetails {
        name: sa_metadata.display_name,
        username: Some(client_email),
        account_type: Some("service_account".into()),
        token_type: Some("service_account_key".into()),
        user_id: sa_metadata.unique_id,
        ..Default::default()
    });

    Ok(AccessMapResult {
        cloud: "gcp".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations,
        risk_notes,
        token_details,
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_project_policy(
    client: &Client,
    token: &str,
    project_id: Option<&str>,
) -> Result<Option<Value>> {
    let project = project_id.ok_or_else(|| anyhow!("Missing project_id"))?;
    let url =
        format!("https://cloudresourcemanager.googleapis.com/v1/projects/{}:getIamPolicy", project);

    let resp_v3 = client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "options": { "requestedPolicyVersion": 3 } }))
        .send()
        .await?;
    let status_v3 = resp_v3.status();
    let body_v3 = resp_v3.bytes().await?;

    if status_v3.is_success() {
        let json = serde_json::from_slice(&body_v3)?;
        return Ok(Some(json));
    }

    if let Some(disabled) = service_disabled_message(&body_v3)? {
        verbose_warn!(
            "GCP access-map: Cloud Resource Manager API disabled for project {project}: {disabled}"
        );
        return Ok(None);
    }

    if status_v3 == StatusCode::FORBIDDEN || status_v3 == StatusCode::BAD_REQUEST {
        let resp_v1 =
            client.post(&url).bearer_auth(token).json(&serde_json::json!({})).send().await?;
        let status_v1 = resp_v1.status();
        let body_v1 = resp_v1.bytes().await?;

        if status_v1.is_success() {
            let json = serde_json::from_slice(&body_v1)?;
            return Ok(Some(json));
        }

        if let Some(disabled) = service_disabled_message(&body_v1)? {
            verbose_warn!(
                "GCP access-map: Cloud Resource Manager API disabled for project {project}: {disabled}"
            );
            return Ok(None);
        }

        if status_v1 == StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: insufficient permissions to read IAM policy (v1 and v3)"
            );
            return Ok(None);
        }

        return Err(anyhow!(
            "Failed to fetch project IAM policy (v1): HTTP {} {}",
            status_v1,
            String::from_utf8_lossy(&body_v1)
        ));
    }

    Err(anyhow!(
        "Failed to fetch project IAM policy (v3): HTTP {} {}",
        status_v3,
        String::from_utf8_lossy(&body_v3)
    ))
}

async fn fetch_project_ancestry(
    client: &Client,
    token: &str,
    project_id: &str,
) -> Result<Vec<Ancestor>> {
    let url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:getAncestry",
        project_id
    );

    let resp = client.post(url).bearer_auth(token).json(&serde_json::json!({})).send().await?;
    let status = resp.status();
    let body = resp.bytes().await?;

    if let Some(disabled) = service_disabled_message(&body)? {
        verbose_warn!(
            "GCP access-map: Cloud Resource Manager API disabled for project {project_id}: {disabled}"
        );
        return Ok(Vec::new());
    }

    if status == StatusCode::FORBIDDEN {
        verbose_warn!("GCP access-map: ancestry lookup forbidden for project {project_id}");
        return Ok(Vec::new());
    }

    if !status.is_success() {
        return Err(anyhow!(
            "Failed to fetch project ancestry: HTTP {} {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }

    let json: Value = serde_json::from_slice(&body)?;
    let mut ancestors = Vec::new();
    if let Some(arr) = json.get("ancestor").and_then(|a| a.as_array()) {
        for item in arr {
            if let Some(resource) = item.get("resourceId")
                && let (Some(kind), Some(id)) = (resource.get("type"), resource.get("id"))
                && let (Some(kind), Some(id)) = (kind.as_str(), id.as_str())
            {
                ancestors.push(Ancestor { kind: kind.to_string(), id: id.to_string() });
            }
        }
    }

    Ok(ancestors)
}

async fn fetch_ancestor_policy(
    client: &Client,
    token: &str,
    ancestor: &Ancestor,
) -> Result<Option<Value>> {
    let url = match ancestor.kind.as_str() {
        "organization" => format!(
            "https://cloudresourcemanager.googleapis.com/v1/organizations/{}:getIamPolicy",
            ancestor.id
        ),
        "folder" => format!(
            "https://cloudresourcemanager.googleapis.com/v1/folders/{}:getIamPolicy",
            ancestor.id
        ),
        _ => return Ok(None),
    };

    let resp_v3 = client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "options": { "requestedPolicyVersion": 3 } }))
        .send()
        .await?;
    let status_v3 = resp_v3.status();
    let body_v3 = resp_v3.bytes().await?;

    if status_v3.is_success() {
        let json = serde_json::from_slice(&body_v3)?;
        return Ok(Some(json));
    }

    if let Some(disabled) = service_disabled_message(&body_v3)? {
        verbose_warn!(
            "GCP access-map: Cloud Resource Manager API disabled for {} {}: {disabled}",
            ancestor.kind,
            ancestor.id
        );
        return Ok(None);
    }

    if status_v3 == StatusCode::FORBIDDEN || status_v3 == StatusCode::BAD_REQUEST {
        let resp_v1 =
            client.post(&url).bearer_auth(token).json(&serde_json::json!({})).send().await?;
        let status_v1 = resp_v1.status();
        let body_v1 = resp_v1.bytes().await?;

        if status_v1.is_success() {
            let json = serde_json::from_slice(&body_v1)?;
            return Ok(Some(json));
        }

        if let Some(disabled) = service_disabled_message(&body_v1)? {
            verbose_warn!(
                "GCP access-map: Cloud Resource Manager API disabled for {} {}: {disabled}",
                ancestor.kind,
                ancestor.id
            );
            return Ok(None);
        }

        if status_v1 == StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: insufficient permissions to read {} IAM policy (v1 and v3)",
                ancestor.kind
            );
            return Ok(None);
        }

        return Err(anyhow!(
            "Failed to fetch {} IAM policy (v1): HTTP {} {}",
            ancestor.kind,
            status_v1,
            String::from_utf8_lossy(&body_v1)
        ));
    }

    Err(anyhow!(
        "Failed to fetch {} IAM policy (v3): HTTP {} {}",
        ancestor.kind,
        status_v3,
        String::from_utf8_lossy(&body_v3)
    ))
}

#[derive(Debug, Clone, Default)]
struct ServiceAccountMetadata {
    project_id: Option<String>,
    display_name: Option<String>,
    unique_id: Option<String>,
    is_disabled: bool,
}

async fn fetch_service_account_metadata(
    client: &Client,
    token: &str,
    client_email: &str,
) -> Result<ServiceAccountMetadata> {
    let encoded_email = utf8_percent_encode(client_email, NON_ALPHANUMERIC);
    let url = format!("https://iam.googleapis.com/v1/projects/-/serviceAccounts/{}", encoded_email);

    let resp = client.get(url).bearer_auth(token).send().await?;
    let status = resp.status();
    let body = resp.bytes().await?;

    if let Some(disabled) = service_disabled_message(&body)? {
        verbose_warn!(
            "GCP access-map: IAM API disabled when fetching metadata for {client_email}: {disabled}"
        );
        return Ok(ServiceAccountMetadata::default());
    }

    if status == StatusCode::FORBIDDEN {
        verbose_warn!("GCP access-map: service account metadata forbidden for {client_email}");
        return Ok(ServiceAccountMetadata::default());
    }

    if !status.is_success() {
        return Err(anyhow!(
            "Failed to fetch service account metadata: HTTP {} {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }

    let json: Value = serde_json::from_slice(&body)?;
    Ok(ServiceAccountMetadata {
        project_id: json.get("projectId").and_then(|p| p.as_str()).map(|s| s.to_string()),
        display_name: json.get("displayName").and_then(|d| d.as_str()).map(|s| s.to_string()),
        unique_id: json.get("uniqueId").and_then(|u| u.as_str()).map(|s| s.to_string()),
        is_disabled: json.get("disabled").and_then(|d| d.as_bool()).unwrap_or(false),
    })
}

fn extract_roles(policy: &Value, client_email: &str) -> Vec<String> {
    let email_member = format!("serviceAccount:{client_email}");
    let mut role_bindings = Vec::new();
    if let Some(bindings) = policy["bindings"].as_array() {
        for binding in bindings {
            if let Some(role_name) = binding["role"].as_str()
                && let Some(members) = binding["members"].as_array()
                && members.iter().any(|m| m.as_str() == Some(&email_member))
            {
                role_bindings.push(role_name.to_string());
            }
        }
    }
    role_bindings
}

fn collect_roles(
    policy: &Value,
    client_email: &str,
    source: &str,
    out: &mut Vec<(String, String)>,
) {
    for role in extract_roles(policy, client_email) {
        out.push((role, source.to_string()));
    }
}

async fn fetch_role_permissions(
    client: &Client,
    token: &str,
    role_name: &str,
) -> Result<Vec<String>> {
    let url = if role_name.starts_with("roles/")
        || role_name.starts_with("projects/")
        || role_name.starts_with("organizations/")
    {
        format!("https://iam.googleapis.com/v1/{role_name}")
    } else {
        format!("https://iam.googleapis.com/v1/roles/{role_name}")
    };

    let resp = client.get(url).bearer_auth(token).send().await?;
    let status = resp.status();
    let body = resp.bytes().await?;

    if let Some(disabled) = service_disabled_message(&body)? {
        verbose_warn!("GCP access-map: IAM API disabled while expanding {role_name}: {disabled}");
        return Ok(Vec::new());
    }

    if !status.is_success() {
        return Err(anyhow!(
            "Failed to expand permissions for {role_name}: HTTP {} {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }

    let json: Value = serde_json::from_slice(&body)?;
    let permissions = json
        .get("includedPermissions")
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    Ok(permissions)
}

fn classify_permissions(roles: &[RoleBinding]) -> PermissionSummary {
    let mut admin = HashSet::new();
    let mut privilege_escalation = HashSet::new();
    let mut risky = HashSet::new();
    let mut read_only = HashSet::new();

    for role in roles {
        let role_lower = role.name.to_lowercase();
        if role_lower.contains("owner")
            || role_lower.contains("admin")
            || role.name == "roles/editor"
        {
            admin.insert(role.name.clone());
        }

        for perm in &role.permissions {
            if perm.contains("*") {
                risky.insert(perm.clone());
                continue;
            }

            if perm.contains("setIamPolicy")
                || perm.contains("serviceAccountTokenCreator")
                || perm.contains("serviceAccounts.actAs")
                || perm.contains("roles.create")
                || perm.contains("roles.update")
            {
                privilege_escalation.insert(perm.clone());
                continue;
            }

            if perm.contains(".get") || perm.contains(".list") {
                read_only.insert(perm.clone());
                continue;
            }

            risky.insert(perm.clone());
        }
    }

    PermissionSummary {
        admin: sorted(admin),
        privilege_escalation: sorted(privilege_escalation),
        risky: sorted(risky),
        read_only: sorted(read_only),
    }
}

fn derive_severity(permissions: &PermissionSummary) -> Severity {
    if !permissions.admin.is_empty() || !permissions.privilege_escalation.is_empty() {
        Severity::Critical
    } else if !permissions.risky.is_empty() {
        Severity::High
    } else if !permissions.read_only.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn collect_permission_set(roles: &[RoleBinding]) -> HashSet<String> {
    let mut perms = HashSet::new();
    for role in roles {
        for perm in &role.permissions {
            perms.insert(perm.clone());
        }
    }
    perms
}

fn matching_permissions(perm_set: &HashSet<String>, prefixes: &[&str]) -> Vec<String> {
    let mut matches: Vec<String> = perm_set
        .iter()
        .filter(|perm| *perm == "*" || prefixes.iter().any(|prefix| perm.starts_with(prefix)))
        .cloned()
        .collect();

    matches.sort();
    matches
}

async fn enumerate_resources(
    client: &Client,
    token: &str,
    project_id: &str,
    permissions: &PermissionSummary,
    roles: &[RoleBinding],
) -> Result<Vec<ResourceExposure>> {
    let mut resources = Vec::new();
    let perm_set = collect_permission_set(roles);
    let mut add_storage = false;
    let mut add_bigquery = false;
    let mut add_secret_manager = false;
    let mut add_compute = false;
    let mut add_cloud_sql = false;
    let mut add_pubsub = false;
    let mut add_cloud_run = false;
    let mut add_artifact_registry = false;
    let mut add_gke = false;
    let mut add_cloud_kms = false;
    let mut add_cloud_functions = false;
    let mut add_service_accounts = false;
    let mut add_firestore = false;
    let mut add_spanner = false;

    for perm in permissions
        .risky
        .iter()
        .chain(permissions.read_only.iter())
        .chain(permissions.privilege_escalation.iter())
    {
        if perm.starts_with("storage.buckets.list") || perm.starts_with("storage.buckets.get") {
            add_storage = true;
        }
        if perm.starts_with("bigquery.datasets.list") || perm.starts_with("bigquery.datasets.get") {
            add_bigquery = true;
        }
        if perm.starts_with("secretmanager.secrets.list") {
            add_secret_manager = true;
        }
        if perm.starts_with("compute.instances.list") || perm.starts_with("compute.instances.get") {
            add_compute = true;
        }
        if perm.starts_with("cloudsql.instances.list") || perm.starts_with("sql.instances.list") {
            add_cloud_sql = true;
        }
        if perm.starts_with("pubsub.topics.list") || perm.starts_with("pubsub.subscriptions.list") {
            add_pubsub = true;
        }
        if perm.starts_with("run.services.list") {
            add_cloud_run = true;
        }
        if perm.starts_with("artifactregistry.repositories.list") {
            add_artifact_registry = true;
        }
        if perm.starts_with("container.clusters.list") {
            add_gke = true;
        }
        if perm.starts_with("cloudkms.cryptoKeys.list")
            || perm.starts_with("cloudkms.keyRings.list")
        {
            add_cloud_kms = true;
        }
        if perm.starts_with("cloudfunctions.functions.list") {
            add_cloud_functions = true;
        }
        if perm.starts_with("iam.serviceAccounts.list") {
            add_service_accounts = true;
        }
        if perm.starts_with("datastore.databases.list")
            || perm.starts_with("datastore.entities.list")
        {
            add_firestore = true;
        }
        if perm.starts_with("spanner.instances.list") {
            add_spanner = true;
        }
    }

    if add_storage {
        let url = format!("https://storage.googleapis.com/storage/v1/b?project={}", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud Storage API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("storage.objects.create")
                        || p.starts_with("storage.objects.update")
                        || p.starts_with("storage.objects.delete")
                });
                for bucket in items {
                    if let Some(name) = bucket.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "storage_bucket".into(),
                            name: format!("projects/{project_id}/buckets/{name}"),
                            permissions: matching_permissions(
                                &perm_set,
                                &["storage.buckets.", "storage.objects."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can list and write bucket objects".into()
                            } else {
                                "Service account can list bucket contents".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: storage enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_compute {
        let url = format!(
            "https://compute.googleapis.com/compute/v1/projects/{}/aggregated/instances",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Compute Engine API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("items").and_then(|i| i.as_object()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("compute.instances.insert")
                        || p.starts_with("compute.instances.update")
                        || p.starts_with("compute.instances.delete")
                });

                for zone in items.values() {
                    if let Some(instances) = zone.get("instances").and_then(|i| i.as_array()) {
                        for instance in instances {
                            if let Some(name) = instance.get("name").and_then(|n| n.as_str()) {
                                resources.push(ResourceExposure {
                                    resource_type: "compute_instance".into(),
                                    name: format!("projects/{project_id}/instances/{name}"),
                                    permissions: matching_permissions(
                                        &perm_set,
                                        &["compute.instances."],
                                    ),
                                    risk: if writable { "high".into() } else { "medium".into() },
                                    reason: if writable {
                                        "Service account can manage Compute Engine instances".into()
                                    } else {
                                        "Service account can list Compute Engine instances".into()
                                    },
                                });
                            }
                        }
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Compute Engine enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_cloud_sql {
        let url = format!(
            "https://sqladmin.googleapis.com/sql/v1beta4/projects/{}/instances",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud SQL Admin API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("cloudsql.instances.update")
                        || p.starts_with("cloudsql.instances.create")
                        || p.starts_with("cloudsql.instances.delete")
                        || p.starts_with("sql.instances.update")
                        || p.starts_with("sql.instances.create")
                        || p.starts_with("sql.instances.delete")
                });

                for instance in items {
                    if let Some(name) = instance.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "cloudsql_instance".into(),
                            name: format!("projects/{project_id}/instances/{name}"),
                            permissions: matching_permissions(
                                &perm_set,
                                &["cloudsql.instances.", "sql.instances."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can manage Cloud SQL instances".into()
                            } else {
                                "Service account can list Cloud SQL instances".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Cloud SQL enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_pubsub {
        let topics_url = format!("https://pubsub.googleapis.com/v1/projects/{project_id}/topics");
        let subs_url =
            format!("https://pubsub.googleapis.com/v1/projects/{project_id}/subscriptions");

        let writable = perm_set.iter().any(|p| {
            p.starts_with("pubsub.topics.publish")
                || p.starts_with("pubsub.topics.create")
                || p.starts_with("pubsub.subscriptions.create")
        });

        for (url, resource_type) in
            [(topics_url, "pubsub_topic"), (subs_url, "pubsub_subscription")]
        {
            let resp = client.get(&url).bearer_auth(token).send().await?;
            let status = resp.status();
            let body = resp.bytes().await?;

            if let Some(disabled) = service_disabled_message(&body)? {
                verbose_warn!(
                    "GCP access-map: Pub/Sub API disabled for project {project_id}: {disabled}"
                );
                continue;
            }

            if status.is_success() {
                let json: Value = serde_json::from_slice(&body)?;
                let key = if resource_type == "pubsub_topic" { "topics" } else { "subscriptions" };
                if let Some(items) = json.get(key).and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(name) = item.get("name").and_then(|n| n.as_str()) {
                            resources.push(ResourceExposure {
                                resource_type: resource_type.into(),
                                name: name.to_string(),
                                permissions: matching_permissions(
                                    &perm_set,
                                    &["pubsub.topics.", "pubsub.subscriptions."],
                                ),
                                risk: if writable { "high".into() } else { "medium".into() },
                                reason: if writable {
                                    "Service account can publish to or manage Pub/Sub resources"
                                        .into()
                                } else {
                                    "Service account can list Pub/Sub resources".into()
                                },
                            });
                        }
                    }
                }
            } else if status != StatusCode::FORBIDDEN {
                verbose_warn!(
                    "GCP access-map: Pub/Sub enumeration failed for {resource_type}: HTTP {} {}",
                    status,
                    String::from_utf8_lossy(&body)
                );
            }
        }
    }

    if add_cloud_run {
        let url =
            format!("https://run.googleapis.com/v2/projects/{}/locations/-/services", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud Run API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("services").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("run.services.update") || p.starts_with("run.services.create")
                });

                for service in items {
                    if let Some(name) = service.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "cloud_run_service".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(&perm_set, &["run.services."]),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can deploy or modify Cloud Run services".into()
                            } else {
                                "Service account can list Cloud Run services".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Cloud Run enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_artifact_registry {
        let url = format!(
            "https://artifactregistry.googleapis.com/v1/projects/{}/locations/-/repositories",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Artifact Registry API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("repositories").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("artifactregistry.repositories.uploadArtifacts")
                        || p.starts_with("artifactregistry.repositories.create")
                        || p.starts_with("artifactregistry.repositories.update")
                });

                for repo in items {
                    if let Some(name) = repo.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "artifact_registry_repository".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(&perm_set, &["artifactregistry."]),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can push or modify Artifact Registry repositories"
                                    .into()
                            } else {
                                "Service account can list Artifact Registry repositories".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Artifact Registry enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_gke {
        let url = format!(
            "https://container.googleapis.com/v1/projects/{}/locations/-/clusters",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Kubernetes Engine API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("clusters").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("container.clusters.update")
                        || p.starts_with("container.clusters.create")
                });

                for cluster in items {
                    if let Some(name) = cluster.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "gke_cluster".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(&perm_set, &["container.clusters."]),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can modify or create GKE clusters".into()
                            } else {
                                "Service account can list GKE clusters".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: GKE enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_bigquery {
        let url =
            format!("https://bigquery.googleapis.com/bigquery/v2/projects/{}/datasets", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: BigQuery API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("datasets").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("bigquery.tables.update")
                        || p.starts_with("bigquery.tables.delete")
                        || p.starts_with("bigquery.jobs.create")
                        || p.starts_with("bigquery.datasets.update")
                        || p.starts_with("bigquery.datasets.delete")
                });

                for dataset in items {
                    if let Some(ds_id) = dataset
                        .get("datasetReference")
                        .and_then(|r| r.get("datasetId"))
                        .and_then(|n| n.as_str())
                    {
                        resources.push(ResourceExposure {
                            resource_type: "bigquery_dataset".into(),
                            name: format!("projects/{project_id}/datasets/{ds_id}"),
                            permissions: matching_permissions(
                                &perm_set,
                                &["bigquery.datasets.", "bigquery.tables.", "bigquery.jobs."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can modify BigQuery datasets or run jobs".into()
                            } else {
                                "Service account can list BigQuery datasets".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: BigQuery enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_secret_manager {
        let url =
            format!("https://secretmanager.googleapis.com/v1/projects/{}/secrets", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Secret Manager API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("secrets").and_then(|i| i.as_array()) {
                let can_access_values =
                    perm_set.iter().any(|p| p.contains("secretmanager.versions.access"));
                let can_write = perm_set.iter().any(|p| {
                    p.contains("secretmanager.secrets.create")
                        || p.contains("secretmanager.secrets.update")
                        || p.contains("secretmanager.versions.add")
                });
                let high_risk = can_access_values || can_write;

                for secret in items {
                    if let Some(name) = secret.get("name").and_then(|n| n.as_str()) {
                        let reason = if can_access_values && can_write {
                            "Service account can read and write secret values"
                        } else if can_access_values {
                            "Service account can read secret values"
                        } else if can_write {
                            "Service account can create or modify secrets"
                        } else {
                            "Service account can list secrets"
                        };
                        resources.push(ResourceExposure {
                            resource_type: "secretmanager_secret".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(
                                &perm_set,
                                &["secretmanager.secrets.", "secretmanager.versions."],
                            ),
                            risk: if high_risk { "high".into() } else { "medium".into() },
                            reason: reason.into(),
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Secret Manager enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_cloud_kms {
        let url = format!(
            "https://cloudkms.googleapis.com/v1/projects/{}/locations/-/keyRings",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud KMS API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(key_rings) = json.get("keyRings").and_then(|k| k.as_array()) {
                let can_decrypt = perm_set
                    .iter()
                    .any(|p| p.starts_with("cloudkms.cryptoKeyVersions.useToDecrypt"));
                let can_encrypt = perm_set
                    .iter()
                    .any(|p| p.starts_with("cloudkms.cryptoKeyVersions.useToEncrypt"));
                let writable = can_decrypt
                    || perm_set.iter().any(|p| {
                        p.starts_with("cloudkms.cryptoKeys.create")
                            || p.starts_with("cloudkms.cryptoKeys.update")
                    });

                for kr in key_rings {
                    if let Some(name) = kr.get("name").and_then(|n| n.as_str()) {
                        let risk = if can_decrypt {
                            "critical"
                        } else if writable || can_encrypt {
                            "high"
                        } else {
                            "medium"
                        };
                        let reason = if can_decrypt {
                            "Service account can decrypt data using KMS keys in this key ring"
                        } else if writable {
                            "Service account can manage KMS keys in this key ring"
                        } else {
                            "Service account can list KMS key rings"
                        };
                        resources.push(ResourceExposure {
                            resource_type: "kms_key_ring".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(
                                &perm_set,
                                &[
                                    "cloudkms.cryptoKeys.",
                                    "cloudkms.keyRings.",
                                    "cloudkms.cryptoKeyVersions.",
                                ],
                            ),
                            risk: risk.into(),
                            reason: reason.into(),
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Cloud KMS enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_cloud_functions {
        let url = format!(
            "https://cloudfunctions.googleapis.com/v2/projects/{}/locations/-/functions",
            project_id
        );
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud Functions API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(items) = json.get("functions").and_then(|f| f.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("cloudfunctions.functions.create")
                        || p.starts_with("cloudfunctions.functions.update")
                        || p.starts_with("cloudfunctions.functions.delete")
                });

                for func in items {
                    if let Some(name) = func.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "cloud_function".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(
                                &perm_set,
                                &["cloudfunctions.functions."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can deploy or modify Cloud Functions (code execution)".into()
                            } else {
                                "Service account can list Cloud Functions".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Cloud Functions enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_service_accounts {
        let url = format!("https://iam.googleapis.com/v1/projects/{}/serviceAccounts", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!("GCP access-map: IAM API disabled for project {project_id}: {disabled}");
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(accounts) = json.get("accounts").and_then(|a| a.as_array()) {
                let can_impersonate = perm_set.iter().any(|p| {
                    p.contains("serviceAccounts.actAs")
                        || p.contains("serviceAccounts.getAccessToken")
                });

                for sa in accounts {
                    if let Some(email) = sa.get("email").and_then(|e| e.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "service_account".into(),
                            name: format!("projects/{project_id}/serviceAccounts/{email}"),
                            permissions: matching_permissions(
                                &perm_set,
                                &["iam.serviceAccounts.", "iam.serviceAccountKeys."],
                            ),
                            risk: if can_impersonate { "high".into() } else { "medium".into() },
                            reason: if can_impersonate {
                                "Service account visible and potentially impersonatable".into()
                            } else {
                                "Service account visible in the project".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: service account enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_firestore {
        let url = format!("https://firestore.googleapis.com/v1/projects/{}/databases", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Firestore API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(databases) = json.get("databases").and_then(|d| d.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("datastore.entities.create")
                        || p.starts_with("datastore.entities.update")
                        || p.starts_with("datastore.entities.delete")
                });

                for db in databases {
                    if let Some(name) = db.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "firestore_database".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(
                                &perm_set,
                                &["datastore.databases.", "datastore.entities."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can read and write Firestore data".into()
                            } else {
                                "Service account can list Firestore databases".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Firestore enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    if add_spanner {
        let url = format!("https://spanner.googleapis.com/v1/projects/{}/instances", project_id);
        let resp = client.get(&url).bearer_auth(token).send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if let Some(disabled) = service_disabled_message(&body)? {
            verbose_warn!(
                "GCP access-map: Cloud Spanner API disabled for project {project_id}: {disabled}"
            );
        } else if status.is_success() {
            let json: Value = serde_json::from_slice(&body)?;
            if let Some(instances) = json.get("instances").and_then(|i| i.as_array()) {
                let writable = perm_set.iter().any(|p| {
                    p.starts_with("spanner.instances.update")
                        || p.starts_with("spanner.instances.create")
                        || p.starts_with("spanner.databases.write")
                });

                for instance in instances {
                    if let Some(name) = instance.get("name").and_then(|n| n.as_str()) {
                        resources.push(ResourceExposure {
                            resource_type: "spanner_instance".into(),
                            name: name.to_string(),
                            permissions: matching_permissions(
                                &perm_set,
                                &["spanner.instances.", "spanner.databases."],
                            ),
                            risk: if writable { "high".into() } else { "medium".into() },
                            reason: if writable {
                                "Service account can manage Cloud Spanner instances".into()
                            } else {
                                "Service account can list Cloud Spanner instances".into()
                            },
                        });
                    }
                }
            }
        } else if status != StatusCode::FORBIDDEN {
            verbose_warn!(
                "GCP access-map: Cloud Spanner enumeration failed: HTTP {} {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
    }

    Ok(resources)
}

async fn fetch_service_account_iam_policy(
    client: &Client,
    token: &str,
    project_id: &str,
    client_email: &str,
) -> Result<Option<Value>> {
    let encoded_email = utf8_percent_encode(client_email, NON_ALPHANUMERIC);
    let url = format!(
        "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}:getIamPolicy",
        project_id, encoded_email
    );

    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "options": { "requestedPolicyVersion": 3 } }))
        .send()
        .await?;
    let status = resp.status();
    let body = resp.bytes().await?;

    if let Some(disabled) = service_disabled_message(&body)? {
        verbose_warn!(
            "GCP access-map: IAM API disabled when fetching service account policy: {disabled}"
        );
        return Ok(None);
    }

    if status == StatusCode::FORBIDDEN {
        verbose_warn!("GCP access-map: service account IAM policy forbidden for {client_email}");
        return Ok(None);
    }

    if !status.is_success() {
        return Err(anyhow!(
            "Failed to fetch service account IAM policy: HTTP {} {}",
            status,
            String::from_utf8_lossy(&body)
        ));
    }

    let policy: Value = serde_json::from_slice(&body)?;
    Ok(Some(policy))
}

fn extract_impersonation_notes(policy: &Value) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(bindings) = policy.get("bindings").and_then(|b| b.as_array()) {
        for binding in bindings {
            let role = binding.get("role").and_then(|r| r.as_str()).unwrap_or("");
            if !(role.contains("serviceAccountTokenCreator")
                || role.contains("serviceAccountUser")
                || role.contains("ServiceAccountUser"))
            {
                continue;
            }

            if let Some(members) = binding.get("members").and_then(|m| m.as_array()) {
                for member in members {
                    if let Some(m) = member.as_str() {
                        notes.push(format!("{m} can impersonate this service account via {role}"));
                    }
                }
            }
        }
    }
    notes
}

fn derive_risk_notes(roles: &[RoleBinding], permissions: &PermissionSummary) -> Vec<String> {
    let mut notes = Vec::new();
    if !permissions.admin.is_empty() {
        notes.push(format!("Admin-level roles attached: {}", permissions.admin.join(", ")));
    }
    if !permissions.privilege_escalation.is_empty() {
        notes.push(format!(
            "Privilege escalation permissions detected: {}",
            permissions.privilege_escalation.join(", ")
        ));
    }

    let perm_set = collect_permission_set(roles);
    if perm_set.iter().any(|p| p.contains("serviceAccounts.actAs")) {
        notes.push("Can impersonate other service accounts (iam.serviceAccounts.actAs)".into());
    }
    if perm_set.iter().any(|p| p.contains("resourcemanager.projects.setIamPolicy")) {
        notes.push("Can modify project IAM policies".into());
    }
    if perm_set.iter().any(|p| {
        p.starts_with("storage.") && (p.contains("objects.create") || p.contains("buckets.update"))
    }) {
        notes.push("Has write access to Cloud Storage resources".into());
    }
    if perm_set.iter().any(|p| p.contains("secretmanager.secrets.addVersion")) {
        notes.push("Can write new versions into Secret Manager".into());
    }
    if perm_set.iter().any(|p| p.contains("secretmanager.versions.access")) {
        notes.push("Can read secret values from Secret Manager".into());
    }
    if perm_set.iter().any(|p| p.contains("cloudkms.cryptoKeyVersions.useToDecrypt")) {
        notes.push("Can decrypt data using Cloud KMS".into());
    }
    if perm_set.iter().any(|p| {
        p.starts_with("cloudfunctions.functions.create")
            || p.starts_with("cloudfunctions.functions.update")
    }) {
        notes.push("Can deploy or modify Cloud Functions (code execution)".into());
    }
    if perm_set.iter().any(|p| p.contains("compute.instances.setMetadata")) {
        notes.push("Can modify instance metadata (SSH key injection risk)".into());
    }

    if roles.iter().any(|r| r.source.starts_with("org:")) {
        notes.push("Inherited organization-level roles detected".into());
    }
    if roles.iter().any(|r| r.source.starts_with("folder:")) {
        notes.push("Inherited folder-level roles detected".into());
    }

    notes
}

fn sorted(items: HashSet<String>) -> Vec<String> {
    let mut v: Vec<_> = items.into_iter().collect();
    v.sort();
    v
}

async fn test_project_permissions(
    client: &Client,
    token: &str,
    project_id: &str,
) -> Result<Vec<String>> {
    let candidates = vec![
        "resourcemanager.projects.getIamPolicy",
        "resourcemanager.projects.setIamPolicy",
        "resourcemanager.projects.testIamPermissions",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.list",
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccountKeys.list",
        "iam.serviceAccountTokenCreator",
        "storage.buckets.list",
        "storage.objects.list",
        "compute.instances.list",
        "compute.instances.create",
        "compute.instances.setMetadata",
        "bigquery.datasets.get",
        "bigquery.tables.list",
        "bigquery.jobs.create",
        "secretmanager.secrets.list",
        "secretmanager.versions.access",
        "cloudsql.instances.list",
        "pubsub.topics.list",
        "pubsub.subscriptions.list",
        "run.services.list",
        "cloudfunctions.functions.list",
        "cloudfunctions.functions.create",
        "artifactregistry.repositories.list",
        "container.clusters.list",
        "cloudkms.keyRings.list",
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "spanner.instances.list",
        "datastore.databases.list",
    ];

    let url = format!(
        "https://cloudresourcemanager.googleapis.com/v1/projects/{}:testIamPermissions",
        project_id
    );

    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "permissions": candidates }))
        .send()
        .await?;

    if resp.status() == StatusCode::FORBIDDEN {
        verbose_warn!("GCP access-map: testIamPermissions forbidden for project {project_id}");
        return Ok(Vec::new());
    }

    let resp = resp.error_for_status()?;
    let json: Value = resp.json().await?;
    let permissions = json
        .get("permissions")
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(permissions)
}

async fn test_service_account_permissions(
    client: &Client,
    token: &str,
    project_id: &str,
    client_email: &str,
) -> Result<Vec<String>> {
    let candidates = vec![
        "iam.serviceAccounts.get",
        "iam.serviceAccounts.getIamPolicy",
        "iam.serviceAccounts.actAs",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.signJwt",
        "iam.serviceAccounts.implicitDelegation",
        "iam.serviceAccountKeys.list",
    ];

    let encoded_email = utf8_percent_encode(client_email, NON_ALPHANUMERIC);
    let resource = format!("projects/{}/serviceAccounts/{}", project_id, encoded_email);

    let url = format!("https://iam.googleapis.com/v1/{}:testIamPermissions", resource);

    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "permissions": candidates }))
        .send()
        .await?;

    if resp.status() == StatusCode::FORBIDDEN {
        verbose_warn!(
            "GCP access-map: testIamPermissions forbidden for service account {client_email}"
        );
        return Ok(Vec::new());
    }

    let resp = resp.error_for_status()?;
    let json: Value = resp.json().await?;
    let permissions = json
        .get("permissions")
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|p| p.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(permissions)
}

fn service_disabled_message(body: &[u8]) -> Result<Option<String>> {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    let Some(error) = parsed.get("error") else {
        return Ok(None);
    };

    if let Some(details) = error.get("details").and_then(|d| d.as_array()) {
        for detail in details {
            let reason = detail.get("reason").and_then(|r| r.as_str());
            if reason == Some("SERVICE_DISABLED") {
                let metadata = detail.get("metadata");
                let service_title = metadata
                    .and_then(|m| m.get("serviceTitle"))
                    .and_then(|s| s.as_str())
                    .or_else(|| metadata.and_then(|m| m.get("service")).and_then(|s| s.as_str()))
                    .unwrap_or("unknown service");
                let activation_url = metadata
                    .and_then(|m| m.get("activationUrl"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("https://console.developers.google.com/apis/dashboard");

                return Ok(Some(format!(
                    "{service_title} is disabled; enable it at {activation_url}"
                )));
            }
        }
    }

    Ok(None)
}
