use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as b64, URL_SAFE, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use quick_xml::{Reader, events::Event};
use reqwest::{Client, Url, header::HeaderValue};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use sha2::Sha256;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";
const DEFAULT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com";
const DEFAULT_MANAGEMENT_BASE_URL: &str = "https://management.azure.com";
const MICROSOFT_ACCOUNT_TENANT_ID: &str = "9188040d-6c67-4c5b-b112-36a304b66dad";
const MAX_GRAPH_PAGES: usize = 10;
const MAX_ARM_PAGES: usize = 10;
const MAX_SUBSCRIPTIONS: usize = 25;
const MAX_RBAC_PRINCIPALS: usize = 10;
const MAX_ROLE_DEFINITIONS: usize = 100;

#[derive(Clone, Copy)]
enum StorageService {
    Blob,
    File,
    Queue,
}

impl StorageService {
    fn endpoint_suffix(self) -> &'static str {
        match self {
            StorageService::Blob => "blob.core.windows.net",
            StorageService::File => "file.core.windows.net",
            StorageService::Queue => "queue.core.windows.net",
        }
    }

    fn resource_type(self) -> &'static str {
        match self {
            StorageService::Blob => "storage_container",
            StorageService::File => "storage_file_share",
            StorageService::Queue => "storage_queue",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            StorageService::Blob => "blob containers",
            StorageService::File => "file shares",
            StorageService::Queue => "queues",
        }
    }
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("Azure access-map requires a credential JSON path"))?;
    let data = std::fs::read_to_string(path).context("Failed to read credential file")?;
    map_access_from_json(&data).await
}

pub async fn map_access_from_json(data: &str) -> Result<AccessMapResult> {
    map_access_from_json_with_hints(data, None).await
}

pub async fn map_access_from_json_with_hints(
    data: &str,
    containers_hint: Option<&[String]>,
) -> Result<AccessMapResult> {
    let credential = parse_azure_credentials(data)?;
    match credential {
        AzureCredential::Storage { storage_account, storage_key } => {
            map_storage_access(storage_account, storage_key, containers_hint).await
        }
        AzureCredential::Enterprise(config) => map_enterprise_access(config).await,
    }
}

async fn map_storage_access(
    storage_account: String,
    storage_key: String,
    containers_hint: Option<&[String]>,
) -> Result<AccessMapResult> {
    let mut risk_notes =
        vec!["Storage account keys grant full control over the storage account".to_string()];

    let containers = match containers_hint {
        Some(list) if !list.is_empty() => list.to_vec(),
        _ => match list_service_items(&storage_account, &storage_key, StorageService::Blob).await {
            Ok(list) => list,
            Err(err) => {
                risk_notes.push(format!("Container enumeration failed: {err}"));
                Vec::new()
            }
        },
    };
    let file_shares =
        match list_service_items(&storage_account, &storage_key, StorageService::File).await {
            Ok(list) => list,
            Err(err) => {
                risk_notes.push(format!("File share enumeration failed: {err}"));
                Vec::new()
            }
        };
    let queues =
        match list_service_items(&storage_account, &storage_key, StorageService::Queue).await {
            Ok(list) => list,
            Err(err) => {
                risk_notes.push(format!("Queue enumeration failed: {err}"));
                Vec::new()
            }
        };

    let severity = Severity::Critical;
    let permissions =
        PermissionSummary { admin: vec!["storage:*".into()], ..PermissionSummary::default() };

    let roles = vec![RoleBinding {
        name: "storage_account_key".into(),
        source: "shared_key".into(),
        permissions: vec!["storage:*".into()],
    }];

    let mut resources = Vec::new();
    resources.push(ResourceExposure {
        resource_type: "storage_account".into(),
        name: storage_account.clone(),
        permissions: vec!["storage:*".into()],
        risk: "critical".into(),
        reason: "Storage account accessible with shared key".into(),
    });

    push_storage_resources(
        &mut resources,
        containers,
        StorageService::Blob,
        "Blob container accessible with shared key",
        "Blob container list unavailable; storage account key still grants full access",
    );
    push_storage_resources(
        &mut resources,
        file_shares,
        StorageService::File,
        "File share accessible with shared key",
        "File share list unavailable; storage account key still grants full access",
    );
    push_storage_resources(
        &mut resources,
        queues,
        StorageService::Queue,
        "Queue accessible with shared key",
        "Queue list unavailable; storage account key still grants full access",
    );

    let identity = AccessSummary {
        id: storage_account,
        access_type: "storage_account_key".into(),
        project: None,
        tenant: None,
        account_id: None,
    };

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "azure".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: None,
        provider_metadata: None,
        fingerprint: None,
    })
}

enum AzureCredential {
    Storage { storage_account: String, storage_key: String },
    Enterprise(EnterpriseCredential),
}

#[derive(Clone)]
struct EnterpriseCredential {
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    graph_access_token: Option<String>,
    management_access_token: Option<String>,
    authority_host: String,
    graph_base_url: String,
    management_base_url: String,
}

#[derive(Default)]
struct AzureTokens {
    graph: Option<String>,
    management: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct TokenClaims {
    audience: Option<String>,
    tenant_id: Option<String>,
    object_id: Option<String>,
    client_id: Option<String>,
    subject: Option<String>,
    name: Option<String>,
    username: Option<String>,
    token_type: Option<String>,
    version: Option<String>,
    scopes: Vec<String>,
    roles: Vec<String>,
    groups: Vec<String>,
    directory_roles: Vec<String>,
    expires_at: Option<i64>,
}

impl TokenClaims {
    fn is_application(&self) -> bool {
        self.token_type.as_deref() == Some("app")
            || (!self.roles.is_empty() && self.scopes.is_empty())
            || (self.client_id.is_some() && self.username.is_none() && self.scopes.is_empty())
    }

    fn permissions(&self) -> Vec<String> {
        let mut values = self.roles.clone();
        values.extend(self.scopes.clone());
        values.sort();
        values.dedup();
        values
    }

    fn merge_missing(&mut self, other: &Self) {
        if self.audience.is_none() {
            self.audience.clone_from(&other.audience);
        }
        if self.tenant_id.is_none() {
            self.tenant_id.clone_from(&other.tenant_id);
        }
        if self.object_id.is_none() {
            self.object_id.clone_from(&other.object_id);
        }
        if self.client_id.is_none() {
            self.client_id.clone_from(&other.client_id);
        }
        if self.subject.is_none() {
            self.subject.clone_from(&other.subject);
        }
        if self.name.is_none() {
            self.name.clone_from(&other.name);
        }
        if self.username.is_none() {
            self.username.clone_from(&other.username);
        }
        if self.token_type.is_none() {
            self.token_type.clone_from(&other.token_type);
        }
        if self.version.is_none() {
            self.version.clone_from(&other.version);
        }
        if self.expires_at.is_none() {
            self.expires_at = other.expires_at;
        }
        self.scopes.extend(other.scopes.iter().cloned());
        self.roles.extend(other.roles.iter().cloned());
        self.groups.extend(other.groups.iter().cloned());
        self.directory_roles.extend(other.directory_roles.iter().cloned());
        sort_dedup(&mut self.scopes);
        sort_dedup(&mut self.roles);
        sort_dedup(&mut self.groups);
        sort_dedup(&mut self.directory_roles);
    }
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize, Default)]
struct GraphCollection<T> {
    #[serde(default)]
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct GraphPrincipal {
    #[serde(default)]
    id: String,
    #[serde(rename = "appId")]
    app_id: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
    mail: Option<String>,
    #[serde(rename = "userType")]
    user_type: Option<String>,
    #[serde(rename = "servicePrincipalType")]
    service_principal_type: Option<String>,
    #[serde(rename = "accountEnabled")]
    account_enabled: Option<bool>,
    #[serde(rename = "appOwnerOrganizationId")]
    app_owner_organization_id: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct GraphDirectoryObject {
    #[serde(default)]
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "@odata.type")]
    odata_type: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct GraphOrganization {
    #[serde(default)]
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ArmCollection<T> {
    #[serde(default)]
    value: Vec<T>,
    #[serde(rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmSubscription {
    #[serde(rename = "subscriptionId", default)]
    subscription_id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    state: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmResourceGroup {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    location: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmRoleAssignment {
    #[serde(default)]
    id: String,
    #[serde(default)]
    properties: ArmRoleAssignmentProperties,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmRoleAssignmentProperties {
    #[serde(rename = "roleDefinitionId", default)]
    role_definition_id: String,
    #[serde(default)]
    scope: String,
    #[serde(rename = "principalId")]
    principal_id: Option<String>,
    #[serde(rename = "principalType")]
    principal_type: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmRoleDefinition {
    #[serde(default)]
    id: String,
    #[serde(default)]
    properties: ArmRoleDefinitionProperties,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmRoleDefinitionProperties {
    #[serde(rename = "roleName")]
    role_name: Option<String>,
    #[serde(default)]
    permissions: Vec<ArmRolePermission>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct ArmRolePermission {
    #[serde(default)]
    actions: Vec<String>,
    #[serde(rename = "dataActions", default)]
    data_actions: Vec<String>,
}

#[derive(Clone)]
struct RbacPrincipal {
    id: String,
    source: String,
}

fn parse_azure_credentials(data: &str) -> Result<AzureCredential> {
    let values = parse_credential_values(data)?;

    let storage_account =
        find_value(&values, &["storage_account", "storageAccount", "account_name", "AccountName"]);
    let storage_key =
        find_value(&values, &["storage_key", "storageKey", "account_key", "AccountKey"]);
    if let (Some(storage_account), Some(storage_key)) = (storage_account, storage_key) {
        return Ok(AzureCredential::Storage { storage_account, storage_key });
    }

    let tenant_id = find_value(
        &values,
        &["tenant_id", "tenantId", "tenant", "AZURE_TENANT_ID", "ARM_TENANT_ID"],
    );
    let client_id = find_value(
        &values,
        &["client_id", "clientId", "appId", "application_id", "AZURE_CLIENT_ID", "ARM_CLIENT_ID"],
    );
    let client_secret = find_value(
        &values,
        &["client_secret", "clientSecret", "password", "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET"],
    );
    let generic_access_token = find_value(&values, &["access_token", "accessToken"]);
    let mut graph_access_token =
        find_value(&values, &["graph_access_token", "graphAccessToken", "MS_GRAPH_TOKEN"]);
    let mut management_access_token = find_value(
        &values,
        &["management_access_token", "managementAccessToken", "arm_access_token", "armAccessToken"],
    );

    if let Some(token) = generic_access_token {
        match decode_token_claims(&token).audience.as_deref() {
            Some(audience) if is_management_audience(audience) => {
                management_access_token.get_or_insert(token);
            }
            _ => {
                graph_access_token.get_or_insert(token);
            }
        }
    }

    let has_client_credentials =
        tenant_id.is_some() && client_id.is_some() && client_secret.is_some();
    if !has_client_credentials && graph_access_token.is_none() && management_access_token.is_none()
    {
        bail!(
            "Azure credential file must contain storage_account/storage_key, \
             tenant_id/client_id/client_secret, or an Azure access token"
        );
    }

    Ok(AzureCredential::Enterprise(EnterpriseCredential {
        tenant_id,
        client_id,
        client_secret,
        graph_access_token,
        management_access_token,
        authority_host: find_value(
            &values,
            &["authority_host", "authorityHost", "AZURE_AUTHORITY_HOST"],
        )
        .unwrap_or_else(|| DEFAULT_AUTHORITY_HOST.to_string()),
        graph_base_url: find_value(
            &values,
            &["graph_base_url", "graphBaseUrl", "AZURE_GRAPH_BASE_URL"],
        )
        .unwrap_or_else(|| DEFAULT_GRAPH_BASE_URL.to_string()),
        management_base_url: find_value(
            &values,
            &["management_base_url", "managementBaseUrl", "AZURE_MANAGEMENT_BASE_URL"],
        )
        .unwrap_or_else(|| DEFAULT_MANAGEMENT_BASE_URL.to_string()),
    }))
}

fn parse_credential_values(data: &str) -> Result<BTreeMap<String, String>> {
    if let Ok(JsonValue::Object(object)) = serde_json::from_str::<JsonValue>(data) {
        return Ok(object
            .into_iter()
            .filter_map(|(key, value)| value.as_str().map(|value| (key, value.to_string())))
            .collect());
    }

    let mut values = BTreeMap::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            continue;
        };
        let value = value.trim().trim_matches(['"', '\'']);
        if !key.trim().is_empty() && !value.is_empty() {
            values.insert(key.trim().to_string(), value.to_string());
        }
    }

    if values.is_empty() {
        bail!("Azure credential file must be a JSON object or KEY=VALUE document");
    }
    Ok(values)
}

fn find_value(values: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|candidate| {
        values.iter().find_map(|(key, value)| {
            key.eq_ignore_ascii_case(candidate)
                .then(|| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
    })
}

async fn map_enterprise_access(config: EnterpriseCredential) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Azure access-map HTTP client")?;
    let mut risk_notes = Vec::new();
    let tokens = acquire_enterprise_tokens(&client, &config, &mut risk_notes).await?;

    let graph_claims = tokens.graph.as_deref().map(decode_token_claims).unwrap_or_default();
    let management_claims =
        tokens.management.as_deref().map(decode_token_claims).unwrap_or_default();
    let mut claims = graph_claims.clone();
    claims.merge_missing(&management_claims);

    if claims.tenant_id.is_none() {
        claims.tenant_id.clone_from(&config.tenant_id);
    }
    if claims.client_id.is_none() {
        claims.client_id.clone_from(&config.client_id);
    }
    if claims.token_type.is_none() && config.client_secret.is_some() {
        claims.token_type = Some("app".into());
    }

    let mut graph = GraphMapping::default();
    if let Some(graph_token) = tokens.graph.as_deref() {
        graph = map_graph_access(
            &client,
            &config.graph_base_url,
            graph_token,
            &claims,
            &mut risk_notes,
        )
        .await;
    } else {
        risk_notes.push(
            "No Microsoft Graph token was available; Entra directory enumeration was skipped"
                .into(),
        );
    }

    let principal_id = graph
        .principal
        .as_ref()
        .map(|principal| principal.id.as_str())
        .filter(|value| !value.is_empty())
        .or(claims.object_id.as_deref());
    let mut rbac_principals = BTreeMap::<String, String>::new();
    if let Some(principal_id) = principal_id {
        rbac_principals.insert(principal_id.to_string(), "direct principal".into());
    }
    for membership in &graph.memberships {
        if membership.odata_type.as_deref().is_some_and(|kind| kind.ends_with("group"))
            && !membership.id.is_empty()
        {
            rbac_principals.insert(
                membership.id.clone(),
                format!(
                    "Entra group {}",
                    membership.display_name.as_deref().unwrap_or(&membership.id)
                ),
            );
        }
    }
    for group_id in &claims.groups {
        rbac_principals
            .entry(group_id.clone())
            .or_insert_with(|| format!("Entra group {group_id}"));
    }
    let rbac_principals: Vec<RbacPrincipal> =
        rbac_principals.into_iter().map(|(id, source)| RbacPrincipal { id, source }).collect();

    let mut arm = ArmMapping::default();
    if let Some(management_token) = tokens.management.as_deref() {
        arm = map_arm_access(
            &client,
            &config.management_base_url,
            management_token,
            &rbac_principals,
            &mut risk_notes,
        )
        .await;
    } else {
        risk_notes.push(
            "No Azure Resource Manager token was available; subscription and RBAC enumeration \
             was skipped"
                .into(),
        );
    }

    let mut permissions = PermissionSummary::default();
    let graph_permissions = graph_claims.permissions();
    for permission in &graph_permissions {
        classify_graph_permission(permission, &mut permissions);
    }
    merge_permissions(&mut permissions, arm.permissions.clone());

    let mut roles = Vec::new();
    if !graph_permissions.is_empty() {
        roles.push(RoleBinding {
            name: if graph_claims.is_application() {
                "microsoft_graph_application_permissions".into()
            } else {
                "microsoft_graph_delegated_scopes".into()
            },
            source: "access_token_claims".into(),
            permissions: graph_permissions.clone(),
        });
    }
    let mut resources = graph.resources.clone();
    resources.extend(arm.resources.clone());

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "entra_tenant".into(),
            name: claims
                .tenant_id
                .clone()
                .or(config.tenant_id.clone())
                .unwrap_or_else(|| "unknown_tenant".into()),
            permissions: graph_permissions.clone(),
            risk: severity_to_str(Severity::Medium).into(),
            reason: "Azure credential authenticated, but resource enumeration was restricted"
                .into(),
        });
    }

    for membership in &graph.memberships {
        if membership.odata_type.as_deref().is_some_and(|kind| kind.ends_with("directoryRole")) {
            roles.push(RoleBinding {
                name: membership.display_name.clone().unwrap_or_else(|| membership.id.clone()),
                source: "entra_directory_role".into(),
                permissions: Vec::new(),
            });
        }
    }

    let severity = derive_enterprise_severity(&permissions, &graph.memberships, &arm);
    let mut recommendations = build_recommendations(severity);
    recommendations.push(
        "Review Microsoft Graph admin consent, Entra directory roles, and Azure RBAC assignments"
            .into(),
    );
    if config.client_secret.is_some() {
        recommendations.push(
            "Replace long-lived client secrets with managed identity, workload identity \
             federation, or certificate authentication"
                .into(),
        );
    }

    let principal = graph.principal.as_ref();
    let identity_id = principal
        .and_then(|value| {
            value
                .user_principal_name
                .clone()
                .or(value.display_name.clone())
                .or(value.app_id.clone())
                .or_else(|| (!value.id.is_empty()).then(|| value.id.clone()))
        })
        .or_else(|| claims.username.clone())
        .or_else(|| claims.name.clone())
        .or_else(|| claims.object_id.clone())
        .or_else(|| claims.client_id.clone())
        .unwrap_or_else(|| "azure_principal".into());
    let access_type = if claims.is_application() || config.client_secret.is_some() {
        "entra_service_principal"
    } else {
        "entra_delegated_user"
    };
    let tenant_id = graph
        .organization
        .as_ref()
        .map(|organization| organization.id.clone())
        .filter(|value| !value.is_empty())
        .or(claims.tenant_id.clone())
        .or(config.tenant_id.clone());

    if let Some(organization) = &graph.organization
        && let Some(name) = organization.display_name.as_deref()
    {
        risk_notes.push(format!("Microsoft Entra tenant: {name}"));
    }
    if graph_claims.is_application() && !graph_permissions.is_empty() {
        risk_notes.push(format!(
            "Application token carries {} Microsoft Graph application permission(s)",
            graph_permissions.len()
        ));
    } else if !graph_permissions.is_empty() {
        risk_notes.push(format!(
            "Delegated token carries {} Microsoft Graph scope(s)",
            graph_permissions.len()
        ));
    }
    if !arm.subscriptions.is_empty() {
        risk_notes.push(format!(
            "Azure Resource Manager exposed {} subscription(s)",
            arm.subscriptions.len()
        ));
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "azure".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: access_type.into(),
            project: arm
                .subscriptions
                .first()
                .map(|subscription| subscription.subscription_id.clone()),
            tenant: tenant_id,
            account_id: claims.client_id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations,
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: principal.and_then(|value| value.display_name.clone()).or(claims.name.clone()),
            username: principal
                .and_then(|value| value.user_principal_name.clone())
                .or(claims.username.clone()),
            account_type: Some(access_type.into()),
            email: principal.and_then(|value| value.mail.clone()),
            token_type: Some(if config.client_secret.is_some() {
                "oauth2_client_credentials".into()
            } else {
                "oauth2_access_token".into()
            }),
            expires_at: claims.expires_at.and_then(format_timestamp),
            user_id: claims.object_id.clone(),
            scopes: graph_permissions,
            ..AccessTokenDetails::default()
        }),
        provider_metadata: Some(ProviderMetadata {
            version: claims.version,
            enterprise: claims
                .tenant_id
                .as_deref()
                .map(|tenant_id| tenant_id != MICROSOFT_ACCOUNT_TENANT_ID),
        }),
        fingerprint: None,
    })
}

async fn acquire_enterprise_tokens(
    client: &Client,
    config: &EnterpriseCredential,
    risk_notes: &mut Vec<String>,
) -> Result<AzureTokens> {
    let mut tokens = AzureTokens {
        graph: config.graph_access_token.clone(),
        management: config.management_access_token.clone(),
    };

    let (Some(tenant_id), Some(client_id), Some(client_secret)) =
        (config.tenant_id.as_deref(), config.client_id.as_deref(), config.client_secret.as_deref())
    else {
        if tokens.graph.is_none() && tokens.management.is_none() {
            bail!("Azure enterprise credential did not contain usable access tokens");
        }
        return Ok(tokens);
    };

    if tokens.graph.is_none() {
        let scope = default_scope(&config.graph_base_url);
        match request_client_token(
            client,
            &config.authority_host,
            tenant_id,
            client_id,
            client_secret,
            &scope,
        )
        .await
        {
            Ok(token) => tokens.graph = Some(token.access_token),
            Err(err) => {
                warn!("Azure access-map: Microsoft Graph token acquisition failed: {err}");
                risk_notes.push(format!("Microsoft Graph token acquisition failed: {err}"));
            }
        }
    }

    if tokens.management.is_none() {
        let scope = default_scope(&config.management_base_url);
        match request_client_token(
            client,
            &config.authority_host,
            tenant_id,
            client_id,
            client_secret,
            &scope,
        )
        .await
        {
            Ok(token) => tokens.management = Some(token.access_token),
            Err(err) => {
                warn!("Azure access-map: Resource Manager token acquisition failed: {err}");
                risk_notes.push(format!("Azure Resource Manager token acquisition failed: {err}"));
            }
        }
    }

    if tokens.graph.is_none() && tokens.management.is_none() {
        bail!("Azure client credentials could not acquire a Microsoft Graph or management token");
    }
    Ok(tokens)
}

async fn request_client_token(
    client: &Client,
    authority_host: &str,
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Result<OAuthTokenResponse> {
    let url = append_url(authority_host, &format!("{tenant_id}/oauth2/v2.0/token"))?;
    let response = client
        .post(url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("scope", scope),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .await
        .context("Azure OAuth2 token request failed")?;
    parse_json_response(response, "Azure OAuth2 token request").await
}

fn default_scope(base_url: &str) -> String {
    format!("{}/.default", base_url.trim_end_matches('/'))
}

fn decode_token_claims(token: &str) -> TokenClaims {
    let Some(payload) = token.split('.').nth(1) else {
        return TokenClaims::default();
    };
    let decoded = URL_SAFE_NO_PAD.decode(payload).or_else(|_| URL_SAFE.decode(payload));
    let Ok(decoded) = decoded else {
        return TokenClaims::default();
    };
    let Ok(value) = serde_json::from_slice::<JsonValue>(&decoded) else {
        return TokenClaims::default();
    };

    TokenClaims {
        audience: json_string(&value, &["aud"]),
        tenant_id: json_string(&value, &["tid", "tenant_id"]),
        object_id: json_string(&value, &["oid"]),
        client_id: json_string(&value, &["appid", "azp", "client_id"]),
        subject: json_string(&value, &["sub"]),
        name: json_string(&value, &["name"]),
        username: json_string(&value, &["preferred_username", "upn", "unique_name"]),
        token_type: json_string(&value, &["idtyp"]),
        version: json_string(&value, &["ver"]),
        scopes: json_string(&value, &["scp"])
            .map(|scope| scope.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        roles: json_string_array(&value, "roles"),
        groups: json_string_array(&value, "groups"),
        directory_roles: json_string_array(&value, "wids"),
        expires_at: value.get("exp").and_then(JsonValue::as_i64),
    }
}

fn json_string(value: &JsonValue, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(JsonValue::as_str)
            .map(str::to_string)
            .filter(|value| !value.is_empty())
    })
}

fn json_string_array(value: &JsonValue, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .map(str::to_string)
        .collect()
}

fn is_management_audience(audience: &str) -> bool {
    let audience = audience.trim_end_matches('/');
    audience.eq_ignore_ascii_case("https://management.azure.com")
        || audience.eq_ignore_ascii_case("https://management.core.windows.net")
}

#[derive(Default)]
struct GraphMapping {
    principal: Option<GraphPrincipal>,
    organization: Option<GraphOrganization>,
    memberships: Vec<GraphDirectoryObject>,
    resources: Vec<ResourceExposure>,
}

async fn map_graph_access(
    client: &Client,
    graph_base_url: &str,
    access_token: &str,
    claims: &TokenClaims,
    risk_notes: &mut Vec<String>,
) -> GraphMapping {
    let mut mapping = GraphMapping::default();
    let object_id = claims.object_id.as_deref();
    let principal_path = if claims.is_application() {
        object_id.map(|id| {
            format!(
                "v1.0/servicePrincipals/{id}?$select=id,appId,displayName,servicePrincipalType,\
                 accountEnabled,appOwnerOrganizationId"
            )
        })
    } else {
        Some(
            "v1.0/me?$select=id,displayName,userPrincipalName,mail,userType,accountEnabled"
                .to_string(),
        )
    };

    if let Some(path) = principal_path {
        match graph_get::<GraphPrincipal>(client, graph_base_url, access_token, &path).await {
            Ok(principal) => {
                let display_name = principal
                    .display_name
                    .clone()
                    .or(principal.user_principal_name.clone())
                    .or(principal.app_id.clone())
                    .unwrap_or_else(|| principal.id.clone());
                let mut metadata = Vec::new();
                if let Some(kind) =
                    principal.service_principal_type.as_deref().or(principal.user_type.as_deref())
                {
                    metadata.push(format!("type:{kind}"));
                }
                if let Some(enabled) = principal.account_enabled {
                    metadata.push(format!("account_enabled:{enabled}"));
                }
                if let Some(owner_tenant) = principal.app_owner_organization_id.as_deref() {
                    metadata.push(format!("app_owner_tenant:{owner_tenant}"));
                }
                mapping.resources.push(ResourceExposure {
                    resource_type: if claims.is_application() {
                        "entra_service_principal".into()
                    } else {
                        "entra_user".into()
                    },
                    name: display_name,
                    permissions: metadata,
                    risk: severity_to_str(Severity::High).into(),
                    reason: "Microsoft Graph resolved the authenticated Entra principal".into(),
                });
                mapping.principal = Some(principal);
            }
            Err(err) => {
                warn!("Azure access-map: Graph principal lookup failed: {err}");
                risk_notes.push(format!("Microsoft Graph principal lookup failed: {err}"));
            }
        }
    } else {
        risk_notes.push(
            "Access token did not expose an object ID; service-principal lookup was skipped".into(),
        );
    }

    match graph_get_collection::<GraphOrganization>(
        client,
        graph_base_url,
        access_token,
        "v1.0/organization?$select=id,displayName",
    )
    .await
    {
        Ok(organizations) => {
            if let Some(organization) = organizations.into_iter().next() {
                mapping.resources.push(ResourceExposure {
                    resource_type: "entra_tenant".into(),
                    name: organization
                        .display_name
                        .clone()
                        .unwrap_or_else(|| organization.id.clone()),
                    permissions: claims.permissions(),
                    risk: severity_to_str(Severity::High).into(),
                    reason: "Microsoft Entra tenant reachable through Microsoft Graph".into(),
                });
                mapping.organization = Some(organization);
            }
        }
        Err(err) => {
            warn!("Azure access-map: Graph organization lookup failed: {err}");
            risk_notes.push(format!("Microsoft Graph tenant lookup was restricted: {err}"));
        }
    }

    let membership_path = if claims.is_application() {
        object_id.map(|id| {
            format!("v1.0/servicePrincipals/{id}/transitiveMemberOf?$select=id,displayName")
        })
    } else {
        Some("v1.0/me/transitiveMemberOf?$select=id,displayName".to_string())
    };
    if let Some(path) = membership_path {
        match graph_get_collection::<GraphDirectoryObject>(
            client,
            graph_base_url,
            access_token,
            &path,
        )
        .await
        {
            Ok(memberships) => {
                for membership in &memberships {
                    let is_role = membership
                        .odata_type
                        .as_deref()
                        .is_some_and(|kind| kind.ends_with("directoryRole"));
                    mapping.resources.push(ResourceExposure {
                        resource_type: if is_role {
                            "entra_directory_role".into()
                        } else {
                            "entra_group".into()
                        },
                        name: membership
                            .display_name
                            .clone()
                            .unwrap_or_else(|| membership.id.clone()),
                        permissions: Vec::new(),
                        risk: severity_to_str(if is_role {
                            Severity::Critical
                        } else {
                            Severity::Medium
                        })
                        .into(),
                        reason: if is_role {
                            "Authenticated principal is transitively assigned this directory role"
                                .into()
                        } else {
                            "Authenticated principal is transitively a member of this Entra group"
                                .into()
                        },
                    });
                }
                mapping.memberships = memberships;
            }
            Err(err) => {
                warn!("Azure access-map: Graph membership lookup failed: {err}");
                risk_notes.push(format!("Microsoft Graph membership lookup was restricted: {err}"));
            }
        }
    }

    if !claims.groups.is_empty() && mapping.memberships.is_empty() {
        risk_notes.push(format!(
            "Token claims expose {} group membership ID(s), but Graph could not resolve names",
            claims.groups.len()
        ));
        for group_id in &claims.groups {
            mapping.resources.push(ResourceExposure {
                resource_type: "entra_group".into(),
                name: group_id.clone(),
                permissions: Vec::new(),
                risk: severity_to_str(Severity::Medium).into(),
                reason: "Group membership was present in the access token claims".into(),
            });
        }
    }
    if !claims.directory_roles.is_empty() {
        risk_notes.push(format!(
            "Token claims expose {} Entra directory role template ID(s)",
            claims.directory_roles.len()
        ));
    }

    mapping
}

async fn graph_get<T: for<'de> Deserialize<'de>>(
    client: &Client,
    graph_base_url: &str,
    access_token: &str,
    path: &str,
) -> Result<T> {
    let url = append_url(graph_base_url, path)?;
    let response = client.get(url).bearer_auth(access_token).send().await?;
    parse_json_response(response, "Microsoft Graph request").await
}

async fn graph_get_collection<T: for<'de> Deserialize<'de> + Default>(
    client: &Client,
    graph_base_url: &str,
    access_token: &str,
    path: &str,
) -> Result<Vec<T>> {
    let base = Url::parse(graph_base_url).context("Invalid Microsoft Graph base URL")?;
    let mut next = Some(append_url(graph_base_url, path)?);
    let mut values = Vec::new();

    for _ in 0..MAX_GRAPH_PAGES {
        let Some(url) = next.take() else {
            break;
        };
        ensure_same_origin(&base, &url, "Microsoft Graph pagination")?;
        let response = client.get(url).bearer_auth(access_token).send().await?;
        let page: GraphCollection<T> =
            parse_json_response(response, "Microsoft Graph collection request").await?;
        values.extend(page.value);
        next = match page.next_link {
            Some(value) => Some(
                Url::parse(&value)
                    .or_else(|_| append_url(graph_base_url, &value))
                    .context("Microsoft Graph returned an invalid pagination URL")?,
            ),
            None => None,
        };
    }

    if next.is_some() {
        warn!("Azure access-map: stopped Microsoft Graph pagination after {MAX_GRAPH_PAGES} pages");
    }
    Ok(values)
}

#[derive(Default)]
struct ArmMapping {
    subscriptions: Vec<ArmSubscription>,
    roles: Vec<RoleBinding>,
    permissions: PermissionSummary,
    resources: Vec<ResourceExposure>,
}

async fn map_arm_access(
    client: &Client,
    management_base_url: &str,
    access_token: &str,
    rbac_principals: &[RbacPrincipal],
    risk_notes: &mut Vec<String>,
) -> ArmMapping {
    let mut mapping = ArmMapping::default();
    let subscriptions = match arm_get_collection::<ArmSubscription>(
        client,
        management_base_url,
        access_token,
        "subscriptions?api-version=2022-12-01",
    )
    .await
    {
        Ok(subscriptions) => subscriptions,
        Err(err) => {
            warn!("Azure access-map: subscription enumeration failed: {err}");
            risk_notes.push(format!("Azure subscription enumeration failed: {err}"));
            return mapping;
        }
    };

    if subscriptions.len() > MAX_SUBSCRIPTIONS {
        risk_notes.push(format!(
            "Azure subscription enumeration was capped at {MAX_SUBSCRIPTIONS} of {} subscriptions",
            subscriptions.len()
        ));
    }
    mapping.subscriptions = subscriptions.into_iter().take(MAX_SUBSCRIPTIONS).collect();
    if rbac_principals.len() > MAX_RBAC_PRINCIPALS {
        risk_notes.push(format!(
            "Azure RBAC lookup was capped at {MAX_RBAC_PRINCIPALS} of {} direct or \
             group-derived principals",
            rbac_principals.len()
        ));
    }
    let rbac_principals: Vec<&RbacPrincipal> =
        rbac_principals.iter().take(MAX_RBAC_PRINCIPALS).collect();

    let mut role_definitions = BTreeMap::<String, ArmRoleDefinition>::new();
    for subscription in &mapping.subscriptions {
        let subscription_name = subscription
            .display_name
            .clone()
            .unwrap_or_else(|| subscription.subscription_id.clone());
        let mut subscription_metadata =
            vec![format!("state:{}", subscription.state.as_deref().unwrap_or("unknown"))];
        if let Some(tenant_id) = subscription.tenant_id.as_deref() {
            subscription_metadata.push(format!("tenant:{tenant_id}"));
        }
        mapping.resources.push(ResourceExposure {
            resource_type: "azure_subscription".into(),
            name: subscription_name,
            permissions: subscription_metadata,
            risk: severity_to_str(Severity::Medium).into(),
            reason: "Subscription is visible through Azure Resource Manager".into(),
        });
        mapping.permissions.read_only.push("Microsoft.Resources/subscriptions/read".into());

        let resource_group_path = format!(
            "subscriptions/{}/resourcegroups?api-version=2021-04-01",
            subscription.subscription_id
        );
        match arm_get_collection::<ArmResourceGroup>(
            client,
            management_base_url,
            access_token,
            &resource_group_path,
        )
        .await
        {
            Ok(resource_groups) => {
                for group in resource_groups {
                    mapping.resources.push(ResourceExposure {
                        resource_type: "azure_resource_group".into(),
                        name: if group.name.is_empty() { group.id } else { group.name },
                        permissions: group
                            .location
                            .map(|location| vec![format!("location:{location}")])
                            .unwrap_or_default(),
                        risk: severity_to_str(Severity::Medium).into(),
                        reason: format!(
                            "Resource group is visible in subscription {}",
                            subscription.subscription_id
                        ),
                    });
                }
            }
            Err(err) => {
                warn!(
                    "Azure access-map: resource-group enumeration failed for {}: {err}",
                    subscription.subscription_id
                );
                risk_notes.push(format!(
                    "Resource-group enumeration failed for subscription {}: {err}",
                    subscription.subscription_id
                ));
            }
        }

        for rbac_principal in &rbac_principals {
            let role_path = format!(
                "subscriptions/{}/providers/Microsoft.Authorization/roleAssignments?\
                 api-version=2022-04-01&$filter=principalId%20eq%20{}",
                subscription.subscription_id, rbac_principal.id
            );
            let assignments = match arm_get_collection::<ArmRoleAssignment>(
                client,
                management_base_url,
                access_token,
                &role_path,
            )
            .await
            {
                Ok(assignments) => assignments,
                Err(err) => {
                    warn!(
                        "Azure access-map: RBAC enumeration failed for {} via {}: {err}",
                        subscription.subscription_id, rbac_principal.source
                    );
                    risk_notes.push(format!(
                        "Azure RBAC assignment enumeration failed for subscription {} via {}: \
                         {err}",
                        subscription.subscription_id, rbac_principal.source
                    ));
                    continue;
                }
            };

            for assignment in assignments {
                let role_definition_id = assignment.properties.role_definition_id.clone();
                if !role_definition_id.is_empty()
                    && !role_definitions.contains_key(&role_definition_id)
                    && role_definitions.len() < MAX_ROLE_DEFINITIONS
                {
                    match arm_get::<ArmRoleDefinition>(
                        client,
                        management_base_url,
                        access_token,
                        &format!("{role_definition_id}?api-version=2022-04-01"),
                    )
                    .await
                    {
                        Ok(definition) => {
                            role_definitions.insert(role_definition_id.clone(), definition);
                        }
                        Err(err) => {
                            warn!("Azure access-map: role-definition lookup failed: {err}");
                            risk_notes.push(format!(
                                "Azure role-definition lookup failed for {role_definition_id}: \
                                 {err}"
                            ));
                        }
                    }
                }

                let definition = role_definitions.get(&role_definition_id);
                let role_name =
                    definition.and_then(|value| value.properties.role_name.clone()).unwrap_or_else(
                        || role_definition_id.rsplit('/').next().unwrap_or("unknown").into(),
                    );
                let actions = definition.map(role_definition_permissions).unwrap_or_default();
                let scope = if assignment.properties.scope.is_empty() {
                    format!("/subscriptions/{}", subscription.subscription_id)
                } else {
                    assignment.properties.scope.clone()
                };
                classify_arm_role(&role_name, &scope, &actions, &mut mapping.permissions);
                mapping.roles.push(RoleBinding {
                    name: role_name.clone(),
                    source: format!("{scope} via {}", rbac_principal.source),
                    permissions: actions.clone(),
                });
                let mut assignment_permissions = vec![
                    format!("role:{role_name}"),
                    format!("assignment_source:{}", rbac_principal.source),
                ];
                if let Some(principal_type) = assignment.properties.principal_type.as_deref() {
                    assignment_permissions.push(format!("principal_type:{principal_type}"));
                }
                if let Some(assigned_principal) = assignment.properties.principal_id.as_deref() {
                    assignment_permissions.push(format!("principal_id:{assigned_principal}"));
                }
                if !assignment.id.is_empty() {
                    assignment_permissions.push(format!("assignment_id:{}", assignment.id));
                }
                mapping.resources.push(ResourceExposure {
                    resource_type: "azure_rbac_assignment".into(),
                    name: scope,
                    permissions: assignment_permissions,
                    risk: severity_to_str(arm_role_severity(&role_name, &actions)).into(),
                    reason: if rbac_principal.source == "direct principal" {
                        "Direct Azure RBAC assignment for the authenticated principal".into()
                    } else {
                        format!("Azure RBAC assignment inherited through {}", rbac_principal.source)
                    },
                });
            }
        }
    }

    if role_definitions.len() == MAX_ROLE_DEFINITIONS {
        risk_notes.push(format!(
            "Azure role-definition resolution was capped at {MAX_ROLE_DEFINITIONS} definitions"
        ));
    }
    sort_permission_summary(&mut mapping.permissions);
    mapping
}

async fn arm_get<T: for<'de> Deserialize<'de>>(
    client: &Client,
    management_base_url: &str,
    access_token: &str,
    path: &str,
) -> Result<T> {
    let url = append_url(management_base_url, path)?;
    let response = client.get(url).bearer_auth(access_token).send().await?;
    parse_json_response(response, "Azure Resource Manager request").await
}

async fn arm_get_collection<T: for<'de> Deserialize<'de> + Default>(
    client: &Client,
    management_base_url: &str,
    access_token: &str,
    path: &str,
) -> Result<Vec<T>> {
    let base = Url::parse(management_base_url).context("Invalid Azure management base URL")?;
    let mut next = Some(append_url(management_base_url, path)?);
    let mut values = Vec::new();

    for _ in 0..MAX_ARM_PAGES {
        let Some(url) = next.take() else {
            break;
        };
        ensure_same_origin(&base, &url, "Azure Resource Manager pagination")?;
        let response = client.get(url).bearer_auth(access_token).send().await?;
        let page: ArmCollection<T> =
            parse_json_response(response, "Azure Resource Manager collection request").await?;
        values.extend(page.value);
        next = match page.next_link {
            Some(value) => Some(
                Url::parse(&value)
                    .or_else(|_| append_url(management_base_url, &value))
                    .context("Azure Resource Manager returned an invalid pagination URL")?,
            ),
            None => None,
        };
    }

    if next.is_some() {
        warn!("Azure access-map: stopped ARM pagination after {MAX_ARM_PAGES} pages");
    }
    Ok(values)
}

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
    operation: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        bail!("{operation} failed with HTTP {status}: {}", truncate(&body, 300));
    }
    response.json::<T>().await.with_context(|| format!("{operation} returned invalid JSON"))
}

fn append_url(base_url: &str, path: &str) -> Result<Url> {
    let mut base = base_url.trim_end_matches('/').to_string();
    base.push('/');
    let base = Url::parse(&base).with_context(|| format!("Invalid Azure API URL: {base_url}"))?;
    base.join(path.trim_start_matches('/'))
        .with_context(|| format!("Invalid Azure API path: {path}"))
}

fn ensure_same_origin(base: &Url, next: &Url, operation: &str) -> Result<()> {
    if base.scheme() != next.scheme()
        || base.host_str() != next.host_str()
        || base.port_or_known_default() != next.port_or_known_default()
    {
        bail!("{operation} returned a pagination URL on a different origin");
    }
    Ok(())
}

fn truncate(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn classify_graph_permission(permission: &str, summary: &mut PermissionSummary) {
    let normalized = permission.to_ascii_lowercase();
    if [
        "rolemanagement.readwrite.directory",
        "approleassignment.readwrite.all",
        "delegatedpermissiongrant.readwrite.all",
        "directory.readwrite.all",
        "application.readwrite.all",
        "application.readwrite.ownedby",
    ]
    .iter()
    .any(|value| normalized == *value)
    {
        summary.privilege_escalation.push(permission.to_string());
    } else if normalized.starts_with("policy.readwrite.")
        || normalized.starts_with("privilegedaccess.readwrite.")
    {
        summary.admin.push(permission.to_string());
    } else if normalized.contains(".readwrite")
        || normalized.ends_with(".write")
        || normalized.ends_with(".send")
        || normalized.contains("fullcontrol")
        || normalized.starts_with("devicemanagement")
    {
        summary.risky.push(permission.to_string());
    } else if normalized.contains(".read")
        || matches!(normalized.as_str(), "openid" | "profile" | "email" | "offline_access")
    {
        summary.read_only.push(permission.to_string());
    } else {
        summary.risky.push(permission.to_string());
    }
}

fn role_definition_permissions(definition: &ArmRoleDefinition) -> Vec<String> {
    let mut actions = Vec::new();
    for permission in &definition.properties.permissions {
        actions.extend(permission.actions.iter().cloned());
        actions.extend(permission.data_actions.iter().map(|action| format!("data:{action}")));
    }
    if !definition.id.is_empty() {
        actions.push(format!("role_definition:{}", definition.id));
    }
    sort_dedup(&mut actions);
    actions
}

fn classify_arm_role(
    role_name: &str,
    scope: &str,
    actions: &[String],
    summary: &mut PermissionSummary,
) {
    let permission = format!("azure_rbac:{role_name}@{scope}");
    let normalized_name = role_name.to_ascii_lowercase();
    let normalized_actions: Vec<String> =
        actions.iter().map(|action| action.to_ascii_lowercase()).collect();
    let can_assign_roles = normalized_actions.iter().any(|action| {
        action.contains("microsoft.authorization/roleassignments/write")
            || action.contains("microsoft.authorization/roledefinitions/write")
    });
    if can_assign_roles {
        summary.privilege_escalation.push(permission);
    } else if matches!(
        normalized_name.as_str(),
        "owner" | "user access administrator" | "role based access control administrator"
    ) {
        summary.admin.push(permission);
    } else if normalized_name.contains("contributor")
        || normalized_actions.iter().any(|action| {
            action == "*"
                || action.ends_with("/write")
                || action.ends_with("/delete")
                || action.starts_with("data:")
        })
    {
        summary.risky.push(permission);
    } else {
        summary.read_only.push(permission);
    }
}

fn arm_role_severity(role_name: &str, actions: &[String]) -> Severity {
    let mut summary = PermissionSummary::default();
    classify_arm_role(role_name, "scope", actions, &mut summary);
    if !summary.admin.is_empty() || !summary.privilege_escalation.is_empty() {
        Severity::Critical
    } else if !summary.risky.is_empty() {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn merge_permissions(target: &mut PermissionSummary, source: PermissionSummary) {
    target.admin.extend(source.admin);
    target.privilege_escalation.extend(source.privilege_escalation);
    target.risky.extend(source.risky);
    target.read_only.extend(source.read_only);
    sort_permission_summary(target);
}

fn sort_permission_summary(summary: &mut PermissionSummary) {
    sort_dedup(&mut summary.admin);
    sort_dedup(&mut summary.privilege_escalation);
    sort_dedup(&mut summary.risky);
    sort_dedup(&mut summary.read_only);
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn derive_enterprise_severity(
    permissions: &PermissionSummary,
    memberships: &[GraphDirectoryObject],
    arm: &ArmMapping,
) -> Severity {
    let has_directory_role = memberships.iter().any(|membership| {
        membership.odata_type.as_deref().is_some_and(|kind| kind.ends_with("directoryRole"))
    });
    if !permissions.admin.is_empty()
        || !permissions.privilege_escalation.is_empty()
        || has_directory_role
    {
        Severity::Critical
    } else if !permissions.risky.is_empty() || !arm.roles.is_empty() {
        Severity::High
    } else if !permissions.read_only.is_empty() || !arm.subscriptions.is_empty() {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn format_timestamp(timestamp: i64) -> Option<String> {
    DateTime::<Utc>::from_timestamp(timestamp, 0).map(|value| value.to_rfc3339())
}

fn push_storage_resources(
    resources: &mut Vec<ResourceExposure>,
    items: Vec<String>,
    service: StorageService,
    success_reason: &str,
    fallback_reason: &str,
) {
    if items.is_empty() {
        resources.push(ResourceExposure {
            resource_type: service.resource_type().into(),
            name: String::new(),
            permissions: vec!["storage:*".into()],
            risk: "critical".into(),
            reason: fallback_reason.into(),
        });
        return;
    }

    for item in items {
        resources.push(ResourceExposure {
            resource_type: service.resource_type().into(),
            name: item,
            permissions: vec!["storage:*".into()],
            risk: "critical".into(),
            reason: success_reason.into(),
        });
    }
}

async fn list_service_items(
    storage_account: &str,
    storage_key: &str,
    service: StorageService,
) -> Result<Vec<String>> {
    let mut items = std::collections::BTreeSet::new();
    let mut marker: Option<String> = None;
    let client = Client::builder().build()?;

    loop {
        let now_rfc = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mut url = reqwest::Url::parse(&format!(
            "https://{account}.{suffix}/",
            account = storage_account,
            suffix = service.endpoint_suffix()
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("comp", "list");
            if let Some(marker_value) = marker.as_deref() {
                query.append_pair("marker", marker_value);
            }
        }

        let canon_headers = format!("x-ms-date:{now_rfc}\nx-ms-version:2023-11-03\n");
        let mut canon_resource = format!("/{account}/\ncomp:list", account = storage_account);
        if let Some(marker_value) = marker.as_deref() {
            canon_resource.push_str(&format!("\nmarker:{marker_value}"));
        }
        let string_to_sign = format!(
            "GET\n\n\n\n\n\n\n\n\n\n\n\n{headers}{resource}",
            headers = canon_headers,
            resource = canon_resource
        );

        let key_bytes = b64.decode(storage_key)?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
            .map_err(|_| anyhow!("invalid key length"))?;
        mac.update(string_to_sign.as_bytes());
        let signature = b64.encode(mac.finalize().into_bytes());

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("x-ms-date", HeaderValue::from_str(&now_rfc)?);
        headers.insert("x-ms-version", HeaderValue::from_static("2023-11-03"));
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!(
                "SharedKey {account}:{sig}",
                account = storage_account,
                sig = signature
            ))?,
        );

        let resp = client.get(url).headers(headers).send().await?;
        let status = resp.status();
        let body_txt = resp.text().await?;

        if !status.is_success() {
            return Err(anyhow!(
                "Azure Storage list {} failed (HTTP {}): {}",
                service.display_name(),
                status,
                body_txt
            ));
        }

        let mut reader = Reader::from_str(&body_txt);
        reader.config_mut().trim_text(true);
        let mut buf = Vec::new();
        let mut next_marker: Option<String> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Eof) => break,
                Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"name") => {
                    let text = reader.read_text(e.name())?;
                    let name = text.decode()?.into_owned();
                    if !name.is_empty() {
                        items.insert(name);
                    }
                }
                Ok(Event::Start(e)) if e.name().as_ref().eq_ignore_ascii_case(b"nextmarker") => {
                    let text = reader.read_text(e.name())?;
                    let value = text.decode()?.into_owned();
                    if !value.trim().is_empty() {
                        next_marker = Some(value);
                    }
                }
                Err(e) => return Err(anyhow!("XML parse error: {e}")),
                _ => {}
            }
            buf.clear();
        }

        if next_marker.is_none() {
            break;
        }
        marker = next_marker;
    }

    Ok(items.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_string_contains, method, path, query_param},
    };

    use super::*;

    fn fake_jwt(payload: JsonValue) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{payload}.{}", "signaturebytes01234567890123456789")
    }

    #[test]
    fn parses_azure_cli_service_principal_aliases() {
        let credential = parse_azure_credentials(
            r#"{
                "appId": "12345678-90ab-4cde-8f01-234567890abc",
                "password": "secret-value",
                "tenant": "11111111-2222-4333-8444-555555555555"
            }"#,
        )
        .unwrap();

        let AzureCredential::Enterprise(config) = credential else {
            panic!("expected enterprise credential");
        };
        assert_eq!(config.client_id.as_deref(), Some("12345678-90ab-4cde-8f01-234567890abc"));
        assert_eq!(config.client_secret.as_deref(), Some("secret-value"));
        assert_eq!(config.tenant_id.as_deref(), Some("11111111-2222-4333-8444-555555555555"));
    }

    #[test]
    fn routes_management_audience_tokens_to_arm() {
        let token = fake_jwt(json!({
            "aud": "https://management.azure.com/",
            "tid": "tenant",
            "oid": "principal"
        }));
        let credential =
            parse_azure_credentials(&json!({ "access_token": token }).to_string()).unwrap();

        let AzureCredential::Enterprise(config) = credential else {
            panic!("expected enterprise credential");
        };
        assert!(config.graph_access_token.is_none());
        assert!(config.management_access_token.is_some());
    }

    #[test]
    fn classifies_graph_privilege_escalation_permissions() {
        let mut permissions = PermissionSummary::default();
        classify_graph_permission("Application.ReadWrite.All", &mut permissions);
        classify_graph_permission("User.Read.All", &mut permissions);
        classify_graph_permission("Mail.Send", &mut permissions);

        assert_eq!(permissions.privilege_escalation, vec!["Application.ReadWrite.All".to_string()]);
        assert_eq!(permissions.read_only, vec!["User.Read.All".to_string()]);
        assert_eq!(permissions.risky, vec!["Mail.Send".to_string()]);
    }

    #[test]
    fn classifies_rbac_role_assignment_write_as_privilege_escalation() {
        let mut permissions = PermissionSummary::default();
        classify_arm_role(
            "Custom IAM Operator",
            "/subscriptions/sub",
            &["Microsoft.Authorization/roleAssignments/write".into()],
            &mut permissions,
        );

        assert_eq!(
            permissions.privilege_escalation,
            vec!["azure_rbac:Custom IAM Operator@/subscriptions/sub".to_string()]
        );
    }

    #[tokio::test]
    async fn maps_entra_graph_and_arm_access_from_client_credentials() {
        let server = MockServer::start().await;
        let tenant_id = "11111111-2222-4333-8444-555555555555";
        let client_id = "12345678-90ab-4cde-8f01-234567890abc";
        let principal_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let graph_base_url = format!("{}/graph", server.uri());
        let management_base_url = format!("{}/management", server.uri());
        let graph_token = fake_jwt(json!({
            "aud": graph_base_url,
            "tid": tenant_id,
            "oid": principal_id,
            "appid": client_id,
            "idtyp": "app",
            "ver": "2.0",
            "roles": ["Directory.ReadWrite.All", "User.Read.All"],
            "exp": 4102444800_i64
        }));
        let management_token = fake_jwt(json!({
            "aud": management_base_url,
            "tid": tenant_id,
            "oid": principal_id,
            "appid": client_id,
            "idtyp": "app",
            "ver": "2.0",
            "exp": 4102444800_i64
        }));

        Mock::given(method("POST"))
            .and(path(format!("/{tenant_id}/oauth2/v2.0/token")))
            .and(body_string_contains("graph%2F.default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": graph_token
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/{tenant_id}/oauth2/v2.0/token")))
            .and(body_string_contains("management%2F.default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": management_token
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/graph/v1.0/servicePrincipals/{principal_id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": principal_id,
                "appId": client_id,
                "displayName": "Kingfisher Enterprise App",
                "servicePrincipalType": "Application",
                "accountEnabled": true,
                "appOwnerOrganizationId": tenant_id
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/organization"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "id": tenant_id,
                    "displayName": "Contoso"
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/graph/v1.0/servicePrincipals/{principal_id}/transitiveMemberOf")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "id": "group-id",
                    "displayName": "Production Operators",
                    "@odata.type": "#microsoft.graph.group"
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/management/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "subscriptionId": "sub-123",
                    "displayName": "Production",
                    "state": "Enabled",
                    "tenantId": tenant_id
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/management/subscriptions/sub-123/resourcegroups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "id": "/subscriptions/sub-123/resourceGroups/payments",
                    "name": "payments",
                    "location": "westus2"
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/management/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments",
            ))
            .and(query_param(
                "$filter",
                format!("principalId eq {principal_id}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments/ra-1",
                    "properties": {
                        "roleDefinitionId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/role-1",
                        "scope": "/subscriptions/sub-123",
                        "principalId": principal_id,
                        "principalType": "ServicePrincipal"
                    }
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/management/subscriptions/sub-123/providers/Microsoft.Authorization/roleAssignments",
            ))
            .and(query_param("$filter", "principalId eq group-id"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/management/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/role-1",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/role-1",
                "properties": {
                    "roleName": "Contributor",
                    "permissions": [{
                        "actions": ["*"],
                        "dataActions": []
                    }]
                }
            })))
            .mount(&server)
            .await;

        let credential = json!({
            "tenant_id": tenant_id,
            "client_id": client_id,
            "client_secret": "client-secret-value",
            "authority_host": server.uri(),
            "graph_base_url": graph_base_url,
            "management_base_url": management_base_url
        });
        let result = map_access_from_json(&credential.to_string()).await.unwrap();

        assert_eq!(result.identity.id, "Kingfisher Enterprise App");
        assert_eq!(result.identity.tenant.as_deref(), Some(tenant_id));
        assert_eq!(result.identity.project.as_deref(), Some("sub-123"));
        assert!(
            result
                .permissions
                .privilege_escalation
                .contains(&"Directory.ReadWrite.All".to_string())
        );
        assert!(
            result.permissions.risky.iter().any(|permission| permission.contains("Contributor"))
        );
        assert!(
            result
                .resources
                .iter()
                .any(|resource| resource.resource_type == "azure_resource_group")
        );
        assert!(result.resources.iter().any(|resource| resource.resource_type == "entra_group"));
        assert!(matches!(result.severity, Severity::Critical));
    }
}
