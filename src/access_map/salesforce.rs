use anyhow::{Context, Result, anyhow};
use regex::Regex;
use reqwest::{Client, StatusCode, Url, header};
use serde_json::Value;
use std::{collections::BTreeMap, sync::LazyLock};
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const FALLBACK_SALESFORCE_API_VERSION: &str = "v60.0";
const MAX_OBJECT_RESOURCES: usize = 100;
const MAX_ROLE_BINDINGS: usize = 100;

static TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?xi)\b(00[A-Z0-9]{13}![A-Z0-9._-]{80,260})\b")
        .expect("valid salesforce token regex")
});
static INSTANCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?xi)\b((?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:MY\.)?SALESFORCE\.COM)\b")
        .expect("valid salesforce instance regex")
});
static LEGACY_INSTANCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?xi)^[a-z]{2,8}[0-9]{1,4}\.salesforce\.com$")
        .expect("valid salesforce legacy instance regex")
});
static USER_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b005[A-Z0-9]{12}(?:[A-Z0-9]{3})?\b").expect("valid salesforce user id regex")
});
static ORG_ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b00D[A-Z0-9]{12}(?:[A-Z0-9]{3})?\b").expect("valid salesforce org id regex")
});

#[derive(Clone, Copy, Debug)]
enum PermissionRisk {
    Admin,
    PrivilegeEscalation,
    Risky,
    ReadOnly,
}

#[derive(Clone, Copy)]
struct TrackedSystemPermission {
    api_name: &'static str,
    risk: PermissionRisk,
}

const TRACKED_SYSTEM_PERMISSIONS: &[TrackedSystemPermission] = &[
    TrackedSystemPermission { api_name: "PermissionsModifyAllData", risk: PermissionRisk::Admin },
    TrackedSystemPermission { api_name: "PermissionsManageUsers", risk: PermissionRisk::Admin },
    TrackedSystemPermission {
        api_name: "PermissionsManageProfilesPermissionsets",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsAssignPermissionSets",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsManageSessionPermissionSets",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsManageRoles",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsManageSharing",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsAuthorApex",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsCustomizeApplication",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission {
        api_name: "PermissionsModifyMetadata",
        risk: PermissionRisk::PrivilegeEscalation,
    },
    TrackedSystemPermission { api_name: "PermissionsViewAllData", risk: PermissionRisk::Risky },
    TrackedSystemPermission {
        api_name: "PermissionsViewEncryptedData",
        risk: PermissionRisk::Risky,
    },
    TrackedSystemPermission {
        api_name: "PermissionsViewEventLogFiles",
        risk: PermissionRisk::Risky,
    },
    TrackedSystemPermission { api_name: "PermissionsDataExport", risk: PermissionRisk::Risky },
    TrackedSystemPermission {
        api_name: "PermissionsBulkApiHardDelete",
        risk: PermissionRisk::Risky,
    },
    TrackedSystemPermission {
        api_name: "PermissionsTransferAnyEntity",
        risk: PermissionRisk::Risky,
    },
    TrackedSystemPermission { api_name: "PermissionsViewAllUsers", risk: PermissionRisk::Risky },
    TrackedSystemPermission { api_name: "PermissionsApiEnabled", risk: PermissionRisk::Risky },
    TrackedSystemPermission { api_name: "PermissionsViewSetup", risk: PermissionRisk::ReadOnly },
    TrackedSystemPermission { api_name: "PermissionsRunReports", risk: PermissionRisk::ReadOnly },
    TrackedSystemPermission { api_name: "PermissionsExportReport", risk: PermissionRisk::Risky },
];

#[derive(Clone, Debug, Default)]
struct SalesforceUser {
    id: Option<String>,
    username: Option<String>,
    name: Option<String>,
    email: Option<String>,
    user_type: Option<String>,
    active: Option<bool>,
    profile_name: Option<String>,
    role_name: Option<String>,
}

#[derive(Clone, Debug)]
struct SalesforceObject {
    name: String,
    label: String,
    custom: bool,
    queryable: bool,
    retrieveable: bool,
    searchable: bool,
    createable: bool,
    updateable: bool,
    deletable: bool,
    undeletable: bool,
}

#[derive(Clone, Debug)]
struct EffectiveSystemPermission {
    api_name: String,
    label: String,
    risk: PermissionRisk,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AssignedRole {
    name: String,
    source: String,
}

#[derive(Default)]
struct SalesforceDiscovery {
    limits: Value,
    user_info: Value,
    user: SalesforceUser,
    objects: Vec<SalesforceObject>,
    system_permissions: Vec<EffectiveSystemPermission>,
    assigned_roles: Vec<AssignedRole>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!("Salesforce access-map requires a credential file with token and instance")
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read Salesforce credential file from {}", path.display())
    })?;
    let (token, instance) = parse_salesforce_credentials(&raw)?;
    map_access_from_token_and_instance(&token, &instance).await
}

pub async fn map_access_from_token_and_instance(
    token: &str,
    instance: &str,
) -> Result<AccessMapResult> {
    let instance_host = normalize_instance(instance)
        .ok_or_else(|| anyhow!("Salesforce access-map requires a valid instance domain"))?;
    let base_url = format!("https://{instance_host}");

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Salesforce HTTP client")?;

    map_access_with_client(&client, token, &base_url, &instance_host).await
}

async fn map_access_with_client(
    client: &Client,
    token: &str,
    base_url: &str,
    instance_host: &str,
) -> Result<AccessMapResult> {
    let mut risk_notes = Vec::new();
    let api_version = fetch_api_version(client, token, base_url).await.unwrap_or_else(|err| {
        warn!("Salesforce access-map: API version discovery failed: {err}");
        risk_notes.push(format!(
            "API version discovery failed; using {FALLBACK_SALESFORCE_API_VERSION}: {err}"
        ));
        FALLBACK_SALESFORCE_API_VERSION.to_string()
    });

    let (limits_result, user_info_result, objects_result) = tokio::join!(
        fetch_limits(client, token, base_url, &api_version),
        fetch_user_info(client, token, base_url),
        list_sobjects(client, token, base_url, &api_version),
    );

    // Limits is the baseline authentication check. Preserve the existing behavior of failing
    // closed when the token cannot reach the org at all.
    let limits = limits_result?;
    let user_info = user_info_result.unwrap_or_else(|err| {
        warn!("Salesforce access-map: userinfo lookup failed: {err}");
        risk_notes.push(format!("Identity lookup failed: {err}"));
        Value::Null
    });
    let objects = objects_result.unwrap_or_else(|err| {
        warn!("Salesforce access-map: global describe failed: {err}");
        risk_notes.push(format!("Object capability enumeration failed: {err}"));
        Vec::new()
    });

    let user_id =
        salesforce_id_from_value(&user_info, &["user_id", "userId", "sub", "id"], &USER_ID_RE);
    let (user_result, permission_result, assignment_result) = tokio::join!(
        fetch_current_user(client, token, base_url, &api_version, user_id.as_deref()),
        fetch_effective_system_permissions(client, token, base_url, &api_version),
        fetch_permission_assignments(client, token, base_url, &api_version, user_id.as_deref()),
    );

    let user = user_result.unwrap_or_else(|err| {
        warn!("Salesforce access-map: current user query failed: {err}");
        risk_notes.push(format!("Profile and role lookup failed: {err}"));
        SalesforceUser::default()
    });
    let system_permissions = permission_result.unwrap_or_else(|err| {
        warn!("Salesforce access-map: effective permission query failed: {err}");
        risk_notes.push(format!("Effective system-permission enumeration failed: {err}"));
        Vec::new()
    });
    let assigned_roles = assignment_result.unwrap_or_else(|err| {
        warn!("Salesforce access-map: permission-set assignment query failed: {err}");
        risk_notes.push(format!("Permission-set assignment enumeration failed: {err}"));
        Vec::new()
    });

    let discovery = SalesforceDiscovery {
        limits,
        user_info,
        user,
        objects,
        system_permissions,
        assigned_roles,
    };

    Ok(build_access_map(instance_host, &api_version, discovery, risk_notes))
}

fn build_access_map(
    instance_host: &str,
    api_version: &str,
    discovery: SalesforceDiscovery,
    mut risk_notes: Vec<String>,
) -> AccessMapResult {
    let SalesforceDiscovery {
        limits,
        user_info,
        user,
        mut objects,
        system_permissions,
        assigned_roles,
    } = discovery;

    let organization_id = salesforce_id_from_value(
        &user_info,
        &["organization_id", "organizationId", "org_id", "orgId", "id"],
        &ORG_ID_RE,
    );
    let user_id = user.id.clone().or_else(|| {
        salesforce_id_from_value(&user_info, &["user_id", "userId", "sub", "id"], &USER_ID_RE)
    });
    let username = user
        .username
        .clone()
        .or_else(|| value_as_string(&user_info, &["preferred_username", "preferredUsername"]));
    let full_name =
        user.name.clone().or_else(|| value_as_string(&user_info, &["name", "nickname"]));
    let email =
        user.email.clone().or_else(|| value_as_string(&user_info, &["email", "email_address"]));

    let identity_id = username
        .clone()
        .or_else(|| user_id.clone())
        .or_else(|| organization_id.clone())
        .unwrap_or_else(|| "salesforce_access_token".to_string());

    let mut permissions = PermissionSummary::default();
    permissions.read_only.push("api:limits:read".to_string());
    permissions.risky.push("api:rest_access".to_string());

    for permission in &system_permissions {
        let value = format!("system:{}", permission.api_name.trim_start_matches("Permissions"));
        match permission.risk {
            PermissionRisk::Admin => permissions.admin.push(value),
            PermissionRisk::PrivilegeEscalation => permissions.privilege_escalation.push(value),
            PermissionRisk::Risky => permissions.risky.push(value),
            PermissionRisk::ReadOnly => permissions.read_only.push(value),
        }
    }

    let mut readable_objects = 0;
    let mut writable_objects = 0;
    let mut deletable_objects = 0;
    let mut sensitive_read = false;
    let mut sensitive_write = false;

    for object in &objects {
        let object_permissions = object_permission_strings(object);
        let readable = object.queryable || object.retrieveable || object.searchable;
        let writable = object.createable || object.updateable;
        if readable {
            readable_objects += 1;
        }
        if writable {
            writable_objects += 1;
        }
        if object.deletable || object.undeletable {
            deletable_objects += 1;
        }
        if is_sensitive_object(object) {
            sensitive_read |= readable;
            sensitive_write |= writable || object.deletable || object.undeletable;
        }
        debug_assert!(!object_permissions.is_empty());
    }

    if !objects.is_empty() {
        permissions.read_only.push("sobjects:global_describe".to_string());
    }
    if readable_objects > 0 {
        permissions.read_only.push("sobjects:read".to_string());
    }
    if writable_objects > 0 {
        permissions.risky.push("sobjects:write".to_string());
    }
    if deletable_objects > 0 {
        permissions.risky.push("sobjects:delete".to_string());
    }
    if sensitive_read {
        permissions.risky.push("sensitive_objects:read".to_string());
    }
    if sensitive_write {
        permissions.risky.push("sensitive_objects:write".to_string());
    }
    sort_permission_summary(&mut permissions);

    let mut roles = vec![RoleBinding {
        name: "token_type:access_token".into(),
        source: "salesforce".into(),
        permissions: vec!["api:rest_access".into()],
    }];
    if let Some(profile) = &user.profile_name {
        roles.push(RoleBinding {
            name: profile.clone(),
            source: "profile".into(),
            permissions: Vec::new(),
        });
    }
    if let Some(role) = &user.role_name {
        roles.push(RoleBinding {
            name: role.clone(),
            source: "user_role".into(),
            permissions: Vec::new(),
        });
    }
    let mut assigned_roles = assigned_roles;
    assigned_roles.sort();
    assigned_roles.dedup();
    for assigned in assigned_roles.iter().take(MAX_ROLE_BINDINGS) {
        roles.push(RoleBinding {
            name: assigned.name.clone(),
            source: assigned.source.clone(),
            permissions: Vec::new(),
        });
    }
    if assigned_roles.len() > MAX_ROLE_BINDINGS {
        risk_notes.push(format!(
            "Role binding list truncated to first {MAX_ROLE_BINDINGS} entries ({} total assignments visible)",
            assigned_roles.len()
        ));
    }

    objects.sort_by(|left, right| {
        object_priority(right).cmp(&object_priority(left)).then_with(|| left.name.cmp(&right.name))
    });

    let severity = derive_severity(&permissions, sensitive_write, deletable_objects);
    let mut resources = vec![ResourceExposure {
        resource_type: "salesforce_org".into(),
        name: organization_id.clone().unwrap_or_else(|| instance_host.to_string()),
        permissions: vec!["api:limits:read".into(), "sobjects:global_describe".into()],
        risk: severity_to_str(severity).to_string(),
        reason: "Salesforce org reachable with this access token".to_string(),
    }];

    for object in objects.iter().take(MAX_OBJECT_RESOURCES) {
        let object_permissions = object_permission_strings(object);
        let object_severity = object_severity(object);
        resources.push(ResourceExposure {
            resource_type: if object.custom {
                "salesforce_custom_object".into()
            } else {
                "salesforce_object".into()
            },
            name: object.name.clone(),
            permissions: object_permissions,
            risk: severity_to_str(object_severity).to_string(),
            reason: format!(
                "{} ({}) capabilities reported by Salesforce global describe; record sharing and field security can further restrict accessible data",
                object.label, object.name
            ),
        });
    }
    if objects.len() > MAX_OBJECT_RESOURCES {
        risk_notes.push(format!(
            "Object resource list prioritized and truncated to {MAX_OBJECT_RESOURCES} entries ({} total objects visible)",
            objects.len()
        ));
    }

    if !objects.is_empty() {
        risk_notes.push(format!(
            "Salesforce reports object-level access to {readable_objects} readable, {writable_objects} writable, and {deletable_objects} deletable/undeletable objects; row sharing and field-level security may reduce effective record access"
        ));
    }
    if let Some((remaining, maximum)) = daily_api_limit(&limits) {
        risk_notes.push(format!("Daily API request allowance: {remaining} remaining of {maximum}"));
    } else if !limits.is_object() {
        risk_notes.push("Salesforce limits response was not a JSON object".to_string());
    }
    if user.active == Some(false) {
        risk_notes.push(
            "The queried Salesforce user is inactive even though the access token reached the API"
                .to_string(),
        );
    }
    if !system_permissions.is_empty() {
        let labels = system_permissions
            .iter()
            .map(|permission| permission.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        risk_notes.push(format!("High-signal effective system permissions: {labels}"));
    }

    let mut recommendations = build_recommendations(severity);
    recommendations.push(
        "Review the connected app, OAuth session, profile, permission sets, and permission-set groups tied to this token"
            .to_string(),
    );
    recommendations.push(
        "Correlate recent Login, ApiEvent, and RestApi activity for limits, object enumeration, bulk queries, and exports"
            .to_string(),
    );
    recommendations.sort();
    recommendations.dedup();

    AccessMapResult {
        cloud: "salesforce".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: user.user_type.clone().unwrap_or_else(|| "user_token".into()),
            project: organization_id.clone(),
            tenant: organization_id.clone(),
            account_id: organization_id,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations,
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: full_name,
            username,
            account_type: user.user_type,
            company: None,
            location: None,
            email,
            url: Some(format!("https://{instance_host}")),
            token_type: Some("access_token".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id,
            scopes: Vec::new(),
        }),
        provider_metadata: Some(ProviderMetadata {
            version: Some(api_version.to_string()),
            enterprise: None,
            authorization_evidence: None,
        }),
        fingerprint: None,
    }
}

fn parse_salesforce_credentials(raw: &str) -> Result<(String, String)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = value_as_string(&json, &["token", "access_token", "salesforce_token"]);
        let instance =
            value_as_string(&json, &["instance", "instance_url", "instanceUrl", "domain", "host"]);

        if let (Some(token), Some(instance)) = (token, instance) {
            let normalized = normalize_instance(&instance).ok_or_else(|| {
                anyhow!("Credential JSON contains an invalid Salesforce instance")
            })?;
            return Ok((token, normalized));
        }
    }

    let token = TOKEN_RE.captures(raw).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));
    let instance =
        INSTANCE_RE.captures(raw).and_then(|caps| caps.get(1).map(|m| m.as_str().to_string()));

    if let (Some(token), Some(instance)) = (token, instance) {
        return Ok((token, instance.to_ascii_lowercase()));
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if lines.len() >= 2
        && let Some(instance) = normalize_instance(lines[1])
    {
        return Ok((lines[0].to_string(), instance));
    }

    Err(anyhow!(
        "Salesforce credential format not recognized. Provide JSON with token + instance_url, or text containing both."
    ))
}

fn normalize_instance(raw: &str) -> Option<String> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.is_empty() {
        return None;
    }

    let candidate = if raw.contains("://") {
        raw.to_string()
    } else if raw.contains('.') {
        format!("https://{raw}")
    } else {
        format!("https://{raw}.my.salesforce.com")
    };

    let url = Url::parse(&candidate).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if url.path() != "/" && !url.path().is_empty() {
        return None;
    }

    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    if is_allowed_salesforce_host(&host) { Some(host) } else { None }
}

fn is_allowed_salesforce_host(host: &str) -> bool {
    if matches!(host, "login.salesforce.com" | "test.salesforce.com") {
        return false;
    }

    if let Some(prefix) = host.strip_suffix(".my.salesforce.com") {
        return valid_dns_labels(prefix);
    }

    LEGACY_INSTANCE_RE.is_match(host)
}

fn valid_dns_labels(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

async fn fetch_api_version(client: &Client, token: &str, base_url: &str) -> Result<String> {
    let body = send_json(
        client
            .get(format!("{base_url}/services/data/"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::ACCEPT, "application/json"),
        "Salesforce access-map: failed to discover API versions",
    )
    .await?;

    select_api_version(&body)
        .ok_or_else(|| anyhow!("Salesforce access-map: API version response contained no versions"))
}

fn select_api_version(body: &Value) -> Option<String> {
    body.as_array()?
        .iter()
        .filter_map(|entry| {
            let version = entry.get("version")?.as_str()?.trim();
            let numeric = version.trim_start_matches('v').parse::<f64>().ok()?;
            Some((numeric, format!("v{}", version.trim_start_matches('v'))))
        })
        .max_by(|left, right| left.0.total_cmp(&right.0))
        .map(|(_, version)| version)
}

async fn fetch_limits(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
) -> Result<Value> {
    send_json(
        authorized_get(client, token, format!("{base_url}/services/data/{api_version}/limits")),
        "Salesforce access-map: failed to query limits endpoint",
    )
    .await
}

async fn fetch_user_info(client: &Client, token: &str, base_url: &str) -> Result<Value> {
    send_json(
        authorized_get(client, token, format!("{base_url}/services/oauth2/userinfo")),
        "Salesforce access-map: failed to query userinfo endpoint",
    )
    .await
}

async fn list_sobjects(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
) -> Result<Vec<SalesforceObject>> {
    let body = send_json(
        authorized_get(client, token, format!("{base_url}/services/data/{api_version}/sobjects")),
        "Salesforce access-map: failed to query global describe endpoint",
    )
    .await?;

    let mut objects = Vec::new();
    if let Some(items) = body.get("sobjects").and_then(Value::as_array) {
        for item in items {
            let Some(name) = value_as_string(item, &["name"]) else {
                continue;
            };
            let label = value_as_string(item, &["label"]).unwrap_or_else(|| name.clone());
            objects.push(SalesforceObject {
                name,
                label,
                custom: value_as_bool(item, "custom"),
                queryable: value_as_bool(item, "queryable"),
                retrieveable: value_as_bool(item, "retrieveable"),
                searchable: value_as_bool(item, "searchable"),
                createable: value_as_bool(item, "createable"),
                updateable: value_as_bool(item, "updateable"),
                deletable: value_as_bool(item, "deletable"),
                undeletable: value_as_bool(item, "undeletable"),
            });
        }
    }
    objects.sort_by(|left, right| left.name.cmp(&right.name));
    objects.dedup_by(|left, right| left.name == right.name);
    Ok(objects)
}

async fn fetch_current_user(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
    user_id: Option<&str>,
) -> Result<SalesforceUser> {
    let Some(user_id) = user_id.filter(|value| USER_ID_RE.is_match(value)) else {
        return Ok(SalesforceUser::default());
    };
    let soql = format!(
        "SELECT Id, Username, Name, Email, UserType, IsActive, Profile.Name, UserRole.Name FROM User WHERE Id = '{user_id}' LIMIT 1"
    );
    let body = salesforce_query(client, token, base_url, api_version, &soql).await?;
    let record = body
        .get("records")
        .and_then(Value::as_array)
        .and_then(|records| records.first())
        .ok_or_else(|| anyhow!("Salesforce access-map: current user query returned no records"))?;

    Ok(SalesforceUser {
        id: value_as_string(record, &["Id"]),
        username: value_as_string(record, &["Username"]),
        name: value_as_string(record, &["Name"]),
        email: value_as_string(record, &["Email"]),
        user_type: value_as_string(record, &["UserType"]),
        active: record.get("IsActive").and_then(Value::as_bool),
        profile_name: record.get("Profile").and_then(|profile| value_as_string(profile, &["Name"])),
        role_name: record.get("UserRole").and_then(|role| value_as_string(role, &["Name"])),
    })
}

async fn fetch_effective_system_permissions(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
) -> Result<Vec<EffectiveSystemPermission>> {
    let describe = send_json(
        authorized_get(
            client,
            token,
            format!(
                "{base_url}/services/data/{api_version}/sobjects/UserPermissionAccess/describe"
            ),
        ),
        "Salesforce access-map: failed to describe UserPermissionAccess",
    )
    .await?;

    let mut available_fields = BTreeMap::new();
    if let Some(fields) = describe.get("fields").and_then(Value::as_array) {
        for field in fields {
            let Some(name) = value_as_string(field, &["name"]) else {
                continue;
            };
            if field.get("type").and_then(Value::as_str) != Some("boolean") {
                continue;
            }
            let label = value_as_string(field, &["label"]).unwrap_or_else(|| name.clone());
            available_fields.insert(name.to_ascii_lowercase(), (name, label));
        }
    }

    let selected = TRACKED_SYSTEM_PERMISSIONS
        .iter()
        .filter_map(|tracked| {
            available_fields
                .get(&tracked.api_name.to_ascii_lowercase())
                .map(|(name, label)| (tracked, name.clone(), label.clone()))
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Ok(Vec::new());
    }

    let field_list =
        selected.iter().map(|(_, name, _)| name.as_str()).collect::<Vec<_>>().join(", ");
    let soql = format!("SELECT Id, {field_list} FROM UserPermissionAccess LIMIT 1");
    let body = salesforce_query(client, token, base_url, api_version, &soql).await?;
    let Some(record) =
        body.get("records").and_then(Value::as_array).and_then(|records| records.first())
    else {
        return Ok(Vec::new());
    };

    let mut permissions = selected
        .into_iter()
        .filter(|(_, name, _)| record.get(name).and_then(Value::as_bool) == Some(true))
        .map(|(tracked, name, label)| EffectiveSystemPermission {
            api_name: name,
            label,
            risk: tracked.risk,
        })
        .collect::<Vec<_>>();
    permissions.sort_by(|left, right| left.api_name.cmp(&right.api_name));
    Ok(permissions)
}

async fn fetch_permission_assignments(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
    user_id: Option<&str>,
) -> Result<Vec<AssignedRole>> {
    let Some(user_id) = user_id.filter(|value| USER_ID_RE.is_match(value)) else {
        return Ok(Vec::new());
    };
    let soql = format!(
        "SELECT PermissionSet.Name, PermissionSet.Label, PermissionSetGroup.DeveloperName, PermissionSetGroup.MasterLabel FROM PermissionSetAssignment WHERE AssigneeId = '{user_id}'"
    );
    let body = salesforce_query(client, token, base_url, api_version, &soql).await?;
    let mut roles = Vec::new();
    if let Some(records) = body.get("records").and_then(Value::as_array) {
        for record in records {
            if let Some(permission_set) = record.get("PermissionSet")
                && let Some(name) = value_as_string(permission_set, &["Label", "Name"])
            {
                roles.push(AssignedRole { name, source: "permission_set".into() });
            }
            if let Some(group) = record.get("PermissionSetGroup")
                && let Some(name) = value_as_string(group, &["MasterLabel", "DeveloperName"])
            {
                roles.push(AssignedRole { name, source: "permission_set_group".into() });
            }
        }
    }
    roles.sort();
    roles.dedup();
    Ok(roles)
}

async fn salesforce_query(
    client: &Client,
    token: &str,
    base_url: &str,
    api_version: &str,
    soql: &str,
) -> Result<Value> {
    send_json(
        authorized_get(client, token, format!("{base_url}/services/data/{api_version}/query"))
            .query(&[("q", soql)]),
        "Salesforce access-map: SOQL query failed",
    )
    .await
}

fn authorized_get(client: &Client, token: &str, url: String) -> reqwest::RequestBuilder {
    client
        .get(url)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
}

async fn send_json(request: reqwest::RequestBuilder, context: &'static str) -> Result<Value> {
    let response = request.send().await.context(context)?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!("{context} with HTTP {}", response.status()));
    }
    response.json().await.with_context(|| format!("{context}: invalid JSON"))
}

fn salesforce_id_from_value(value: &Value, keys: &[&str], pattern: &Regex) -> Option<String> {
    for key in keys {
        if let Some(candidate) = value.get(*key).and_then(Value::as_str)
            && let Some(found) = pattern.find(candidate)
        {
            return Some(found.as_str().to_string());
        }
    }
    None
}

fn object_permission_strings(object: &SalesforceObject) -> Vec<String> {
    let mut permissions = Vec::new();
    if object.queryable {
        permissions.push("records:query".to_string());
    }
    if object.retrieveable {
        permissions.push("records:retrieve".to_string());
    }
    if object.searchable {
        permissions.push("records:search".to_string());
    }
    if object.createable {
        permissions.push("records:create".to_string());
    }
    if object.updateable {
        permissions.push("records:update".to_string());
    }
    if object.deletable {
        permissions.push("records:delete".to_string());
    }
    if object.undeletable {
        permissions.push("records:undelete".to_string());
    }
    if permissions.is_empty() {
        permissions.push("object:metadata".to_string());
    }
    permissions
}

fn is_sensitive_object(object: &SalesforceObject) -> bool {
    object.custom
        || matches!(
            object.name.as_str(),
            "Account"
                | "Contact"
                | "Lead"
                | "Opportunity"
                | "OpportunityLineItem"
                | "Case"
                | "User"
                | "UserRole"
                | "ContentDocument"
                | "ContentVersion"
                | "Attachment"
                | "EmailMessage"
                | "Task"
                | "Event"
                | "Campaign"
                | "Order"
                | "Contract"
                | "Quote"
                | "Asset"
                | "LoginHistory"
                | "AuthSession"
                | "ConnectedApplication"
                | "OAuthToken"
                | "EventLogFile"
                | "Report"
                | "Dashboard"
                | "ApexClass"
                | "ApexTrigger"
                | "SetupAuditTrail"
                | "PermissionSet"
                | "PermissionSetAssignment"
        )
}

fn object_priority(object: &SalesforceObject) -> u8 {
    let mut score = 0;
    if is_sensitive_object(object) {
        score += 8;
    }
    if object.deletable || object.undeletable {
        score += 4;
    }
    if object.createable || object.updateable {
        score += 2;
    }
    if object.queryable || object.retrieveable || object.searchable {
        score += 1;
    }
    score
}

fn object_severity(object: &SalesforceObject) -> Severity {
    let sensitive = is_sensitive_object(object);
    let writable = object.createable || object.updateable || object.deletable || object.undeletable;
    let readable = object.queryable || object.retrieveable || object.searchable;

    match (sensitive, writable, readable) {
        (true, true, _) => Severity::High,
        (true, false, true) | (false, true, _) => Severity::Medium,
        _ => Severity::Low,
    }
}

fn derive_severity(
    permissions: &PermissionSummary,
    sensitive_write: bool,
    deletable_objects: usize,
) -> Severity {
    if permissions.admin.iter().any(|permission| permission == "system:ModifyAllData") {
        Severity::Critical
    } else if !permissions.admin.is_empty()
        || !permissions.privilege_escalation.is_empty()
        || permissions.risky.iter().any(|permission| permission == "system:ViewAllData")
        || sensitive_write
        || deletable_objects > 0
    {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn daily_api_limit(limits: &Value) -> Option<(u64, u64)> {
    let daily = limits.get("DailyApiRequests")?;
    let remaining = daily.get("Remaining")?.as_u64()?;
    let maximum = daily.get("Max")?.as_u64()?;
    Some((remaining, maximum))
}

fn sort_permission_summary(summary: &mut PermissionSummary) {
    for values in [
        &mut summary.admin,
        &mut summary.privilege_escalation,
        &mut summary.risky,
        &mut summary.read_only,
    ] {
        values.sort();
        values.dedup();
    }
}

fn value_as_string(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(s) = value.get(*key).and_then(Value::as_str) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn value_as_bool(value: &Value, key: &str) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(false)
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
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    fn object(name: &str) -> SalesforceObject {
        SalesforceObject {
            name: name.to_string(),
            label: name.to_string(),
            custom: name.ends_with("__c"),
            queryable: false,
            retrieveable: false,
            searchable: false,
            createable: false,
            updateable: false,
            deletable: false,
            undeletable: false,
        }
    }

    #[test]
    fn normalizes_my_domain_sandbox_and_legacy_instances() {
        assert_eq!(
            normalize_instance("https://Acme.my.salesforce.com"),
            Some("acme.my.salesforce.com".to_string())
        );
        assert_eq!(
            normalize_instance("acme--dev.sandbox.my.salesforce.com"),
            Some("acme--dev.sandbox.my.salesforce.com".to_string())
        );
        assert_eq!(
            normalize_instance("na123.salesforce.com"),
            Some("na123.salesforce.com".to_string())
        );
        assert_eq!(normalize_instance("Acme"), Some("acme.my.salesforce.com".to_string()));
    }

    #[test]
    fn rejects_non_instance_hosts_and_url_smuggling() {
        assert_eq!(normalize_instance("https://login.salesforce.com"), None);
        assert_eq!(normalize_instance("https://test.salesforce.com"), None);
        assert_eq!(normalize_instance("https://salesforce.com.evil.example"), None);
        assert_eq!(normalize_instance("https://user@acme.my.salesforce.com"), None);
        assert_eq!(normalize_instance("https://acme.my.salesforce.com/path"), None);
    }

    #[test]
    fn parses_json_credentials_with_full_instance_url() {
        let token = format!("00D{}!{}", "A".repeat(12), "B".repeat(100));
        let raw = json!({
            "access_token": token,
            "instance_url": "https://acme--dev.sandbox.my.salesforce.com"
        })
        .to_string();

        let (parsed_token, instance) = parse_salesforce_credentials(&raw).unwrap();
        assert!(parsed_token.starts_with("00D"));
        assert_eq!(instance, "acme--dev.sandbox.my.salesforce.com");
    }

    #[test]
    fn selects_latest_numeric_api_version() {
        let body = json!([
            {"version": "59.0"},
            {"version": "66.0"},
            {"version": "60.0"}
        ]);
        assert_eq!(select_api_version(&body).as_deref(), Some("v66.0"));
    }

    #[test]
    fn maps_effective_object_capabilities_and_admin_permissions() {
        let mut account = object("Account");
        account.queryable = true;
        account.createable = true;
        account.updateable = true;
        let mut metadata = object("SomeMetadata");
        metadata.queryable = true;

        let result = build_access_map(
            "acme.my.salesforce.com",
            "v66.0",
            SalesforceDiscovery {
                limits: json!({"DailyApiRequests": {"Remaining": 900, "Max": 1000}}),
                user_info: json!({
                    "organization_id": "00D000000000001AAA",
                    "user_id": "005000000000001AAA",
                    "preferred_username": "admin@example.com"
                }),
                user: SalesforceUser {
                    id: Some("005000000000001AAA".into()),
                    username: Some("admin@example.com".into()),
                    name: Some("Example Admin".into()),
                    email: Some("admin@example.com".into()),
                    user_type: Some("Standard".into()),
                    active: Some(true),
                    profile_name: Some("System Administrator".into()),
                    role_name: Some("Operations".into()),
                },
                objects: vec![metadata, account],
                system_permissions: vec![EffectiveSystemPermission {
                    api_name: "PermissionsModifyAllData".into(),
                    label: "Modify All Data".into(),
                    risk: PermissionRisk::Admin,
                }],
                assigned_roles: vec![AssignedRole {
                    name: "Security Operations".into(),
                    source: "permission_set".into(),
                }],
            },
            Vec::new(),
        );

        assert!(matches!(result.severity, Severity::Critical));
        assert_eq!(result.provider_metadata.unwrap().version.as_deref(), Some("v66.0"));
        assert!(result.permissions.admin.contains(&"system:ModifyAllData".to_string()));
        assert!(result.permissions.risky.contains(&"sobjects:write".to_string()));
        let account = result.resources.iter().find(|resource| resource.name == "Account").unwrap();
        assert!(account.permissions.contains(&"records:query".to_string()));
        assert!(account.permissions.contains(&"records:create".to_string()));
        assert_eq!(account.risk, "high");
        assert!(result.roles.iter().any(|role| role.name == "System Administrator"));
        assert!(result.roles.iter().any(|role| role.name == "Security Operations"));
    }

    #[test]
    fn read_only_objects_remain_medium_credential_risk() {
        let mut object = object("SomeMetadata");
        object.queryable = true;
        let result = build_access_map(
            "acme.my.salesforce.com",
            "v60.0",
            SalesforceDiscovery {
                limits: json!({}),
                objects: vec![object],
                ..SalesforceDiscovery::default()
            },
            Vec::new(),
        );

        assert!(matches!(result.severity, Severity::Medium));
        assert!(result.permissions.read_only.contains(&"sobjects:read".to_string()));
        assert!(!result.permissions.risky.contains(&"sobjects:write".to_string()));
    }

    #[tokio::test]
    async fn returns_partial_map_when_optional_enumeration_is_denied() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/services/data/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"version": "66.0"}
            ])))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/services/data/v66.0/limits"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "DailyApiRequests": {"Remaining": 10, "Max": 100}
            })))
            .mount(&server)
            .await;

        let result = map_access_with_client(
            &Client::new(),
            "salesforce-access-token",
            &server.uri(),
            "acme.my.salesforce.com",
        )
        .await
        .unwrap();

        assert!(matches!(result.severity, Severity::Medium));
        assert_eq!(result.resources.len(), 1);
        assert!(result.risk_notes.iter().any(|note| note.contains("Identity lookup failed")));
        assert!(
            result
                .risk_notes
                .iter()
                .any(|note| note.contains("Object capability enumeration failed"))
        );
        assert!(
            result
                .risk_notes
                .iter()
                .any(|note| note.contains("Effective system-permission enumeration failed"))
        );
    }
}
