use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const TERRAFORM_API: &str = "https://app.terraform.io";

#[derive(Deserialize)]
struct TerraformAccountResponse {
    #[serde(default)]
    data: Option<TerraformAccountData>,
}

#[derive(Deserialize)]
struct TerraformAccountData {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: Option<TerraformAccountAttributes>,
}

#[derive(Deserialize)]
struct TerraformAccountAttributes {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default, rename = "is-service-account")]
    is_service_account: Option<bool>,
}

#[derive(Deserialize)]
struct TerraformOrgsResponse {
    #[serde(default)]
    data: Vec<TerraformOrgData>,
}

#[derive(Deserialize)]
struct TerraformOrgData {
    #[expect(dead_code)]
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: Option<TerraformOrgAttributes>,
}

#[derive(Deserialize)]
struct TerraformOrgAttributes {
    #[serde(default)]
    name: Option<String>,
    #[expect(dead_code)]
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    permissions: Option<TerraformOrgPermissions>,
}

#[derive(Deserialize)]
struct TerraformOrgPermissions {
    #[serde(default, rename = "can-create-workspace")]
    can_create_workspace: Option<bool>,
    #[serde(default, rename = "can-manage-modules")]
    can_manage_modules: Option<bool>,
    #[serde(default, rename = "can-manage-providers")]
    can_manage_providers: Option<bool>,
    #[serde(default, rename = "can-update")]
    can_update: Option<bool>,
    #[serde(default, rename = "can-destroy")]
    can_destroy: Option<bool>,
    #[serde(default, rename = "can-access-via-teams")]
    can_access_via_teams: Option<bool>,
}

#[derive(Deserialize)]
struct TerraformWorkspacesResponse {
    #[serde(default)]
    data: Vec<TerraformWorkspaceData>,
}

#[derive(Deserialize)]
struct TerraformWorkspaceData {
    #[expect(dead_code)]
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    attributes: Option<TerraformWorkspaceAttributes>,
}

#[derive(Deserialize)]
struct TerraformWorkspaceAttributes {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    locked: Option<bool>,
    #[serde(default, rename = "auto-apply")]
    auto_apply: Option<bool>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Terraform token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Terraform access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Terraform HTTP client")?;

    let account = fetch_account(&client, token).await?;

    let account_data = account.data.as_ref();
    let attrs = account_data.and_then(|d| d.attributes.as_ref());

    let username = attrs
        .and_then(|a| a.username.clone())
        .or_else(|| attrs.and_then(|a| a.email.clone()))
        .unwrap_or_else(|| "terraform_user".to_string());

    let is_service_account = attrs.and_then(|a| a.is_service_account).unwrap_or(false);

    let identity = AccessSummary {
        id: username.clone(),
        access_type: if is_service_account { "service_account".into() } else { "user".into() },
        project: None,
        tenant: None,
        account_id: account_data.and_then(|d| d.id.clone()),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut all_scopes: Vec<String> = Vec::new();

    let orgs = list_organizations(&client, token).await.unwrap_or_else(|err| {
        warn!("Terraform access-map: organization enumeration failed: {err}");
        Vec::new()
    });

    let mut has_org_admin = false;
    let mut has_workspace_write = false;

    for org in &orgs {
        let org_attrs = org.attributes.as_ref();
        let org_name =
            org_attrs.and_then(|a| a.name.clone()).unwrap_or_else(|| "unknown_org".to_string());

        let org_perms = org_attrs.and_then(|a| a.permissions.as_ref());

        // Classify org-level permissions.
        if let Some(perms) = org_perms {
            if perms.can_manage_modules == Some(true) {
                permissions.admin.push(format!("{org_name}:can-manage-modules"));
                all_scopes.push(format!("{org_name}:can-manage-modules"));
                has_org_admin = true;
            }
            if perms.can_manage_providers == Some(true) {
                permissions.admin.push(format!("{org_name}:can-manage-providers"));
                all_scopes.push(format!("{org_name}:can-manage-providers"));
                has_org_admin = true;
            }
            if perms.can_destroy == Some(true) {
                permissions.admin.push(format!("{org_name}:can-destroy"));
                all_scopes.push(format!("{org_name}:can-destroy"));
                has_org_admin = true;
            }
            if perms.can_create_workspace == Some(true) {
                permissions.risky.push(format!("{org_name}:can-create-workspace"));
                all_scopes.push(format!("{org_name}:can-create-workspace"));
                has_workspace_write = true;
            }
            if perms.can_update == Some(true) {
                permissions.risky.push(format!("{org_name}:can-update"));
                all_scopes.push(format!("{org_name}:can-update"));
                has_workspace_write = true;
            }
            if perms.can_access_via_teams == Some(true) {
                permissions.read_only.push(format!("{org_name}:can-access-via-teams"));
                all_scopes.push(format!("{org_name}:can-access-via-teams"));
            }
        }

        let org_perm_list: Vec<String> = org_perms
            .map(|p| {
                let mut v = Vec::new();
                if p.can_manage_modules == Some(true) {
                    v.push("can-manage-modules".to_string());
                }
                if p.can_manage_providers == Some(true) {
                    v.push("can-manage-providers".to_string());
                }
                if p.can_create_workspace == Some(true) {
                    v.push("can-create-workspace".to_string());
                }
                if p.can_update == Some(true) {
                    v.push("can-update".to_string());
                }
                if p.can_destroy == Some(true) {
                    v.push("can-destroy".to_string());
                }
                v
            })
            .unwrap_or_default();

        roles.push(RoleBinding {
            name: format!("org:{org_name}"),
            source: "terraform".into(),
            permissions: org_perm_list.clone(),
        });

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name.clone(),
            permissions: org_perm_list,
            risk: severity_to_str(if has_org_admin {
                Severity::Critical
            } else if has_workspace_write {
                Severity::High
            } else {
                Severity::Medium
            })
            .to_string(),
            reason: "Terraform Cloud organization accessible with this token".into(),
        });

        // Enumerate workspaces.
        let workspaces = list_workspaces(&client, token, &org_name).await.unwrap_or_else(|err| {
            warn!("Terraform access-map: workspace enumeration for {org_name} failed: {err}");
            Vec::new()
        });

        for ws in &workspaces {
            let ws_attrs = ws.attributes.as_ref();
            let ws_name = ws_attrs
                .and_then(|a| a.name.clone())
                .unwrap_or_else(|| "unknown_workspace".to_string());

            let is_auto_apply = ws_attrs.and_then(|a| a.auto_apply).unwrap_or(false);
            let is_locked = ws_attrs.and_then(|a| a.locked).unwrap_or(false);

            let mut ws_notes = Vec::new();
            if is_auto_apply {
                ws_notes.push("auto-apply enabled");
            }
            if !is_locked {
                ws_notes.push("unlocked");
            }

            let ws_risk = if has_workspace_write && is_auto_apply && !is_locked {
                Severity::High
            } else if has_workspace_write {
                Severity::Medium
            } else {
                Severity::Low
            };

            resources.push(ResourceExposure {
                resource_type: "workspace".into(),
                name: format!("{org_name}/{ws_name}"),
                permissions: vec!["workspace:read".to_string()],
                risk: severity_to_str(ws_risk).to_string(),
                reason: if ws_notes.is_empty() {
                    "Workspace accessible with this token".to_string()
                } else {
                    format!("Workspace accessible ({})", ws_notes.join(", "))
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

    let severity = derive_severity(has_org_admin, has_workspace_write, &orgs);

    if orgs.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Terraform Cloud account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any organizations".into());
    }

    if is_service_account {
        risk_notes.push("Token belongs to a service account".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "terraform".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: attrs.and_then(|a| a.username.clone()),
            username: attrs.and_then(|a| a.username.clone()),
            account_type: Some(
                if is_service_account { "service_account" } else { "user" }.to_string(),
            ),
            company: None,
            location: None,
            email: attrs.and_then(|a| a.email.clone()),
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: account_data.and_then(|d| d.id.clone()),
            scopes: all_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_account(client: &Client, token: &str) -> Result<TerraformAccountResponse> {
    let resp = client
        .get(format!("{TERRAFORM_API}/api/v2/account/details"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/vnd.api+json")
        .send()
        .await
        .context("Terraform access-map: failed to fetch account details")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Terraform access-map: account lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Terraform access-map: invalid account JSON")
}

async fn list_organizations(client: &Client, token: &str) -> Result<Vec<TerraformOrgData>> {
    let resp = client
        .get(format!("{TERRAFORM_API}/api/v2/organizations"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/vnd.api+json")
        .send()
        .await
        .context("Terraform access-map: failed to list organizations")?;

    if !resp.status().is_success() {
        warn!("Terraform access-map: organization enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: TerraformOrgsResponse =
        resp.json().await.context("Terraform access-map: invalid organizations JSON")?;
    Ok(body.data)
}

async fn list_workspaces(
    client: &Client,
    token: &str,
    org_name: &str,
) -> Result<Vec<TerraformWorkspaceData>> {
    let mut workspaces = Vec::new();
    let mut page = 1;

    loop {
        let resp = client
            .get(format!(
                "{TERRAFORM_API}/api/v2/organizations/{org_name}/workspaces?page%5Bnumber%5D={page}&page%5Bsize%5D=100"
            ))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/vnd.api+json")
            .send()
            .await
            .context("Terraform access-map: failed to list workspaces")?;

        if !resp.status().is_success() {
            warn!("Terraform access-map: workspace enumeration failed with HTTP {}", resp.status());
            break;
        }

        let body: TerraformWorkspacesResponse =
            resp.json().await.context("Terraform access-map: invalid workspaces JSON")?;

        if body.data.is_empty() {
            break;
        }

        workspaces.extend(body.data);
        page += 1;
    }

    Ok(workspaces)
}

fn derive_severity(
    has_org_admin: bool,
    has_workspace_write: bool,
    orgs: &[TerraformOrgData],
) -> Severity {
    if has_org_admin {
        return Severity::Critical;
    }

    if has_workspace_write && !orgs.is_empty() {
        return Severity::High;
    }

    if !orgs.is_empty() {
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
