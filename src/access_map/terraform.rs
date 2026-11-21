use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use chrono::{DateTime, SecondsFormat, Utc};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const TERRAFORM_API: &str = "https://app.terraform.io";
const AUTH_TOKEN_PATH: &str = "/api/v2/authentication-tokens/";
const LAST_USED_SOURCE: &str = "HCP Terraform token activity";

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
    #[serde(default)]
    links: Value,
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
struct TerraformTokenResponse {
    data: TerraformTokenData,
}

#[derive(Deserialize)]
struct TerraformTokenData {
    id: String,
    attributes: TerraformTokenAttributes,
}

#[derive(Deserialize)]
struct TerraformTokenAttributes {
    #[serde(rename = "last-used-at")]
    last_used_at: Option<String>,
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
    map_access_from_token_at(token, TERRAFORM_API).await
}

async fn map_access_from_token_at(token: &str, api_base: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build Terraform HTTP client")?;

    map_access_with_client(&client, token, api_base).await
}

async fn map_access_with_client(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<AccessMapResult> {
    let account = fetch_account(client, token, api_base).await?;

    let account_data = account.data.as_ref();
    let attrs = account_data.and_then(|d| d.attributes.as_ref());
    let auth_token_id = account_data
        .and_then(|data| data.links.get("auth-token"))
        .and_then(Value::as_str)
        .and_then(auth_token_id_from_link);
    let last_used_at = if let Some(id) = auth_token_id {
        fetch_token_last_used(client, token, api_base, id).await.unwrap_or_else(|err| {
            debug!("Terraform access-map: token activity unavailable: {err}");
            None
        })
    } else {
        None
    };
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some(LAST_USED_SOURCE.into()),
        ..ProviderMetadata::default()
    });

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

    let orgs = list_organizations(client, token, api_base).await.unwrap_or_else(|err| {
        warn!("Terraform access-map: organization enumeration failed: {err}");
        Vec::new()
    });

    let mut has_org_admin = false;
    let mut has_workspace_write = false;

    for org in &orgs {
        let mut org_admin = false;
        let mut org_workspace_write = false;
        let org_attrs = org.attributes.as_ref();
        let org_name =
            org_attrs.and_then(|a| a.name.clone()).unwrap_or_else(|| "unknown_org".to_string());

        let org_perms = org_attrs.and_then(|a| a.permissions.as_ref());

        // Classify org-level permissions.
        if let Some(perms) = org_perms {
            if perms.can_manage_modules == Some(true) {
                permissions.admin.push(format!("{org_name}:can-manage-modules"));
                all_scopes.push(format!("{org_name}:can-manage-modules"));
                org_admin = true;
            }
            if perms.can_manage_providers == Some(true) {
                permissions.admin.push(format!("{org_name}:can-manage-providers"));
                all_scopes.push(format!("{org_name}:can-manage-providers"));
                org_admin = true;
            }
            if perms.can_destroy == Some(true) {
                permissions.admin.push(format!("{org_name}:can-destroy"));
                all_scopes.push(format!("{org_name}:can-destroy"));
                org_admin = true;
            }
            if perms.can_create_workspace == Some(true) {
                permissions.risky.push(format!("{org_name}:can-create-workspace"));
                all_scopes.push(format!("{org_name}:can-create-workspace"));
                org_workspace_write = true;
            }
            if perms.can_update == Some(true) {
                permissions.risky.push(format!("{org_name}:can-update"));
                all_scopes.push(format!("{org_name}:can-update"));
                org_workspace_write = true;
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
            risk: severity_to_str(if org_admin {
                Severity::Critical
            } else if org_workspace_write {
                Severity::High
            } else {
                Severity::Medium
            })
            .to_string(),
            reason: "Terraform Cloud organization accessible with this token".into(),
        });

        has_org_admin |= org_admin;
        has_workspace_write |= org_workspace_write;

        // Enumerate workspaces.
        let workspaces =
            list_workspaces(client, token, &org_name, api_base).await.unwrap_or_else(|err| {
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

            let ws_risk = if org_workspace_write && is_auto_apply && !is_locked {
                Severity::High
            } else if org_workspace_write {
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
            last_used_at,
            expires_at: None,
            user_id: account_data.and_then(|d| d.id.clone()),
            scopes: all_scopes,
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn fetch_account(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<TerraformAccountResponse> {
    let resp = client
        .get(format!("{api_base}/api/v2/account/details"))
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

fn auth_token_id_from_link(link: &str) -> Option<&str> {
    // Accept the documented relative link for the authenticating token only.
    let id = link.strip_prefix(AUTH_TOKEN_PATH)?;
    let suffix = id.strip_prefix("at-")?;
    (!suffix.is_empty()
        && suffix.len() <= 128
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(id)
}

async fn fetch_token_last_used(
    client: &Client,
    token: &str,
    api_base: &str,
    id: &str,
) -> Result<Option<String>> {
    let response = client
        .get(format!("{api_base}{AUTH_TOKEN_PATH}{id}"))
        .bearer_auth(token)
        .header(header::ACCEPT, "application/vnd.api+json")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("Terraform token activity request failed")?;
    let status = response.status();
    ensure!(status.is_success(), "Terraform token activity lookup returned HTTP {status}");

    let body = response
        .json::<TerraformTokenResponse>()
        .await
        .context("Invalid Terraform token activity JSON")?;
    ensure!(body.data.id == id, "Terraform returned activity for a different token");
    Ok(body
        .data
        .attributes
        .last_used_at
        .and_then(|timestamp| DateTime::parse_from_rfc3339(&timestamp).ok())
        .map(|date| date.with_timezone(&Utc).to_rfc3339_opts(SecondsFormat::AutoSi, true)))
}

async fn list_organizations(
    client: &Client,
    token: &str,
    api_base: &str,
) -> Result<Vec<TerraformOrgData>> {
    let resp = client
        .get(format!("{api_base}/api/v2/organizations"))
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
    api_base: &str,
) -> Result<Vec<TerraformWorkspaceData>> {
    let mut workspaces = Vec::new();
    let mut page = 1;

    loop {
        let resp = client
            .get(format!(
                "{api_base}/api/v2/organizations/{org_name}/workspaces?page%5Bnumber%5D={page}&page%5Bsize%5D=100"
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
        Severity::Unknown => "unknown",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn token_header_is_never_forwarded_to_a_redirect() {
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{header, method},
        };
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", destination.uri().replace("127.0.0.1", "localhost")),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(super::map_access_from_token_at("test-token", &server.uri()).await.is_err());
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    #[tokio::test]
    async fn usage_lookup_requires_and_matches_the_authenticating_token_id() {
        let destination = MockServer::start().await;
        let token_path = "/api/v2/authentication-tokens/at-actor123";
        let activity = |id: &str, last_used_at: Option<&str>| {
            ResponseTemplate::new(200).set_body_json(json!({
                "data": {"id": id, "attributes": {"last-used-at": last_used_at}}
            }))
        };
        let foreign_url = format!("{}{token_path}", destination.uri());
        let date = "2024-02-12T01:23:45.123-05:00";
        for (link, token_response, expected) in [
            (
                Some(token_path),
                Some(activity("at-actor123", Some(date))),
                Some("2024-02-12T06:23:45.123Z"),
            ),
            (Some(token_path), Some(activity("at-other456", Some(date))), None),
            (Some(token_path), Some(activity("at-actor123", None)), None),
            (Some(token_path), Some(ResponseTemplate::new(403)), None),
            (
                Some(token_path),
                Some(ResponseTemplate::new(302).insert_header("Location", &foreign_url)),
                None,
            ),
            (Some(foreign_url.as_str()), None, None),
            (None, None, None),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v2/account/details"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "data": {"attributes": {"username": "example"}, "links": {"auth-token": link}}
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/api/v2/organizations"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
                .mount(&server)
                .await;
            let expected_requests = u64::from(token_response.is_some());
            Mock::given(method("GET"))
                .and(path(token_path))
                .and(header("authorization", "Bearer test-token"))
                .respond_with(token_response.unwrap_or_else(|| ResponseTemplate::new(404)))
                .expect(expected_requests)
                .mount(&server)
                .await;

            let result = map_access_from_token_at("test-token", &server.uri()).await.unwrap();
            assert_eq!(result.identity.id, "example");
            assert_eq!(result.token_details.unwrap().last_used_at.as_deref(), expected);
            assert_eq!(
                result
                    .provider_metadata
                    .and_then(|metadata| metadata.credential_last_used_source)
                    .as_deref(),
                expected.map(|_| LAST_USED_SOURCE),
            );
        }
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn organization_permissions_do_not_inflate_other_resource_risk() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2/account/details"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"data": {"id": "user", "attributes": { "username": "member" }}}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET")).and(path("/api/v2/organizations"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [
                { "attributes": { "name": "admin-org", "permissions": { "can-destroy": true, "can-update": true } } },
                { "attributes": { "name": "read-org", "permissions": { "can-destroy": false, "can-update": false } } }
            ] }))).mount(&server).await;
        for org in ["admin-org", "read-org"] {
            Mock::given(method("GET")).and(path(format!("/api/v2/organizations/{org}/workspaces"))).and(query_param("page[number]", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [{ "attributes": { "name": "workspace", "auto-apply": true, "locked": false } }] })))
                .mount(&server).await;
            Mock::given(method("GET"))
                .and(path(format!("/api/v2/organizations/{org}/workspaces")))
                .and(query_param("page[number]", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
                .mount(&server)
                .await;
        }
        let result = map_access_with_client(&Client::new(), "token", &server.uri()).await.unwrap();
        let risk_for = |name: &str| {
            result.resources.iter().find(|resource| resource.name == name).unwrap().risk.as_str()
        };
        assert_eq!(risk_for("admin-org"), "critical");
        assert_eq!(risk_for("admin-org/workspace"), "high");
        assert_eq!(risk_for("read-org"), "medium");
        assert_eq!(risk_for("read-org/workspace"), "low");
        assert!(matches!(result.severity, Severity::Critical));
    }
}
