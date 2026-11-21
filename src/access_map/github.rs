use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use futures::future::join_all;
use reqwest::{Client, Url, header};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ProviderMetadata,
    ResourceExposure, RoleBinding, Severity, build_recommendations,
};

const DEFAULT_GITHUB_API: &str = "https://api.github.com";
const MAX_TOKEN_AUDIT_ORGANIZATIONS: usize = 4;
const MAX_TOKEN_AUDIT_RESPONSE_BYTES: usize = 256 * 1024;
const TOKEN_AUDIT_REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Known GitHub App user-level permissions (as opposed to repository-level).
const USER_LEVEL_PERMISSIONS: &[&str] = &[
    "blocking",
    "codespace_user_secrets",
    "email",
    "followers",
    "git_ssh_keys",
    "gpg_keys",
    "interaction_limits",
    "plan",
    "profile",
    "ssh_signing_keys",
    "starring",
    "watching",
];

#[derive(Deserialize)]
struct GitHubUser {
    login: String,
    #[expect(dead_code)]
    id: u64,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    r#type: String,
}

#[derive(Deserialize)]
struct GitHubRepo {
    full_name: String,
    private: bool,
    permissions: Option<GitHubRepoPermissions>,
}

#[derive(Deserialize)]
struct GitHubOrg {
    login: String,
}

#[derive(Deserialize)]
struct GitHubOrgMembership {
    organization: GitHubOrg,
    #[serde(default)]
    role: String,
    #[serde(default)]
    state: String,
}

#[derive(Clone, Deserialize)]
struct GitHubRepoPermissions {
    admin: bool,
    push: bool,
    pull: bool,
}

/// Response from `GET /user/installations`.
#[derive(Deserialize)]
struct GitHubInstallationsResponse {
    installations: Vec<GitHubInstallation>,
}

/// A single GitHub App installation.
#[derive(Deserialize)]
struct GitHubInstallation {
    id: u64,
    #[serde(default)]
    app_slug: Option<String>,
    #[serde(default)]
    permissions: BTreeMap<String, String>,
    #[serde(default)]
    #[expect(dead_code)]
    repository_selection: Option<String>,
    #[serde(default)]
    account: Option<GitHubInstallationAccount>,
}

#[derive(Deserialize)]
struct GitHubInstallationAccount {
    login: String,
}

/// Response from `GET /user/installations/{id}/repositories`.
#[derive(Deserialize)]
struct GitHubInstallationReposResponse {
    repositories: Vec<GitHubRepo>,
}

#[derive(Deserialize)]
struct GitHubCredentialFile {
    token: String,
    #[serde(alias = "base_url")]
    api_endpoint: Option<String>,
    activity: Option<GitHubAuditCredentials>,
}

#[derive(Deserialize)]
struct GitHubAuditCredentials {
    audit_token: String,
    organizations: Vec<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args
        .credential_path
        .as_deref()
        .ok_or_else(|| anyhow!("GitHub access-map requires a validated token from scan results"))?;
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read GitHub token from {}", path.display()))?;
    let raw = raw.trim();
    if !raw.starts_with('{') {
        return map_access_from_token(raw).await;
    }

    let mut credential: GitHubCredentialFile = serde_json::from_str(raw).map_err(|_| {
        anyhow!("Invalid GitHub credential JSON; expected token and optional activity")
    })?;
    let token = credential.token.trim();
    if token.is_empty() {
        return Err(anyhow!("GitHub credential JSON requires a non-empty token"));
    }
    let api_url = crate::provider_endpoints::access_map_api_url(
        "github",
        credential.api_endpoint.as_deref().unwrap_or(DEFAULT_GITHUB_API),
    )?;
    if let Some(audit) = &mut credential.activity {
        audit.audit_token = audit.audit_token.trim().to_owned();
        if api_url.scheme() != "https"
            || audit.audit_token.is_empty()
            || audit.audit_token == token
            || !(1..=MAX_TOKEN_AUDIT_ORGANIZATIONS).contains(&audit.organizations.len())
            || !audit.organizations.iter().all(|slug| valid_audit_org(slug))
        {
            return Err(anyhow!(
                "GitHub activity requires HTTPS, a separate audit_token, and one to four organization slugs"
            ));
        }
    }
    map_access_with_auditor(token, api_url, Utc::now(), credential.activity.as_ref()).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    map_access_from_token_before(token, Utc::now()).await
}

pub(crate) async fn map_access_from_token_before(
    token: &str,
    activity_before: DateTime<Utc>,
) -> Result<AccessMapResult> {
    map_access_from_token_at_before(token, DEFAULT_GITHUB_API, activity_before).await
}

pub(crate) async fn map_access_from_token_at_before(
    token: &str,
    api_endpoint: &str,
    activity_before: DateTime<Utc>,
) -> Result<AccessMapResult> {
    let api_url = crate::provider_endpoints::access_map_api_url("github", api_endpoint)?;
    map_access_with_auditor(token, api_url, activity_before, None).await
}

async fn map_access_with_auditor(
    token: &str,
    api_url: Url,
    activity_before: DateTime<Utc>,
    auditor: Option<&GitHubAuditCredentials>,
) -> Result<AccessMapResult> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(20))
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build GitHub HTTP client")?;

    let audited_at = if let Some(audit) = auditor {
        search_token_audit(
            &client,
            &api_url,
            token,
            &audit.audit_token,
            audit.organizations.iter().map(String::as_str),
            activity_before,
        )
        .await
    } else {
        None
    };
    let user_resp = client
        .get(api_url.join("user")?)
        .header(header::AUTHORIZATION, format!("token {token}"))
        .header(header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("GitHub access-map: failed to fetch user info")?;

    if !user_resp.status().is_success() {
        return Err(anyhow!(
            "GitHub access-map: user lookup failed with HTTP {}",
            user_resp.status()
        ));
    }

    let oauth_scopes = parse_csv_header(user_resp.headers().get("x-oauth-scopes"));
    let token_expiration = user_resp
        .headers()
        .get("github-authentication-token-expiration")
        .and_then(|val| val.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let token_type = user_resp
        .headers()
        .get("github-authentication-token-type")
        .and_then(|val| val.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let user: GitHubUser =
        user_resp.json().await.context("GitHub access-map: invalid user JSON")?;

    let identity = AccessSummary {
        id: user.login.clone(),
        access_type: if user.r#type.is_empty() {
            "user".into()
        } else {
            user.r#type.to_lowercase()
        },
        project: None,
        tenant: None,
        account_id: None,
    };

    let is_app_token = token.starts_with("ghu_") || token.starts_with("ghs_");

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // For GitHub App tokens (ghu_/ghs_), enumerate installation permissions
    // and repos through the installations API for richer access mapping.
    let repos = if is_app_token {
        let installations =
            list_user_installations(&client, &api_url, token).await.unwrap_or_else(|err| {
                warn!("GitHub access-map: installation lookup failed: {err}");
                Vec::new()
            });

        let mut all_repos = Vec::new();
        for installation in &installations {
            let (repo_perms, user_perms) =
                categorize_installation_permissions(&installation.permissions);

            let install_label = installation
                .account
                .as_ref()
                .map(|a| a.login.clone())
                .or_else(|| installation.app_slug.clone())
                .unwrap_or_else(|| format!("installation-{}", installation.id));

            // Record repository-level permissions as a role binding.
            if !repo_perms.is_empty() {
                let perm_strings: Vec<String> = repo_perms
                    .iter()
                    .map(|(name, level)| format!("{}:{}", name, permission_to_label(level)))
                    .collect();

                roles.push(RoleBinding {
                    name: format!("installation_repo_permissions:{install_label}"),
                    source: "github_app".into(),
                    permissions: perm_strings.clone(),
                });

                // Classify installation-level permissions by risk.
                for (_, level) in &repo_perms {
                    match level.as_str() {
                        "admin" => permissions.admin.push(format!("app:{install_label}:admin")),
                        "write" => permissions.risky.push(format!("app:{install_label}:write")),
                        _ => permissions.read_only.push(format!("app:{install_label}:read")),
                    }
                }
            }

            // Record user-level permissions as a separate role binding.
            if !user_perms.is_empty() {
                let perm_strings: Vec<String> = user_perms
                    .iter()
                    .map(|(name, level)| format!("{}:{}", name, permission_to_label(level)))
                    .collect();

                roles.push(RoleBinding {
                    name: format!("installation_user_permissions:{install_label}"),
                    source: "github_app".into(),
                    permissions: perm_strings,
                });
            }

            // Enumerate repos through the installation.
            let install_repos = list_installation_repos(&client, &api_url, token, installation.id)
                .await
                .unwrap_or_else(|err| {
                    warn!(
                        "GitHub access-map: repo enumeration for installation {} failed: {err}",
                        installation.id
                    );
                    Vec::new()
                });
            all_repos.extend(install_repos);
        }

        // Deduplicate repos by full_name.
        let mut seen = BTreeSet::new();
        all_repos.retain(|repo| seen.insert(repo.full_name.clone()));

        // If no installations returned data, fall back to /user/repos.
        if all_repos.is_empty() {
            list_accessible_repos(&client, &api_url, token).await?
        } else {
            all_repos
        }
    } else {
        list_accessible_repos(&client, &api_url, token).await?
    };

    let org_scopes = org_scopes(&oauth_scopes);
    let org_memberships =
        list_org_memberships(&client, &api_url, token).await.unwrap_or_else(|err| {
            warn!("GitHub access-map: org membership lookup failed: {err}");
            Vec::new()
        });
    let last_used_at = if auditor.is_some() {
        audited_at
    } else {
        find_token_activity(
            &client,
            &api_url,
            token,
            &oauth_scopes,
            &org_memberships,
            activity_before,
        )
        .await
    }
    .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true));
    let provider_metadata = last_used_at.as_ref().map(|_| ProviderMetadata {
        credential_last_used_source: Some(
            "GitHub organization audit log (latest audited event)".into(),
        ),
        ..ProviderMetadata::default()
    });

    for membership in org_memberships.into_iter().filter(|m| m.state == "active") {
        let mut org_permissions = org_scopes.clone();
        if !membership.role.trim().is_empty() {
            org_permissions.push(format!("org_role:{}", membership.role.trim()));
        }
        org_permissions.sort();
        org_permissions.dedup();
        if org_permissions.is_empty() {
            continue;
        }

        let risk = if org_permissions.iter().any(|perm| perm.contains("admin")) {
            Severity::High
        } else if org_permissions.iter().any(|perm| perm.contains("write")) {
            Severity::Medium
        } else {
            Severity::Low
        };

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: membership.organization.login,
            permissions: org_permissions.clone(),
            risk: severity_to_str(risk).to_string(),
            reason: "Organization membership available to the token".into(),
        });
    }

    for repo in &repos {
        let perms = repo.permissions.clone().unwrap_or(GitHubRepoPermissions {
            admin: false,
            push: false,
            pull: true,
        });

        let mut repo_perms = Vec::new();
        if perms.admin {
            repo_perms.push("repo:admin".to_string());
        }
        if perms.push {
            repo_perms.push("repo:write".to_string());
        }
        if perms.pull {
            repo_perms.push("repo:read".to_string());
        }

        let risk = if perms.admin {
            Severity::High
        } else if perms.push {
            Severity::Medium
        } else {
            Severity::Low
        };

        let reason = if repo.private {
            "Accessible private repository".to_string()
        } else {
            "Accessible public repository".to_string()
        };

        resources.push(ResourceExposure {
            resource_type: "repository".into(),
            name: repo.full_name.clone(),
            permissions: repo_perms.clone(),
            risk: severity_to_str(risk).to_string(),
            reason,
        });

        if perms.admin {
            permissions.admin.push("repo:admin".to_string());
        } else if perms.push {
            permissions.risky.push("repo:write".to_string());
        } else if perms.pull {
            permissions.read_only.push("repo:read".to_string());
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&repos);

    if !oauth_scopes.is_empty() {
        roles.push(RoleBinding {
            name: "token_scopes".into(),
            source: "github".into(),
            permissions: oauth_scopes.clone(),
        });
    }

    if repos.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: user.login.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "GitHub account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any repositories".into());
    }

    if roles.is_empty() {
        risk_notes.push(
            "GitHub did not report OAuth scopes; fine-grained tokens may omit scope headers".into(),
        );
    }

    let user_display_name = user
        .name
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| Some(user.login.clone()));
    let user_identifier = if let Some(email) = user.email.as_ref().filter(|v| !v.trim().is_empty())
    {
        format!("{} ({email})", user.login)
    } else {
        user.login.clone()
    };

    Ok(AccessMapResult {
        cloud: "github".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: user_display_name,
            username: Some(user.login.clone()),
            account_type: Some(user.r#type.clone()).filter(|value| !value.trim().is_empty()),
            company: user.company.clone().filter(|value| !value.trim().is_empty()),
            location: user.location.clone().filter(|value| !value.trim().is_empty()),
            email: user.email.clone().filter(|value| !value.trim().is_empty()),
            url: user.html_url.clone().filter(|value| !value.trim().is_empty()),
            token_type,
            created_at: None,
            last_used_at,
            expires_at: token_expiration,
            user_id: Some(user_identifier),
            scopes: oauth_scopes.clone(),
        }),
        provider_metadata,
        fingerprint: None,
    })
}

async fn find_token_activity(
    client: &Client,
    api_url: &Url,
    token: &str,
    oauth_scopes: &[String],
    memberships: &[GitHubOrgMembership],
    activity_before: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    // Classic PATs and OAuth app tokens need read:audit_log. Fine-grained credentials
    // omit X-OAuth-Scopes, and GitHub checks the organization Administration permission.
    if !oauth_scopes.iter().any(|scope| scope == "read:audit_log")
        && !["github_pat_", "ghu_", "ghs_"].iter().any(|prefix| token.starts_with(prefix))
    {
        return None;
    }

    let organizations = memberships
        .iter()
        .filter(|membership| membership.role == "admin" && membership.state == "active")
        .map(|membership| membership.organization.login.as_str());
    search_token_audit(client, api_url, token, token, organizations, activity_before).await
}

fn valid_audit_org(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 100
        && slug.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

async fn search_token_audit<'a>(
    client: &Client,
    api_url: &Url,
    target_token: &str,
    audit_token: &str,
    organizations: impl Iterator<Item = &'a str>,
    activity_before: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let mut seen = BTreeSet::new();
    let token_hash = STANDARD.encode(Sha256::digest(target_token.as_bytes()));
    let cutoff = activity_before.to_rfc3339_opts(SecondsFormat::Secs, true);
    // The documented hashed-token search covers web audit events. Git events require an export.
    let filter = format!("hashed_token:\"{token_hash}\" created:<{cutoff}");
    let requests = organizations
        .filter(|slug| valid_audit_org(slug))
        .filter(|slug| seen.insert(slug.to_ascii_lowercase()))
        .take(MAX_TOKEN_AUDIT_ORGANIZATIONS)
        .map(|slug| {
            query_org_token_activity(
                client,
                api_url,
                audit_token,
                slug,
                &token_hash,
                &filter,
                activity_before,
            )
        });
    join_all(requests).await.into_iter().flatten().max()
}

async fn query_org_token_activity(
    client: &Client,
    api_url: &Url,
    token: &str,
    slug: &str,
    token_hash: &str,
    filter: &str,
    activity_before: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let url = api_url.join(&format!("orgs/{slug}/audit-log")).ok()?;
    let mut response = client
        .get(url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/vnd.github+json")
        .query(&[("phrase", filter), ("include", "web"), ("order", "desc"), ("per_page", "10")])
        .timeout(TOKEN_AUDIT_REQUEST_TIMEOUT)
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > MAX_TOKEN_AUDIT_RESPONSE_BYTES.saturating_sub(body.len()) {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    let events: Vec<serde_json::Value> = serde_json::from_slice(&body).ok()?;
    events
        .iter()
        .filter(|event| {
            event["hashed_token"].as_str().is_some_and(|hash| {
                hash == token_hash || token_hash.strip_suffix('=') == Some(hash)
            })
        })
        .filter_map(|event| {
            let milliseconds =
                event["@timestamp"].as_i64().or_else(|| event["created_at"].as_i64())?;
            DateTime::from_timestamp_millis(milliseconds)
        })
        .filter(|timestamp| timestamp.timestamp() < activity_before.timestamp())
        .max()
}

fn parse_csv_header(value: Option<&header::HeaderValue>) -> Vec<String> {
    value
        .and_then(|val| val.to_str().ok())
        .map(|scopes| {
            scopes
                .split(',')
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

async fn list_accessible_repos(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GitHubRepo>> {
    let mut repos = Vec::new();
    let mut page = 1u32;
    let per_page = 100u32;

    loop {
        let mut url = api_url.join("user/repos")?;
        url.query_pairs_mut()
            .append_pair("per_page", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("GitHub access-map: failed to list repositories")?;

        if !resp.status().is_success() {
            warn!("GitHub access-map: repo enumeration failed with HTTP {}", resp.status());
            break;
        }

        let mut page_repos: Vec<GitHubRepo> =
            resp.json().await.context("GitHub access-map: invalid repository JSON")?;
        let count = page_repos.len();
        repos.append(&mut page_repos);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(repos)
}

async fn list_org_memberships(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GitHubOrgMembership>> {
    let mut orgs = Vec::new();
    let mut page = 1u32;
    let per_page = 100u32;

    loop {
        let mut url = api_url.join("user/memberships/orgs")?;
        url.query_pairs_mut()
            .append_pair("per_page", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("GitHub access-map: failed to list org memberships")?;

        if !resp.status().is_success() {
            warn!(
                "GitHub access-map: org membership enumeration failed with HTTP {}",
                resp.status()
            );
            break;
        }

        let mut page_orgs: Vec<GitHubOrgMembership> =
            resp.json().await.context("GitHub access-map: invalid org JSON")?;
        let count = page_orgs.len();
        orgs.append(&mut page_orgs);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(orgs)
}

fn derive_severity(repos: &[GitHubRepo]) -> Severity {
    let mut severity = Severity::Low;
    for repo in repos {
        let perms = repo.permissions.as_ref();
        if perms.is_some_and(|p| p.admin) {
            return Severity::High;
        }
        if perms.is_some_and(|p| p.push) {
            severity = Severity::Medium;
        }
    }
    severity
}

fn org_scopes(scopes: &[String]) -> Vec<String> {
    let mut result: Vec<String> = scopes
        .iter()
        .filter(|scope| scope.contains(":org") || scope.contains(":enterprise"))
        .cloned()
        .collect();
    result.sort();
    result.dedup();
    result
}

/// List GitHub App installations accessible to a user-to-server token.
async fn list_user_installations(
    client: &Client,
    api_url: &Url,
    token: &str,
) -> Result<Vec<GitHubInstallation>> {
    let mut installations = Vec::new();
    let mut page = 1u32;
    let per_page = 100u32;

    loop {
        let mut url = api_url.join("user/installations")?;
        url.query_pairs_mut()
            .append_pair("per_page", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("GitHub access-map: failed to list installations")?;

        if !resp.status().is_success() {
            warn!("GitHub access-map: installation enumeration failed with HTTP {}", resp.status());
            break;
        }

        let body: GitHubInstallationsResponse =
            resp.json().await.context("GitHub access-map: invalid installations JSON")?;
        let count = body.installations.len();
        installations.extend(body.installations);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(installations)
}

/// List repos accessible through a specific installation.
async fn list_installation_repos(
    client: &Client,
    api_url: &Url,
    token: &str,
    installation_id: u64,
) -> Result<Vec<GitHubRepo>> {
    let mut repos = Vec::new();
    let mut page = 1u32;
    let per_page = 100u32;

    loop {
        let mut url =
            api_url.join(&format!("user/installations/{installation_id}/repositories"))?;
        url.query_pairs_mut()
            .append_pair("per_page", &per_page.to_string())
            .append_pair("page", &page.to_string());

        let resp = client
            .get(url)
            .header(header::AUTHORIZATION, format!("token {token}"))
            .header(header::ACCEPT, "application/vnd.github+json")
            .send()
            .await
            .context("GitHub access-map: failed to list installation repositories")?;

        if !resp.status().is_success() {
            warn!(
                "GitHub access-map: installation repo enumeration failed with HTTP {}",
                resp.status()
            );
            break;
        }

        let body: GitHubInstallationReposResponse =
            resp.json().await.context("GitHub access-map: invalid installation repos JSON")?;
        let count = body.repositories.len();
        repos.extend(body.repositories);

        if count < per_page as usize {
            break;
        }
        page += 1;
    }

    Ok(repos)
}

/// Categorize installation permissions into repository-level and user-level.
///
/// Returns `(repo_permissions, user_permissions)` where each is a sorted vec
/// of `(permission_name, access_level)`.
#[allow(clippy::type_complexity)]
fn categorize_installation_permissions(
    perms: &BTreeMap<String, String>,
) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut repo_perms = Vec::new();
    let mut user_perms = Vec::new();

    for (name, level) in perms {
        if USER_LEVEL_PERMISSIONS.contains(&name.as_str()) {
            user_perms.push((name.clone(), level.clone()));
        } else {
            repo_perms.push((name.clone(), level.clone()));
        }
    }

    repo_perms.sort();
    user_perms.sort();
    (repo_perms, user_perms)
}

/// Convert a GitHub permission level to a display label.
fn permission_to_label(level: &str) -> &str {
    match level {
        "admin" => "ADMIN",
        "write" => "READ_WRITE",
        "read" => "READ_ONLY",
        _ => level,
    }
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
mod endpoint_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    #[tokio::test]
    async fn enterprise_mapping_keeps_the_api_prefix() {
        let server = MockServer::start().await;
        for (resource, body) in [
            ("user", json!({ "login": "enterprise-user", "id": 1, "type": "User" })),
            ("user/repos", json!([])),
            ("user/memberships/orgs", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/team/api/v3/{resource}")))
                .and(header("authorization", "token test-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let result = map_access_from_token_at_before(
            "test-token",
            &format!("{}/team/api/v3", server.uri()),
            Utc::now(),
        )
        .await
        .unwrap();
        assert_eq!(result.identity.id, "enterprise-user");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn mapping_does_not_follow_credential_redirects() {
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/user"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/user", destination.uri())),
            )
            .mount(&server)
            .await;
        assert!(
            map_access_from_token_at_before(
                "test-token",
                &format!("{}/api/v3", server.uri()),
                Utc::now()
            )
            .await
            .is_err()
        );
        assert!(destination.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn organization_audit_reports_the_latest_exact_pre_scan_event() {
        const HASH: &str = "TF3Jt3CJBfd/Xl0WMWtd+0JeaMsybc1VqGDpCncHAx4";
        let server = MockServer::start().await;
        let cutoff = "2026-11-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let before = cutoff.timestamp_millis() - 1_000;
        let audit_body = json!([
            { "hashed_token": HASH, "@timestamp": cutoff.timestamp_millis() },
            { "@timestamp": before + 2 },
            { "hashed_token": "other", "@timestamp": before + 1 },
            { "hashed_token": format!("{HASH}="), "@timestamp": before },
            { "hashed_token": HASH, "created_at": before - 1_000 },
        ]);

        for (resource, body) in [
            ("user", json!({ "login": "test-user", "id": 1 })),
            ("user/repos", json!([])),
            (
                "user/memberships/orgs",
                json!([
                    {"role": "admin", "state": "active", "organization": {"login": "denied"}},
                    {"role": "admin", "state": "active", "organization": {"login": "allowed"}},
                    {"role": "member", "state": "active", "organization": {"login": "member"}},
                    {"role": "admin", "state": "pending", "organization": {"login": "pending"}},
                    {"role": "admin", "state": "active", "organization": {"login": "../wrong"}},
                ]),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/team/api/v3/{resource}")))
                .and(header("authorization", "token test-token"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("x-oauth-scopes", "read:audit_log")
                        .set_body_json(body),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        for (slug, response) in [
            ("denied", ResponseTemplate::new(403)),
            ("allowed", ResponseTemplate::new(200).set_body_json(audit_body)),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/team/api/v3/orgs/{slug}/audit-log")))
                .and(header("authorization", "Bearer test-token"))
                .and(query_param(
                    "phrase",
                    format!("hashed_token:\"{HASH}=\" created:<2026-11-01T00:00:00Z"),
                ))
                .and(query_param("include", "web"))
                .and(query_param("order", "desc"))
                .and(query_param("per_page", "10"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
        }

        let result = map_access_from_token_at_before(
            "test-token",
            &format!("{}/team/api/v3", server.uri()),
            cutoff,
        )
        .await
        .unwrap();
        assert_eq!(
            result.token_details.unwrap().last_used_at.as_deref(),
            Some("2026-10-31T23:59:59Z")
        );
        assert_eq!(
            result.provider_metadata.unwrap().credential_last_used_source.as_deref(),
            Some("GitHub organization audit log (latest audited event)"),
        );
        assert_eq!(server.received_requests().await.unwrap().len(), 5);
    }

    #[tokio::test]
    async fn configured_auditor_reads_history_before_mapping_with_the_target() {
        let server = MockServer::start().await;
        let audit = GitHubAuditCredentials {
            audit_token: "auditor".into(),
            organizations: vec!["external-org".into()],
        };
        let hash = STANDARD.encode(Sha256::digest(b"target"));
        let cutoff = "2026-11-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        Mock::given(method("GET"))
            .and(path("/orgs/external-org/audit-log"))
            .and(header("authorization", "Bearer auditor"))
            .and(query_param(
                "phrase",
                format!("hashed_token:\"{hash}\" created:<2026-11-01T00:00:00Z"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"hashed_token": hash, "@timestamp": cutoff.timestamp_millis() - 1000},
            ])))
            .expect(1)
            .mount(&server)
            .await;
        for (path_name, body) in [
            ("/user", json!({"login": "user", "id": 1})),
            ("/user/repos", json!([])),
            ("/user/memberships/orgs", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(path_name))
                .and(header("authorization", "token target"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let result =
            map_access_with_auditor("target", server.uri().parse().unwrap(), cutoff, Some(&audit))
                .await
                .unwrap();
        assert_eq!(
            result.token_details.unwrap().last_used_at.as_deref(),
            Some("2026-10-31T23:59:59Z")
        );
        assert_eq!(
            server.received_requests().await.unwrap()[0].url.path(),
            "/orgs/external-org/audit-log"
        );
    }
}
