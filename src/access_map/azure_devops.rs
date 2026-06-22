use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as b64};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use tracing::warn;

use crate::validation::GLOBAL_USER_AGENT;

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const AZURE_DEVOPS_PROFILE_API: &str =
    "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1-preview.1";
const AZURE_DEVOPS_API_VERSION: &str = "7.1-preview.1";
const AZURE_DEVOPS_TOKEN_ADMIN_VERSION: &str = "7.1";

#[derive(Deserialize)]
struct AzureDevopsProfile {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "publicAlias")]
    public_alias: Option<String>,
    #[serde(rename = "emailAddress")]
    email_address: Option<String>,
    id: Option<String>,
}

#[derive(Deserialize)]
struct AzureDevopsProject {
    name: String,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    _state: Option<String>,
}

#[derive(Deserialize)]
struct AzureDevopsRepo {
    name: String,
    #[serde(rename = "isDisabled", default)]
    is_disabled: bool,
    #[serde(default)]
    project: AzureDevopsProjectRef,
}

#[derive(Deserialize, Default)]
struct AzureDevopsProjectRef {
    name: Option<String>,
}

#[derive(Deserialize)]
struct AzureDevopsListResponse<T> {
    value: Vec<T>,
}

#[derive(Deserialize)]
struct AzureDevopsIdentity {
    #[serde(rename = "subjectDescriptor")]
    subject_descriptor: Option<String>,
}

#[derive(Clone, Deserialize)]
struct AzureDevopsPat {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "validFrom")]
    valid_from: Option<String>,
    #[serde(rename = "validTo")]
    valid_to: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    scope: Option<String>,
}

pub async fn map_access_from_token(token: &str, organization: &str) -> Result<AccessMapResult> {
    let org = normalize_org(organization);
    if org.is_empty() {
        return Err(anyhow!("Azure DevOps access-map requires a valid organization name"));
    }

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Azure DevOps HTTP client")?;
    let auth_header = build_auth_header(token)?;

    let (profile, scopes, user_data) = match fetch_profile(&client, auth_header.clone()).await {
        Ok(value) => value,
        Err(err) => {
            warn!("Azure DevOps access-map: profile lookup failed: {err}");
            (
                AzureDevopsProfile {
                    display_name: None,
                    public_alias: None,
                    email_address: None,
                    id: None,
                },
                Vec::new(),
                AzureDevopsUserData::default(),
            )
        }
    };
    let pat_details =
        fetch_pat_details(&client, &org, auth_header.clone(), &profile, &scopes).await;
    let projects = list_projects(&client, &org, auth_header.clone()).await?;
    let repos = list_repositories(&client, &org, auth_header.clone(), &projects).await?;

    let identity_id = profile
        .email_address
        .clone()
        .or_else(|| user_data.email.clone())
        .or(profile.public_alias.clone())
        .or(profile.display_name.clone())
        .or(profile.id.clone())
        .or_else(|| user_data.user_id.clone())
        .unwrap_or_else(|| "azure_devops_user".to_string());

    let identity = AccessSummary {
        id: identity_id,
        access_type: "pat".into(),
        project: Some(org.clone()),
        tenant: None,
        account_id: None,
    };

    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut risk_notes = Vec::new();

    let mut seen_repos = std::collections::BTreeSet::new();
    for repo in &repos {
        let risk = if repo.is_disabled { Severity::Low } else { Severity::Medium };
        let reason = if repo.is_disabled {
            "Repository is disabled but visible to the token".to_string()
        } else {
            "Accessible Azure DevOps repository".to_string()
        };

        let repo_permissions = vec!["repo:read".to_string()];
        permissions.read_only.push("repo:read".to_string());

        let repo_name = match repo.project.name.as_deref() {
            Some(project_name) if !project_name.is_empty() => {
                format!("{}/{}", project_name, repo.name)
            }
            _ => repo.name.clone(),
        };

        if !seen_repos.insert(repo_name.clone()) {
            continue;
        }

        resources.push(ResourceExposure {
            resource_type: "repository".into(),
            name: repo_name,
            permissions: repo_permissions,
            risk: severity_to_str(risk).to_string(),
            reason,
        });
    }

    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&projects, &repos);

    let mut roles = Vec::new();
    if !scopes.is_empty() {
        roles.push(RoleBinding {
            name: "token_scopes".into(),
            source: "azure_devops".into(),
            permissions: scopes.clone(),
        });
    }

    if repos.is_empty() {
        for project in &projects {
            let is_private = project
                .visibility
                .as_deref()
                .map(|v| v.eq_ignore_ascii_case("private"))
                .unwrap_or(false);
            let risk = if is_private { Severity::Medium } else { Severity::Low };
            let reason = if is_private {
                "Accessible private Azure DevOps project".to_string()
            } else {
                "Accessible public Azure DevOps project".to_string()
            };

            resources.push(ResourceExposure {
                resource_type: "project".into(),
                name: project.name.clone(),
                permissions: vec!["project:read".to_string()],
                risk: severity_to_str(risk).to_string(),
                reason,
            });
        }

        if projects.is_empty() {
            resources.push(ResourceExposure {
                resource_type: "organization".into(),
                name: org.clone(),
                permissions: Vec::new(),
                risk: severity_to_str(Severity::Low).to_string(),
                reason: "Azure DevOps organization associated with the token".into(),
            });
        }

        risk_notes.push("Token did not enumerate any repositories".into());
    }

    if roles.is_empty() {
        risk_notes
            .push("Azure DevOps did not report PAT scopes; review the token permissions".into());
    }

    let pat_scopes =
        pat_details.as_ref().map(|pat| parse_pat_scopes(pat.scope.as_deref())).unwrap_or_default();
    let token_scopes = if scopes.is_empty() { pat_scopes.clone() } else { scopes.clone() };

    Ok(AccessMapResult {
        cloud: "azure_devops".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: pat_details
                .as_ref()
                .and_then(|pat| pat.display_name.clone())
                .filter(|value| !value.trim().is_empty())
                .or_else(|| {
                    profile
                        .display_name
                        .clone()
                        .or(profile.public_alias.clone())
                        .filter(|value| !value.trim().is_empty())
                }),
            username: profile.public_alias.clone().filter(|value| !value.trim().is_empty()),
            account_type: None,
            company: None,
            location: None,
            email: profile.email_address.clone().filter(|value| !value.trim().is_empty()),
            url: None,
            token_type: Some("pat".into()),
            created_at: pat_details.as_ref().and_then(|pat| pat.valid_from.clone()),
            last_used_at: None,
            expires_at: pat_details.as_ref().and_then(|pat| pat.valid_to.clone()),
            user_id: pat_details
                .as_ref()
                .and_then(|pat| pat.user_id.clone())
                .or(profile.id.clone())
                .or_else(|| user_data.user_id.clone())
                .or(profile.email_address.clone())
                .or(profile.public_alias.clone()),
            scopes: token_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

#[derive(Default)]
struct AzureDevopsUserData {
    user_id: Option<String>,
    email: Option<String>,
}

async fn fetch_profile(
    client: &Client,
    auth_header: header::HeaderValue,
) -> Result<(AzureDevopsProfile, Vec<String>, AzureDevopsUserData)> {
    let profile_url = Url::parse(AZURE_DEVOPS_PROFILE_API).expect("valid Azure DevOps profile URL");
    let resp = client
        .get(profile_url)
        .header(header::AUTHORIZATION, auth_header)
        .send()
        .await
        .context("Azure DevOps access-map: failed to fetch user profile")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Azure DevOps access-map: profile lookup failed with HTTP {}",
            resp.status()
        ));
    }

    let scopes = resp
        .headers()
        .get("x-vss-token-scopes")
        .and_then(|val| val.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|scope| scope.trim().to_string())
                .filter(|scope| !scope.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let user_data = parse_user_data(resp.headers().get("x-vss-userdata"));
    let profile = resp.json().await.context("Azure DevOps access-map: invalid profile JSON")?;

    Ok((profile, scopes, user_data))
}

fn normalize_org(raw: &str) -> String {
    raw.trim().trim_matches('/').split('/').next_back().unwrap_or("").trim().to_string()
}

fn build_auth_header(token: &str) -> Result<header::HeaderValue> {
    let encoded = b64.encode(format!(":{token}"));
    header::HeaderValue::from_str(&format!("Basic {encoded}"))
        .context("Failed to build Azure DevOps auth header")
}

fn parse_user_data(value: Option<&header::HeaderValue>) -> AzureDevopsUserData {
    let Some(value) = value.and_then(|val| val.to_str().ok()) else {
        return AzureDevopsUserData::default();
    };
    let mut parts = value.splitn(2, ':');
    let user_id = parts.next().map(|item| item.trim().to_string());
    let email = parts.next().map(|item| item.trim().to_string());

    AzureDevopsUserData {
        user_id: user_id.filter(|item| !item.is_empty()),
        email: email.filter(|item| !item.is_empty()),
    }
}

async fn fetch_pat_details(
    client: &Client,
    organization: &str,
    auth_header: header::HeaderValue,
    profile: &AzureDevopsProfile,
    scopes: &[String],
) -> Option<AzureDevopsPat> {
    let subject_descriptor =
        fetch_subject_descriptor(client, organization, auth_header.clone(), profile).await?;
    let mut url = Url::parse(&format!(
        "https://vssps.dev.azure.com/{organization}/_apis/tokenadmin/personalaccesstokens/"
    ))
    .ok()?;
    url.path_segments_mut().ok()?.push(&subject_descriptor);
    url.query_pairs_mut().append_pair("api-version", AZURE_DEVOPS_TOKEN_ADMIN_VERSION);
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, auth_header)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let payload: AzureDevopsListResponse<AzureDevopsPat> = resp.json().await.ok()?;
    select_matching_pat(&payload.value, scopes, profile.id.as_deref())
}

async fn fetch_subject_descriptor(
    client: &Client,
    organization: &str,
    auth_header: header::HeaderValue,
    profile: &AzureDevopsProfile,
) -> Option<String> {
    let mut attempts: Vec<(Option<&str>, Option<&str>)> = Vec::new();
    if let Some(identity_id) = profile.id.as_deref().filter(|value| !value.trim().is_empty()) {
        attempts.push((Some(identity_id), None));
    }
    if let Some(email) = profile.email_address.as_deref().filter(|value| !value.trim().is_empty()) {
        attempts.push((None, Some(email)));
    }
    if let Some(alias) = profile.public_alias.as_deref().filter(|value| !value.trim().is_empty()) {
        attempts.push((None, Some(alias)));
    }
    if let Some(display_name) =
        profile.display_name.as_deref().filter(|value| !value.trim().is_empty())
    {
        attempts.push((None, Some(display_name)));
    }

    for (identity_id, search_value) in attempts {
        let mut url =
            Url::parse(&format!("https://vssps.dev.azure.com/{organization}/_apis/identities"))
                .ok()?;
        url.query_pairs_mut()
            .append_pair("api-version", AZURE_DEVOPS_TOKEN_ADMIN_VERSION)
            .append_pair("queryMembership", "None");
        if let Some(identity_id) = identity_id {
            url.query_pairs_mut().append_pair("identityIds", identity_id);
        } else if let Some(search_value) = search_value {
            url.query_pairs_mut()
                .append_pair("searchFilter", "General")
                .append_pair("filterValue", search_value);
        }

        let resp = client
            .get(url)
            .header(header::ACCEPT, "application/json")
            .header(header::AUTHORIZATION, auth_header.clone())
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            continue;
        }

        let payload: AzureDevopsListResponse<AzureDevopsIdentity> = resp.json().await.ok()?;
        if let Some(descriptor) = payload
            .value
            .into_iter()
            .filter_map(|identity| identity.subject_descriptor)
            .find(|value| !value.trim().is_empty())
        {
            return Some(descriptor);
        }
    }

    None
}

fn parse_pat_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .map(|value| {
            value
                .split_whitespace()
                .map(|entry| entry.trim().to_string())
                .filter(|entry| !entry.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn select_matching_pat(
    pats: &[AzureDevopsPat],
    scopes: &[String],
    user_id: Option<&str>,
) -> Option<AzureDevopsPat> {
    if pats.is_empty() {
        return None;
    }

    let mut candidates: Vec<&AzureDevopsPat> = pats
        .iter()
        .filter(|pat| {
            if let Some(user_id) = user_id
                && let Some(pat_user_id) = pat.user_id.as_deref()
            {
                return pat_user_id == user_id;
            }
            true
        })
        .collect();

    let mut desired_scopes = scopes.to_vec();
    desired_scopes.sort();
    desired_scopes.dedup();

    if !desired_scopes.is_empty() {
        let scope_matches: Vec<&AzureDevopsPat> = candidates
            .iter()
            .copied()
            .filter(|pat| {
                let mut pat_scopes = parse_pat_scopes(pat.scope.as_deref());
                pat_scopes.sort();
                pat_scopes.dedup();
                if pat_scopes.is_empty() {
                    return false;
                }
                pat_scopes == desired_scopes
                    || desired_scopes.iter().all(|scope| pat_scopes.contains(scope))
            })
            .collect();
        if !scope_matches.is_empty() {
            candidates = scope_matches;
        }
    }

    candidates.into_iter().max_by_key(|pat| pat.valid_from.as_deref().unwrap_or_default()).cloned()
}

async fn list_repositories(
    client: &Client,
    organization: &str,
    auth_header: header::HeaderValue,
    projects: &[AzureDevopsProject],
) -> Result<Vec<AzureDevopsRepo>> {
    let url = format!(
        "https://dev.azure.com/{organization}/_apis/git/repositories?api-version={AZURE_DEVOPS_API_VERSION}"
    );
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, auth_header.clone())
        .send()
        .await
        .context("Azure DevOps access-map: failed to list repositories")?;

    let mut repos = if resp.status().is_success() {
        let payload: AzureDevopsListResponse<AzureDevopsRepo> =
            resp.json().await.context("Azure DevOps access-map: invalid repo JSON")?;
        payload.value
    } else {
        warn!("Azure DevOps access-map: repository enumeration failed with HTTP {}", resp.status());
        Vec::new()
    };

    if !repos.is_empty() || projects.is_empty() {
        return Ok(repos);
    }

    for project in projects {
        let project_name = project.name.trim();
        if project_name.is_empty() {
            continue;
        }

        let mut project_repos = list_project_repositories(
            client,
            organization,
            project_name,
            auth_header.clone(),
        )
        .await
        .unwrap_or_else(|err| {
            warn!(
                "Azure DevOps access-map: project repo enumeration failed for {project_name}: {err}"
            );
            Vec::new()
        });
        repos.append(&mut project_repos);
    }

    Ok(repos)
}

async fn list_project_repositories(
    client: &Client,
    organization: &str,
    project: &str,
    auth_header: header::HeaderValue,
) -> Result<Vec<AzureDevopsRepo>> {
    let url = format!(
        "https://dev.azure.com/{organization}/{project}/_apis/git/repositories?api-version={AZURE_DEVOPS_API_VERSION}"
    );
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, auth_header)
        .send()
        .await
        .context("Azure DevOps access-map: failed to list project repositories")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Azure DevOps access-map: project repository enumeration failed with HTTP {}",
            resp.status()
        ));
    }

    let payload: AzureDevopsListResponse<AzureDevopsRepo> =
        resp.json().await.context("Azure DevOps access-map: invalid repo JSON")?;
    Ok(payload.value)
}

async fn list_projects(
    client: &Client,
    organization: &str,
    auth_header: header::HeaderValue,
) -> Result<Vec<AzureDevopsProject>> {
    let url = format!(
        "https://dev.azure.com/{organization}/_apis/projects?api-version={AZURE_DEVOPS_API_VERSION}"
    );
    let resp = client
        .get(url)
        .header(header::ACCEPT, "application/json")
        .header(header::AUTHORIZATION, auth_header)
        .send()
        .await
        .context("Azure DevOps access-map: failed to list projects")?;

    if !resp.status().is_success() {
        warn!("Azure DevOps access-map: project enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let payload: AzureDevopsListResponse<AzureDevopsProject> =
        resp.json().await.context("Azure DevOps access-map: invalid project JSON")?;
    Ok(payload.value)
}

fn derive_severity(projects: &[AzureDevopsProject], repos: &[AzureDevopsRepo]) -> Severity {
    if !repos.is_empty()
        || projects.iter().any(|project| {
            project
                .visibility
                .as_deref()
                .map(|v| v.eq_ignore_ascii_case("private"))
                .unwrap_or(false)
        })
    {
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
