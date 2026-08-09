use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use std::collections::BTreeSet;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const HUGGINGFACE_API: &str = "https://huggingface.co/api";
const MAX_HF_RESOURCES_PER_KIND: usize = 100;

#[derive(Deserialize)]
struct HfWhoAmI {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "fullname")]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    orgs: Vec<HfOrg>,
    #[serde(default)]
    auth: Option<HfAuth>,
}

#[derive(Deserialize)]
struct HfOrg {
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "roleInOrg")]
    role_in_org: Option<String>,
}

#[derive(Deserialize)]
struct HfAuth {
    #[serde(default, rename = "type")]
    token_type: Option<String>,
    #[serde(default, rename = "accessToken")]
    access_token: Option<HfAccessTokenInfo>,
}

#[derive(Deserialize)]
struct HfAccessTokenInfo {
    #[serde(default, rename = "displayName")]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default, rename = "createdAt")]
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct HfModel {
    #[serde(default, rename = "modelId")]
    model_id: Option<String>,
    #[serde(default, rename = "id")]
    id: Option<String>,
    #[serde(default)]
    private: bool,
}

#[derive(Deserialize)]
struct HfDataset {
    #[serde(default, rename = "id")]
    id: Option<String>,
    #[serde(default)]
    private: bool,
}

#[derive(Deserialize)]
struct HfSpace {
    #[serde(default, rename = "id")]
    id: Option<String>,
    #[serde(default)]
    private: bool,
}

#[derive(Deserialize)]
struct HfBucket {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Clone, Deserialize)]
struct HfStorageResource {
    id: String,
    #[serde(rename = "type")]
    resource_type: String,
    visibility: String,
    #[serde(default)]
    storage: Option<u64>,
}

#[derive(Clone)]
struct HfResource {
    id: String,
    resource_type: String,
    visibility: String,
    storage: Option<u64>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!("Failed to read Hugging Face token from {}", path.display())
        })?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "Hugging Face access-map requires a validated token from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Hugging Face HTTP client")?;

    let whoami_resp = client
        .get(format!("{HUGGINGFACE_API}/whoami-v2"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to fetch whoami")?;

    if !whoami_resp.status().is_success() {
        return Err(anyhow!(
            "Hugging Face access-map: whoami failed with HTTP {}",
            whoami_resp.status()
        ));
    }

    let whoami: HfWhoAmI =
        whoami_resp.json().await.context("Hugging Face access-map: invalid whoami JSON")?;

    let username = whoami.name.clone().unwrap_or_else(|| "huggingface_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: whoami.r#type.clone().unwrap_or_else(|| "user".into()).to_lowercase(),
        project: None,
        tenant: None,
        account_id: None,
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // Extract token role/type from auth info.
    let token_role =
        whoami.auth.as_ref().and_then(|a| a.access_token.as_ref()).and_then(|t| t.role.clone());
    let token_type = whoami.auth.as_ref().and_then(|a| a.token_type.clone());
    let token_name = whoami
        .auth
        .as_ref()
        .and_then(|a| a.access_token.as_ref())
        .and_then(|t| t.display_name.clone());
    let token_created = whoami
        .auth
        .as_ref()
        .and_then(|a| a.access_token.as_ref())
        .and_then(|t| t.created_at.clone());

    if let Some(ref role) = token_role {
        roles.push(RoleBinding {
            name: "token_role".into(),
            source: "huggingface".into(),
            permissions: vec![format!("role:{role}")],
        });

        match role.as_str() {
            "write" => permissions.risky.push("token:write".to_string()),
            "read" => permissions.read_only.push("token:read".to_string()),
            "admin" => permissions.admin.push("token:admin".to_string()),
            "fineGrained" | "fine-grained" => {}
            _ => permissions.read_only.push(format!("token:{role}")),
        }
    }

    // Enumerate organizations.
    for org in &whoami.orgs {
        let org_name = org.name.clone().unwrap_or_else(|| "unknown_org".to_string());
        let org_role = org.role_in_org.clone().unwrap_or_else(|| "member".to_string());

        roles.push(RoleBinding {
            name: format!("organization:{org_name}:{org_role}"),
            source: "huggingface".into(),
            permissions: vec![format!("organization:{org_role}")],
        });

        let token_can_write = matches!(token_role.as_deref(), Some("write" | "admin"));
        let token_is_fine_grained =
            matches!(token_role.as_deref(), Some("fineGrained" | "fine-grained"));
        let risk = match (org_role.as_str(), token_can_write, token_is_fine_grained) {
            ("admin", true, _) => {
                permissions.admin.push(format!("organization:{org_name}:admin"));
                Severity::High
            }
            ("write" | "contributor", true, _) => {
                permissions.risky.push(format!("organization:{org_name}:{org_role}"));
                Severity::Medium
            }
            ("admin" | "write" | "contributor", false, true) => {
                permissions.risky.push(format!("organization:{org_name}:scoped"));
                Severity::Medium
            }
            ("admin" | "write" | "contributor" | "read", false, false) => {
                permissions.read_only.push(format!("organization:{org_name}:read"));
                Severity::Low
            }
            ("no_access", _, _) => Severity::Low,
            _ => Severity::Low,
        };

        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: org_name,
            permissions: vec![format!("org_role:{org_role}")],
            risk: severity_to_str(risk).to_string(),
            reason: "Organization membership available to the token".into(),
        });
    }

    let mut authors = BTreeSet::new();
    authors.insert(username.clone());
    for org in &whoami.orgs {
        if let Some(org_name) = org.name.as_ref().filter(|name| !name.is_empty()) {
            authors.insert(org_name.clone());
        }
    }

    let mut discovered_resources = Vec::new();
    let mut used_fallback_enumeration = false;
    for author in &authors {
        let is_user = author == &username;
        match list_storage_resources(&client, token, if is_user { None } else { Some(author) })
            .await
        {
            Ok(mut author_resources) => discovered_resources.append(&mut author_resources),
            Err(err) => {
                used_fallback_enumeration = true;
                warn!(
                    "Hugging Face access-map: unified resource enumeration failed for {author}: {err}; falling back to public resource APIs"
                );
                let mut fallback = list_resources_fallback(&client, token, author).await;
                discovered_resources.append(&mut fallback);
            }
        }
    }

    let mut seen_resources = BTreeSet::new();
    for resource in &discovered_resources {
        if !seen_resources.insert((resource.resource_type.clone(), resource.id.clone())) {
            continue;
        }

        let visibility = resource.visibility.to_ascii_lowercase();
        let sensitive = matches!(visibility.as_str(), "private" | "protected");
        let risk = if sensitive { Severity::Medium } else { Severity::Low };
        let perm_label = format!("{}:{visibility}", resource.resource_type);
        let storage_suffix =
            resource.storage.map(|bytes| format!(" ({bytes} bytes stored)")).unwrap_or_default();

        resources.push(ResourceExposure {
            resource_type: resource.resource_type.clone(),
            name: resource.id.clone(),
            permissions: vec![perm_label.clone()],
            risk: severity_to_str(risk).to_string(),
            reason: format!(
                "Accessible {visibility} Hugging Face {}{storage_suffix}",
                resource.resource_type
            ),
        });

        if sensitive {
            permissions.risky.push(perm_label);
        } else {
            permissions.read_only.push(perm_label);
        }
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&token_role, &discovered_resources, &whoami.orgs);

    if discovered_resources.is_empty() && whoami.orgs.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Hugging Face account associated with the token".into(),
        });
        risk_notes.push(
            "Token did not enumerate any models, datasets, Spaces, buckets, or organizations"
                .into(),
        );
    }

    if token_role.is_none() {
        risk_notes.push("Hugging Face did not report token role information".into());
    }
    if matches!(token_role.as_deref(), Some("fineGrained" | "fine-grained")) {
        risk_notes.push(
            "Fine-grained token scope details are not exposed by whoami; resources reflect what the token could enumerate"
                .into(),
        );
    }
    if used_fallback_enumeration {
        risk_notes.push(
            "The unified Hugging Face resource listing was unavailable for at least one namespace; fallback enumeration may omit restricted resources"
                .into(),
        );
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "huggingface".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: token_name.or_else(|| whoami.full_name.clone()),
            username: whoami.name.clone(),
            account_type: whoami.r#type.clone(),
            company: None,
            location: None,
            email: whoami.email.clone(),
            url: Some(format!("https://huggingface.co/{username}")),
            token_type,
            created_at: token_created,
            last_used_at: None,
            expires_at: None,
            user_id: Some(username),
            scopes: token_role.into_iter().collect(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_models_by_author(client: &Client, token: &str, author: &str) -> Result<Vec<HfModel>> {
    let mut models = Vec::new();
    let limit = MAX_HF_RESOURCES_PER_KIND;

    let resp = client
        .get(format!("{HUGGINGFACE_API}/models"))
        .query(&[("author", author), ("limit", &limit.to_string())])
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to list models")?;

    if !resp.status().is_success() {
        warn!("Hugging Face access-map: model enumeration failed with HTTP {}", resp.status());
        return Ok(models);
    }

    let page_models: Vec<HfModel> =
        resp.json().await.context("Hugging Face access-map: invalid model JSON")?;
    models.extend(page_models);

    Ok(models)
}

async fn list_datasets_by_author(
    client: &Client,
    token: &str,
    author: &str,
) -> Result<Vec<HfDataset>> {
    let resp = client
        .get(format!("{HUGGINGFACE_API}/datasets"))
        .query(&[("author", author), ("limit", &MAX_HF_RESOURCES_PER_KIND.to_string())])
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to list datasets")?;

    if !resp.status().is_success() {
        warn!("Hugging Face access-map: dataset enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Hugging Face access-map: invalid dataset JSON")
}

async fn list_spaces_by_author(client: &Client, token: &str, author: &str) -> Result<Vec<HfSpace>> {
    let resp = client
        .get(format!("{HUGGINGFACE_API}/spaces"))
        .query(&[("author", author), ("limit", &MAX_HF_RESOURCES_PER_KIND.to_string())])
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to list Spaces")?;

    if !resp.status().is_success() {
        warn!("Hugging Face access-map: Space enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Hugging Face access-map: invalid Space JSON")
}

async fn list_buckets_by_author(
    client: &Client,
    token: &str,
    author: &str,
) -> Result<Vec<HfBucket>> {
    let resp = client
        .get(format!("{HUGGINGFACE_API}/buckets/{author}"))
        .query(&[("limit", &MAX_HF_RESOURCES_PER_KIND.to_string())])
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await
        .context("Hugging Face access-map: failed to list buckets")?;

    if !resp.status().is_success() {
        warn!("Hugging Face access-map: bucket enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    resp.json().await.context("Hugging Face access-map: invalid bucket JSON")
}

async fn list_storage_resources(
    client: &Client,
    token: &str,
    organization: Option<&str>,
) -> Result<Vec<HfResource>> {
    let mut url = match organization {
        Some(org) => {
            Url::parse(&format!("{HUGGINGFACE_API}/organizations/{org}/settings/repositories"))?
        }
        None => Url::parse(&format!("{HUGGINGFACE_API}/settings/repositories"))?,
    };
    let mut resources = Vec::new();

    loop {
        let response = client
            .get(url.clone())
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .send()
            .await
            .context("Hugging Face access-map: failed to list unified resources")?;
        let status = response.status();
        let next = response
            .headers()
            .get(header::LINK)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_next_link);
        if !status.is_success() {
            return Err(anyhow!(
                "Hugging Face access-map: unified resource enumeration failed with HTTP {status}"
            ));
        }

        let page: Vec<HfStorageResource> = response
            .json()
            .await
            .context("Hugging Face access-map: invalid unified resource JSON")?;
        resources.extend(page.into_iter().map(|resource| HfResource {
            id: resource.id,
            resource_type: resource.resource_type,
            visibility: resource.visibility,
            storage: resource.storage,
        }));

        match next {
            Some(next) => url = next,
            None => break,
        }
    }

    Ok(resources)
}

async fn list_resources_fallback(client: &Client, token: &str, author: &str) -> Vec<HfResource> {
    let mut resources = Vec::new();

    match list_models_by_author(client, token, author).await {
        Ok(models) => resources.extend(models.into_iter().filter_map(|model| {
            model.model_id.or(model.id).map(|id| HfResource {
                id,
                resource_type: "model".into(),
                visibility: if model.private { "private" } else { "public" }.into(),
                storage: None,
            })
        })),
        Err(err) => warn!("Hugging Face access-map: model enumeration failed for {author}: {err}"),
    }

    match list_datasets_by_author(client, token, author).await {
        Ok(datasets) => resources.extend(datasets.into_iter().filter_map(|dataset| {
            dataset.id.map(|id| HfResource {
                id,
                resource_type: "dataset".into(),
                visibility: if dataset.private { "private" } else { "public" }.into(),
                storage: None,
            })
        })),
        Err(err) => {
            warn!("Hugging Face access-map: dataset enumeration failed for {author}: {err}")
        }
    }

    match list_spaces_by_author(client, token, author).await {
        Ok(spaces) => resources.extend(spaces.into_iter().filter_map(|space| {
            space.id.map(|id| HfResource {
                id,
                resource_type: "space".into(),
                visibility: if space.private { "private" } else { "public" }.into(),
                storage: None,
            })
        })),
        Err(err) => warn!("Hugging Face access-map: Space enumeration failed for {author}: {err}"),
    }

    match list_buckets_by_author(client, token, author).await {
        Ok(buckets) => resources.extend(buckets.into_iter().filter_map(|bucket| {
            bucket.id.map(|id| HfResource {
                id,
                resource_type: "bucket".into(),
                visibility: if bucket.private { "private" } else { "public" }.into(),
                storage: bucket.size,
            })
        })),
        Err(err) => warn!("Hugging Face access-map: bucket enumeration failed for {author}: {err}"),
    }

    resources
}

fn parse_next_link(value: &str) -> Option<Url> {
    value.split(',').find_map(|part| {
        let part = part.trim();
        let (url_part, params) = part.split_once('>')?;
        if params.contains("rel=\"next\"") {
            Url::parse(url_part.trim_start_matches('<').trim()).ok()
        } else {
            None
        }
    })
}

fn derive_severity(
    token_role: &Option<String>,
    resources: &[HfResource],
    organizations: &[HfOrg],
) -> Severity {
    let has_private_assets = resources.iter().any(|resource| {
        matches!(resource.visibility.to_ascii_lowercase().as_str(), "private" | "protected")
    });
    let has_admin_org = organizations.iter().any(|org| org.role_in_org.as_deref() == Some("admin"));

    if let Some(role) = token_role {
        match role.as_str() {
            "admin" => return Severity::High,
            "write" => {
                if has_private_assets || has_admin_org {
                    return Severity::High;
                }
                return Severity::Medium;
            }
            "fineGrained" | "fine-grained" => {
                if has_private_assets {
                    return Severity::Medium;
                }
                return Severity::Low;
            }
            _ => {}
        }
    }

    if has_private_assets { Severity::Medium } else { Severity::Low }
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
    use super::*;

    #[test]
    fn fine_grained_token_is_not_implicitly_admin() {
        let role = Some("fineGrained".to_string());
        let public = vec![HfResource {
            id: "owner/model".into(),
            resource_type: "model".into(),
            visibility: "public".into(),
            storage: None,
        }];
        assert!(matches!(derive_severity(&role, &public, &[]), Severity::Low));
    }

    #[test]
    fn protected_resources_raise_severity() {
        let role = Some("read".to_string());
        let protected = vec![HfResource {
            id: "owner/space".into(),
            resource_type: "space".into(),
            visibility: "protected".into(),
            storage: None,
        }];
        assert!(matches!(derive_severity(&role, &protected, &[]), Severity::Medium));
    }

    #[test]
    fn write_token_with_admin_org_is_high_severity() {
        let role = Some("write".to_string());
        let organizations =
            vec![HfOrg { name: Some("example".into()), role_in_org: Some("admin".into()) }];
        assert!(matches!(derive_severity(&role, &[], &organizations), Severity::High));
    }
}
