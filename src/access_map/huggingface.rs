use anyhow::{Context, Result, anyhow};
use reqwest::{Client, Url, header};
use serde::Deserialize;
use std::collections::BTreeSet;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const HUGGINGFACE_API: &str = "https://huggingface.co/api";

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

    // Hugging Face documents this identity/token-role schema in its Hub OpenAPI document and in
    // the Apache-2.0 huggingface_hub SDK:
    // https://huggingface.co/.well-known/openapi.json
    // https://github.com/huggingface/huggingface_hub/blob/v0.24.3/src/huggingface_hub/hf_api.py
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

    // The unified user and organization repository inventory endpoints are specified by the
    // vendor OpenAPI schema above. Unlike author-filtered public searches, these settings APIs
    // return the authenticated token's actual visible models, datasets, Spaces, and buckets.
    let mut discovered_resources = Vec::new();
    match list_storage_resources(&client, token, None).await {
        Ok(mut user_resources) => discovered_resources.append(&mut user_resources),
        Err(err) => risk_notes.push(format!("User repository inventory failed: {err}")),
    }
    for org in &whoami.orgs {
        if let Some(org_name) = org.name.as_deref().filter(|name| !name.is_empty()) {
            match list_storage_resources(&client, token, Some(org_name)).await {
                Ok(mut org_resources) => discovered_resources.append(&mut org_resources),
                Err(err) => risk_notes.push(format!(
                    "Organization repository inventory failed for {org_name}: {err}"
                )),
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
    Ok(AccessMapResult {
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

async fn list_storage_resources(
    client: &Client,
    token: &str,
    organization: Option<&str>,
) -> Result<Vec<HfResource>> {
    // Vendor OpenAPI operations:
    // GET /api/settings/repositories
    // GET /api/organizations/{name}/settings/repositories
    // https://huggingface.co/.well-known/openapi.json
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
    fn private_bucket_raises_severity() {
        let role = Some("read".to_string());
        let private_bucket = vec![HfResource {
            id: "owner/checkpoints".into(),
            resource_type: "bucket".into(),
            visibility: "private".into(),
            storage: Some(42),
        }];
        assert!(matches!(derive_severity(&role, &private_bucket, &[]), Severity::Medium));
    }

    #[test]
    fn bucket_inventory_metadata_deserializes() {
        let resource: HfStorageResource = serde_json::from_value(serde_json::json!({
            "id": "owner/checkpoints",
            "type": "bucket",
            "visibility": "private",
            "storage": 42,
            "updatedAt": "2026-08-27T00:00:00Z",
            "storagePercent": 0.1
        }))
        .unwrap();

        assert_eq!(resource.id, "owner/checkpoints");
        assert_eq!(resource.resource_type, "bucket");
        assert_eq!(resource.visibility, "private");
        assert_eq!(resource.storage, Some(42));
    }

    #[test]
    fn write_token_with_admin_org_is_high_severity() {
        let role = Some("write".to_string());
        let organizations =
            vec![HfOrg { name: Some("example".into()), role_in_org: Some("admin".into()) }];
        assert!(matches!(derive_severity(&role, &[], &organizations), Severity::High));
    }
}
