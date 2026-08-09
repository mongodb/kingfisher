use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const AIRTABLE_API: &str = "https://api.airtable.com";

#[derive(Deserialize)]
struct AirtableWhoami {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct AirtableBasesResponse {
    #[serde(default)]
    bases: Vec<AirtableBase>,
}

#[derive(Deserialize)]
struct AirtableBase {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "permissionLevel", default)]
    permission_level: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Airtable token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Airtable access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Airtable HTTP client")?;

    let whoami = fetch_whoami(&client, token).await?;

    let username = whoami
        .email
        .clone()
        .unwrap_or_else(|| whoami.id.clone().unwrap_or_else(|| "airtable_user".to_string()));

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "user".into(),
        project: None,
        tenant: None,
        account_id: whoami.id.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    for scope in &whoami.scopes {
        let role = RoleBinding {
            name: format!("scope:{scope}"),
            source: "airtable".into(),
            permissions: vec![scope.clone()],
        };
        roles.push(role);

        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    let bases = list_bases(&client, token).await.unwrap_or_else(|err| {
        warn!("Airtable access-map: base enumeration failed: {err}");
        Vec::new()
    });

    for base in &bases {
        let base_name = base
            .name
            .clone()
            .or_else(|| base.id.clone())
            .unwrap_or_else(|| "unknown_base".to_string());

        let perm_level = base.permission_level.as_deref().unwrap_or("unknown");

        let risk = match perm_level {
            "create" => Severity::High,
            "edit" => Severity::Medium,
            "read" | "comment" => Severity::Low,
            _ => Severity::Medium,
        };

        resources.push(ResourceExposure {
            resource_type: "base".into(),
            name: base_name.clone(),
            permissions: vec![format!("permissionLevel:{perm_level}")],
            risk: severity_to_str(risk).to_string(),
            reason: format!("Airtable base accessible with {perm_level} permission"),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&whoami.scopes, &bases);

    if bases.is_empty() && whoami.scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Airtable account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any bases or scopes".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "airtable".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: None,
            username: whoami.email.clone(),
            account_type: None,
            company: None,
            location: None,
            email: whoami.email.clone(),
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: whoami.id,
            scopes: whoami.scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_whoami(client: &Client, token: &str) -> Result<AirtableWhoami> {
    let resp = client
        .get(format!("{AIRTABLE_API}/v0/meta/whoami"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Airtable access-map: failed to fetch whoami")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Airtable access-map: whoami lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("Airtable access-map: invalid whoami JSON")
}

async fn list_bases(client: &Client, token: &str) -> Result<Vec<AirtableBase>> {
    let resp = client
        .get(format!("{AIRTABLE_API}/v0/meta/bases"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Airtable access-map: failed to list bases")?;

    if !resp.status().is_success() {
        warn!("Airtable access-map: base enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: AirtableBasesResponse =
        resp.json().await.context("Airtable access-map: invalid bases JSON")?;
    Ok(body.bases)
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "schema:bases:write" | "user.email:read" => ScopeRisk::Admin,
        "data.records:write" | "data.recordComments:write" => ScopeRisk::Write,
        _ if scope.contains(":write") => ScopeRisk::Write,
        _ => ScopeRisk::Read,
    }
}

fn has_admin_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| matches!(s.as_str(), "schema:bases:write" | "user.email:read"))
}

fn has_write_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s.contains(":write"))
}

fn derive_severity(scopes: &[String], bases: &[AirtableBase]) -> Severity {
    if has_admin_scope(scopes) {
        return Severity::Critical;
    }

    let has_write = has_write_scope(scopes);
    if has_write && bases.len() > 5 {
        return Severity::High;
    }

    if has_write {
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
