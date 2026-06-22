use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use serde_json::Value;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const MAX_REPO_RESOURCES: usize = 100;

#[derive(Deserialize)]
struct XrayRepo {
    name: Option<String>,
    #[serde(rename = "type")]
    repo_type: Option<String>,
    #[expect(dead_code)]
    #[serde(rename = "pkg_type")]
    package_type: Option<String>,
}

#[derive(Deserialize)]
struct XrayPolicy {
    name: Option<String>,
    #[serde(rename = "type")]
    policy_type: Option<String>,
    #[expect(dead_code)]
    author: Option<String>,
}

/// Entry point when invoked via the CLI `access-map jfrog-xray` subcommand.
pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let path = args.credential_path.as_deref().ok_or_else(|| {
        anyhow!(
            "JFrog Xray access-map requires a credential file with token (and optionally base_url)"
        )
    })?;
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!("Failed to read JFrog Xray credential file from {}", path.display())
    })?;
    let (token, base_url) = parse_xray_credentials(&raw)?;
    match base_url {
        Some(url) => map_access_from_token_and_url(&token, &url).await,
        None => map_access_from_token(&token).await,
    }
}

/// Maps a JFrog Xray token without a known base URL.
pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build JFrog Xray HTTP client")?;

    // Without a base URL, try the generic JFrog cloud endpoint
    let ping_ok = ping_xray(&client, token, "https://access.jfrog.io").await;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    if ping_ok {
        permissions.read_only.push("system:ping".to_string());
        risk_notes.push("Token responded to JFrog Xray cloud ping; base_url unknown so full mapping not possible".to_string());
    } else {
        risk_notes.push(
            "Token did not respond to JFrog Xray cloud ping; provide base_url for full mapping"
                .to_string(),
        );
    }

    let severity = Severity::Medium;
    Ok(AccessMapResult {
        cloud: "jfrog_xray".into(),
        identity: AccessSummary {
            id: "unknown_xray_user".into(),
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles: Vec::new(),
        permissions,
        resources: Vec::new(),
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            token_type: Some("bearer_token".into()),
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

/// Maps a JFrog Xray token with a known base URL to an access profile.
pub async fn map_access_from_token_and_url(token: &str, base_url: &str) -> Result<AccessMapResult> {
    let base_url = base_url.trim().trim_end_matches('/');
    if base_url.is_empty() {
        return Err(anyhow!("JFrog Xray access-map requires a non-empty base URL"));
    }

    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build JFrog Xray HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut permissions = PermissionSummary::default();

    // Ping
    let ping_ok = ping_xray(&client, token, base_url).await;
    if !ping_ok {
        return Err(anyhow!("JFrog Xray access-map: ping failed for {base_url}"));
    }
    permissions.read_only.push("system:ping".to_string());

    // Fetch repos under binary manager
    let repos = fetch_repos(&client, token, base_url).await.unwrap_or_else(|err| {
        warn!("JFrog Xray access-map: repo listing failed: {err}");
        risk_notes.push(format!("Repository listing failed: {err}"));
        Vec::new()
    });

    if !repos.is_empty() {
        permissions.read_only.push("repos:list".to_string());
    }

    // Fetch policies
    let policies = fetch_policies(&client, token, base_url).await.unwrap_or_else(|err| {
        warn!("JFrog Xray access-map: policy listing failed: {err}");
        risk_notes.push(format!("Policy listing failed: {err}"));
        Vec::new()
    });

    let has_policy_access = !policies.is_empty();
    if has_policy_access {
        permissions.risky.push("policies:list".to_string());
        risk_notes.push(format!("Can view {} security policies", policies.len()));
    }

    // Determine if user has admin-level access based on policy management
    // If policies are readable AND repos are listed, likely has elevated access
    let can_manage_policies = has_policy_access && !policies.is_empty();
    let can_scan_repos = !repos.is_empty();

    if can_manage_policies {
        permissions.risky.push("policies:read".to_string());
        risk_notes.push("Policy management access detected".to_string());
    }

    if can_scan_repos {
        permissions.risky.push("repos:scan_control".to_string());
        risk_notes.push("Repository scanning control access detected".to_string());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    // Severity: admin if can manage policies, high if repo scanning, medium otherwise
    let severity = if can_manage_policies && can_scan_repos {
        Severity::High
    } else if can_manage_policies || can_scan_repos {
        Severity::Medium
    } else {
        Severity::Low
    };

    let roles = vec![RoleBinding {
        name: if can_manage_policies {
            "xray:policy_manager".into()
        } else if can_scan_repos {
            "xray:scanner".into()
        } else {
            "xray:viewer".into()
        },
        source: "jfrog_xray".into(),
        permissions: permissions
            .admin
            .iter()
            .chain(permissions.risky.iter())
            .chain(permissions.read_only.iter())
            .cloned()
            .collect(),
    }];

    let mut resources = vec![ResourceExposure {
        resource_type: "xray_instance".into(),
        name: base_url.to_string(),
        permissions: vec!["authenticated".into()],
        risk: severity_to_str(severity).to_string(),
        reason: "JFrog Xray instance accessible with this token".to_string(),
    }];

    for repo in repos.iter().take(MAX_REPO_RESOURCES) {
        let repo_name = repo.name.clone().unwrap_or_default();
        let repo_type = repo.repo_type.clone().unwrap_or_default();

        resources.push(ResourceExposure {
            resource_type: format!("xray_repo:{repo_type}"),
            name: repo_name,
            permissions: vec!["scan:visible".into()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Repository visible in Xray scan configuration".to_string(),
        });
    }

    if repos.len() > MAX_REPO_RESOURCES {
        risk_notes.push(format!(
            "Repository list truncated to first {MAX_REPO_RESOURCES} entries ({} total)",
            repos.len()
        ));
    }

    for policy in &policies {
        if let Some(name) = &policy.name {
            let policy_type = policy.policy_type.clone().unwrap_or_else(|| "unknown".to_string());
            resources.push(ResourceExposure {
                resource_type: format!("xray_policy:{policy_type}"),
                name: name.clone(),
                permissions: vec!["policy:read".into()],
                risk: severity_to_str(Severity::Medium).to_string(),
                reason: "Security policy visible to this token".to_string(),
            });
        }
    }

    Ok(AccessMapResult {
        cloud: "jfrog_xray".into(),
        identity: AccessSummary {
            id: "xray_token".into(),
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            url: Some(base_url.to_string()),
            token_type: Some("bearer_token".into()),
            ..Default::default()
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

fn parse_xray_credentials(raw: &str) -> Result<(String, Option<String>)> {
    if let Ok(json) = serde_json::from_str::<Value>(raw) {
        let token = json
            .get("token")
            .or_else(|| json.get("access_token"))
            .or_else(|| json.get("api_key"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());
        let base_url = json
            .get("base_url")
            .or_else(|| json.get("url"))
            .or_else(|| json.get("instance_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string());

        if let Some(token) = token {
            return Ok((token, base_url));
        }
    }

    let lines: Vec<&str> = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    match lines.len() {
        1 => Ok((lines[0].to_string(), None)),
        n if n >= 2 => Ok((lines[0].to_string(), Some(lines[1].to_string()))),
        _ => Err(anyhow!(
            "JFrog Xray credential format not recognized. Provide JSON with token (+ optional base_url), or lines."
        )),
    }
}

async fn ping_xray(client: &Client, token: &str, base_url: &str) -> bool {
    let resp = client
        .get(format!("{base_url}/xray/api/v1/system/ping"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .send()
        .await;

    matches!(resp, Ok(r) if r.status().is_success())
}

async fn fetch_repos(client: &Client, token: &str, base_url: &str) -> Result<Vec<XrayRepo>> {
    let resp = client
        .get(format!("{base_url}/xray/api/v1/binMgr/default/repos"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("JFrog Xray access-map: failed to query binMgr repos endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "JFrog Xray access-map: binMgr repos endpoint returned HTTP {}",
            resp.status()
        ));
    }

    // The response may be a direct array or wrapped in an object
    let body: Value =
        resp.json().await.context("JFrog Xray access-map: invalid binMgr repos JSON")?;

    if let Some(arr) = body.as_array() {
        let repos: Vec<XrayRepo> =
            arr.iter().filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
        return Ok(repos);
    }

    // Try nested "repos" key
    if let Some(arr) = body.get("repos").and_then(|v| v.as_array()) {
        let repos: Vec<XrayRepo> =
            arr.iter().filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
        return Ok(repos);
    }

    Ok(Vec::new())
}

async fn fetch_policies(client: &Client, token: &str, base_url: &str) -> Result<Vec<XrayPolicy>> {
    let resp = client
        .get(format!("{base_url}/xray/api/v1/policies"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("JFrog Xray access-map: failed to query policies endpoint")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "JFrog Xray access-map: policies endpoint returned HTTP {}",
            resp.status()
        ));
    }

    let body: Value = resp.json().await.context("JFrog Xray access-map: invalid policies JSON")?;

    if let Some(arr) = body.as_array() {
        let policies: Vec<XrayPolicy> =
            arr.iter().filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
        return Ok(policies);
    }

    if let Some(arr) = body.get("policies").and_then(|v| v.as_array()) {
        let policies: Vec<XrayPolicy> =
            arr.iter().filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
        return Ok(policies);
    }

    Ok(Vec::new())
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
