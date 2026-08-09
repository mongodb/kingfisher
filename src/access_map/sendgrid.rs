use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const SENDGRID_API: &str = "https://api.sendgrid.com";

#[derive(Deserialize)]
struct SendGridAccount {
    #[serde(rename = "type", default)]
    account_type: Option<String>,
    #[serde(default)]
    reputation: Option<f64>,
}

#[derive(Deserialize)]
struct SendGridProfile {
    #[serde(default)]
    #[expect(dead_code)]
    address: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    #[expect(dead_code)]
    phone: Option<String>,
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize)]
struct SendGridScopesResponse {
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct SendGridApiKey {
    #[serde(default)]
    #[expect(dead_code)]
    api_key_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct SendGridApiKeysResponse {
    #[serde(default)]
    result: Vec<SendGridApiKey>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SendGrid token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("SendGrid access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build SendGrid HTTP client")?;

    let account = fetch_account(&client, token).await?;

    let profile = fetch_profile(&client, token).await.unwrap_or_else(|err| {
        warn!("SendGrid access-map: profile lookup failed: {err}");
        SendGridProfile {
            address: None,
            city: None,
            company: None,
            email: None,
            first_name: None,
            last_name: None,
            phone: None,
            username: None,
        }
    });

    let username = profile
        .username
        .clone()
        .or_else(|| profile.email.clone())
        .unwrap_or_else(|| "sendgrid_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: account.account_type.clone().unwrap_or_else(|| "api_key".into()),
        project: None,
        tenant: profile.company.clone(),
        account_id: profile.username.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();

    // Fetch scopes
    let scopes = fetch_scopes(&client, token).await.unwrap_or_else(|err| {
        warn!("SendGrid access-map: scopes lookup failed: {err}");
        Vec::new()
    });

    for scope in &scopes {
        let role = RoleBinding {
            name: format!("scope:{scope}"),
            source: "sendgrid".into(),
            permissions: vec![scope.clone()],
        };
        roles.push(role);

        match classify_scope(scope) {
            ScopeRisk::Admin => permissions.admin.push(scope.clone()),
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    // Check for other API keys (indicates admin access)
    let other_api_keys = fetch_api_keys(&client, token).await.unwrap_or_else(|err| {
        warn!("SendGrid access-map: API keys enumeration failed: {err}");
        Vec::new()
    });

    if !other_api_keys.is_empty() {
        risk_notes.push(format!("Token can enumerate {} other API keys", other_api_keys.len()));
    }

    // Add account resource
    resources.push(ResourceExposure {
        resource_type: "account".into(),
        name: username.clone(),
        permissions: scopes.clone(),
        risk: severity_to_str(if has_admin_scope(&scopes) {
            Severity::Critical
        } else if has_mail_send(&scopes) {
            Severity::High
        } else {
            Severity::Medium
        })
        .to_string(),
        reason: "SendGrid account accessible with this token".to_string(),
    });

    if has_mail_send(&scopes) {
        resources.push(ResourceExposure {
            resource_type: "capability".into(),
            name: "mail.send".into(),
            permissions: vec!["mail.send".into()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "Token can send email as the organization - phishing risk".to_string(),
        });
    }

    for api_key in &other_api_keys {
        let key_name = api_key.name.clone().unwrap_or_else(|| "unnamed_key".to_string());

        resources.push(ResourceExposure {
            resource_type: "api_key".into(),
            name: key_name,
            permissions: vec!["api_keys.read".into()],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "API key enumerable with this token".to_string(),
        });
    }

    if let Some(rep) = account.reputation {
        risk_notes.push(format!("Sender reputation: {rep:.1}"));
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&scopes);

    if scopes.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: username.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "SendGrid account associated with the token".into(),
        });
        risk_notes.push("Token did not enumerate any scopes".into());
    }

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "sendgrid".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: profile.first_name.as_ref().map(|f| {
                let last = profile.last_name.as_deref().unwrap_or("");
                format!("{f} {last}").trim().to_string()
            }),
            username: profile.username,
            account_type: account.account_type,
            company: profile.company,
            location: profile.city,
            email: profile.email,
            url: None,
            token_type: None,
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_account(client: &Client, token: &str) -> Result<SendGridAccount> {
    let resp = client
        .get(format!("{SENDGRID_API}/v3/user/account"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("SendGrid access-map: failed to fetch account info")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "SendGrid access-map: account lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("SendGrid access-map: invalid account JSON")
}

async fn fetch_profile(client: &Client, token: &str) -> Result<SendGridProfile> {
    let resp = client
        .get(format!("{SENDGRID_API}/v3/user/profile"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("SendGrid access-map: failed to fetch user profile")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "SendGrid access-map: profile lookup failed with HTTP {}",
            resp.status()
        ));
    }

    resp.json().await.context("SendGrid access-map: invalid profile JSON")
}

async fn fetch_scopes(client: &Client, token: &str) -> Result<Vec<String>> {
    let resp = client
        .get(format!("{SENDGRID_API}/v3/scopes"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("SendGrid access-map: failed to fetch scopes")?;

    if !resp.status().is_success() {
        warn!("SendGrid access-map: scopes lookup failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: SendGridScopesResponse =
        resp.json().await.context("SendGrid access-map: invalid scopes JSON")?;
    Ok(body.scopes)
}

async fn fetch_api_keys(client: &Client, token: &str) -> Result<Vec<SendGridApiKey>> {
    let resp = client
        .get(format!("{SENDGRID_API}/v3/api_keys"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("SendGrid access-map: failed to list API keys")?;

    if !resp.status().is_success() {
        warn!("SendGrid access-map: API keys enumeration failed with HTTP {}", resp.status());
        return Ok(Vec::new());
    }

    let body: SendGridApiKeysResponse =
        resp.json().await.context("SendGrid access-map: invalid API keys JSON")?;
    Ok(body.result)
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "api_keys.create" | "api_keys.delete" | "api_keys.update" | "user.account.update" => {
            ScopeRisk::Admin
        }
        s if s.starts_with("mail.send")
            || s.starts_with("marketing.")
            || s.starts_with("templates.")
            || s.starts_with("stats.") =>
        {
            ScopeRisk::Write
        }
        _ if scope.ends_with(".read") => ScopeRisk::Read,
        _ => ScopeRisk::Read,
    }
}

fn has_admin_scope(scopes: &[String]) -> bool {
    scopes.iter().any(|s| {
        matches!(
            s.as_str(),
            "api_keys.create" | "api_keys.delete" | "api_keys.update" | "user.account.update"
        )
    })
}

fn has_mail_send(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "mail.send")
}

fn derive_severity(scopes: &[String]) -> Severity {
    if has_admin_scope(scopes) {
        return Severity::Critical;
    }

    if has_mail_send(scopes) {
        return Severity::High;
    }

    let has_read = scopes.iter().any(|s| s.ends_with(".read"));
    if has_read {
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
