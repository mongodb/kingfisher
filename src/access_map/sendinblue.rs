use anyhow::{Context, Result, anyhow};
use reqwest::{Client, header};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary, ResourceExposure,
    RoleBinding, Severity, build_recommendations,
};

const BREVO_API: &str = "https://api.brevo.com";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BrevoAccount {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    company_name: Option<String>,
    #[serde(default)]
    plan: Vec<BrevoPlan>,
}

#[derive(Deserialize)]
struct BrevoPlan {
    #[serde(rename = "type", default)]
    plan_type: Option<String>,
    #[serde(default)]
    credits: Option<f64>,
}

#[derive(Deserialize)]
struct BrevoSender {
    #[serde(default)]
    #[expect(dead_code)]
    id: Option<u64>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Deserialize)]
struct BrevoSendersResponse {
    #[serde(default)]
    senders: Vec<BrevoSender>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path).with_context(|| {
            format!("Failed to read Brevo (Sendinblue) token from {}", path.display())
        })?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "Brevo (Sendinblue) access-map requires a validated token from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Brevo HTTP client")?;

    let account = fetch_account(&client, token).await?;

    let username = account.email.clone().unwrap_or_else(|| "brevo_user".to_string());

    let identity = AccessSummary {
        id: username.clone(),
        access_type: "api_key".into(),
        project: None,
        tenant: account.company_name.clone(),
        account_id: account.email.clone(),
    };

    let mut risk_notes = Vec::new();
    let mut resources = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut roles = Vec::new();
    let mut detected_scopes: Vec<String> = Vec::new();

    // Brevo API keys are full-access; determine capabilities by probing endpoints
    let senders = fetch_senders(&client, token).await.unwrap_or_else(|err| {
        warn!("Brevo access-map: senders lookup failed: {err}");
        Vec::new()
    });

    let contacts_accessible = probe_contacts(&client, token).await;
    let templates_accessible = probe_templates(&client, token).await;

    // Brevo doesn't have granular scopes; full API key grants everything
    detected_scopes.push("account.read".into());

    if !senders.is_empty() {
        detected_scopes.push("senders.read".into());
        detected_scopes.push("email.send".into());
        risk_notes.push(format!(
            "Token has access to {} configured senders - email sending possible",
            senders.len()
        ));
    }

    if contacts_accessible {
        detected_scopes.push("contacts.read".into());
        detected_scopes.push("contacts.write".into());
    }

    if templates_accessible {
        detected_scopes.push("templates.read".into());
        detected_scopes.push("templates.write".into());
    }

    // Since Brevo API keys are full-access, classify as admin
    permissions.admin.push("full_api_key".into());
    roles.push(RoleBinding {
        name: "full_api_key".into(),
        source: "brevo".into(),
        permissions: detected_scopes.clone(),
    });

    for scope in &detected_scopes {
        match classify_scope(scope) {
            ScopeRisk::Admin => { /* already added full_api_key above */ }
            ScopeRisk::Write => permissions.risky.push(scope.clone()),
            ScopeRisk::Read => permissions.read_only.push(scope.clone()),
        }
    }

    // Account-level resource
    resources.push(ResourceExposure {
        resource_type: "account".into(),
        name: username.clone(),
        permissions: detected_scopes.clone(),
        risk: severity_to_str(if !senders.is_empty() { Severity::High } else { Severity::Medium })
            .to_string(),
        reason: "Brevo account accessible with full API key".to_string(),
    });

    // Add plan information
    for plan in &account.plan {
        let plan_type = plan.plan_type.as_deref().unwrap_or("unknown");
        let credits = plan.credits.unwrap_or(0.0);
        risk_notes.push(format!("Plan: {plan_type}, credits: {credits}"));

        resources.push(ResourceExposure {
            resource_type: "plan".into(),
            name: plan_type.to_string(),
            permissions: vec!["account.read".into()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: format!("Brevo plan with {credits} credits"),
        });
    }

    // Sender resources
    for sender in &senders {
        let sender_name = sender.name.clone().unwrap_or_else(|| "unnamed_sender".to_string());
        let sender_email = sender.email.clone().unwrap_or_default();

        resources.push(ResourceExposure {
            resource_type: "sender".into(),
            name: format!("{sender_name} <{sender_email}>"),
            permissions: vec!["email.send".into()],
            risk: severity_to_str(Severity::High).to_string(),
            reason: "Configured sender - can be used to send email".to_string(),
        });
    }

    if contacts_accessible {
        resources.push(ResourceExposure {
            resource_type: "capability".into(),
            name: "contacts".into(),
            permissions: vec!["contacts.read".into(), "contacts.write".into()],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Contact list accessible - contains recipient PII".to_string(),
        });
    }

    if templates_accessible {
        resources.push(ResourceExposure {
            resource_type: "capability".into(),
            name: "templates".into(),
            permissions: vec!["templates.read".into(), "templates.write".into()],
            risk: severity_to_str(Severity::Medium).to_string(),
            reason: "Email templates accessible and modifiable".to_string(),
        });
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&senders);

    Ok(AccessMapResult {
        mapping_error: None,
        cloud: "sendinblue".into(),
        identity,
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: account.first_name.as_ref().map(|f| {
                let last = account.last_name.as_deref().unwrap_or("");
                format!("{f} {last}").trim().to_string()
            }),
            username: account.email.clone(),
            account_type: account.plan.first().and_then(|p| p.plan_type.clone()),
            company: account.company_name,
            location: None,
            email: account.email,
            url: None,
            token_type: Some("api_key".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes: detected_scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn fetch_account(client: &Client, token: &str) -> Result<BrevoAccount> {
    let resp = client
        .get(format!("{BREVO_API}/v3/account"))
        .header("api-key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Brevo access-map: failed to fetch account info")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Brevo access-map: account lookup failed with HTTP {}", resp.status()));
    }

    resp.json().await.context("Brevo access-map: invalid account JSON")
}

async fn fetch_senders(client: &Client, token: &str) -> Result<Vec<BrevoSender>> {
    let resp = client
        .get(format!("{BREVO_API}/v3/senders"))
        .header("api-key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Brevo access-map: failed to fetch senders")?;

    if !resp.status().is_success() {
        return Err(anyhow!("Brevo access-map: senders lookup failed with HTTP {}", resp.status()));
    }

    let body: BrevoSendersResponse =
        resp.json().await.context("Brevo access-map: invalid senders JSON")?;
    Ok(body.senders)
}

async fn probe_contacts(client: &Client, token: &str) -> bool {
    let resp = client
        .get(format!("{BREVO_API}/v3/contacts?limit=1"))
        .header("api-key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await;

    match resp {
        Ok(r) => r.status().is_success(),
        Err(err) => {
            warn!("Brevo access-map: contacts probe failed: {err}");
            false
        }
    }
}

async fn probe_templates(client: &Client, token: &str) -> bool {
    let resp = client
        .get(format!("{BREVO_API}/v3/smtp/templates?limit=1"))
        .header("api-key", token)
        .header(header::ACCEPT, "application/json")
        .send()
        .await;

    match resp {
        Ok(r) => r.status().is_success(),
        Err(err) => {
            warn!("Brevo access-map: templates probe failed: {err}");
            false
        }
    }
}

enum ScopeRisk {
    Admin,
    Write,
    Read,
}

fn classify_scope(scope: &str) -> ScopeRisk {
    match scope {
        "full_api_key" => ScopeRisk::Admin,
        s if s.contains(".write") || s == "email.send" => ScopeRisk::Write,
        _ => ScopeRisk::Read,
    }
}

fn derive_severity(senders: &[BrevoSender]) -> Severity {
    if !senders.is_empty() {
        return Severity::High;
    }

    Severity::Medium
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
