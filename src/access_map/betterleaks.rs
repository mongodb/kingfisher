//! Opt-in access mapping from a custom Betterleaks v2 analysis program.

use anyhow::{Context, Result};
use kingfisher_rules::BetterleaksValidation;
use kingfisher_scanner::validation::limits::{ResourceTimeout, timeout};
use liquid_core::ValueView;
use serde_json::Value;

use super::{AccessMapResult, AccessSummary, PermissionSummary, ProviderMetadata, Severity};

#[derive(Clone)]
pub struct AnalysisRequest {
    pub allow_internal_ips: bool,
    pub rule_id: String,
    pub config: BetterleaksValidation,
    pub captures: Vec<(String, String, usize, usize)>,
    pub globals: liquid::Object,
    pub validation_result: Option<Value>,
    pub fingerprint: String,
}

impl std::fmt::Debug for AnalysisRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnalysisRequest").field("rule_id", &self.rule_id).finish_non_exhaustive()
    }
}

pub async fn map_access(request: AnalysisRequest) -> Result<AccessMapResult> {
    timeout(std::time::Duration::from_secs(30), map_access_inner(request))
        .await
        .context("Betterleaks credential analysis timed out")?
}

async fn map_access_inner(request: AnalysisRequest) -> Result<AccessMapResult> {
    let mut credentials: Vec<String> =
        request.captures.iter().map(|(_, value, ..)| value.clone()).collect();
    for variable in request.config.components.values() {
        if let Some(value) = request
            .globals
            .get(variable.as_str())
            .or_else(|| request.globals.get(variable.to_uppercase().as_str()))
        {
            credentials.push(value.to_kstr().to_string());
        }
    }
    for name in ["__BETTERLEAKS_COMPONENTS", "__BETTERLEAKS_FINDING_CAPTURES"] {
        if let Some(value) =
            request.globals.get(name).and_then(|value| serde_json::to_value(value).ok())
        {
            let value = if let Value::String(source) = value {
                serde_json::from_str(&source).unwrap_or(Value::Null)
            } else {
                value
            };
            credential_strings(&value, &mut credentials);
        }
    }
    credentials.retain(|value| !value.is_empty());
    credentials.sort_by_key(|value| std::cmp::Reverse(value.len()));
    credentials.dedup();
    let client = reqwest::Client::builder()
        .user_agent(crate::validation::GLOBAL_USER_AGENT.as_str())
        .redirect(reqwest::redirect::Policy::none())
        .resource_timeout(std::time::Duration::from_secs(30))
        .build()?;
    let validation = match request.validation_result {
        Some(validation) => validation,
        None => kingfisher_scanner::validation::betterleaks::validate(
            &request.config,
            &request.captures,
            &request.globals,
            &client,
            request.allow_internal_ips,
        )
        .await
        .analysis_data
        .unwrap_or(Value::Null),
    };
    let mut analysis = kingfisher_scanner::validation::betterleaks::analyze(
        &request.config,
        &request.captures,
        &request.globals,
        &client,
        request.allow_internal_ips,
        &validation,
    )
    .await?;
    sanitize_analysis(&mut analysis, &credentials);
    Ok(analysis_result(&request.rule_id, analysis))
}

fn credential_strings(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(value) => output.push(value.clone()),
        Value::Array(values) => {
            for value in values {
                credential_strings(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                credential_strings(value, output);
            }
        }
        _ => {}
    }
}

fn sanitize_analysis(value: &mut Value, credentials: &[String]) {
    for field in ["reason", "metadata"] {
        if let Some(value) = value.get_mut(field) {
            redact_value(value, credentials);
        }
    }
    if let Some(identity) = value.get_mut("identity") {
        redact_identity(identity, credentials);
    }
}

fn redact_identity(value: &mut Value, credentials: &[String]) {
    match value {
        Value::Object(values) => {
            for value in values.values_mut() {
                redact_identity(value, credentials);
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_identity(value, credentials);
            }
        }
        _ => redact_value(value, credentials),
    }
}

fn redact_value(value: &mut Value, credentials: &[String]) {
    let sanitize = |value: &str| {
        credentials
            .iter()
            .fold(value.to_string(), |value, credential| value.replace(credential, "[REDACTED]"))
    };
    match value {
        Value::String(value) => *value = sanitize(value),
        Value::Array(values) => {
            for value in values {
                redact_value(value, credentials);
            }
        }
        Value::Object(values) => {
            let original = std::mem::take(values);
            for (name, mut value) in original {
                redact_value(&mut value, credentials);
                values.insert(sanitize(&name), value);
            }
        }
        _ => {}
    }
}

fn analysis_result(rule_id: &str, analysis: Value) -> AccessMapResult {
    let identity = &analysis["identity"];
    let capabilities: Vec<String> = analysis["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut permissions = PermissionSummary::default();
    for capability in &capabilities {
        match capability.as_str() {
            "admin" | "manage_users" => permissions.admin.push(capability.clone()),
            "create_credentials" => permissions.privilege_escalation.push(capability.clone()),
            "write" | "read_secrets" => permissions.risky.push(capability.clone()),
            "read" => permissions.read_only.push(capability.clone()),
            _ => {}
        }
    }
    let severity = match analysis["severity"].as_str() {
        Some("high") => Severity::High,
        Some("medium") => Severity::Medium,
        _ => Severity::Unknown,
    };
    let string = |key| identity[key].as_str().map(str::to_owned);
    let risk_notes = if capabilities.is_empty() {
        vec![
            "Analysis established no positive capabilities; the credential's risk is unknown."
                .into(),
        ]
    } else {
        Vec::new()
    };
    AccessMapResult {
        cloud: rule_id.to_owned(),
        fingerprint: None,
        identity: AccessSummary {
            id: string("id")
                .or_else(|| string("username"))
                .or_else(|| string("name"))
                .or_else(|| string("email"))
                .unwrap_or_else(|| "unknown".into()),
            access_type: "credential".into(),
            project: None,
            tenant: identity["account"]["name"].as_str().map(str::to_owned),
            account_id: identity["account"]["id"].as_str().map(str::to_owned),
        },
        roles: Vec::new(),
        permissions,
        resources: Vec::new(),
        severity,
        recommendations: vec!["Revoke exposed credentials and review observed access.".into()],
        risk_notes,
        token_details: None,
        provider_metadata: Some(ProviderMetadata {
            betterleaks_analysis: Some(analysis),
            ..Default::default()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_preserves_public_evidence_and_maps_positive_capabilities() {
        let public = serde_json::json!({
            "identity": {"id":"alice", "account":{"id":"account-7", "name":"Example", "domains":["example.test"]}},
            "severity": "high",
            "capabilities": ["read", "read_secrets"],
            "metadata": {"scopes":["secrets:read"]}
        });
        let mapped = analysis_result("custom.acme", public.clone());
        assert_eq!(mapped.identity.id, "alice");
        assert_eq!(mapped.identity.account_id.as_deref(), Some("account-7"));
        assert_eq!(mapped.identity.tenant.as_deref(), Some("Example"));
        assert!(matches!(mapped.severity, Severity::High));
        assert_eq!(mapped.permissions.read_only, ["read"]);
        assert_eq!(mapped.permissions.risky, ["read_secrets"]);
        assert_eq!(mapped.provider_metadata.unwrap().betterleaks_analysis, Some(public));
    }
    #[test]
    fn analysis_without_positive_grants_retains_unknown_risk() {
        let mapped = analysis_result("custom.acme", serde_json::json!({"severity":"unknown"}));
        assert!(matches!(mapped.severity, Severity::Unknown));
        assert!(mapped.risk_notes[0].contains("unknown"));
    }

    #[test]
    fn analysis_uses_canonical_severity_and_username_identity() {
        let mapped = analysis_result(
            "custom.acme",
            serde_json::json!({"identity":{"username":"alice"}, "capabilities":["read"],"severity":"medium"}),
        );
        assert_eq!(mapped.identity.id, "alice");
        assert!(matches!(mapped.severity, Severity::Medium));
        let write = analysis_result(
            "custom.acme",
            serde_json::json!({"capabilities":["write"],"severity":"high"}),
        );
        assert!(matches!(write.severity, Severity::High));
    }
    #[test]
    fn public_analysis_redacts_primary_and_component_values_recursively() {
        let mut evidence = serde_json::json!({"identity":{"id":"secret-account"},"metadata":{"secret-token":["Bearer secret-token",{"nested":"secret-account"}]},"capabilities":["read"],"severity":"medium"});
        sanitize_analysis(&mut evidence, &["secret-token".into(), "secret-account".into()]);
        let output = serde_json::to_string(&evidence).unwrap();
        assert!(!output.contains("secret-token"));
        assert!(!output.contains("secret-account"));
        assert_eq!(evidence["capabilities"], serde_json::json!(["read"]));
        assert_eq!(evidence["metadata"]["[REDACTED]"][0], "Bearer [REDACTED]");
    }
}
