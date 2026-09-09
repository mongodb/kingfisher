use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use futures::{StreamExt, stream};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::Value;

use crate::access_map::{
    AccessMapResult, AccessProbeEvidence, AccessSummary, AccessTokenDetails, AuthorizationEvidence,
    HierarchyScope, PermissionSummary, PrincipalEvidence, ProviderMetadata, ResourceExposure,
    Severity,
};

const PROBE_CONCURRENCY: usize = 4;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BODY: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
struct ApiKeyProbe {
    service: &'static str,
    method: &'static str,
    url: &'static str,
    auth: ApiKeyProbeAuth,
    risk: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum ApiKeyProbeAuth {
    QueryParameter,
    Header,
}

const PROBES: [ApiKeyProbe; 4] = [
    ApiKeyProbe {
        service: "identitytoolkit.googleapis.com",
        method: "identitytoolkit.getProjectConfig",
        url: "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig",
        auth: ApiKeyProbeAuth::QueryParameter,
        risk: "medium",
    },
    ApiKeyProbe {
        service: "generativelanguage.googleapis.com",
        method: "generativelanguage.models.list",
        url: "https://generativelanguage.googleapis.com/v1beta/models?pageSize=1",
        auth: ApiKeyProbeAuth::Header,
        risk: "low",
    },
    ApiKeyProbe {
        service: "translate.googleapis.com",
        method: "language.languages.list",
        url: "https://translation.googleapis.com/language/translate/v2/languages",
        auth: ApiKeyProbeAuth::Header,
        risk: "low",
    },
    ApiKeyProbe {
        service: "youtube.googleapis.com",
        method: "youtube.i18nLanguages.list",
        url: "https://www.googleapis.com/youtube/v3/i18nLanguages?part=snippet&hl=en_US",
        auth: ApiKeyProbeAuth::Header,
        risk: "low",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeStatus {
    Accepted,
    Restricted,
    Invalid,
    Inconclusive,
}

impl ProbeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Restricted => "restricted",
            Self::Invalid => "invalid",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug)]
struct ProbeResult {
    probe: ApiKeyProbe,
    status: ProbeStatus,
    http_status: Option<StatusCode>,
    reason: Option<String>,
    project: Option<String>,
}

/// Map a Google API key with a small, fixed set of read-only API probes.
pub async fn map_access(api_key: &str) -> Result<AccessMapResult> {
    if api_key.trim().is_empty() {
        return Err(anyhow!("Google API key cannot be empty"));
    }

    let client = probe_client()?;
    let mut results = stream::iter(PROBES)
        .map(|probe| probe_api_key(&client, api_key, probe))
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    results.sort_unstable_by_key(|result| result.probe.service);

    build_access_map(results)
}

/// Builds a redirect-free client for the API-key probes.
///
/// The probes send the key in the query string or the `x-goog-api-key`
/// header, and reqwest's cross-host redirect handling strips neither, so
/// following a redirect could forward the credential to a different domain.
/// The probes target fixed googleapis.com endpoints and gain nothing from
/// redirects; an unexpected 3xx response classifies as inconclusive.
fn probe_client() -> Result<Client> {
    Client::builder()
        .user_agent(crate::validation::GLOBAL_USER_AGENT.as_str())
        .redirect(Policy::none())
        .build()
        .context("Failed to build Google API-key probe client")
}

async fn probe_api_key(client: &Client, api_key: &str, probe: ApiKeyProbe) -> ProbeResult {
    let request = async {
        let request = client.get(probe.url);
        let request = match probe.auth {
            ApiKeyProbeAuth::QueryParameter => request.query(&[("key", api_key)]),
            ApiKeyProbeAuth::Header => request.header("x-goog-api-key", api_key),
        };
        let response = request.send().await.map_err(|err| transport_reason(&err))?;
        let status = response.status();
        let body = read_limited_body(response).await.map_err(|err| transport_reason(&err))?;
        Ok::<_, &'static str>((status, body))
    };

    match tokio::time::timeout(PROBE_TIMEOUT, request).await {
        Ok(Ok((status, body))) => classify_response(probe, status, &body),
        Ok(Err(reason)) => ProbeResult {
            probe,
            status: ProbeStatus::Inconclusive,
            http_status: None,
            reason: Some(reason.into()),
            project: None,
        },
        Err(_) => ProbeResult {
            probe,
            status: ProbeStatus::Inconclusive,
            http_status: None,
            reason: Some("timeout".into()),
            project: None,
        },
    }
}

async fn read_limited_body(response: reqwest::Response) -> reqwest::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunks = response.bytes_stream();
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        let remaining = MAX_RESPONSE_BODY.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    Ok(body)
}

fn transport_reason(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connection_error"
    } else if error.is_body() || error.is_decode() {
        "response_error"
    } else {
        "request_error"
    }
}

fn classify_response(probe: ApiKeyProbe, http_status: StatusCode, body: &[u8]) -> ProbeResult {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    let project = parsed.as_ref().and_then(extract_project);
    if http_status.is_success() {
        if !parsed.as_ref().is_some_and(|value| response_confirms_probe(probe, value)) {
            return ProbeResult {
                probe,
                status: ProbeStatus::Inconclusive,
                http_status: Some(http_status),
                reason: Some("unexpected_response".into()),
                project,
            };
        }
        return ProbeResult {
            probe,
            status: ProbeStatus::Accepted,
            http_status: Some(http_status),
            reason: None,
            project,
        };
    }

    let reason = parsed.as_ref().and_then(google_error_reason);
    let status = match reason.as_deref() {
        Some("API_KEY_INVALID" | "API_KEY_EXPIRED" | "CONSUMER_INVALID" | "INVALID_ARGUMENT") => {
            ProbeStatus::Invalid
        }
        Some(
            "API_KEY_SERVICE_BLOCKED"
            | "API_KEY_HTTP_REFERRER_BLOCKED"
            | "API_KEY_IP_ADDRESS_BLOCKED"
            | "API_KEY_ANDROID_APP_BLOCKED"
            | "API_KEY_IOS_APP_BLOCKED"
            | "SERVICE_DISABLED"
            | "BILLING_DISABLED",
        ) => ProbeStatus::Restricted,
        // The shared GCP validator treats any 403 (including unrestricted
        // reasons such as PERMISSION_DENIED and CONSUMER_SUSPENDED) as proof
        // that Google recognized the key, so a 403 response is live-key
        // evidence even when the reason is outside the known taxonomy.
        _ if http_status == StatusCode::FORBIDDEN && reason.is_some() => ProbeStatus::Restricted,
        _ => ProbeStatus::Inconclusive,
    };

    ProbeResult { probe, status, http_status: Some(http_status), reason, project }
}

fn response_confirms_probe(probe: ApiKeyProbe, value: &Value) -> bool {
    match probe.method {
        "identitytoolkit.getProjectConfig" => value.get("projectId").is_some_and(Value::is_string),
        "generativelanguage.models.list" => value.get("models").is_some_and(Value::is_array),
        "language.languages.list" => value.pointer("/data/languages").is_some_and(Value::is_array),
        "youtube.i18nLanguages.list" => {
            value.get("kind").and_then(Value::as_str) == Some("youtube#i18nLanguageListResponse")
                && value.get("items").is_some_and(Value::is_array)
        }
        _ => false,
    }
}

fn google_error_reason(value: &Value) -> Option<String> {
    if let Some(details) = value.pointer("/error/details").and_then(Value::as_array) {
        for detail in details {
            if let Some(reason) = detail.get("reason").and_then(Value::as_str) {
                return Some(reason.to_string());
            }
        }
    }

    let error = value.get("error")?;
    if let Some(message) = error.get("message").and_then(Value::as_str)
        && message.to_ascii_lowercase().contains("api key not valid")
    {
        return Some("API_KEY_INVALID".into());
    }
    error.get("status").and_then(Value::as_str).map(str::to_string)
}

fn extract_project(value: &Value) -> Option<String> {
    if let Some(project) = value.get("projectId").and_then(Value::as_str) {
        return Some(project.to_string());
    }

    value
        .pointer("/error/details")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|detail| detail.pointer("/metadata/consumer").and_then(Value::as_str))
        .find_map(|consumer| consumer.strip_prefix("projects/").map(str::to_string))
}

fn build_access_map(results: Vec<ProbeResult>) -> Result<AccessMapResult> {
    let accepted =
        results.iter().filter(|result| result.status == ProbeStatus::Accepted).collect::<Vec<_>>();
    let restricted_count =
        results.iter().filter(|result| result.status == ProbeStatus::Restricted).count();
    let invalid_count =
        results.iter().filter(|result| result.status == ProbeStatus::Invalid).count();
    let inconclusive_count =
        results.iter().filter(|result| result.status == ProbeStatus::Inconclusive).count();

    if accepted.is_empty() && restricted_count == 0 {
        if invalid_count > 0 {
            return Err(anyhow!("Google rejected the supplied API key as invalid"));
        }
        return Err(anyhow!("Google API-key access probes were inconclusive"));
    }

    let project = results
        .iter()
        .filter(|result| result.status == ProbeStatus::Accepted)
        .find_map(|result| result.project.clone())
        .or_else(|| results.iter().find_map(|result| result.project.clone()));
    // The key string does not expose its API Keys API resource ID, so do not invent a
    // canonical resource path from the project discovered by a probe.
    let identity_id = "google-api-key:[redacted]".to_string();
    let accepted_methods =
        accepted.iter().map(|result| result.probe.method.to_string()).collect::<Vec<_>>();
    let resources = accepted
        .iter()
        .map(|result| ResourceExposure {
            resource_type: "google_api_service".into(),
            name: result.probe.service.into(),
            permissions: vec![result.probe.method.into()],
            risk: result.probe.risk.into(),
            reason: format!(
                "The Google API key was accepted by the read-only {} probe; no broader access was inferred",
                result.probe.method
            ),
        })
        .collect();

    let mut principal_attributes = BTreeMap::from([
        ("accepted_probe_count".into(), accepted.len().to_string()),
        ("inconclusive_probe_count".into(), inconclusive_count.to_string()),
        ("invalid_probe_count".into(), invalid_count.to_string()),
        ("probe_count".into(), results.len().to_string()),
        ("restricted_probe_count".into(), restricted_count.to_string()),
    ]);
    if let Some(project) = project.as_ref() {
        principal_attributes.insert("project_id".into(), project.clone());
    }

    let probes = results
        .iter()
        .map(|result| AccessProbeEvidence {
            service: result.probe.service.into(),
            method: result.probe.method.into(),
            status: result.status.as_str().into(),
            http_status: result.http_status.map(|status| status.as_u16()),
            reason: result.reason.clone(),
        })
        .collect();
    let mut limitations = vec![
        "Only four fixed, read-only Google API methods are probed; unprobed services and methods may still accept the key.".into(),
        "A successful probe proves only the exact reported method, not all methods on that service.".into(),
        "Application restrictions can reject Kingfisher's caller even when the key works from an allowed IP, referrer, Android app, or iOS app.".into(),
        "Kingfisher cannot read the key's configured restrictions without separate OAuth authorization.".into(),
    ];
    if inconclusive_count > 0 {
        limitations.push(format!(
            "{inconclusive_count} probe(s) were inconclusive because Google returned an unrecognized denial or no usable response."
        ));
    }

    let mut risk_notes = vec![format!(
        "{} of {} read-only Google API probes accepted the key; {} were restricted",
        accepted.len(),
        results.len(),
        restricted_count
    )];
    risk_notes.extend(results.iter().filter_map(|result| {
        if result.status == ProbeStatus::Accepted {
            return None;
        }
        Some(format!(
            "{} ({}) was {}{}",
            result.probe.service,
            result.probe.method,
            result.status.as_str(),
            result.reason.as_deref().map(|reason| format!(" [{reason}]")).unwrap_or_default()
        ))
    }));

    let authorization_evidence = AuthorizationEvidence {
        principal: Some(PrincipalEvidence {
            id: identity_id.clone(),
            kind: "api_key".into(),
            canonical_id: None,
            name: None,
            groups: Vec::new(),
            tags: BTreeMap::new(),
            attributes: principal_attributes,
        }),
        hierarchy: project
            .iter()
            .map(|project| HierarchyScope {
                kind: "project".into(),
                id: format!("projects/{project}"),
            })
            .collect(),
        probes,
        limitations,
        ..AuthorizationEvidence::default()
    };

    Ok(AccessMapResult {
        cloud: "gcp".into(),
        fingerprint: None,
        identity: AccessSummary {
            id: identity_id,
            access_type: "api_key".into(),
            project,
            tenant: None,
            account_id: None,
        },
        roles: Vec::new(),
        permissions: PermissionSummary {
            read_only: accepted_methods,
            ..PermissionSummary::default()
        },
        resources,
        severity: if accepted.is_empty() { Severity::Low } else { Severity::Medium },
        recommendations: vec![
            "Rotate the exposed API key after investigating its use.".into(),
            "Apply both application restrictions and API restrictions to the replacement key.".into(),
            "Restrict the key to only the Google API services and methods the application requires.".into(),
            "Review Google Cloud API usage, audit logs, quotas, and billing for unexpected activity.".into(),
        ],
        risk_notes,
        token_details: Some(AccessTokenDetails {
            account_type: Some("api_key".into()),
            token_type: Some("google_api_key".into()),
            ..AccessTokenDetails::default()
        }),
        provider_metadata: Some(ProviderMetadata {
            authorization_evidence: Some(authorization_evidence),
            ..ProviderMetadata::default()
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> ApiKeyProbe {
        PROBES[0]
    }

    #[test]
    fn successful_probe_extracts_identity_toolkit_project() {
        let result = classify_response(
            probe(),
            StatusCode::OK,
            br#"{"projectId":"example-project","authorizedDomains":["example.test"]}"#,
        );

        assert_eq!(result.status, ProbeStatus::Accepted);
        assert_eq!(result.project.as_deref(), Some("example-project"));
        assert!(result.reason.is_none());
    }

    #[test]
    fn restriction_reason_and_consumer_are_retained_without_response_text() {
        let result = classify_response(
            probe(),
            StatusCode::FORBIDDEN,
            br#"{
                "error": {
                    "details": [{
                        "reason": "API_KEY_SERVICE_BLOCKED",
                        "metadata": {"consumer": "projects/123456", "service": "example.googleapis.com"}
                    }]
                }
            }"#,
        );

        assert_eq!(result.status, ProbeStatus::Restricted);
        assert_eq!(result.reason.as_deref(), Some("API_KEY_SERVICE_BLOCKED"));
        assert_eq!(result.project.as_deref(), Some("123456"));
    }

    #[test]
    fn generic_success_response_is_not_treated_as_access() {
        let result = classify_response(PROBES[2], StatusCode::OK, br#"{"status":"healthy"}"#);

        assert_eq!(result.status, ProbeStatus::Inconclusive);
        assert_eq!(result.reason.as_deref(), Some("unexpected_response"));
    }

    #[test]
    fn unrecognized_403_reason_is_still_live_key_evidence() {
        // The shared validator classifies any 403 as proof the key was
        // recognized (classify_gcp_api_key_probe), so the mapper must not
        // degrade these responses to inconclusive.
        for reason in ["PERMISSION_DENIED", "CONSUMER_SUSPENDED"] {
            let body = format!(r#"{{"error":{{"details":[{{"reason":"{reason}"}}]}}}}"#);
            let result = classify_response(probe(), StatusCode::FORBIDDEN, body.as_bytes());
            assert_eq!(result.status, ProbeStatus::Restricted, "reason: {reason}");
            assert_eq!(result.reason.as_deref(), Some(reason));
        }

        // A 403 without a structured Google error is not enough to distinguish
        // a live key from a proxy or generic edge-policy denial.
        let result = classify_response(probe(), StatusCode::FORBIDDEN, b"forbidden");
        assert_eq!(result.status, ProbeStatus::Inconclusive);
        assert!(result.reason.is_none());

        // Non-403 errors with unknown reasons remain inconclusive.
        let result = classify_response(
            probe(),
            StatusCode::BAD_REQUEST,
            br#"{"error":{"details":[{"reason":"SOMETHING_ELSE"}]}}"#,
        );
        assert_eq!(result.status, ProbeStatus::Inconclusive);
    }

    #[test]
    fn access_map_grants_only_successfully_probed_methods() {
        let results = vec![
            ProbeResult {
                probe: PROBES[0],
                status: ProbeStatus::Accepted,
                http_status: Some(StatusCode::OK),
                reason: None,
                project: Some("example-project".into()),
            },
            ProbeResult {
                probe: PROBES[1],
                status: ProbeStatus::Restricted,
                http_status: Some(StatusCode::FORBIDDEN),
                reason: Some("API_KEY_SERVICE_BLOCKED".into()),
                project: None,
            },
        ];

        let mapped = build_access_map(results).unwrap();

        assert_eq!(mapped.identity.project.as_deref(), Some("example-project"));
        assert_eq!(mapped.permissions.read_only, ["identitytoolkit.getProjectConfig"]);
        assert_eq!(mapped.resources.len(), 1);
        assert_eq!(mapped.resources[0].name, "identitytoolkit.googleapis.com");
        let probes = &mapped
            .provider_metadata
            .as_ref()
            .unwrap()
            .authorization_evidence
            .as_ref()
            .unwrap()
            .probes;
        assert_eq!(probes.len(), 2);
        assert_eq!(probes[1].status, "restricted");
    }

    #[test]
    fn restricted_key_returns_partial_result_without_inferred_permissions() {
        let mapped = build_access_map(vec![ProbeResult {
            probe: PROBES[1],
            status: ProbeStatus::Restricted,
            http_status: Some(StatusCode::FORBIDDEN),
            reason: Some("API_KEY_SERVICE_BLOCKED".into()),
            project: Some("123456".into()),
        }])
        .unwrap();

        assert!(matches!(mapped.severity, Severity::Low));
        assert_eq!(mapped.identity.project.as_deref(), Some("123456"));
        assert!(mapped.permissions.read_only.is_empty());
        assert!(mapped.resources.is_empty());
        let probes = &mapped
            .provider_metadata
            .as_ref()
            .unwrap()
            .authorization_evidence
            .as_ref()
            .unwrap()
            .probes;
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].status, "restricted");
        assert_eq!(probes[0].reason.as_deref(), Some("API_KEY_SERVICE_BLOCKED"));
    }

    #[test]
    fn invalid_key_does_not_produce_a_successful_mapping() {
        let result = build_access_map(vec![ProbeResult {
            probe: PROBES[0],
            status: ProbeStatus::Invalid,
            http_status: Some(StatusCode::BAD_REQUEST),
            reason: Some("API_KEY_INVALID".into()),
            project: None,
        }]);

        assert!(result.unwrap_err().to_string().contains("invalid"));
    }

    #[test]
    fn invalid_argument_is_classified_as_an_invalid_key() {
        let result = classify_response(
            probe(),
            StatusCode::BAD_REQUEST,
            br#"{"error":{"status":"INVALID_ARGUMENT"}}"#,
        );
        assert_eq!(result.status, ProbeStatus::Invalid);
    }
}
