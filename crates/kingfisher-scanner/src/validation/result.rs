//! Explicit validation states and credential-safe diagnostics.
use crate::ValidationOutcome;
use reqwest::StatusCode;
use serde::Serialize;
use std::{collections::BTreeMap, fmt};

/// Credential-free explanation for an inconclusive or skipped check.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationReason {
    MissingDependency,
    AmbiguousDependency,
    FeatureDisabled,
    NonAuthoritative,
    RedactedInput,
    InvalidConfiguration,
    RequestFailed,
    DeadlineExceeded,
    ResponseMismatch,
    ResponseTooLarge,
    TargetBlocked,
    UnsupportedValidator,
}

/// An explicit validation outcome, with an optional provider response.
///
/// `response_body` may contain secrets. Debug omits it; this type deliberately
/// does not implement Serialize. High-level findings omit the provider response.
#[derive(Clone)]
#[non_exhaustive]
pub struct ValidationResult {
    pub outcome: ValidationOutcome,
    pub reason: Option<ValidationReason>,
    pub http_status: Option<u16>,
    pub response_body: String,
    /// Structured Betterleaks analysis. May contain secrets; omitted from Debug and serialization.
    pub analysis_data: Option<serde_json::Value>,
    pub(crate) accepted_http_endpoint: Option<(usize, usize, reqwest::Url)>,
    pub(crate) accepted_http_fallback: Option<String>,
    pub(crate) input_diagnostics: Vec<super::preparation::CredentialInputDiagnostic>,
}
impl fmt::Debug for ValidationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationResult")
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("http_status", &self.http_status)
            .finish_non_exhaustive()
    }
}
impl ValidationResult {
    pub(crate) fn outcome(outcome: ValidationOutcome) -> Self {
        Self {
            outcome,
            reason: None,
            http_status: None,
            response_body: String::new(),
            analysis_data: None,
            accepted_http_endpoint: None,
            accepted_http_fallback: None,
            input_diagnostics: Vec::new(),
        }
    }
    pub(crate) fn skipped(reason: ValidationReason) -> Self {
        Self { reason: Some(reason), ..Self::outcome(ValidationOutcome::Skipped) }
    }
    pub(crate) fn unavailable(reason: ValidationReason) -> Self {
        Self { reason: Some(reason), ..Self::outcome(ValidationOutcome::Unavailable) }
    }
    pub(crate) fn reason(mut self, reason: ValidationReason) -> Self {
        self.reason = Some(reason);
        self
    }
    pub(crate) fn body(mut self, body: String) -> Self {
        self.response_body = body;
        self
    }
    pub(crate) fn status(mut self, status: StatusCode) -> Self {
        self.http_status = Some(status.as_u16());
        self
    }

    /// Variables identifying the HTTP endpoint that verified the credential.
    ///
    /// These are empty unless validation succeeded. URLs may contain credentials;
    /// retain them only in private credential snapshots, never ordinary reporting.
    /// Revocation URL lists select `VALIDATION_ENDPOINT_INDEX`; a single revocation
    /// URL can use `{{ VALIDATION_ORIGIN }}` or `{{ VALIDATION_URL }}`.
    pub fn endpoint_variables(&self) -> BTreeMap<String, String> {
        if !self.outcome.is_verified_active() {
            return BTreeMap::new();
        }
        let Some((index, count, url)) = &self.accepted_http_endpoint else {
            return BTreeMap::new();
        };
        let mut variables = BTreeMap::from([
            ("VALIDATION_ENDPOINT_INDEX".into(), index.to_string()),
            ("VALIDATION_ENDPOINT_COUNT".into(), count.to_string()),
            ("VALIDATION_URL".into(), url.as_str().into()),
            ("VALIDATION_ORIGIN".into(), url.origin().ascii_serialization()),
        ]);
        if let Some(id) = &self.accepted_http_fallback {
            variables.insert("VALIDATION_FALLBACK_ID".into(), id.clone());
        }
        variables
    }
}
