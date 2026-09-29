//! Explicit validation states and credential-safe diagnostics.
use crate::ValidationOutcome;
use reqwest::StatusCode;
use serde::Serialize;
use std::fmt;

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
        Self { outcome, reason: None, http_status: None, response_body: String::new() }
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
}
