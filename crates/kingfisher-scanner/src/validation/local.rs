//! Dispatch for deterministic, network-free validation.

use super::{ValidationDisposition, ethereum};

/// Result from a deterministic validator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalValidationOutcome {
    /// Semantic result of parsing the local material.
    pub disposition: ValidationDisposition,
    /// Secret-free JSON evidence suitable for strict sanitization before reporting.
    pub body: String,
}

/// Whether a raw validator name is implemented without network access.
pub fn handles(kind: &str) -> bool {
    ethereum::handles(kind)
}

/// Run a deterministic validator when one is registered for `kind`.
pub fn validate(kind: &str, token: &str) -> Option<LocalValidationOutcome> {
    handles(kind).then(|| ethereum::validate(kind, token))
}

/// Return a strictly allowlisted, secret-free response for reporting.
pub fn sanitized_report_body(
    kind: &str,
    disposition: ValidationDisposition,
    body: &str,
) -> Option<String> {
    ethereum::sanitized_report_body(kind, disposition, body)
}
