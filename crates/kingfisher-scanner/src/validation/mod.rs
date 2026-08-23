//! Credential validation module for Kingfisher.
//!
//! This module provides functionality for validating detected secrets by checking
//! if they are still active/valid. Validation is gated behind the `validation` feature.
//!
//! # Features
//!
//! Enable validation features in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! kingfisher-scanner = { version = "0.1", features = ["validation"] }
//! ```
//!
//! # Available Validators
//!
//! - **HTTP**: Generic HTTP-based validation via configurable requests
//! - **AWS**: AWS credential validation via STS (requires `validation-aws` feature)
//! - **GCP**: GCP service account validation (requires `validation-gcp` feature)
//! - **Azure**: Azure Storage credential validation (requires `validation-azure` feature)
//! - **Databases**: MongoDB, MySQL, Postgres, JDBC (requires `validation-database` feature)
//! - **JWT**: JWT token validation (requires `validation-jwt` feature)
//! - **Raw**: provider/protocol-specific validators that need custom logic
//!   (requires `validation-raw` feature)
//! - **Ethereum**: network-free key parsing and address derivation
//!   (requires `validation-ethereum` feature)

mod utils;
mod validation_body;

use kingfisher_core::ValidationOutcome;

#[cfg(feature = "validation-http")]
pub mod http_validation;

#[cfg(feature = "validation-aws")]
pub mod aws;

#[cfg(feature = "validation-azure")]
pub mod azure;

#[cfg(feature = "validation-coinbase")]
pub mod coinbase;

#[cfg(feature = "validation-gcp")]
pub mod gcp;

#[cfg(feature = "validation-jwt")]
pub mod jwt;

#[cfg(feature = "validation-database")]
pub mod jdbc;

#[cfg(feature = "validation-database")]
pub mod mongodb;

#[cfg(feature = "validation-database")]
pub mod mysql;

#[cfg(feature = "validation-database")]
pub mod postgres;

#[cfg(feature = "validation-ethereum")]
pub mod ethereum;

#[cfg(feature = "validation-raw")]
pub mod raw;

// Re-exports
pub use utils::{find_closest_variable, process_captures};
pub use validation_body::{ValidationResponseBody, as_str, clone_as_string, from_string};

#[cfg(feature = "validation-http")]
pub use http_validation::{
    SSRF_BLOCKED_MESSAGE, SsrfBlockedError, build_request_builder, check_host_resolvable,
    check_url_resolvable, generate_http_cache_key_parts, is_ssrf_safe_ip, parse_http_method,
    process_headers, retry_multipart_request, retry_request, validate_response,
    with_request_template_globals,
};

#[cfg(feature = "validation-raw")]
pub use raw::{RawValidationOutcome, required_vars as raw_required_vars, validate_raw};

#[cfg(feature = "validation-http")]
#[expect(deprecated)]
pub use http_validation::check_url_resolvable_safe;

#[cfg(feature = "validation-aws")]
pub use aws::{
    aws_key_to_account_number, generate_aws_cache_key, revoke_aws_access_key,
    set_aws_skip_account_ids, set_aws_validation_concurrency, should_skip_aws_validation,
    validate_aws_credentials, validate_aws_credentials_input,
};

#[cfg(feature = "validation-http")]
use std::sync::{LazyLock, OnceLock};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crossbeam_skiplist::SkipMap;

/// User agent string used for HTTP validation requests.
#[cfg(feature = "validation-http")]
pub static GLOBAL_USER_AGENT: LazyLock<String> = LazyLock::new(build_user_agent);

#[cfg(feature = "validation-http")]
static USER_AGENT_SUFFIX: OnceLock<String> = OnceLock::new();

#[cfg(feature = "validation-http")]
const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36";

#[cfg(feature = "validation-http")]
fn build_user_agent() -> String {
    let base = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    if let Some(suffix) = USER_AGENT_SUFFIX.get() {
        format!("{base} {suffix} {BROWSER_USER_AGENT}")
    } else {
        format!("{base} {BROWSER_USER_AGENT}")
    }
}

/// Configure a user-agent suffix that is appended after the Kingfisher package name/version.
///
/// The suffix is inserted before the browser portion of the user-agent. Empty or whitespace-only
/// values are ignored. This should be called once near program start prior to accessing
/// [`GLOBAL_USER_AGENT`].
#[cfg(feature = "validation-http")]
pub fn set_user_agent_suffix<S: Into<String>>(suffix: Option<S>) {
    if let Some(suffix) = suffix {
        let trimmed = suffix.into().trim().to_string();
        if trimmed.is_empty() {
            return;
        }
        let _ = USER_AGENT_SUFFIX.set(trimmed);
    }
}

/// Cache duration for validation results (20 minutes).
pub const VALIDATION_CACHE_SECONDS: u64 = 1200;

/// Cache type used for validation memoization.
pub type Cache = Arc<SkipMap<String, CachedResponse>>;

/// A cached validation response.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    /// The response body from validation.
    pub body: ValidationResponseBody,
    /// The HTTP status code.
    pub status: http::StatusCode,
    /// Whether the credential was valid.
    pub is_valid: bool,
    /// Semantic validation classification, including offline outcomes.
    pub outcome: ValidationOutcome,
    /// When this result was cached.
    pub timestamp: Instant,
}

impl CachedResponse {
    /// Create a new cached response.
    pub fn new(body: ValidationResponseBody, status: http::StatusCode, is_valid: bool) -> Self {
        let outcome = ValidationOutcome::from_legacy(false, is_valid, status.as_u16());
        Self { body, status, is_valid, outcome, timestamp: Instant::now() }
    }

    /// Override the inferred legacy outcome with an explicit semantic outcome.
    pub fn with_outcome(mut self, outcome: ValidationOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    /// Check if this cached response is still valid.
    pub fn is_still_valid(&self, cache_duration: Duration) -> bool {
        self.timestamp.elapsed() < cache_duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_response_expiry() {
        let response = CachedResponse::new(from_string("test"), http::StatusCode::OK, true);

        assert!(response.is_still_valid(Duration::from_secs(60)));
        assert!(response.is_still_valid(Duration::from_secs(1)));
    }
}
