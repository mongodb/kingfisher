//! This module defines rule syntax and evaluation types for secret detection.
//!
//! It provides structures and methods to represent validation configurations,
//! HTTP requests for validation, rule syntax (with support for comment stripping),
//! and associated metadata such as confidence and fingerprints.

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
    hash::Hash,
    path::Path,
    str::FromStr,
    sync::{LazyLock, OnceLock},
};

use anyhow::{Context, Result, anyhow};
use liquid::{ParserBuilder, model::Value, object};
use regex::Regex;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use tracing::debug;
use xxhash_rust::xxh3::xxh3_64;

use crate::liquid_filters;

/// Returns false as the default value.
fn default_false() -> bool {
    false
}

/// Returns true as the default value.
fn default_true() -> bool {
    true
}

/// TLS certificate validation mode for secret validation requests.
///
/// Controls how TLS certificates are validated when connecting to endpoints
/// during credential validation (e.g., database connections, API calls).
#[derive(
    Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    /// Full WebPKI certificate validation: trusted CA chain, hostname match, not expired.
    /// This is the default and most secure mode.
    #[default]
    Strict,

    /// Permit certificate-verification bypass when both the global policy and
    /// the rule opt into lax mode. Validators configure their own transports;
    /// hostname and expiry checks are not guaranteed in this mode.
    Lax,

    /// Disable all TLS certificate validation. Use with extreme caution.
    Off,
}

/// Represents various types of validation that a rule can perform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Validation {
    /// Mark a high-signal match as not attempted without performing network validation.
    Assumed,
    AWS,
    AzureStorage,
    Coinbase,
    GCP,
    MongoDB,
    MySQL,
    Postgres,
    Jdbc,
    /// Dispatch a captured credential URI to an HTTPS Basic Auth or database validator.
    ///
    /// Scan rules can provide a named `URI` capture; otherwise `TOKEN` is used. Keeping `TOKEN`
    /// separate lets broad URI detectors report only the embedded password while validation uses
    /// the complete connection string.
    CredentialUri,
    JWT,
    /// Deterministic, network-free Ethereum key-material validation.
    Ethereum(EthereumValidation),
    Raw(String),
    /// A pre-parsed Betterleaks validation expression. The Expr parser is used only by the
    /// snapshot generator; production builds evaluate this portable AST directly.
    Betterleaks(BetterleaksValidation),
    Http(HttpValidation),
    Grpc(GrpcValidation),
}

impl Validation {
    /// Return an inspection copy with literal OAuth2 operator credentials redacted.
    ///
    /// Environment variable names, client IDs and other validation metadata are
    /// preserved. This does not resolve environment variables or mutate the
    /// executable configuration; ordinary `Serialize` remains lossless.
    pub fn redacted_for_inspection(&self) -> Self {
        let mut inspected = self.clone();
        if let Self::Http(http) = &mut inspected {
            redact_http_auth(http);
        }
        inspected
    }
}

fn redact_http_auth(http: &mut HttpValidation) {
    if let Some(auth) = &mut http.auth {
        let credentials = &mut auth.oauth2.ropc;
        for value in
            [&mut credentials.username, &mut credentials.password, &mut credentials.client_secret]
                .into_iter()
                .flatten()
        {
            *value = "[REDACTED]".into();
        }
    }
}

/// A Betterleaks validation expression parsed at snapshot-generation time.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct BetterleaksValidation {
    /// Original Betterleaks expression retained for development-time inspection.
    #[cfg(debug_assertions)]
    #[serde(default)]
    pub source: String,
    #[serde(deserialize_with = "deserialize_betterleaks_expression")]
    pub expression: BetterleaksExpr,
    /// Optional Betterleaks analysis program, evaluated only by explicit access mapping.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_betterleaks_expression"
    )]
    pub analyze: Option<BetterleaksExpr>,
    /// Betterleaks component rule ID to the Kingfisher dependency variable populated at runtime.
    #[serde(default)]
    pub components: BTreeMap<String, String>,
    /// Kingfisher-only operational capabilities joined to this Betterleaks detector at build time.
    #[serde(default)]
    pub capabilities: BetterleaksCapabilities,
}

/// Operational metadata that is intentionally kept separate from Betterleaks detection rules.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Default)]
pub struct BetterleaksCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_map: Option<BetterleaksAccessMap>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_bindings: Option<BetterleaksRevocationBindings>,
}

/// Access-map collector selected for a Betterleaks detector.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct BetterleaksAccessMap {
    pub handler: BetterleaksAccessMapHandler,
    /// Handler input name to `finding.secret` or `components.<betterleaks-rule-id>`.
    #[serde(default)]
    pub inputs: BTreeMap<String, String>,
    /// Permit access mapping for a reachable 2xx validation response even if it was inconclusive.
    #[serde(default)]
    pub reachable_2xx: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum BetterleaksAccessMapHandler {
    Aws,
    Gcp,
    GcpApiKey,
    AzureClientSecret,
    AzureStorage,
    Algolia,
    Alibaba,
    Artifactory,
    Salesforce,
    Airtable,
    Anthropic,
    Auth0,
    Buildkite,
    Circleci,
    Fastly,
    Github,
    Gitlab,
    Harness,
    Huggingface,
    IbmCloud,
    Monday,
    Openai,
    Paypal,
    Pinecone,
    Sendinblue,
    Stripe,
    WeightsAndBiases,
}

/// Remaps a Betterleaks finding and its components into an existing revocation action.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct BetterleaksRevocationBindings {
    /// Value passed as the positional secret to `kingfisher revoke`.
    #[serde(default = "default_finding_secret_source")]
    pub secret: String,
    /// Revocation template variable to a Betterleaks finding/component source.
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
}

fn default_finding_secret_source() -> String {
    "finding.secret".to_string()
}

/// Portable subset of expr-lang's AST used by Betterleaks validation rules.
///
/// Keeping the parsed representation in the generated rule snapshot means neither Go nor the
/// expr parser is present in a production Kingfisher build.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BetterleaksExpr {
    Nil,
    Identifier {
        value: String,
    },
    Integer {
        value: i64,
    },
    Float {
        /// Decimal spelling retained from the source to keep this type Eq/Ord/Hash.
        value: String,
    },
    Bool {
        value: bool,
    },
    String {
        value: String,
    },
    Unary {
        operator: String,
        node: Box<BetterleaksExpr>,
    },
    Binary {
        operator: String,
        left: Box<BetterleaksExpr>,
        right: Box<BetterleaksExpr>,
    },
    Chain {
        node: Box<BetterleaksExpr>,
    },
    Member {
        node: Box<BetterleaksExpr>,
        property: Box<BetterleaksExpr>,
        #[serde(default)]
        optional: bool,
        #[serde(default)]
        method: bool,
    },
    Slice {
        node: Box<BetterleaksExpr>,
        from: Box<BetterleaksExpr>,
        to: Box<BetterleaksExpr>,
    },
    Call {
        callee: Box<BetterleaksExpr>,
        #[serde(default)]
        arguments: Vec<BetterleaksExpr>,
    },
    Builtin {
        name: String,
        #[serde(default)]
        arguments: Vec<BetterleaksExpr>,
    },
    Conditional {
        cond: Box<BetterleaksExpr>,
        exp1: Box<BetterleaksExpr>,
        exp2: Box<BetterleaksExpr>,
    },
    VariableDeclarator {
        name: String,
        value: Box<BetterleaksExpr>,
        expr: Box<BetterleaksExpr>,
    },
    Sequence {
        #[serde(default)]
        nodes: Vec<BetterleaksExpr>,
    },
    Array {
        #[serde(default)]
        nodes: Vec<BetterleaksExpr>,
    },
    Map {
        #[serde(default)]
        pairs: Vec<BetterleaksExpr>,
    },
    Pair {
        key: Box<BetterleaksExpr>,
        value: Box<BetterleaksExpr>,
    },
    Predicate {
        node: Box<BetterleaksExpr>,
    },
    Pointer {
        name: String,
    },
}

/// Ethereum key material that can be validated and mapped to a public address locally.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum EthereumValidation {
    PrivateKey,
    PublicKey,
    Mnemonic,
}

/// Represents revocation actions that a rule can perform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Revocation {
    AWS,
    GCP,
    /// Explicit Betterleaks revocation program; never evaluated by scanning or validation.
    Betterleaks(BetterleaksValidation),
    Http(#[serde(deserialize_with = "deserialize_http_revocation")] HttpValidation),
    /// Multi-step HTTP revocation (up to 2 steps).
    /// Some services require looking up an ID before deletion.
    HttpMultiStep(HttpMultiStepRevocation),
}

impl Revocation {
    /// Redact literal OAuth2 credentials even in programmatically built actions.
    /// Loading rule files rejects revocation auth; inspection must also be safe
    /// for Rust callers that construct `Revocation::Http` directly.
    pub fn redacted_for_inspection(&self) -> Self {
        let mut inspected = self.clone();
        if let Self::Http(http) = &mut inspected {
            redact_http_auth(http);
        }
        inspected
    }
}

fn deserialize_betterleaks_expression<'de, D>(
    deserializer: D,
) -> std::result::Result<BetterleaksExpr, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Expression {
        Ast(BetterleaksExpr),
        Source(String),
    }

    match Expression::deserialize(deserializer)? {
        Expression::Ast(expression) => Ok(expression),
        Expression::Source(source) => {
            let expression = crate::betterleaks::parse_custom_expression(&source)
                .map_err(serde::de::Error::custom)?;
            serde_json::from_value(expression).map_err(serde::de::Error::custom)
        }
    }
}

fn deserialize_optional_betterleaks_expression<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<BetterleaksExpr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Expression(
        #[serde(deserialize_with = "deserialize_betterleaks_expression")] BetterleaksExpr,
    );
    Option::<Expression>::deserialize(deserializer).map(|value| value.map(|value| value.0))
}

fn deserialize_http_revocation<'de, D>(
    deserializer: D,
) -> std::result::Result<HttpValidation, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Ignore auth's contents rather than parse operator credentials for an
    // unsupported action. Even malformed auth must produce a credential-free error.
    #[derive(Deserialize)]
    struct HttpRevocation {
        request: HttpRequest,
        multipart: Option<MultipartConfig>,
        #[serde(default)]
        auth: Option<serde::de::IgnoredAny>,
    }
    let http = HttpRevocation::deserialize(deserializer)?;
    if http.auth.is_some() {
        return Err(serde::de::Error::custom("OAuth2 auth is supported for validation only"));
    }
    Ok(HttpValidation { request: http.request, multipart: http.multipart, auth: None })
}

/// Configuration for multi-step HTTP revocation.
///
/// This allows up to 2 steps where the first step can extract values
/// (e.g., an ID) from its response, which are then used in the second step.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpMultiStepRevocation {
    /// Sequential steps to execute (minimum 1, maximum 2).
    pub steps: Vec<RevocationStep>,
}

/// A single step in a multi-step revocation process.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct RevocationStep {
    /// Human-readable name for this step (e.g., "lookup_id", "delete").
    #[serde(default)]
    pub name: Option<String>,

    /// HTTP request configuration for this step.
    pub request: HttpRequest,

    /// Optional multipart configuration for this step.
    #[serde(default)]
    pub multipart: Option<MultipartConfig>,

    /// Variables to extract from the response for use in subsequent steps.
    /// Keys are variable names (uppercase), values are extraction patterns.
    #[serde(default)]
    pub extract: Option<BTreeMap<String, ResponseExtractor>>,
}

/// Describes how to extract a value from an HTTP response.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type")]
pub enum ResponseExtractor {
    /// Extract from JSON response using a JSONPath-like syntax.
    /// Example: `$.data.id` or `$.items[0].token_id`
    JsonPath { path: String },

    /// Extract using a regex pattern with a capture group.
    /// The first capture group is used as the extracted value.
    Regex { pattern: String },

    /// Extract an HTTP response header value.
    Header { name: String },

    /// Extract the entire response body as-is.
    Body,

    /// Extract the HTTP status code as a string.
    StatusCode,
}

/// Specifies that a rule depends on a variable from another rule.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct DependsOnRule {
    /// Try ranked credential candidates against an explicitly supported fixed-endpoint validator.
    /// Endpoint dependencies must never opt in. Defaults to strict association.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub verify_candidates: bool,
    pub rule_id: String,
    pub variable: String,
    /// Whether the dependency may be absent without preventing validation.
    #[serde(default)]
    pub optional: bool,
    /// Betterleaks proximity expression retained for association and parity diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within: Option<String>,
}

/// Specifies character type requirements for matched secrets.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct PatternRequirements {
    /// Minimum number of digits required (0-9)
    #[serde(default)]
    pub min_digits: Option<usize>,
    /// Minimum number of uppercase letters required (A-Z)
    #[serde(default)]
    pub min_uppercase: Option<usize>,
    /// Minimum number of lowercase letters required (a-z)
    #[serde(default)]
    pub min_lowercase: Option<usize>,
    /// Minimum number of special characters required
    #[serde(default)]
    pub min_special_chars: Option<usize>,
    /// Custom set of characters to consider as "special" (defaults to common punctuation)
    #[serde(default)]
    pub special_chars: Option<String>,
    /// Words that should cause the match to be excluded when present (case-insensitive)
    #[serde(default)]
    pub ignore_if_contains: Option<Vec<String>>,
    /// Optional checksum validation configuration.
    #[serde(default)]
    pub checksum: Option<ChecksumRequirement>,
}

/// Defines a checksum validation strategy for a matched pattern.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct ChecksumRequirement {
    /// Template describing how to extract the checksum from the match.
    pub actual: ChecksumActual,
    /// Template describing how to compute the expected checksum.
    pub expected: String,
    /// When true, checksum evaluation is skipped if the required capture is missing.
    #[serde(default)]
    pub skip_if_missing: bool,
}

/// Describes how to extract the checksum value from a match.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct ChecksumActual {
    /// Liquid template used to compute the checksum from the match.
    pub template: String,
    /// Optional capture group that must be present before evaluating the checksum.
    #[serde(default)]
    pub requires_capture: Option<String>,
}

/// Contextual information available when validating pattern requirements.
#[derive(Clone, Copy)]
pub struct PatternRequirementContext<'a> {
    /// Compiled regex associated with the rule.
    pub regex: &'a regex::bytes::Regex,
    /// Captures for the current match.
    pub captures: &'a regex::bytes::Captures<'a>,
    /// Full bytes matched by the rule (capture group 0).
    pub full_match: &'a [u8],
}

impl PatternRequirements {
    /// Default special characters if none are specified
    const DEFAULT_SPECIAL_CHARS: &'static str = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/\\`~";

    /// Validates whether the given byte slice meets the character requirements.
    /// Returns the validation outcome, including whether the match should be ignored
    /// due to `ignore_if_contains` entries when that behaviour is enabled.
    pub fn validate(
        &self,
        input: &[u8],
        context: Option<PatternRequirementContext<'_>>,
        respect_ignore_if_contains: bool,
    ) -> PatternValidationResult {
        // Convert to string (lossy for non-UTF8)
        let s = String::from_utf8_lossy(input);

        // Check digit requirement
        if let Some(min_digits) = self.min_digits {
            let digit_count = s.chars().filter(|c| c.is_ascii_digit()).count();
            if digit_count < min_digits {
                return PatternValidationResult::Failed;
            }
        }

        // Check uppercase requirement
        if let Some(min_uppercase) = self.min_uppercase {
            let uppercase_count = s.chars().filter(|c| c.is_ascii_uppercase()).count();
            if uppercase_count < min_uppercase {
                return PatternValidationResult::Failed;
            }
        }

        // Check lowercase requirement
        if let Some(min_lowercase) = self.min_lowercase {
            let lowercase_count = s.chars().filter(|c| c.is_ascii_lowercase()).count();
            if lowercase_count < min_lowercase {
                return PatternValidationResult::Failed;
            }
        }

        // Check special character requirement
        if let Some(min_special) = self.min_special_chars {
            let special_chars =
                self.special_chars.as_deref().unwrap_or(Self::DEFAULT_SPECIAL_CHARS);
            let special_count = s.chars().filter(|c| special_chars.contains(*c)).count();
            if special_count < min_special {
                return PatternValidationResult::Failed;
            }
        }

        // Check ignore-if-contains requirement
        if respect_ignore_if_contains && let Some(ignore_terms) = self.ignore_if_contains.as_ref() {
            let lowercase_input = s.to_lowercase();
            if let Some(matched_term) = ignore_terms
                .iter()
                .filter_map(|term| {
                    let trimmed = term.trim();
                    if trimmed.is_empty() { None } else { Some((trimmed, trimmed.to_lowercase())) }
                })
                .find_map(|(original, lowered)| {
                    if lowercase_input.contains(&lowered) {
                        Some(original.to_string())
                    } else {
                        None
                    }
                })
            {
                return PatternValidationResult::IgnoredBySubstring { matched_term };
            }
        }

        if let Some(checksum) = &self.checksum {
            let Some(ctx) = context else {
                return if checksum.skip_if_missing {
                    PatternValidationResult::Passed
                } else {
                    PatternValidationResult::Failed
                };
            };

            if let Some(required) = checksum.actual.requires_capture.as_deref()
                && ctx.captures.name(required).is_none()
            {
                return if checksum.skip_if_missing {
                    PatternValidationResult::Passed
                } else {
                    PatternValidationResult::Failed
                };
            }

            let mut globals = object!({
                "MATCH": s.to_string(),
                "FULL_MATCH": String::from_utf8_lossy(ctx.full_match).to_string(),
            });

            for name in ctx.regex.capture_names().flatten() {
                if let Some(capture) = ctx.captures.name(name) {
                    let value = String::from_utf8_lossy(capture.as_bytes()).to_string();
                    globals.insert(name.to_owned().into(), Value::scalar(value.clone()));
                    globals.insert(name.to_ascii_uppercase().into(), Value::scalar(value));
                }
            }

            let actual =
                match render_pattern_requirement_template(&checksum.actual.template, &globals) {
                    Ok(rendered) => rendered,
                    Err(err) => {
                        debug!(
                            "Failed to render checksum actual template '{}': {}",
                            checksum.actual.template, err
                        );
                        return PatternValidationResult::Failed;
                    }
                };
            let expected = match render_pattern_requirement_template(&checksum.expected, &globals) {
                Ok(rendered) => rendered,
                Err(err) => {
                    debug!(
                        "Failed to render checksum expected template '{}': {}",
                        checksum.expected, err
                    );
                    return PatternValidationResult::Failed;
                }
            };

            if actual != expected {
                let actual_len = actual.chars().count();
                let expected_len = expected.chars().count();
                return PatternValidationResult::FailedChecksum { actual_len, expected_len };
            }
        }

        PatternValidationResult::Passed
    }
}

fn render_pattern_requirement_template(
    template: &str,
    globals: &liquid::Object,
) -> Result<String, String> {
    PATTERN_REQUIREMENTS_TEMPLATE_PARSER
        .parse(template)
        .map_err(|e| e.to_string())
        .and_then(|parsed| parsed.render(globals).map_err(|e| e.to_string()))
}

/// Result of validating [`PatternRequirements`] against a potential match.
#[derive(Debug, PartialEq, Eq)]
pub enum PatternValidationResult {
    /// All requirements are satisfied and the match should be kept.
    Passed,
    /// Requirements were not satisfied.
    Failed,
    /// Checksum requirements were not satisfied; captures basic mismatch details for debugging.
    FailedChecksum { actual_len: usize, expected_len: usize },
    /// The match contains one of the `ignore_if_contains` substrings and should be skipped.
    IgnoredBySubstring { matched_term: String },
}

/// Configuration for HTTP validation. This contains a request configuration
/// and an optional multipart configuration.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpValidation {
    pub request: HttpRequest,
    pub multipart: Option<MultipartConfig>,
    /// Authentication for a configured verification service, separate from the candidate secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Box<HttpValidationAuth>>,
}

/// Maximum additional HTTP environments attempted after the primary.
pub const MAX_HTTP_FALLBACKS: usize = 2;

/// An explicit alternative environment. Validation and revocation reuse are independent opt-ins.
#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd, Clone)]
#[serde(deny_unknown_fields)]
pub struct HttpFallback {
    /// Unique environment identifier; `primary` is reserved.
    pub id: String,
    /// False by default. Reuse primary method/auth/headers/body/matchers, not its target URL.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reuse_primary_validation_logic: bool,
    /// Required replacement URL when reusing validation logic; the primary URL is not inherited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Complete independent HTTP validation; required unless reuse is explicitly true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<Validation>,
    /// False by default. Reuse primary action logic, with explicit replacement URL(s).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reuse_primary_revocation_logic: bool,
    /// Required replacement URL for reused single-request HTTP revocation logic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_url: Option<String>,
    /// One replacement URL per existing multi-step action step; never alternative mutation targets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocation_urls: Vec<String>,
    /// Independent action. Omission is unavailable unless primary revocation reuse is explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation: Option<Revocation>,
}

impl HttpFallback {
    fn resolved_revocation<'a>(
        &'a self,
        primary: Option<&Revocation>,
    ) -> Result<Option<Cow<'a, Revocation>>> {
        use anyhow::{bail, ensure};
        if !self.reuse_primary_revocation_logic {
            ensure!(
                self.revocation_url.is_none() && self.revocation_urls.is_empty(),
                "Revocation URL overrides require reuse_primary_revocation_logic: true"
            );
            return Ok(self.revocation.as_ref().map(Cow::Borrowed));
        }
        ensure!(
            self.revocation.is_none(),
            "reuse_primary_revocation_logic: true cannot include revocation"
        );
        let mut action = primary
            .context("reuse_primary_revocation_logic: true requires primary revocation")?
            .clone();
        match &mut action {
            Revocation::Http(http) => {
                ensure!(
                    self.revocation_urls.is_empty(),
                    "Single-request revocation logic reuse requires revocation_url, not revocation_urls"
                );
                http.request.url = self
                    .revocation_url
                    .as_ref()
                    .filter(|url| !url.trim().is_empty())
                    .context(
                        "Single-request revocation logic reuse requires a nonblank revocation_url",
                    )?
                    .clone();
                http.request.fallback_urls.clear();
            }
            Revocation::HttpMultiStep(multi) => {
                ensure!(
                    self.revocation_url.is_none(),
                    "Multi-step revocation logic reuse requires revocation_urls, not revocation_url"
                );
                ensure!(
                    (1..=2).contains(&multi.steps.len())
                        && self.revocation_urls.len() == multi.steps.len()
                        && self.revocation_urls.iter().all(|url| !url.trim().is_empty()),
                    "Multi-step revocation logic reuse requires one nonblank revocation_urls entry per step (one or two steps)"
                );
                for (step, url) in multi.steps.iter_mut().zip(&self.revocation_urls) {
                    step.request.url = url.clone();
                    step.request.fallback_urls.clear();
                }
            }
            _ => bail!(
                "Primary revocation logic reuse supports only HTTP and HTTP multi-step actions"
            ),
        }
        Ok(Some(Cow::Owned(action)))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(deny_unknown_fields)]
pub struct HttpValidationAuth {
    pub oauth2: OAuth2Config,
}

/// OAuth2 password-grant authentication for an explicitly configured verifier.
/// Values are operator configuration, never templates populated from findings.
#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(deny_unknown_fields)]
pub struct OAuth2Config {
    pub token_endpoint: String,
    #[serde(default = "default_token_header")]
    pub token_header: String,
    pub ropc: OAuth2PasswordCredentials,
}

fn default_token_header() -> String {
    "Authorization".into()
}

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(deny_unknown_fields)]
pub struct OAuth2PasswordCredentials {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub username_env: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub password_env: Option<String>,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_env: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

impl fmt::Debug for OAuth2Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2Config").finish_non_exhaustive()
    }
}

impl fmt::Debug for OAuth2PasswordCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2PasswordCredentials").finish_non_exhaustive()
    }
}

/// Configuration for gRPC validation.
///
/// This is intended for services that are gRPC-only (HTTP/2 + trailers),
/// such as Modal's control plane.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GrpcValidation {
    pub request: GrpcRequest,
}

/// Configuration for a single gRPC unary request.
///
/// Notes:
/// - `url` should include the full gRPC method path, e.g.
///   `https://api.modal.com/modal.client.ModalClientModal/ContainerHello`
/// - `headers` can include custom auth headers, content-type, etc.
/// - `body` is sent as raw bytes; YAML `\u0000` escapes are supported.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct GrpcRequest {
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub response_matcher: Option<Vec<ResponseMatcher>>,
}

/// Configuration for an HTTP request used for validation.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(try_from = "HttpRequestDefinition", into = "HttpRequestDefinition")]
pub struct HttpRequest {
    pub method: String,
    /// Primary URL template. YAML also accepts an ordered, nonempty list of URLs.
    pub url: String,
    /// Additional URL templates, attempted in order after `url` for validation.
    /// Revocation selects exactly one URL using the accepted validation endpoint index.
    pub fallback_urls: Vec<String>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub response_matcher: Option<Vec<ResponseMatcher>>,
    pub multipart: Option<MultipartConfig>,
    // allow HTML only when explicitly set true
    pub response_is_html: bool,
}

impl HttpRequest {
    /// URL templates in their configured order, including the primary URL.
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.url.as_str()).chain(self.fallback_urls.iter().map(String::as_str))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum HttpRequestUrls {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Serialize, Deserialize)]
struct HttpRequestDefinition {
    method: String,
    url: HttpRequestUrls,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    response_matcher: Option<Vec<ResponseMatcher>>,
    #[serde(default)]
    multipart: Option<MultipartConfig>,
    #[serde(default = "default_false")]
    response_is_html: bool,
}

impl TryFrom<HttpRequestDefinition> for HttpRequest {
    type Error = &'static str;

    fn try_from(definition: HttpRequestDefinition) -> std::result::Result<Self, Self::Error> {
        let (url, fallback_urls) = match definition.url {
            HttpRequestUrls::Single(url) => (url, Vec::new()),
            HttpRequestUrls::Multiple(mut urls) => {
                if urls.is_empty() {
                    return Err("HTTP url list must contain at least one endpoint");
                }
                if urls.iter().any(|url| url.trim().is_empty()) {
                    return Err("HTTP url list cannot contain an empty endpoint");
                }
                let url = urls.remove(0);
                (url, urls)
            }
        };
        Ok(Self {
            method: definition.method,
            url,
            fallback_urls,
            headers: definition.headers,
            body: definition.body,
            response_matcher: definition.response_matcher,
            multipart: definition.multipart,
            response_is_html: definition.response_is_html,
        })
    }
}

impl From<HttpRequest> for HttpRequestDefinition {
    fn from(request: HttpRequest) -> Self {
        let url = if request.fallback_urls.is_empty() {
            HttpRequestUrls::Single(request.url)
        } else {
            HttpRequestUrls::Multiple(
                std::iter::once(request.url).chain(request.fallback_urls).collect(),
            )
        };
        Self {
            method: request.method,
            url,
            headers: request.headers,
            body: request.body,
            response_matcher: request.response_matcher,
            multipart: request.multipart,
            response_is_html: request.response_is_html,
        }
    }
}

/// Configuration for multipart HTTP requests.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct MultipartConfig {
    pub parts: Vec<MultipartPart>,
}

/// Configuration for a single multipart part.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct MultipartPart {
    pub name: String,
    #[serde(rename = "type")]
    pub part_type: String,
    pub content: String,
    #[serde(default)]
    pub content_type: Option<String>,
}

// ── wrapper with deny_unknown_fields ───────────────────────────
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReportResponseData {
    #[serde(default = "default_true")]
    report_response: bool,
}

/// Describes how to match HTTP responses.
/// This is an untagged enum to allow for different matching strategies.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(untagged)]
pub enum ResponseMatcher {
    WordMatch {
        r#type: String,
        words: Vec<String>,
        #[serde(default = "default_false")]
        match_all_words: bool,
        #[serde(default = "default_false")]
        negative: bool, // true = “fail if the pattern *does* appear”
    },
    StatusMatch {
        r#type: String,
        status: Vec<u16>,
        #[serde(default = "default_false")]
        match_all_status: bool,
        #[serde(default = "default_false")]
        negative: bool, // true = “fail if the status *does* match”
    },
    HeaderMatch {
        r#type: String,        // "HeaderMatch"
        header: String,        // e.g. "content-type"
        expected: Vec<String>, // one or more acceptable tokens
        #[serde(default = "default_false")]
        match_all_values: bool,
    },
    JsonValid {
        // "JsonValid"
        r#type: String,
    },
    XmlValid {
        // "XmlValid"
        r#type: String,
    },
    ReportResponse(ReportResponseData),
}

/// The confidence level associated with a rule.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy, Default)]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl PartialOrd for Confidence {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Confidence {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Confidence::Low, Confidence::Low) => Ordering::Equal,
            (Confidence::Low, _) => Ordering::Less,
            (Confidence::Medium, Confidence::Low) => Ordering::Greater,
            (Confidence::Medium, Confidence::Medium) => Ordering::Equal,
            (Confidence::Medium, Confidence::High) => Ordering::Less,
            (Confidence::High, Confidence::High) => Ordering::Equal,
            (Confidence::High, _) => Ordering::Greater,
        }
    }
}

impl Confidence {
    /// Returns true if the current confidence is at least as high as `other`.
    pub fn is_at_least(&self, other: &Confidence) -> bool {
        self >= other
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for Confidence {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            _ => Err(anyhow!("Invalid confidence level: {}", s)),
        }
    }
}

impl JsonSchema for Confidence {
    fn schema_name() -> Cow<'static, str> {
        "Confidence".into()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "enum": ["Low", "Medium", "High"]
        })
    }
}

// Custom serialization/deserialization for case-insensitive handling.
impl Serialize for Confidence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Confidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The syntactic representation of a rule.
#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Clone)]
pub struct RuleSyntax {
    /// Human-readable name of the rule.
    pub name: String,
    /// Globally unique identifier for the rule.
    pub id: String,
    /// The regex pattern used by the rule.
    pub pattern: String,
    /// Higher values take precedence when imported Betterleaks findings overlap.
    #[serde(default)]
    pub specificity: i64,
    /// Optional metadata labels retained from custom YAML and Betterleaks TOML.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Case-insensitive candidate keywords; at least one must occur in the source fragment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keywords: Vec<String>,
    /// A Betterleaks path-only rule reports its matching path without content matching.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub betterleaks_path_only: bool,
    /// Optional source-path predicate. The content pattern is evaluated only for matching paths.
    #[serde(default)]
    pub path: Option<String>,
    /// Betterleaks expression that returns true when a candidate should be discarded.
    #[serde(default)]
    pub betterleaks_filter: Option<BetterleaksExpr>,
    /// Betterleaks capture-selection semantics.
    ///
    /// `Some(0)` selects the first non-empty capture, while `Some(n)` selects capture `n`.
    /// `None` uses the capture-selection behavior of the Kingfisher rule format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub betterleaks_secret_group: Option<usize>,
    /// Whether a successful validator may establish that this finding is an active credential.
    #[serde(default = "default_true")]
    pub authoritative: bool,
    /// Legacy v1 matching-engine hint.
    ///
    /// Kingfisher v2 retains this field for custom-rule deserialization compatibility but ignores
    /// its value: every rule uses Vectorscan for candidate detection and is then confirmed by the
    /// exact Rust regex for capture extraction.
    #[serde(default = "default_true")]
    pub vectorscan_compatible: bool,
    /// Minimum Shannon entropy required.
    #[serde(default)]
    pub min_entropy: f32,
    /// Confidence level of the rule.
    #[serde(default)]
    pub confidence: Confidence,
    /// Whether the rule is visible to end-users.
    #[serde(default = "default_true")]
    pub visible: bool,
    /// Example inputs that should match.
    #[serde(default)]
    pub examples: Vec<String>,
    /// Example inputs that should not match.
    #[serde(default)]
    pub negative_examples: Vec<String>,
    /// References (e.g., URLs) for further context.
    #[serde(default)]
    pub references: Vec<String>,
    /// Optional validation configuration.
    #[serde(default)]
    pub validation: Option<Validation>,
    /// Optional revocation configuration.
    #[serde(default)]
    pub revocation: Option<Revocation>,
    /// Optional named HTTP environments; execution requires explicit opt-in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallbacks: Vec<HttpFallback>,
    /// Optional dependencies on other rules.
    #[serde(default)]
    pub depends_on_rule: Vec<Option<DependsOnRule>>,
    /// Optional character type requirements for matched secrets.
    #[serde(default)]
    pub pattern_requirements: Option<PatternRequirements>,
    /// Optional TLS mode for validation connections.
    #[serde(default)]
    pub tls_mode: Option<TlsMode>,
}

/// Regex pattern used to remove vectorscan-style comments from rule patterns.
pub static RULE_COMMENTS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)(\(\?#[^)]*\))|(\s\#[\sa-zA-Z]*$)")
        .expect("comment-stripping regex should compile")
});

static PATTERN_REQUIREMENTS_TEMPLATE_PARSER: LazyLock<liquid::Parser> = LazyLock::new(|| {
    liquid_filters::register_all(ParserBuilder::with_stdlib())
        .build()
        .expect("pattern requirement template parser should compile")
});

impl RuleSyntax {
    /// Inspection copy with literal OAuth2 operator credentials redacted in every environment.
    pub fn redacted_for_inspection(&self) -> Self {
        let mut inspected = self.clone();
        inspected.validation =
            inspected.validation.as_ref().map(Validation::redacted_for_inspection);
        inspected.revocation =
            inspected.revocation.as_ref().map(Revocation::redacted_for_inspection);
        for fallback in &mut inspected.fallbacks {
            fallback.validation =
                fallback.validation.as_ref().map(Validation::redacted_for_inspection);
            fallback.revocation =
                fallback.revocation.as_ref().map(Revocation::redacted_for_inspection);
        }
        inspected
    }

    /// Creates a visible custom rule with no validators, filters, or entropy threshold.
    ///
    /// The pattern is compiled by `RulesDatabase`; construction itself performs no I/O.
    pub fn new(id: impl Into<String>, name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            pattern: pattern.into(),
            specificity: 0,
            tags: Vec::new(),
            keywords: Vec::new(),
            betterleaks_path_only: false,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
            min_entropy: 0.0,
            confidence: Confidence::default(),
            visible: true,
            examples: Vec::new(),
            negative_examples: Vec::new(),
            references: Vec::new(),
            validation: None,
            revocation: None,
            fallbacks: Vec::new(),
            depends_on_rule: Vec::new(),
            pattern_requirements: None,
            tls_mode: None,
        }
    }

    /// Validate only the new optional capability; legacy rules need no migration.
    pub fn check_http_fallbacks(&self) -> Result<()> {
        use anyhow::{bail, ensure};
        if self.fallbacks.is_empty() {
            return Ok(());
        }
        ensure!(
            self.fallbacks.len() <= MAX_HTTP_FALLBACKS,
            "At most two HTTP fallbacks are allowed"
        );
        let Some(Validation::Http(primary)) = &self.validation else {
            bail!("HTTP fallbacks require primary HTTP validation");
        };
        ensure!(
            primary.request.fallback_urls.is_empty(),
            "Do not mix named fallbacks with legacy URL lists"
        );
        let mut ids = std::collections::BTreeSet::new();
        for fallback in &self.fallbacks {
            ensure!(
                !fallback.id.is_empty()
                    && fallback.id != "primary"
                    && fallback
                        .id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
                    && ids.insert(&fallback.id),
                "Fallback IDs must be unique, nonempty identifiers other than primary"
            );
            if fallback.reuse_primary_validation_logic {
                ensure!(
                    fallback.validation.is_none(),
                    "reuse_primary_validation_logic: true cannot include validation"
                );
                ensure!(
                    fallback.url.as_ref().is_some_and(|url| !url.trim().is_empty()),
                    "reuse_primary_validation_logic: true requires a nonblank url (only the logic is reused)"
                );
            } else {
                ensure!(
                    fallback.url.is_none(),
                    "Fallback url requires reuse_primary_validation_logic: true"
                );
                let Some(Validation::Http(http)) = &fallback.validation else {
                    bail!(
                        "reuse_primary_validation_logic defaults to false and requires complete HTTP validation"
                    );
                };
                ensure!(
                    http.request.fallback_urls.is_empty() && !http.request.url.trim().is_empty(),
                    "Fallback validation must have one nonblank scalar URL"
                );
                ensure!(
                    http.request.response_matcher.as_ref().is_some_and(|m| !m.is_empty()),
                    "Fallback HTTP validation requires response_matcher"
                );
            }
            if let Some(action) = fallback.resolved_revocation(self.revocation.as_ref())? {
                let requests: Vec<_> = match action.as_ref() {
                    Revocation::Http(http) => vec![&http.request],
                    Revocation::HttpMultiStep(multi) => {
                        ensure!(
                            (1..=2).contains(&multi.steps.len()),
                            "Fallback revocation requires one or two steps"
                        );
                        multi.steps.iter().map(|step| &step.request).collect()
                    }
                    _ => bail!("Fallback revocation must be HTTP or HTTP multi-step"),
                };
                ensure!(
                    requests.iter().all(|r| r.fallback_urls.is_empty()),
                    "Named fallback revocation must use scalar URLs"
                );
                ensure!(
                    requests.last().is_some_and(|r| r
                        .response_matcher
                        .as_ref()
                        .is_some_and(|m| !m.is_empty())),
                    "Fallback revocation requires a final response_matcher"
                );
            }
        }
        Ok(())
    }

    /// Resolve HTTP configurations without rendering templates or performing I/O.
    /// The primary is always first. Disabled alternatives impose no input requirements.
    pub fn http_validations(&self, enabled: bool) -> Result<Vec<(Option<&str>, HttpValidation)>> {
        self.check_http_fallbacks()?;
        let Some(Validation::Http(primary)) = &self.validation else { return Ok(Vec::new()) };
        let mut first = primary.clone();
        first.request.fallback_urls.clear();
        let mut configurations = vec![(None, first)];
        if !enabled {
            return Ok(configurations);
        }
        if self.fallbacks.is_empty() {
            // Legacy lists must remain loadable and must still try the primary
            // when alternatives are enabled. Keep the same bounded execution
            // policy as named fallbacks instead of rejecting the whole rule.
            if primary.request.fallback_urls.len() > MAX_HTTP_FALLBACKS {
                static WARN_LEGACY_URL_LIMIT: std::sync::Once = std::sync::Once::new();
                WARN_LEGACY_URL_LIMIT.call_once(|| {
                    tracing::warn!("HTTP validation uses only the first three URLs in legacy URL lists (primary and two fallbacks); additional URLs are ignored");
                });
            }
            for url in primary.request.fallback_urls.iter().take(MAX_HTTP_FALLBACKS) {
                let mut http = primary.clone();
                http.request.url = url.clone();
                http.request.fallback_urls.clear();
                configurations.push((None, http));
            }
        } else {
            for fallback in &self.fallbacks {
                let mut http = if fallback.reuse_primary_validation_logic {
                    primary.clone()
                } else if let Some(Validation::Http(http)) = &fallback.validation {
                    http.clone()
                } else {
                    unreachable!("checked HTTP fallback")
                };
                if fallback.reuse_primary_validation_logic {
                    http.request.url = fallback.url.clone().expect("checked fallback URL");
                }
                configurations.push((Some(fallback.id.as_str()), http));
            }
        }
        Ok(configurations)
    }

    /// Select one environment's action. Primary revocation is reused only on explicit opt-in.
    pub fn selected_revocation(
        &self,
        fallback_id: Option<&str>,
    ) -> Result<Option<Cow<'_, Revocation>>> {
        match fallback_id {
            None => Ok(self.revocation.as_ref().map(Cow::Borrowed)),
            Some(id) => self
                .fallbacks
                .iter()
                .find(|fallback| fallback.id == id)
                .ok_or_else(|| anyhow!("Unknown validated fallback ID"))?
                .resolved_revocation(self.revocation.as_ref()),
        }
    }

    /// Maximum allowed regex size.
    const REGEX_SIZE_LIMIT: usize = 16 * 1024 * 1024;

    /// Returns the rule pattern with comments removed.
    pub fn uncommented_pattern(&self) -> Cow<'_, str> {
        RULE_COMMENTS_PATTERN.replace_all(&self.pattern, "")
    }

    /// Helper to build a regex from a pattern string.
    fn build_regex(pattern: &str) -> Result<regex::bytes::Regex> {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .size_limit(Self::REGEX_SIZE_LIMIT)
            .build()
            .context("Failed to build regex")
    }

    /// Compile the rule pattern into a regex.
    pub fn as_regex(&self) -> Result<regex::bytes::Regex> {
        Self::build_regex(&self.uncommented_pattern())
    }

    /// Return whether this rule is eligible for the supplied source path.
    pub fn matches_path(&self, path: &str) -> bool {
        self.path
            .as_deref()
            .is_none_or(|pattern| Regex::new(pattern).is_ok_and(|regex| regex.is_match(path)))
    }

    /// Return the imported Betterleaks filter expression, if present.
    pub fn betterleaks_filter(&self) -> Option<&BetterleaksExpr> {
        self.betterleaks_filter.as_ref()
    }

    /// Return the Betterleaks capture selector, if this is an imported Betterleaks rule.
    pub fn betterleaks_secret_group(&self) -> Option<usize> {
        self.betterleaks_secret_group
    }

    /// Whether validation may authoritatively classify this rule as active.
    pub fn is_authoritative(&self) -> bool {
        self.authoritative
    }

    /// Return whether Vectorscan is used as the rule's candidate prefilter.
    pub fn vectorscan_compatible(&self) -> bool {
        true
    }

    /// Compile the rule pattern into an anchored regex (matching end-of-input).
    ///
    /// # Example
    ///
    /// ```
    /// # use kingfisher_rules::RuleSyntax;
    /// let r = RuleSyntax {
    ///     name: "Test rule".to_string(),
    ///     id: "test.1".to_string(),
    ///     pattern: r"hello\s*world".to_string(),
    ///     specificity: 0,
    ///     tags: vec![],
    ///     keywords: vec![],
    ///     betterleaks_path_only: false,
    ///     path: None,
    ///     betterleaks_filter: None,
    ///     betterleaks_secret_group: None,
    ///     vectorscan_compatible: true,
    ///     fallbacks: Vec::new(),
    ///     examples: vec![],
    ///     negative_examples: vec![],
    ///     references: vec![],
    ///     min_entropy: 0.0,
    ///     confidence: Default::default(),
    ///     visible: true,
    ///     validation: None,
    ///     revocation: None,
    ///     depends_on_rule: vec![],
    ///     pattern_requirements: None,
    ///     tls_mode: None,
    ///     authoritative: true,
    /// };
    /// assert_eq!(r.as_anchored_regex().unwrap().as_str(), r"hello\s*world$");
    /// ```
    pub fn as_anchored_regex(&self) -> Result<regex::bytes::Regex> {
        Self::build_regex(&format!("{}$", self.uncommented_pattern()))
    }

    /// Compile a regex constrained to the actual end of a candidate window.
    /// Grouping preserves alternatives; `\z` remains exact in multiline mode.
    pub fn as_endpoint_regex(&self) -> Result<regex::bytes::Regex> {
        Self::build_regex(&format!(r"(?:{})\z", self.uncommented_pattern()))
    }

    /// Computes a content-based fingerprint of the rule's pattern.
    pub fn finding_sha1_fingerprint(&self) -> String {
        let hash = xxh3_64(self.pattern.as_bytes());
        format!("{:x}", hash)
    }

    /// Serializes the rule syntax to JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Serialization of rule syntax should succeed")
    }

    /// Loads rule syntax definitions from a YAML file.
    pub fn from_yaml_file<P: AsRef<Path>>(path: P) -> Result<Vec<Self>> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RuleSyntaxDocument {
            Sequence(Vec<RuleSyntax>),
            Mapped { rules: Vec<RuleSyntax> },
        }

        let parsed: RuleSyntaxDocument = serde_yaml::from_str(&contents).map_err(|e| {
            let context = e.location().map_or(String::new(), |loc| {
                format!(" at line {} column {}", loc.line(), loc.column())
            });
            anyhow!("Failed to parse YAML from {}{}: {}", path.display(), context, e)
        })?;

        Ok(match parsed {
            RuleSyntaxDocument::Sequence(rules) => rules,
            RuleSyntaxDocument::Mapped { rules } => rules,
        })
    }
}

/// A rule combines its syntactic definition with computed metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Rule {
    pub syntax: RuleSyntax,
    finding_sha1_fingerprint: String,
    min_entropy: f32,
    visible: bool,
    #[serde(skip, default = "default_runtime_minimum_confidence")]
    runtime_minimum_confidence: Confidence,
    #[serde(skip)]
    runtime_dependency_helper: bool,
    #[serde(skip)]
    path_regex: OnceLock<(String, Option<Regex>)>,
    #[serde(skip)]
    keyword_regex: OnceLock<(Vec<String>, Option<regex::bytes::Regex>)>,
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.syntax == other.syntax
            && self.finding_sha1_fingerprint == other.finding_sha1_fingerprint
            && self.min_entropy == other.min_entropy
            && self.visible == other.visible
            && self.runtime_minimum_confidence == other.runtime_minimum_confidence
            && self.runtime_dependency_helper == other.runtime_dependency_helper
    }
}

fn default_runtime_minimum_confidence() -> Confidence {
    Confidence::Low
}

impl Rule {
    /// Constructs a new rule from its syntax.
    pub fn new(syntax: RuleSyntax) -> Self {
        Self {
            finding_sha1_fingerprint: syntax.finding_sha1_fingerprint(),
            min_entropy: syntax.min_entropy,
            visible: syntax.visible,
            runtime_minimum_confidence: Confidence::Low,
            runtime_dependency_helper: false,
            path_regex: OnceLock::new(),
            keyword_regex: OnceLock::new(),
            syntax,
        }
    }

    /// Returns a reference to the rule's syntax.
    pub fn syntax(&self) -> &RuleSyntax {
        &self.syntax
    }

    /// Return whether this source fragment meets the rule's optional keyword gate.
    pub fn matches_keywords(&self, bytes: &[u8]) -> bool {
        // Most captures contain their own provider keyword. Keep that short check
        // cheap; searching a whole source byte by byte for every candidate is not.
        if bytes.len() <= 256 || self.syntax.keywords.is_empty() {
            return self.matches_keywords_uncached(bytes);
        }
        let (keywords, ascii_regex) = self.keyword_regex.get_or_init(|| {
            let patterns = self
                .syntax
                .keywords
                .iter()
                .filter(|keyword| keyword.is_ascii())
                .map(|keyword| regex::escape(keyword))
                .collect::<Vec<_>>();
            let compiled = (!patterns.is_empty())
                .then(|| {
                    regex::bytes::RegexBuilder::new(&patterns.join("|"))
                        .case_insensitive(true)
                        .unicode(false)
                        .build()
                        .ok()
                })
                .flatten();
            (self.syntax.keywords.clone(), compiled)
        });
        if keywords == &self.syntax.keywords
            && let Some(regex) = ascii_regex
        {
            // Preserve the existing Unicode lowercase/lossy-UTF-8 semantics rather
            // than letting regex Unicode folding widen ASCII-only keyword matches.
            return regex.is_match(bytes)
                || keywords.iter().filter(|keyword| !keyword.is_ascii()).any(|keyword| {
                    String::from_utf8_lossy(bytes).to_lowercase().contains(&keyword.to_lowercase())
                });
        }
        // Public syntax can change after the cache is initialized. Compilation
        // limits and mutated keywords must retain the original matching behavior.
        self.matches_keywords_uncached(bytes)
    }

    fn matches_keywords_uncached(&self, bytes: &[u8]) -> bool {
        self.syntax.keywords.is_empty()
            || self.syntax.keywords.iter().any(|keyword| {
                if keyword.is_empty() {
                    return true;
                }
                if keyword.is_ascii() {
                    bytes
                        .windows(keyword.len())
                        .any(|window| window.eq_ignore_ascii_case(keyword.as_bytes()))
                } else {
                    String::from_utf8_lossy(bytes).to_lowercase().contains(&keyword.to_lowercase())
                }
            })
    }

    /// Returns the JSON representation of the rule's syntax.
    pub fn json_syntax(&self) -> String {
        self.syntax.to_json()
    }

    /// Returns the rule's computed fingerprint.
    pub fn finding_sha1_fingerprint(&self) -> &str {
        &self.finding_sha1_fingerprint
    }

    /// Returns the human-readable name of the rule.
    pub fn name(&self) -> &str {
        &self.syntax.name
    }

    /// Returns the unique identifier of the rule.
    pub fn id(&self) -> &str {
        &self.syntax.id
    }

    /// Returns the rule's minimum entropy requirement.
    pub fn min_entropy(&self) -> f32 {
        self.min_entropy
    }

    /// Updates the rule's minimum entropy value.
    ///
    /// Returns an error if the new value is negative.
    pub fn set_entropy(&mut self, new_entropy: f32) -> Result<()> {
        if new_entropy < 0.0 {
            return Err(anyhow!("Entropy value cannot be negative"));
        }
        self.min_entropy = new_entropy;
        self.syntax.min_entropy = new_entropy;
        Ok(())
    }

    /// Returns whether the rule is visible.
    pub fn visible(&self) -> bool {
        self.visible
    }

    /// Returns the confidence level of the rule.
    pub fn confidence(&self) -> Confidence {
        self.syntax.confidence
    }

    /// Configure scan-time confidence filtering after rule selection has resolved helpers.
    pub fn set_runtime_confidence_filter(
        &mut self,
        minimum_confidence: Confidence,
        dependency_helper: bool,
    ) {
        self.runtime_minimum_confidence = minimum_confidence;
        self.runtime_dependency_helper = dependency_helper;
    }

    /// Return whether this effective confidence should be retained for matching.
    pub fn accepts_effective_confidence(&self, confidence: Confidence) -> bool {
        self.runtime_dependency_helper || self.reports_effective_confidence(confidence)
    }

    /// Return whether this effective confidence meets the user's reporting threshold.
    pub fn reports_effective_confidence(&self, confidence: Confidence) -> bool {
        confidence.is_at_least(&self.runtime_minimum_confidence)
    }

    /// Return whether this rule was included to support another selected rule.
    pub fn is_runtime_dependency_helper(&self) -> bool {
        self.runtime_dependency_helper
    }

    /// Return the scan-time minimum confidence configured by the rule loader.
    pub fn runtime_minimum_confidence(&self) -> Confidence {
        self.runtime_minimum_confidence
    }

    /// Keep a dependency match available for association without reporting it as a finding.
    pub fn suppress_runtime_reporting(&mut self) {
        self.visible = false;
        self.syntax.visible = false;
    }

    /// Returns the character requirements for this rule, if any.
    pub fn pattern_requirements(&self) -> Option<&PatternRequirements> {
        self.syntax.pattern_requirements.as_ref()
    }

    /// Return whether this rule is eligible for the supplied source path.
    pub fn matches_path(&self, path: &str) -> bool {
        let Some(pattern) = self.syntax.path.as_deref() else {
            return true;
        };
        let (cached_pattern, regex) =
            self.path_regex.get_or_init(|| (pattern.to_owned(), Regex::new(pattern).ok()));
        if cached_pattern != pattern {
            // Syntax is public and can be changed after the cache is initialized.
            // Preserve that behavior rather than using a stale compiled restriction.
            return self.syntax.matches_path(path);
        }
        regex.as_ref().is_some_and(|regex| regex.is_match(path))
    }

    /// Return the imported Betterleaks filter expression, if present.
    pub fn betterleaks_filter(&self) -> Option<&BetterleaksExpr> {
        self.syntax.betterleaks_filter()
    }

    /// Return the Betterleaks capture selector, if this is an imported Betterleaks rule.
    pub fn betterleaks_secret_group(&self) -> Option<usize> {
        self.syntax.betterleaks_secret_group()
    }

    /// Return whether Vectorscan is used as the rule's candidate prefilter.
    pub fn vectorscan_compatible(&self) -> bool {
        self.syntax.vectorscan_compatible()
    }

    /// Returns the TLS mode for this rule, if specified.
    pub fn tls_mode(&self) -> Option<TlsMode> {
        self.syntax.tls_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_path_regex_is_cached_without_changing_serialization_or_equality() {
        let mut syntax = RuleSyntax::new("acme.path", "Path fixture", "token");
        syntax.path = Some(r"(?i)\.pem$".into());
        let rule = Rule::new(syntax);
        let cold = rule.clone();
        let serialized = serde_json::to_value(&rule).unwrap();
        assert!(rule.path_regex.get().is_none());
        for _ in 0..1000 {
            assert!(rule.matches_path("private.PEM"));
            assert!(!rule.matches_path("source.rs"));
        }
        let (pattern, compiled) = rule.path_regex.get().expect("path regex was cached");
        assert_eq!(pattern, r"(?i)\.pem$");
        assert!(compiled.is_some());
        assert_eq!(rule, cold);
        assert_eq!(rule, rule.clone());
        assert_eq!(serde_json::to_value(&rule).unwrap(), serialized);
        let restored: Rule = serde_json::from_value(serialized).unwrap();
        assert_eq!(rule, restored);
        assert!(restored.path_regex.get().is_none());
        assert!(restored.matches_path("private.pem"));
    }

    #[test]
    fn runtime_path_cache_preserves_invalid_and_mutated_path_restrictions() {
        let mut rule = Rule::new(RuleSyntax::new("acme.path", "Path fixture", "token"));
        assert!(rule.matches_path("anywhere"));
        assert!(rule.path_regex.get().is_none());
        rule.syntax.path = Some("[".into());
        assert!(!rule.matches_path("anywhere"));
        assert!(!rule.matches_path("another"));
        assert!(rule.path_regex.get().unwrap().1.is_none());
        rule.syntax.path = Some(r"\.key$".into());
        assert!(rule.matches_path("private.key"));
        assert!(!rule.matches_path("source.rs"));
        rule.syntax.path = None;
        assert!(rule.matches_path("anywhere"));
    }

    #[test]
    fn candidate_keywords_support_ascii_and_unicode_case_folding() {
        let mut syntax = RuleSyntax::new("acme.keyword", "Keyword", "token");
        assert!(Rule::new(syntax.clone()).matches_keywords(b""));
        syntax.keywords = vec!["Provider".into(), "CAFÉ".into()];
        let rule = Rule::new(syntax);
        assert!(rule.matches_keywords(b"pRoViDeR"));
        assert!(rule.matches_keywords("café".as_bytes()));
        assert!(!rule.matches_keywords(b"unrelated"));
    }

    #[test]
    fn large_source_keyword_search_preserves_literal_and_case_folding_semantics() {
        for keywords in [
            vec!["Provider", "CAFÉ"],
            vec!["[literal]+.*", "k"],
            vec!["�", "ASCII"],
            vec![""],
            vec!["CAFÉ"],
        ] {
            let mut syntax = RuleSyntax::new("acme.keyword", "Keyword", "token");
            syntax.keywords = keywords.into_iter().map(str::to_owned).collect();
            let rule = Rule::new(syntax);
            for value in [
                b"pRoViDeR".as_slice(),
                "café".as_bytes(),
                b"[LITERAL]+.*",
                b"LITERALxxxxx",
                "K".as_bytes(),
                b"\xffASCII",
                b"\xff",
                b"unrelated",
            ] {
                let bytes = [vec![b' '; 4096], value.to_vec()].concat();
                assert_eq!(rule.matches_keywords(&bytes), rule.matches_keywords_uncached(&bytes));
            }
        }
    }

    #[test]
    fn runtime_keyword_cache_preserves_serialization_equality_and_mutated_keywords() {
        let mut syntax = RuleSyntax::new("acme.keyword", "Keyword", "token");
        syntax.keywords = vec!["provider".into()];
        let mut rule = Rule::new(syntax);
        let cold = rule.clone();
        let serialized = serde_json::to_value(&rule).unwrap();
        let bytes = [vec![b' '; 4096], b"PROVIDER".to_vec()].concat();
        assert!(rule.matches_keywords(&bytes));
        assert!(rule.keyword_regex.get().unwrap().1.is_some());
        assert_eq!(rule, cold);
        assert_eq!(rule, rule.clone());
        assert_eq!(serde_json::to_value(&rule).unwrap(), serialized);
        let restored: Rule = serde_json::from_value(serialized).unwrap();
        assert!(restored.keyword_regex.get().is_none());
        assert!(restored.matches_keywords(&bytes));
        rule.syntax.keywords = vec!["replacement".into()];
        assert!(!rule.matches_keywords(&bytes));
        let replacement = [vec![b' '; 4096], b"REPLACEMENT".to_vec()].concat();
        assert!(rule.matches_keywords(&replacement));
        rule.syntax.keywords.clear();
        assert!(rule.matches_keywords(&bytes));
    }

    #[test]
    fn custom_yaml_betterleaks_programs_accept_source_and_round_trip_as_ast() {
        let yaml = r#"
type: Betterleaks
content:
  expression: 'let r = http.get("https://example.invalid"); r.status == 200 ? {"result": "valid"} : validate.unknown(r)'
  analyze: 'analysis.capabilities({"read": true})'
"#;
        let validation: Validation = serde_yaml::from_str(yaml).unwrap();
        let Validation::Betterleaks(program) = &validation else { panic!("wrong validator") };
        assert!(matches!(program.expression, BetterleaksExpr::VariableDeclarator { .. }));
        assert!(program.analyze.is_some());
        let ast_yaml = serde_yaml::to_string(&validation).unwrap();
        assert_eq!(serde_yaml::from_str::<Validation>(&ast_yaml).unwrap(), validation);
        let revocation: Revocation = serde_yaml::from_str("type: Betterleaks\ncontent:\n  expression: 'let r = http.delete(\"https://example.invalid\"); r.status == 204 ? {\"result\": \"revoked\"} : revoke.unknown(r)'\n").unwrap();
        assert!(matches!(revocation, Revocation::Betterleaks(_)));
        assert!(
            serde_yaml::from_str::<Validation>(
                "type: Betterleaks\ncontent:\n  expression: 'let broken ='\n"
            )
            .is_err()
        );
    }

    #[test]
    fn http_url_strings_and_fallback_lists_round_trip_without_changing_other_request_fields() {
        for url in [
            serde_json::json!("https://primary.example/identity"),
            serde_json::json!([
                "https://primary.example/identity",
                "https://secondary.example/identity",
                "{{ THIRD_ENDPOINT }}/identity"
            ]),
        ] {
            let definition = serde_json::json!({
                "method": "POST", "url": url,
                "headers": {"Authorization": "Bearer {{ TOKEN }}"},
                "body": "{{ TOKEN }}", "multipart": null,
                "response_matcher": [{"type": "StatusMatch", "status": [200],
                    "match_all_status": false, "negative": false}],
                "response_is_html": true
            });
            let request: HttpRequest = serde_json::from_value(definition.clone()).unwrap();
            assert_eq!(serde_json::to_value(&request).unwrap(), definition);
            let yaml = serde_yaml::to_string(&request).unwrap();
            assert_eq!(serde_yaml::from_str::<HttpRequest>(&yaml).unwrap(), request);
        }
    }

    #[test]
    fn http_url_lists_reject_empty_non_string_and_blank_endpoints() {
        for url in [
            serde_json::json!([]),
            serde_json::json!(["https://primary.example", "  "]),
            serde_json::json!(["https://primary.example", 42]),
        ] {
            assert!(
                serde_json::from_value::<HttpRequest>(serde_json::json!({
                    "method": "GET", "url": url
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn http_url_list_with_one_endpoint_preserves_scalar_request_behavior() {
        let request: HttpRequest =
            serde_yaml::from_str("method: GET\nurl:\n  - https://primary.example/identity\n")
                .unwrap();
        assert_eq!(request.url, "https://primary.example/identity");
        assert!(request.fallback_urls.is_empty());
        assert_eq!(request.urls().collect::<Vec<_>>(), ["https://primary.example/identity"]);
        assert!(serde_json::to_value(&request).unwrap()["url"].is_string());
    }
    use regex::bytes::Regex as BytesRegex;

    #[test]
    fn http_revocation_rejects_oauth2_auth_during_deserialization() {
        let password = "operator-password-secret";
        let client_secret = "operator-client-secret";
        for auth in [
            serde_json::json!({"oauth2": {
                "token_endpoint": "https://idp.example.com/token",
                "ropc": {"username": "operator", "password": password,
                         "client_id": "scanner", "client_secret": client_secret}
            }}),
            // Malformed auth must be rejected without reporting any of its values.
            serde_json::json!({"oauth2": {"ropc": {
                "password": [password], "client_secret": {"secret": client_secret}
            }}}),
        ] {
            let definition = serde_json::json!({"type": "Http", "content": {
                "auth": auth,
                "request": {"method": "DELETE", "url": "https://api.example.com/token",
                    "response_matcher": [{"type": "StatusMatch", "status": [204]}]}
            }});
            let json_error = serde_json::from_value::<Revocation>(definition.clone()).unwrap_err();
            let yaml = serde_yaml::to_string(&definition).unwrap();
            let yaml_error = serde_yaml::from_str::<Revocation>(&yaml).unwrap_err();
            for error in [json_error.to_string(), yaml_error.to_string()] {
                assert!(error.contains("OAuth2 auth is supported for validation only"));
                assert!(!error.contains(password));
                assert!(!error.contains(client_secret));
            }
            let document = serde_json::json!({"rules": [{
                "id": "acme.revocation-auth", "name": "Revocation auth fixture",
                "pattern": "(synthetic-secret)", "revocation": definition
            }]});
            let yaml = serde_yaml::to_string(&document).unwrap();
            let error = crate::Rules::from_paths_and_contents(
                [(Path::new("revocation-auth.yml"), yaml.as_bytes())],
                Confidence::Low,
            )
            .err()
            .expect("unsupported auth must fail during rule loading");
            assert!(!error.to_string().contains(password));
            assert!(!error.to_string().contains(client_secret));
        }
    }

    #[test]
    fn supported_revocation_definitions_preserve_defaults_and_round_trip() {
        for definition in [
            serde_json::json!({"type": "AWS"}),
            serde_json::json!({"type": "GCP"}),
            serde_json::json!({"type": "Http", "content": {
                "request": {"method": "DELETE", "url": "https://api.example.com/token"}
            }}),
            serde_json::json!({"type": "Http", "content": {
                "auth": null,
                "request": {"method": "DELETE", "url": "https://api.example.com/token"}
            }}),
            serde_json::json!({"type": "HttpMultiStep", "content": {"steps": [{
                "request": {"method": "DELETE", "url": "https://api.example.com/token"}
            }]}}),
        ] {
            let revocation: Revocation = serde_json::from_value(definition).unwrap();
            let serialized = serde_json::to_value(&revocation).unwrap();
            assert_eq!(serde_json::from_value::<Revocation>(serialized).unwrap(), revocation);
            let yaml = serde_yaml::to_string(&revocation).unwrap();
            assert_eq!(serde_yaml::from_str::<Revocation>(&yaml).unwrap(), revocation);
            if let Revocation::Http(http) = revocation {
                assert!(http.auth.is_none());
                assert!(http.multipart.is_none());
                assert!(http.request.headers.is_empty());
                assert!(!http.request.response_is_html);
            }
        }
    }

    #[test]
    fn oauth2_inspection_redacts_literals_without_changing_lossless_serialization() {
        for credentials in [
            serde_json::json!({"username": "operator-user-secret", "password": "operator-password-secret",
                "client_id": "scanner", "client_secret": "operator-client-secret"}),
            serde_json::json!({"username_env": "KF_OPERATOR_USERNAME", "password_env": "KF_OPERATOR_PASSWORD",
                "client_id": "scanner", "client_secret_env": "KF_OPERATOR_CLIENT_SECRET"}),
        ] {
            let validation: Validation = serde_json::from_value(serde_json::json!({
                "type": "Http", "content": {
                    "auth": {"oauth2": {"token_endpoint": "https://idp.example.com/token", "ropc": credentials}},
                    "request": {"method": "GET", "url": "https://verifier.example.com/verify"}
                }
            })).unwrap();
            let original = serde_json::to_value(&validation).unwrap();
            let inspected = validation.redacted_for_inspection();
            let redacted = serde_json::to_value(&inspected).unwrap();
            let credentials = &redacted["content"]["auth"]["oauth2"]["ropc"];
            for field in ["username", "password", "client_secret"] {
                let expected = if original["content"]["auth"]["oauth2"]["ropc"][field].is_null() {
                    serde_json::Value::Null
                } else {
                    serde_json::json!("[REDACTED]")
                };
                assert_eq!(credentials[field], expected);
            }
            for field in ["username_env", "password_env", "client_secret_env", "client_id", "scope"]
            {
                assert_eq!(
                    credentials[field],
                    original["content"]["auth"]["oauth2"]["ropc"][field]
                );
            }
            assert_eq!(redacted["content"]["auth"]["oauth2"]["token_header"], "Authorization");
            assert_eq!(serde_json::to_value(&validation).unwrap(), original);
            assert_eq!(serde_json::from_value::<Validation>(original).unwrap(), validation);
        }
    }

    #[test]
    fn test_pattern_requirements_digits() {
        let reqs = PatternRequirements {
            min_digits: Some(2),
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has 3 digits
        assert!(matches!(reqs.validate(b"abc123def", None, true), PatternValidationResult::Passed));

        // Should fail: only 1 digit
        assert!(matches!(reqs.validate(b"abc1def", None, true), PatternValidationResult::Failed));

        // Should fail: no digits
        assert!(matches!(reqs.validate(b"abcdef", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_checksum() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: None,
            checksum: Some(ChecksumRequirement {
                actual: ChecksumActual {
                    template: "{{ MATCH | suffix: 6 }}".to_string(),
                    requires_capture: Some("checksum".to_string()),
                },
                expected: "{{ BODY | crc32 | base62: 6 }}".to_string(),
                skip_if_missing: true,
            }),
        };

        let token = b"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";
        let regex =
            BytesRegex::new(r"(?x) ghp_(?P<body>[A-Za-z0-9]{30})(?P<checksum>[A-Za-z0-9]{6})")
                .unwrap();
        let captures = regex.captures(token).expect("token should match");
        assert!(matches!(
            reqs.validate(
                token,
                Some(PatternRequirementContext {
                    regex: &regex,
                    captures: &captures,
                    full_match: token
                }),
                true
            ),
            PatternValidationResult::Passed
        ));

        let mut invalid = token.to_vec();
        *invalid.last_mut().unwrap() = b'0';
        let captures_invalid =
            regex.captures(&invalid).expect("invalid token should still match pattern");
        assert!(matches!(
            reqs.validate(
                &invalid,
                Some(PatternRequirementContext {
                    regex: &regex,
                    captures: &captures_invalid,
                    full_match: &invalid,
                }),
                true
            ),
            PatternValidationResult::FailedChecksum { .. }
        ));

        let legacy = b"ghp_legacy_token";
        assert!(matches!(reqs.validate(legacy, None, true), PatternValidationResult::Passed));
    }

    #[test]
    fn test_pattern_requirements_uppercase() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: Some(2),
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has 3 uppercase
        assert!(matches!(reqs.validate(b"ABCdef", None, true), PatternValidationResult::Passed));

        // Should fail: only 1 uppercase
        assert!(matches!(reqs.validate(b"Adef", None, true), PatternValidationResult::Failed));

        // Should fail: no uppercase
        assert!(matches!(reqs.validate(b"abcdef", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_lowercase() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: Some(2),
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has 3 lowercase
        assert!(matches!(reqs.validate(b"ABCdef", None, true), PatternValidationResult::Passed));

        // Should fail: only 1 lowercase
        assert!(matches!(reqs.validate(b"ABCd", None, true), PatternValidationResult::Failed));

        // Should fail: no lowercase
        assert!(matches!(reqs.validate(b"ABC123", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_special_chars() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: Some(2),
            special_chars: None, // uses default
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has 2 special chars
        assert!(matches!(reqs.validate(b"abc!@def", None, true), PatternValidationResult::Passed));

        // Should fail: only 1 special char
        assert!(matches!(reqs.validate(b"abc!def", None, true), PatternValidationResult::Failed));

        // Should fail: no special chars
        assert!(matches!(reqs.validate(b"abcdef", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_custom_special_chars() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: Some(2),
            special_chars: Some("$%^".to_string()),
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has 2 custom special chars
        assert!(matches!(reqs.validate(b"abc$%def", None, true), PatternValidationResult::Passed));

        // Should fail: has special chars but not the custom ones
        assert!(matches!(reqs.validate(b"abc!@def", None, true), PatternValidationResult::Failed));

        // Should fail: only 1 custom special char
        assert!(matches!(reqs.validate(b"abc$def", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_combined() {
        let reqs = PatternRequirements {
            min_digits: Some(1),
            min_uppercase: Some(1),
            min_lowercase: Some(1),
            min_special_chars: Some(1),
            special_chars: None,
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: has all requirements
        assert!(matches!(reqs.validate(b"Abc1!", None, true), PatternValidationResult::Passed));

        // Should fail: missing digit
        assert!(matches!(reqs.validate(b"Abc!", None, true), PatternValidationResult::Failed));

        // Should fail: missing uppercase
        assert!(matches!(reqs.validate(b"abc1!", None, true), PatternValidationResult::Failed));

        // Should fail: missing lowercase
        assert!(matches!(reqs.validate(b"ABC1!", None, true), PatternValidationResult::Failed));

        // Should fail: missing special
        assert!(matches!(reqs.validate(b"Abc1", None, true), PatternValidationResult::Failed));
    }

    #[test]
    fn test_pattern_requirements_ignore_if_contains() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: Some(vec!["test".to_string(), "Demo".to_string()]),
            checksum: None,
        };

        // Should fail: contains "test" (case-insensitive)
        assert!(matches!(
            reqs.validate(b"MyTestToken", None, true),
            PatternValidationResult::IgnoredBySubstring { .. }
        ));

        // Should fail: contains "demo" (case-insensitive)
        assert!(matches!(
            reqs.validate(b"example-demo-value", None, true),
            PatternValidationResult::IgnoredBySubstring { .. }
        ));

        // Should pass: does not contain excluded words
        assert!(matches!(
            reqs.validate(b"example-value", None, true),
            PatternValidationResult::Passed
        ));
    }

    #[test]
    fn test_pattern_requirements_ignore_if_contains_ignores_empty_entries() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: Some(vec![" ".to_string(), "".to_string(), "BLOCK".to_string()]),
            checksum: None,
        };

        // Should fail only when non-empty exclusion matches
        assert!(matches!(
            reqs.validate(b"needs-blocking", None, true),
            PatternValidationResult::IgnoredBySubstring { .. }
        ));
        assert!(matches!(reqs.validate(b"allowed", None, true), PatternValidationResult::Passed));
    }

    #[test]
    fn test_pattern_requirements_ignore_if_contains_can_be_disabled() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: Some(vec!["ignoreme".to_string()]),
            checksum: None,
        };

        // With ignoring enabled, the match is skipped
        assert!(matches!(
            reqs.validate(b"value-ignoreme", None, true),
            PatternValidationResult::IgnoredBySubstring { .. }
        ));

        // With ignoring disabled, the same input passes requirements
        assert!(matches!(
            reqs.validate(b"value-ignoreme", None, false),
            PatternValidationResult::Passed
        ));
    }

    #[test]
    fn test_pattern_requirements_none() {
        let reqs = PatternRequirements {
            min_digits: None,
            min_uppercase: None,
            min_lowercase: None,
            min_special_chars: None,
            special_chars: None,
            ignore_if_contains: None,
            checksum: None,
        };

        // Should pass: no requirements
        assert!(matches!(reqs.validate(b"anything", None, true), PatternValidationResult::Passed));
        assert!(matches!(reqs.validate(b"123", None, true), PatternValidationResult::Passed));
        assert!(matches!(reqs.validate(b"!@#", None, true), PatternValidationResult::Passed));
    }
}
