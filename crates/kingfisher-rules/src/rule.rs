//! This module defines rule syntax and evaluation types for secret detection.
//!
//! It provides structures and methods to represent validation configurations,
//! HTTP requests for validation, rule syntax (with support for comment stripping),
//! and associated metadata such as confidence and fingerprints.

use std::{
    borrow::Cow, cmp::Ordering, collections::BTreeMap, fmt, hash::Hash, path::Path, str::FromStr,
    sync::LazyLock,
};

use anyhow::{Context, Result, anyhow};
use liquid::{
    ParserBuilder,
    model::{KString, Value},
    object,
};
use regex::Regex;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use tracing::debug;
// use sha1::{Digest, Sha1};
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

    /// Accept self-signed or unknown CA certificates, but still enforce:
    /// - Hostname must match certificate's CN/SAN
    /// - Certificate must not be expired
    /// - TLS 1.2 or higher required
    ///
    /// Useful for database connections (PostgreSQL, MySQL, MongoDB) that often use
    /// self-signed certificates or private CAs (e.g., Amazon RDS).
    Lax,

    /// Disable all TLS certificate validation. Use with extreme caution.
    Off,
}

/// Represents various types of validation that a rule can perform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Validation {
    AWS,
    AzureStorage,
    Coinbase,
    GCP,
    MongoDB,
    MySQL,
    Postgres,
    Jdbc,
    JWT,
    Raw(String),
    Http(HttpValidation),
    Grpc(GrpcValidation),
}

/// Represents revocation actions that a rule can perform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Revocation {
    AWS,
    GCP,
    Http(HttpValidation),
    /// Multi-step HTTP revocation (up to 2 steps).
    /// Some services require looking up an ID before deletion.
    HttpMultiStep(HttpMultiStepRevocation),
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
    /// Example: "$.data.id" or "$.items[0].token_id"
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
    pub rule_id: String,
    pub variable: String,
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
                    globals.insert(KString::from_ref(name), Value::scalar(value.clone()));
                    globals.insert(
                        KString::from_string(name.to_ascii_uppercase()),
                        Value::scalar(value),
                    );
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
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub response_matcher: Option<Vec<ResponseMatcher>>,
    #[serde(default)]
    pub multipart: Option<MultipartConfig>,
    // allow HTML only when explicitly set true
    #[serde(default = "default_false")]
    pub response_is_html: bool,
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
    /// };
    /// assert_eq!(r.as_anchored_regex().unwrap().as_str(), r"hello\s*world$");
    /// ```
    pub fn as_anchored_regex(&self) -> Result<regex::bytes::Regex> {
        Self::build_regex(&format!("{}$", self.uncommented_pattern()))
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
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Rule {
    pub syntax: RuleSyntax,
    finding_sha1_fingerprint: String,
    min_entropy: f32,
    visible: bool,
}

impl Rule {
    /// Constructs a new rule from its syntax.
    pub fn new(syntax: RuleSyntax) -> Self {
        Self {
            finding_sha1_fingerprint: syntax.finding_sha1_fingerprint(),
            min_entropy: syntax.min_entropy,
            visible: syntax.visible,
            syntax,
        }
    }

    /// Returns a reference to the rule's syntax.
    pub fn syntax(&self) -> &RuleSyntax {
        &self.syntax
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

    /// Returns the character requirements for this rule, if any.
    pub fn pattern_requirements(&self) -> Option<&PatternRequirements> {
        self.syntax.pattern_requirements.as_ref()
    }

    /// Returns the TLS mode for this rule, if specified.
    pub fn tls_mode(&self) -> Option<TlsMode> {
        self.syntax.tls_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::bytes::Regex as BytesRegex;

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
