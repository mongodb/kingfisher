//! This module defines rule syntax and evaluation types for secret detection.
//!
//! It provides structures and methods to represent validation configurations,
//! HTTP requests for validation, rule syntax (with support for comment stripping),
//! and associated metadata such as confidence and fingerprints.

use std::{
    borrow::Cow, cmp::Ordering, collections::BTreeMap, fmt, hash::Hash, path::Path, str::FromStr,
};

use anyhow::{anyhow, Context, Result};
use lazy_static::lazy_static;
use regex::Regex;
use schemars::{
    gen::SchemaGenerator,
    schema::{Schema, SchemaObject},
    JsonSchema,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

/// Returns false as the default value.
fn default_false() -> bool {
    false
}

/// Returns true as the default value.
fn default_true() -> bool {
    true
}

/// Represents various types of validation that a rule can perform.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
#[serde(tag = "type", content = "content")]
pub enum Validation {
    AWS,
    AzureStorage,
    GCP,
    MongoDB,
    Postgres,
    Raw(String),
    Http(HttpValidation),
}

/// Specifies that a rule depends on a variable from another rule.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct DependsOnRule {
    pub rule_id: String,
    pub variable: String,
}

/// Configuration for HTTP validation. This contains a request configuration
/// and an optional multipart configuration.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpValidation {
    pub request: HttpRequest,
    pub multipart: Option<MultipartConfig>,
}

/// Configuration for an HTTP request used for validation.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub response_matcher: Vec<ResponseMatcher>,
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
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Medium
    }
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
        match (self, other) {
            (Confidence::High, _) => true,
            (Confidence::Medium, Confidence::Low) | (Confidence::Medium, Confidence::Medium) => {
                true
            }
            (Confidence::Low, Confidence::Low) => true,
            _ => false,
        }
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
    fn schema_name() -> String {
        "Confidence".to_string()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        let mut schema = SchemaObject::default();
        schema.enum_values = Some(vec![
            serde_json::to_value("Low").unwrap(),
            serde_json::to_value("Medium").unwrap(),
            serde_json::to_value("High").unwrap(),
        ]);
        Schema::Object(schema)
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
    /// Optional dependencies on other rules.
    #[serde(default)]
    pub depends_on_rule: Vec<Option<DependsOnRule>>,
    /// Whether matches should always be considered validated.
    #[serde(default)]
    pub prevalidated: bool,
}

lazy_static! {
    /// Regex pattern used to remove vectorscan-style comments from rule patterns.
    pub static ref RULE_COMMENTS_PATTERN: Regex = Regex::new(
        r"(?m)(\(\?#[^)]*\))|(\s\#[\sa-zA-Z]*$)"
    ).expect("comment-stripping regex should compile");
}

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
    ///     depends_on_rule: vec![],
    /// };
    /// assert_eq!(r.as_anchored_regex().unwrap().as_str(), r"hello\s*world$");
    /// ```
    pub fn as_anchored_regex(&self) -> Result<regex::bytes::Regex> {
        Self::build_regex(&format!("{}$", self.uncommented_pattern()))
    }

    /// Computes a content-based fingerprint of the rule's pattern.
    pub fn finding_sha1_fingerprint(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(self.pattern.as_bytes());
        format!("{:x}", hasher.finalize())
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
        serde_yaml::from_str(&contents).map_err(|e| {
            let context = e.location().map_or(String::new(), |loc| {
                format!(" at line {} column {}", loc.line(), loc.column())
            });
            anyhow!("Failed to parse YAML from {}{}: {}", path.display(), context, e)
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
}
