use std::sync::Arc;

use http::StatusCode;
use kingfisher_core::ValidationOutcome;
use schemars::JsonSchema;
use serde::Serialize;
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    blob::BlobId,
    location::{Location, LocationMapping, OffsetSpan, SourcePoint, SourceSpan},
    rules::rule::Rule,
    validation_body::{self, ValidationResponseBody},
};

use super::{
    BlobMatch,
    captures::{SerializableCapture, SerializableCaptures},
};

use kingfisher_scanner::primitives::compute_finding_fingerprint;

/// Select the capture used by externally persisted finding fingerprints.
///
/// Imported Betterleaks rules serialize their selected secret as `TOKEN`. Rules without
/// Betterleaks capture metadata retain the historical second-entry fallback.
fn external_fingerprint_value(rule: &Rule, captures: &SerializableCaptures) -> &'static str {
    let capture = if rule.betterleaks_secret_group().is_some() {
        captures
            .captures
            .iter()
            .find(|capture| capture.name.is_some_and(|name| name.eq_ignore_ascii_case("TOKEN")))
            .or_else(|| captures.captures.first())
    } else {
        captures.captures.get(1).or_else(|| captures.captures.first())
    };
    capture.map_or("", SerializableCapture::raw_value)
}

// -------------------------------------------------------------------------------------------------
// OwnedBlobMatch
// -------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub struct OwnedBlobMatch {
    pub rule: Arc<Rule>,
    pub blob_id: BlobId,
    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,
    pub matching_input_offset_span: OffsetSpan,
    pub captures: SerializableCaptures,
    pub validation_response_body: ValidationResponseBody,
    pub validation_response_status: StatusCode,
    pub validation_success: bool,
    pub validation_outcome: ValidationOutcome,
    pub calculated_entropy: f32,
    pub is_base64: bool,
    /// Variables captured from dependent rules (from depends_on_rule).
    /// Maps variable name (uppercase) to captured value.
    pub dependent_captures: std::collections::BTreeMap<String, String>,
}

impl OwnedBlobMatch {
    /// Refresh the semantic outcome after legacy validation fields change.
    pub fn refresh_validation_outcome(&mut self) {
        if !self.rule.syntax().is_authoritative() {
            self.validation_success = false;
            self.validation_outcome = ValidationOutcome::NotAttempted;
            return;
        }
        if matches!(
            self.validation_outcome,
            ValidationOutcome::LocallyDerived | ValidationOutcome::InvalidMaterial
        ) {
            return;
        }
        let assumed = matches!(
            self.rule.syntax().validation.as_ref(),
            Some(crate::rules::rule::Validation::Assumed)
        );
        self.validation_outcome = ValidationOutcome::from_legacy(
            assumed,
            self.validation_success,
            self.validation_response_status.as_u16(),
        );
    }

    pub fn convert_match_to_owned_blobmatch(m: &Match, rule: Arc<Rule>) -> OwnedBlobMatch {
        OwnedBlobMatch {
            rule,
            blob_id: m.blob_id,
            finding_fingerprint: m.finding_fingerprint,
            // matching_input: m.snippet.matching.0.to_vec(),
            matching_input_offset_span: m.location.offset_span,
            captures: m.groups.clone(),
            validation_response_body: m.validation_response_body.clone(),
            validation_response_status: StatusCode::from_u16(m.validation_response_status)
                .unwrap_or(StatusCode::CONTINUE),
            validation_success: m.validation_success,
            validation_outcome: m.validation_outcome,
            calculated_entropy: m.calculated_entropy,
            is_base64: m.is_base64,
            dependent_captures: m.dependent_captures.clone(),
        }
    }

    pub fn from_blob_match(blob_match: BlobMatch) -> Self {
        let finding_value = external_fingerprint_value(&blob_match.rule, &blob_match.captures);

        let mut owned_blob_match = OwnedBlobMatch {
            rule: blob_match.rule,
            blob_id: *blob_match.blob_id,
            matching_input_offset_span: blob_match.matching_input_offset_span,
            captures: blob_match.captures.clone(),
            validation_response_body: blob_match.validation_response_body,
            validation_response_status: blob_match.validation_response_status,
            validation_success: blob_match.validation_success,
            validation_outcome: blob_match.validation_outcome,
            calculated_entropy: blob_match.calculated_entropy,
            finding_fingerprint: 0, //default
            is_base64: blob_match.is_base64,
            dependent_captures: blob_match.dependent_captures,
        };

        // Use blob_id as the file/commit identifier
        let file_or_commit = &blob_match.blob_id.to_string();

        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        owned_blob_match.finding_fingerprint =
            compute_finding_fingerprint(finding_value, file_or_commit, offset_start, offset_end);

        owned_blob_match
    }
}

// -------------------------------------------------------------------------------------------------
// Match
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Match {
    /// The location of the entire matching content
    pub location: Location,

    /// The capture groups
    pub groups: SerializableCaptures, // Store serialized captures

    /// unique identifier of file / blob where this match was found
    pub blob_id: BlobId,

    /// The unique content-based identifier of this match
    pub finding_fingerprint: u64,

    /// The rule that produced this match
    #[serde(skip_serializing)]
    #[schemars(skip)]
    pub rule: Arc<Rule>,

    /// Validation Body
    #[serde(
        default,
        serialize_with = "validation_body::serialize",
        deserialize_with = "validation_body::deserialize"
    )]
    #[schemars(schema_with = "validation_body::schema")]
    pub validation_response_body: ValidationResponseBody,

    /// Validation Status Code
    pub validation_response_status: u16,

    /// Validation Success
    pub validation_success: bool,

    /// Semantic validation outcome. This is authoritative for filtering and reporting.
    #[serde(default)]
    pub validation_outcome: ValidationOutcome,

    /// Validation Success
    pub calculated_entropy: f32,

    pub visible: bool,
    #[serde(default)]
    pub is_base64: bool,

    /// Variables captured from dependent rules (from depends_on_rule).
    /// Maps variable name (uppercase) to captured value.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub dependent_captures: std::collections::BTreeMap<String, String>,
}

impl Match {
    /// Refresh the semantic outcome after applying a cached validation result.
    pub fn refresh_validation_outcome(&mut self) {
        if !self.rule.syntax().is_authoritative() {
            self.validation_success = false;
            self.validation_outcome = ValidationOutcome::NotAttempted;
            return;
        }
        if matches!(
            self.validation_outcome,
            ValidationOutcome::LocallyDerived | ValidationOutcome::InvalidMaterial
        ) {
            return;
        }
        let assumed = matches!(
            self.rule.syntax().validation.as_ref(),
            Some(crate::rules::rule::Validation::Assumed)
        );
        self.validation_outcome = ValidationOutcome::from_legacy(
            assumed,
            self.validation_success,
            self.validation_response_status,
        );
    }

    #[inline]
    pub fn convert_owned_blobmatch_to_match<'a>(
        loc_mapping: Option<&'a LocationMapping<'a>>,
        owned_blob_match: &'a OwnedBlobMatch,
        origin_type: &'a str,
    ) -> Self {
        let offset_span = owned_blob_match.matching_input_offset_span;
        let finding_value_for_fp =
            external_fingerprint_value(&owned_blob_match.rule, &owned_blob_match.captures);

        let source_span =
            loc_mapping.map(|lm| lm.get_source_span(&offset_span)).unwrap_or(SourceSpan {
                start: SourcePoint { line: 0, column: 0 },
                end: SourcePoint { line: 0, column: 0 },
            });
        let offset_start: u64 =
            owned_blob_match.matching_input_offset_span.start.try_into().unwrap();
        let offset_end: u64 = owned_blob_match.matching_input_offset_span.end.try_into().unwrap();

        let finding_fingerprint = compute_finding_fingerprint(
            finding_value_for_fp,
            origin_type, // file_or_commit,
            offset_start,
            offset_end,
        );

        // matching_snippet
        Match {
            rule: owned_blob_match.rule.clone(),
            visible: owned_blob_match.rule.visible().to_owned(),
            location: Location::with_source_span(offset_span, Some(source_span.clone())),
            groups: owned_blob_match.captures.clone(),
            blob_id: owned_blob_match.blob_id,
            finding_fingerprint,
            validation_response_body: owned_blob_match.validation_response_body.clone(),
            validation_response_status: owned_blob_match.validation_response_status.as_u16(),
            validation_success: owned_blob_match.validation_success,
            validation_outcome: owned_blob_match.validation_outcome,
            calculated_entropy: owned_blob_match.calculated_entropy,
            is_base64: owned_blob_match.is_base64,
            dependent_captures: owned_blob_match.dependent_captures.clone(),
        }
    }

    /// Returns the `blob_id` of the match.
    pub fn get_blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub fn finding_id(&self) -> String {
        let mut buffer = Vec::with_capacity(128);
        buffer.extend_from_slice(self.rule.finding_sha1_fingerprint().as_bytes());
        buffer.push(0);
        serde_json::to_writer(&mut buffer, &self.groups)
            .expect("should be able to serialize groups as JSON");
        let mut num = xxh3_64(&buffer);
        // Ensure the number is positive and within i64 range
        num &= 0x7FFF_FFFF_FFFF_FFFF; // Clear the sign bit to make it positive
        // Convert to string
        num.to_string()
    }
}

// -------------------------------------------------------------------------------------------------
// MatcherStats
// -------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct MatcherStats {
    pub blobs_seen: u64,
    pub blobs_scanned: u64,
    pub bytes_seen: u64,
    pub bytes_scanned: u64,
}

impl MatcherStats {
    pub fn update(&mut self, other: &Self) {
        self.blobs_seen += other.blobs_seen;
        self.blobs_scanned += other.blobs_scanned;
        self.bytes_seen += other.bytes_seen;
        self.bytes_scanned += other.bytes_scanned;
    }
}

#[cfg(test)]
mod tests {
    use kingfisher_core::ValidationOutcome;

    use super::*;
    use crate::{
        blob::Blob,
        rules::rule::{Confidence, RuleSyntax},
    };

    const APP_CONFIG_PATTERN: &str = r#"(?i)Endpoint=(?P<azure_appconfig_endpoint>https://[a-z0-9-]+\.azconfig\.io);Id=(?P<azure_appconfig_id>[^;\s'"]{4,80});Secret=([A-Za-z0-9+/]{36,100}={0,2})"#;

    fn app_config_rule(secret_group: Option<usize>) -> Arc<Rule> {
        Arc::new(Rule::new(RuleSyntax {
            name: "Azure App Configuration".into(),
            id: "test.azure-app-configuration".into(),
            pattern: APP_CONFIG_PATTERN.into(),
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: secret_group,
            authoritative: true,
            vectorscan_compatible: true,
            min_entropy: 0.0,
            confidence: Confidence::High,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        }))
    }

    fn app_config_captures(rule: &Rule, secret: &str) -> SerializableCaptures {
        let input = format!("Endpoint=https://demo.azconfig.io;Id=shared-id;Secret={secret}");
        let regex = rule.syntax().as_regex().unwrap();
        let captures = regex.captures(input.as_bytes()).unwrap();
        SerializableCaptures::from_captures_with_secret_group(
            &captures,
            input.as_bytes(),
            &regex,
            rule.betterleaks_secret_group(),
        )
    }

    fn owned_from_captures(
        rule: Arc<Rule>,
        blob: &Blob,
        captures: SerializableCaptures,
    ) -> OwnedBlobMatch {
        OwnedBlobMatch::from_blob_match(BlobMatch {
            rule,
            blob_id: blob.id_ref(),
            matching_input: b"",
            matching_input_offset_span: OffsetSpan::from_range(50..90),
            association_offset_span: OffsetSpan::from_range(50..90),
            captures,
            validation_response_body: None,
            validation_response_status: StatusCode::CONTINUE,
            validation_success: false,
            validation_outcome: ValidationOutcome::NotAttempted,
            calculated_entropy: 0.0,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        })
    }

    #[test]
    fn explicit_secret_group_fingerprints_selected_secret_in_both_conversions() {
        const SECRET_A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const SECRET_B: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let rule = app_config_rule(Some(3));
        let blob = Blob::from_bytes(b"stable blob identity".to_vec());
        let owned_a1 =
            owned_from_captures(Arc::clone(&rule), &blob, app_config_captures(&rule, SECRET_A));
        let owned_a2 =
            owned_from_captures(Arc::clone(&rule), &blob, app_config_captures(&rule, SECRET_A));
        let owned_b =
            owned_from_captures(Arc::clone(&rule), &blob, app_config_captures(&rule, SECRET_B));

        assert_eq!(
            owned_a1.finding_fingerprint,
            compute_finding_fingerprint(SECRET_A, &blob.id().to_string(), 50, 90)
        );
        assert_eq!(owned_a1.finding_fingerprint, owned_a2.finding_fingerprint);
        assert_ne!(owned_a1.finding_fingerprint, owned_b.finding_fingerprint);

        let converted_a1 = Match::convert_owned_blobmatch_to_match(None, &owned_a1, "file");
        let converted_a2 = Match::convert_owned_blobmatch_to_match(None, &owned_a2, "file");
        let converted_b = Match::convert_owned_blobmatch_to_match(None, &owned_b, "file");
        assert_eq!(
            converted_a1.finding_fingerprint,
            compute_finding_fingerprint(SECRET_A, "file", 50, 90)
        );
        assert_eq!(converted_a1.finding_fingerprint, converted_a2.finding_fingerprint);
        assert_ne!(converted_a1.finding_fingerprint, converted_b.finding_fingerprint);
    }

    #[test]
    fn custom_rule_fingerprints_keep_legacy_second_capture() {
        let rule = app_config_rule(None);
        let blob = Blob::from_bytes(b"stable custom blob identity".to_vec());
        let owned = owned_from_captures(
            Arc::clone(&rule),
            &blob,
            app_config_captures(&rule, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        );

        assert_eq!(
            owned.finding_fingerprint,
            compute_finding_fingerprint("shared-id", &blob.id().to_string(), 50, 90)
        );
        let converted = Match::convert_owned_blobmatch_to_match(None, &owned, "file");
        assert_eq!(
            converted.finding_fingerprint,
            compute_finding_fingerprint("shared-id", "file", 50, 90)
        );
    }
}
