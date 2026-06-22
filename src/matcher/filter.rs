use std::sync::Arc;

use http::StatusCode;
use regex::bytes::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::{
    blob::Blob,
    entropy::calculate_shannon_entropy,
    inline_ignore::InlineIgnoreConfig,
    location::OffsetSpan,
    origin::OriginSet,
    rule_profiling::{ConcurrentRuleProfiler, RuleTimer},
    rules::rule::{PatternRequirementContext, PatternValidationResult, Rule, Validation},
    safe_list::{is_safe_match_reason, is_user_match},
    validation::{is_parseable_mongodb_uri, is_parseable_mysql_uri, is_parseable_postgres_uri},
};

use super::{
    BlobMatch,
    captures::SerializableCaptures,
    dedup::{compute_match_key, record_match},
};

// Re-use the canonical secret capture selection from kingfisher-scanner.
use kingfisher_scanner::primitives::find_secret_capture;

// -------------------------------------------------------------------------------------------------
// Entropy and safe-list check
// -------------------------------------------------------------------------------------------------

/// Returns `Some(entropy)` if the match passes entropy and safe-list checks,
/// `None` if it should be skipped.
fn check_entropy_and_safelist(
    entropy_bytes: &[u8],
    full_bytes: &[u8],
    min_entropy: f32,
) -> Option<f32> {
    let calculated_entropy = calculate_shannon_entropy(entropy_bytes);
    if calculated_entropy <= min_entropy {
        debug!("Skipping match: entropy {} <= min_entropy {}", calculated_entropy, min_entropy);
        None
    } else if let Some(reason) = is_safe_match_reason(entropy_bytes) {
        debug!("Skipping match: safe-list match - {reason}");
        None
    } else if is_user_match(entropy_bytes, full_bytes) {
        debug!("Skipping match: user safe-list match");
        None
    } else {
        Some(calculated_entropy)
    }
}

// -------------------------------------------------------------------------------------------------
// Pattern requirements check
// -------------------------------------------------------------------------------------------------

/// Returns `true` if the match passes pattern requirements, `false` if it should be skipped.
fn check_pattern_requirements(
    rule: &Rule,
    re: &Regex,
    captures: &regex::bytes::Captures,
    full_bytes: &[u8],
    entropy_bytes: &[u8],
    respect_ignore_if_contains: bool,
) -> bool {
    let Some(char_reqs) = rule.pattern_requirements() else {
        return true;
    };

    let context = PatternRequirementContext { regex: re, captures, full_match: full_bytes };

    // Decide which bytes to validate:
    // - If there are multiple capture groups OR any named captures -> use full match
    // - Otherwise -> use entropy_bytes (the actual secret)
    let use_full_match = {
        let has_named_captures = re.capture_names().any(|n| n.is_some());
        let capture_count = captures.len(); // includes group 0
        has_named_captures || capture_count > 2
    };

    let validation_bytes = if use_full_match { full_bytes } else { entropy_bytes };

    match char_reqs.validate(validation_bytes, Some(context), respect_ignore_if_contains) {
        PatternValidationResult::Passed => true,
        PatternValidationResult::Failed => {
            debug!(
                "Skipping match that does not meet character requirements for rule {}",
                rule.id()
            );
            false
        }
        PatternValidationResult::FailedChecksum { actual_len, expected_len } => {
            debug!(
                "Skipping match for rule {} due to checksum mismatch (actual_len={}, expected_len={})",
                rule.id(),
                actual_len,
                expected_len
            );
            false
        }
        PatternValidationResult::IgnoredBySubstring { matched_term } => {
            debug!(
                "Skipping match for rule {} because it contains ignored term {matched_term}",
                rule.id()
            );
            false
        }
    }
}

// -------------------------------------------------------------------------------------------------
// URI validation
// -------------------------------------------------------------------------------------------------

/// Returns `true` if the match passes URI validation (for database rules), `false` if it should
/// be skipped.
fn check_uri_validation(rule: &Rule, matching_input_bytes: &[u8]) -> bool {
    let Some(validation) = rule.syntax.validation.as_ref() else {
        return true;
    };

    match validation {
        Validation::MongoDB => {
            let Ok(uri) = std::str::from_utf8(matching_input_bytes) else {
                debug!("Skipping match for rule {} due to non-UTF8 MongoDB URI", rule.id());
                return false;
            };
            if !is_parseable_mongodb_uri(uri) {
                debug!("Skipping match for rule {} due to invalid MongoDB URI", rule.id());
                return false;
            }
        }
        Validation::Postgres => {
            let Ok(uri) = std::str::from_utf8(matching_input_bytes) else {
                debug!("Skipping match for rule {} due to non-UTF8 Postgres URI", rule.id());
                return false;
            };
            if !is_parseable_postgres_uri(uri) {
                debug!("Skipping match for rule {} due to invalid Postgres URI", rule.id());
                return false;
            }
        }
        Validation::MySQL => {
            let Ok(uri) = std::str::from_utf8(matching_input_bytes) else {
                debug!("Skipping match for rule {} due to non-UTF8 MySQL URI", rule.id());
                return false;
            };
            if !is_parseable_mysql_uri(uri) {
                debug!("Skipping match for rule {} due to invalid MySQL URI", rule.id());
                return false;
            }
        }
        _ => {}
    }
    true
}

// -------------------------------------------------------------------------------------------------
// filter_match — main entry point
// -------------------------------------------------------------------------------------------------

#[expect(clippy::too_many_arguments)]
pub(crate) fn filter_match<'b>(
    blob: &'b Blob,
    rule: Arc<Rule>,
    re: &Regex,
    start: usize,
    end: usize,
    matches: &mut Vec<BlobMatch<'b>>,
    full_matches: Option<&mut FxHashMap<usize, Vec<OffsetSpan>>>,
    previous_matches: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    rule_id: usize,
    seen_matches: &mut FxHashSet<u64>,
    _origin: &OriginSet,
    ts_match: Option<&[u8]>,
    is_base64: bool,
    _redact: bool,
    filename: &str,
    profiler: Option<&Arc<ConcurrentRuleProfiler>>,
    respect_ignore_if_contains: bool,
    inline_ignore_config: &InlineIgnoreConfig,
) {
    let mut timer =
        profiler.map(|p| RuleTimer::new(p, rule.id(), rule.name(), &rule.syntax.pattern, filename));
    let mut full_matches = full_matches;

    let initial_len = matches.len();

    let blob_bytes = blob.bytes();
    let default_slice = &blob_bytes[start..end];
    let haystack = ts_match.unwrap_or(default_slice);

    for captures in re.captures_iter(haystack) {
        let full_capture = captures.get(0).unwrap();
        let full_capture_offset_span =
            OffsetSpan::from_range((start + full_capture.start())..(start + full_capture.end()));
        if let Some(full_matches) = full_matches.as_deref_mut()
            && !record_match(full_matches, rule_id, full_capture_offset_span)
        {
            continue;
        }
        let matching_input_for_entropy = find_secret_capture(re, &captures);

        let min_entropy = rule.min_entropy();
        let entropy_bytes = matching_input_for_entropy.as_bytes();
        let full_bytes = full_capture.as_bytes();

        // Check entropy and safe-listing
        let calculated_entropy =
            match check_entropy_and_safelist(entropy_bytes, full_bytes, min_entropy) {
                Some(e) => e,
                None => continue,
            };

        // Check pattern requirements
        if !check_pattern_requirements(
            &rule,
            re,
            &captures,
            full_bytes,
            entropy_bytes,
            respect_ignore_if_contains,
        ) {
            continue;
        }

        // Use the `matching_input_for_entropy` as the span/key for the finding.
        let matching_input = matching_input_for_entropy;

        let matching_input_offset_span = OffsetSpan::from_range(
            (start + matching_input.start())..(start + matching_input.end()),
        );

        // Check inline ignore directives
        if inline_ignore_config.should_ignore(blob_bytes, &matching_input_offset_span) {
            debug!("Skipping match due to inline ignore directive");
            continue;
        }

        // Check URI validation (MongoDB, Postgres, MySQL)
        if !check_uri_validation(&rule, matching_input.as_bytes()) {
            continue;
        }

        // Deduplication
        let match_key = compute_match_key(
            matching_input.as_bytes(),
            rule.id().as_bytes(),
            matching_input_offset_span.start,
            matching_input_offset_span.end,
        );
        if !seen_matches.insert(match_key) {
            continue;
        }
        if !record_match(previous_matches, rule_id, matching_input_offset_span) {
            continue;
        }
        let only_matching_input =
            &blob.bytes()[matching_input_offset_span.start..matching_input_offset_span.end];

        // Pass the *full* capture object to from_captures
        let groups = SerializableCaptures::from_captures(&captures, haystack, re);

        matches.push(BlobMatch {
            rule: Arc::clone(&rule),
            blob_id: blob.id_ref(),
            matching_input: only_matching_input,
            matching_input_offset_span,
            captures: groups,
            validation_response_body: None,
            validation_response_status: StatusCode::from_u16(0).unwrap_or(StatusCode::CONTINUE),
            validation_success: false,
            calculated_entropy,
            is_base64,
        });
    }
    if let Some(t) = timer.take() {
        let new_count = (matches.len() - initial_len) as u64;
        t.end(new_count > 0, new_count, 0);
    }
}
