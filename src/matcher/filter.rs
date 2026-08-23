use std::{collections::BTreeMap, sync::Arc};

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
    validation::{
        is_parseable_credential_uri, is_parseable_mongodb_uri, is_parseable_mysql_uri,
        is_parseable_postgres_uri,
    },
};

use super::{
    BlobMatch,
    captures::SerializableCaptures,
    dedup::{compute_match_key, record_match},
};

// Re-use the canonical secret capture selection from kingfisher-scanner.
use kingfisher_rules::{RulesDatabase, betterleaks_filter::BetterleaksFilterContext};
use kingfisher_scanner::primitives::find_secret_capture_with_group;

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
fn check_uri_validation(
    rule: &Rule,
    re: &Regex,
    captures: &regex::bytes::Captures,
    matching_input_bytes: &[u8],
) -> bool {
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
        Validation::CredentialUri => {
            let named_capture = |expected: &str| {
                re.capture_names().enumerate().find_map(|(index, name)| {
                    name.filter(|name| name.eq_ignore_ascii_case(expected))
                        .and_then(|_| captures.get(index))
                })
            };
            let uri_bytes = named_capture("URI")
                .map(|capture| capture.as_bytes())
                .unwrap_or(matching_input_bytes);
            let (Ok(uri), scheme) = (
                std::str::from_utf8(uri_bytes),
                named_capture("SCHEME")
                    .and_then(|capture| std::str::from_utf8(capture.as_bytes()).ok()),
            ) else {
                debug!("Skipping match for rule {} due to a non-UTF8 credential URI", rule.id());
                return false;
            };
            if !is_parseable_credential_uri(uri, scheme) {
                debug!("Skipping match for rule {} due to an invalid credential URI", rule.id());
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
    rules_db: &RulesDatabase,
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
    bounded_confirmation: bool,
) -> bool {
    if !rule.matches_path(filename) {
        return false;
    }

    let mut timer =
        profiler.map(|p| RuleTimer::new(p, rule.id(), rule.name(), &rule.syntax.pattern, filename));
    let mut full_matches = full_matches;

    let initial_len = matches.len();

    let blob_bytes = blob.bytes();
    let default_slice = &blob_bytes[start..end];
    let haystack = ts_match.unwrap_or(default_slice);
    let mut confirmed = false;

    for captures in re.captures_iter(haystack) {
        let full_capture = captures.get(0).unwrap();
        if bounded_confirmation
            && ((start > 0 && full_capture.start() == 0) || full_capture.end() != haystack.len())
        {
            continue;
        }
        confirmed = true;
        let full_capture_offset_span =
            OffsetSpan::from_range((start + full_capture.start())..(start + full_capture.end()));
        if let Some(full_matches) = full_matches.as_deref_mut()
            && !record_match(full_matches, rule_id, full_capture_offset_span)
        {
            continue;
        }
        let matching_input_for_entropy =
            find_secret_capture_with_group(re, &captures, rule.betterleaks_secret_group());

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

        let filter_outcome = rule.betterleaks_filter().and_then(|expression| {
            let match_start_idx = full_capture.start();
            let match_end_idx = full_capture.end();
            let match_line_start_idx = haystack[..match_start_idx]
                .iter()
                .rposition(|byte| *byte == b'\n')
                .map_or(0, |position| position + 1);
            let match_line_end_idx = haystack[match_end_idx..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(haystack.len(), |position| match_end_idx + position);
            let line = String::from_utf8_lossy(&haystack[match_line_start_idx..match_line_end_idx]);
            let captures = re
                .capture_names()
                .flatten()
                .filter_map(|name| {
                    captures.name(name).map(|capture| {
                        (name.to_string(), String::from_utf8_lossy(capture.as_bytes()).into_owned())
                    })
                })
                .collect::<BTreeMap<_, _>>();
            let secret = String::from_utf8_lossy(entropy_bytes);
            let full_match = String::from_utf8_lossy(full_bytes);
            let fragment_raw = String::from_utf8_lossy(haystack);
            let context = BetterleaksFilterContext {
                path: filename,
                secret: &secret,
                full_match: &full_match,
                line: &line,
                fragment_raw: &fragment_raw,
                match_start_idx,
                match_end_idx,
                match_line_start_idx,
                match_line_end_idx,
                rule_id: rule.id(),
                description: rule.name(),
                captures,
            };
            match rules_db.evaluate_betterleaks_filter(expression, &context) {
                Ok(outcome) => Some(outcome),
                Err(error) => {
                    debug!(rule_id = rule.id(), %error, "Betterleaks filter evaluation failed");
                    None
                }
            }
        });
        if filter_outcome.is_some_and(|outcome| outcome.discard) {
            continue;
        }
        let effective_confidence = filter_outcome
            .and_then(|outcome| outcome.confidence)
            .unwrap_or_else(|| rule.confidence());
        if !rule.accepts_effective_confidence(effective_confidence) {
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

        // Check URI validation (MongoDB, Postgres, MySQL, and dynamic credential URIs)
        if !check_uri_validation(&rule, re, &captures, matching_input.as_bytes()) {
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
        let groups = SerializableCaptures::from_captures_with_secret_group(
            &captures,
            haystack,
            re,
            rule.betterleaks_secret_group(),
        );

        let suppress_helper_reporting = rule.is_runtime_dependency_helper()
            && !rule.reports_effective_confidence(effective_confidence);
        let match_rule = if effective_confidence != rule.confidence() || suppress_helper_reporting {
            let mut effective_rule = rule.as_ref().clone();
            effective_rule.syntax.confidence = effective_confidence;
            if suppress_helper_reporting {
                effective_rule.suppress_runtime_reporting();
            }
            Arc::new(effective_rule)
        } else {
            Arc::clone(&rule)
        };
        matches.push(BlobMatch {
            rule: match_rule,
            blob_id: blob.id_ref(),
            matching_input: only_matching_input,
            matching_input_offset_span,
            association_offset_span: full_capture_offset_span,
            captures: groups,
            validation_response_body: None,
            validation_response_status: StatusCode::from_u16(0).unwrap_or(StatusCode::CONTINUE),
            validation_success: false,
            validation_outcome: match rule.syntax().validation.as_ref() {
                Some(Validation::Assumed) => kingfisher_core::ValidationOutcome::Assumed,
                _ => kingfisher_core::ValidationOutcome::NotAttempted,
            },
            calculated_entropy,
            is_base64,
            dependent_captures: std::collections::BTreeMap::new(),
        });
    }
    if let Some(t) = timer.take() {
        let new_count = (matches.len() - initial_len) as u64;
        t.end(new_count > 0, new_count, 0);
    }
    confirmed
}
