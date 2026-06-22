//! Shared matching primitives for secret detection.
//!
//! These functions are used by both the high-level `Scanner` API and the
//! binary crate's `Matcher`. Having a single canonical implementation
//! eliminates duplicated logic across the codebase.

use std::hash::{Hash, Hasher};

use base64::{Engine, engine::general_purpose};
use kingfisher_core::OffsetSpan;
use rustc_hash::{FxHashMap, FxHasher};
use xxhash_rust::xxh3::xxh3_64;

// -------------------------------------------------------------------------------------------------
// Base64 detection
// -------------------------------------------------------------------------------------------------

/// Decoded Base64 data with position information.
#[derive(Debug, Clone)]
pub struct DecodedData {
    pub decoded: Vec<u8>,
    pub pos_start: usize,
    pub pos_end: usize,
}

#[inline]
pub fn is_base64_byte(b: u8) -> bool {
    // Accepts both standard base64 ('+', '/') and URL-safe base64 ('-', '_') characters.
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_')
}

/// Finds standalone Base64-encoded strings in the input and returns decoded data
/// with byte-offset positions.
pub fn get_base64_strings(input: &[u8]) -> Vec<DecodedData> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < input.len() {
        while i < input.len() && !is_base64_byte(input[i]) {
            i += 1;
        }
        let start = i;
        while i < input.len() && is_base64_byte(input[i]) {
            i += 1;
        }

        let mut eq_count = 0;
        while i < input.len() && input[i] == b'=' && eq_count < 2 {
            i += 1;
            eq_count += 1;
        }
        let end = i;

        let len = end - start;
        if len >= 32 && len % 4 == 0 {
            let base64_slice = &input[start..end];

            // Try decoding with STANDARD, then URL_SAFE, then URL_SAFE_NO_PAD
            let decode_result = general_purpose::STANDARD
                .decode(base64_slice)
                .or_else(|_| general_purpose::URL_SAFE.decode(base64_slice))
                .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(base64_slice));

            if let Ok(decoded) = decode_result
                && decoded.is_ascii()
            {
                results.push(DecodedData { decoded, pos_start: start, pos_end: end });
            }
        }
    }

    results
}

// -------------------------------------------------------------------------------------------------
// Match deduplication
// -------------------------------------------------------------------------------------------------

/// Computes a deduplication key for a match based on content, rule ID, and span.
#[inline]
pub fn compute_match_key(content: &[u8], rule_id: &[u8], start: usize, end: usize) -> u64 {
    let mut hasher = FxHasher::default();
    // Hash each component directly without allocation
    content.hash(&mut hasher);
    rule_id.hash(&mut hasher);
    start.hash(&mut hasher);
    end.hash(&mut hasher);
    hasher.finish()
}

/// Inserts a span into a sorted list of spans, handling containment.
///
/// Returns `false` if the span is already contained in an existing span
/// (i.e., it's redundant and should be skipped).
#[inline]
pub fn insert_span(spans: &mut Vec<OffsetSpan>, span: OffsetSpan) -> bool {
    let mut idx = spans.binary_search_by(|s| s.start.cmp(&span.start)).unwrap_or_else(|i| i);
    if idx > 0 {
        if spans[idx - 1].fully_contains(&span) {
            return false;
        }
        if span.fully_contains(&spans[idx - 1]) {
            spans.remove(idx - 1);
            idx -= 1;
        }
    }
    if idx < spans.len() {
        if spans[idx].fully_contains(&span) {
            return false;
        }
        if span.fully_contains(&spans[idx]) {
            spans.remove(idx);
        }
    }
    spans.insert(idx, span);
    true
}

/// Records a match span for a given rule, returning `false` if it's a duplicate.
#[inline]
pub fn record_match(
    map: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    rule_id: usize,
    span: OffsetSpan,
) -> bool {
    insert_span(map.entry(rule_id).or_default(), span)
}

// -------------------------------------------------------------------------------------------------
// Finding fingerprint
// -------------------------------------------------------------------------------------------------

/// Computes a stable fingerprint for a finding based on its value, location, and origin.
pub fn compute_finding_fingerprint(
    finding_value: &str,
    file_or_commit: &str,
    offset_start: u64,
    offset_end: u64,
) -> u64 {
    // Combine all into a byte buffer and hash it directly:
    let mut buf = Vec::with_capacity(
        finding_value.len() + file_or_commit.len() + 2 * std::mem::size_of::<u64>(),
    );
    buf.extend_from_slice(finding_value.as_bytes());
    buf.extend_from_slice(file_or_commit.as_bytes());
    buf.extend_from_slice(&offset_start.to_le_bytes());
    buf.extend_from_slice(&offset_end.to_le_bytes());

    xxh3_64(&buf)
}

// -------------------------------------------------------------------------------------------------
// Secret capture selection
// -------------------------------------------------------------------------------------------------

/// Selects the "secret" capture from the regex match using the priority:
/// 1. Named capture called TOKEN (case-insensitive)
/// 2. First matched named capture
/// 3. First positional capture (group 1)
/// 4. Full match (group 0)
pub fn find_secret_capture<'a>(
    re: &regex::bytes::Regex,
    captures: &regex::bytes::Captures<'a>,
) -> regex::bytes::Match<'a> {
    // 1. Prefer a named capture called TOKEN (case-insensitive).
    if let Some(token_cap) = re.capture_names().enumerate().find_map(|(i, name_opt)| {
        name_opt.filter(|name| name.eq_ignore_ascii_case("TOKEN")).and_then(|_| captures.get(i))
    }) {
        return token_cap;
    }

    // 2. Otherwise, prefer the first *matched* named capture.
    if let Some(named_cap) = re
        .capture_names()
        .enumerate()
        .find_map(|(i, name_opt)| name_opt.and_then(|_| captures.get(i)))
    {
        return named_cap;
    }

    // 3. Otherwise, fall back to the first positional capture (group 1).
    if let Some(pos_cap) = captures.get(1) {
        return pos_cap;
    }

    // 4. Finally, fall back to the full match (group 0).
    captures.get(0).unwrap()
}
