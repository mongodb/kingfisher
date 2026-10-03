//! Shared matching primitives for secret detection.
//!
//! These functions are used by both the high-level `Scanner` API and the
//! binary crate's `Matcher`. Having a single canonical implementation
//! eliminates duplicated logic across the codebase.

use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

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
    // This classification runs for every input byte. A small lookup avoids
    // repeating several range checks in the scanner's hottest byte loop.
    static ALPHABET: [bool; 256] = {
        let mut alphabet = [false; 256];
        let mut i = 0;
        while i < alphabet.len() {
            alphabet[i] = matches!(
                i as u8,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_'
            );
            i += 1;
        }
        alphabet
    };
    ALPHABET[usize::from(b)]
}

/// Finds standalone Base64-encoded strings in the input and returns decoded data
/// with byte-offset positions.
pub fn get_base64_strings(input: &[u8]) -> Vec<DecodedData> {
    get_base64_strings_with_control(input, &crate::ScanControl::default())
        .expect("unlimited scan cannot be cancelled")
}

pub(crate) fn get_base64_strings_with_control(
    input: &[u8],
    control: &crate::ScanControl,
) -> Result<Vec<DecodedData>, crate::ScanAborted> {
    if control.is_limited() {
        get_base64_strings_impl::<true>(input, control)
    } else {
        get_base64_strings_impl::<false>(input, control)
    }
}

fn get_base64_strings_impl<const CHECK: bool>(
    input: &[u8],
    control: &crate::ScanControl,
) -> Result<Vec<DecodedData>, crate::ScanAborted> {
    let mut results = Vec::new();
    let mut i = 0;
    while i < input.len() {
        if CHECK {
            control.check()?;
        }
        while i < input.len() && !is_base64_byte(input[i]) {
            if CHECK && i.is_multiple_of(64 * 1024) {
                control.check()?;
            }
            i += 1;
        }
        let start = i;
        while i < input.len() && is_base64_byte(input[i]) {
            if CHECK && i.is_multiple_of(64 * 1024) {
                control.check()?;
            }
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

    if CHECK {
        control.check()?;
    }
    Ok(results)
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

/// Original leftmost, non-overlapping regex matches, indexed once per rule and input.
/// Candidate windows normally share these boundaries. A window that changes the
/// first match (for example by cutting through one) uses the original iterator.
#[derive(Debug)]
pub struct CandidateMatchIndex(Vec<OffsetSpan>);

impl CandidateMatchIndex {
    pub fn new(regex: &regex::bytes::Regex, input: &[u8]) -> Self {
        Self(
            regex.find_iter(input).map(|m| OffsetSpan { start: m.start(), end: m.end() }).collect(),
        )
    }

    pub(crate) fn with_control(
        regex: &regex::bytes::Regex,
        input: &[u8],
        control: &crate::ScanControl,
    ) -> Result<Self, crate::ScanAborted> {
        if !control.is_limited() {
            return Ok(Self::new(regex, input));
        }
        let mut spans = Vec::new();
        for found in regex.find_iter(input) {
            control.check()?;
            spans.push(OffsetSpan { start: found.start(), end: found.end() });
        }
        control.check()?;
        Ok(Self(spans))
    }

    pub fn captures<'r, 'h>(
        &self,
        regex: &'r regex::bytes::Regex,
        endpoint_regex: Option<&regex::bytes::Regex>,
        haystack: &'h [u8],
        start: usize,
    ) -> ConfirmationCaptures<'r, 'h> {
        let end = start + haystack.len();
        if let Ok(index) = self.0.binary_search_by_key(&end, |span| span.end) {
            let span = self.0[index];
            if span.start >= start {
                // Verify the window's first match agrees with the index before skipping
                // earlier captures. EOF-sensitive alternatives can change selection
                // even when the window starts at zero.
                let first = self.0.partition_point(|span| span.start < start);
                let aligned = regex.find(haystack).is_some_and(|m| {
                    self.0.get(first).is_some_and(|span| {
                        span.start == start + m.start() && span.end == start + m.end()
                    })
                });
                // End anchoring can change lazy/alternative selection. Use it only
                // as a guard: if it prefers an earlier start than the original index,
                // retain the original iterator rather than merging separate matches.
                let endpoint_agrees = endpoint_regex
                    .and_then(|re| re.find(haystack))
                    .is_some_and(|m| m.start() == span.start - start && m.end() == haystack.len());
                if aligned && endpoint_agrees {
                    let captures = regex.captures_at(haystack, span.start - start);
                    if captures.as_ref().is_some_and(|captures| {
                        let full = captures.get(0).unwrap();
                        full.start() == span.start - start && full.end() == haystack.len()
                    }) {
                        return ConfirmationCaptures::One(captures);
                    }
                }
            }
        }
        ConfirmationCaptures::Search(regex.captures_iter(haystack))
    }
}

/// Either one indexed confirmation or the original search when window semantics differ.
pub enum ConfirmationCaptures<'r, 'h> {
    One(Option<regex::bytes::Captures<'h>>),
    Search(regex::bytes::CaptureMatches<'r, 'h>),
}

impl<'h> Iterator for ConfirmationCaptures<'_, 'h> {
    type Item = regex::bytes::Captures<'h>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::One(captures) => captures.take(),
            Self::Search(captures) => captures.next(),
        }
    }
}

/// Maximal match spans ordered by start. Ends also increase, so a predecessor
/// lookup answers containment without walking all previous matches.
#[derive(Debug, Default)]
pub struct MatchSpans(BTreeMap<usize, usize>);

impl MatchSpans {
    /// Whether a recorded full match covers this candidate endpoint.
    pub fn contains_end(&self, end: usize) -> bool {
        self.0.range(..end).next_back().is_some_and(|(_, previous_end)| end <= *previous_end)
    }

    /// Record a span unless already contained. Each removed span is removed once;
    /// insertion and predecessor searches do not shift an ever-growing vector.
    pub fn insert(&mut self, span: OffsetSpan) -> bool {
        if self.0.range(..=span.start).next_back().is_some_and(|(_, end)| *end >= span.end) {
            return false;
        }
        while let Some((&start, &end)) = self.0.range(span.start..).next() {
            if end > span.end {
                break;
            }
            self.0.remove(&start);
        }
        self.0.insert(span.start, span.end);
        true
    }
}

/// Records a match span using the legacy sorted-vector containment tracker.
#[inline]
pub fn record_match(
    map: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    rule_id: usize,
    span: OffsetSpan,
) -> bool {
    insert_span(map.entry(rule_id).or_default(), span)
}

/// Records a match using ordered containment tracking on the scanner's hot path.
#[inline]
pub(crate) fn record_indexed_match(
    map: &mut FxHashMap<usize, MatchSpans>,
    rule_id: usize,
    span: OffsetSpan,
) -> bool {
    map.entry(rule_id).or_default().insert(span)
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

/// Select a capture using Betterleaks' `secretGroup` semantics when supplied.
///
/// Betterleaks treats an omitted/zero `secretGroup` as the first non-empty positional capture.
/// A positive value selects that exact capture. `None` retains Kingfisher's legacy custom-rule
/// behavior implemented by [`find_secret_capture`].
pub fn find_secret_capture_with_group<'a>(
    re: &regex::bytes::Regex,
    captures: &regex::bytes::Captures<'a>,
    betterleaks_secret_group: Option<usize>,
) -> regex::bytes::Match<'a> {
    let Some(secret_group) = betterleaks_secret_group else {
        return find_secret_capture(re, captures);
    };

    if secret_group > 0 {
        return captures.get(secret_group).unwrap_or_else(|| captures.get(0).unwrap());
    }

    (1..captures.len())
        .filter_map(|index| captures.get(index))
        .find(|capture| !capture.as_bytes().is_empty())
        .unwrap_or_else(|| captures.get(0).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_confirmation_agrees_with_original_window_searches() {
        for (pattern, input) in [
            (r"(ab)|(bc)", "abc abc abc"),
            (r"(ar)|(bar$)", "bar!"),
            (r"(z)|(ar)|(bar$)", "zbar!"),
            (r"(z)|(ar)|(b[a-z]+$)", "zbzar!"),
            (r"(a+?)(a*)", "aaa aaa"),
            (r"(?s)BEGIN(.*?)END", "BEGIN one END gap BEGIN two END"),
            (r"(?m)^(token_[a-z]{2})$", "token_ab\ntoken_cd\ntrailing"),
            (r"\b([a-z]{1,4})\b", "one two three four"),
            (r"([a-z]{1,3})", "alphabet words"),
        ] {
            let regex = regex::bytes::Regex::new(pattern).unwrap();
            let bytes = input.as_bytes();
            let index = CandidateMatchIndex::new(&regex, bytes);
            let endpoint = regex::bytes::Regex::new(&format!(r"(?:{pattern})\z")).unwrap();
            for start in 0..bytes.len() {
                for end in start + 1..=bytes.len() {
                    let haystack = &bytes[start..end];
                    let accepted = |captures: regex::bytes::Captures<'_>| {
                        let full = captures.get(0).unwrap();
                        if full.end() != haystack.len() || (start > 0 && full.start() == 0) {
                            return None;
                        }
                        Some(
                            captures
                                .iter()
                                .map(|capture| capture.map(|m| (m.start(), m.end())))
                                .collect::<Vec<_>>(),
                        )
                    };
                    let original: Vec<_> =
                        regex.captures_iter(haystack).filter_map(accepted).collect();
                    let indexed: Vec<_> = index
                        .captures(&regex, Some(&endpoint), haystack, start)
                        .filter_map(accepted)
                        .collect();
                    assert_eq!(indexed, original, "pattern={pattern} window={start}..{end}");
                }
            }
        }
    }

    #[test]
    fn ordered_spans_agree_with_a_containment_oracle() {
        let mut spans = MatchSpans::default();
        let mut oracle: Vec<OffsetSpan> = Vec::new();
        let mut state = 532_u64;
        for _ in 0..2000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let start = (state >> 32) as usize % 200;
            let end = start + (state as usize % 30);
            let span = OffsetSpan { start, end };
            let expected = !oracle.iter().any(|old| old.fully_contains(&span));
            assert_eq!(spans.insert(span), expected);
            if expected {
                oracle.retain(|old| !span.fully_contains(old));
                oracle.push(span);
            }
            for endpoint in 0..230 {
                assert_eq!(
                    spans.contains_end(endpoint),
                    oracle.iter().any(|old| old.start < endpoint && endpoint <= old.end)
                );
            }
        }
    }

    #[test]
    fn base64_alphabet_accepts_only_standard_and_url_safe_bytes() {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_";
        for byte in u8::MIN..=u8::MAX {
            assert_eq!(is_base64_byte(byte), alphabet.contains(&byte), "byte {byte}");
        }
    }

    #[test]
    fn base64_detection_preserves_alphabets_padding_and_offsets() {
        let payload = b"???>>>a sufficiently long ASCII payload";
        for engine in [general_purpose::STANDARD, general_purpose::URL_SAFE] {
            let encoded = engine.encode(payload);
            let input = format!("\"{encoded}\"\n");
            let decoded = get_base64_strings(input.as_bytes());
            assert_eq!(decoded.len(), 1);
            assert_eq!(decoded[0].decoded, payload);
            assert_eq!(decoded[0].pos_start, 1);
            assert_eq!(decoded[0].pos_end, 1 + encoded.len());
        }
        assert!(get_base64_strings(&[0xff; 64]).is_empty());
        assert!(get_base64_strings(b"short").is_empty());
    }

    #[test]
    fn betterleaks_default_uses_first_non_empty_capture() {
        let regex = regex::bytes::Regex::new(r"(?:(?P<first>a)|b)(?P<second>c)").unwrap();
        let captures = regex.captures(b"bc").unwrap();

        assert_eq!(find_secret_capture_with_group(&regex, &captures, Some(0)).as_bytes(), b"c");
    }

    #[test]
    fn betterleaks_explicit_group_ignores_capture_names() {
        let regex = regex::bytes::Regex::new(r"(?P<named>a)(b)").unwrap();
        let captures = regex.captures(b"ab").unwrap();

        assert_eq!(find_secret_capture_with_group(&regex, &captures, Some(2)).as_bytes(), b"b");
    }
}
