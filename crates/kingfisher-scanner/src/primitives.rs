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

/// Lazily index repeated candidate endpoints for one rule and input range.
/// Sparse candidates retain bounded regex confirmation. An index is built after at least
/// sixteen endpoints, once their combined initial window lengths reach the indexed byte count.
#[derive(Debug, Default)]
pub struct CandidateMatchCache {
    candidates: usize,
    index: Option<CandidateMatchIndex>,
}

/// Return whether a failed exact candidate confirmation needs a wider search window.
///
/// A rule with a certified finite maximum match length cannot produce a match ending at the
/// candidate after a strictly larger suffix has already been searched. Equality still widens:
/// callers exclude matches touching a non-zero left boundary because they may be truncated.
#[inline]
pub(crate) fn confirmation_needs_wider_window(
    confirmed: bool,
    window_start: usize,
    window_end: usize,
    maximum_match_len: Option<usize>,
) -> bool {
    !confirmed
        && window_start > 0
        && maximum_match_len
            .is_none_or(|maximum| maximum >= window_end.saturating_sub(window_start))
}

impl CandidateMatchCache {
    /// Consider one new endpoint, invoking `build` only when indexing is justified.
    pub fn get_or_insert_with(
        &mut self,
        indexed_bytes: usize,
        window_bytes: usize,
        build: impl FnOnce() -> CandidateMatchIndex,
    ) -> Option<&CandidateMatchIndex> {
        self.get_or_try_insert_with(indexed_bytes, window_bytes, || {
            Ok::<_, std::convert::Infallible>(build())
        })
        .expect("infallible index builder")
    }

    pub(crate) fn get_or_try_insert_with<E>(
        &mut self,
        indexed_bytes: usize,
        window_bytes: usize,
        build: impl FnOnce() -> Result<CandidateMatchIndex, E>,
    ) -> Result<Option<&CandidateMatchIndex>, E> {
        self.candidates = self.candidates.saturating_add(1);
        if self.index.is_none()
            && self.candidates >= 16
            && self.candidates.saturating_mul(window_bytes) >= indexed_bytes
        {
            self.index = Some(build()?);
        }
        Ok(self.index.as_ref())
    }
}

/// Original leftmost, non-overlapping regex matches, indexed once per rule and input range.
/// Candidate windows normally share these boundaries. A window that changes the
/// first match (for example by cutting through one) uses the original iterator.
#[derive(Debug)]
pub struct CandidateMatchIndex {
    spans: Vec<OffsetSpan>,
    range: std::ops::Range<usize>,
    maximum_len: Option<usize>,
    endpoint_maximum_len: Option<usize>,
    prefix_stable: bool,
    chains: parking_lot::Mutex<FxHashMap<(usize, u32), usize>>,
}

impl CandidateMatchIndex {
    /// Index a regex with its original match boundaries.
    /// Generic regexes retain full searches because builder flags cannot be recovered.
    pub fn new(regex: &regex::bytes::Regex, input: &[u8]) -> Self {
        Self::new_in_range(regex, input, 0..input.len())
    }

    /// Index only `range`, keeping offsets relative to the complete input.
    /// Confirmation windows outside this range retain the original regex search.
    ///
    /// Panics if `range` is not a valid slice of `input`.
    pub fn new_in_range(
        regex: &regex::bytes::Regex,
        input: &[u8],
        range: std::ops::Range<usize>,
    ) -> Self {
        Self::new_in_range_with_maximum_len(regex, input, range, None, None, false)
    }

    /// Index a rule regex with a precomputed safe confirmation-tail bound.
    /// `maximum_len` must account for all builder flags and EOF-sensitive alternatives,
    /// and the regex must never match an empty string. `endpoint_maximum_len` must
    /// bound the complete consuming match (not just a delimiter-terminated suffix);
    /// use `None` for arbitrary regexes. `prefix_stable` must come from the rule
    /// builder's certified HIR metadata, never an arbitrary Regex's pattern text.
    /// Rule callers use `RulesDatabase::confirmation_maximum_len` and
    /// `RulesDatabase::confirmation_prefix_stable`.
    pub(crate) fn new_in_range_with_maximum_len(
        regex: &regex::bytes::Regex,
        input: &[u8],
        range: std::ops::Range<usize>,
        maximum_len: Option<usize>,
        endpoint_maximum_len: Option<usize>,
        prefix_stable: bool,
    ) -> Self {
        let spans = regex
            .find_iter(&input[range.clone()])
            .map(|m| OffsetSpan { start: range.start + m.start(), end: range.start + m.end() })
            .collect();
        Self::from_spans(spans, range, maximum_len, endpoint_maximum_len, prefix_stable)
    }

    pub(crate) fn with_control(
        regex: &regex::bytes::Regex,
        input: &[u8],
        control: &crate::ScanControl,
        maximum_len: Option<usize>,
        endpoint_maximum_len: Option<usize>,
        prefix_stable: bool,
    ) -> Result<Self, crate::ScanAborted> {
        if !control.is_limited() {
            return Ok(Self::new_in_range_with_maximum_len(
                regex,
                input,
                0..input.len(),
                maximum_len,
                endpoint_maximum_len,
                prefix_stable,
            ));
        }
        let mut spans = Vec::new();
        for found in regex.find_iter(input) {
            control.check()?;
            spans.push(OffsetSpan { start: found.start(), end: found.end() });
        }
        control.check()?;
        Ok(Self::from_spans(
            spans,
            0..input.len(),
            maximum_len,
            endpoint_maximum_len,
            prefix_stable,
        ))
    }

    fn from_spans(
        spans: Vec<OffsetSpan>,
        range: std::ops::Range<usize>,
        maximum_len: Option<usize>,
        endpoint_maximum_len: Option<usize>,
        prefix_stable: bool,
    ) -> Self {
        Self {
            spans,
            range,
            maximum_len,
            endpoint_maximum_len,
            prefix_stable,
            chains: parking_lot::Mutex::new(FxHashMap::default()),
        }
    }

    // Keys use absolute offsets for one regex and input. Callers reuse a jump
    // only after resynchronizing the window's leftmost sequence, and only when
    // its end is inside safe_end, where changing EOF cannot alter the match.
    // Cache complete jumps only: an incomplete EOF tail may grow in another
    // confirmation window. Shifted leftmost sequences (e.g. delimiter-consuming
    // URL patterns) share these transitions instead of rescanning every window.
    #[allow(clippy::too_many_arguments)]
    fn chain_jump(
        &self,
        chains: &mut FxHashMap<(usize, u32), usize>,
        regex: &regex::bytes::Regex,
        haystack: &[u8],
        start: usize,
        boundary: usize,
        level: u32,
        limit: usize,
        control: &crate::ScanControl,
    ) -> Result<Option<usize>, crate::ScanAborted> {
        control.check()?;
        if let Some(&end) = chains.get(&(boundary, level)) {
            return Ok((end <= limit).then_some(end));
        }
        let end = if level == 0 {
            if let Ok(index) = self.spans.binary_search_by_key(&boundary, |span| span.end) {
                return Ok(self
                    .spans
                    .get(index + 1)
                    .map(|span| span.end)
                    .filter(|&end| end <= limit));
            }
            let Some(found) = regex.find_at(haystack, boundary - start) else {
                return Ok(None);
            };
            start + found.end()
        } else {
            let Some(middle) = self.chain_jump(
                chains,
                regex,
                haystack,
                start,
                boundary,
                level - 1,
                limit,
                control,
            )?
            else {
                return Ok(None);
            };
            let Some(end) =
                self.chain_jump(chains, regex, haystack, start, middle, level - 1, limit, control)?
            else {
                return Ok(None);
            };
            end
        };
        if end <= boundary || end > limit {
            return Ok(None);
        }
        chains.insert((boundary, level), end);
        Ok(Some(end))
    }

    pub fn captures<'r, 'h>(
        &self,
        regex: &'r regex::bytes::Regex,
        endpoint_regex: Option<&regex::bytes::Regex>,
        haystack: &'h [u8],
        start: usize,
    ) -> ConfirmationCaptures<'r, 'h> {
        self.captures_with_control(
            regex,
            endpoint_regex,
            haystack,
            start,
            &crate::ScanControl::default(),
        )
        .expect("unlimited scan cannot be cancelled")
        .into_legacy()
    }

    pub(crate) fn captures_with_control<'r, 'h>(
        &self,
        regex: &'r regex::bytes::Regex,
        endpoint_regex: Option<&regex::bytes::Regex>,
        haystack: &'h [u8],
        start: usize,
        control: &crate::ScanControl,
    ) -> Result<crate::confirmation::IndexedCaptures<'r, 'h>, crate::ScanAborted> {
        control.check()?;
        let end = start + haystack.len();
        if start < self.range.start || end > self.range.end {
            return Ok(crate::confirmation::IndexedCaptures::search(regex, haystack));
        }
        let first = self.spans.partition_point(|span| span.start < start);
        let prefix_aligned = self.prefix_stable
            && (first == 0
                || self.spans[first - 1].end <= start
                || regex.find(haystack).is_some_and(|m| {
                    self.spans.get(first).is_some_and(|span| {
                        span.start == start + m.start() && span.end == start + m.end()
                    })
                }));
        if let Ok(index) = self.spans.binary_search_by_key(&end, |span| span.end) {
            let span = self.spans[index];
            if span.start >= start {
                // Verify the window's first match agrees with the index before skipping
                // earlier captures. EOF-sensitive alternatives can change selection
                // even when the window starts at zero.
                let aligned = prefix_aligned
                    || !self.prefix_stable
                        && regex.find(haystack).is_some_and(|m| {
                            self.spans.get(first).is_some_and(|span| {
                                span.start == start + m.start() && span.end == start + m.end()
                            })
                        });
                // End anchoring can change lazy/alternative selection. Use it only
                // as a guard: if it prefers an earlier start than the original index,
                // retain the original iterator rather than merging separate matches.
                // A finite consuming bound rules out all earlier starts. Keep the original
                // haystack for find_at so ^ and word boundaries still see their original context.
                let endpoint_start = self
                    .endpoint_maximum_len
                    .map_or(0, |length| haystack.len().saturating_sub(length));
                // Assertion-free consuming expressions preserve every indexed
                // leftmost choice through an existing match endpoint when the
                // suffix is removed. Once the first match is aligned, confirm
                // that endpoint with the original regex directly. End anchoring
                // a lazy span would instead launch a wide PikeVM search seeking
                // an earlier start, then discard that work and search the tail.
                let endpoint_agrees = self.prefix_stable
                    || aligned
                        && endpoint_regex
                            .and_then(|re| re.find_at(haystack, endpoint_start))
                            .is_some_and(|m| {
                                m.start() == span.start - start && m.end() == haystack.len()
                            });
                if aligned && endpoint_agrees {
                    let captures = regex.captures_at(haystack, span.start - start);
                    if captures.as_ref().is_some_and(|captures| {
                        let full = captures.get(0).unwrap();
                        full.start() == span.start - start && full.end() == haystack.len()
                    }) {
                        return Ok(crate::confirmation::IndexedCaptures::one(captures));
                    }
                }
            }
        }
        if prefix_aligned {
            // With no assertions, removing a suffix cannot introduce an earlier
            // consuming success or change a winning path that still fits. Starting
            // in an unmatched gap also preserves the indexed sequence; starting
            // inside a match needs the explicit first-match alignment above.
            // Resume after its last complete match before this endpoint. The first
            // match crossing EOF may shorten or fail, so search it with the original
            // regex and window instead of scanning a maximum-length tail again.
            let tail = self.spans.partition_point(|span| span.end < end);
            if tail > first {
                return Ok(crate::confirmation::IndexedCaptures::from_position(
                    regex,
                    haystack,
                    self.spans[tail - 1].end - start,
                ));
            }
        }
        if let Some(maximum_len) = self.maximum_len {
            // Matches starting more than maximum_len bytes before EOF cannot change
            // when the confirmation window ends earlier than the indexed input. Leave
            // four extra bytes for Unicode word-boundary assertions. Resynchronize the window's
            // leftmost iterator with an original match before jumping to that safe tail.
            let safe_end = end.saturating_sub(maximum_len.saturating_add(4));
            let tail = self.spans.partition_point(|span| span.end <= safe_end);
            if let Some(first) =
                regex.find(haystack).filter(|found| start + found.end() <= safe_end)
            {
                let first_end = start + first.end();
                let boundary = if self
                    .spans
                    .binary_search_by_key(&first_end, |span| span.end)
                    .is_ok_and(|i| self.spans[i].start == start + first.start())
                    && tail > 0
                {
                    self.spans[tail - 1].end
                } else {
                    let mut chains = self.chains.lock();
                    let mut boundary = first_end;
                    loop {
                        let mut furthest = None;
                        for level in 0..usize::BITS {
                            let Some(end) = self.chain_jump(
                                &mut chains,
                                regex,
                                haystack,
                                start,
                                boundary,
                                level,
                                safe_end,
                                control,
                            )?
                            else {
                                break;
                            };
                            furthest = Some(end);
                        }
                        let Some(end) = furthest else { break };
                        boundary = end;
                    }
                    boundary
                };
                return Ok(crate::confirmation::IndexedCaptures::from_position(
                    regex,
                    haystack,
                    boundary - start,
                ));
            }
        }
        Ok(crate::confirmation::IndexedCaptures::search(regex, haystack))
    }
}

/// One indexed confirmation or a full regex search.
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
    fn bounded_failed_confirmation_does_not_widen_past_a_complete_window() {
        assert!(!confirmation_needs_wider_window(false, 4096, 8192, Some(79)));
        assert!(confirmation_needs_wider_window(false, 4096, 8192, Some(4096)));
        assert!(confirmation_needs_wider_window(false, 4096, 8192, None));
        assert!(!confirmation_needs_wider_window(true, 4096, 8192, None));
        assert!(!confirmation_needs_wider_window(false, 0, 4096, None));
    }

    #[test]
    fn sparse_candidates_do_not_build_an_index() {
        for input_len in [32, 8 * 1024 * 1024, 256 * 1024 * 1024] {
            let mut cache = CandidateMatchCache::default();
            for _ in 0..3 {
                assert!(
                    cache
                        .get_or_insert_with(input_len, 4096, || {
                            panic!("sparse confirmation must not scan the indexed input")
                        })
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn repeated_candidates_build_once_and_preserve_confirmation() {
        let regex = regex::bytes::Regex::new(r"(token_[a-z]{2})").unwrap();
        let endpoint = regex::bytes::Regex::new(r"(token_[a-z]{2})\z").unwrap();
        let input = b"token_ab token_cd\n".repeat(2500);
        let builds = std::cell::Cell::new(0);
        let mut cache = CandidateMatchCache::default();
        let mut unindexed = 0;
        for found in regex.find_iter(&input) {
            let end = found.end();
            let start = end.saturating_sub(4096);
            let haystack = &input[start..end];
            let index = cache.get_or_insert_with(input.len(), 4096, || {
                builds.set(builds.get() + 1);
                CandidateMatchIndex::new(&regex, &input)
            });
            let captures = if let Some(index) = index {
                index.captures(&regex, Some(&endpoint), haystack, start)
            } else {
                unindexed += 1;
                ConfirmationCaptures::Search(regex.captures_iter(haystack))
            };
            let confirmed: Vec<_> = captures
                .filter_map(|captures| {
                    let full = captures.get(0).unwrap();
                    (full.end() == haystack.len() && (start == 0 || full.start() > 0))
                        .then_some((start + full.start(), start + full.end()))
                })
                .collect();
            assert_eq!(confirmed, vec![(found.start(), found.end())]);
        }
        assert!(unindexed >= 3);
        assert_eq!(builds.get(), 1);
    }

    #[test]
    fn candidate_index_build_errors_are_propagated_without_caching() {
        let mut cache = CandidateMatchCache::default();
        let mut attempted = false;
        for _ in 0..100 {
            let result = cache.get_or_try_insert_with(1, 4096, || Err("scan cancelled"));
            if let Err(error) = result {
                assert_eq!(error, "scan cancelled");
                attempted = true;
                break;
            }
        }
        assert!(attempted);
        assert!(cache.index.is_none());
    }

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
            let indexes = [
                CandidateMatchIndex::new(&regex, bytes),
                CandidateMatchIndex::new_in_range(
                    &regex,
                    bytes,
                    bytes.len() / 3..bytes.len() * 2 / 3,
                ),
                CandidateMatchIndex::new_in_range(&regex, bytes, bytes.len() / 2..bytes.len()),
            ];
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
                    for index in &indexes {
                        let indexed: Vec<_> = index
                            .captures(&regex, Some(&endpoint), haystack, start)
                            .filter_map(accepted)
                            .collect();
                        assert_eq!(
                            indexed, original,
                            "pattern={pattern} range={:?} window={start}..{end}",
                            index.range
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn arbitrary_builder_flags_do_not_certify_prefix_reuse() {
        // ignore_whitespace is absent from Regex::as_str(). Parsing this source
        // with default flags sees a character class and misses the real EOF
        // assertion. Public constructors must not infer a certificate from it.
        let regex = regex::bytes::RegexBuilder::new("#[\n(z)|(ar)|(bar$)#]\n")
            .ignore_whitespace(true)
            .build()
            .unwrap();
        let input = b"zbar!";
        let index = CandidateMatchIndex::new(&regex, input);
        assert!(!index.prefix_stable);
        let captures: Vec<_> = index
            .captures_with_control(&regex, None, &input[..4], 0, &crate::ScanControl::default())
            .unwrap()
            .filter(|captures| captures.get(0).unwrap().end() == 4)
            .collect();
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].get(0).unwrap().as_bytes(), b"bar");
        assert!(captures[0].get(2).is_none());
        assert_eq!(captures[0].get(3).unwrap().as_bytes(), b"bar");
    }

    #[test]
    fn prefix_stable_partial_endpoints_resume_after_complete_matches() {
        let rule = kingfisher_rules::RuleSyntax::new(
            "acme.lazy",
            "Lazy span",
            r"BEGIN(?P<TOKEN>.{1,32}?)END[0-9]{2,4}",
        );
        let db =
            kingfisher_rules::RulesDatabase::from_rules(vec![kingfisher_rules::Rule::new(rule)])
                .unwrap();
        let regex = &db.anchored_regexes()[0];
        let input = "BEGIN payload END1234 gap ".repeat(1_000);
        let bytes = input.as_bytes();
        let index = CandidateMatchIndex::new_in_range_with_maximum_len(
            regex,
            bytes,
            0..bytes.len(),
            db.confirmation_maximum_len(0),
            db.confirmation_match_maximum_len(0),
            db.confirmation_prefix_stable(0),
        );
        assert!(index.prefix_stable);
        // EOF shortens the greedy numeric suffix without altering any complete
        // preceding match. The resumed search must preserve the named lazy capture.
        let end = index.spans.last().unwrap().end - 1;
        for start in [0, index.spans[4].end + 1] {
            let window = &bytes[start..end];
            let captures = index
                .captures_with_control(regex, None, window, start, &crate::ScanControl::default())
                .unwrap();
            assert_eq!(
                captures.search_position(),
                Some(index.spans[index.spans.len() - 2].end - start)
            );
            let actual: Vec<_> = captures
                .map(|captures| {
                    (
                        captures.get(0).unwrap().as_bytes(),
                        captures.name("TOKEN").unwrap().as_bytes(),
                    )
                })
                .collect();
            let expected: Vec<_> = regex
                .captures_iter(window)
                .filter(|captures| captures.get(0).unwrap().end() == window.len())
                .map(|captures| {
                    (
                        captures.get(0).unwrap().as_bytes(),
                        captures.name("TOKEN").unwrap().as_bytes(),
                    )
                })
                .collect();
            assert_eq!(actual, expected);
            assert_eq!(actual, vec![(&b"BEGIN payload END123"[..], &b" payload "[..])]);
        }
    }

    #[test]
    fn dense_tail_confirmation_preserves_eof_alternatives_and_boundary_captures() {
        for (pattern, input) in [
            (r"(z)|(ar)|(bar$)", "zbar! ".repeat(30)),
            (r"(z)|(ar)|(b[a-z]+$)", "zbzar! ".repeat(30)),
            (r"([a-z-]+\.online\.tableau\.com)\b", "acme-team.online.tableau.com\n".repeat(30)),
            (r"(?i)([a-z-]+\.online\.tableau\.com)\b", "acme-team.online.tableau.com\n".repeat(30)),
            (r"(ab)|(bc)", "abc ".repeat(30)),
            (r"(aa)", "aaaaaaaaaaaaaaaaaaaa ".repeat(20)),
            (r"(a+?)(a*)", "aaa ".repeat(30)),
            (r"a[^z]+z|(b)", "abbbz abbb ".repeat(30)),
            (r"(?m)^(token_[a-z]{2})$", "token_ab\ntoken_cd\n".repeat(30)),
            (r"(?s)BEGIN(.*?)END", "BEGIN one END gap BEGIN two END\n".repeat(20)),
            (r"(?s)BEGIN(?P<TOKEN>.{1,32}?)END", "BEGIN one END gap BEGIN two END\n".repeat(20)),
            (r"(é+)\b", "éé aa ééé ".repeat(30)),
            (r"()|a", "a ".repeat(30)),
        ] {
            let rule = kingfisher_rules::RuleSyntax::new("acme.oracle", "Oracle", pattern);
            let regex = rule.as_regex().unwrap();
            let endpoint = rule.as_endpoint_regex().unwrap();
            let (maximum_len, endpoint_maximum_len, prefix_stable) = if pattern == r"()|a" {
                (None, None, false)
            } else {
                let db =
                    kingfisher_rules::RulesDatabase::from_rules(vec![kingfisher_rules::Rule::new(
                        rule,
                    )])
                    .unwrap();
                (
                    db.confirmation_maximum_len(0),
                    db.confirmation_match_maximum_len(0),
                    db.confirmation_prefix_stable(0),
                )
            };
            let bytes = input.as_bytes();
            let index = CandidateMatchIndex::new_in_range_with_maximum_len(
                &regex,
                bytes,
                0..bytes.len(),
                maximum_len,
                endpoint_maximum_len,
                prefix_stable,
            );
            for start in (0..20).chain([bytes.len() / 3, bytes.len() / 2, bytes.len() - 1]) {
                for end in (start + 1)..=bytes.len() {
                    let haystack = &bytes[start..end];
                    let accepted = |captures: regex::bytes::Captures<'_>| {
                        let full = captures.get(0).unwrap();
                        (full.end() == haystack.len() && (start == 0 || full.start() > 0)).then(
                            || {
                                captures
                                    .iter()
                                    .map(|capture| capture.map(|m| (m.start(), m.end())))
                                    .collect::<Vec<_>>()
                            },
                        )
                    };
                    let expected: Vec<_> =
                        regex.captures_iter(haystack).filter_map(accepted).collect();
                    let actual: Vec<_> = index
                        .captures_with_control(
                            &regex,
                            Some(&endpoint),
                            haystack,
                            start,
                            &crate::ScanControl::default(),
                        )
                        .unwrap()
                        .filter_map(accepted)
                        .collect();
                    assert_eq!(actual, expected, "pattern={pattern} window={start}..{end}");
                }
            }
        }
    }

    #[test]
    fn shifted_dense_match_sequences_reuse_cached_jumps() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<CandidateMatchIndex>();
        let regex =
            regex::bytes::Regex::new(r"(?:^|[^a-z-])([a-z-]{1,63}\.jfrog\.io)(?:$|[^a-z-])")
                .unwrap();
        let input = "acme-team.jfrog.io\n".repeat(10_000);
        let index = CandidateMatchIndex::new_in_range_with_maximum_len(
            &regex,
            input.as_bytes(),
            0..input.len(),
            Some(100),
            Some(100),
            false,
        );
        for end in [input.len(), input.len() - 18, input.len() - 36] {
            let captures = index
                .captures_with_control(
                    &regex,
                    None,
                    &input.as_bytes()[12..end],
                    12,
                    &crate::ScanControl::default(),
                )
                .unwrap();
            assert!(captures.search_position().is_some());
            let _ = captures.count();
        }
        let jumps = index.chains.lock().len();
        for _ in 0..10 {
            let _ = index
                .captures_with_control(
                    &regex,
                    None,
                    &input.as_bytes()[12..],
                    12,
                    &crate::ScanControl::default(),
                )
                .unwrap()
                .count();
        }
        assert_eq!(index.chains.lock().len(), jumps);
    }

    #[test]
    fn rejected_dense_endpoints_search_only_the_confirmed_tail() {
        let regex = regex::bytes::Regex::new(r"(token_[a-z]{2})").unwrap();
        let input = "token_ab ".repeat(10_000);
        let index = CandidateMatchIndex::new_in_range_with_maximum_len(
            &regex,
            input.as_bytes(),
            0..input.len(),
            Some(8),
            Some(8),
            false,
        );
        let haystack = &input.as_bytes()[..input.len() - 3];
        let captures = index
            .captures_with_control(&regex, None, haystack, 0, &crate::ScanControl::default())
            .unwrap();
        let Some(position) = captures.search_position() else {
            panic!("dense rejected endpoints must reuse a synchronized boundary");
        };
        assert!(haystack.len() - position <= 20);
        assert_eq!(captures.count(), 0);
    }

    #[test]
    fn ranged_candidate_index_bounds_dense_match_storage() {
        let regex = regex::bytes::Regex::new("a").unwrap();
        let bytes = vec![b'a'; 1024 * 1024];
        let range = 512 * 1024..512 * 1024 + 64;
        let index = CandidateMatchIndex::new_in_range(&regex, &bytes, range.clone());
        assert_eq!(index.spans.len(), range.len());
        assert_eq!(index.spans.first().unwrap().start, range.start);
        assert_eq!(index.spans.last().unwrap().end, range.end);
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

#[cfg(test)]
mod control_regressions {
    use super::*;
    use crate::{CancellationToken, ScanAborted, ScanControl};

    #[test]
    fn dense_indexes_do_not_preallocate_duplicate_chain_entries() {
        let input = b"a ".repeat(10_000);
        for pattern in ["(a)", "(a+)"] {
            let regex = regex::bytes::Regex::new(pattern).unwrap();
            let index = CandidateMatchIndex::new(&regex, &input);
            assert_eq!(index.spans.len(), 10_000);
            assert!(index.chains.lock().is_empty());
        }
    }

    #[test]
    fn arbitrary_builder_flags_keep_original_confirmation_semantics() {
        let regex =
            regex::bytes::RegexBuilder::new("(k{32})").case_insensitive(true).build().unwrap();
        let input = "K".repeat(200);
        let bytes = input.as_bytes();
        let index = CandidateMatchIndex::new(&regex, bytes);
        assert_eq!(index.maximum_len, None);
        for start in [0, 3, 63, 159] {
            for end in (start + 1)..=bytes.len() {
                let window = &bytes[start..end];
                let accepted = |captures: regex::bytes::Captures<'_>| {
                    let full = captures.get(0).unwrap();
                    (full.end() == window.len()).then_some((full.start(), full.end()))
                };
                let expected: Vec<_> = regex.captures_iter(window).filter_map(accepted).collect();
                let actual: Vec<_> =
                    index.captures(&regex, None, window, start).filter_map(accepted).collect();
                assert_eq!(actual, expected, "window={start}..{end}");
            }
        }
    }

    #[test]
    fn chain_walks_and_tail_iteration_observe_interruption() {
        let regex = regex::bytes::Regex::new("(aa)").unwrap();
        let input = b"a".repeat(20_000);
        let index = CandidateMatchIndex::new_in_range_with_maximum_len(
            &regex,
            &input,
            0..input.len(),
            Some(2),
            Some(2),
            false,
        );
        let checks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = std::sync::Arc::clone(&checks);
        let budget = ScanControl::default().with_check_observer(move |_| {
            if observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 10 {
                Err(ScanAborted::TimedOut)
            } else {
                Ok(())
            }
        });
        assert_eq!(
            index.chain_jump(
                &mut index.chains.lock(),
                &regex,
                &input,
                0,
                1,
                8,
                input.len() - 6,
                &budget
            ),
            Err(ScanAborted::TimedOut)
        );
        assert!(checks.load(std::sync::atomic::Ordering::SeqCst) > 10);
        let token = CancellationToken::default();
        let control = ScanControl::default().with_cancellation(token.clone());
        token.cancel();
        assert_eq!(
            index.chain_jump(
                &mut index.chains.lock(),
                &regex,
                &input,
                0,
                1,
                8,
                input.len() - 6,
                &control
            ),
            Err(ScanAborted::Cancelled)
        );
        let mut captures = crate::confirmation::IndexedCaptures::from_position(&regex, &input, 1);
        assert!(matches!(captures.next_with_control(&control), Err(ScanAborted::Cancelled)));
        let expired = ScanControl::default().with_deadline(std::time::Instant::now());
        assert!(matches!(captures.next_with_control(&expired), Err(ScanAborted::TimedOut)));
        assert!(matches!(
            index.captures_with_control(&regex, None, &input, 1, &expired),
            Err(ScanAborted::TimedOut)
        ));
    }
}
