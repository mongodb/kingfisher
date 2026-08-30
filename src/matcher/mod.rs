mod base64_decode;
mod captures;
mod conversion;
mod dedup;
mod filter;
mod fingerprint;

// Re-export public API
pub use base64_decode::{DecodedData, get_base64_strings};
pub use captures::{Group, Groups, SerializableCapture, SerializableCaptures};
pub use conversion::{Match, MatcherStats, OwnedBlobMatch};
pub use fingerprint::compute_finding_fingerprint;

use std::sync::{Arc, Mutex};

use anyhow::Result;
use http::StatusCode;
use kingfisher_core::ValidationOutcome;
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::{
    blob::{Blob, BlobId, BlobIdMap},
    inline_ignore::InlineIgnoreConfig,
    location::OffsetSpan,
    origin::OriginSet,
    parser,
    parser::Language,
    rule_profiling::{ConcurrentRuleProfiler, RuleStats},
    rules::rule::Rule,
    rules_database::RulesDatabase,
    scanner_pool::ScannerPool,
    validation_body::ValidationResponseBody,
};
use kingfisher_scanner::primitives::find_secret_capture_with_group;

use self::{base64_decode::get_base64_strings as get_b64_strings, filter::filter_match};

const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB per scan segment
const CHUNK_OVERLAP: usize = 64 * 1024; // 64 KiB overlap to catch boundary matches
const RAW_MATCH_LOOKBACK: usize = 4 * 1024; // Initial exact-confirmation suffix.
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024; // skip expensive Base64 pass on huge blobs
// The old tree-sitter limit was 128 KiB due to full-AST parsing cost.
// The lightweight regex-based lexer is O(n) line-by-line, so we can afford
// a much higher ceiling.  We still cap it to avoid spending time on huge
// generated/minified blobs where context verification adds little value.
const CONTEXT_VERIFIER_MAX_LIMIT: usize = 2 * 1024 * 1024; // verify code context on blobs <= 2 MiB
const CONTEXT_VERIFIER_MIN_LIMIT: usize = 0; // allow context verification starting at 0 bytes

#[inline]
pub(crate) fn should_attempt_context_verification(blob_len: usize) -> bool {
    (CONTEXT_VERIFIER_MIN_LIMIT..=CONTEXT_VERIFIER_MAX_LIMIT).contains(&blob_len)
}

// -------------------------------------------------------------------------------------------------
// RawMatch
// -------------------------------------------------------------------------------------------------
/// A raw match, as recorded by a callback to Vectorscan.
///
/// When matching with Vectorscan, we simply collect all matches into a
/// preallocated `Vec`, and then go through them all after scanning is complete.
#[derive(PartialEq, Eq, Debug, Clone)]
struct RawMatch {
    rule_id: u32,
    start_idx: u64,
    end_idx: u64,
}

// -------------------------------------------------------------------------------------------------
// BlobMatch
// -------------------------------------------------------------------------------------------------
/// A `BlobMatch` is the result type from `Matcher::scan_blob`.
///
/// It is mostly made up of references and small data.
/// For a representation that is more friendly for human consumption, see
/// `Match`.
pub struct BlobMatch<'a> {
    /// The rule that was matched
    pub rule: Arc<Rule>,

    /// The blob that was matched
    pub blob_id: &'a BlobId,

    /// The matching input in `blob.input`
    pub matching_input: &'a [u8],

    /// The location of the matching input in `blob.input`
    pub matching_input_offset_span: OffsetSpan,

    /// Full regex-match span used for Betterleaks component proximity.
    pub association_offset_span: OffsetSpan,

    /// The capture groups from the match
    pub captures: SerializableCaptures,

    pub validation_response_body: ValidationResponseBody,
    pub validation_response_status: StatusCode,

    pub validation_success: bool,
    pub validation_outcome: ValidationOutcome,
    pub calculated_entropy: f32,
    pub is_base64: bool,
    pub dependent_captures: std::collections::BTreeMap<String, String>,
}

#[derive(Clone)]
struct UserData {
    /// A scratch vector for raw matches from Vectorscan, to minimize allocation
    raw_matches_scratch: Vec<RawMatch>,

    /// The length of the input being scanned
    input_len: u64,
}

// -------------------------------------------------------------------------------------------------
// Matcher
// -------------------------------------------------------------------------------------------------
/// A `Matcher` is able to scan inputs for matches from rules in a
/// `RulesDatabase`.
///
/// If doing multi-threaded scanning, use a separate `Matcher` for each thread.
#[derive(Clone)]
pub struct Matcher<'a> {
    /// Thread-local pool that hands out a &mut BlockScanner
    scanner_pool: std::sync::Arc<crate::scanner_pool::ScannerPool>,

    /// The rules database used for matching
    rules_db: &'a RulesDatabase,

    /// Local statistics for this `Matcher`
    local_stats: MatcherStats,

    /// Global statistics, updated with the local statsistics when this
    /// `Matcher` is dropped
    global_stats: Option<&'a Mutex<MatcherStats>>,

    /// The set of blobs that have been seen
    seen_blobs: &'a BlobIdMap<bool>,

    /// Data passed to the Vectorscan callback
    user_data: UserData,

    /// Rule profiler for measuring performance of individual rules
    profiler: Option<Arc<ConcurrentRuleProfiler>>,

    /// Configuration that controls inline ignore directives
    inline_ignore_config: InlineIgnoreConfig,

    /// Whether matches should honour `ignore_if_contains` requirements.
    respect_ignore_if_contains: bool,
}

/// This `Drop` implementation updates the `global_stats` with the local stats
impl<'a> Drop for Matcher<'a> {
    fn drop(&mut self) {
        if let Some(global_stats) = self.global_stats {
            let mut global_stats = global_stats.lock().unwrap();
            global_stats.update(&self.local_stats);
        }
    }
}

pub enum ScanResult<'a> {
    SeenWithMatches,
    SeenSansMatches,
    New(Vec<BlobMatch<'a>>),
}

impl<'a> Matcher<'a> {
    pub fn get_profiling_report(&self) -> Option<Vec<RuleStats>> {
        self.profiler.as_ref().map(|p| p.generate_report())
    }
}

impl<'a> Matcher<'a> {
    /// Create a new `Matcher` from the given `RulesDatabase`.
    ///
    /// If `global_stats` is provided, it will be updated with the local stats
    /// from this `Matcher` when it is dropped.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rules_db: &'a RulesDatabase,
        scanner_pool: Arc<ScannerPool>,
        seen_blobs: &'a BlobIdMap<bool>,
        global_stats: Option<&'a Mutex<MatcherStats>>,
        enable_profiling: bool,
        shared_profiler: Option<Arc<ConcurrentRuleProfiler>>,
        extra_ignore_directives: &[String],
        disable_inline_ignores: bool,
        respect_ignore_if_contains: bool,
    ) -> Result<Self> {
        // Changed: removed `with_capacity(16384)` so we don't pre-allocate a large Vec
        let raw_matches_scratch = Vec::new();
        let user_data = UserData { raw_matches_scratch, input_len: 0 };
        let profiler = shared_profiler.or_else(|| {
            if enable_profiling { Some(Arc::new(ConcurrentRuleProfiler::new())) } else { None }
        });
        Ok(Matcher {
            scanner_pool,
            rules_db,
            local_stats: MatcherStats::default(),
            global_stats,
            seen_blobs,
            user_data,
            profiler,
            inline_ignore_config: if disable_inline_ignores {
                InlineIgnoreConfig::disabled()
            } else {
                InlineIgnoreConfig::new(extra_ignore_directives)
            },
            respect_ignore_if_contains,
        })
    }

    #[cfg(test)]
    fn scan_bytes_raw(&mut self, input: &[u8], _filename: &str) -> Result<()> {
        // Remember previous peak automatically
        let prev_capacity = self.user_data.raw_matches_scratch.capacity();
        self.user_data.raw_matches_scratch.clear();
        self.user_data.raw_matches_scratch.reserve(prev_capacity.max(64));

        self.user_data.input_len = input.len() as u64;

        let mut offset: usize = 0;
        while offset < input.len() {
            let end = (offset + MAX_CHUNK_SIZE).min(input.len());
            let slice = &input[offset..end];
            let base = offset as u64;
            self.scanner_pool.with(|scanner| {
                scanner.scan(slice, |rule_id, from, to, _flags| {
                    if (rule_id as usize) < self.rules_db.num_rules() {
                        self.user_data.raw_matches_scratch.push(RawMatch {
                            rule_id,
                            start_idx: from + base,
                            end_idx: to + base,
                        });
                    }
                    vectorscan_rs::Scan::Continue
                })
            })?;

            if end == input.len() {
                break;
            }
            offset = end.saturating_sub(CHUNK_OVERLAP);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_and_process_raw_matches<'b>(
        &mut self,
        blob: &'b Blob,
        origin: &OriginSet,
        filename: &str,
        redact: bool,
        matches: &mut Vec<BlobMatch<'b>>,
        previous_matches: &mut FxHashMap<usize, Vec<OffsetSpan>>,
        seen_matches: &mut FxHashSet<u64>,
        match_rule_indices: &mut Vec<usize>,
        betterleaks_path_prefiltered: bool,
    ) -> Result<()>
    where
        'a: 'b,
    {
        let input = blob.bytes();
        self.user_data.input_len = input.len() as u64;

        // Build the same overlapping ranges as `scan_bytes_raw`, then process them in reverse.
        // The old implementation collected every raw match and iterated that Vec in reverse;
        // reversing ranges preserves that ordering while bounding scratch to one segment.
        let mut ranges = Vec::new();
        let mut offset = 0;
        while offset < input.len() {
            let end = (offset + MAX_CHUNK_SIZE).min(input.len());
            ranges.push(offset..end);
            if end == input.len() {
                break;
            }
            offset = end.saturating_sub(CHUNK_OVERLAP);
        }

        let mut seen_raw_match_ends: FxHashSet<(usize, usize)> = FxHashSet::default();
        let mut seen_prefilter_rules: FxHashSet<usize> = FxHashSet::default();
        let mut previous_full_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        for range in ranges.into_iter().rev() {
            self.user_data.raw_matches_scratch.clear();
            let base = range.start as u64;
            self.scanner_pool.with(|scanner| {
                scanner.scan(&input[range], |rule_id, from, to, _flags| {
                    if (rule_id as usize) < self.rules_db.num_rules() {
                        self.user_data.raw_matches_scratch.push(RawMatch {
                            rule_id,
                            start_idx: from + base,
                            end_idx: to + base,
                        });
                    }
                    vectorscan_rs::Scan::Continue
                })
            })?;

            self.process_raw_matches(
                blob,
                origin,
                filename,
                redact,
                matches,
                previous_matches,
                seen_matches,
                match_rule_indices,
                betterleaks_path_prefiltered,
                &mut seen_raw_match_ends,
                &mut seen_prefilter_rules,
                &mut previous_full_matches,
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_raw_matches<'b>(
        &self,
        blob: &'b Blob,
        origin: &OriginSet,
        filename: &str,
        redact: bool,
        matches: &mut Vec<BlobMatch<'b>>,
        previous_matches: &mut FxHashMap<usize, Vec<OffsetSpan>>,
        seen_matches: &mut FxHashSet<u64>,
        match_rule_indices: &mut Vec<usize>,
        betterleaks_path_prefiltered: bool,
        seen_raw_match_ends: &mut FxHashSet<(usize, usize)>,
        seen_prefilter_rules: &mut FxHashSet<usize>,
        previous_full_matches: &mut FxHashMap<usize, Vec<OffsetSpan>>,
    ) where
        'a: 'b,
    {
        let rules_db = self.rules_db;
        for &RawMatch { rule_id, start_idx, end_idx } in
            self.user_data.raw_matches_scratch.iter().rev()
        {
            let rule_id_usize: usize = rule_id as usize;
            if betterleaks_path_prefiltered && rules_db.is_betterleaks_rule(rule_id_usize) {
                continue;
            }
            let rule = Arc::clone(&rules_db.rules()[rule_id_usize]);
            let re = &rules_db.anchored_regexes()[rule_id_usize];
            let end_idx_usize = end_idx as usize;
            let _ = start_idx; // Vectorscan block mode does not provide a reliable start offset.
            let (mut scan_start, scan_end) = if rules_db.uses_vectorscan_prefilter(rule_id_usize) {
                if !seen_prefilter_rules.insert(rule_id_usize) {
                    continue;
                }
                // Vectorscan PREFILTER guarantees candidate coverage but not exact end offsets.
                // Confirm the rule once against the complete blob after its first candidate.
                (0, blob.len())
            } else {
                if !seen_raw_match_ends.insert((rule_id_usize, end_idx_usize)) {
                    continue;
                }
                if previous_full_matches.get(&rule_id_usize).is_some_and(|spans| {
                    spans.iter().any(|span| span.start < end_idx_usize && end_idx_usize <= span.end)
                }) {
                    continue;
                }
                (end_idx_usize.saturating_sub(RAW_MATCH_LOOKBACK), end_idx_usize)
            };
            if !rule.matches_path(filename) {
                continue;
            }
            let before_len = matches.len();
            loop {
                let confirmed = filter_match(
                    rules_db,
                    blob,
                    Arc::clone(&rule),
                    re,
                    scan_start,
                    scan_end,
                    matches,
                    Some(&mut *previous_full_matches),
                    previous_matches,
                    rule_id_usize,
                    seen_matches,
                    origin,
                    None,
                    false,
                    redact,
                    filename,
                    self.profiler.as_ref(),
                    self.respect_ignore_if_contains,
                    &self.inline_ignore_config,
                    !rules_db.uses_vectorscan_prefilter(rule_id_usize),
                );
                if confirmed || scan_start == 0 {
                    break;
                }

                // Ordinary candidates keep the bounded confirmation path. Only a failed exact
                // scan widens toward the start of the blob, so matches have no lookback limit.
                let lookback = scan_end - scan_start;
                scan_start = scan_end.saturating_sub(lookback.saturating_mul(2));
            }
            match_rule_indices
                .extend(std::iter::repeat_n(rule_id_usize, matches.len() - before_len));
        }
    }

    pub fn scan_blob<'b>(
        &mut self,
        blob: &'b Blob,
        origin: &OriginSet,
        lang: Option<String>,
        redact: bool,
        no_dedup: bool,
        no_base64: bool,
    ) -> Result<ScanResult<'b>>
    where
        'a: 'b,
    {
        // Update local stats
        self.local_stats.blobs_seen += 1;
        self.local_stats.bytes_seen += blob.bytes().len() as u64;

        // Preserve the complete source path for path expressions and filters. A deduplicated blob
        // may have several origins; Betterleaks candidates survive when any path survives its
        // global source prefilter, while rules from other sources are never governed by it.
        let mut filename = None;
        let mut saw_path = false;
        let mut betterleaks_path_prefiltered = true;
        for candidate in origin.iter().filter_map(|item| item.blob_path()) {
            saw_path = true;
            let candidate = candidate.to_string_lossy().into_owned();
            if filename.is_none() {
                filename = Some(candidate.clone());
            }
            if !self.rules_db.is_path_prefiltered(&candidate)? {
                filename = Some(candidate);
                betterleaks_path_prefiltered = false;
                break;
            }
        }
        let filename = filename.unwrap_or_else(|| "unknown_file".to_string());
        if !saw_path {
            betterleaks_path_prefiltered = self.rules_db.is_path_prefiltered(&filename)?;
        }
        if betterleaks_path_prefiltered && !self.rules_db.has_non_betterleaks_rules() {
            return Ok(ScanResult::New(Vec::new()));
        }
        self.local_stats.blobs_scanned += 1;
        self.local_stats.bytes_scanned += blob.bytes().len() as u64;
        // Opportunistically look for standalone Base64 blobs. If neither
        // the raw scan nor this check yields anything, we can return early
        // before doing any heavier work.
        let mut b64_items = if no_base64 || blob.len() > BASE64_SCAN_LIMIT {
            Vec::new()
        } else {
            get_b64_strings(blob.bytes())
        };

        let lang_hint = lang.as_deref();
        let mut seen_matches = FxHashSet::default();
        let mut previous_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();
        let mut match_rule_indices: Vec<usize> = Vec::new();

        let blob_len = blob.len();
        let mut matches = Vec::new();
        self.scan_and_process_raw_matches(
            blob,
            origin,
            &filename,
            redact,
            &mut matches,
            &mut previous_matches,
            &mut seen_matches,
            &mut match_rule_indices,
            betterleaks_path_prefiltered,
        )?;
        if matches.is_empty() && b64_items.is_empty() {
            return Ok(ScanResult::New(Vec::new()));
        }

        if !no_base64 {
            let rules_db = self.rules_db;
            // If the blob contains standalone Base64 blobs, decode and scan them as well
            const MAX_B64_DEPTH: usize = 2; // decode at most two levels deep
            let mut b64_stack: Vec<(DecodedData, usize)> =
                b64_items.drain(..).map(|d| (d, 0)).collect();
            while let Some((item, depth)) = b64_stack.pop() {
                let mut candidate_rule_ids = Vec::new();
                let mut seen_candidate_rules = FxHashSet::default();
                self.scanner_pool.with(|scanner| {
                    scanner.scan(&item.decoded, |rule_id, _from, _to, _flags| {
                        let rule_id = rule_id as usize;
                        if rule_id < rules_db.num_rules() && seen_candidate_rules.insert(rule_id) {
                            candidate_rule_ids.push(rule_id);
                        }
                        vectorscan_rs::Scan::Continue
                    })
                })?;
                for rule_id_usize in candidate_rule_ids {
                    if betterleaks_path_prefiltered && rules_db.is_betterleaks_rule(rule_id_usize) {
                        continue;
                    }
                    let rule = &rules_db.rules()[rule_id_usize];
                    let re = &rules_db.anchored_regexes()[rule_id_usize];
                    let before_len = matches.len();
                    filter_match(
                        rules_db,
                        blob,
                        rule.clone(),
                        re,
                        item.pos_start,
                        item.pos_end,
                        &mut matches,
                        None,
                        &mut previous_matches,
                        rule_id_usize,
                        &mut seen_matches,
                        origin,
                        Some(item.decoded.as_slice()),
                        true,
                        redact,
                        &filename,
                        self.profiler.as_ref(),
                        self.respect_ignore_if_contains,
                        &self.inline_ignore_config,
                        false,
                    );
                    match_rule_indices
                        .extend(std::iter::repeat_n(rule_id_usize, matches.len() - before_len));
                }
                if depth + 1 < MAX_B64_DEPTH {
                    for nested in get_b64_strings(item.decoded.as_slice()) {
                        b64_stack.push((
                            DecodedData {
                                decoded: nested.decoded,
                                pos_start: item.pos_start,
                                pos_end: item.pos_end,
                            },
                            depth + 1,
                        ));
                    }
                }
            }
        }

        maybe_apply_markup_context_gate(
            self.rules_db,
            blob,
            lang_hint,
            blob_len,
            &mut matches,
            &match_rule_indices,
        );
        associate_betterleaks_components(blob.bytes(), &mut matches);
        suppress_credential_uri_fallbacks(&mut matches);
        deduplicate_imported_catalog_matches(&mut matches);

        // Finalize
        if !no_dedup && !matches.is_empty() {
            let blob_id = blob.id();
            if let Some(had_matches) = self.seen_blobs.insert(blob_id, true) {
                return Ok(if had_matches {
                    ScanResult::SeenWithMatches
                } else {
                    ScanResult::SeenSansMatches
                });
            }
        }

        // --- opportunistic capacity cap ---------------------------------
        if self.user_data.raw_matches_scratch.capacity()
            > self.user_data.raw_matches_scratch.len() * 4
        {
            // Vec::shrink_to_fit may re-allocate, but we're about to leave scan_blob
            // so the cost is hidden off the hot path.
            self.user_data.raw_matches_scratch.shrink_to_fit();
        }

        Ok(ScanResult::New(matches))
    }
}

fn suppress_credential_uri_fallbacks(matches: &mut Vec<BlobMatch<'_>>) {
    let mut keep = vec![true; matches.len()];
    for (fallback_index, fallback) in matches.iter().enumerate() {
        if !fallback.rule.visible()
            || !fallback.rule.id().starts_with("betterleaks.")
            || !matches!(
                &fallback.rule.syntax().validation,
                Some(crate::rules::Validation::CredentialUri)
            )
            || fallback.matching_input.is_empty()
        {
            continue;
        }

        let has_specific_finding = matches.iter().enumerate().any(|(specific_index, specific)| {
            specific_index != fallback_index
                && specific.rule.visible()
                && specific.rule.id().starts_with("betterleaks.")
                && specific.rule.id() != fallback.rule.id()
                && specific.association_offset_span.start < fallback.association_offset_span.end
                && fallback.association_offset_span.start < specific.association_offset_span.end
                && specific
                    .matching_input
                    .windows(fallback.matching_input.len())
                    .any(|window| window == fallback.matching_input)
        });
        if has_specific_finding {
            keep[fallback_index] = false;
        }
    }

    let mut index = 0;
    matches.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

fn deduplicate_imported_catalog_matches(matches: &mut Vec<BlobMatch<'_>>) {
    let mut keep = vec![true; matches.len()];
    for left in 0..matches.len() {
        if !keep[left] || !matches[left].rule.visible() {
            continue;
        }
        let left_catalog = imported_catalog(matches[left].rule.id());
        let Some(left_catalog) = left_catalog else { continue };
        for right in (left + 1)..matches.len() {
            if !keep[right]
                || !matches[right].rule.visible()
                || matches[left].matching_input_offset_span
                    != matches[right].matching_input_offset_span
            {
                continue;
            }
            let Some(right_catalog) = imported_catalog(matches[right].rule.id()) else {
                continue;
            };
            if left_catalog == right_catalog {
                continue;
            }
            let left_rank = imported_rule_rank(matches[left].rule.as_ref());
            let right_rank = imported_rule_rank(matches[right].rule.as_ref());
            if right_rank > left_rank {
                keep[left] = false;
                break;
            }
            keep[right] = false;
        }
    }
    let mut index = 0;
    matches.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

fn imported_catalog(rule_id: &str) -> Option<bool> {
    if rule_id.starts_with("betterleaks.") {
        Some(true)
    } else if rule_id.starts_with("veles.") {
        Some(false)
    } else {
        None
    }
}

fn imported_rule_rank(rule: &Rule) -> (bool, bool) {
    (rule.syntax().validation.is_some(), rule.id().starts_with("betterleaks."))
}

#[derive(Clone, Copy, Default)]
struct ComponentWindow {
    cols_before: usize,
    cols_after: usize,
    lines_before: usize,
    lines_after: usize,
    has_lines: bool,
}

fn parse_component_window(value: &str) -> Option<ComponentWindow> {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Some(ComponentWindow::default());
    }

    let mut window = ComponentWindow::default();
    for token in value.split(',').map(str::trim) {
        let (direction, amount_and_unit) = match token.as_bytes().first() {
            Some(b'+' | b'-') => (token.as_bytes()[0], &token[1..]),
            _ => (b' ', token),
        };
        let (amount, is_lines) = match amount_and_unit.as_bytes().last() {
            Some(b'L' | b'l') => (&amount_and_unit[..amount_and_unit.len() - 1], true),
            Some(b'C' | b'c') => (&amount_and_unit[..amount_and_unit.len() - 1], false),
            _ => (amount_and_unit, false),
        };
        let mut amount = amount.parse::<usize>().ok()?;
        if is_lines {
            amount = amount.saturating_sub(1);
            window.has_lines = true;
            if direction != b'+' {
                window.lines_before = window.lines_before.max(amount);
            }
            if direction != b'-' {
                window.lines_after = window.lines_after.max(amount);
            }
        } else {
            if direction != b'+' {
                window.cols_before = window.cols_before.max(amount);
            }
            if direction != b'-' {
                window.cols_after = window.cols_after.max(amount);
            }
        }
    }
    Some(window)
}

fn component_is_within(
    bytes: &[u8],
    line_starts: &[usize],
    primary: OffsetSpan,
    component: OffsetSpan,
    within: &str,
) -> bool {
    let Some(window) = parse_component_window(within) else {
        return false;
    };
    if within.trim().is_empty() || within.trim() == "0" {
        return true;
    }

    if !window.has_lines {
        return component.start >= primary.start.saturating_sub(window.cols_before)
            && component.start < primary.end.saturating_add(window.cols_after).min(bytes.len());
    }

    let line =
        |offset: usize| line_starts.partition_point(|start| *start <= offset).saturating_sub(1);
    let primary_start_line = line(primary.start);
    let primary_end_line = line(primary.end);
    let component_line = line(component.start);
    if component_line < primary_start_line.saturating_sub(window.lines_before)
        || component_line > primary_end_line.saturating_add(window.lines_after)
    {
        return false;
    }
    if primary_start_line == primary_end_line && (window.cols_before > 0 || window.cols_after > 0) {
        let column = |offset: usize| {
            let line = line(offset);
            offset.saturating_sub(line_starts.get(line).copied().unwrap_or_default())
        };
        let component_column = column(component.start);
        return component_column >= column(primary.start).saturating_sub(window.cols_before)
            && component_column < column(primary.end).saturating_add(window.cols_after);
    }
    true
}

fn span_distance(left: OffsetSpan, right: OffsetSpan) -> usize {
    if left.end <= right.start {
        right.start - left.end
    } else if right.end <= left.start {
        left.start.saturating_sub(right.end)
    } else {
        0
    }
}

fn associate_betterleaks_components<'a>(bytes: &[u8], matches: &mut Vec<BlobMatch<'a>>) {
    if !matches.iter().any(|finding| {
        finding.rule.syntax().depends_on_rule.iter().flatten().any(|dep| dep.within.is_some())
    }) {
        return;
    }
    let mut line_starts = vec![0];
    line_starts.extend(
        bytes.iter().enumerate().filter(|(_, byte)| **byte == b'\n').map(|(index, _)| index + 1),
    );

    let mut keep = vec![true; matches.len()];
    loop {
        let mut changed = false;
        for (primary_index, primary) in matches.iter().enumerate() {
            if !keep[primary_index] {
                continue;
            }
            for dependency in primary.rule.syntax().depends_on_rule.iter().flatten() {
                let Some(within) = dependency.within.as_deref() else {
                    continue;
                };
                let found = matches.iter().enumerate().any(|(candidate_index, candidate)| {
                    keep[candidate_index]
                        && candidate.rule.id() == dependency.rule_id
                        && component_is_within(
                            bytes,
                            &line_starts,
                            primary.association_offset_span,
                            candidate.association_offset_span,
                            within,
                        )
                });
                if !found && !dependency.optional {
                    keep[primary_index] = false;
                    changed = true;
                    break;
                }
            }
        }
        if !changed {
            break;
        }
    }

    let mut associated = vec![std::collections::BTreeMap::new(); matches.len()];
    for (primary_index, primary) in matches.iter().enumerate().filter(|(index, _)| keep[*index]) {
        for dependency in primary.rule.syntax().depends_on_rule.iter().flatten() {
            let Some(within) = dependency.within.as_deref() else {
                continue;
            };
            if let Some(component) = matches
                .iter()
                .enumerate()
                .filter(|(index, candidate)| {
                    keep[*index]
                        && candidate.rule.id() == dependency.rule_id
                        && component_is_within(
                            bytes,
                            &line_starts,
                            primary.association_offset_span,
                            candidate.association_offset_span,
                            within,
                        )
                })
                .map(|(_, candidate)| candidate)
                .min_by_key(|candidate| {
                    span_distance(
                        primary.association_offset_span,
                        candidate.association_offset_span,
                    )
                })
            {
                let value = component.captures.captures.first().map_or_else(
                    || String::from_utf8_lossy(component.matching_input).into_owned(),
                    |capture| capture.raw_value().to_string(),
                );
                associated[primary_index].insert(dependency.variable.to_uppercase(), value);
            }
        }
    }

    let mut index = 0;
    matches.retain_mut(|finding| {
        finding.dependent_captures.append(&mut associated[index]);
        let retain = keep[index];
        index += 1;
        retain
    });
}

/// Apply parser-based context verification only for HTML and CSS blobs.
///
/// HTML and CSS are the one regime where regex can't easily express
/// "this capture is in a real value position" — attribute values, CSS
/// property values, and nested script/style content need structural
/// understanding. For every other language (and for blobs without a
/// language hint, e.g. logs, binaries), this function is a no-op.
///
/// Self-identifying rules (matched by literal shape — `GHP_`, `AIzaSy`,
/// `xox[pbarose]`, PEM envelopes, Slack webhook URLs, etc.) bypass the
/// gate even in HTML/CSS so plain-prose leaks are still caught.
///
/// The gate is subtractive only when the parser actually runs and rejects
/// a match. If the parser is unavailable (too-large blob, parser error),
/// all matches are kept — never silently dropped.
fn maybe_apply_markup_context_gate<'a>(
    rules_db: &RulesDatabase,
    blob: &'a Blob,
    lang_hint: Option<&str>,
    blob_len: usize,
    matches: &mut Vec<BlobMatch<'a>>,
    match_rule_indices: &[usize],
) {
    if matches.is_empty() {
        return;
    }
    if !should_attempt_context_verification(blob_len) {
        return;
    }
    let Some(hint) = lang_hint else {
        return;
    };
    let language = match Language::from_hint(hint) {
        Some(lang @ (Language::Html | Language::Css)) => lang,
        _ => return,
    };

    let candidate_indices: Vec<usize> = matches
        .iter()
        .enumerate()
        .filter(|(idx, m)| {
            if m.is_base64 {
                return false;
            }
            match match_rule_indices.get(*idx) {
                Some(rule_idx) => !rules_db.is_rule_self_identifying(*rule_idx),
                None => false,
            }
        })
        .map(|(idx, _)| idx)
        .collect();

    if candidate_indices.is_empty() {
        return;
    }

    let mut remaining = candidate_indices.clone();
    let verification = parser::stream_context_candidates(blob.bytes(), &language, |text| {
        remaining.retain(|idx| {
            let Some(rule_idx) = match_rule_indices.get(*idx).copied() else {
                return false;
            };
            let Some(rule) = rules_db.get_rule(rule_idx) else {
                return false;
            };
            let re = &rules_db.anchored_regexes()[rule_idx];
            let expected_secret = matches[*idx].matching_input;
            !verify_match_in_context_text(
                re,
                expected_secret,
                text.as_bytes(),
                rule.betterleaks_secret_group(),
            )
        });
        !remaining.is_empty()
    });

    if let Err(e) = verification {
        debug!("HTML/CSS context verification unavailable: {e}");
        return;
    }

    if remaining.is_empty() {
        return;
    }

    let mut keep = vec![true; matches.len()];
    for idx in remaining {
        keep[idx] = false;
    }
    let mut filtered = Vec::with_capacity(matches.len());
    for (idx, item) in std::mem::take(matches).into_iter().enumerate() {
        if keep[idx] {
            filtered.push(item);
        }
    }
    *matches = filtered;
}

fn verify_match_in_context_text(
    re: &regex::bytes::Regex,
    expected_secret: &[u8],
    text: &[u8],
    betterleaks_secret_group: Option<usize>,
) -> bool {
    re.captures_iter(text).any(|captures| {
        find_secret_capture_with_group(re, &captures, betterleaks_secret_group).as_bytes()
            == expected_secret
    })
}

// -------------------------------------------------------------------------------------------------
// test
// -------------------------------------------------------------------------------------------------
#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, path::PathBuf};

    use pretty_assertions::assert_eq;
    // ---------------------------------------------------------------------
    // proptest: raw-match dedup + entropy gate
    // ---------------------------------------------------------------------
    use proptest::prelude::*;

    use super::*;
    use crate::{
        blob::{Blob, BlobIdMap},
        entropy::calculate_shannon_entropy,
        origin::{Origin, OriginSet},
        rules::rule::{
            Confidence, DependsOnRule, HttpRequest, HttpValidation, PatternRequirements,
            RuleSyntax, Validation,
        },
    };

    type TestFinding = (String, Confidence, Option<String>, bool);

    fn scan_test_rules(rules: Vec<Rule>, input: &[u8]) -> Result<Vec<TestFinding>> {
        let rules_db = RulesDatabase::from_rules(rules)?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
        let blob = Blob::from_bytes(input.to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("compatibility.txt")));
        let ScanResult::New(matches) =
            matcher.scan_blob(&blob, &origin, None, false, true, true)?
        else {
            panic!("deduplication is disabled");
        };
        Ok(matches
            .iter()
            .map(|finding| {
                (
                    finding.rule.id().to_string(),
                    finding.rule.confidence(),
                    finding.dependent_captures.get("COMPONENT").cloned(),
                    finding.rule.visible(),
                )
            })
            .collect())
    }

    fn compatibility_rule(
        id: &str,
        pattern: &str,
        confidence: Confidence,
        filter: Option<crate::rules::BetterleaksExpr>,
        dependencies: Vec<DependsOnRule>,
        visible: bool,
    ) -> Rule {
        Rule::new(RuleSyntax {
            id: id.into(),
            name: id.into(),
            pattern: pattern.into(),
            confidence,
            min_entropy: 0.0,
            visible,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: dependencies.into_iter().map(Some).collect(),
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: filter,
            betterleaks_secret_group: Some(1),
            authoritative: true,
            vectorscan_compatible: true,
        })
    }

    fn set_confidence_filter(confidence: &str) -> crate::rules::BetterleaksExpr {
        crate::rules::BetterleaksExpr::Sequence {
            nodes: vec![
                crate::rules::BetterleaksExpr::Call {
                    callee: Box::new(crate::rules::BetterleaksExpr::Identifier {
                        value: "setConfidence".into(),
                    }),
                    arguments: vec![crate::rules::BetterleaksExpr::String {
                        value: confidence.into(),
                    }],
                },
                crate::rules::BetterleaksExpr::Bool { value: false },
            ],
        }
    }

    #[test]
    fn dynamic_confidence_is_filtered_after_promotion_or_demotion() -> Result<()> {
        let mut promoted = compatibility_rule(
            "betterleaks.promoted",
            r"(PROMOTE_[A-Z0-9]{12})",
            Confidence::Low,
            Some(set_confidence_filter("high")),
            vec![],
            true,
        );
        promoted.set_runtime_confidence_filter(Confidence::Medium, false);
        let mut demoted = compatibility_rule(
            "betterleaks.demoted",
            r"(DEMOTE_[A-Z0-9]{12})",
            Confidence::Medium,
            Some(set_confidence_filter("low")),
            vec![],
            true,
        );
        demoted.set_runtime_confidence_filter(Confidence::Medium, false);

        let findings =
            scan_test_rules(vec![promoted, demoted], b"PROMOTE_123456ABCDEF DEMOTE_123456ABCDEF")?;
        assert_eq!(findings, [("betterleaks.promoted".to_string(), Confidence::High, None, true)]);
        Ok(())
    }

    #[test]
    fn required_betterleaks_components_enforce_line_and_byte_windows() -> Result<()> {
        let helper = compatibility_rule(
            "betterleaks.component",
            r"(COMP_[A-Z0-9]{8})",
            Confidence::Medium,
            None,
            vec![],
            false,
        );
        let primary = compatibility_rule(
            "betterleaks.primary",
            r"(PRIMARY_[A-Z0-9]{8})",
            Confidence::High,
            None,
            vec![DependsOnRule {
                rule_id: "betterleaks.component".into(),
                variable: "COMPONENT".into(),
                optional: false,
                within: Some("5L".into()),
            }],
            true,
        );

        let near = scan_test_rules(
            vec![helper.clone(), primary.clone()],
            b"COMP_FAR00000\none\ntwo\nthree\nfour\nPRIMARY_ABCDEFGH\nCOMP_NEAR0000",
        )?;
        assert!(near.iter().any(|(id, _, associated, _)| {
            id == "betterleaks.primary" && associated.as_deref() == Some("COMP_NEAR0000")
        }));
        assert!(
            near.iter().any(|(id, _, _, visible)| { id == "betterleaks.component" && !visible })
        );

        let far = scan_test_rules(
            vec![helper.clone(), primary],
            b"COMP_12345678\none\ntwo\nthree\nfour\nPRIMARY_ABCDEFGH",
        )?;
        assert!(!far.iter().any(|(id, _, _, _)| id == "betterleaks.primary"));

        let byte_primary = compatibility_rule(
            "betterleaks.byte-primary",
            r"(BYTEPRIMARY_[A-Z0-9]{8})",
            Confidence::High,
            None,
            vec![DependsOnRule {
                rule_id: "betterleaks.component".into(),
                variable: "COMPONENT".into(),
                optional: false,
                within: Some("8C".into()),
            }],
            true,
        );
        let near = scan_test_rules(
            vec![helper.clone(), byte_primary.clone()],
            b"BYTEPRIMARY_ABCDEFGH COMP_12345678",
        )?;
        assert!(near.iter().any(|(id, _, associated, _)| {
            id == "betterleaks.byte-primary" && associated.as_deref() == Some("COMP_12345678")
        }));
        let far = scan_test_rules(
            vec![helper, byte_primary],
            b"BYTEPRIMARY_ABCDEFGH -------- COMP_12345678",
        )?;
        assert!(!far.iter().any(|(id, _, _, _)| id == "betterleaks.byte-primary"));
        Ok(())
    }

    #[test]
    fn aws_access_key_is_retained_when_used_by_a_session_token() -> Result<()> {
        let access_key = compatibility_rule(
            "betterleaks.aws-access-token",
            r"(ASIA[A-Z0-9]{16})",
            Confidence::High,
            None,
            vec![],
            true,
        );
        let secret_key = compatibility_rule(
            "betterleaks.aws-secret-access-key",
            r"(SECRET_[A-Z0-9]{8})",
            Confidence::High,
            None,
            vec![],
            false,
        );
        let session_token = compatibility_rule(
            "betterleaks.aws-session-token",
            r"(AWS_SESSION_TOKEN=[A-Za-z0-9]{16})",
            Confidence::Medium,
            None,
            vec![
                DependsOnRule {
                    rule_id: "betterleaks.aws-access-token".into(),
                    variable: "AKID".into(),
                    optional: false,
                    within: Some("5L".into()),
                },
                DependsOnRule {
                    rule_id: "betterleaks.aws-secret-access-key".into(),
                    variable: "AWS_SECRET_ACCESS_KEY".into(),
                    optional: false,
                    within: Some("5L".into()),
                },
            ],
            true,
        );

        let temporary = scan_test_rules(
            vec![access_key.clone(), secret_key, session_token.clone()],
            b"AWS_ACCESS_KEY_ID=ASIA4XXC3LMYUK5SL77P\nAWS_SECRET_ACCESS_KEY=SECRET_A1B2C3D4\nAWS_SESSION_TOKEN=Ab9xQ7mN2kLp4RsT",
        )?;
        assert_eq!(
            temporary.iter().filter(|(id, ..)| id == "betterleaks.aws-access-token").count(),
            1,
            "temporary findings: {temporary:?}"
        );
        assert!(
            temporary
                .iter()
                .any(|(id, _, _, visible)| { id == "betterleaks.aws-session-token" && *visible }),
            "temporary findings: {temporary:?}"
        );

        let static_key =
            scan_test_rules(vec![access_key], b"AWS_ACCESS_KEY_ID=ASIA4XXC3LMYUK5SL77P")?;
        assert!(
            static_key
                .iter()
                .any(|(id, _, _, visible)| { id == "betterleaks.aws-access-token" && *visible })
        );
        Ok(())
    }

    #[test]
    fn old_yaml_dependency_without_within_does_not_suppress_primary() -> Result<()> {
        let primary = compatibility_rule(
            "custom.legacy-primary",
            r"(LEGACY_[A-Z0-9]{8})",
            Confidence::High,
            None,
            vec![DependsOnRule {
                rule_id: "custom.missing".into(),
                variable: "COMPONENT".into(),
                optional: false,
                within: None,
            }],
            true,
        );
        let findings = scan_test_rules(vec![primary], b"LEGACY_12345678")?;
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    proptest! {
        #[test]
        fn prop_no_dupes_and_entropy(
            // random ASCII up to 300 bytes
            mut noise in proptest::collection::vec(any::<u8>().prop_filter("ascii", |b| b.is_ascii()), 0..300),
            // 0-4 random insertion points
            inserts in proptest::collection::vec(0usize..300, 0..5)
        ) {
            // Constant high-entropy secret token that matches the rule below
            const TOKEN: &[u8] = b"secret_abcd1234";

            // Splice the token at the requested offsets
            for &idx in &inserts {
                let pos = idx.min(noise.len());
                noise.splice(pos..pos, TOKEN.iter().copied());
            }

            // ── build a single test rule ──────────────────────────────────
            use crate::rules::rule::{RuleSyntax, Validation, Confidence};

            let rule = Rule::new(RuleSyntax {
                id: "prop.secret".into(),
                name: "prop secret".into(),
                pattern: "secret_[a-z]{4}[0-9]{4}".into(),
                confidence: Confidence::Low,
                min_entropy: 3.0,
                visible: true,
                examples: vec![],
                negative_examples: vec![],
                references: vec![],
                validation: None::<Validation>,          // no HTTP validation needed
                revocation: None,
                depends_on_rule: vec![],
                pattern_requirements: None,
                tls_mode: None,
                path: None,
                betterleaks_filter: None,
                betterleaks_secret_group: None,
                authoritative: true,
                vectorscan_compatible: true,
            });

            let rules_db  = RulesDatabase::from_rules(vec![rule]).unwrap();
            let seen      = BlobIdMap::new();
            let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
            let mut m     = Matcher::new(
                &rules_db,
                scanner_pool,
                &seen,
                None,
                false,
                None,
                &[],
                false,
                true,
            )
            .unwrap();

            // ── run the scan ──────────────────────────────────────────────
            m.scan_bytes_raw(&noise, "buf").unwrap();

            // ── property 1: dedup – each (rule,start,end) is unique ──────

            let mut coords = FxHashSet::default();
            for RawMatch{rule_id, start_idx, end_idx} in &m.user_data.raw_matches_scratch {
                assert!(
                    coords.insert((*rule_id, *start_idx, *end_idx)),
                    "duplicate raw-match detected for coords ({rule_id},{start_idx},{end_idx})"
                );

                // ── property 2: entropy gate held ────────────────────────
                let slice = &noise[*start_idx as usize .. *end_idx as usize];
                let ent   = calculate_shannon_entropy(slice);
                assert!(ent > 3.0, "entropy {ent} ≤ min_entropy, gate failed");
            }
        }
    }

    #[test]
    pub fn test_simple() -> Result<()> {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.1".to_string(),
            name: "test".to_string(),
            pattern: "test".to_string(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 1.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: Some(Validation::Http(HttpValidation {
                request: HttpRequest {
                    method: "GET".to_string(),
                    url: "https://example.com".to_string(),
                    headers: BTreeMap::new(),
                    body: None,
                    response_matcher: Some(vec![]),
                    multipart: None,
                    response_is_html: false,
                },
                multipart: None,
            })),
            revocation: None,
            depends_on_rule: vec![
                Some(DependsOnRule {
                    rule_id: "d8f3c34b-015f-4cd6-b411-b1366493104c".to_string(),
                    variable: "email".to_string(),
                    optional: false,
                    within: None,
                }),
                Some(DependsOnRule {
                    rule_id: "8910f364-7718-4a27-a435-d2da13e6ba9e".to_string(),
                    variable: "domain".to_string(),
                    optional: false,
                    within: None,
                }),
            ],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })];
        let rules_db = RulesDatabase::from_rules(rules)?;
        let input = "some test data for vectorscan";
        let seen_blobs: BlobIdMap<bool> = BlobIdMap::new();
        let enable_rule_profiling = true;
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            enable_rule_profiling,
            None, // Pass the shared profiler
            &[],
            false,
            true,
        )?;
        matcher.scan_bytes_raw(input.as_bytes(), "fname")?;
        assert_eq!(
            matcher.user_data.raw_matches_scratch,
            vec![RawMatch { rule_id: 0, start_idx: 0, end_idx: 9 },]
        );
        Ok(())
    }

    #[test]
    fn test_pattern_requirements_ignore_if_contains_filters_matches() -> Result<()> {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.exclude".to_string(),
            name: "exclude words".to_string(),
            pattern: "(?P<token>prefix[A-Za-z]+)".to_string(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: Some(PatternRequirements {
                min_digits: None,
                min_uppercase: None,
                min_lowercase: None,
                min_special_chars: None,
                special_chars: None,
                ignore_if_contains: Some(vec!["TEST".to_string()]),
                checksum: None,
            }),
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })];

        let rules_db = RulesDatabase::from_rules(rules)?;
        let input = b"prefixgood prefixtest";
        let seen_blobs: BlobIdMap<bool> = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            false,
            None,
            &[],
            false,
            true,
        )?;

        let blob = Blob::from_bytes(input.to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("exclude.txt")));

        let matches = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            ScanResult::SeenWithMatches => {
                panic!(
                    "unexpected scan result: blob should not be considered previously seen with matches"
                )
            }
            ScanResult::SeenSansMatches => {
                panic!(
                    "unexpected scan result: blob should not be considered previously seen without matches"
                )
            }
        };

        assert_eq!(matches.len(), 1, "ignore_if_contains should drop filtered matches");
        assert_eq!(
            matches[0].matching_input, b"prefixgood",
            "remaining match should be the non-excluded token",
        );

        Ok(())
    }

    #[test]
    fn test_pattern_requirements_ignore_if_contains_can_be_disabled_in_matcher() -> Result<()> {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.exclude".to_string(),
            name: "exclude words".to_string(),
            pattern: "(?P<token>prefix[A-Za-z]+)".to_string(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: Some(PatternRequirements {
                min_digits: None,
                min_uppercase: None,
                min_lowercase: None,
                min_special_chars: None,
                special_chars: None,
                ignore_if_contains: Some(vec!["TEST".to_string()]),
                checksum: None,
            }),
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })];

        let rules_db = RulesDatabase::from_rules(rules)?;
        let input = b"prefixgood prefixtest";
        let seen_blobs: BlobIdMap<bool> = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            false,
            None,
            &[],
            false,
            false,
        )?;

        let blob = Blob::from_bytes(input.to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("exclude-disabled.txt")));

        let matches = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            ScanResult::SeenWithMatches => {
                panic!(
                    "unexpected scan result: blob should not be considered previously seen with matches"
                )
            }
            ScanResult::SeenSansMatches => {
                panic!(
                    "unexpected scan result: blob should not be considered previously seen without matches"
                )
            }
        };

        assert_eq!(matches.len(), 2, "disabling ignore_if_contains should keep all matches");
        Ok(())
    }

    // ---------------------------------------------------------------------
    // additional deterministic unit-tests
    // ---------------------------------------------------------------------

    #[test]
    fn betterleaks_path_rules_receive_the_complete_source_path() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "custom.path-aware".into(),
            name: "path-aware test".into(),
            pattern: r"(secret_[a-z0-9]{8})".into(),
            path: Some(r"(?:^|/)src/nested/config\.txt$".into()),
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
            confidence: Confidence::High,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen_blobs = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher = Matcher::new(
            &rules_db,
            scanner_pool,
            &seen_blobs,
            None,
            false,
            None,
            &[],
            false,
            true,
        )?;
        let blob = Blob::from_bytes(b"secret_abcd1234".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("src/nested/config.txt")));

        let ScanResult::New(matches) =
            matcher.scan_blob(&blob, &origin, None, false, false, false)?
        else {
            panic!("fresh blob should return a new scan result");
        };
        assert_eq!(matches.len(), 1);
        Ok(())
    }

    #[test]
    fn betterleaks_source_prefilter_only_gates_betterleaks_rules() -> Result<()> {
        let prefilter = crate::defaults::get_builtin_rules(None)?.betterleaks_prefilter;
        let rule = |id: &str, pattern: &str| {
            Rule::new(RuleSyntax {
                id: id.into(),
                name: format!("Rule {id}"),
                pattern: pattern.into(),
                path: None,
                betterleaks_filter: None,
                betterleaks_secret_group: None,
                authoritative: true,
                vectorscan_compatible: true,
                confidence: Confidence::High,
                min_entropy: 0.0,
                visible: true,
                examples: vec![],
                negative_examples: vec![],
                references: vec![],
                validation: None,
                revocation: None,
                depends_on_rule: vec![],
                pattern_requirements: None,
                tls_mode: None,
            })
        };
        let rules_db = RulesDatabase::from_rules_with_betterleaks_prefilter(
            vec![
                rule("betterleaks.path-prefilter-test", r"(betterleaks_[A-Za-z0-9]{16})"),
                rule("custom.path-prefilter-test", r"(toml_[A-Za-z0-9]{16})"),
                rule("private.path-prefilter-test", r"(yaml_[A-Za-z0-9]{16})"),
                rule("veles.test/pathprefilter", r"(veles_[A-Za-z0-9]{16})"),
            ],
            prefilter,
        )?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
        let blob = Blob::from_bytes(
            b"betterleaks_Q7mZ2pL9xR4vN8kT\ntoml_Q7mZ2pL9xR4vN8kT\n\
yaml_Q7mZ2pL9xR4vN8kT\nveles_Q7mZ2pL9xR4vN8kT"
                .to_vec(),
        );

        let source = OriginSet::from(Origin::from_file(PathBuf::from("src/config.rs")));
        let ScanResult::New(source_matches) =
            matcher.scan_blob(&blob, &source, None, false, true, true)?
        else {
            panic!("fresh blob should return a new scan result");
        };
        assert_eq!(source_matches.len(), 4);

        let excluded =
            OriginSet::from(Origin::from_file(PathBuf::from("node_modules/package/README.md")));
        let ScanResult::New(excluded_matches) =
            matcher.scan_blob(&blob, &excluded, None, false, true, true)?
        else {
            panic!("deduplication is disabled");
        };
        let mut excluded_ids =
            excluded_matches.iter().map(|item| item.rule.id()).collect::<Vec<_>>();
        excluded_ids.sort_unstable();
        assert_eq!(
            excluded_ids,
            vec![
                "custom.path-prefilter-test",
                "private.path-prefilter-test",
                "veles.test/pathprefilter",
            ]
        );
        Ok(())
    }

    /// `get_base64_strings` should recognise a well-formed token, decode it,
    /// and report correct byte-offsets.
    #[test]
    fn test_get_base64_strings_basic() {
        let base64_payload = b"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        let mut raw = b"foo ".to_vec();
        raw.extend_from_slice(base64_payload);
        raw.extend_from_slice(b" bar");
        // decodes to "0123456789abcdef0123456789abcdef"
        let hits = get_base64_strings(&raw);
        assert_eq!(hits.len(), 1);
        let item = &hits[0];
        assert_eq!(std::str::from_utf8(&item.decoded).unwrap(), "0123456789abcdef0123456789abcdef");
        // "foo␠" is 4 bytes, so the start offset is 4
        assert_eq!((item.pos_start, item.pos_end), (4, 4 + base64_payload.len()));
    }

    /// `compute_finding_fingerprint` must be stable (same input => same output)
    /// and sensitive to any input component.
    #[test]
    fn test_finding_fingerprint_stability_and_uniqueness() {
        let a = compute_finding_fingerprint("secret", "fileA", 0, 6);
        let b = compute_finding_fingerprint("secret", "fileA", 0, 6);
        assert_eq!(a, b, "fingerprint should be deterministic");

        // changing any parameter should perturb the hash
        let c = compute_finding_fingerprint("secret", "fileA", 1, 7); // offsets differ
        let d = compute_finding_fingerprint("secret", "fileB", 0, 6); // file id differs
        let e = compute_finding_fingerprint("different", "fileA", 0, 6); // content differs
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_ne!(a, e);
    }

    /// The (private) `compute_match_key` helper is the linchpin of the raw-dedup
    /// path.  It should return identical keys for identical inputs and different
    /// keys as soon as *anything* changes.
    #[test]
    fn test_compute_match_key_uniqueness() {
        use super::dedup::compute_match_key;

        let k1 = compute_match_key(b"abc", b"rule-1", 0, 3);
        let k2 = compute_match_key(b"abc", b"rule-1", 0, 3);
        assert_eq!(k1, k2);

        // mutate each component in turn
        let diff_content = compute_match_key(b"abcd", b"rule-1", 0, 4);
        let diff_rule = compute_match_key(b"abc", b"rule-2", 0, 3);
        let diff_span = compute_match_key(b"abc", b"rule-1", 1, 4);
        assert_ne!(k1, diff_content);
        assert_ne!(k1, diff_rule);
        assert_ne!(k1, diff_span);
    }

    /// Running `scan_bytes_raw` twice over the *same* input should never record
    /// duplicate entries in `raw_matches_scratch`.
    #[test]
    fn test_scan_bytes_raw_no_duplicate_raw_matches() -> Result<()> {
        // simple rule: literal "dup"
        let rule = Rule::new(RuleSyntax {
            id: "dup.check".into(),
            name: "dup".into(),
            pattern: "dup".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut m =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let buf = b"dup dup"; // two literal hits, same rule

        // first scan
        m.scan_bytes_raw(buf, "buf1")?;
        let first_len = m.user_data.raw_matches_scratch.len();

        // second scan over the same buffer
        m.scan_bytes_raw(buf, "buf1")?;
        let second_len = m.user_data.raw_matches_scratch.len();

        // we should still only have two unique raw matches recorded
        assert_eq!(first_len, 2);
        assert_eq!(second_len, 2);
        Ok(())
    }

    #[test]
    fn scan_blob_finds_matches_across_chunk_boundary() -> Result<()> {
        const TOKEN: &[u8] = b"chunk_boundary_token_7f3a9c";

        let rule = Rule::new(RuleSyntax {
            id: "chunk.boundary".into(),
            name: "chunk boundary".into(),
            pattern: String::from_utf8(TOKEN.to_vec()).unwrap(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let boundary_start = MAX_CHUNK_SIZE - TOKEN.len() / 2;
        let later_start = MAX_CHUNK_SIZE + CHUNK_OVERLAP + 128;
        let mut bytes = vec![b'x'; later_start + TOKEN.len() + 1];
        bytes[boundary_start..boundary_start + TOKEN.len()].copy_from_slice(TOKEN);
        bytes[later_start..later_start + TOKEN.len()].copy_from_slice(TOKEN);

        let blob = Blob::from_bytes(bytes);
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("chunk-boundary.txt")));
        let found = match matcher.scan_blob(&blob, &origin, None, false, false, true)? {
            ScanResult::New(found) => found,
            other => panic!(
                "expected new scan result, got {}",
                match other {
                    ScanResult::SeenWithMatches => "seen with matches",
                    ScanResult::SeenSansMatches => "seen without matches",
                    ScanResult::New(_) => unreachable!(),
                }
            ),
        };

        let mut starts: Vec<_> = found.iter().map(|m| m.matching_input_offset_span.start).collect();
        starts.sort_unstable();
        assert_eq!(starts, vec![boundary_start, later_start]);
        Ok(())
    }

    #[test]
    fn scan_blob_confirms_exact_matches_longer_than_initial_lookback() -> Result<()> {
        let token_rule = Rule::new(RuleSyntax {
            id: "betterleaks.1password-service-account-token-test".into(),
            name: "1Password service account token".into(),
            pattern: r"ops_eyJ[A-Za-z0-9+/]{250,}={0,3}".into(),
            confidence: Confidence::High,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: Some(0),
            authoritative: true,
            vectorscan_compatible: true,
        });
        let private_key_rule = Rule::new(RuleSyntax {
            id: "test.long-private-key".into(),
            name: "Long private key".into(),
            pattern: r"(-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/\n]+\n-----END PRIVATE KEY-----)"
                .into(),
            confidence: Confidence::High,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });
        let rules_db = RulesDatabase::from_rules(vec![token_rule, private_key_rule])?;
        assert!(!rules_db.uses_vectorscan_prefilter(0));
        assert!(!rules_db.uses_vectorscan_prefilter(1));

        const ALPHABET: &[u8] = b"A1b2C3d4E5f6G7h8I9j0K+L/MnOpQrStUvWxYz";
        let mut token = b"ops_eyJ".to_vec();
        token.extend(ALPHABET.iter().copied().cycle().take(6 * 1024));

        let key_body: Vec<u8> = ALPHABET
            .iter()
            .copied()
            .chain(std::iter::once(b'\n'))
            .cycle()
            .take(70 * 1024)
            .collect();
        let mut private_key = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
        private_key.extend_from_slice(&key_body);
        private_key.extend_from_slice(b"\n-----END PRIVATE KEY-----");

        let mut input = token.clone();
        input.push(b' ');
        input.extend_from_slice(&private_key);
        let blob = Blob::from_bytes(input);
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("long-secrets.txt")));
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let ScanResult::New(matches) =
            matcher.scan_blob(&blob, &origin, None, false, false, true)?
        else {
            panic!("fresh blob should return new matches");
        };
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().any(|matched| matched.matching_input == token));
        assert!(matches.iter().any(|matched| matched.matching_input == private_key));
        Ok(())
    }

    #[test]
    fn inline_comment_skips_match() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.ignore".into(),
            name: "inline".into(),
            pattern: "secret_token".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(b"let key = \"secret_token\" # kingfisher:ignore".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("inline.txt")));

        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }

    #[test]
    fn inline_comment_after_multiline_secret_skips_match() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.multiline".into(),
            name: "inline multiline".into(),
            pattern: "line1\\s+line2".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(
            br#"let data = """
line1
line2
"""
# kingfisher:ignore
"#
            .to_vec(),
        );
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("multiline.txt")));

        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }

    #[test]
    fn compat_flag_controls_external_directives() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "inline.compat".into(),
            name: "inline compat".into(),
            pattern: "supersecret123".into(),
            confidence: crate::rules::rule::Confidence::Low,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;

        let blob = Blob::from_bytes(b"token = \"supersecret123\" # gitleaks:allow".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("compat.txt")));

        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
        let matches_without_compat =
            match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
                ScanResult::New(matches) => matches.len(),
                _ => panic!("unexpected scan result"),
            };
        assert_eq!(matches_without_compat, 1, "directive should be ignored without compat flag");

        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let extra = vec![String::from("gitleaks:allow")];
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &extra, false, true)?;
        match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => assert!(matches.is_empty()),
            _ => panic!("unexpected scan result"),
        }

        Ok(())
    }

    #[test]
    fn serializes_captures_in_numeric_order() {
        use regex::bytes::Regex;

        let re =
            Regex::new(r"(?xi)\b(ghp_(?P<body>[A-Z0-9]{3})(?P<checksum>[A-Z0-9]{2}))").unwrap();
        let caps = re.captures(b"ghp_ABC12").expect("expected captures");

        let serialized = SerializableCaptures::from_captures(&caps, b"", &re);
        let entries: Vec<(Option<&str>, i32, &str)> =
            serialized.captures.iter().map(|cap| (cap.name, cap.match_number, cap.value)).collect();

        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0], (None, 1, "ghp_ABC12"));
        assert_eq!(entries[1], (Some("body"), 2, "ABC"));
        assert_eq!(entries[2], (Some("checksum"), 3, "12"));
    }

    #[test]
    fn serializes_betterleaks_secret_without_losing_named_capture() {
        use regex::bytes::Regex;

        let re = Regex::new(r"(?:(?P<optional>a)|b)(?P<secret>c)").unwrap();
        let caps = re.captures(b"bc").expect("expected captures");
        let serialized =
            SerializableCaptures::from_captures_with_secret_group(&caps, b"bc", &re, Some(0));
        let entries: Vec<(Option<&str>, i32, &str)> =
            serialized.captures.iter().map(|cap| (cap.name, cap.match_number, cap.value)).collect();

        assert_eq!(entries[0], (Some("TOKEN"), 2, "c"));
        assert_eq!(entries[1], (Some("secret"), 2, "c"));
    }

    #[test]
    fn parser_second_pass_keeps_verified_contextual_match() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rule = Rule::new(RuleSyntax {
            id: "custom.auth0.secret".into(),
            name: "auth0 secret".into(),
            pattern: "(?xi)\\bauth0(?:.|[\\n\\r]){0,16}?(?:secret|token)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9_-]{64,})\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let mut content = "x".repeat(1200);
        content.push_str(&format!("\nauth0_client_secret = \"{token}\"\n"));
        let blob = Blob::from_bytes(content.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("verified.py")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("python".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(found.len(), 1);
        Ok(())
    }

    #[test]
    fn parser_second_pass_suppresses_unverified_contextual_match() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rule = Rule::new(RuleSyntax {
            id: "custom.auth0.secret".into(),
            name: "auth0 secret".into(),
            pattern: "(?xi)\\bauth0(?:.|[\\n\\r]){0,16}?(?:secret|token)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9_-]{64,})\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let mut content = "x".repeat(1200);
        content.push_str(&format!("\n# auth0 secret {token}\n"));
        let blob = Blob::from_bytes(content.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("comment.py")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("python".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "raw regex matches should remain findings without classifier gating"
        );
        Ok(())
    }

    #[test]
    fn strict_context_rule_survives_without_classifier_gating() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rule = Rule::new(RuleSyntax {
            id: "custom.auth0.secret".into(),
            name: "auth0 secret".into(),
            pattern: "(?xi)\\bauth0(?:.|[\\n\\r]){0,16}?(?:secret|token)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9_-]{64,})\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let content = format!("auth0 token {token}");
        let blob = Blob::from_bytes(content.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("small.txt")));

        let found = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "strict contextual rules should still be reported without classifier gating"
        );
        Ok(())
    }

    #[test]
    fn assignment_style_context_rule_survives_when_context_verification_is_unavailable()
    -> Result<()> {
        let token = "xcexacEQFtULkSTDCXejdWy5ew8NyU9QJoip5a97TE7A";
        let rule = Rule::new(RuleSyntax {
            id: "custom.livekit.secret".into(),
            name: "livekit api secret".into(),
            pattern: "(?xi)\\b(?:LIVEKIT_API_SECRET|livekit_api_secret|livekit[-_]?secret|livekitSecret)\\s*[:=]\\s*['\"]?([A-Za-z0-9]{43,44})['\"]?\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(format!("LIVEKIT_API_SECRET={token}").into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("secrets.log")));

        let found = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "assignment-style contextual rules should still scan raw text without classifier gating"
        );
        Ok(())
    }

    #[test]
    fn depends_on_assignment_style_rule_survives_when_context_verification_is_unavailable()
    -> Result<()> {
        use crate::rules::rule::DependsOnRule;

        let token = "xcexacEQFtULkSTDCXejdWy5ew8NyU9QJoip5a97TE7A";
        let rule = Rule::new(RuleSyntax {
            id: "custom.livekit.secret".into(),
            name: "livekit api secret".into(),
            pattern: "(?xi)\\b(?:LIVEKIT_API_SECRET|livekit_api_secret|livekit[-_]?secret|livekitSecret)\\s*[:=]\\s*['\"]?([A-Za-z0-9]{43,44})['\"]?\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![Some(DependsOnRule {
                rule_id: "custom.livekit.url".into(),
                variable: "API_KEY".into(),
                optional: false,
                within: None,
            })],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(format!("LIVEKIT_API_SECRET={token}").into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("secrets.log")));

        let found = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "depends_on assignment-style rules should still scan raw text without classifier gating"
        );
        Ok(())
    }

    #[test]
    fn self_identifying_rule_remains_hyperscan_only() -> Result<()> {
        let token = "CCIPAT_FERZRjTN451xnDCy1y9gWn_79fb6ca4d0e5f833612eee17de397a9dca0a9e9f";
        let rule = Rule::new(RuleSyntax {
            id: "custom.circleci.token".into(),
            name: "circleci pat".into(),
            pattern: "(?x)\\b(CCIPAT_[A-Za-z0-9]{22}_[a-z0-9]{40})\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(format!("token={token}").into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("circleci.txt")));

        let found = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(found.len(), 1, "self-identifying tokens should remain raw-pass findings");
        Ok(())
    }

    #[test]
    fn self_identifying_charclass_prefix_rule_remains_hyperscan_only() -> Result<()> {
        let token = "xoxb-730191371696-1413868247813-IG7Z6nYevC2hdviE3aJhb5kY";
        let rule = Rule::new(RuleSyntax {
            id: "custom.slack.token".into(),
            name: "slack token".into(),
            pattern:
                "(?xi)\\b(xox[pbarose][-0-9]{0,3}-[0-9a-z]{6,15}-[0-9a-z]{6,15}-[-0-9a-z]{6,66})\\b"
                    .into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });

        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let blob = Blob::from_bytes(format!("token={token}").into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("slack.txt")));

        let found = match matcher.scan_blob(&blob, &origin, None, false, false, false)? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "self-identifying token families should still be reported without classifier gating"
        );
        Ok(())
    }

    fn generic_auth0_rule() -> Rule {
        Rule::new(RuleSyntax {
            id: "custom.auth0.secret".into(),
            name: "auth0 secret".into(),
            pattern: "(?xi)\\bauth0(?:.|[\\n\\r]){0,16}?(?:secret|token)(?:.|[\\n\\r]){0,64}?\\b([a-z0-9_-]{64,})\\b".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })
    }

    #[test]
    fn html_gate_drops_generic_contextual_match_outside_value_position() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rules_db = RulesDatabase::from_rules(vec![generic_auth0_rule()])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let body = format!("<html><body><!-- auth0 secret {token} --></body></html>");
        let blob = Blob::from_bytes(body.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("page.html")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("html".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert!(
            found.is_empty(),
            "HTML gate should drop generic contextual hits that sit outside any value position"
        );
        Ok(())
    }

    #[test]
    fn html_gate_keeps_generic_contextual_match_inside_script_assignment() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rules_db = RulesDatabase::from_rules(vec![generic_auth0_rule()])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let body = format!(
            "<html><body><script>const auth0_client_secret = \"{token}\";</script></body></html>"
        );
        let blob = Blob::from_bytes(body.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("app.html")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("html".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "HTML gate should keep generic contextual hits that appear inside a script assignment"
        );
        Ok(())
    }

    #[test]
    fn html_gate_does_not_affect_self_identifying_rule_in_prose() -> Result<()> {
        let rule = Rule::new(RuleSyntax {
            id: "custom.google.token".into(),
            name: "google api key".into(),
            pattern: "(?xi)\\b(AIzaSy[A-Za-z0-9_-]{33})".into(),
            confidence: crate::rules::rule::Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        });
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let body = "<html><body><p>Key: AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM</p></body></html>"
            .to_string();
        let blob = Blob::from_bytes(body.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("docs.html")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("html".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "self-identifying rules must bypass the HTML gate so prose leaks still fire"
        );
        Ok(())
    }

    #[test]
    fn html_gate_does_not_trigger_for_other_languages() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rules_db = RulesDatabase::from_rules(vec![generic_auth0_rule()])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        let body = format!("# auth0 secret {token}");
        let blob = Blob::from_bytes(body.into_bytes());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("notes.py")));

        let found = match matcher.scan_blob(
            &blob,
            &origin,
            Some("python".to_string()),
            false,
            false,
            false,
        )? {
            ScanResult::New(matches) => matches,
            _ => panic!("unexpected scan result"),
        };
        assert_eq!(
            found.len(),
            1,
            "non-HTML/CSS blobs must bypass the gate even when parser hint is available"
        );
        Ok(())
    }
}
