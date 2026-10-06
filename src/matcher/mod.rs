mod base64_decode;
mod candidate_context;
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
    inline_ignore::{InlineIgnoreConfig, InlineIgnoreIndex},
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
use kingfisher_scanner::primitives::{MatchSpans, find_secret_capture_with_group};

use self::{base64_decode::get_base64_strings as get_b64_strings, filter::filter_match};

const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MiB per scan segment
const CHUNK_OVERLAP: usize = 64 * 1024; // 64 KiB overlap to catch boundary matches
const RAW_MATCH_LOOKBACK: usize = 4 * 1024; // Initial exact-confirmation suffix.
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024; // skip expensive Base64 pass on huge blobs
// Bound structural context checks on large generated/minified content.
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
/// Candidate endpoints are buffered per scan segment for exact regex confirmation.
/// Block mode does not provide a reliable start offset; exact confirmation finds it.
#[derive(PartialEq, Eq, Debug, Clone)]
struct RawMatch {
    rule_id: u32,
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
    pub ambiguous_dependencies: std::collections::BTreeMap<String, usize>,
    pub dependency_candidates: std::collections::BTreeMap<String, Vec<String>>,
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
    resources: crate::limits::ResourceLimits,
    /// Thread-local pool that hands out a &mut BlockScanner
    scanner_pool: std::sync::Arc<crate::scanner_pool::ScannerPool>,

    /// The rules database used for matching
    rules_db: &'a RulesDatabase,

    /// Local statistics for this `Matcher`
    local_stats: MatcherStats,

    /// Global statistics, updated with the local statistics when this
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
    pub fn with_resource_limits(mut self, resources: crate::limits::ResourceLimits) -> Self {
        self.resources = resources;
        self
    }

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
        let raw_matches_scratch = Vec::new();
        let user_data = UserData { raw_matches_scratch, input_len: 0 };
        let profiler = shared_profiler.or_else(|| {
            if enable_profiling { Some(Arc::new(ConcurrentRuleProfiler::new())) } else { None }
        });
        Ok(Matcher {
            resources: crate::limits::ResourceLimits::default(),
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
            self.scanner_pool.try_with(|scanner| {
                scanner.scan(slice, |rule_id, _from, to, _flags| {
                    if (rule_id as usize) < self.rules_db.num_rules() {
                        self.user_data
                            .raw_matches_scratch
                            .push(RawMatch { rule_id, end_idx: to + base });
                    }
                    kingfisher_vectorscan::Scan::Continue
                })
            })??;

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
        previous_matches: &mut FxHashMap<usize, MatchSpans>,
        seen_matches: &mut FxHashSet<u64>,
        match_rule_indices: &mut Vec<usize>,
        betterleaks_path_prefiltered: bool,
        inline_ignore_index: &std::sync::OnceLock<InlineIgnoreIndex>,
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
        let mut previous_full_matches: FxHashMap<usize, MatchSpans> = FxHashMap::default();
        let mut filter_line_cache =
            kingfisher_rules::betterleaks_filter::BetterleaksFilterLineCache::default();

        for range in ranges.into_iter().rev() {
            // Index only this segment and the initial confirmation lookback. Drop the indexes
            // after processing it so dense inputs cannot accumulate whole-blob regex spans.
            let mut candidate_indexes = FxHashMap::default();
            let index_range = range.start.saturating_sub(RAW_MATCH_LOOKBACK)..range.end;
            self.user_data.raw_matches_scratch.clear();
            let base = range.start as u64;
            self.scanner_pool.try_with(|scanner| {
                scanner.scan(&input[range], |rule_id, _from, to, _flags| {
                    if (rule_id as usize) < self.rules_db.num_rules() {
                        self.user_data
                            .raw_matches_scratch
                            .push(RawMatch { rule_id, end_idx: to + base });
                    }
                    kingfisher_vectorscan::Scan::Continue
                })
            })??;

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
                inline_ignore_index,
                &mut seen_raw_match_ends,
                &mut seen_prefilter_rules,
                &mut previous_full_matches,
                &mut candidate_indexes,
                index_range,
                &mut filter_line_cache,
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
        previous_matches: &mut FxHashMap<usize, MatchSpans>,
        seen_matches: &mut FxHashSet<u64>,
        match_rule_indices: &mut Vec<usize>,
        betterleaks_path_prefiltered: bool,
        inline_ignore_index: &std::sync::OnceLock<InlineIgnoreIndex>,
        seen_raw_match_ends: &mut FxHashSet<(usize, usize)>,
        seen_prefilter_rules: &mut FxHashSet<usize>,
        previous_full_matches: &mut FxHashMap<usize, MatchSpans>,
        candidate_indexes: &mut FxHashMap<
            usize,
            kingfisher_scanner::primitives::CandidateMatchCache,
        >,
        index_range: std::ops::Range<usize>,
        filter_line_cache: &mut kingfisher_rules::betterleaks_filter::BetterleaksFilterLineCache,
    ) where
        'a: 'b,
    {
        let rules_db = self.rules_db;
        for &RawMatch { rule_id, end_idx } in self.user_data.raw_matches_scratch.iter().rev() {
            let rule_id_usize: usize = rule_id as usize;
            if betterleaks_path_prefiltered && rules_db.is_betterleaks_rule(rule_id_usize) {
                continue;
            }
            let rule = Arc::clone(&rules_db.rules()[rule_id_usize]);
            let re = &rules_db.anchored_regexes()[rule_id_usize];
            let end_idx_usize = end_idx as usize;
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
                if previous_full_matches
                    .get(&rule_id_usize)
                    .is_some_and(|spans| spans.contains_end(end_idx_usize))
                {
                    continue;
                }
                (end_idx_usize.saturating_sub(RAW_MATCH_LOOKBACK), end_idx_usize)
            };
            if !rule.matches_path(filename) {
                continue;
            }
            let before_len = matches.len();
            let candidate_index = if rules_db.uses_vectorscan_prefilter(rule_id_usize) {
                None
            } else {
                candidate_indexes.entry(rule_id_usize).or_default().get_or_insert_with(
                    index_range.len(),
                    RAW_MATCH_LOOKBACK,
                    || {
                        kingfisher_scanner::__cli_internals::candidate_index(
                            rules_db,
                            rule_id_usize,
                            blob.bytes(),
                            index_range.clone(),
                        )
                    },
                )
            };
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
                    inline_ignore_index,
                    !rules_db.uses_vectorscan_prefilter(rule_id_usize),
                    candidate_index,
                    filter_line_cache,
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
        let inline_ignore_index = std::sync::OnceLock::new();
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
        crate::scan_progress::scanned(blob.bytes().len() as u64);
        // Opportunistically look for standalone Base64 blobs. If neither
        // the raw scan nor this check yields anything, we can return early
        // before doing any heavier work.
        let mut b64_items = if no_base64 || self.resources.exceeds(blob.len(), BASE64_SCAN_LIMIT) {
            Vec::new()
        } else {
            get_b64_strings(blob.bytes())
        };

        let lang_hint = lang.as_deref();
        let mut seen_matches = FxHashSet::default();
        let mut previous_matches: FxHashMap<usize, MatchSpans> = FxHashMap::default();
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
            &inline_ignore_index,
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
                let mut filter_line_cache =
                    kingfisher_rules::betterleaks_filter::BetterleaksFilterLineCache::default();
                self.scanner_pool.try_with(|scanner| {
                    scanner.scan(&item.decoded, |rule_id, _from, _to, _flags| {
                        let rule_id = rule_id as usize;
                        if rule_id < rules_db.num_rules() && seen_candidate_rules.insert(rule_id) {
                            candidate_rule_ids.push(rule_id);
                        }
                        kingfisher_vectorscan::Scan::Continue
                    })
                })??;
                for rule_id_usize in candidate_rule_ids {
                    if betterleaks_path_prefiltered && rules_db.is_betterleaks_rule(rule_id_usize) {
                        continue;
                    }
                    let rule = &rules_db.rules()[rule_id_usize];
                    let re = &rules_db.anchored_regexes()[rule_id_usize];
                    let before_len = matches.len();
                    // Association offsets use decoded positions relative to the
                    // outer encoded start, including nested decodes. Keep this
                    // convention aligned with the embedding scanner; it does not
                    // map decoded byte positions back into the encoded source.
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
                        &inline_ignore_index,
                        false,
                        None,
                        &mut filter_line_cache,
                    );
                    match_rule_indices
                        .extend(std::iter::repeat_n(rule_id_usize, matches.len() - before_len));
                }
                if !self.resources.reached(depth + 1, MAX_B64_DEPTH) {
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
        associate_betterleaks_components(blob.bytes(), &mut matches, self.resources);
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
            // Release excess scratch capacity before the next blob; shrinking can reallocate.
            self.user_data.raw_matches_scratch.shrink_to_fit();
        }

        Ok(ScanResult::New(matches))
    }
}

fn suppress_credential_uri_fallbacks(matches: &mut Vec<BlobMatch<'_>>) {
    let keep = kingfisher_scanner::__cli_internals::credential_uri_keep(
        matches.iter().map(|finding| {
            let secret = if finding.is_base64 {
                finding
                    .captures
                    .captures
                    .first()
                    .map_or(finding.matching_input, |capture| capture.raw_value().as_bytes())
            } else {
                finding.matching_input
            };
            (finding.rule.as_ref(), finding.association_offset_span, secret)
        }),
        &kingfisher_scanner::ScanControl::default(),
    )
    .expect("unlimited scan cannot be cancelled");
    let mut index = 0;
    matches.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

fn deduplicate_imported_catalog_matches(matches: &mut Vec<BlobMatch<'_>>) {
    let keep = kingfisher_scanner::__cli_internals::catalog_keep(
        matches.iter().map(|finding| (finding.rule.as_ref(), finding.matching_input_offset_span)),
        &kingfisher_scanner::ScanControl::default(),
    )
    .expect("unlimited scan cannot be cancelled");
    let mut index = 0;
    matches.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

#[cfg(test)]
use kingfisher_scanner::__cli_internals::{component_candidate_range, component_is_within};
use kingfisher_scanner::__cli_internals::{
    component_candidate_range_with_window, component_is_within_window, parse_component_window,
};

fn associate_betterleaks_components<'a>(
    bytes: &[u8],
    matches: &mut Vec<BlobMatch<'a>>,
    resources: crate::limits::ResourceLimits,
) {
    if !matches.iter().any(|finding| !finding.rule.syntax().depends_on_rule.is_empty()) {
        return;
    }
    let mut line_starts = vec![0];
    {
        use bstr::ByteSlice;
        line_starts.extend(bytes.find_iter(b"\n").map(|index| index + 1));
    }

    let mut candidate_index =
        kingfisher_scanner::__cli_internals::RuleMatchIndex::new(matches.iter().enumerate().map(
            |(index, finding)| (finding.rule.id(), finding.association_offset_span.start, index),
        ));
    let dependency_counts: Vec<_> = matches
        .iter()
        .map(|finding| {
            finding
                .rule
                .syntax()
                .depends_on_rule
                .iter()
                .flatten()
                .filter(|dependency| !dependency.optional && dependency.within.is_some())
                .count()
        })
        .collect();
    let keep = kingfisher_scanner::__cli_internals::dependency_keep(
        &dependency_counts,
        &mut candidate_index,
        |candidate_index, primary_index, dependency_index| {
            let primary = &matches[primary_index];
            let dependency = primary
                .rule
                .syntax()
                .depends_on_rule
                .iter()
                .flatten()
                .filter(|dependency| !dependency.optional && dependency.within.is_some())
                .nth(dependency_index)
                .expect("required dependency index is valid");
            let within = dependency.within.as_deref().expect("required dependency has a window");
            let window = parse_component_window(within);
            Ok(candidate_index
                .candidates(
                    &dependency.rule_id,
                    window.map_or(0..0, |window| {
                        component_candidate_range_with_window(
                            bytes.len(),
                            &line_starts,
                            primary.association_offset_span,
                            window,
                        )
                    }),
                )
                .find_map(|&(_, index)| {
                    let candidate = &matches[index];
                    (candidate.rule.id() == dependency.rule_id
                        && window.is_some_and(|window| {
                            component_is_within_window(
                                bytes.len(),
                                &line_starts,
                                primary.association_offset_span,
                                candidate.association_offset_span,
                                window,
                            )
                        }))
                    .then_some(index)
                }))
        },
        |candidate_index, index| {
            let finding = &matches[index];
            candidate_index.remove(finding.rule.id(), finding.association_offset_span.start, index);
        },
        &kingfisher_scanner::ScanControl::default(),
    )
    .expect("unlimited scan cannot be cancelled");

    let scopes = if matches
        .iter()
        .any(|m| m.rule.syntax().depends_on_rule.iter().flatten().any(|d| d.verify_candidates))
    {
        candidate_context::scopes(bytes, matches.iter().map(|m| m.matching_input_offset_span.start))
    } else {
        Default::default()
    };
    let mut global_values = FxHashMap::<&str, std::collections::BTreeSet<String>>::default();
    let mut candidates = vec![std::collections::BTreeMap::new(); matches.len()];
    let mut associated = vec![std::collections::BTreeMap::new(); matches.len()];
    let mut ambiguous = vec![std::collections::BTreeMap::new(); matches.len()];
    for (primary_index, primary) in matches.iter().enumerate().filter(|(index, _)| keep[*index]) {
        let supports_candidates =
            primary.rule.syntax().depends_on_rule.iter().flatten().any(|dep| dep.verify_candidates)
                && crate::validation::candidates::supported(primary.rule.syntax());
        for dependency in primary.rule.syntax().depends_on_rule.iter().flatten() {
            let mut values = std::collections::BTreeSet::new();
            let mut ranked = std::collections::BTreeMap::new();
            let try_candidates = supports_candidates
                && crate::validation::candidates::eligible_dependency(
                    primary.rule.syntax(),
                    dependency,
                );
            if !try_candidates
                && dependency
                    .within
                    .as_deref()
                    .is_none_or(|within| within.trim().is_empty() || within.trim() == "0")
            {
                let values = global_values.entry(&dependency.rule_id).or_insert_with(|| {
                    candidate_index
                        .candidates(&dependency.rule_id, 0..usize::MAX)
                        .filter(|&&(_, index)| keep[index])
                        .map(|&(_, index)| {
                            let candidate = &matches[index];
                            candidate.captures.captures.first().map_or_else(
                                || String::from_utf8_lossy(candidate.matching_input).into_owned(),
                                |capture| capture.raw_value().to_string(),
                            )
                        })
                        .collect()
                });
                let variable = dependency.variable.to_uppercase();
                if values.len() > 1 {
                    ambiguous[primary_index].insert(variable, values.len());
                } else if let Some(value) = values.first() {
                    associated[primary_index].insert(variable, value.clone());
                }
                continue;
            }
            let family = try_candidates
                .then(|| {
                    candidate_context::assignment_family(bytes, primary.matching_input_offset_span)
                })
                .flatten();
            let window = parse_component_window(dependency.within.as_deref().unwrap_or(""));
            for &(_, index) in candidate_index.candidates(
                &dependency.rule_id,
                window.map_or(0..0, |window| {
                    component_candidate_range_with_window(
                        bytes.len(),
                        &line_starts,
                        primary.association_offset_span,
                        window,
                    )
                }),
            ) {
                let candidate = &matches[index];
                if keep[index]
                    && candidate.rule.id() == dependency.rule_id
                    && window.is_some_and(|window| {
                        component_is_within_window(
                            bytes.len(),
                            &line_starts,
                            primary.association_offset_span,
                            candidate.association_offset_span,
                            window,
                        )
                    })
                {
                    let value = candidate.captures.captures.first().map_or_else(
                        || String::from_utf8_lossy(candidate.matching_input).into_owned(),
                        |capture| capture.raw_value().to_string(),
                    );
                    if try_candidates {
                        let matching_name = family.as_ref().is_some_and(|name| {
                            candidate_context::assignment_family(
                                bytes,
                                candidate.matching_input_offset_span,
                            )
                            .as_ref()
                                == Some(name)
                        });
                        let scope = scopes
                            .get(&primary.matching_input_offset_span.start)
                            .copied()
                            .unwrap_or_default();
                        let same_scope = scope != 0
                            && scopes.get(&candidate.matching_input_offset_span.start)
                                == Some(&scope);
                        let distance = primary
                            .matching_input_offset_span
                            .start
                            .abs_diff(candidate.matching_input_offset_span.start);
                        let rank = (!matching_name, !same_scope, distance);
                        ranked
                            .entry(value.clone())
                            .and_modify(|old| *old = std::cmp::min(*old, rank))
                            .or_insert(rank);
                    }
                    values.insert(value);
                }
            }
            let variable = dependency.variable.to_uppercase();
            if values.len() > 1 {
                if try_candidates {
                    let mut ranked: Vec<_> =
                        ranked.into_iter().map(|(value, rank)| (rank, value)).collect();
                    ranked.sort();
                    if !resources.unlimited {
                        ranked.truncate(crate::validation::candidates::MAX_COMBINATIONS);
                    }
                    candidates[primary_index].insert(
                        variable.clone(),
                        ranked.into_iter().map(|(_, value)| value).collect(),
                    );
                }
                ambiguous[primary_index].insert(variable, values.len());
            } else if let Some(value) = values.into_iter().next() {
                associated[primary_index].insert(variable, value);
            }
        }
    }

    let mut index = 0;
    matches.retain_mut(|finding| {
        finding.dependent_captures.append(&mut associated[index]);
        finding.ambiguous_dependencies.append(&mut ambiguous[index]);
        finding.dependency_candidates.append(&mut candidates[index]);
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
            // Markup parsers normalize invalid UTF-8 and cannot verify these bytes.
            if m.is_base64 || std::str::from_utf8(m.matching_input).is_err() {
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

    // Confirm a rule once per parser candidate, sharing the result across equal
    // secrets and their occurrences. Per-finding regex searches are quadratic
    // when one HTML/CSS value contains many distinct findings.
    let mut remaining: FxHashMap<usize, FxHashMap<&[u8], Vec<usize>>> = FxHashMap::default();
    for idx in candidate_indices {
        remaining
            .entry(match_rule_indices[idx])
            .or_default()
            .entry(matches[idx].matching_input)
            .or_default()
            .push(idx);
    }
    let verification = parser::stream_context_candidates(blob.bytes(), &language, |text| {
        remaining.retain(|rule_idx, secrets| {
            let Some(rule) = rules_db.get_rule(*rule_idx) else {
                return false;
            };
            let re = &rules_db.anchored_regexes()[*rule_idx];
            for captures in re.captures_iter(text.as_bytes()) {
                let secret =
                    find_secret_capture_with_group(re, &captures, rule.betterleaks_secret_group());
                secrets.remove(secret.as_bytes());
                if secrets.is_empty() {
                    break;
                }
            }
            !secrets.is_empty()
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
    for idx in remaining.into_values().flat_map(|secrets| secrets.into_values().flatten()) {
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

    #[test]
    fn sdk_detection_policy_agrees_with_cli_windows_uri_suppression_and_base64() -> Result<()> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        use kingfisher_scanner::{Scanner, context::DetectionOptions};
        let helper = compatibility_rule(
            "acme.helper",
            r"(HELP_[a-z0-9]{8})",
            Confidence::High,
            None,
            vec![],
            false,
        );
        let make_primary = |pattern: &str, within: &str| {
            compatibility_rule(
                "acme.primary",
                pattern,
                Confidence::High,
                None,
                vec![DependsOnRule {
                    rule_id: "acme.helper".into(),
                    variable: "COMPONENT".into(),
                    within: Some(within.into()),
                    optional: false,
                    verify_candidates: false,
                }],
                true,
            )
        };
        let uri = "https://u8q3n:p7v9c2k4m1@api.q7r9v3.net";
        let mut fallback = compatibility_rule(
            "betterleaks.uri-fallback",
            r"(https://[a-z0-9]+:[a-z0-9]+@api\.q7r9v3\.net)",
            Confidence::High,
            None,
            vec![],
            true,
        );
        fallback.syntax.validation = Some(Validation::CredentialUri);
        let specific = compatibility_rule(
            "betterleaks.specific",
            r"SERVICE (https://[a-z0-9]+:[a-z0-9]+@api\.q7r9v3\.net)",
            Confidence::High,
            None,
            vec![],
            true,
        );
        let token = compatibility_rule(
            "acme.token",
            r"(demo_[a-z0-9]{16})",
            Confidence::High,
            None,
            vec![],
            true,
        );
        let double = STANDARD.encode(STANDARD.encode(b"token=demo_abcd1234efgh5678"));
        let cases = vec![
            (
                vec![helper.clone(), make_primary(r"PREFIX_x{48}(PRIMARY_[a-z0-9]{8})", "16C")],
                format!("HELP_efgh5678 PREFIX_{}PRIMARY_abcd1234", "x".repeat(48)).into_bytes(),
            ),
            (
                vec![helper.clone(), make_primary(r"(PRIMARY_[a-z0-9]{8})\n", "1L")],
                b"PRIMARY_abcd1234\nHELP_efgh5678".to_vec(),
            ),
            (
                vec![helper.clone(), make_primary(r"(PRIMARY_[a-z0-9]{8})", "-2L")],
                b"HELP_efgh5678\nPRIMARY_abcd1234".to_vec(),
            ),
            (
                vec![helper, make_primary(r"(PRIMARY_[a-z0-9]{8})", "+2L")],
                b"HELP_efgh5678\nPRIMARY_abcd1234".to_vec(),
            ),
            (vec![fallback.clone(), specific.clone()], format!("SERVICE {uri}").into_bytes()),
            (vec![fallback, specific], STANDARD.encode(format!("SERVICE {uri}")).into_bytes()),
            (vec![token.clone()], double.into_bytes()),
            (
                vec![token],
                STANDARD.encode(b"demo_abcd1234efgh5678 demo_abcd1234efgh5678").into_bytes(),
            ),
            (
                vec![compatibility_rule(
                    "acme.hex",
                    r"([0-9a-f]{32})",
                    Confidence::High,
                    None,
                    vec![],
                    true,
                )],
                (0..5001)
                    .scan(0x739b_u64, |state, _| {
                        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                        Some(b"0123456789abcdef"[(*state >> 60) as usize])
                    })
                    .collect(),
            ),
        ];
        for (rules, input) in cases {
            let rules_db = Arc::new(RulesDatabase::from_rules(rules)?);
            let seen = BlobIdMap::new();
            let pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
            let mut matcher =
                Matcher::new(&rules_db, pool, &seen, None, false, None, &[], false, true)?;
            let blob = Blob::from_bytes(input);
            let origin = OriginSet::from(Origin::from_file(PathBuf::from("parity.txt")));
            let ScanResult::New(matches) =
                matcher.scan_blob(&blob, &origin, None, false, true, false)?
            else {
                panic!("dedup disabled")
            };
            let mut cli: Vec<_> = matches
                .iter()
                .map(|m| {
                    (
                        m.rule.id().to_owned(),
                        m.captures.captures.first().unwrap().raw_value().to_owned(),
                        m.is_base64,
                        (!m.is_base64).then_some((
                            m.matching_input_offset_span.start,
                            m.matching_input_offset_span.end,
                        )),
                    )
                })
                .collect();
            let scanner = Scanner::new(Arc::clone(&rules_db));
            let options = DetectionOptions { markup_context: false, ..Default::default() };
            let mut sdk: Vec<_> = scanner
                .scan_blob_at_path_with_options(&blob, "parity.txt", &options)?
                .into_iter()
                .map(|f| {
                    let span = (!f.is_base64_encoded)
                        .then_some((f.location.start_offset, f.location.end_offset));
                    (f.rule_id, f.secret, f.is_base64_encoded, span)
                })
                .collect();
            cli.sort();
            sdk.sort();
            assert_eq!(sdk, cli, "input length {}", blob.len());
        }
        Ok(())
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
    fn dense_line_filters_preserve_secret_results_for_raw_and_decoded_bytes() -> Result<()> {
        use crate::rules::BetterleaksExpr as Expr;
        use base64::{Engine, engine::general_purpose::STANDARD};

        let filter = |field: &str, pattern: &str| Expr::Call {
            callee: Box::new(Expr::Identifier { value: "matchesAny".into() }),
            arguments: vec![
                Expr::Member {
                    node: Box::new(Expr::Identifier { value: "finding".into() }),
                    property: Box::new(Expr::String { value: field.into() }),
                    optional: false,
                    method: false,
                },
                Expr::Array { nodes: vec![Expr::String { value: pattern.into() }] },
            ],
        };
        let rule = compatibility_rule(
            "acme.filtered",
            r"(demo_[a-z0-9]{16})",
            Confidence::High,
            Some(Expr::Binary {
                operator: "||".into(),
                left: Box::new(filter("line", "IGNORE-LINE")),
                right: Box::new(filter("secret", "^demo_a9c300000020f7d2$")),
            }),
            vec![],
            true,
        );
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let secrets: Vec<_> = (0..128).map(|index| format!("demo_a9c3{index:08x}f7d2")).collect();
        let mut bytes = b"\xff ".to_vec();
        bytes.extend(secrets[..64].join(" ").as_bytes());
        bytes.extend(b"\r\n\xff IGNORE-LINE ");
        bytes.extend(secrets[64..].join(" ").as_bytes());
        // The Base64 pass intentionally accepts only ASCII decoded payloads.
        let decoded: Vec<_> =
            bytes.iter().map(|&byte| if byte.is_ascii() { byte } else { b' ' }).collect();

        for (input, base64) in [(bytes, false), (STANDARD.encode(decoded).into_bytes(), true)] {
            let seen = BlobIdMap::new();
            let scanner_pool =
                Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
            let mut matcher =
                Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
            let blob = Blob::from_bytes(input);
            let origin = OriginSet::from(Origin::from_file(PathBuf::from("dense.txt")));
            let ScanResult::New(found) =
                matcher.scan_blob(&blob, &origin, None, false, true, false)?
            else {
                panic!("deduplication is disabled");
            };
            let mut values: Vec<_> = found
                .iter()
                .map(|finding| {
                    assert_eq!(finding.is_base64, base64);
                    finding.captures.captures.first().unwrap().raw_value().to_owned()
                })
                .collect();
            values.sort();
            let expected: Vec<_> = secrets[..64]
                .iter()
                .filter(|secret| *secret != "demo_a9c300000020f7d2")
                .cloned()
                .collect();
            assert_eq!(values, expected, "base64={base64}");
        }
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
                verify_candidates: false,
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
                verify_candidates: false,
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
    fn dense_component_windows_and_global_values_preserve_association() -> Result<()> {
        for within in
            [Some("1L"), Some("+1L"), Some("-1L"), Some("16C"), Some("1L,16C"), Some("0"), None]
        {
            let helper = compatibility_rule(
                "acme.helper",
                r"(HELP_[a-z0-9]{8})",
                Confidence::High,
                None,
                vec![],
                false,
            );
            let primary = compatibility_rule(
                "acme.primary",
                r"(PRIMARY_[a-z0-9]{8})",
                Confidence::High,
                None,
                vec![DependsOnRule {
                    rule_id: "acme.helper".into(),
                    variable: "COMPONENT".into(),
                    within: within.map(str::to_owned),
                    optional: false,
                    verify_candidates: false,
                }],
                true,
            );
            let input = "PRIMARY_abcd1234 HELP_efgh5678\n".repeat(2500);
            let findings = scan_test_rules(vec![primary, helper], input.as_bytes())?;
            assert_eq!(findings.len(), 5000, "{within:?}");
            assert!(
                findings
                    .iter()
                    .filter(|(id, _, _, _)| id == "acme.primary")
                    .all(|(_, _, value, _)| value.as_deref() == Some("HELP_efgh5678")),
                "{within:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn component_candidate_ranges_cover_exact_window_semantics() {
        let bytes = b"first\nsecond\nthird\nfourth\n";
        let lines = [0, 6, 13, 19, 26];
        for within in ["", "0", "1L", "2L", "+2L", "-2L", "2C", "+3C", "1L,2C", "2L,3C", "invalid"]
        {
            for start in 0..bytes.len() {
                let primary = OffsetSpan { start, end: (start + 4).min(bytes.len()) };
                let range = component_candidate_range(bytes.len(), &lines, primary, Some(within));
                for candidate in 0..=bytes.len() {
                    let component = OffsetSpan { start: candidate, end: candidate };
                    if component_is_within(bytes, &lines, primary, component, within) {
                        assert!(range.contains(&candidate), "{within} {primary:?} {candidate}");
                    }
                }
            }
        }
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
                    verify_candidates: false,
                    variable: "AKID".into(),
                    optional: false,
                    within: Some("5L".into()),
                },
                DependsOnRule {
                    rule_id: "betterleaks.aws-secret-access-key".into(),
                    verify_candidates: false,
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
                verify_candidates: false,
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

            // ── property 1: dedup – each (rule,end) is unique ──────

            let mut coords = FxHashSet::default();
            for RawMatch{rule_id, end_idx} in &m.user_data.raw_matches_scratch {
                assert!(
                    coords.insert((*rule_id, *end_idx)),
                    "duplicate raw-match detected for coords ({rule_id},{end_idx})"
                );

                // ── property 2: entropy gate held ────────────────────────
                // This fixed-width test pattern lets us recover its start from the end.
                let end = *end_idx as usize;
                let slice = &noise[end - TOKEN.len() .. end];
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
                    verify_candidates: false,
                    variable: "email".to_string(),
                    optional: false,
                    within: None,
                }),
                Some(DependsOnRule {
                    rule_id: "8910f364-7718-4a27-a435-d2da13e6ba9e".to_string(),
                    verify_candidates: false,
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
            vec![RawMatch { rule_id: 0, end_idx: 9 },]
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
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("long-secrets.txt")));
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;

        // In the second case the key needs a wider confirmation window than the segment index.
        for padding in [0, MAX_CHUNK_SIZE - CHUNK_OVERLAP + 128] {
            let mut bytes = vec![b' '; padding];
            bytes.extend_from_slice(&input);
            let blob = Blob::from_bytes(bytes);
            let ScanResult::New(matches) =
                matcher.scan_blob(&blob, &origin, None, false, false, true)?
            else {
                panic!("fresh blob should return new matches");
            };
            assert_eq!(matches.len(), 2, "padding={padding}");
            assert!(matches.iter().any(|matched| matched.matching_input == token));
            assert!(matches.iter().any(|matched| matched.matching_input == private_key));
        }
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
        let entries: Vec<(Option<&str>, i32, &str)> = serialized
            .captures
            .iter()
            .map(|cap| (cap.name, cap.match_number, cap.raw_value()))
            .collect();

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
        let entries: Vec<(Option<&str>, i32, &str)> = serialized
            .captures
            .iter()
            .map(|cap| (cap.name, cap.match_number, cap.raw_value()))
            .collect();

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
                verify_candidates: false,
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
    fn html_gate_preserves_non_utf8_secret() -> Result<()> {
        let rule = Rule::new(RuleSyntax::new("acme.context", "Context", r"(demo_[^\x22]{4})"));
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        let seen = BlobIdMap::new();
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        let mut matcher =
            Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
        let blob = Blob::from_bytes(b"<input password=\"demo_abc\xff\">".to_vec());
        let origin = OriginSet::from(Origin::from_file(PathBuf::from("page.html")));
        let ScanResult::New(found) =
            matcher.scan_blob(&blob, &origin, Some("html".to_string()), false, false, false)?
        else {
            panic!("unexpected scan result");
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matching_input, b"demo_abc\xff");
        Ok(())
    }

    #[test]
    fn markup_gate_handles_dense_distinct_values_and_duplicate_occurrences() -> Result<()> {
        let rule = compatibility_rule(
            "acme.context",
            r"(?:password|secret)=(demo_[a-z0-9]{16})",
            Confidence::High,
            None,
            vec![],
            true,
        );
        let rules_db = RulesDatabase::from_rules(vec![rule])?;
        assert!(!rules_db.is_rule_self_identifying(0));
        let secrets: Vec<_> = (0..1024).map(|index| format!("demo_a9c3{index:08x}f7d2")).collect();
        let values = secrets.iter().map(|secret| format!("password={secret}")).collect::<Vec<_>>();
        let values = format!("{} password={}", values.join(" "), secrets[0]);
        let excluded = "demo_q8r2m6v4c9x7z3k5";

        for (language, body) in [
            ("html", format!(r#"<input data-config="{values}"><!-- password={excluded} -->"#)),
            ("css", format!(r#".sample {{ content: "{values}"; }} /* password={excluded} */"#)),
        ] {
            let seen = BlobIdMap::new();
            let scanner_pool =
                Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
            let mut matcher =
                Matcher::new(&rules_db, scanner_pool, &seen, None, false, None, &[], false, true)?;
            let blob = Blob::from_bytes(body.into_bytes());
            let origin =
                OriginSet::from(Origin::from_file(PathBuf::from(format!("dense.{language}"))));
            let ScanResult::New(found) =
                matcher.scan_blob(&blob, &origin, Some(language.into()), false, true, true)?
            else {
                panic!("deduplication is disabled");
            };
            assert_eq!(found.len(), secrets.len() + 1, "{language}");
            assert_eq!(
                found
                    .iter()
                    .filter(|finding| finding.matching_input == secrets[0].as_bytes())
                    .count(),
                2,
                "{language}"
            );
            assert!(!found.iter().any(|finding| finding.matching_input == excluded.as_bytes()));
        }
        Ok(())
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
