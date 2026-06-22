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
use kingfisher_scanner::primitives::find_secret_capture;

use self::{base64_decode::get_base64_strings as get_b64_strings, filter::filter_match};

const MAX_CHUNK_SIZE: usize = 1 << 30; // 1 GiB per scan segment
const CHUNK_OVERLAP: usize = 64 * 1024; // 64 KiB overlap to catch boundary matches
const RAW_MATCH_LOOKBACK: usize = 4 * 1024; // Re-scan a bounded suffix ending at the raw match.
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

    /// The capture groups from the match
    pub captures: SerializableCaptures,

    pub validation_response_body: ValidationResponseBody,
    pub validation_response_status: StatusCode,

    pub validation_success: bool,
    pub calculated_entropy: f32,
    pub is_base64: bool,
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
                    self.user_data.raw_matches_scratch.push(RawMatch {
                        rule_id,
                        start_idx: from + base,
                        end_idx: to + base,
                    });
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
    ) where
        'a: 'b,
    {
        let rules_db = self.rules_db;
        let mut seen_raw_match_ends: FxHashSet<(usize, usize)> = FxHashSet::default();
        let mut previous_full_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();
        for &RawMatch { rule_id, start_idx, end_idx } in
            self.user_data.raw_matches_scratch.iter().rev()
        {
            let rule_id_usize: usize = rule_id as usize;
            let rule = Arc::clone(&rules_db.rules()[rule_id_usize]);
            let re = &rules_db.anchored_regexes()[rule_id_usize];
            let end_idx_usize = end_idx as usize;
            let _ = start_idx; // Vectorscan block mode does not provide a reliable start offset.
            if !seen_raw_match_ends.insert((rule_id_usize, end_idx_usize)) {
                continue;
            }

            let scan_start = end_idx_usize.saturating_sub(RAW_MATCH_LOOKBACK);
            let before_len = matches.len();
            filter_match(
                blob,
                rule,
                re,
                scan_start,
                end_idx_usize,
                matches,
                Some(&mut previous_full_matches),
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
            );
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
        self.local_stats.blobs_scanned += 1;
        self.local_stats.bytes_scanned += blob.bytes().len() as u64;

        // Extract filename from origin
        let filename = origin
            .first()
            .blob_path()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .unwrap_or("unknown_file")
            .to_string();
        // Perform the scan
        self.scan_bytes_raw(blob.bytes(), &filename)?;

        // Opportunistically look for standalone Base64 blobs. If neither
        // the raw scan nor this check yields anything, we can return early
        // before doing any heavier work.
        let mut b64_items = if no_base64 || blob.len() > BASE64_SCAN_LIMIT {
            Vec::new()
        } else {
            get_b64_strings(blob.bytes())
        };

        let lang_hint = lang.as_deref();
        let has_raw_matches = !self.user_data.raw_matches_scratch.is_empty();
        let has_base64_items = !b64_items.is_empty();

        if !has_raw_matches && !has_base64_items {
            return Ok(ScanResult::New(Vec::new()));
        }

        let mut seen_matches = FxHashSet::default();
        let mut previous_matches: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();
        let mut match_rule_indices: Vec<usize> = Vec::new();

        let blob_len = blob.len();
        let mut matches = Vec::new();
        self.process_raw_matches(
            blob,
            origin,
            &filename,
            redact,
            &mut matches,
            &mut previous_matches,
            &mut seen_matches,
            &mut match_rule_indices,
        );

        if !no_base64 {
            let rules_db = self.rules_db;
            // If the blob contains standalone Base64 blobs, decode and scan them as well
            const MAX_B64_DEPTH: usize = 2; // decode at most two levels deep
            let mut b64_stack: Vec<(DecodedData, usize)> =
                b64_items.drain(..).map(|d| (d, 0)).collect();
            while let Some((item, depth)) = b64_stack.pop() {
                for (rule_id_usize, rule) in rules_db.rules().iter().enumerate() {
                    let re = &rules_db.anchored_regexes()[rule_id_usize];
                    let before_len = matches.len();
                    filter_match(
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
            let re = &rules_db.anchored_regexes()[rule_idx];
            let expected_secret = matches[*idx].matching_input;
            !verify_match_in_context_text(re, expected_secret, text.as_bytes())
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
) -> bool {
    re.captures_iter(text)
        .any(|captures| find_secret_capture(re, &captures).as_bytes() == expected_secret)
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
            DependsOnRule, HttpRequest, HttpValidation, PatternRequirements, RuleSyntax, Validation,
        },
    };

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
                }),
                Some(DependsOnRule {
                    rule_id: "8910f364-7718-4a27-a435-d2da13e6ba9e".to_string(),
                    variable: "domain".to_string(),
                }),
            ],
            pattern_requirements: None,
            tls_mode: None,
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
    fn parser_second_pass_keeps_verified_contextual_match() -> Result<()> {
        let token = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";
        let rule = Rule::new(RuleSyntax {
            id: "kingfisher.auth0.2".into(),
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
            id: "kingfisher.auth0.2".into(),
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
            id: "kingfisher.auth0.2".into(),
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
            id: "kingfisher.livekit.2".into(),
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
            id: "kingfisher.livekit.2".into(),
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
                rule_id: "kingfisher.livekit.1".into(),
                variable: "API_KEY".into(),
            })],
            pattern_requirements: None,
            tls_mode: None,
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
            id: "kingfisher.circleci.1".into(),
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
            id: "kingfisher.slack.2".into(),
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
            id: "kingfisher.auth0.2".into(),
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
            id: "kingfisher.google.7".into(),
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
