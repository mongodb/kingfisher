//! High-level scanner API.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use kingfisher_core::{Blob, BlobId, LocationMapping, OffsetSpan, calculate_shannon_entropy};
use kingfisher_rules::{
    Confidence, Rule, RulesDatabase,
    betterleaks_filter::{BetterleaksFilterContext, BetterleaksFilterLineCache},
};
use parking_lot::RwLock;
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::ScanControl;
use crate::finding::{Finding, FindingLocation};
use crate::primitives;
use crate::scanner_pool::ScannerPool;

// Preserve the SDK's historical window alignment, including fixed-width runs.
// Dense rules use the candidate index to skip earlier matches. Failed confirmation
// doubles this window below, so this is not a limit on match length.
const RAW_MATCH_LOOKBACK: usize = 64 * 1024;

pub(crate) struct ScanFinding {
    pub finding: Finding,
    pub association_span: OffsetSpan,
    pub secret_span: OffsetSpan,
    #[cfg(feature = "context")]
    pub rule_index: usize,
    // Secret spans from different decoded buffers use unrelated synthetic coordinates.
    // Zero identifies raw input; every decoded buffer receives its own scope.
    #[cfg(feature = "context")]
    pub buffer_id: usize,
}

impl std::ops::Deref for ScanFinding {
    type Target = Finding;
    fn deref(&self) -> &Finding {
        &self.finding
    }
}
impl std::ops::DerefMut for ScanFinding {
    fn deref_mut(&mut self) -> &mut Finding {
        &mut self.finding
    }
}

/// Configuration options for the scanner.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Whether to decode and scan Base64 content.
    pub enable_base64_decoding: bool,

    /// Suppress repeated successful findings for the same content and source path.
    /// Disabled by default. Concurrent calls may both report a first occurrence.
    pub enable_dedup: bool,

    /// Override the minimum entropy threshold for all rules.
    pub min_entropy_override: Option<f32>,

    /// Replace returned secrets and all capture values with `[REDACTED]`.
    pub redact_secrets: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enable_base64_decoding: true,
            enable_dedup: false,
            min_entropy_override: None,
            redact_secrets: false,
        }
    }
}

/// A high-level scanner for detecting secrets in content.
///
/// The `Scanner` provides a clean API for scanning bytes, files, or blobs
/// for secrets using compiled rules.
///
/// # Thread Safety
///
/// The `Scanner` is thread-safe and can be shared across threads using `Arc`.
/// Each scanning operation is independent and uses thread-local resources.
///
/// Compile rules once with [`RulesDatabase::from_rule_collection`] and reuse this
/// scanner. See the crate-level examples for complete, executable usage.
pub struct Scanner {
    rules_db: Arc<RulesDatabase>,
    scanner_pool: Arc<ScannerPool>,
    config: ScannerConfig,
    seen_blobs: RwLock<FxHashSet<(BlobId, String)>>,
}

impl Scanner {
    /// Creates a new scanner with the given rules database.
    pub fn new(rules_db: Arc<RulesDatabase>) -> Self {
        Self::with_config(rules_db, ScannerConfig::default())
    }

    /// Creates a new scanner with custom configuration.
    pub fn with_config(rules_db: Arc<RulesDatabase>, config: ScannerConfig) -> Self {
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        Self { rules_db, scanner_pool, config, seen_blobs: RwLock::new(FxHashSet::default()) }
    }

    /// Scans a byte slice for secrets.
    ///
    /// Borrows the input unless UTF-16/32 decoding requires an owned UTF-8 buffer.
    /// Returns scan and filter errors instead of treating them as an empty result.
    ///
    /// # Errors
    ///
    /// Returns native matching, regex confirmation, and rule-filter errors.
    /// An error is never converted into an empty successful scan.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use kingfisher_scanner::Scanner;
    /// # use std::sync::Arc;
    /// # fn example(scanner: &Scanner) -> anyhow::Result<()> {
    /// let content = b"password = 'super_secret_password_12345'";
    /// let findings = scanner.scan_bytes(content)?;
    /// for finding in findings {
    ///     println!("Found {} at line {}", finding.rule_name, finding.line());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn scan_bytes(&self, bytes: &[u8]) -> Result<Vec<Finding>> {
        let blob = Blob::from_borrowed(bytes);
        self.scan_blob_at_path(&blob, "")
    }

    /// Scans a file for secrets.
    ///
    /// Non-empty files are memory-mapped; empty files use owned bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or if matching, regex
    /// confirmation, or a rule filter fails.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Finding>> {
        let blob = Blob::from_file(&path)?;
        self.scan_blob_at_path(&blob, &path.as_ref().to_string_lossy())
    }

    /// Scans a blob for secrets.
    ///
    /// This is the core scanning method. Use this when you have a pre-existing
    /// `Blob` instance.
    ///
    /// # Errors
    ///
    /// Returns matching, regex confirmation, and rule-filter errors, as with
    /// [`Self::scan_bytes`].
    pub fn scan_blob(&self, blob: &Blob) -> Result<Vec<Finding>> {
        self.scan_blob_at_path(blob, "")
    }

    /// Scan a blob while supplying the source path used by path-aware rules and filters.
    ///
    /// # Errors
    ///
    /// Returns matching, regex confirmation, and rule-filter errors, including
    /// errors evaluating the source-path prefilter.
    pub fn scan_blob_at_path(&self, blob: &Blob, path: &str) -> Result<Vec<Finding>> {
        self.scan_blob_at_path_with_control(blob, path, &ScanControl::default())
    }

    /// Scan bytes with a cooperative deadline and/or cancellation signal.
    /// Returns an error on interruption, never partial findings.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Self::scan_bytes`], or an error
    /// containing [`crate::ScanAborted`] when cancelled or past its deadline.
    pub fn scan_bytes_with_control(
        &self,
        bytes: &[u8],
        control: &ScanControl,
    ) -> Result<Vec<Finding>> {
        control.check()?;
        let blob = Blob::from_borrowed(bytes);
        self.scan_blob_at_path_with_control(&blob, "", control)
    }

    /// Read and scan a file with per-call controls. File reads are not preemptible.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Self::scan_file`], or an error
    /// containing [`crate::ScanAborted`] when cancelled or past its deadline.
    pub fn scan_file_with_control<P: AsRef<Path>>(
        &self,
        path: P,
        control: &ScanControl,
    ) -> Result<Vec<Finding>> {
        control.check()?;
        let blob = Blob::from_file(&path)?;
        self.scan_blob_at_path_with_control(&blob, &path.as_ref().to_string_lossy(), control)
    }

    /// Scan a blob and logical source path with per-call controls.
    ///
    /// # Errors
    ///
    /// Returns the errors documented by [`Self::scan_blob_at_path`], or an error
    /// containing [`crate::ScanAborted`] when cancelled or past its deadline.
    /// Interrupted calls return no partial findings and do not commit deduplication.
    pub fn scan_blob_at_path_with_control(
        &self,
        blob: &Blob,
        path: &str,
        control: &ScanControl,
    ) -> Result<Vec<Finding>> {
        self.scan_blob_impl(
            blob,
            path,
            control,
            #[cfg(feature = "context")]
            None,
        )
    }

    /// Scan with opt-in CLI detection policies and unlimited execution controls.
    /// See [`Self::scan_blob_at_path_with_options_and_control`] for interruption and dedup semantics.
    #[cfg(feature = "context")]
    pub fn scan_blob_at_path_with_options(
        &self,
        blob: &Blob,
        path: &str,
        options: &crate::context::DetectionOptions,
    ) -> Result<Vec<Finding>> {
        self.scan_blob_at_path_with_options_and_control(
            blob,
            path,
            options,
            &ScanControl::default(),
        )
    }

    /// Scan with opt-in CLI matching, Base64 and context policies under cooperative controls.
    /// The dedup key contains the blob ID and path, but not `options`.
    /// Use a separate scanner for each policy when enabling deduplication.
    /// Interrupted calls return no partial findings and commit no dedup state.
    ///
    /// # Errors
    /// Returns matching/filtering errors, or a [`crate::ScanAborted`] on interruption.
    #[cfg(feature = "context")]
    pub fn scan_blob_at_path_with_options_and_control(
        &self,
        blob: &Blob,
        path: &str,
        options: &crate::context::DetectionOptions,
        control: &ScanControl,
    ) -> Result<Vec<Finding>> {
        self.scan_blob_impl(blob, path, control, Some(options))
    }

    fn scan_blob_impl(
        &self,
        blob: &Blob,
        path: &str,
        control: &ScanControl,
        #[cfg(feature = "context")] options: Option<&crate::context::DetectionOptions>,
    ) -> Result<Vec<Finding>> {
        #[cfg(feature = "context")]
        let cli_match_semantics = options.is_some_and(|options| options.cli_match_semantics);
        #[cfg(not(feature = "context"))]
        let cli_match_semantics = false;
        let lookback = if cli_match_semantics { 4 * 1024 } else { RAW_MATCH_LOOKBACK };
        control.check()?;
        // Check for dedup
        if self.config.enable_dedup {
            let blob_id = blob.id();
            if self.seen_blobs.read().contains(&(blob_id, path.to_owned())) {
                return Ok(Vec::new());
            }
        }

        let bytes = blob.bytes();
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let betterleaks_path_prefiltered = self.rules_db.is_path_prefiltered(path)?;
        if betterleaks_path_prefiltered && !self.rules_db.has_non_betterleaks_rules() {
            return Ok(Vec::new());
        }

        control.check()?;
        // Run Vectorscan to find candidate matches
        let mut raw_matches = Vec::new();
        let scan_result = self.scanner_pool.try_with(|scanner| {
            scanner.scan(bytes, |rule_id, from, to, _flags| {
                if control.check().is_err() {
                    return kingfisher_vectorscan::Scan::Terminate;
                }
                if (rule_id as usize) < self.rules_db.num_rules() {
                    raw_matches.push((rule_id as usize, from as usize, to as usize));
                }
                kingfisher_vectorscan::Scan::Continue
            })
        });
        control.check()?;
        scan_result??;
        // Early exit if no matches
        if raw_matches.is_empty() && !self.config.enable_base64_decoding {
            return Ok(Vec::new());
        }

        // Create location mapping for line/column info
        let loc_mapping = LocationMapping::new(bytes);

        // Process matches through regex
        let mut findings = Vec::new();
        let mut seen_matches: FxHashSet<u64> = FxHashSet::default();
        let mut seen_raw_match_ends: FxHashSet<(usize, usize)> = FxHashSet::default();
        let mut seen_prefilter_rules: FxHashSet<usize> = FxHashSet::default();
        let mut previous_full_spans: FxHashMap<usize, primitives::MatchSpans> =
            FxHashMap::default();

        let mut candidate_indexes: FxHashMap<usize, primitives::CandidateMatchCache> =
            FxHashMap::default();
        let fragment_raw = std::cell::OnceCell::new();
        let line_index = std::cell::OnceCell::new();
        let mut filter_lines = FxHashMap::default();
        let mut filter_line_cache = BetterleaksFilterLineCache::default();
        for (rule_id, _start, end) in raw_matches.into_iter().rev() {
            control.check()?;
            if betterleaks_path_prefiltered && self.rules_db.is_betterleaks_rule(rule_id) {
                continue;
            }
            let rule = match self.rules_db.get_rule(rule_id) {
                Some(r) => r,
                None => continue,
            };
            if !rule.matches_path(path) {
                continue;
            }

            let Some(confirmation_regex) = self.rules_db.anchored_regexes().get(rule_id) else {
                continue;
            };

            // Block-mode Vectorscan reports `from` as 0 unless SOM is enabled.
            let (mut scan_start, scan_end) = if self.rules_db.uses_vectorscan_prefilter(rule_id) {
                if !seen_prefilter_rules.insert(rule_id) {
                    continue;
                }
                (0, bytes.len())
            } else {
                if !seen_raw_match_ends.insert((rule_id, end)) {
                    continue;
                }
                if previous_full_spans.get(&rule_id).is_some_and(|spans| spans.contains_end(end)) {
                    continue;
                }
                (end.saturating_sub(lookback), end)
            };
            let bounded_confirmation = !self.rules_db.uses_vectorscan_prefilter(rule_id);
            let candidate_index = if bounded_confirmation {
                candidate_indexes.entry(rule_id).or_default().get_or_try_insert_with(
                    bytes.len(),
                    lookback,
                    || {
                        primitives::CandidateMatchIndex::with_control(
                            confirmation_regex,
                            bytes,
                            control,
                            self.rules_db.confirmation_maximum_len(rule_id),
                            self.rules_db.confirmation_match_maximum_len(rule_id),
                            self.rules_db.confirmation_prefix_stable(rule_id),
                        )
                    },
                )?
            } else {
                None
            };
            loop {
                control.check()?;
                let haystack = &bytes[scan_start..scan_end];
                let mut confirmed = false;

                let mut captures = if let Some(index) = candidate_index {
                    index.captures_with_control(
                        confirmation_regex,
                        if self.rules_db.confirmation_prefix_stable(rule_id) {
                            None
                        } else {
                            self.rules_db.endpoint_regex(rule_id)
                        },
                        haystack,
                        scan_start,
                        control,
                    )?
                } else {
                    crate::confirmation::IndexedCaptures::search(confirmation_regex, haystack)
                };
                while let Some(captures) = captures.next_with_control(control)? {
                    control.check()?;
                    let full_capture = captures.get(0).unwrap();
                    if bounded_confirmation
                        && ((scan_start > 0 && full_capture.start() == 0)
                            || full_capture.end() != haystack.len())
                    {
                        continue;
                    }
                    confirmed = true;
                    let full_capture_span = OffsetSpan::from_range(
                        (scan_start + full_capture.start())..(scan_start + full_capture.end()),
                    );
                    if !primitives::record_indexed_match(
                        &mut previous_full_spans,
                        rule_id,
                        full_capture_span,
                    ) {
                        continue;
                    }

                    // Get the primary secret value
                    let secret_capture = primitives::find_secret_capture_with_group(
                        confirmation_regex,
                        &captures,
                        rule.betterleaks_secret_group(),
                    );
                    let secret_bytes = secret_capture.as_bytes();

                    // Check entropy
                    let min_entropy =
                        self.config.min_entropy_override.unwrap_or(rule.min_entropy());
                    let entropy = calculate_shannon_entropy(secret_bytes);
                    if entropy <= min_entropy {
                        debug!("Skipping low entropy match: {:.2} <= {:.2}", entropy, min_entropy);
                        continue;
                    }

                    let capture_map = named_captures(confirmation_regex, &captures);
                    let filter_outcome = if let Some(expression) = rule.betterleaks_filter() {
                        let full_match = String::from_utf8_lossy(full_capture.as_bytes());
                        let secret = String::from_utf8_lossy(secret_bytes);
                        let fragment_raw =
                            fragment_raw.get_or_init(|| String::from_utf8_lossy(bytes));
                        let match_start_idx = scan_start + full_capture.start();
                        let match_end_idx = scan_start + full_capture.end();
                        let (match_line_start_idx, match_line_end_idx) = line_index
                            .get_or_init(|| crate::line_index::LineIndex::new(bytes))
                            .bounds(match_start_idx, match_end_idx);
                        let line = filter_line(
                            bytes,
                            match fragment_raw {
                                std::borrow::Cow::Borrowed(text) => Some(*text),
                                _ => None,
                            },
                            (match_line_start_idx, match_line_end_idx),
                            line_index.get().unwrap(),
                            &mut filter_lines,
                        );
                        let context = BetterleaksFilterContext {
                            path,
                            secret: &secret,
                            full_match: &full_match,
                            line: &line,
                            fragment_raw,
                            match_start_idx,
                            match_end_idx,
                            match_line_start_idx,
                            match_line_end_idx,
                            rule_id: rule.id(),
                            description: rule.name(),
                            captures: capture_map.clone(),
                        };
                        Some(self.rules_db.evaluate_betterleaks_filter_with_line_cache(
                            expression,
                            &context,
                            match_line_start_idx..match_line_end_idx,
                            &mut filter_line_cache,
                        )?)
                    } else {
                        None
                    };
                    if filter_outcome.is_some_and(|outcome| outcome.discard) {
                        continue;
                    }
                    let confidence = filter_outcome
                        .and_then(|outcome| outcome.confidence)
                        .unwrap_or_else(|| rule.confidence());
                    if !rule.accepts_effective_confidence(confidence) {
                        continue;
                    }

                    // Compute match key for dedup
                    let offset_start = scan_start + secret_capture.start();
                    let offset_end = scan_start + secret_capture.end();
                    let match_key = primitives::compute_match_key(
                        secret_bytes,
                        rule.id().as_bytes(),
                        offset_start,
                        offset_end,
                    );
                    if !seen_matches.insert(match_key) {
                        continue;
                    }

                    // Build the finding
                    let offset_span = OffsetSpan::from_range(offset_start..offset_end);
                    let source_span = loc_mapping.get_source_span(&offset_span);

                    let secret = String::from_utf8_lossy(secret_bytes).to_string();

                    let fingerprint = primitives::compute_finding_fingerprint(
                        &secret,
                        &blob.id().to_string(),
                        offset_span.start as u64,
                        offset_span.end as u64,
                    );

                    findings.push(ScanFinding {
                        finding: Finding {
                            rule: finding_rule(&rule, confidence),
                            rule_id: rule.id().to_string(),
                            rule_name: rule.name().to_string(),
                            secret,
                            location: FindingLocation::new(
                                offset_span.start,
                                offset_span.end,
                                source_span.start.line,
                                source_span.start.column,
                                source_span.end.line,
                                source_span.end.column,
                            ),
                            confidence,
                            entropy,
                            fingerprint,
                            captures: capture_map.into_iter().collect::<HashMap<_, _>>(),
                            is_base64_encoded: false,
                            blob_id: blob.id(),
                        },
                        association_span: full_capture_span,
                        secret_span: offset_span,
                        #[cfg(feature = "context")]
                        rule_index: rule_id,
                        #[cfg(feature = "context")]
                        buffer_id: 0,
                    });
                }

                if confirmed || scan_start == 0 {
                    break;
                }

                // Keep the bounded fast path for ordinary candidates and widen only when exact
                // confirmation fails, removing the match-length limit without routine blob scans.
                let lookback = scan_end - scan_start;
                scan_start = scan_end.saturating_sub(lookback.saturating_mul(2));
            }
        }

        // Scan Base64-encoded content
        if self.config.enable_base64_decoding {
            let b64_findings = self.scan_base64_content(
                blob,
                path,
                betterleaks_path_prefiltered,
                &loc_mapping,
                &mut seen_matches,
                control,
                #[cfg(feature = "context")]
                options,
            )?;
            findings.extend(b64_findings);
        }

        #[cfg(feature = "context")]
        if let Some(options) = options {
            crate::context::filter_findings(
                &self.rules_db,
                blob,
                path,
                &mut findings,
                options,
                control,
            )?;
        }
        enforce_betterleaks_components(&mut findings, bytes, cli_match_semantics, control)?;
        if cli_match_semantics {
            let keep = crate::postprocess::credential_uri_keep(
                findings.iter().map(|f| (f.rule.as_ref(), f.association_span, f.secret.as_bytes())),
                control,
            )?;
            let mut index = 0;
            findings.retain(|_| {
                let retain = keep[index];
                index += 1;
                retain
            });
        }
        control.check()?;
        deduplicate_imported_catalog_findings(&mut findings, cli_match_semantics, control)?;
        control.check()?;

        // Redact only after dependency matching and fingerprint calculation.
        if self.config.redact_secrets {
            for finding in &mut findings {
                control.check()?;
                finding.secret = "[REDACTED]".to_owned();
                for value in finding.captures.values_mut() {
                    *value = "[REDACTED]".to_owned();
                }
            }
        }
        control.check()?;
        // Mark blob as seen for dedup
        if self.config.enable_dedup && !findings.is_empty() {
            self.seen_blobs.write().insert((blob.id(), path.to_owned()));
        }

        Ok(findings.into_iter().map(|matched| matched.finding).collect())
    }

    /// Resets the deduplication state.
    ///
    /// Call this to clear the seen blobs cache if you want to rescan
    /// previously scanned content. Scans already in flight can still commit entries
    /// after the reset; wait for them to finish before resetting for a fresh batch.
    pub fn reset_dedup(&self) {
        self.seen_blobs.write().clear();
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_base64_content(
        &self,
        blob: &Blob,
        path: &str,
        betterleaks_path_prefiltered: bool,
        loc_mapping: &LocationMapping,
        seen_matches: &mut FxHashSet<u64>,
        control: &ScanControl,
        #[cfg(feature = "context")] options: Option<&crate::context::DetectionOptions>,
    ) -> Result<Vec<ScanFinding>> {
        let mut findings = Vec::new();
        let bytes = blob.bytes();
        #[cfg(feature = "context")]
        let cli_match_semantics = options.is_some_and(|o| o.cli_match_semantics);
        #[cfg(not(feature = "context"))]
        let cli_match_semantics = false;

        #[cfg(feature = "context")]
        let (max_depth, max_input_bytes) =
            options.map_or((1, None), |o| (o.base64_max_depth, o.base64_max_input_bytes));
        #[cfg(not(feature = "context"))]
        let (max_depth, max_input_bytes) = (1, None::<usize>);
        if max_depth == 0 || max_input_bytes.is_some_and(|limit| bytes.len() > limit) {
            return Ok(findings);
        }
        let mut b64_items: Vec<_> = primitives::get_base64_strings_with_control(bytes, control)?
            .into_iter()
            .map(|item| (item, 1))
            .collect();
        // Preserve legacy first-layer order; CLI-compatible scans use a stack for nested decoding.
        if max_depth == 1 {
            b64_items.reverse();
        }
        #[cfg(feature = "context")]
        let mut buffer_id = 0;
        while let Some((item, depth)) = b64_items.pop() {
            control.check()?;
            #[cfg(feature = "context")]
            {
                buffer_id += 1;
            }
            // CLI spans belong to this decoded buffer. Legacy scans retain their
            // historical source-span deduplication across first-layer buffers.
            let mut decoded_seen_matches = FxHashSet::default();
            let seen_matches =
                if cli_match_semantics { &mut decoded_seen_matches } else { &mut *seen_matches };
            let fragment_raw = std::cell::OnceCell::new();
            let line_index = std::cell::OnceCell::new();
            let mut filter_lines = FxHashMap::default();
            let mut filter_line_cache = BetterleaksFilterLineCache::default();
            let mut candidate_rule_ids = Vec::new();
            let mut seen_candidate_rules = FxHashSet::default();
            let scan_result = self.scanner_pool.try_with(|scanner| {
                scanner.scan(&item.decoded, |rule_id, _from, _to, _flags| {
                    if control.check().is_err() {
                        return kingfisher_vectorscan::Scan::Terminate;
                    }
                    let rule_id = rule_id as usize;
                    if rule_id < self.rules_db.num_rules() && seen_candidate_rules.insert(rule_id) {
                        candidate_rule_ids.push(rule_id);
                    }
                    kingfisher_vectorscan::Scan::Continue
                })
            });
            control.check()?;
            scan_result??;
            for rule_id in candidate_rule_ids {
                control.check()?;
                if betterleaks_path_prefiltered && self.rules_db.is_betterleaks_rule(rule_id) {
                    continue;
                }
                let Some(rule) = self.rules_db.get_rule(rule_id) else {
                    continue;
                };
                if !rule.matches_path(path) {
                    continue;
                }
                let regex = &self.rules_db.anchored_regexes()[rule_id];

                for captures in regex.captures_iter(&item.decoded) {
                    control.check()?;
                    let full_capture = captures.get(0).expect("regex captures include group zero");
                    let secret_capture = primitives::find_secret_capture_with_group(
                        regex,
                        &captures,
                        rule.betterleaks_secret_group(),
                    );
                    let secret_bytes = secret_capture.as_bytes();

                    let min_entropy =
                        self.config.min_entropy_override.unwrap_or(rule.min_entropy());
                    let entropy = calculate_shannon_entropy(secret_bytes);
                    if entropy <= min_entropy {
                        continue;
                    }

                    let capture_map = named_captures(regex, &captures);
                    let filter_outcome = if let Some(expression) = rule.betterleaks_filter() {
                        let full_match = String::from_utf8_lossy(full_capture.as_bytes());
                        let secret = String::from_utf8_lossy(secret_bytes);
                        let fragment_raw =
                            fragment_raw.get_or_init(|| String::from_utf8_lossy(&item.decoded));
                        let (match_line_start_idx, match_line_end_idx) = line_index
                            .get_or_init(|| crate::line_index::LineIndex::new(&item.decoded))
                            .bounds(full_capture.start(), full_capture.end());
                        let line = filter_line(
                            &item.decoded,
                            match fragment_raw {
                                std::borrow::Cow::Borrowed(text) => Some(*text),
                                _ => None,
                            },
                            (match_line_start_idx, match_line_end_idx),
                            line_index.get().unwrap(),
                            &mut filter_lines,
                        );
                        let context = BetterleaksFilterContext {
                            path,
                            secret: &secret,
                            full_match: &full_match,
                            line: &line,
                            fragment_raw,
                            match_start_idx: full_capture.start(),
                            match_end_idx: full_capture.end(),
                            match_line_start_idx,
                            match_line_end_idx,
                            rule_id: rule.id(),
                            description: rule.name(),
                            captures: capture_map.clone(),
                        };
                        Some(self.rules_db.evaluate_betterleaks_filter_with_line_cache(
                            expression,
                            &context,
                            match_line_start_idx..match_line_end_idx,
                            &mut filter_line_cache,
                        )?)
                    } else {
                        None
                    };
                    if filter_outcome.is_some_and(|outcome| outcome.discard) {
                        continue;
                    }
                    let confidence = filter_outcome
                        .and_then(|outcome| outcome.confidence)
                        .unwrap_or_else(|| rule.confidence());
                    if !rule.accepts_effective_confidence(confidence) {
                        continue;
                    }

                    // CLI-compatible association coordinates translate decoded
                    // offsets from the outer encoded start, at every depth.
                    // They are synthetic, not byte positions in the source.
                    // Public locations always cover the outer encoded span.
                    let key_span = if cli_match_semantics {
                        OffsetSpan::from_range(
                            (item.pos_start + secret_capture.start())
                                ..(item.pos_start + secret_capture.end()),
                        )
                    } else {
                        OffsetSpan::from_range(item.pos_start..item.pos_end)
                    };
                    let match_key = primitives::compute_match_key(
                        secret_bytes,
                        rule.id().as_bytes(),
                        key_span.start,
                        key_span.end,
                    );
                    if !seen_matches.insert(match_key) {
                        continue;
                    }

                    let offset_span = OffsetSpan::from_range(item.pos_start..item.pos_end);
                    let source_span = loc_mapping.get_source_span(&offset_span);

                    let secret = String::from_utf8_lossy(secret_bytes).to_string();

                    let fingerprint = primitives::compute_finding_fingerprint(
                        &secret,
                        &blob.id().to_string(),
                        offset_span.start as u64,
                        offset_span.end as u64,
                    );

                    findings.push(ScanFinding {
                        finding: Finding {
                            rule: finding_rule(&rule, confidence),
                            rule_id: rule.id().to_string(),
                            rule_name: rule.name().to_string(),
                            secret,
                            location: FindingLocation::new(
                                offset_span.start,
                                offset_span.end,
                                source_span.start.line,
                                source_span.start.column,
                                source_span.end.line,
                                source_span.end.column,
                            ),
                            confidence,
                            entropy,
                            fingerprint,
                            captures: capture_map.into_iter().collect::<HashMap<_, _>>(),
                            is_base64_encoded: true,
                            blob_id: blob.id(),
                        },
                        association_span: OffsetSpan::from_range(
                            (item.pos_start + full_capture.start())
                                ..(item.pos_start + full_capture.end()),
                        ),
                        secret_span: OffsetSpan::from_range(
                            (item.pos_start + secret_capture.start())
                                ..(item.pos_start + secret_capture.end()),
                        ),
                        #[cfg(feature = "context")]
                        rule_index: rule_id,
                        #[cfg(feature = "context")]
                        buffer_id,
                    });
                }
            }
            if depth < max_depth {
                for nested in primitives::get_base64_strings_with_control(&item.decoded, control)? {
                    b64_items.push((
                        primitives::DecodedData {
                            decoded: nested.decoded,
                            pos_start: item.pos_start,
                            pos_end: item.pos_end,
                        },
                        depth + 1,
                    ));
                }
            }
        }

        Ok(findings)
    }
}

fn deduplicate_imported_catalog_findings(
    findings: &mut Vec<ScanFinding>,
    cli_match_semantics: bool,
    control: &ScanControl,
) -> Result<()> {
    let keep = crate::postprocess::catalog_keep(
        findings.iter().map(|finding| {
            (
                finding.rule.as_ref(),
                if cli_match_semantics {
                    finding.secret_span
                } else {
                    OffsetSpan::from_range(
                        finding.location.start_offset..finding.location.end_offset,
                    )
                },
            )
        }),
        control,
    )?;
    let mut index = 0;
    findings.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
    Ok(())
}

fn finding_rule(rule: &Arc<Rule>, confidence: Confidence) -> Arc<Rule> {
    let suppress_helper_reporting =
        rule.is_runtime_dependency_helper() && !rule.reports_effective_confidence(confidence);
    if confidence == rule.confidence() && !suppress_helper_reporting {
        return Arc::clone(rule);
    }

    let mut effective_rule = rule.as_ref().clone();
    effective_rule.syntax.confidence = confidence;
    if suppress_helper_reporting {
        effective_rule.suppress_runtime_reporting();
    }
    Arc::new(effective_rule)
}

fn enforce_betterleaks_components(
    findings: &mut Vec<ScanFinding>,
    bytes: &[u8],
    cli_match_semantics: bool,
    control: &ScanControl,
) -> Result<()> {
    if !findings.iter().any(|finding| {
        finding
            .rule
            .syntax()
            .depends_on_rule
            .iter()
            .flatten()
            .any(|dependency| !dependency.optional && dependency.within.is_some())
    }) {
        return Ok(());
    }
    let mut line_starts = vec![0];
    for (chunk, data) in bytes.chunks(64 * 1024).enumerate() {
        use bstr::ByteSlice;
        control.check()?;
        line_starts.extend(data.find_iter(b"\n").map(|offset| chunk * 64 * 1024 + offset + 1));
    }
    let association_start = |f: &ScanFinding| {
        if cli_match_semantics { f.association_span.start } else { f.location.start_offset }
    };
    let offsets = crate::postprocess::RuleMatchIndex::new(
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| (finding.rule_id.as_str(), association_start(finding), index)),
    );
    let lines = crate::postprocess::RuleMatchIndex::new(
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| (finding.rule_id.as_str(), finding.location.line, index)),
    );
    fn dependencies(
        primary: &ScanFinding,
    ) -> impl Iterator<Item = &kingfisher_rules::DependsOnRule> {
        primary
            .rule
            .syntax()
            .depends_on_rule
            .iter()
            .flatten()
            .filter(|dependency| !dependency.optional && dependency.within.is_some())
    }
    let counts: Vec<_> = findings.iter().map(|primary| dependencies(primary).count()).collect();
    let keep = crate::components::dependency_keep(
        &counts,
        &mut (offsets, lines),
        |(offsets, lines), primary_index, dependency_index| {
            let primary = &findings[primary_index];
            let dependency = dependencies(primary).nth(dependency_index).unwrap();
            let within = dependency.within.as_deref().unwrap();
            let window = FindingWindow::parse(primary, within);
            let component_window = crate::postprocess::parse_component_window(within);
            let (index, range) = if cli_match_semantics {
                (
                    offsets,
                    component_window.map_or(0..0, |window| {
                        crate::postprocess::component_candidate_range_with_window(
                            bytes.len(),
                            &line_starts,
                            primary.association_span,
                            window,
                        )
                    }),
                )
            } else {
                match &window {
                    FindingWindow::Offsets(range) => (offsets, range.clone()),
                    FindingWindow::Lines(range, Some(columns))
                        if range.end.min(line_starts.len().saturating_add(1))
                            == range.start.max(1).saturating_add(1) =>
                    {
                        let start = line_starts[range.start.max(1) - 1];
                        (
                            offsets,
                            start.saturating_add(columns.start)..start.saturating_add(columns.end),
                        )
                    }
                    FindingWindow::Lines(range, _) => (lines, range.clone()),
                    FindingWindow::Any => (offsets, 0..usize::MAX),
                    FindingWindow::Invalid => (offsets, 0..0),
                }
            };
            for &(_, candidate_index) in index.candidates(&dependency.rule_id, range) {
                control.check()?;
                let candidate = &findings[candidate_index];
                if if cli_match_semantics {
                    component_window.is_some_and(|window| {
                        crate::postprocess::component_is_within_window(
                            bytes.len(),
                            &line_starts,
                            primary.association_span,
                            candidate.association_span,
                            window,
                        )
                    })
                } else {
                    window.contains(candidate)
                } {
                    return Ok(Some(candidate_index));
                }
            }
            Ok(None)
        },
        |(offsets, lines), primary_index| {
            let primary = &findings[primary_index];
            offsets.remove(&primary.rule_id, association_start(primary), primary_index);
            lines.remove(&primary.rule_id, primary.location.line, primary_index);
        },
        control,
    )?;

    let mut index = 0;
    findings.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
    Ok(())
}

enum FindingWindow {
    Any,
    Invalid,
    Offsets(std::ops::Range<usize>),
    Lines(std::ops::Range<usize>, Option<std::ops::Range<usize>>),
}

impl FindingWindow {
    fn parse(primary: &Finding, within: &str) -> Self {
        let within = within.trim();
        if within.is_empty() || within == "0" {
            return Self::Any;
        }

        let mut cols_before = 0;
        let mut cols_after = 0;
        let mut lines_before = None;
        let mut lines_after = None;
        for token in within.split(',').map(str::trim) {
            let (direction, amount_and_unit) = match token.as_bytes().first() {
                Some(b'+' | b'-') => (token.as_bytes()[0], &token[1..]),
                _ => (b' ', token),
            };
            let is_lines = amount_and_unit.ends_with(['L', 'l']);
            let amount =
                amount_and_unit.strip_suffix(['L', 'l', 'C', 'c']).unwrap_or(amount_and_unit);
            let Ok(mut amount) = amount.parse::<usize>() else {
                return Self::Invalid;
            };
            if is_lines {
                amount = amount.saturating_sub(1);
                if direction != b'+' {
                    lines_before = Some(lines_before.unwrap_or(0).max(amount));
                }
                if direction != b'-' {
                    lines_after = Some(lines_after.unwrap_or(0).max(amount));
                }
            } else {
                if direction != b'+' {
                    cols_before = cols_before.max(amount);
                }
                if direction != b'-' {
                    cols_after = cols_after.max(amount);
                }
            }
        }

        if lines_before.is_none() && lines_after.is_none() {
            return Self::Offsets(
                primary.location.start_offset.saturating_sub(cols_before)
                    ..primary.location.end_offset.saturating_add(cols_after),
            );
        }
        let columns = (primary.location.line == primary.location.end_line
            && (cols_before > 0 || cols_after > 0))
            .then(|| {
                primary.location.column.saturating_sub(cols_before)
                    ..primary.location.end_column.saturating_add(cols_after)
            });
        Self::Lines(
            primary.location.line.saturating_sub(lines_before.unwrap_or_default())
                ..primary
                    .location
                    .end_line
                    .saturating_add(lines_after.unwrap_or_default())
                    .saturating_add(1),
            columns,
        )
    }

    fn contains(&self, component: &Finding) -> bool {
        match self {
            Self::Any => true,
            Self::Invalid => false,
            Self::Offsets(range) => range.contains(&component.location.start_offset),
            Self::Lines(lines, columns) => {
                lines.contains(&component.location.line)
                    && columns
                        .as_ref()
                        .is_none_or(|range| range.contains(&component.location.column))
            }
        }
    }
}

#[cfg(feature = "validation")]
pub(crate) fn finding_is_within(primary: &Finding, component: &Finding, within: &str) -> bool {
    FindingWindow::parse(primary, within).contains(component)
}

fn named_captures(
    regex: &regex::bytes::Regex,
    captures: &regex::bytes::Captures<'_>,
) -> BTreeMap<String, String> {
    regex
        .capture_names()
        .flatten()
        .filter_map(|name| {
            captures.name(name).map(|capture| {
                (name.to_string(), String::from_utf8_lossy(capture.as_bytes()).into_owned())
            })
        })
        .collect()
}

// Valid UTF-8 fragments let line filters borrow without revalidating each long line.
// For lossy input, cache only complete individual lines: their total storage is bounded
// by the input, even when many multiline matches overlap.
fn filter_line<'a>(
    bytes: &[u8],
    fragment: Option<&'a str>,
    (start, end): (usize, usize),
    line_index: &crate::line_index::LineIndex,
    cache: &'a mut FxHashMap<(usize, usize), String>,
) -> std::borrow::Cow<'a, str> {
    if let Some(text) = fragment {
        return std::borrow::Cow::Borrowed(&text[start..end]);
    }
    let line = &bytes[start..end];
    if line_index.is_single_line(start, end) {
        std::borrow::Cow::Borrowed(
            cache
                .entry((start, end))
                .or_insert_with(|| String::from_utf8_lossy(line).into_owned())
                .as_str(),
        )
    } else {
        std::borrow::Cow::Owned(String::from_utf8_lossy(line).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kingfisher_rules::{BetterleaksExpr, Confidence, Rule, RuleSyntax, get_builtin_rules};

    fn create_test_scanner_with_engine(vectorscan_compatible: bool) -> Scanner {
        let rules = vec![Rule::new(RuleSyntax {
            id: "test.secret".to_string(),
            name: "Test Secret".to_string(),
            pattern: r"secret_[a-z]{4}[0-9]{4}".to_string(),
            min_entropy: 2.0,
            confidence: Confidence::Medium,
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
            vectorscan_compatible,
        })];

        let rules_db = Arc::new(RulesDatabase::from_rules(rules).unwrap());
        Scanner::new(rules_db)
    }

    fn create_test_scanner() -> Scanner {
        create_test_scanner_with_engine(true)
    }

    #[cfg(feature = "context")]
    #[test]
    fn interruption_during_context_never_returns_partial_findings_or_commits_dedup() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let rules = Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
                "acme.context",
                "Context",
                r"(demo_[a-z0-9]{16})",
            ))])
            .unwrap(),
        );
        for (reason, markup) in [crate::ScanAborted::Cancelled, crate::ScanAborted::TimedOut]
            .into_iter()
            .flat_map(|reason| [(reason, false), (reason, true)])
        {
            let scanner = Scanner::with_config(
                Arc::clone(&rules),
                ScannerConfig {
                    enable_dedup: true,
                    enable_base64_decoding: false,
                    ..Default::default()
                },
            );
            let checks = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&checks);
            let control = ScanControl::default().with_check_observer(move |location| {
                if location.file().replace('\\', "/").ends_with("context/mod.rs")
                    && observed.fetch_add(1, Ordering::SeqCst) >= 1
                {
                    return Err(reason);
                }
                Ok(())
            });
            let blob = Blob::from_bytes(if markup {
                br#"<input password="demo_abcd1234efgh5678"><input password="demo_ijkl9012mnop3456"><input password="demo_qrst7890uvwx1234">"#.to_vec()
            } else {
                b"demo_abcd1234efgh5678\ndemo_ijkl9012mnop3456\ndemo_qrst7890uvwx1234".to_vec()
            });
            let options = crate::context::DetectionOptions {
                inline_ignores: !markup,
                cli_match_semantics: !markup,
                markup_context: markup,
                language: markup.then(|| "html".into()),
                ..Default::default()
            };
            let error = scanner
                .scan_blob_at_path_with_options_and_control(&blob, "config.env", &options, &control)
                .unwrap_err();
            assert_eq!(error.downcast_ref::<crate::ScanAborted>(), Some(&reason));
            assert!(checks.load(Ordering::SeqCst) >= 2);
            assert_eq!(
                scanner
                    .scan_blob_at_path_with_options(&blob, "config.env", &options)
                    .unwrap()
                    .len(),
                3
            );
            assert!(
                scanner
                    .scan_blob_at_path_with_options(&blob, "config.env", &options)
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn test_scan_bytes_finds_secret() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"my secret_abcd1234 is here").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abcd1234");
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"nothing secret here").unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_bytes_multiple_matches() {
        let scanner = create_test_scanner();
        let findings =
            scanner.scan_bytes(b"first secret_aaaa1111 and second secret_bbbb2222").unwrap();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_scan_bytes_uses_vectorscan_for_base64_candidates() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"c2VjcmV0X2FiY2QxMjM0c2VjcmV0X2FiY2QxMjM0").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abcd1234");
        assert!(findings[0].is_base64_encoded);
    }

    #[test]
    fn scans_utf16_and_utf32_with_or_without_bom() {
        let scanner = create_test_scanner();
        let source = b"my secret_abcd1234 is here";
        let cases = [
            (encode_utf16(source, true, true), "UTF-16 LE BOM"),
            (encode_utf16(source, false, true), "UTF-16 BE BOM"),
            (encode_utf16(source, true, false), "UTF-16 LE"),
            (encode_utf16(source, false, false), "UTF-16 BE"),
            (encode_utf32(source, true, true), "UTF-32 LE BOM"),
            (encode_utf32(source, false, true), "UTF-32 BE BOM"),
            (encode_utf32(source, true, false), "UTF-32 LE"),
            (encode_utf32(source, false, false), "UTF-32 BE"),
        ];
        for (encoded, name) in cases {
            let findings = scanner.scan_bytes(&encoded).unwrap();
            assert_eq!(findings.len(), 1, "{name} should be scanned");
            assert_eq!(findings[0].secret, "secret_abcd1234", "{name}");
        }
    }

    fn encode_utf16(input: &[u8], little_endian: bool, bom: bool) -> Vec<u8> {
        let mut output = Vec::new();
        if bom {
            output.extend_from_slice(if little_endian { &[0xff, 0xfe] } else { &[0xfe, 0xff] });
        }
        for &byte in input {
            let encoded = if little_endian {
                (byte as u16).to_le_bytes()
            } else {
                (byte as u16).to_be_bytes()
            };
            output.extend_from_slice(&encoded);
        }
        output
    }

    fn encode_utf32(input: &[u8], little_endian: bool, bom: bool) -> Vec<u8> {
        let mut output = Vec::new();
        if bom {
            output.extend_from_slice(if little_endian {
                &[0xff, 0xfe, 0, 0]
            } else {
                &[0, 0, 0xfe, 0xff]
            });
        }
        for &byte in input {
            let encoded = if little_endian {
                (byte as u32).to_le_bytes()
            } else {
                (byte as u32).to_be_bytes()
            };
            output.extend_from_slice(&encoded);
        }
        output
    }

    #[test]
    fn legacy_engine_hint_does_not_bypass_vectorscan() {
        let scanner = create_test_scanner_with_engine(false);
        let findings = scanner.scan_bytes(b"my secret_abcd1234 is here").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abcd1234");
    }

    #[test]
    fn betterleaks_filters_receive_source_paths() {
        let mut builtins = get_builtin_rules(None).unwrap();
        let prefilter = builtins.betterleaks_prefilter.clone();
        let syntax = builtins
            .rules
            .remove("betterleaks.github-pat")
            .expect("Betterleaks GitHub PAT rule should be embedded");
        let database = Arc::new(
            RulesDatabase::from_rules_with_betterleaks_prefilter(
                vec![Rule::new(syntax)],
                prefilter,
            )
            .unwrap(),
        );
        let token = b"token=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";

        let source_scanner = Scanner::new(database.clone());
        let source = Blob::from_bytes(token.to_vec());
        assert_eq!(source_scanner.scan_blob_at_path(&source, "src/config.rs").unwrap().len(), 1);

        let fixture_scanner = Scanner::new(database);
        let fixture = Blob::from_bytes(token.to_vec());
        assert!(
            fixture_scanner
                .scan_blob_at_path(&fixture, "node_modules/@octokit/auth-token/README.md")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn betterleaks_source_prefilter_only_gates_betterleaks_rules() {
        let mut builtins = get_builtin_rules(None).unwrap();
        let prefilter = builtins.betterleaks_prefilter.clone();
        let builtin = Rule::new(
            builtins.rules.remove("betterleaks.github-pat").expect("Betterleaks rule should exist"),
        );
        let rule = |id: &str, name: &str, pattern: &str| {
            Rule::new(RuleSyntax {
                id: id.to_string(),
                name: name.to_string(),
                pattern: pattern.to_string(),
                min_entropy: 0.0,
                confidence: Confidence::Medium,
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
            })
        };
        let custom_toml = rule(
            "custom.path-prefilter.1",
            "Custom TOML path-prefilter rule",
            r"(toml_[A-Za-z0-9]{16})",
        );
        let custom_yaml = rule(
            "private.path-prefilter.1",
            "Custom YAML path-prefilter rule",
            r"(yaml_[A-Za-z0-9]{16})",
        );
        let veles = rule(
            "veles.test/pathprefilter",
            "Veles path-prefilter rule",
            r"(veles_[A-Za-z0-9]{16})",
        );
        let database = Arc::new(
            RulesDatabase::from_rules_with_betterleaks_prefilter(
                vec![builtin, custom_toml, custom_yaml, veles],
                prefilter,
            )
            .unwrap(),
        );
        let content = Blob::from_bytes(
            b"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\n\
toml_AbCdEfGhIjKlMnOp\nyaml_AbCdEfGhIjKlMnOp\nveles_AbCdEfGhIjKlMnOp"
                .to_vec(),
        );

        let source_scanner = Scanner::new(database.clone());
        let source_findings = source_scanner.scan_blob_at_path(&content, "src/config.rs").unwrap();
        assert_eq!(source_findings.len(), 4);

        let fixture_scanner = Scanner::new(database);
        let mut fixture_ids =
            fixture_scanner.scan_blob_at_path(&content, "node_modules/package/README.md").unwrap();
        fixture_ids.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        assert_eq!(
            fixture_ids.iter().map(|finding| finding.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["custom.path-prefilter.1", "private.path-prefilter.1", "veles.test/pathprefilter",]
        );
    }

    #[test]
    fn betterleaks_secret_group_controls_high_level_finding_secret() {
        let rule = Rule::new(RuleSyntax {
            id: "betterleaks.capture-selection".to_string(),
            name: "Betterleaks capture selection".to_string(),
            pattern: r"(prefix_([A-Za-z0-9]{16}))".to_string(),
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
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: Some(2),
            authoritative: true,
            vectorscan_compatible: true,
        });
        assert!(rule.syntax().as_regex().unwrap().is_match(b"prefix_AbCdEfGhIjKlMnOp"));
        let scanner = Scanner::new(Arc::new(RulesDatabase::from_rules(vec![rule]).unwrap()));
        let findings = scanner.scan_bytes(b"prefix_AbCdEfGhIjKlMnOp").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "AbCdEfGhIjKlMnOp");
    }

    #[test]
    fn confirms_exact_matches_longer_than_initial_lookback() {
        let make_rule = |id: &str, name: &str, pattern: &str, secret_group| {
            Rule::new(RuleSyntax {
                id: id.into(),
                name: name.into(),
                pattern: pattern.into(),
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
                path: None,
                betterleaks_filter: None,
                betterleaks_secret_group: secret_group,
                authoritative: true,
                vectorscan_compatible: true,
            })
        };
        let rules_db = Arc::new(
            RulesDatabase::from_rules(vec![
                make_rule(
                    "betterleaks.1password-service-account-token-test",
                    "1Password service account token",
                    r"ops_eyJ[A-Za-z0-9+/]{250,}={0,3}",
                    Some(0),
                ),
                make_rule(
                    "test.long-private-key",
                    "Long private key",
                    r"(-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/\n]+\n-----END PRIVATE KEY-----)",
                    None,
                ),
            ])
            .unwrap(),
        );
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

        let scanner = Scanner::with_config(
            rules_db,
            ScannerConfig { enable_base64_decoding: false, ..ScannerConfig::default() },
        );
        let findings = scanner.scan_bytes(&input).unwrap();

        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.secret.as_bytes() == token));
        assert!(findings.iter().any(|finding| finding.secret.as_bytes() == private_key));
    }

    #[test]
    fn betterleaks_finding_filters_discard_candidates_before_reporting() {
        let filter = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".to_string() }),
            arguments: vec![
                BetterleaksExpr::Member {
                    node: Box::new(BetterleaksExpr::Identifier { value: "finding".to_string() }),
                    property: Box::new(BetterleaksExpr::String { value: "secret".to_string() }),
                    optional: false,
                    method: false,
                },
                BetterleaksExpr::Array {
                    nodes: vec![BetterleaksExpr::String { value: "discard".to_string() }],
                },
            ],
        };
        let rule = Rule::new(RuleSyntax {
            id: "betterleaks.filter-test".to_string(),
            name: "Betterleaks finding filter".to_string(),
            pattern: r"(token_[a-z]{6,32})".to_string(),
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
            path: None,
            betterleaks_filter: Some(filter),
            betterleaks_secret_group: Some(1),
            authoritative: true,
            vectorscan_compatible: true,
        });
        let scanner = Scanner::new(Arc::new(RulesDatabase::from_rules(vec![rule]).unwrap()));
        let findings = scanner.scan_bytes(b"token_discard token_keepme").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "token_keepme");
    }

    #[test]
    fn betterleaks_capability_filter_suppresses_stripe_test_tokens() {
        let mut rules = get_builtin_rules(None).unwrap();
        let stripe = Rule::new(
            rules
                .rules
                .remove("betterleaks.stripe-access-token")
                .expect("Betterleaks catalog should contain Stripe access tokens"),
        );
        let database = Arc::new(RulesDatabase::from_rules(vec![stripe]).unwrap());
        let scanner = Scanner::new(database);

        let findings = scanner.scan_bytes(
            b"live=sk_live_51H8mHnGp6qGv7Kc9l1DdS3uVpjkz9gDf2QpPnPO2xZTfWnyQbB3hH9WZQwJfBQEZl7IuK2\n\
test=sk_test_2MaYVU9EhTxxRKdvOPGiykzM",
        ).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].secret,
            "sk_live_51H8mHnGp6qGv7Kc9l1DdS3uVpjkz9gDf2QpPnPO2xZTfWnyQbB3hH9WZQwJfBQEZl7IuK2"
        );
    }

    #[test]
    fn veles_bitwarden_import_reports_the_client_secret() {
        let mut rules = get_builtin_rules(None).unwrap();
        let rule = Rule::new(
            rules
                .rules
                .remove("veles.secrets/bitwardenoauth2access")
                .expect("pinned Veles catalog should contain Bitwarden OAuth2 credentials"),
        );
        assert!(rule.syntax().matches_path("/home/demo/Bitwarden CLI/data.json"));
        assert!(rule.syntax().as_regex().unwrap().is_match(
            br#"{"user_12345678-1234-1234-1234-123456789012_token_apiKeyClientSecret": "Ab3dE5fG7hI9jK1lM3nO5pQ7rS9tU"}"#,
        ));
        let scanner = Scanner::new(Arc::new(RulesDatabase::from_rules(vec![rule]).unwrap()));
        let blob = Blob::from_bytes(
            br#"{"user_12345678-1234-1234-1234-123456789012_token_apiKeyClientSecret": "Ab3dE5fG7hI9jK1lM3nO5pQ7rS9tU"}"#
                .to_vec(),
        );
        let findings =
            scanner.scan_blob_at_path(&blob, "/home/demo/Bitwarden CLI/data.json").unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "Ab3dE5fG7hI9jK1lM3nO5pQ7rS9tU");
    }
}
