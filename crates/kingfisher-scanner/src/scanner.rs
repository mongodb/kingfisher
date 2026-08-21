//! High-level scanner API.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use kingfisher_core::{Blob, BlobIdMap, LocationMapping, OffsetSpan, calculate_shannon_entropy};
use kingfisher_rules::{
    Confidence, Rule, RulesDatabase, betterleaks_filter::BetterleaksFilterContext,
};
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::finding::{Finding, FindingLocation};
use crate::primitives;
use crate::scanner_pool::ScannerPool;

const RAW_MATCH_LOOKBACK: usize = 64 * 1024;

/// Configuration options for the scanner.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Whether to decode and scan Base64 content.
    pub enable_base64_decoding: bool,

    /// Whether to deduplicate findings.
    pub enable_dedup: bool,

    /// Override the minimum entropy threshold for all rules.
    pub min_entropy_override: Option<f32>,

    /// Language hint for parser-based context verification (e.g., "python", "javascript").
    pub language_hint: Option<String>,

    /// Whether to redact secrets in findings.
    pub redact_secrets: bool,

    /// Maximum depth for Base64 decoding (prevents infinite recursion).
    pub max_base64_depth: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            enable_base64_decoding: true,
            enable_dedup: true,
            min_entropy_override: None,
            language_hint: None,
            redact_secrets: false,
            max_base64_depth: 2,
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
/// # Examples
///
/// ```no_run
/// use kingfisher_scanner::{Scanner, ScannerConfig, RulesDatabase};
/// use std::sync::Arc;
///
/// // Assuming you have a compiled RulesDatabase
/// // let rules_db = Arc::new(RulesDatabase::from_rules(rules)?);
/// // let scanner = Scanner::new(rules_db);
/// //
/// // // Scan bytes
/// // let findings = scanner.scan_bytes(b"api_key = 'secret123'");
/// //
/// // // Scan a file
/// // let findings = scanner.scan_file("config.yml")?;
/// ```
pub struct Scanner {
    rules_db: Arc<RulesDatabase>,
    scanner_pool: Arc<ScannerPool>,
    config: ScannerConfig,
    seen_blobs: BlobIdMap<bool>,
}

impl Scanner {
    /// Creates a new scanner with the given rules database.
    pub fn new(rules_db: Arc<RulesDatabase>) -> Self {
        Self::with_config(rules_db, ScannerConfig::default())
    }

    /// Creates a new scanner with custom configuration.
    pub fn with_config(rules_db: Arc<RulesDatabase>, config: ScannerConfig) -> Self {
        let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
        Self { rules_db, scanner_pool, config, seen_blobs: BlobIdMap::new() }
    }

    /// Scans a byte slice for secrets.
    ///
    /// This is the most direct scanning method. The bytes are scanned in-place
    /// without copying.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use kingfisher_scanner::Scanner;
    /// # use std::sync::Arc;
    /// # fn example(scanner: &Scanner) {
    /// let content = b"password = 'super_secret_password_12345'";
    /// let findings = scanner.scan_bytes(content);
    /// for finding in findings {
    ///     println!("Found {} at line {}", finding.rule_name, finding.line());
    /// }
    /// # }
    /// ```
    pub fn scan_bytes(&self, bytes: &[u8]) -> Vec<Finding> {
        let blob = Blob::from_bytes(bytes.to_vec());
        self.scan_blob_at_path(&blob, "").unwrap_or_default()
    }

    /// Scans a file for secrets.
    ///
    /// Large files are automatically memory-mapped for efficiency.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Finding>> {
        let blob = Blob::from_file(&path)?;
        self.scan_blob_at_path(&blob, &path.as_ref().to_string_lossy())
    }

    /// Scans a blob for secrets.
    ///
    /// This is the core scanning method. Use this when you have a pre-existing
    /// `Blob` instance.
    pub fn scan_blob(&self, blob: &Blob) -> Result<Vec<Finding>> {
        self.scan_blob_at_path(blob, "")
    }

    /// Scan a blob while supplying the source path used by path-aware rules and filters.
    pub fn scan_blob_at_path(&self, blob: &Blob, path: &str) -> Result<Vec<Finding>> {
        // Check for dedup
        if self.config.enable_dedup {
            let blob_id = blob.id();
            if self.seen_blobs.contains_key(&blob_id) {
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

        // Run Vectorscan to find candidate matches
        let mut raw_matches = Vec::new();
        self.scanner_pool.with(|scanner| {
            let _ = scanner.scan(bytes, |rule_id, from, to, _flags| {
                if (rule_id as usize) < self.rules_db.num_rules() {
                    raw_matches.push((rule_id as usize, from as usize, to as usize));
                }
                vectorscan_rs::Scan::Continue
            });
        });
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
        let mut previous_full_spans: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        for (rule_id, _start, end) in raw_matches.into_iter().rev() {
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

            let Some(anchored_regex) = self.rules_db.anchored_regexes().get(rule_id) else {
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
                if previous_full_spans.get(&rule_id).is_some_and(|spans| {
                    spans.iter().any(|span| span.start < end && end <= span.end)
                }) {
                    continue;
                }
                (end.saturating_sub(RAW_MATCH_LOOKBACK), end)
            };
            let bounded_confirmation = !self.rules_db.uses_vectorscan_prefilter(rule_id);
            loop {
                let haystack = &bytes[scan_start..scan_end];
                let mut confirmed = false;

                for captures in anchored_regex.captures_iter(haystack) {
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
                    if !primitives::record_match(
                        &mut previous_full_spans,
                        rule_id,
                        full_capture_span,
                    ) {
                        continue;
                    }

                    // Get the primary secret value
                    let secret_capture = primitives::find_secret_capture_with_group(
                        anchored_regex,
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

                    let capture_map = named_captures(anchored_regex, &captures);
                    let filter_outcome = rule.betterleaks_filter().and_then(|expression| {
                        let full_match = String::from_utf8_lossy(full_capture.as_bytes());
                        let secret = String::from_utf8_lossy(secret_bytes);
                        let fragment_raw = String::from_utf8_lossy(bytes);
                        let match_start_idx = scan_start + full_capture.start();
                        let match_end_idx = scan_start + full_capture.end();
                        let (match_line_start_idx, match_line_end_idx) =
                            line_bounds(bytes, match_start_idx, match_end_idx);
                        let line = String::from_utf8_lossy(
                            &bytes[match_line_start_idx..match_line_end_idx],
                        );
                        let context = BetterleaksFilterContext {
                            path,
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
                            captures: capture_map.clone(),
                        };
                        match self.rules_db.evaluate_betterleaks_filter(expression, &context) {
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

                    let secret = if self.config.redact_secrets {
                        self.redact(secret_bytes)
                    } else {
                        String::from_utf8_lossy(secret_bytes).to_string()
                    };

                    let fingerprint = primitives::compute_finding_fingerprint(
                        &secret,
                        &blob.id().to_string(),
                        offset_span.start as u64,
                        offset_span.end as u64,
                    );

                    findings.push(Finding {
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
            );
            findings.extend(b64_findings);
        }

        enforce_betterleaks_components(&mut findings);
        deduplicate_imported_catalog_findings(&mut findings);

        // Mark blob as seen for dedup
        if self.config.enable_dedup && !findings.is_empty() {
            self.seen_blobs.insert(blob.id(), true);
        }

        Ok(findings)
    }

    /// Resets the deduplication state.
    ///
    /// Call this to clear the seen blobs cache if you want to rescan
    /// previously scanned content.
    pub fn reset_dedup(&self) {
        self.seen_blobs.clear();
    }

    fn redact(&self, bytes: &[u8]) -> String {
        let s = String::from_utf8_lossy(bytes);
        if s.len() <= 8 { "*".repeat(s.len()) } else { format!("{}...{}", &s[..4], "*".repeat(4)) }
    }

    fn scan_base64_content(
        &self,
        blob: &Blob,
        path: &str,
        betterleaks_path_prefiltered: bool,
        loc_mapping: &LocationMapping,
        seen_matches: &mut FxHashSet<u64>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let bytes = blob.bytes();

        // Find Base64-encoded strings
        let b64_items = primitives::get_base64_strings(bytes);

        for item in b64_items {
            let mut candidate_rule_ids = Vec::new();
            let mut seen_candidate_rules = FxHashSet::default();
            self.scanner_pool.with(|scanner| {
                let _ = scanner.scan(&item.decoded, |rule_id, _from, _to, _flags| {
                    let rule_id = rule_id as usize;
                    if rule_id < self.rules_db.num_rules() && seen_candidate_rules.insert(rule_id) {
                        candidate_rule_ids.push(rule_id);
                    }
                    vectorscan_rs::Scan::Continue
                });
            });
            for rule_id in candidate_rule_ids {
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
                    let filter_outcome = rule.betterleaks_filter().and_then(|expression| {
                        let full_match = String::from_utf8_lossy(full_capture.as_bytes());
                        let secret = String::from_utf8_lossy(secret_bytes);
                        let fragment_raw = String::from_utf8_lossy(&item.decoded);
                        let (match_line_start_idx, match_line_end_idx) = line_bounds(
                            &item.decoded,
                            full_capture.start(),
                            full_capture.end(),
                        );
                        let line = String::from_utf8_lossy(
                            &item.decoded[match_line_start_idx..match_line_end_idx],
                        );
                        let context = BetterleaksFilterContext {
                            path,
                            secret: &secret,
                            full_match: &full_match,
                            line: &line,
                            fragment_raw: &fragment_raw,
                            match_start_idx: full_capture.start(),
                            match_end_idx: full_capture.end(),
                            match_line_start_idx,
                            match_line_end_idx,
                            rule_id: rule.id(),
                            description: rule.name(),
                            captures: capture_map.clone(),
                        };
                        match self.rules_db.evaluate_betterleaks_filter(expression, &context) {
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
                    let confidence = filter_outcome
                        .and_then(|outcome| outcome.confidence)
                        .unwrap_or_else(|| rule.confidence());
                    if !rule.accepts_effective_confidence(confidence) {
                        continue;
                    }

                    let match_key = primitives::compute_match_key(
                        secret_bytes,
                        rule.id().as_bytes(),
                        item.pos_start,
                        item.pos_end,
                    );
                    if !seen_matches.insert(match_key) {
                        continue;
                    }

                    let offset_span = OffsetSpan::from_range(item.pos_start..item.pos_end);
                    let source_span = loc_mapping.get_source_span(&offset_span);

                    let secret = if self.config.redact_secrets {
                        self.redact(secret_bytes)
                    } else {
                        String::from_utf8_lossy(secret_bytes).to_string()
                    };

                    let fingerprint = primitives::compute_finding_fingerprint(
                        &secret,
                        &blob.id().to_string(),
                        offset_span.start as u64,
                        offset_span.end as u64,
                    );

                    findings.push(Finding {
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
                    });
                }
            }
        }

        findings
    }
}

fn deduplicate_imported_catalog_findings(findings: &mut Vec<Finding>) {
    let mut keep = vec![true; findings.len()];
    for left in 0..findings.len() {
        if !keep[left] || !findings[left].rule.visible() {
            continue;
        }
        let Some(left_catalog) = imported_catalog(&findings[left].rule_id) else {
            continue;
        };
        for right in (left + 1)..findings.len() {
            if !keep[right]
                || !findings[right].rule.visible()
                || findings[left].location.start_offset != findings[right].location.start_offset
                || findings[left].location.end_offset != findings[right].location.end_offset
            {
                continue;
            }
            let Some(right_catalog) = imported_catalog(&findings[right].rule_id) else {
                continue;
            };
            if left_catalog == right_catalog {
                continue;
            }
            let left_rank = imported_rule_rank(findings[left].rule.as_ref());
            let right_rank = imported_rule_rank(findings[right].rule.as_ref());
            if right_rank > left_rank {
                keep[left] = false;
                break;
            }
            keep[right] = false;
        }
    }
    let mut index = 0;
    findings.retain(|_| {
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

fn enforce_betterleaks_components(findings: &mut Vec<Finding>) {
    let mut keep = vec![true; findings.len()];
    loop {
        let mut changed = false;
        for (primary_index, primary) in findings.iter().enumerate() {
            if !keep[primary_index] {
                continue;
            }
            for dependency in primary.rule.syntax().depends_on_rule.iter().flatten() {
                let Some(within) = dependency.within.as_deref() else {
                    continue;
                };
                let found = findings.iter().enumerate().any(|(candidate_index, candidate)| {
                    keep[candidate_index]
                        && candidate.rule_id == dependency.rule_id
                        && finding_is_within(primary, candidate, within)
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

    let mut index = 0;
    findings.retain(|_| {
        let retain = keep[index];
        index += 1;
        retain
    });
}

fn finding_is_within(primary: &Finding, component: &Finding, within: &str) -> bool {
    let within = within.trim();
    if within.is_empty() || within == "0" {
        return true;
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
        let amount = amount_and_unit.trim_end_matches(['L', 'l', 'C', 'c']);
        let Ok(mut amount) = amount.parse::<usize>() else {
            return false;
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
        return component.location.start_offset
            >= primary.location.start_offset.saturating_sub(cols_before)
            && component.location.start_offset
                < primary.location.end_offset.saturating_add(cols_after);
    }
    if component.location.line
        < primary.location.line.saturating_sub(lines_before.unwrap_or_default())
        || component.location.line
            > primary.location.end_line.saturating_add(lines_after.unwrap_or_default())
    {
        return false;
    }
    if primary.location.line == primary.location.end_line && (cols_before > 0 || cols_after > 0) {
        return component.location.column >= primary.location.column.saturating_sub(cols_before)
            && component.location.column < primary.location.end_column.saturating_add(cols_after);
    }
    true
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

fn line_bounds(bytes: &[u8], start: usize, end: usize) -> (usize, usize) {
    let line_start =
        bytes[..start].iter().rposition(|byte| *byte == b'\n').map_or(0, |index| index + 1);
    let line_end = bytes[end..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(bytes.len(), |index| end + index);
    (line_start, line_end)
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

    #[test]
    fn test_scan_bytes_finds_secret() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"my secret_abcd1234 is here");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abcd1234");
    }

    #[test]
    fn test_scan_bytes_no_match() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"nothing secret here");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_bytes_multiple_matches() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"first secret_aaaa1111 and second secret_bbbb2222");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_scan_bytes_uses_vectorscan_for_base64_candidates() {
        let scanner = create_test_scanner();
        let findings = scanner.scan_bytes(b"c2VjcmV0X2FiY2QxMjM0c2VjcmV0X2FiY2QxMjM0");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].secret, "secret_abcd1234");
        assert!(findings[0].is_base64_encoded);
    }

    #[test]
    fn legacy_engine_hint_does_not_bypass_vectorscan() {
        let scanner = create_test_scanner_with_engine(false);
        let findings = scanner.scan_bytes(b"my secret_abcd1234 is here");
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
        let findings = scanner.scan_bytes(b"prefix_AbCdEfGhIjKlMnOp");

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
        let findings = scanner.scan_bytes(&input);

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
        let findings = scanner.scan_bytes(b"token_discard token_keepme");

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
                .expect("pinned Betterleaks catalog should contain Stripe access tokens"),
        );
        let database = Arc::new(RulesDatabase::from_rules(vec![stripe]).unwrap());
        let scanner = Scanner::new(database);

        let findings = scanner.scan_bytes(
            b"live=sk_live_51H8mHnGp6qGv7Kc9l1DdS3uVpjkz9gDf2QpPnPO2xZTfWnyQbB3hH9WZQwJfBQEZl7IuK2\n\
test=sk_test_2MaYVU9EhTxxRKdvOPGiykzM",
        );

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
