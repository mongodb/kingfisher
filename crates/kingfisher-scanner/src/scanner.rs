//! High-level scanner API.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use kingfisher_core::{Blob, BlobIdMap, LocationMapping, OffsetSpan, calculate_shannon_entropy};
use kingfisher_rules::RulesDatabase;
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
        self.scan_blob(&blob).unwrap_or_default()
    }

    /// Scans a file for secrets.
    ///
    /// Large files are automatically memory-mapped for efficiency.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Finding>> {
        let blob = Blob::from_file(path)?;
        self.scan_blob(&blob)
    }

    /// Scans a blob for secrets.
    ///
    /// This is the core scanning method. Use this when you have a pre-existing
    /// `Blob` instance.
    pub fn scan_blob(&self, blob: &Blob) -> Result<Vec<Finding>> {
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

        // Run Vectorscan to find candidate matches
        let mut raw_matches = Vec::new();
        self.scanner_pool.with(|scanner| {
            let _ = scanner.scan(bytes, |rule_id, from, to, _flags| {
                raw_matches.push((rule_id as usize, from as usize, to as usize));
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
        let mut previous_full_spans: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();

        for (rule_id, start, end) in raw_matches.into_iter().rev() {
            let _ = start; // Block-mode Vectorscan reports `from` as 0 unless SOM is enabled.
            if !seen_raw_match_ends.insert((rule_id, end)) {
                continue;
            }
            let rule = match self.rules_db.get_rule(rule_id) {
                Some(r) => r,
                None => continue,
            };

            let anchored_regex = match rule.syntax().as_regex() {
                Ok(r) => r,
                Err(_) => continue,
            };

            let scan_start = end.saturating_sub(RAW_MATCH_LOOKBACK);
            let haystack = &bytes[scan_start..end];

            for captures in anchored_regex.captures_iter(haystack) {
                let full_capture = captures.get(0).unwrap();
                let full_capture_span = OffsetSpan::from_range(
                    (scan_start + full_capture.start())..(scan_start + full_capture.end()),
                );
                if !primitives::record_match(&mut previous_full_spans, rule_id, full_capture_span) {
                    continue;
                }

                // Get the primary secret value
                let secret_capture = primitives::find_secret_capture(&anchored_regex, &captures);
                let secret_bytes = secret_capture.as_bytes();

                // Check entropy
                let min_entropy = self.config.min_entropy_override.unwrap_or(rule.min_entropy());
                let entropy = calculate_shannon_entropy(secret_bytes);
                if entropy <= min_entropy {
                    debug!("Skipping low entropy match: {:.2} <= {:.2}", entropy, min_entropy);
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

                // Extract named captures
                let mut capture_map = HashMap::new();
                for name in anchored_regex.capture_names().flatten() {
                    if let Some(cap) = captures.name(name) {
                        let value = String::from_utf8_lossy(cap.as_bytes()).to_string();
                        capture_map.insert(name.to_string(), value);
                    }
                }

                let fingerprint = primitives::compute_finding_fingerprint(
                    &secret,
                    &blob.id().to_string(),
                    offset_span.start as u64,
                    offset_span.end as u64,
                );

                findings.push(Finding {
                    rule: rule.clone(),
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
                    confidence: rule.confidence(),
                    entropy,
                    fingerprint,
                    captures: capture_map,
                    is_base64_encoded: false,
                    blob_id: blob.id(),
                });
            }
        }

        // Scan Base64-encoded content
        if self.config.enable_base64_decoding {
            let b64_findings = self.scan_base64_content(blob, &loc_mapping, &mut seen_matches);
            findings.extend(b64_findings);
        }

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
        loc_mapping: &LocationMapping,
        seen_matches: &mut FxHashSet<u64>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let bytes = blob.bytes();

        // Find Base64-encoded strings
        let b64_items = primitives::get_base64_strings(bytes);

        for item in b64_items {
            // Try to match decoded content against all rules
            for rule in self.rules_db.rules() {
                let regex = match rule.syntax().as_regex() {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                for captures in regex.captures_iter(&item.decoded) {
                    let secret_capture = primitives::find_secret_capture(&regex, &captures);
                    let secret_bytes = secret_capture.as_bytes();

                    let min_entropy =
                        self.config.min_entropy_override.unwrap_or(rule.min_entropy());
                    let entropy = calculate_shannon_entropy(secret_bytes);
                    if entropy <= min_entropy {
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

                    let mut capture_map = HashMap::new();
                    for name in regex.capture_names().flatten() {
                        if let Some(cap) = captures.name(name) {
                            capture_map.insert(
                                name.to_string(),
                                String::from_utf8_lossy(cap.as_bytes()).to_string(),
                            );
                        }
                    }

                    let fingerprint = primitives::compute_finding_fingerprint(
                        &secret,
                        &blob.id().to_string(),
                        offset_span.start as u64,
                        offset_span.end as u64,
                    );

                    findings.push(Finding {
                        rule: rule.clone(),
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
                        confidence: rule.confidence(),
                        entropy,
                        fingerprint,
                        captures: capture_map,
                        is_base64_encoded: true,
                        blob_id: blob.id(),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kingfisher_rules::{Confidence, Rule, RuleSyntax};

    fn create_test_scanner() -> Scanner {
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
        })];

        let rules_db = Arc::new(RulesDatabase::from_rules(rules).unwrap());
        Scanner::new(rules_db)
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
}
