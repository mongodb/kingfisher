//! Opt-in CLI-compatible context filtering, before components, deduplication and redaction.
pub(crate) mod inline_ignore;
pub(crate) mod parser;

use crate::{Blob, OffsetSpan, RulesDatabase, ScanControl, scanner::ScanFinding};
use anyhow::Result;
use inline_ignore::InlineIgnoreConfig;
use parser::Language;
use std::{path::Path, sync::OnceLock};

/// CLI-compatible detection policies (including bounded nested Base64 decoding). Existing scanner methods leave these disabled.
#[derive(Clone, Debug)]
pub struct DetectionOptions {
    /// Use CLI confirmation windows, full-match component anchors, URI fallback suppression,
    /// and per-rule secret-span containment suppression. False preserves legacy SDK matching.
    pub cli_match_semantics: bool,
    /// Maximum decoded Base64 layers. Zero disables the pass; default is the CLI's two layers.
    pub base64_max_depth: usize,
    /// Skip Base64 decoding when the original input exceeds this byte count.
    /// `None` removes the cap; the default is the CLI's 64 MiB input limit.
    pub base64_max_input_bytes: Option<usize>,
    /// Honor `kingfisher:ignore` and additional comment markers.
    pub inline_ignores: bool,
    /// Additional case-insensitive ignore markers.
    pub ignore_comments: Vec<String>,
    /// Verify ambiguous HTML/CSS candidates structurally, on inputs up to 2 MiB.
    pub markup_context: bool,
    /// Explicit language hint; otherwise infer HTML/CSS from the logical path.
    pub language: Option<String>,
}

impl Default for DetectionOptions {
    fn default() -> Self {
        Self {
            cli_match_semantics: true,
            base64_max_depth: 2,
            base64_max_input_bytes: Some(64 * 1024 * 1024),
            inline_ignores: true,
            ignore_comments: Vec::new(),
            markup_context: true,
            language: None,
        }
    }
}

pub(crate) fn filter_findings(
    db: &RulesDatabase,
    blob: &Blob,
    path: &str,
    findings: &mut Vec<ScanFinding>,
    options: &DetectionOptions,
    control: &ScanControl,
) -> Result<()> {
    if options.inline_ignores {
        let config = InlineIgnoreConfig::new(&options.ignore_comments);
        let index = OnceLock::new();
        let mut retained = Vec::with_capacity(findings.len());
        for finding in std::mem::take(findings) {
            control.check()?;
            let span = if options.cli_match_semantics {
                finding.secret_span
            } else {
                OffsetSpan::from_range(finding.location.start_offset..finding.location.end_offset)
            };
            if !config.should_ignore_cached(blob.bytes(), &span, &index) {
                retained.push(finding);
            }
        }
        *findings = retained;
    }
    if options.cli_match_semantics {
        let mut spans = rustc_hash::FxHashMap::default();
        let mut retained = Vec::with_capacity(findings.len());
        for finding in std::mem::take(findings) {
            control.check()?;
            if crate::primitives::record_indexed_match(
                &mut spans,
                finding.rule_index,
                finding.secret_span,
            ) {
                retained.push(finding);
            }
        }
        *findings = retained;
    }
    if !options.markup_context || blob.len() > 2 * 1024 * 1024 || findings.is_empty() {
        return Ok(());
    }
    let inferred = kingfisher_core::content_type::ContentInspector::new()
        .guess_language(Path::new(path), blob.bytes());
    let hint = options.language.as_deref().or(inferred.as_deref()).unwrap_or("");
    let language = match Language::from_hint(hint) {
        Some(lang @ (Language::Html | Language::Css)) => lang,
        _ => return Ok(()),
    };
    // Group equal candidate values by their native rule index. Confirming the
    // same rule once per finding made dense HTML/CSS inputs quadratic; one
    // confirmed value satisfies all of its occurrences, as in the prior gate.
    let mut remaining: rustc_hash::FxHashMap<usize, rustc_hash::FxHashMap<&[u8], Vec<usize>>> =
        rustc_hash::FxHashMap::default();
    for (index, finding) in findings.iter().enumerate() {
        control.check()?;
        if finding.is_base64_encoded || db.is_rule_self_identifying(finding.rule_index) {
            continue;
        }
        // Parsers normalize invalid UTF-8; retain secrets they cannot represent
        // faithfully instead of treating normalization as rejection.
        let secret = &blob.bytes()[finding.location.start_offset..finding.location.end_offset];
        if std::str::from_utf8(secret).is_ok() {
            remaining.entry(finding.rule_index).or_default().entry(secret).or_default().push(index);
        }
    }
    if remaining.is_empty() {
        return Ok(());
    }
    let result = parser::stream_context_candidates(blob.bytes(), &language, |text| {
        if control.check().is_err() {
            return false;
        }
        remaining.retain(|rule, secrets| {
            let regex = &db.anchored_regexes()[*rule];
            for captures in regex.captures_iter(text.as_bytes()) {
                if control.check().is_err() {
                    return true;
                }
                let secret = crate::primitives::find_secret_capture_with_group(
                    regex,
                    &captures,
                    db.rules()[*rule].betterleaks_secret_group(),
                );
                secrets.remove(secret.as_bytes());
                if secrets.is_empty() {
                    break;
                }
            }
            !secrets.is_empty()
        });
        !remaining.is_empty()
    });
    control.check()?;
    // Preserve candidates when parsing fails, matching the CLI's fallback.
    if result.is_ok() {
        let rejected: std::collections::HashSet<_> =
            remaining.into_values().flat_map(|secrets| secrets.into_values().flatten()).collect();
        let mut index = 0;
        findings.retain(|_| {
            let keep = !rejected.contains(&index);
            index += 1;
            keep
        });
    }
    Ok(())
}
