use std::{collections::BTreeMap, sync::Arc};

use http::StatusCode;
use regex::bytes::Regex;
use rustc_hash::{FxHashMap, FxHashSet};
use tracing::debug;

use crate::{
    blob::Blob,
    entropy::calculate_shannon_entropy,
    inline_ignore::{InlineIgnoreConfig, InlineIgnoreIndex},
    location::OffsetSpan,
    origin::OriginSet,
    rule_profiling::{ConcurrentRuleProfiler, RuleTimer},
    rules::rule::{Rule, Validation},
    safe_list::{is_safe_match_reason, is_user_match},
};

use super::{
    BlobMatch,
    captures::SerializableCaptures,
    dedup::{compute_match_key, record_match},
};

// Re-use the canonical secret capture selection from kingfisher-scanner.
use kingfisher_rules::{
    RulesDatabase,
    betterleaks_filter::{BetterleaksFilterContext, BetterleaksFilterLineCache},
};
use kingfisher_scanner::primitives::{
    MatchSpans, check_pattern_requirements, check_uri_validation, find_secret_capture_with_group,
};

/// Check an example with the same capture selection and content filters used during scanning.
///
/// Examples have no source path or companion findings, so path restrictions, source prefilters,
/// inline ignore directives, and dependency resolution are intentionally not applied. No live
/// validation is performed. Any surviving match is enough, even if earlier matches are filtered.
pub fn rule_matches_example(rules_db: &RulesDatabase, rule_index: usize, example: &[u8]) -> bool {
    rule_matches_example_with_substring_filter(rules_db, rule_index, example, true)
}

/// Recheck a rejected example with only `ignore_if_contains` disabled.
///
/// The rules-check compatibility warning must not bypass entropy, safe-list,
/// checksum, URI, or rule filters. All other example-check semantics are unchanged.
#[doc(hidden)]
pub fn rule_matches_example_ignoring_substrings(
    rules_db: &RulesDatabase,
    rule_index: usize,
    example: &[u8],
) -> bool {
    rule_matches_example_with_substring_filter(rules_db, rule_index, example, false)
}

fn rule_matches_example_with_substring_filter(
    rules_db: &RulesDatabase,
    rule_index: usize,
    example: &[u8],
    respect_ignore_if_contains: bool,
) -> bool {
    let mut rule = Arc::clone(&rules_db.rules()[rule_index]);
    if rule.syntax().path.is_some() {
        Arc::make_mut(&mut rule).syntax.path = None;
    }
    let blob = Blob::from_bytes(example.to_vec());
    let origin = OriginSet::from(crate::origin::Origin::from_file("rule-example".into()));
    let mut matches = Vec::new();
    filter_match(
        rules_db,
        &blob,
        rule,
        &rules_db.anchored_regexes()[rule_index],
        0,
        example.len(),
        &mut matches,
        None,
        &mut FxHashMap::default(),
        rule_index,
        &mut FxHashSet::default(),
        &origin,
        None,
        false,
        false,
        "",
        None,
        None,
        respect_ignore_if_contains,
        &InlineIgnoreConfig::disabled(),
        &std::sync::OnceLock::new(),
        false,
        None,
        &mut BetterleaksFilterLineCache::default(),
    );
    !matches.is_empty()
}

// -------------------------------------------------------------------------------------------------
// Entropy and safe-list check
// -------------------------------------------------------------------------------------------------

/// Returns `Some(entropy)` if the match passes entropy and safe-list checks,
/// `None` if it should be skipped.
fn check_entropy_and_safelist(
    entropy_bytes: &[u8],
    full_bytes: &[u8],
    min_entropy: f32,
) -> Option<f32> {
    let calculated_entropy = calculate_shannon_entropy(entropy_bytes);
    if calculated_entropy <= min_entropy {
        debug!("Skipping match: entropy {} <= min_entropy {}", calculated_entropy, min_entropy);
        None
    } else if let Some(reason) = is_safe_match_reason(entropy_bytes) {
        debug!("Skipping match: safe-list match - {reason}");
        None
    } else if is_user_match(entropy_bytes, full_bytes) {
        debug!("Skipping match: user safe-list match");
        None
    } else {
        Some(calculated_entropy)
    }
}

// -------------------------------------------------------------------------------------------------
// filter_match — main entry point
// -------------------------------------------------------------------------------------------------

/// Source metadata available without fetching content or changing the caller's repository.
pub(super) fn source_attributes(
    origin: &crate::origin::Origin,
    path: &str,
    requested: &std::collections::BTreeSet<String>,
) -> BTreeMap<String, String> {
    use crate::origin::Origin;
    let needs = |name: &str| requested.contains(name) || requested.contains("*");
    let mut attributes = BTreeMap::from([("path".into(), path.to_owned())]);
    match origin {
        Origin::File(file) => {
            if needs("resource") {
                attributes.insert("resource".into(), "fs.content".into());
            }
            if needs("fs.first_fragment") {
                attributes.insert("fs.first_fragment".into(), "true".into());
            }
            if needs("fs.symlink")
                && std::fs::symlink_metadata(file.path.as_ref())
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                attributes.insert("fs.symlink".into(), path.to_owned());
            }
        }
        Origin::GitRepo(git) => {
            if needs("resource") {
                attributes.insert("resource".into(), "git.blob".into());
            }
            if let Some(commit) = &git.first_commit {
                let metadata = &commit.commit_metadata;
                if needs("git.sha") {
                    attributes.insert("git.sha".into(), metadata.commit_id.to_hex().to_string());
                }
                if needs("git.author_name")
                    && let Some(name) = &metadata.author_name
                {
                    attributes.insert("git.author_name".into(), name.to_string());
                }
                if needs("git.author_email")
                    && let Some(email) = &metadata.author_email
                {
                    attributes.insert("git.author_email".into(), email.to_string());
                }
                // The attribution snapshot retains no message or author timestamp.
                // Read the referenced local commit; unavailable metadata stays absent.
                let needs_commit = needs("git.message")
                    || needs("git.date")
                    || (needs("git.author_name") && metadata.author_name.is_none())
                    || (needs("git.author_email") && metadata.author_email.is_none());
                if needs_commit
                    && let Ok(repo) = gix::open(git.repo_path.as_ref())
                    && let Ok(commit) = repo.find_commit(metadata.commit_id)
                {
                    if needs("git.message")
                        && let Ok(message) = commit.message_raw()
                    {
                        attributes.insert(
                            "git.message".into(),
                            String::from_utf8_lossy(message.as_ref()).into_owned(),
                        );
                    }
                    if let Ok(author) = commit.author() {
                        if needs("git.author_name") {
                            attributes.insert(
                                "git.author_name".into(),
                                String::from_utf8_lossy(author.name.as_ref()).into_owned(),
                            );
                        }
                        if needs("git.author_email") {
                            attributes.insert(
                                "git.author_email".into(),
                                String::from_utf8_lossy(author.email.as_ref()).into_owned(),
                            );
                        }
                        if needs("git.date")
                            && let Ok(time) = gix::date::parse(author.time, None)
                            && let Some(date) =
                                chrono::DateTime::<chrono::Utc>::from_timestamp(time.seconds, 0)
                        {
                            attributes.insert(
                                "git.date".into(),
                                date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                            );
                        }
                    }
                }
            }
            if (needs("git.remote_url") || needs("git.platform"))
                && let Ok(remote) = crate::origin::get_repo_url(git.repo_path.as_ref())
            {
                if needs("git.remote_url") {
                    attributes.insert("git.remote_url".into(), remote.to_string());
                }
                if needs("git.platform")
                    && let Ok(url) = url::Url::parse(&remote)
                {
                    let platform = match url.host_str().unwrap_or_default() {
                        "github.com" => "github",
                        "gitlab.com" => "gitlab",
                        "bitbucket.org" => "bitbucket",
                        "dev.azure.com" => "azuredevops",
                        host if host.ends_with(".visualstudio.com") => "azuredevops",
                        _ => "unknown",
                    };
                    attributes.insert("git.platform".into(), platform.into());
                }
            }
        }
        Origin::Extended(extended) => {
            if let Some(values) =
                extended.0.get("attributes").and_then(serde_json::Value::as_object)
            {
                attributes.extend(values.iter().filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                }));
                attributes.insert("path".into(), path.to_owned());
            }
        }
    }
    attributes
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn filter_match<'b>(
    rules_db: &RulesDatabase,
    blob: &'b Blob,
    rule: Arc<Rule>,
    re: &Regex,
    start: usize,
    end: usize,
    matches: &mut Vec<BlobMatch<'b>>,
    full_matches: Option<&mut FxHashMap<usize, MatchSpans>>,
    previous_matches: &mut FxHashMap<usize, MatchSpans>,
    rule_id: usize,
    seen_matches: &mut FxHashSet<u64>,
    _origin: &OriginSet,
    ts_match: Option<&[u8]>,
    is_base64: bool,
    _redact: bool,
    filename: &str,
    source_attributes: Option<&BTreeMap<String, String>>,
    profiler: Option<&Arc<ConcurrentRuleProfiler>>,
    respect_ignore_if_contains: bool,
    inline_ignore_config: &InlineIgnoreConfig,
    inline_ignore_index: &std::sync::OnceLock<InlineIgnoreIndex>,
    bounded_confirmation: bool,
    candidate_index: Option<&kingfisher_scanner::primitives::CandidateMatchIndex>,
    filter_line_cache: &mut BetterleaksFilterLineCache,
) -> bool {
    if rule.syntax().betterleaks_path_only || !rule.matches_path(filename) {
        return false;
    }

    let mut timer =
        profiler.map(|p| RuleTimer::new(p, rule.id(), rule.name(), &rule.syntax.pattern, filename));
    let mut full_matches = full_matches;

    let initial_len = matches.len();

    let blob_bytes = blob.bytes();
    let default_slice = &blob_bytes[start..end];
    let haystack = ts_match.unwrap_or(default_slice);
    let line_index = std::cell::OnceCell::new();
    let fragment_raw = std::cell::OnceCell::new();
    let mut line_text = FxHashMap::default();
    let mut confirmed = false;

    let captures = if let Some(index) = candidate_index {
        kingfisher_scanner::__cli_internals::confirm(
            index,
            re,
            if rules_db.confirmation_prefix_stable(rule_id) {
                None
            } else {
                rules_db.endpoint_regex(rule_id)
            },
            haystack,
            start,
        )
    } else {
        kingfisher_scanner::__cli_internals::IndexedCaptures::search(re, haystack)
    };
    for captures in captures {
        let full_capture = captures.get(0).unwrap();
        // confirmation_needs_wider_window relies on rejecting interior matches.
        if bounded_confirmation
            && ((start > 0 && full_capture.start() == 0) || full_capture.end() != haystack.len())
        {
            continue;
        }
        confirmed = true;
        let full_capture_offset_span =
            OffsetSpan::from_range((start + full_capture.start())..(start + full_capture.end()));
        if let Some(full_matches) = full_matches.as_deref_mut()
            && !record_match(full_matches, rule_id, full_capture_offset_span)
        {
            continue;
        }
        let matching_input_for_entropy =
            find_secret_capture_with_group(re, &captures, rule.betterleaks_secret_group());

        let min_entropy = rule.min_entropy();
        let entropy_bytes = matching_input_for_entropy.as_bytes();
        let full_bytes = full_capture.as_bytes();
        if !rule.matches_keywords(full_bytes)
            && !rule.matches_keywords(ts_match.unwrap_or(blob_bytes))
        {
            continue;
        }

        // Check entropy and safe-listing
        let calculated_entropy =
            match check_entropy_and_safelist(entropy_bytes, full_bytes, min_entropy) {
                Some(e) => e,
                None => continue,
            };

        // Check pattern requirements
        if !check_pattern_requirements(
            &rule,
            re,
            &captures,
            full_bytes,
            entropy_bytes,
            respect_ignore_if_contains,
        ) {
            continue;
        }

        let filter_outcome = rule.betterleaks_filter().and_then(|expression| {
            let match_start_idx = full_capture.start();
            let match_end_idx = full_capture.end();
            let line_index = line_index
                .get_or_init(|| kingfisher_scanner::__cli_internals::LineIndex::new(haystack));
            let (match_line_start_idx, match_line_end_idx) =
                line_index.bounds(match_start_idx, match_end_idx);
            let fragment_raw = fragment_raw.get_or_init(|| String::from_utf8_lossy(haystack));
            let uncached_line;
            let line = if let std::borrow::Cow::Borrowed(text) = fragment_raw {
                &text[match_line_start_idx..match_line_end_idx]
            } else if line_index.is_single_line(match_line_start_idx, match_line_end_idx) {
                // Cache disjoint lines only: malformed UTF-8 may allocate an
                // owned conversion, and overlapping multiline spans must not
                // accumulate copies of the whole haystack.
                let converted = line_text
                    .entry((match_line_start_idx, match_line_end_idx))
                    .or_insert_with(|| {
                        String::from_utf8_lossy(&haystack[match_line_start_idx..match_line_end_idx])
                    });
                &**converted
            } else {
                uncached_line =
                    String::from_utf8_lossy(&haystack[match_line_start_idx..match_line_end_idx]);
                uncached_line.as_ref()
            };
            let captures = re
                .capture_names()
                .flatten()
                .filter_map(|name| {
                    captures.name(name).map(|capture| {
                        (name.to_string(), String::from_utf8_lossy(capture.as_bytes()).into_owned())
                    })
                })
                .collect::<BTreeMap<_, _>>();
            let secret = String::from_utf8_lossy(entropy_bytes);
            let full_match = String::from_utf8_lossy(full_bytes);
            let context = BetterleaksFilterContext {
                path: filename,
                attributes: source_attributes,
                secret: &secret,
                full_match: &full_match,
                line,
                fragment_raw,
                match_start_idx,
                match_end_idx,
                match_line_start_idx,
                match_line_end_idx,
                rule_id: rule.id(),
                description: rule.name(),
                captures,
            };
            match rules_db.evaluate_betterleaks_filter_with_line_cache(
                expression,
                &context,
                start + match_line_start_idx..start + match_line_end_idx,
                filter_line_cache,
            ) {
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
        let effective_confidence = filter_outcome
            .and_then(|outcome| outcome.confidence)
            .unwrap_or_else(|| rule.confidence());
        if !rule.accepts_effective_confidence(effective_confidence) {
            continue;
        }

        // Use the `matching_input_for_entropy` as the span/key for the finding.
        let matching_input = matching_input_for_entropy;

        let matching_input_offset_span = OffsetSpan::from_range(
            (start + matching_input.start())..(start + matching_input.end()),
        );

        // Check inline ignore directives
        if inline_ignore_config.should_ignore_cached(
            blob_bytes,
            &matching_input_offset_span,
            inline_ignore_index,
        ) {
            debug!("Skipping match due to inline ignore directive");
            continue;
        }

        // Check URI validation (MongoDB, Postgres, MySQL, and dynamic credential URIs)
        if !check_uri_validation(&rule, re, &captures, matching_input.as_bytes()) {
            continue;
        }

        // Deduplication
        let match_key = compute_match_key(
            matching_input.as_bytes(),
            rule.id().as_bytes(),
            matching_input_offset_span.start,
            matching_input_offset_span.end,
        );
        if !seen_matches.insert(match_key) {
            continue;
        }
        if !record_match(previous_matches, rule_id, matching_input_offset_span) {
            continue;
        }
        let only_matching_input =
            &blob.bytes()[matching_input_offset_span.start..matching_input_offset_span.end];

        // Pass the *full* capture object to from_captures
        let groups = SerializableCaptures::from_captures_with_secret_group(
            &captures,
            haystack,
            re,
            rule.betterleaks_secret_group(),
        );

        let suppress_helper_reporting = rule.is_runtime_dependency_helper()
            && !rule.reports_effective_confidence(effective_confidence);
        let match_rule = if effective_confidence != rule.confidence() || suppress_helper_reporting {
            let mut effective_rule = rule.as_ref().clone();
            effective_rule.syntax.confidence = effective_confidence;
            if suppress_helper_reporting {
                effective_rule.suppress_runtime_reporting();
            }
            Arc::new(effective_rule)
        } else {
            Arc::clone(&rule)
        };
        matches.push(BlobMatch {
            rule: match_rule,
            blob_id: blob.id_ref(),
            matching_input: only_matching_input,
            matching_input_offset_span,
            association_offset_span: full_capture_offset_span,
            captures: groups,
            validation_response_body: None,
            validation_response_status: StatusCode::from_u16(0).unwrap_or(StatusCode::CONTINUE),
            validation_success: false,
            validation_outcome: match rule.syntax().validation.as_ref() {
                Some(Validation::Assumed) => kingfisher_core::ValidationOutcome::Assumed,
                _ => kingfisher_core::ValidationOutcome::NotAttempted,
            },
            calculated_entropy,
            is_base64,
            dependent_captures: std::collections::BTreeMap::new(),
            ambiguous_dependencies: Default::default(),
            dependency_candidates: Default::default(),
        });
    }
    if let Some(t) = timer.take() {
        let new_count = (matches.len() - initial_len) as u64;
        t.end(new_count > 0, new_count, 0);
    }
    confirmed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{git_commit_metadata::CommitMetadata, origin::Origin};

    #[test]
    fn git_source_attributes_use_the_original_author_date_and_local_commit_message() {
        let directory = tempfile::tempdir().unwrap();
        let run_git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .current_dir(directory.path())
                .args(["-c", "user.name=Original Author", "-c", "user.email=original@example.com"])
                .args(args)
                .env("GIT_AUTHOR_DATE", "2026-01-02T03:04:05+00:00")
                .env("GIT_COMMITTER_DATE", "2026-05-06T07:08:09+00:00")
                .output()
                .unwrap();
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        };
        run_git(&["init", "--quiet"]);
        std::fs::write(directory.path().join("config.txt"), b"fixture").unwrap();
        run_git(&["add", "config.txt"]);
        run_git(&["commit", "--quiet", "--no-gpg-sign", "-m", "Original commit message"]);
        run_git(&["remote", "add", "origin", "https://github.com/example/project.git"]);
        let repository = gix::open(directory.path()).unwrap();
        let commit_id = repository.head_id().unwrap().detach();
        let origin = Origin::from_git_repo_with_first_commit(
            Arc::new(directory.path().to_path_buf()),
            Arc::new(CommitMetadata {
                commit_id,
                author_name: None,
                author_email: None,
                committer_name: "Different Committer".into(),
                committer_email: "committer@example.com".into(),
                committer_timestamp: gix::date::Time::new(0, 0),
            }),
            "config.txt".into(),
        );
        let attributes = source_attributes(
            &origin,
            "config.txt",
            &std::collections::BTreeSet::from(["*".into()]),
        );
        assert_eq!(attributes["path"], "config.txt");
        assert_eq!(attributes["git.sha"], commit_id.to_hex().to_string());
        assert_eq!(attributes["git.author_name"], "Original Author");
        assert_eq!(attributes["git.author_email"], "original@example.com");
        assert_eq!(attributes["git.date"], "2026-01-02T03:04:05Z");
        assert_eq!(attributes["git.message"], "Original commit message\n");
        assert_eq!(attributes["git.remote_url"], "https://github.com/example/project.git");
        assert_eq!(attributes["git.platform"], "github");
        let path_only = source_attributes(
            &origin,
            "config.txt",
            &std::collections::BTreeSet::from(["path".into()]),
        );
        assert_eq!(path_only, BTreeMap::from([("path".into(), "config.txt".into())]));
    }

    #[test]
    fn source_attributes_preserve_explicit_metadata_and_the_actual_logical_path() {
        let origin = Origin::from_extended(serde_json::json!({"path":"logical.txt","attributes":{
            "path":"incorrect.txt","fs.symlink":"link.txt","git.message":"fixture","numeric":42
        }}));
        let attributes = source_attributes(
            &origin,
            "logical.txt",
            &std::collections::BTreeSet::from(["*".into()]),
        );
        assert_eq!(attributes["path"], "logical.txt");
        assert_eq!(attributes["fs.symlink"], "link.txt");
        assert!(!attributes.contains_key("numeric"));
    }
}
