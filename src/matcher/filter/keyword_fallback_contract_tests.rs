use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::*;
use crate::blob::BlobIdMap;
use crate::matcher::{Matcher, ScanResult};
use crate::origin::Origin;
use crate::rules::rule::RuleSyntax;
use crate::scanner_pool::ScannerPool;

const PATTERN: &str = r"(acme_[A-Z0-9]{8})";
const FIRST: &str = "acme_Q7M2V8L4";
const SECOND: &str = "acme_R8N3W9K5";
const THIRD: &str = "acme_S9P4X2J6";
const KEYWORD: &str = "AUTHSOURCE";

#[derive(Debug, PartialEq)]
struct Finding {
    token: String,
    matching_bytes: Vec<u8>,
    span: (usize, usize),
    association_span: (usize, usize),
    is_base64: bool,
}

fn database(pattern: &str, keywords: &[&str]) -> RulesDatabase {
    let mut syntax = RuleSyntax::new("acme.keyword-fallback", "Keyword fallback", pattern);
    syntax.keywords = keywords.iter().map(|keyword| (*keyword).to_owned()).collect();
    syntax.betterleaks_secret_group = Some(1);
    RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap()
}

fn observe(matches: &[BlobMatch<'_>]) -> Vec<Finding> {
    matches
        .iter()
        .map(|finding| {
            let token = finding
                .captures
                .captures
                .iter()
                .find(|capture| capture.name == Some("TOKEN"))
                .expect("the explicitly selected secret group is TOKEN");
            Finding {
                token: token.raw_value().to_owned(),
                matching_bytes: finding.matching_input.to_vec(),
                span: (
                    finding.matching_input_offset_span.start,
                    finding.matching_input_offset_span.end,
                ),
                association_span: (
                    finding.association_offset_span.start,
                    finding.association_offset_span.end,
                ),
                is_base64: finding.is_base64,
            }
        })
        .collect()
}

fn filtered(
    database: &RulesDatabase,
    input: &[u8],
    start: usize,
    end: usize,
    bounded: bool,
) -> (bool, Vec<Finding>) {
    let blob = Blob::from_bytes(input.to_vec());
    let origin = OriginSet::from(Origin::from_file(PathBuf::from("keyword-fixture.txt")));
    let mut matches = Vec::new();
    let confirmed = filter_match(
        database,
        &blob,
        Arc::clone(&database.rules()[0]),
        &database.anchored_regexes()[0],
        start,
        end,
        &mut matches,
        None,
        &mut FxHashMap::default(),
        0,
        &mut FxHashSet::default(),
        &origin,
        None,
        false,
        false,
        "keyword-fixture.txt",
        None,
        None,
        true,
        &InlineIgnoreConfig::disabled(),
        &std::sync::OnceLock::new(),
        bounded,
        None,
        &mut BetterleaksFilterLineCache::default(),
    );
    (confirmed, observe(&matches))
}

fn scanned(database: &RulesDatabase, input: &[u8], no_base64: bool) -> Vec<Finding> {
    let blob = Blob::from_bytes(input.to_vec());
    let origin = OriginSet::from(Origin::from_file(PathBuf::from("keyword-fixture.txt")));
    let seen = BlobIdMap::new();
    let pool = Arc::new(ScannerPool::new(Arc::new(database.vectorscan_db().clone())));
    let mut matcher =
        Matcher::new(database, pool, &seen, None, false, None, &[], false, true).unwrap();
    let ScanResult::New(matches) =
        matcher.scan_blob(&blob, &origin, None, false, true, no_base64).unwrap()
    else {
        panic!("deduplication is disabled for these fixtures");
    };
    observe(&matches)
}

fn position(input: &[u8], value: &[u8]) -> usize {
    input.windows(value.len()).position(|window| window == value).unwrap()
}

fn assert_tokens(findings: &[Finding], expected: &[&str]) {
    let mut actual = findings.iter().map(|finding| finding.token.as_str()).collect::<Vec<_>>();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

#[test]
fn capture_keyword_hits_and_empty_keyword_lists_preserve_all_unique_captures() {
    let input = format!("{FIRST} {SECOND} {THIRD}");
    let with_keyword = database(PATTERN, &["ACME_"]);
    let without_gate = database(PATTERN, &[]);
    for captures in with_keyword.anchored_regexes()[0].captures_iter(input.as_bytes()) {
        assert!(with_keyword.rules()[0].matches_keywords(captures.get(0).unwrap().as_bytes()));
    }
    let (confirmed, findings) = filtered(&with_keyword, input.as_bytes(), 0, input.len(), false);
    assert!(confirmed);
    assert_tokens(&findings, &[FIRST, SECOND, THIRD]);
    assert_eq!(findings, filtered(&without_gate, input.as_bytes(), 0, input.len(), false).1);
}

#[test]
fn absent_whole_buffer_keyword_rejects_multiple_unique_captures_but_keeps_confirmation() {
    let input = format!("{FIRST} {SECOND} {THIRD}");
    let database = database(PATTERN, &[KEYWORD]);
    assert_eq!(database.anchored_regexes()[0].captures_iter(input.as_bytes()).count(), 3);
    assert!(!database.rules()[0].matches_keywords(input.as_bytes()));
    let (confirmed, findings) = filtered(&database, input.as_bytes(), 0, input.len(), false);
    assert!(confirmed, "keyword rejection does not undo exact regex confirmation");
    assert!(findings.is_empty());
    assert!(scanned(&database, input.as_bytes(), true).is_empty());
}

#[test]
fn keyword_outside_captures_authorizes_early_and_late_raw_context() {
    let database = database(PATTERN, &[KEYWORD]);
    for input in [
        format!("{KEYWORD} leading context {FIRST} {SECOND}"),
        format!("{FIRST} {SECOND} {} {KEYWORD}", "padding ".repeat(16)),
    ] {
        let (confirmed, findings) = filtered(&database, input.as_bytes(), 0, input.len(), false);
        assert!(confirmed);
        assert_tokens(&findings, &[FIRST, SECOND]);
        for finding in &findings {
            assert!(!database.rules()[0].matches_keywords(&finding.matching_bytes));
            let start = position(input.as_bytes(), finding.token.as_bytes());
            assert_eq!(finding.span, (start, start + finding.token.len()));
            assert_eq!(finding.association_span, finding.span);
            assert!(!finding.is_base64);
        }
        assert_tokens(&scanned(&database, input.as_bytes(), true), &[FIRST, SECOND]);
    }
}

#[test]
fn whole_buffer_keyword_decisions_do_not_leak_between_same_length_calls() {
    let database = database(PATTERN, &[KEYWORD]);
    let present = format!("{FIRST} {SECOND} {KEYWORD}");
    let absent = format!("{FIRST} {SECOND} NOHITVALUE");
    assert_eq!(present.len(), absent.len());
    for (input, expected) in [(&present, 2), (&absent, 0), (&present, 2)] {
        let (confirmed, findings) = filtered(&database, input.as_bytes(), 0, input.len(), false);
        assert!(confirmed);
        assert_eq!(findings.len(), expected);
    }
}

#[test]
fn bounded_raw_confirmation_uses_keyword_context_outside_its_window() {
    let database = database(PATTERN, &[KEYWORD]);
    for input in
        [format!("{KEYWORD} prefix {FIRST} suffix"), format!("prefix {FIRST} suffix {KEYWORD}")]
    {
        let token_start = position(input.as_bytes(), FIRST.as_bytes());
        let start = token_start - 1;
        let end = token_start + FIRST.len();
        assert!(!database.rules()[0].matches_keywords(&input.as_bytes()[start..end]));
        assert!(database.rules()[0].matches_keywords(input.as_bytes()));
        let (confirmed, findings) = filtered(&database, input.as_bytes(), start, end, true);
        assert!(confirmed);
        assert_tokens(&findings, &[FIRST]);
        assert_eq!(findings[0].span, (token_start, end));
        assert_eq!(findings[0].matching_bytes, FIRST.as_bytes());
    }
}

#[test]
fn keyword_context_does_not_override_bounded_confirmation_edges() {
    let database = database(PATTERN, &[KEYWORD]);
    let input = format!("{KEYWORD} prefix {FIRST} suffix");
    let token_start = position(input.as_bytes(), FIRST.as_bytes());
    let token_end = token_start + FIRST.len();
    for (start, end) in [(token_start, token_end), (token_start - 1, token_end + 1)] {
        let (confirmed, findings) = filtered(&database, input.as_bytes(), start, end, true);
        assert!(!confirmed);
        assert!(findings.is_empty());
    }
}

#[test]
fn base64_fallback_uses_decoded_context_and_rejects_outer_only_keywords() {
    let database = database(PATTERN, &[KEYWORD]);
    for (decoded, outer, expected) in [
        (format!("{FIRST} {SECOND} decoded context {KEYWORD}"), "prefix", 2),
        (format!("{FIRST} {SECOND} decoded context NOHITVALUE"), KEYWORD, 0),
    ] {
        let input = format!("{outer} {} suffix", STANDARD.encode(decoded.as_bytes()));
        assert_eq!(database.rules()[0].matches_keywords(input.as_bytes()), expected == 0);
        assert_eq!(database.rules()[0].matches_keywords(decoded.as_bytes()), expected != 0);
        assert!(scanned(&database, input.as_bytes(), true).is_empty());
        let findings = scanned(&database, input.as_bytes(), false);
        assert_eq!(findings.len(), expected);
        if expected != 0 {
            assert_tokens(&findings, &[FIRST, SECOND]);
            assert!(findings.iter().all(|finding| finding.is_base64));
        }
    }
}

#[test]
fn separate_decoded_items_do_not_share_keyword_fallback_decisions() {
    let database = database(PATTERN, &[KEYWORD]);
    let selected = STANDARD.encode(format!("decoded context {FIRST} ending {KEYWORD}"));
    let rejected = STANDARD.encode(format!("decoded context {SECOND} ending NOHITVALUE"));
    for (first, second) in [(&selected, &rejected), (&rejected, &selected)] {
        let input = format!("records {first} {second} ending");
        assert!(!database.rules()[0].matches_keywords(input.as_bytes()));
        let findings = scanned(&database, input.as_bytes(), false);
        assert_tokens(&findings, &[FIRST]);
        assert!(findings[0].is_base64);
    }
}

#[test]
fn later_capture_keyword_hit_survives_an_earlier_false_whole_buffer_fallback() {
    // Byte matching can cut a valid UTF-8 codepoint. Lossy Unicode keyword
    // matching is therefore not monotonic between a capture and its full blob.
    let database = database(r"([a-z][0-9][a-z][0-9]|[A-Z][0-9][A-Z][0-9]\xC3)", &["�"]);
    let input = "a1b2 A7B9é";
    let captures = database.anchored_regexes()[0]
        .captures_iter(input.as_bytes())
        .map(|capture| capture.get(0).unwrap().as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(captures, vec![b"a1b2".as_slice(), b"A7B9\xc3".as_slice()]);
    assert!(!database.rules()[0].matches_keywords(captures[0]));
    assert!(!database.rules()[0].matches_keywords(input.as_bytes()));
    assert!(database.rules()[0].matches_keywords(captures[1]));
    let (confirmed, findings) = filtered(&database, input.as_bytes(), 0, input.len(), false);
    assert!(confirmed);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].token, "A7B9�");
    assert_eq!(findings[0].matching_bytes, b"A7B9\xc3");
    assert_eq!(findings[0].span, (5, 10));
    assert_eq!(findings[0].association_span, (5, 10));
}

#[test]
fn inputs_without_regex_captures_do_not_become_confirmed_from_keyword_context() {
    let database = database(PATTERN, &[KEYWORD]);
    let input = format!("{KEYWORD} ordinary unrelated content");
    let (confirmed, findings) = filtered(&database, input.as_bytes(), 0, input.len(), false);
    assert!(!confirmed);
    assert!(findings.is_empty());
}
