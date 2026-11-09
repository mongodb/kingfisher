//! Unsupported full-buffer confirmation facade for scanner integration.
//!
//! Keep the original byte regex and its captures as the authority. A second
//! matcher only locates full-match spans. Proven necessary literals can locate
//! bounded-memory candidate starts; confirmation still uses the complete haystack.

use anyhow::{Context, Result};
use regex::bytes::{CaptureMatches, Captures, Regex};
use regex_automata::{Anchored, Input, Match, MatchKind, meta, util::syntax};

use crate::replay_starts::{StartCandidates, StartOracle};

/// Internal replay matcher; not a supported embedding API.
#[doc(hidden)]
pub struct ReplayRegex {
    original: Regex,
    finder: meta::Regex,
    starts: Option<StartOracle>,
}

impl ReplayRegex {
    /// Build a finder for a regex compiled by `RuleSyntax::as_regex`.
    ///
    /// This deliberately mirrors that byte builder's configuration. Arbitrary
    /// external builder options cannot be recovered from `Regex::as_str`, so an
    /// externally configured regex must not be passed here. Leading and scoped
    /// flags in the pattern itself are preserved.
    pub fn new(original: &Regex) -> Result<Self> {
        let starts = StartOracle::new(original.as_str());
        let cache_capacity = if starts.is_some() { 512 * 1024 } else { 2 * 1024 * 1024 };
        let finder = meta::Regex::builder()
            .configure(
                meta::Regex::config()
                    .match_kind(MatchKind::LeftmostFirst)
                    .utf8_empty(false)
                    .nfa_size_limit(Some(16 * 1024 * 1024))
                    .hybrid_cache_capacity(cache_capacity)
                    .auto_prefilter(false),
            )
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .build(original.as_str())
            .context("Failed to build the internal replay regex finder")?;
        Ok(Self { original: original.clone(), finder, starts })
    }

    /// Yield the original regex's captures over the complete, unchanged haystack.
    pub fn captures_iter<'r, 'h>(&'r self, haystack: &'h [u8]) -> ReplayCaptures<'r, 'h> {
        ReplayCaptures {
            original: &self.original,
            haystack,
            state: match &self.starts {
                Some(starts) => State::Starts(AnchoredMatches {
                    finder: &self.finder,
                    starts: starts.candidates(haystack),
                    remaining_work: anchored_work_budget(haystack.len()),
                    last_end: 0,
                    unanchored: false,
                    #[cfg(test)]
                    searches: 0,
                }),
                None => State::Replay(self.finder.find_iter(haystack)),
            },
            returned: 0,
        }
    }
}

/// Original byte-regex captures located by an internal replay finder.
#[doc(hidden)]
pub struct ReplayCaptures<'r, 'h> {
    original: &'r Regex,
    haystack: &'h [u8],
    state: State<'r, 'h>,
    returned: usize,
}

enum State<'r, 'h> {
    Replay(meta::FindMatches<'r, 'h>),
    Starts(AnchoredMatches<'r, 'h>),
    Original(CaptureMatches<'r, 'h>),
}

// An anchored search can inspect the entire suffix even when it fails. Charge that
// worst-case length before each attempt, not merely the candidate count or match length.
// For a fixed regex this bounds the extra search work to O(haystack.len()), including
// successful attempts and the subsequent original capture confirmation. Exhaustion is
// an optimization failure, never truncation: continue with one unanchored, linear
// finder pass from the end of the last returned match. Start-oracle replay requires a
// non-empty minimum match length, so no empty-match suppression state is lost.
const MAX_ANCHORED_HAYSTACK_PASSES: usize = 8;

fn anchored_work_budget(haystack_len: usize) -> usize {
    haystack_len.saturating_add(1).saturating_mul(MAX_ANCHORED_HAYSTACK_PASSES)
}

struct AnchoredMatches<'r, 'h> {
    finder: &'r meta::Regex,
    starts: StartCandidates<'r, 'h>,
    remaining_work: usize,
    last_end: usize,
    unanchored: bool,
    #[cfg(test)]
    searches: usize,
}

impl AnchoredMatches<'_, '_> {
    fn next(&mut self, haystack: &[u8]) -> Result<Option<Match>> {
        if self.unanchored {
            return Ok(self.next_unanchored(haystack));
        }
        while let Some(start) = self.starts.next_start()? {
            let work = haystack.len().saturating_sub(start).saturating_add(1);
            let Some(remaining) = self.remaining_work.checked_sub(work) else {
                tracing::debug!(
                    "Replay anchored search exhausted its work budget; scanning linearly"
                );
                self.unanchored = true;
                return Ok(self.next_unanchored(haystack));
            };
            self.remaining_work = remaining;
            #[cfg(test)]
            {
                self.searches += 1;
            }
            // A necessary literal is not a match. Preserve assertions, unbounded
            // suffixes, and leftmost-first semantics on the complete input.
            if let Some(found) =
                self.finder.find(Input::new(haystack).range(start..).anchored(Anchored::Yes))
            {
                self.last_end = found.end();
                self.starts.seek_to(found.end());
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Leftmost-first search over the unchanged haystack, resuming after the last
    /// returned match. Range searches keep look-behind context for `^` and `\b`.
    fn next_unanchored(&mut self, haystack: &[u8]) -> Option<Match> {
        let found = self.finder.find(Input::new(haystack).range(self.last_end..))?;
        self.last_end = found.end();
        Some(found)
    }
}

impl<'r, 'h> ReplayCaptures<'r, 'h> {
    /// Convert the remaining matches to the original byte-regex iterator.
    ///
    /// Replaying the verified prefix preserves full-haystack assertions and the
    /// original iterator's empty-match suppression, unlike resuming at an offset.
    pub fn into_legacy(self) -> CaptureMatches<'r, 'h> {
        match self.state {
            State::Original(captures) => captures,
            State::Replay(_) | State::Starts(_) => {
                original_after(self.original, self.haystack, self.returned)
            }
        }
    }
}

fn original_after<'r, 'h>(
    original: &'r Regex,
    haystack: &'h [u8],
    returned: usize,
) -> CaptureMatches<'r, 'h> {
    let mut captures = original.captures_iter(haystack);
    for _ in 0..returned {
        if captures.next().is_none() {
            break;
        }
    }
    captures
}

impl<'h> Iterator for ReplayCaptures<'_, 'h> {
    type Item = Captures<'h>;

    fn next(&mut self) -> Option<Self::Item> {
        let found = match &mut self.state {
            State::Original(captures) => return captures.next(),
            State::Replay(matches) => Ok(matches.next()),
            State::Starts(matches) => matches.next(self.haystack),
        };
        let found = match found {
            Ok(Some(found)) => found,
            Ok(None) => return None,
            Err(error) => {
                // Native allocation, scan, or bounded-buffer failures must retain
                // every remaining original match instead of ending confirmation.
                tracing::debug!(%error, "Replay start search failed; using original captures");
                self.state =
                    State::Original(original_after(self.original, self.haystack, self.returned));
                return self.next();
            }
        };
        if let Some(captures) = self.original.captures_at(self.haystack, found.start()) {
            let full = captures.get(0).expect("regex captures include group zero");
            if full.start() == found.start() && full.end() == found.end() {
                self.returned += 1;
                return Some(captures);
            }
        }

        // A disagreement must not silently drop or shift a match. Reconstruct the
        // original iterator over the full haystack and skip only captures already
        // returned. Resuming at a byte offset is insufficient: captures_iter also
        // suppresses empty matches immediately following a consuming match.
        tracing::debug!("Replay finder disagreed with the original regex; using original captures");
        self.state = State::Original(original_after(self.original, self.haystack, self.returned));
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CaptureTuples = Vec<Vec<Option<(usize, usize)>>>;

    fn original(pattern: &str) -> Regex {
        regex::bytes::RegexBuilder::new(pattern)
            .unicode(false)
            .size_limit(16 * 1024 * 1024)
            .build()
            .unwrap()
    }

    fn tuples<'h>(captures: impl Iterator<Item = Captures<'h>>) -> CaptureTuples {
        captures
            .map(|captures| captures.iter().map(|m| m.map(|m| (m.start(), m.end()))).collect())
            .collect()
    }

    fn assert_parity(pattern: &str, haystacks: &[Vec<u8>]) {
        let original = original(pattern);
        let replay = ReplayRegex::new(&original).unwrap();
        for haystack in haystacks {
            assert_eq!(
                tuples(replay.captures_iter(haystack)),
                tuples(original.captures_iter(haystack)),
                "all capture spans must agree for {pattern}"
            );
        }
    }

    #[test]
    fn replay_preserves_empty_overlapping_lazy_and_assertion_captures() {
        let patterns = [
            "",
            "a*",
            "(?:(a)|())",
            "(a*?)(a?)",
            "(a|aa)",
            "(aa|a)",
            "a+?",
            "(?:ab|a)b?",
            "(?P<outer>(?:a(?P<inner>b)?)*)",
            "^",
            "$",
            r"\A",
            r"\z",
            r"\b",
            r"\B",
            "(?m)^(.{0,3})$",
            "(?m)^$",
            "(?s)(.*?)",
            "(?s)(.*)",
            "(?m)(?:^|$)([ab]*)",
            "(?R)(?m)^(.*)$",
            "(?msR)^(.+?)$",
            "(?:(a)|(ab)|())",
            "(?s)(a.*?b|a.*b)",
            "(?U)(a.*b)",
            "(?x)( a | ab ) ( b? )",
            r"(?m:\A|^)(?P<token>[\w+/=]{0,10})(?:$|\z)",
            r"(?:\b){0,3}",
            r"(?:\B|^|$)",
            "(?:a|)*",
            "(?:a*|b*)",
            "(?:a*?){0,3}",
        ];
        let mut haystacks: Vec<Vec<u8>> = [
            b"".as_slice(),
            b"a",
            b"ab",
            b"aaa",
            b"abba",
            b"\n",
            b"\r\n",
            b"a\r\nb\n\r\nc",
            b"token=value\nkey=second",
            b"TokenKey=value",
            b"\xff\x80\xfe",
            b"\xffab\x80a\xfe",
            b"\x00a\x00b",
            b"a\nb\nc\n",
        ]
        .iter()
        .map(|haystack| haystack.to_vec())
        .collect();
        let mut seed = 0x123456789abcdefu64;
        for length in 0..32 {
            let mut haystack = Vec::new();
            for _ in 0..length {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                haystack.push((seed >> 32) as u8);
            }
            haystack.extend_from_slice(b"\nabc\r\naab token=\xffvalue\n");
            haystacks.push(haystack);
        }
        for pattern in patterns {
            assert_parity(pattern, &haystacks);
        }
    }

    #[test]
    fn replay_preserves_leading_scoped_unicode_flags_and_invalid_bytes() {
        let patterns = [
            r"(?u)(\w+)",
            r"(?u)(\b\w+\b)",
            r"(?u)(\b|\B)",
            r"(?u:\b)(?-u:\w+)",
            r"(?u:(\w+))|(?-u:(\xFF+))",
            r"(?i)(token|key)=(\w*)",
            r"(?i:token)(?-i:Key)=(?u:\w*)",
            r"(?u:é+)|(\xFF)",
            r"(?-u:(.))",
            r"(?-u:\b)(\w+)",
            r"(?u)\A(\w+)\z",
            r"[^\x00-\x7F]*",
            r"(?u:[^\p{L}]*)",
            r"(?u:(.|\n)*)",
            r"(?-u:\x80*|[a-z]*)",
        ];
        let mut haystacks = vec![
            Vec::new(),
            b"token=ASCII\nTokenKey=value".to_vec(),
            b"\xff\x80\xfe".to_vec(),
            b"\xc3\xa9\xff\xc3\xa9\x80a\n".to_vec(),
        ];
        for text in ["é", "éAé", "中\naéb", "🙂\ré\n中", "aé🙂\u{301}b"] {
            haystacks.push(text.as_bytes().to_vec());
            let mut haystack = vec![0xff];
            haystack.extend_from_slice(text.as_bytes());
            haystack.extend_from_slice(b"\x80\nabc\r\n");
            haystacks.push(haystack);
        }
        for pattern in patterns {
            assert_parity(pattern, &haystacks);
        }
    }

    #[test]
    fn replay_keeps_full_context_for_long_whitespace_wrappers_and_anchors() {
        let pattern = r#"(?m)(?:^|\b)api_key\s*=\s*(?:\{\s*"value"\s*:\s*)?(?:<v>\s*)?"([a-zA-Z0-9+/=]{16,150})"(?:\s*</v>)?(?:\s*\})?(?:;|$|\z)"#;
        let mut haystacks = Vec::new();
        for length in [0, 1, 8192, 65536] {
            let whitespace = " \t\r\n".repeat(length / 4) + &" ".repeat(length % 4);
            for wrapper in ["", "{\"value\":", "<v>", "{\"value\":<v>"] {
                let mut haystack = format!(
                    "api_key{whitespace}={whitespace}{wrapper}{whitespace}\"aB3+cD4/eF5gH6iJ7=\";"
                )
                .into_bytes();
                haystacks.push(haystack.clone());
                haystack.insert(0, 0xff);
                haystack.push(0xfe);
                haystacks.push(haystack);
            }
        }
        assert_parity(pattern, &haystacks);
    }

    #[test]
    fn necessary_starts_preserve_full_context_across_literal_scan_windows() {
        let pattern =
            r"(?i)(?:<[\w.:-]{0,64})?(?P<label>api_key|token)\s*=\s*(?P<secret>[a-z0-9]+)";
        let original = original(pattern);
        let replay = ReplayRegex::new(&original).unwrap();
        assert!(replay.starts.is_some());
        let mut haystacks = Vec::new();
        for offset in [65530, 65534, 65535, 65536, 131070] {
            let mut haystack = vec![b'!'; offset];
            haystack.extend_from_slice(b"TOKEN=first\napi_key=second\n");
            haystacks.push(haystack);
        }
        let mut xml = vec![b'!'; 65520];
        xml.extend_from_slice(b"<tag.tag.tag.tag.tag.tag.tag.tag.api_key=first\nTOKEN=second\n");
        haystacks.push(xml);
        let mut unbounded = b"!TOKEN".to_vec();
        unbounded.extend(std::iter::repeat_n(b' ', 128 * 1024));
        unbounded.extend_from_slice(b"=first\napi_key=second\n");
        haystacks.push(unbounded);
        for haystack in &haystacks {
            assert_eq!(
                tuples(replay.captures_iter(haystack)),
                tuples(original.captures_iter(haystack))
            );
        }
    }

    #[test]
    fn bundled_generic_rule_has_a_proven_start_oracle_and_fixture_capture_parity() {
        let mut rules =
            crate::defaults::get_builtin_rules(Some(crate::rule::Confidence::Low)).unwrap();
        let generic = rules.rules.remove("betterleaks.generic-api-key").unwrap();
        let original = generic.as_regex().unwrap();
        let replay = ReplayRegex::new(&original).unwrap();
        assert!(replay.starts.is_some(), "the bundled generic rule retains its proven frontier");
        for input in generic.examples.iter().chain(&generic.negative_examples) {
            assert_eq!(
                tuples(replay.captures_iter(input.as_bytes())),
                tuples(original.captures_iter(input.as_bytes()))
            );
        }
    }

    #[test]
    fn necessary_start_unbounded_missing_quote_has_a_linear_search_budget() {
        let original = original(r#"token=([^"]*)""#);
        let replay = ReplayRegex::new(&original).unwrap();
        let oracle = replay.starts.as_ref().expect("literal token has a proven start");
        for repetitions in [128, 4096] {
            let haystack = b"token=unfinished ".repeat(repetitions);
            let budget = anchored_work_budget(haystack.len());
            let mut matches = AnchoredMatches {
                finder: &replay.finder,
                starts: oracle.candidates(&haystack),
                remaining_work: budget,
                last_end: 0,
                unanchored: false,
                searches: 0,
            };
            assert!(matches.next(&haystack).unwrap().is_none());
            // The regression is work-based, not a timing assertion. Repeating the
            // failed unbounded tail must not issue one full suffix search per token.
            assert_eq!(matches.searches, MAX_ANCHORED_HAYSTACK_PASSES);
            assert!(matches.remaining_work < budget);
            assert!(matches.unanchored, "exhaustion continues with one linear pass");

            let mut captures = replay.captures_iter(&haystack);
            assert!(captures.next().is_none());
            assert!(matches!(&captures.state, State::Starts(m) if m.unanchored));
            assert_eq!(tuples(captures), tuples(original.captures_iter(&haystack)));
        }
    }

    #[test]
    fn necessary_start_work_budget_fallback_preserves_returned_and_later_captures() {
        let original = original(r#"token=([^"\n]*)"|done=([a-z]+);"#);
        let replay = ReplayRegex::new(&original).unwrap();
        assert!(replay.starts.is_some());
        for prefix in [b"".as_slice(), b"done=first;"] {
            let mut haystack = prefix.to_vec();
            haystack.extend_from_slice(&b"token=unfinished ".repeat(4096));
            haystack.extend_from_slice(b"\ndone=last;done=final;");
            let mut captures = replay.captures_iter(&haystack);
            let mut expected = original.captures_iter(&haystack);
            if !prefix.is_empty() {
                assert_eq!(tuples(captures.by_ref().take(1)), tuples(expected.by_ref().take(1)));
                assert!(matches!(&captures.state, State::Starts(_)));
            }
            assert_eq!(tuples(captures.by_ref().take(1)), tuples(expected.by_ref().take(1)));
            assert!(matches!(&captures.state, State::Starts(m) if m.unanchored));
            assert_eq!(tuples(captures.into_legacy()), tuples(expected));
        }

        // Many successful candidates also exhaust the conservative budget; the linear
        // continuation must keep every later capture, in order, after the switch.
        let mut haystack = b"token=\"\"done=a;".repeat(64);
        haystack.extend_from_slice(&b"token=unfinished ".repeat(256));
        haystack.extend_from_slice(&b"done=b;token=c\"".repeat(64));
        let mut captures = replay.captures_iter(&haystack);
        let mut all = Vec::new();
        for captures in captures.by_ref() {
            all.push(captures.get(0).map(|m| m.range()));
        }
        assert!(matches!(&captures.state, State::Starts(m) if m.unanchored));
        let expected: Vec<_> = original
            .captures_iter(&haystack)
            .map(|captures| captures.get(0).map(|m| m.range()))
            .collect();
        assert_eq!(all, expected);
        assert_eq!(
            tuples(replay.captures_iter(&haystack)),
            tuples(original.captures_iter(&haystack))
        );

        // Complete unbounded tails still match against the unchanged full input.
        for haystack in [
            b"token=one\"token=two\"".as_slice(),
            b"token=unfinished token=also-unfinished\"done=last;",
        ] {
            assert_eq!(
                tuples(replay.captures_iter(haystack)),
                tuples(original.captures_iter(haystack))
            );
        }
    }

    #[test]
    fn necessary_start_native_errors_recover_all_remaining_original_captures() {
        let original = original(r"(?i)(token|secret)=([a-z0-9]+)");
        let replay = ReplayRegex::new(&original).unwrap();
        let oracle = replay.starts.as_ref().unwrap();
        let mut haystack = Vec::new();
        for (index, value) in
            [b"token=one".as_slice(), b"secret=two", b"token=three"].into_iter().enumerate()
        {
            haystack.resize(index * 65536 + 10, b'!');
            haystack.extend_from_slice(value);
        }
        for returned in 0..=1 {
            let mut captures = replay.captures_iter(&haystack);
            let mut expected = original.captures_iter(&haystack);
            for _ in 0..returned {
                assert_eq!(
                    captures.next().unwrap().get(0).unwrap().range(),
                    expected.next().unwrap().get(0).unwrap().range()
                );
            }
            assert!(matches!(&captures.state, State::Starts(_)));
            oracle.with_native_scanner_borrowed_for_test(|| {
                assert_eq!(
                    captures.next().unwrap().get(0).unwrap().range(),
                    expected.next().unwrap().get(0).unwrap().range()
                );
                assert!(matches!(&captures.state, State::Original(_)));
            });
            assert_eq!(tuples(captures.into_legacy()), tuples(expected));
        }
    }

    #[test]
    fn necessary_start_conversion_to_legacy_preserves_remaining_captures() {
        let original = original(r"(?i)(token|secret)=([a-z0-9]+)");
        let replay = ReplayRegex::new(&original).unwrap();
        assert!(replay.starts.is_some());
        let haystack = b"token=one SECRET=two token=three";
        for returned in 0..=3 {
            let mut captures = replay.captures_iter(haystack);
            for _ in 0..returned {
                assert!(captures.next().is_some());
            }
            assert_eq!(
                tuples(captures.into_legacy()),
                tuples(original.captures_iter(haystack).skip(returned))
            );
        }
    }

    #[test]
    fn necessary_start_disagreement_falls_back_before_returning_wrong_captures() {
        for (pattern, finder, haystack, verified_prefix) in [
            ("(token+)", "token", b"tokenn token".as_slice(), 0),
            ("(token)|(secret+)", "token|secret", b"token secrett token secret", 1),
            (r"(?m)^(token)$", "token", b"token extra\ntoken\ntoken extra", 0),
        ] {
            let replay = with_different_finder(pattern, finder);
            let mut captures = replay.captures_iter(haystack);
            assert!(matches!(&captures.state, State::Starts(_)));
            let mut expected = replay.original.captures_iter(haystack);
            for _ in 0..verified_prefix {
                let got = captures.next().unwrap();
                let want = expected.next().unwrap();
                assert_eq!(got.get(0).unwrap().range(), want.get(0).unwrap().range());
                assert!(matches!(&captures.state, State::Starts(_)));
            }
            let got = captures.next().unwrap();
            let want = expected.next().unwrap();
            assert_eq!(got.get(0).unwrap().range(), want.get(0).unwrap().range());
            assert!(matches!(&captures.state, State::Original(_)));
            assert_eq!(tuples(captures.into_legacy()), tuples(expected));
        }
    }

    fn with_different_finder(pattern: &str, finder: &str) -> ReplayRegex {
        let mut replay = ReplayRegex::new(&original(pattern)).unwrap();
        replay.finder = meta::Regex::builder()
            .syntax(syntax::Config::new().unicode(false).utf8(false))
            .configure(meta::Regex::config().utf8_empty(false).auto_prefilter(false))
            .build(finder)
            .unwrap();
        replay
    }

    #[test]
    fn replay_falls_back_before_returning_a_disagreeing_first_span() {
        let replay = with_different_finder("(a+)", "a");
        let haystack = b"aa a";
        let mut captures = replay.captures_iter(haystack);
        assert_eq!(captures.next().unwrap().get(1).unwrap().range(), 0..2);
        assert!(matches!(&captures.state, State::Original(_)));
        assert_eq!(
            tuples(replay.captures_iter(haystack)),
            tuples(replay.original.captures_iter(haystack))
        );
    }

    #[test]
    fn replay_falls_back_midstream_without_dropping_or_duplicating_captures() {
        let replay = with_different_finder("(?:(a)|(b))", "a|bb?");
        let haystack = b"aa bbb a";
        let mut captures = replay.captures_iter(haystack);
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 0..1);
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 1..2);
        assert!(matches!(&captures.state, State::Replay(_)));
        assert_eq!(captures.next().unwrap().get(2).unwrap().range(), 3..4);
        assert!(matches!(&captures.state, State::Original(_)));
        assert_eq!(
            tuples(replay.captures_iter(haystack)),
            tuples(replay.original.captures_iter(haystack))
        );
    }

    #[test]
    fn replay_fallback_preserves_empty_match_suppression() {
        let replay = with_different_finder("(a*)", "a+|b");
        let haystack = b"aab";
        let mut captures = replay.captures_iter(haystack);
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 0..2);
        // Starting captures_at at byte two would incorrectly return 2..2. The
        // original iterator suppresses that adjacent empty match and yields 3..3.
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 3..3);
        assert!(matches!(&captures.state, State::Original(_)));
        assert!(captures.next().is_none());
        assert_eq!(
            tuples(replay.captures_iter(haystack)),
            tuples(replay.original.captures_iter(haystack))
        );
    }

    #[test]
    fn conversion_to_legacy_preserves_every_remaining_capture() {
        for (pattern, haystack) in [
            ("(?:(a)|(b))", b"a b a".as_slice()),
            ("(a*)", b"aab"),
            ("", b"a\xffb"),
            (r"(?u:(.*))", b"a\xffb"),
            ("(?m)^([ab])$", b"a\nb\na"),
        ] {
            let original = original(pattern);
            let replay = ReplayRegex::new(&original).unwrap();
            for returned in 0..=2 {
                let mut captures = replay.captures_iter(haystack);
                for _ in 0..returned {
                    assert!(captures.next().is_some());
                }
                assert_eq!(
                    tuples(captures.into_legacy()),
                    tuples(original.captures_iter(haystack).skip(returned)),
                    "conversion after {returned} captures must preserve {pattern}"
                );
            }
        }
    }

    #[test]
    fn conversion_to_legacy_retains_an_already_running_fallback() {
        let replay = with_different_finder("(?:(a)|(b))", "a|bb?");
        let haystack = b"aa bbb a";
        let mut captures = replay.captures_iter(haystack);
        for _ in 0..3 {
            assert!(captures.next().is_some());
        }
        assert!(matches!(&captures.state, State::Original(_)));
        assert_eq!(
            tuples(captures.into_legacy()),
            tuples(replay.original.captures_iter(haystack).skip(3))
        );
    }

    #[test]
    fn replay_fallback_uses_full_haystack_after_a_missing_confirmation() {
        let replay = with_different_finder("(?m)^(a)$", "a|b");
        let haystack = b"a\nb\na";
        let mut captures = replay.captures_iter(haystack);
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 0..1);
        assert_eq!(captures.next().unwrap().get(0).unwrap().range(), 4..5);
        assert!(matches!(&captures.state, State::Original(_)));
        assert!(captures.next().is_none());
        assert_eq!(
            tuples(replay.captures_iter(haystack)),
            tuples(replay.original.captures_iter(haystack))
        );
    }
}
