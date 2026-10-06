//! Internal indexes shared by the embedding scanner and CLI matcher.
use std::{
    collections::{BTreeSet, VecDeque},
    ops::Range,
};

use bstr::ByteSlice;
use kingfisher_core::OffsetSpan;
use kingfisher_rules::Rule;
use rustc_hash::FxHashMap;

use crate::{ScanAborted, ScanControl};

/// Preserve ordered cross-catalog elimination, comparing only identical spans.
/// Each rank queue is consumed once, including many matches at one Base64 span.
pub fn catalog_keep<'a>(
    entries: impl IntoIterator<Item = (&'a Rule, OffsetSpan)>,
    control: &ScanControl,
) -> Result<Vec<bool>, ScanAborted> {
    let mut groups: FxHashMap<OffsetSpan, Vec<(usize, usize)>> = FxHashMap::default();
    let mut keep = Vec::new();
    for (rule, span) in entries {
        control.check()?;
        let index = keep.len();
        keep.push(true);
        let catalog = if rule.id().starts_with("betterleaks.") {
            1
        } else if rule.id().starts_with("veles.") {
            0
        } else {
            continue;
        };
        if rule.visible() {
            let rank = usize::from(rule.syntax().validation.is_some()) * 2 + catalog;
            groups.entry(span).or_default().push((index, rank));
        }
    }
    for group in groups.values() {
        let mut ranks: [VecDeque<usize>; 4] = std::array::from_fn(|_| VecDeque::new());
        for &(index, rank) in group {
            ranks[rank].push_back(index);
        }
        for &(left, rank) in group {
            control.check()?;
            if !keep[left] {
                continue;
            }
            // Remove processed/deleted entries lazily from every rank queue.
            for queue in &mut ranks {
                while queue.front().is_some_and(|&i| i <= left || !keep[i]) {
                    queue.pop_front();
                }
            }
            let opposing = [1 - rank % 2, 3 - rank % 2];
            let first_better = opposing
                .iter()
                .filter(|&&r| r > rank)
                .filter_map(|&r| ranks[r].front().copied())
                .min();
            for r in opposing {
                if r > rank {
                    continue;
                }
                while ranks[r].front().is_some_and(|&i| first_better.is_none_or(|stop| i < stop)) {
                    control.check()?;
                    keep[ranks[r].pop_front().unwrap()] = false;
                }
            }
            if first_better.is_some() {
                keep[left] = false;
            }
        }
    }
    Ok(keep)
}

/// Candidate positions sorted separately by rule and coordinate.
#[derive(Default)]
pub struct RuleMatchIndex<'a> {
    positions: FxHashMap<&'a str, BTreeSet<(usize, usize)>>,
}

impl<'a> RuleMatchIndex<'a> {
    pub fn new(entries: impl IntoIterator<Item = (&'a str, usize, usize)>) -> Self {
        let mut index = Self::default();
        for (rule, position, finding) in entries {
            index.positions.entry(rule).or_default().insert((position, finding));
        }
        index
    }

    pub fn candidates(
        &self,
        rule: &str,
        range: Range<usize>,
    ) -> impl Iterator<Item = &(usize, usize)> {
        let end = range.end.max(range.start);
        self.positions
            .get(rule)
            .into_iter()
            .flat_map(move |positions| positions.range((range.start, 0)..(end, 0)))
    }

    pub fn remove(&mut self, rule: &str, position: usize, finding: usize) {
        if let Some(positions) = self.positions.get_mut(rule) {
            positions.remove(&(position, finding));
        }
    }
}

/// Static interval tree for credential-URI overlap checks.
pub struct OverlapIndex {
    spans: Vec<(OffsetSpan, usize)>,
    max_end: Vec<usize>,
    leaves: usize,
    uniform_rule: Vec<usize>,
}

impl OverlapIndex {
    #[cfg(any(test, feature = "__cli-internals"))]
    pub fn new(entries: impl IntoIterator<Item = (OffsetSpan, usize)>) -> Self {
        let mut spans: Vec<_> = entries.into_iter().collect();
        spans.sort_unstable_by_key(|(span, index)| (span.start, *index));
        Self::from_sorted_spans(spans)
    }

    fn from_sorted_spans(spans: Vec<(OffsetSpan, usize)>) -> Self {
        let leaves = spans.len().max(1).next_power_of_two();
        let mut max_end = vec![0; leaves * 2];
        for (index, (span, _)) in spans.iter().enumerate() {
            max_end[leaves + index] = span.end;
        }
        for index in (1..leaves).rev() {
            max_end[index] = max_end[index * 2].max(max_end[index * 2 + 1]);
        }
        Self { spans, max_end, leaves, uniform_rule: Vec::new() }
    }

    fn with_rules(entries: impl IntoIterator<Item = (OffsetSpan, usize)>, rules: &[usize]) -> Self {
        let mut spans: Vec<_> = entries.into_iter().collect();
        // Decoded findings share their encoded span. Keep their rules together so queries can
        // skip whole groups of same-rule findings, which cannot suppress a URI fallback.
        spans.sort_unstable_by_key(|(span, index)| (span.start, rules[*index], *index));
        let mut index = Self::from_sorted_spans(spans);
        index.uniform_rule = vec![usize::MAX; index.leaves * 2];
        for (position, (_, finding)) in index.spans.iter().enumerate() {
            index.uniform_rule[index.leaves + position] = rules[*finding];
        }
        for node in (1..index.leaves).rev() {
            let left = index.uniform_rule[node * 2];
            let right = index.uniform_rule[node * 2 + 1];
            if left == right {
                index.uniform_rule[node] = left;
            }
        }
        index
    }

    fn any_overlapping_excluding(
        &self,
        span: OffsetSpan,
        rule: usize,
        control: &ScanControl,
        mut predicate: impl FnMut(usize) -> bool,
    ) -> Result<bool, ScanAborted> {
        self.visit_excluding(1, (0, self.leaves), span, rule, control, &mut predicate)
    }

    fn visit_excluding(
        &self,
        node: usize,
        (start, end): (usize, usize),
        span: OffsetSpan,
        rule: usize,
        control: &ScanControl,
        predicate: &mut impl FnMut(usize) -> bool,
    ) -> Result<bool, ScanAborted> {
        control.check()?;
        if self.max_end[node] <= span.start
            || self.spans.get(start).is_none_or(|(entry, _)| entry.start >= span.end)
            || self.uniform_rule[node] == rule
        {
            return Ok(false);
        }
        if end - start == 1 {
            return Ok(predicate(self.spans[start].1));
        }
        let middle = start + (end - start) / 2;
        Ok(self.visit_excluding(node * 2, (start, middle), span, rule, control, predicate)?
            || self.visit_excluding(node * 2 + 1, (middle, end), span, rule, control, predicate)?)
    }

    #[cfg(any(test, feature = "__cli-internals"))]
    pub fn overlapping(&self, span: OffsetSpan) -> Vec<usize> {
        let mut found = Vec::new();
        self.visit(1, 0, self.leaves, span, &mut found);
        found
    }

    #[cfg(any(test, feature = "__cli-internals"))]
    fn visit(
        &self,
        node: usize,
        start: usize,
        end: usize,
        span: OffsetSpan,
        found: &mut Vec<usize>,
    ) {
        if self.max_end[node] <= span.start
            || self.spans.get(start).is_none_or(|(entry, _)| entry.start >= span.end)
        {
            return;
        }
        if end - start == 1 {
            found.push(self.spans[start].1);
            return;
        }
        let middle = start + (end - start) / 2;
        self.visit(node * 2, start, middle, span, found);
        self.visit(node * 2 + 1, middle, end, span, found);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;
    use kingfisher_rules::{RuleSyntax, Validation};

    #[test]
    fn catalog_index_agrees_with_ordered_all_pairs_oracle() {
        let mut seed = 537_u64;
        for _ in 0..2000 {
            let mut entries = Vec::new();
            for index in 0..32 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let catalog = ["veles", "betterleaks", "acme"][(seed >> 32) as usize % 3];
                let mut rule = RuleSyntax::new(format!("{catalog}.{index}"), "Token", "(token)");
                rule.visible = !seed.is_multiple_of(5);
                rule.validation = (seed & 8 != 0).then_some(Validation::CredentialUri);
                entries.push((
                    Rule::new(rule),
                    OffsetSpan { start: (seed as usize % 3) * 10, end: 40 },
                ));
            }
            let mut expected = vec![true; entries.len()];
            let rank = |rule: &Rule| {
                (rule.syntax().validation.is_some(), rule.id().starts_with("betterleaks."))
            };
            let catalog = |rule: &Rule| rule.id().split('.').next().unwrap().to_owned();
            for left in 0..entries.len() {
                if !expected[left]
                    || !entries[left].0.visible()
                    || catalog(&entries[left].0) == "acme"
                {
                    continue;
                }
                for right in left + 1..entries.len() {
                    if !expected[right]
                        || !entries[right].0.visible()
                        || entries[left].1 != entries[right].1
                        || catalog(&entries[right].0) == "acme"
                        || catalog(&entries[left].0) == catalog(&entries[right].0)
                    {
                        continue;
                    }
                    if rank(&entries[right].0) > rank(&entries[left].0) {
                        expected[left] = false;
                        break;
                    }
                    expected[right] = false;
                }
            }
            assert_eq!(
                catalog_keep(
                    entries.iter().map(|(rule, span)| (rule, *span)),
                    &ScanControl::default()
                )
                .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn dense_component_index_limits_work_to_the_requested_rule_and_window() {
        let mut index = RuleMatchIndex::new(
            (0..10_000).flat_map(|i| [("component", i * 10, i), ("other", i * 10, i)]),
        );
        assert_eq!(
            index.candidates("component", 50_000..50_011).copied().collect::<Vec<_>>(),
            vec![(50_000, 5000), (50_010, 5001)]
        );
        assert!(index.candidates("missing", 0..usize::MAX).next().is_none());
        assert!(index.candidates("component", 42..42).next().is_none());
        index.remove("component", 50_000, 5000);
        assert_eq!(
            index.candidates("component", 50_000..50_011).copied().collect::<Vec<_>>(),
            vec![(50_010, 5001)]
        );
    }

    #[test]
    fn dense_single_line_component_windows_apply_column_bounds_before_lookup() {
        let index = RuleMatchIndex::new((0..10_000).map(|i| ("component", i * 10, i)));
        let primary = OffsetSpan { start: 50_000, end: 50_005 };
        for within in ["1L,+20C", "1000L,+20C"] {
            let range = component_candidate_range(100_000, &[0], primary, Some(within));
            assert_eq!(range, 50_000..50_025);
            assert_eq!(
                index.candidates("component", range).copied().collect::<Vec<_>>(),
                vec![(50_000, 5000), (50_010, 5001), (50_020, 5002)]
            );
        }
    }

    #[test]
    fn component_candidate_ranges_preserve_column_windows_at_eof_and_crlf() {
        let saturating_columns = format!("1L,{0}C", usize::MAX);
        for bytes in [b"first-line".as_slice(), b"first\r\nsecond\r\n", b"first\r\nsecond"] {
            let mut line_starts = vec![0];
            line_starts.extend(
                bytes.iter().enumerate().filter(|(_, byte)| **byte == b'\n').map(|(i, _)| i + 1),
            );
            let index = RuleMatchIndex::new((0..=bytes.len()).map(|i| ("component", i, i)));
            for primary_start in 0..=bytes.len() {
                let primary = OffsetSpan {
                    start: primary_start,
                    end: primary_start.saturating_add(2).min(bytes.len()),
                };
                for within in [
                    "1L,+3C",
                    "100L,+3C",
                    "1L,-3C",
                    "1L,0C",
                    "2L,3C",
                    "+2L,-3C",
                    "-2L,3C",
                    saturating_columns.as_str(),
                ] {
                    let within_bounds = |start| {
                        component_is_within(
                            bytes,
                            &line_starts,
                            primary,
                            OffsetSpan { start, end: start },
                            within,
                        )
                    };
                    let expected: Vec<_> =
                        (0..=bytes.len()).filter(|&i| within_bounds(i)).collect();
                    let range =
                        component_candidate_range(bytes.len(), &line_starts, primary, Some(within));
                    let actual: Vec<_> = index
                        .candidates("component", range)
                        .map(|&(start, _)| start)
                        .filter(|&start| within_bounds(start))
                        .collect();
                    assert_eq!(actual, expected, "primary {primary:?}, within {within}");
                }
            }
        }
    }

    #[test]
    fn overlap_index_includes_long_enclosing_spans_and_excludes_touching_edges() {
        let spans: Vec<_> = (0..1000)
            .map(|i| (OffsetSpan { start: i * 10, end: i * 10 + 7 }, i))
            .chain([(OffsetSpan { start: 0, end: 10_000 }, 1000)])
            .collect();
        let index = OverlapIndex::new(spans.iter().copied());
        for start in 0..10_000 {
            let query = OffsetSpan { start, end: start + 3 };
            let mut expected: Vec<_> = spans
                .iter()
                .filter(|(span, _)| span.start < query.end && query.start < span.end)
                .map(|(_, index)| *index)
                .collect();
            let mut actual = index.overlapping(query);
            expected.sort_unstable();
            actual.sort_unstable();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn credential_uri_index_agrees_with_all_pairs_oracle() {
        let rules: Vec<_> = [
            ("betterleaks.uri-one", true, true),
            ("betterleaks.uri-two", true, true),
            ("betterleaks.provider", true, false),
            ("veles.provider", true, false),
            ("custom.uri", true, true),
            ("betterleaks.invisible", false, true),
        ]
        .map(|(id, visible, uri)| {
            let mut rule = RuleSyntax::new(id, "Token", "(token)");
            rule.visible = visible;
            rule.validation = uri.then_some(Validation::CredentialUri);
            Rule::new(rule)
        })
        .into();
        let values: &[&[u8]] =
            &[b"", b"password", b"prefix-password-suffix", b"different", b"\xff"];
        let eligible = |rule: &Rule| rule.visible() && rule.id().starts_with("betterleaks.");
        let mut seed = 537_u64;
        for _ in 0..1000 {
            let mut entries = Vec::new();
            for _ in 0..32 {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                let rule = &rules[(seed >> 32) as usize % rules.len()];
                let start = seed as usize % 40;
                let end = start + (seed >> 16) as usize % 20 + 1;
                entries.push((
                    rule,
                    OffsetSpan { start, end },
                    values[(seed >> 48) as usize % values.len()],
                ));
            }
            let expected: Vec<_> = entries
                .iter()
                .map(|&(rule, span, secret)| {
                    !eligible(rule)
                        || !matches!(rule.syntax().validation, Some(Validation::CredentialUri))
                        || secret.is_empty()
                        || !entries.iter().any(|&(other, other_span, value)| {
                            eligible(other)
                                && rule.id() != other.id()
                                && span.start < other_span.end
                                && other_span.start < span.end
                                && value.windows(secret.len()).any(|window| window == secret)
                        })
                })
                .collect();
            assert_eq!(credential_uri_keep(entries, &ScanControl::default()).unwrap(), expected);
        }
    }

    #[test]
    fn dense_decoded_credential_uris_skip_same_rule_overlaps() {
        let mut generic = RuleSyntax::new("betterleaks.uri", "Credential URI", "(token)");
        generic.validation = Some(Validation::CredentialUri);
        let generic = Rule::new(generic);
        let specific = Rule::new(RuleSyntax::new("betterleaks.provider", "Provider", "(token)"));
        let passwords: Vec<_> = (0..4096).map(|index| format!("password_{index:06}")).collect();
        let span = OffsetSpan { start: 0, end: 100_000 };

        for include_specific in [false, true] {
            let mut entries: Vec<_> =
                passwords.iter().map(|password| (&generic, span, password.as_bytes())).collect();
            if include_specific {
                entries.push((&specific, span, passwords[123].as_bytes()));
            }
            let budget = entries.len() * 40;
            let checks = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&checks);
            let control = ScanControl::default().with_check_observer(move |_| {
                if observed.fetch_add(1, Ordering::Relaxed) < budget {
                    Ok(())
                } else {
                    Err(ScanAborted::Cancelled)
                }
            });
            let keep = credential_uri_keep(entries, &control)
                .expect("same-span decoded findings must stay within a linear work budget");
            for (index, retain) in keep.into_iter().enumerate() {
                assert_eq!(retain, !(include_specific && index == 123));
            }
            assert!(checks.load(Ordering::Relaxed) <= budget);
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct ComponentWindow {
    cols_before: usize,
    cols_after: usize,
    lines_before: usize,
    lines_after: usize,
    has_lines: bool,
    unbounded: bool,
}

pub fn parse_component_window(value: &str) -> Option<ComponentWindow> {
    let value = value.trim();
    if value.is_empty() || value == "0" {
        return Some(ComponentWindow { unbounded: true, ..ComponentWindow::default() });
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

#[cfg(any(test, feature = "__cli-internals"))]
pub fn component_is_within(
    bytes: &[u8],
    line_starts: &[usize],
    primary: OffsetSpan,
    component: OffsetSpan,
    within: &str,
) -> bool {
    let Some(window) = parse_component_window(within) else {
        return false;
    };
    component_is_within_window(bytes.len(), line_starts, primary, component, window)
}

pub fn component_is_within_window(
    byte_len: usize,
    line_starts: &[usize],
    primary: OffsetSpan,
    component: OffsetSpan,
    window: ComponentWindow,
) -> bool {
    if window.unbounded {
        return true;
    }

    if !window.has_lines {
        return component.start >= primary.start.saturating_sub(window.cols_before)
            && component.start < primary.end.saturating_add(window.cols_after).min(byte_len);
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

#[cfg(any(test, feature = "__cli-internals"))]
pub fn component_candidate_range(
    byte_len: usize,
    line_starts: &[usize],
    primary: OffsetSpan,
    within: Option<&str>,
) -> std::ops::Range<usize> {
    let Some(window) = parse_component_window(within.unwrap_or("")) else { return 0..0 };
    component_candidate_range_with_window(byte_len, line_starts, primary, window)
}

pub fn component_candidate_range_with_window(
    byte_len: usize,
    line_starts: &[usize],
    primary: OffsetSpan,
    window: ComponentWindow,
) -> std::ops::Range<usize> {
    if window.unbounded {
        return 0..usize::MAX;
    }
    if !window.has_lines {
        return primary.start.saturating_sub(window.cols_before)
            ..primary.end.saturating_add(window.cols_after).min(byte_len);
    }
    let line = |offset| line_starts.partition_point(|start| *start <= offset).saturating_sub(1);
    let primary_start_line = line(primary.start);
    let primary_end_line = line(primary.end);
    let first = primary_start_line.saturating_sub(window.lines_before);
    let after = primary_end_line.saturating_add(window.lines_after).saturating_add(1);
    let mut start = line_starts.get(first).copied().unwrap_or(byte_len);
    let mut end = line_starts.get(after).copied().unwrap_or_else(|| byte_len.saturating_add(1));
    // On a single actual input line, the column restriction is also a contiguous byte range.
    // Apply it before enumerating candidates, including oversized line windows at the edges.
    if primary_start_line == primary_end_line
        && (window.cols_before > 0 || window.cols_after > 0)
        && after.min(line_starts.len()) == first.saturating_add(1)
    {
        start = start.max(primary.start.saturating_sub(window.cols_before));
        end = end.min(primary.end.saturating_add(window.cols_after));
    }
    start..end
}

/// Eliminate visible Betterleaks credential-URI fallbacks covered by another visible rule.
/// Operates on full-match spans and selected secret bytes before redaction.
pub fn credential_uri_keep<'a>(
    entries: impl IntoIterator<Item = (&'a Rule, OffsetSpan, &'a [u8])>,
    control: &ScanControl,
) -> Result<Vec<bool>, ScanAborted> {
    use kingfisher_rules::Validation;
    let entries: Vec<_> = entries.into_iter().collect();
    let eligible = |rule: &Rule| rule.visible() && rule.id().starts_with("betterleaks.");
    let mut keep = vec![true; entries.len()];
    if !entries
        .iter()
        .any(|(rule, _, _)| matches!(rule.syntax().validation, Some(Validation::CredentialUri)))
    {
        return Ok(keep);
    }
    let mut rule_ids = FxHashMap::default();
    let mut rules = Vec::with_capacity(entries.len());
    for &(rule, _, _) in &entries {
        control.check()?;
        let next = rule_ids.len();
        rules.push(*rule_ids.entry(rule.id()).or_insert(next));
    }
    let overlaps = OverlapIndex::with_rules(
        entries
            .iter()
            .enumerate()
            .filter(|(_, (rule, _, _))| eligible(rule))
            .map(|(i, (_, span, _))| (*span, i)),
        &rules,
    );
    for (index, &(rule, span, secret)) in entries.iter().enumerate() {
        control.check()?;
        if !eligible(rule)
            || !matches!(rule.syntax().validation, Some(Validation::CredentialUri))
            || secret.is_empty()
        {
            continue;
        }
        keep[index] =
            !overlaps.any_overlapping_excluding(span, rules[index], control, |candidate| {
                entries[candidate].2.find(secret).is_some()
            })?;
    }
    Ok(keep)
}
