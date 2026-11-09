//! Selective boolean gates for native patterns that are too large to compile.
//!
//! Distributing an alternation through its enclosing concatenations and groups preserves
//! the union language, but not necessarily capture numbering or match selection. These
//! variants are only native boolean gates; the original Rust regex must still confirm
//! captures over the original input. In particular, never distribute inside a repetition:
//! `(a|b){2}` includes `ab` and `ba`, unlike the union of `a{2}` and `b{2}`.

use regex_syntax::ast::{
    Alternation, Ast, Flags, Group, GroupKind, RepetitionKind, RepetitionRange, parse::Parser,
};

/// Remove finite upper bounds from costly nested repetitions to obtain a necessary gate.
///
/// A bounded repeat containing another repeat can make native state expansion very large.
/// Replacing `{min,max}` with `{min,}` only adds strings; minima, scopes, assertions, and
/// greediness are unchanged. Preserve small bounds (at most two) and exact counts: widening
/// them saves little expansion but can admit many more false candidates. These are boolean
/// gates only; original Rust captures and rejection filters still decide every finding.
/// Unlike alternation distribution, this transformation is safe inside repetitions too.
/// Return `None` when parsing fails or no eligible bound changes.
pub(super) fn widen_nested_repetitions(pattern: &str) -> Option<String> {
    let mut root = Parser::new().parse(pattern).ok()?;
    widen_repetitions(&mut root).then(|| root.to_string())
}

fn widen_repetitions(ast: &mut Ast) -> bool {
    match ast {
        Ast::Repetition(repetition) => {
            let mut changed = false;
            if let RepetitionKind::Range(RepetitionRange::Bounded(min, max)) = repetition.op.kind
                && max >= 3
                && max > min
                && contains_repetition(&repetition.ast)
            {
                repetition.op.kind = RepetitionKind::Range(RepetitionRange::AtLeast(min));
                changed = true;
            }
            // Visit every child even when this node already changed.
            widen_repetitions(&mut repetition.ast) | changed
        }
        Ast::Group(group) => widen_repetitions(&mut group.ast),
        Ast::Alternation(alternation) => alternation
            .asts
            .iter_mut()
            .fold(false, |changed, child| widen_repetitions(child) | changed),
        Ast::Concat(concat) => {
            concat.asts.iter_mut().fold(false, |changed, child| widen_repetitions(child) | changed)
        }
        _ => false,
    }
}

/// Split one alternation outside all repetitions into at most `max_alternatives` patterns.
///
/// Every result is a clone of the whole root, with just one alternative selected at the
/// same AST location. Original enclosing groups, scoped flags, assertions and unrelated
/// branches remain intact. Only alternations containing a repetition are eligible:
/// splitting cheap literal/class alternatives rarely reduces native compilation cost.
/// Return `None` for an unsupported pattern or when no eligible alternation fits the cap.
/// Standalone flag setters are supported only as consecutive leading nodes of a root
/// concatenation; scoped flag groups are supported everywhere.
pub(super) fn split_pattern(pattern: &str, max_alternatives: usize) -> Option<Vec<String>> {
    if max_alternatives < 2 {
        return None;
    }
    let root = Parser::new().parse(pattern).ok()?;
    if !supported_standalone_flags(&root) {
        return None;
    }

    let mut candidate = None;
    select_alternation(&root, max_alternatives, &mut Vec::new(), &mut candidate);
    let candidate = candidate?;
    Some(
        candidate
            .alternation
            .asts
            .iter()
            .map(|branch| {
                let mut variant = root.clone();
                replace_alternation(&mut variant, &candidate.path, branch.clone());
                variant.to_string()
            })
            .collect(),
    )
}

fn supported_standalone_flags(root: &Ast) -> bool {
    if let Ast::Concat(concat) = root {
        concat
            .asts
            .iter()
            .skip_while(|node| matches!(node, Ast::Flags(_)))
            .all(|node| !contains_standalone_flags(node))
    } else {
        !contains_standalone_flags(root)
    }
}

fn contains_standalone_flags(ast: &Ast) -> bool {
    match ast {
        Ast::Flags(_) => true,
        Ast::Group(group) => contains_standalone_flags(&group.ast),
        // Validate flags inside repetitions too, without making their alternations
        // eligible for distribution. A scoped flag group is not an Ast::Flags node.
        Ast::Repetition(repetition) => contains_standalone_flags(&repetition.ast),
        Ast::Alternation(alternation) => alternation.asts.iter().any(contains_standalone_flags),
        Ast::Concat(concat) => concat.asts.iter().any(contains_standalone_flags),
        _ => false,
    }
}

struct Candidate<'a> {
    path: Vec<usize>,
    alternation: &'a Alternation,
    estimated_saving: usize,
}

impl Candidate<'_> {
    fn improves(&self, previous: &Self) -> bool {
        // Prefer the estimated reduction of the largest resulting pattern per added
        // native expression. Compare ratios exactly, without floating-point rounding
        // or usize overflow. Keep preorder for otherwise identical candidates.
        let added = self.alternation.asts.len() - 1;
        let previous_added = previous.alternation.asts.len() - 1;
        let saving = self.estimated_saving as u128 * previous_added as u128;
        let previous_saving = previous.estimated_saving as u128 * added as u128;
        saving > previous_saving || (saving == previous_saving && added < previous_added)
    }
}

fn select_alternation<'a>(
    ast: &'a Ast,
    max_alternatives: usize,
    path: &mut Vec<usize>,
    best: &mut Option<Candidate<'a>>,
) {
    let children = match ast {
        Ast::Group(group) => {
            path.push(0);
            select_alternation(&group.ast, max_alternatives, path, best);
            path.pop();
            return;
        }
        Ast::Alternation(alternation) => {
            if (2..=max_alternatives).contains(&alternation.asts.len()) && contains_repetition(ast)
            {
                let candidate = Candidate {
                    path: path.clone(),
                    alternation,
                    estimated_saving: estimated_saving(alternation),
                };
                if best.as_ref().is_none_or(|previous| candidate.improves(previous)) {
                    *best = Some(candidate);
                }
            }
            &alternation.asts
        }
        Ast::Concat(concat) => &concat.asts,
        // Even optional or exactly-once repetitions are deliberately not traversed.
        Ast::Repetition(_) => return,
        _ => return,
    };
    for (index, child) in children.iter().enumerate() {
        path.push(index);
        select_alternation(child, max_alternatives, path, best);
        path.pop();
    }
}

fn contains_repetition(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(_) => true,
        Ast::Group(group) => contains_repetition(&group.ast),
        Ast::Alternation(alternation) => alternation.asts.iter().any(contains_repetition),
        Ast::Concat(concat) => concat.asts.iter().any(contains_repetition),
        _ => false,
    }
}

fn ast_cost(ast: &Ast) -> usize {
    match ast {
        Ast::Group(group) => ast_cost(&group.ast),
        Ast::Alternation(alternation) => {
            alternation.asts.iter().fold(0usize, |cost, child| cost.saturating_add(ast_cost(child)))
        }
        Ast::Concat(concat) => {
            concat.asts.iter().fold(0usize, |cost, child| cost.saturating_add(ast_cost(child)))
        }
        Ast::Repetition(repetition) => {
            let multiplier = match repetition.op.kind {
                RepetitionKind::ZeroOrOne => 1,
                RepetitionKind::ZeroOrMore | RepetitionKind::OneOrMore => 2,
                RepetitionKind::Range(RepetitionRange::Exactly(max))
                | RepetitionKind::Range(RepetitionRange::Bounded(_, max)) => max,
                RepetitionKind::Range(RepetitionRange::AtLeast(min)) => min.max(2),
            };
            ast_cost(&repetition.ast).saturating_mul(multiplier as usize)
        }
        _ => 1,
    }
}

fn estimated_saving(alternation: &Alternation) -> usize {
    // Sum all branch costs except one largest branch. Unlike saturating the total
    // before subtracting the maximum, this preserves small savings beside a branch
    // whose own expanded cost already saturated.
    let mut largest = 0;
    let mut saving = 0usize;
    for branch in &alternation.asts {
        let cost = ast_cost(branch);
        if cost > largest {
            saving = saving.saturating_add(largest);
            largest = cost;
        } else {
            saving = saving.saturating_add(cost);
        }
    }
    saving
}

fn replace_alternation(ast: &mut Ast, path: &[usize], branch: Ast) {
    if let Some((&index, remaining)) = path.split_first() {
        let child = match ast {
            Ast::Group(group) => {
                debug_assert_eq!(index, 0);
                group.ast.as_mut()
            }
            Ast::Alternation(alternation) => &mut alternation.asts[index],
            Ast::Concat(concat) => &mut concat.asts[index],
            _ => unreachable!("selected alternation paths never enter repetitions or leaves"),
        };
        replace_alternation(child, remaining, branch);
    } else {
        debug_assert!(matches!(ast, Ast::Alternation(_)));
        let span = *ast.span();
        // Preserve the original parent group, if any. An extra noncapturing group
        // also makes the replacement safe at the root or directly inside a concat:
        // Ast's printer does not insert precedence-preserving groups on its own.
        *ast = Ast::group(Group {
            span,
            kind: GroupKind::NonCapturing(Flags { span, items: Vec::new() }),
            ast: Box::new(branch),
        });
    }
}

#[cfg(test)]
mod tests {
    use regex::bytes::Regex;

    use super::{Parser, ast_cost, split_pattern, widen_nested_repetitions};

    fn assert_union(pattern: &str, cap: usize, samples: &[(&[u8], bool)]) -> Vec<String> {
        let variants = split_pattern(pattern, cap).expect("pattern has an eligible alternation");
        assert!((2..=cap).contains(&variants.len()));
        let original = Regex::new(pattern).unwrap();
        let compiled: Vec<_> =
            variants.iter().map(|variant| Regex::new(variant).unwrap()).collect();
        for &(input, expected) in samples {
            assert_eq!(original.is_match(input), expected, "original {pattern:?} on {input:?}");
            assert_eq!(
                compiled.iter().any(|variant| variant.is_match(input)),
                expected,
                "variants {variants:?} of {pattern:?} on {input:?}",
            );
        }
        variants
    }

    #[test]
    fn whole_root_variants_preserve_context_captures_and_unrelated_branches() {
        assert_union(
            r"\Apre(?:(?:left|right)-(?P<key>[a-z]+)|standalone)post\z",
            4,
            &[
                (b"preleft-keypost", true),
                (b"preright-keypost", true),
                (b"prestandalonepost", true),
                (b"preleftright-keypost", false),
                (b"prestandalone-keypost", false),
                (b"left-keypost", false),
                (b"preleft-key", false),
            ],
        );
        assert_union(
            r"\Aab{1}\z|\Ac\d\z",
            2,
            &[(b"ab", true), (b"c7", true), (b"c", false), (b"xab", false), (b"abc7", false)],
        );
        let variants = assert_union(
            r"\A(?:(?P<key>a{4}|b{4})x|c)\z",
            2,
            &[(b"aaaax", true), (b"bbbbx", true), (b"c", true), (b"aabbx", false), (b"cx", false)],
        );
        // The expensive nested alternation wins; every root clone retains the other arm.
        assert!(variants.iter().all(|variant| Regex::new(variant).unwrap().is_match(b"c")));
    }

    #[test]
    fn leading_and_scoped_flags_keep_their_original_scopes() {
        assert_union(
            r"(?i)(?m)^prefix(?-i:Ab{1}|Cd)-(?s:x.y)$",
            2,
            &[
                (b"PREFIXAb-x\ny", true),
                (b"prefixCd-x_y", true),
                (b"before\nPREFIXAb-x_y\nafter", true),
                (b"PREFIXab-x\ny", false),
                (b"prefixcd-x_y", false),
            ],
        );
        assert_union(
            r"(?x) \A (?: f o o{1} | b a r ) \x20 \# \z # trailing comment",
            2,
            &[(b"foo #", true), (b"bar #", true), (b"foo#", false), (b"FOO #", false)],
        );
        assert_union(
            r"\A(?i:é{1}|Ω)(?P<end>!)\z",
            2,
            &[("É!".as_bytes(), true), ("ω!".as_bytes(), true), (b"e!", false)],
        );
    }

    #[test]
    fn unsupported_standalone_flags_refuse_the_entire_transformation() {
        for pattern in [
            r"a(?i)(b+|c)",
            r"(?i)a+|b",
            r"(?i)(?:a(?-i)b+|c)",
            r"(?:a+|b(?i)c)",
            r"(?:(a|b)(?i)c)+x(?:d+|e)",
        ] {
            assert!(split_pattern(pattern, 16).is_none(), "{pattern}");
        }
    }

    #[test]
    fn never_distribute_under_any_repetition() {
        for pattern in [
            r"(?:a+|b)+",
            r"(?:a+|b)*",
            r"(?:a+|b)?",
            r"(?:a+|b)??",
            r"(?:a+|b){1}",
            r"(?:a+|b){2}",
            r"(?:a+|b){0,0}",
            r"(?i)(?:a+|b){1,2}",
        ] {
            assert!(split_pattern(pattern, 16).is_none(), "{pattern}");
        }
        assert_union(
            r"\A(?:a|b){2}(?:X{1}|Y)\z",
            2,
            &[
                (b"aaX", true),
                (b"abX", true),
                (b"baY", true),
                (b"bbY", true),
                (b"aX", false),
                (b"abZ", false),
                (b"abcX", false),
            ],
        );
        assert_union(
            r"\A(?:(?:a|b){2}|z)c\z",
            2,
            &[
                (b"aac", true),
                (b"abc", true),
                (b"bac", true),
                (b"bbc", true),
                (b"zc", true),
                (b"ac", false),
                (b"zzc", false),
            ],
        );
    }

    #[test]
    fn preserve_empty_branches_anchors_and_invalid_utf8_byte_captures() {
        assert_union(
            r"\A(?:|ab{1}|a)\z",
            3,
            &[(b"", true), (b"a", true), (b"ab", true), (b"b", false), (b"aa", false)],
        );
        assert_union(r"a{1}||b", 3, &[(b"", true), (b"a", true), (b"anything", true)]);
        assert_union(
            r"\A(?-u:(?P<byte>\xFF{1}|\xFE))(?P<tail>[a-z]+)\z",
            2,
            &[
                (b"\xffkey", true),
                (b"\xfekey", true),
                (b"\xff\xfe", false),
                (b"\xfdkey", false),
                (b"\xc3\xbfkey", false),
                (b"key", false),
                (b"\xffKEY", false),
            ],
        );
        assert_union(
            r"(key{1}|token)=(?P<secret>[A-Za-z0-9]{10})",
            2,
            &[(b"\xffkey=abc123ABCD\xfe", true), (b"\xffother=abc123ABCD\xfe", false)],
        );
    }

    #[test]
    fn caps_invalid_patterns_and_cheap_alternations_return_none() {
        for cap in [0, 1, 2] {
            assert!(split_pattern("a+|b|c", cap).is_none());
        }
        for pattern in [
            "(",
            "[",
            "",
            "plain",
            r"\|",
            "[a|b]",
            "a{3,2}",
            "a|b",
            "[a-z]|[0-9]",
            "(foo|bar)(x|y)",
        ] {
            assert!(split_pattern(pattern, 16).is_none(), "{pattern:?}");
        }
        let variants = assert_union(
            r"\A(a{1}|b|c)(x{1}|y)\z",
            2,
            &[(b"ax", true), (b"by", true), (b"cy", true), (b"az", false), (b"dy", false)],
        );
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| variant.contains("(a{1}|b|c)")));
    }

    #[test]
    fn widening_preserves_minima_scopes_greediness_and_small_wrappers() {
        for (pattern, expected) in [
            (r"(?:a+){1,5}?", r"(?:a+){1,}?"),
            (r"(?i)(?-i:(?:a+|B){2,5}?)[0-9]{4}", r"(?i)(?-i:(?:a+|B){2,}?)[0-9]{4}"),
            (r"(?:(?:a+){0,4}|(?:b+){1,5}){0,2}", r"(?:(?:a+){0,}|(?:b+){1,}){0,2}"),
            (r"(?:(?:a+){1,4}b?){2,5}(?:c*){0,3}x{1,8}", r"(?:(?:a+){1,}b?){2,}(?:c*){0,}x{1,8}"),
        ] {
            let widened = widen_nested_repetitions(pattern).unwrap();
            assert_eq!(widened, expected);
            assert!(widen_nested_repetitions(&widened).is_none(), "must terminate: {pattern}");
        }
        let original = Regex::new(r"\A(?:aB+){3,5}X\z").unwrap();
        let gate = Regex::new(&widen_nested_repetitions(original.as_str()).unwrap()).unwrap();
        for count in 0..=8 {
            let input = format!("{}X", "aB".repeat(count));
            assert_eq!(original.is_match(input.as_bytes()), (3..=5).contains(&count));
            assert_eq!(gate.is_match(input.as_bytes()), count >= 3);
        }
    }

    #[test]
    fn widening_refuses_unhelpful_bounds_and_invalid_patterns() {
        for pattern in [
            "(",
            "[",
            "",
            "plain",
            r"(?:a+){0,2}",
            r"(?:a+){3}",
            r"(?:a+){3,3}",
            r"(?:a+){0,}",
            r"[ab]{3,9}",
            r"(a|b){0,4}",
            r"(?:a+)?",
            r"(?:a+)*",
        ] {
            assert!(widen_nested_repetitions(pattern).is_none(), "{pattern}");
        }
    }

    #[test]
    fn exhaustive_widened_gates_cannot_lose_original_matches() {
        let mut inputs = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..6 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in b"abA\xff\n" {
                    let mut input = prefix.clone();
                    input.push(byte);
                    next.push(input);
                }
            }
            inputs.extend(next.iter().cloned());
            frontier = next;
        }
        for pattern in [
            r"\A(?:a?b){1,3}\z",
            r"\A(?:a?b){2,3}\z",
            r"\A(?:(?:a?){0,3}|(?:b+){1,4}){0,2}\z",
            r"(?i)\A(?-i:(?:a+|A){1,3}?)b\z",
            r"(?m)^(?:a?b){1,3}$",
            r"(?s)\A(?:.b?){1,3}\z",
            r"\A(?-u:(?:\xFF?b){1,3})\z",
            r"\A(?:(?:a+){0,3}b?){1,4}\z",
            r"\A(?:a?b){0,3}?\z|\A(?:b?a){1,4}\z",
        ] {
            let original = Regex::new(pattern).unwrap();
            let gate_pattern = widen_nested_repetitions(pattern).unwrap();
            let gate = Regex::new(&gate_pattern).unwrap();
            for input in &inputs {
                assert!(
                    !original.is_match(input) || gate.is_match(input),
                    "gate {gate_pattern:?} lost {pattern:?} on {input:?}",
                );
            }
        }
    }

    #[test]
    fn rank_by_expanded_saving_per_added_branch_and_split_only_once() {
        // Source length favors the first alternation, but expanded cost favors the second.
        let variants =
            split_pattern("(aaaaaaaaaa{1}|bbbbbbbbbb{1})(x{30}|y{30}|z{30})", 3).unwrap();
        assert_eq!(variants.len(), 3);
        assert!(variants.iter().all(|variant| variant.contains("(aaaaaaaaaa{1}|bbbbbbbbbb{1})")));
        let variants = split_pattern("(a{30}|b{30})(x{2}|y{2}|z{2})", 3).unwrap();
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| variant.contains("(x{2}|y{2}|z{2})")));
        let variants = split_pattern("(x{3}|y{3}|z{3})(a{3}|b{3})", 3).unwrap();
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| variant.contains("(x{3}|y{3}|z{3})")));

        let variants = assert_union(
            r"\A(a{1}|b)(c{1}|d)\z",
            4,
            &[(b"ac", true), (b"ad", true), (b"bc", true), (b"bd", true), (b"abcd", false)],
        );
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| variant.contains("(c{1}|d)")));
    }

    #[test]
    fn expanded_costs_saturate_without_losing_small_savings() {
        for (pattern, expected) in [
            ("a", 1),
            ("(ab)", 2),
            ("a|bc", 3),
            ("a?", 1),
            ("a*", 2),
            ("a+", 2),
            ("a{0}", 0),
            ("a{2,5}", 5),
            ("a{0,}", 2),
            ("a{3,}", 3),
        ] {
            assert_eq!(ast_cost(&Parser::new().parse(pattern).unwrap()), expected, "{pattern}");
        }
        let enormous = r"(?:(?:a{4294967295}){4294967295}){4294967295}";
        assert_eq!(ast_cost(&Parser::new().parse(enormous).unwrap()), usize::MAX);
        let pattern = format!("({enormous}|b{{5}})(x{{4}}|y{{4}})");
        let variants = split_pattern(&pattern, usize::MAX).unwrap();
        assert_eq!(variants.len(), 2);
        assert!(variants.iter().all(|variant| variant.contains("(x{4}|y{4})")));
    }

    #[test]
    fn exhaustive_small_inputs_match_the_original_boolean_union() {
        let mut inputs = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..4 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for &byte in b"abABc\xff" {
                    let mut input = prefix.clone();
                    input.push(byte);
                    next.push(input);
                }
            }
            inputs.extend(next.iter().cloned());
            frontier = next;
        }
        for pattern in [
            r"\A(?:a{1}|b)(?:a|b)\z",
            r"\A(?:(?:a|b)+|c)b?\z",
            r"\A(?:a?|b)c\z",
            r"\A(?:a(?:b{1}|c)|c)\z",
            r"\A(?:a|(?:b{1}|c))\z",
            r"\A(?:a{1}||b)\z",
            r"(?i)\A(?:a{1}|b)c?\z",
            r"\A(?i:a{1}|b)c\z",
            r"\A(?:a|bc){1,2}(?:a{1}|c)\z",
        ] {
            let original = Regex::new(pattern).unwrap();
            let variants = split_pattern(pattern, 4).unwrap();
            let variants: Vec<_> =
                variants.iter().map(|variant| Regex::new(variant).unwrap()).collect();
            for input in &inputs {
                assert_eq!(
                    original.is_match(input),
                    variants.iter().any(|variant| variant.is_match(input)),
                    "{pattern:?} on {input:?}",
                );
            }
        }
    }
}
