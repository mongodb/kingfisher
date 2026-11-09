//! Runtime evaluation for filter expressions imported from Betterleaks.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    ops::Range,
    sync::{Arc, LazyLock, OnceLock},
};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, anyhow, bail};
use base64::{
    Engine as _, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};
use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern, Scan};
use regex::Regex;
use regex_syntax::ast::{AssertionKind, Ast, Flag as AstFlag, parse::Parser as AstParser};
use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::Xxh3;

use crate::{
    BetterleaksExpr, Confidence, Rule, scanner_pool::ScannerPool, tokenizer::cl100k_base_singleton,
};

const MAX_EXPRESSION_STRING_BYTES: usize = 16 * 1024 * 1024;

/// Candidate data exposed to a Betterleaks filter expression.
#[derive(Debug)]
pub struct BetterleaksFilterContext<'a> {
    pub path: &'a str,
    /// Source metadata available to both prefilters and finding filters.
    pub attributes: Option<&'a BTreeMap<String, String>>,
    pub secret: &'a str,
    pub full_match: &'a str,
    pub line: &'a str,
    pub fragment_raw: &'a str,
    pub match_start_idx: usize,
    pub match_end_idx: usize,
    pub match_line_start_idx: usize,
    pub match_line_end_idx: usize,
    pub rule_id: &'a str,
    pub description: &'a str,
    pub captures: BTreeMap<String, String>,
}

/// Result of evaluating an imported Betterleaks filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BetterleaksFilterOutcome {
    /// Betterleaks filters return true when the candidate should be discarded.
    pub discard: bool,
    /// Inert compatibility field retained from the published 3.1.0 API.
    /// Evaluation always returns `None`; rule confidence is static.
    pub confidence: Option<Confidence>,
}

/// Result of evaluating a certified leading secret-only OR prefix.
#[doc(hidden)]
#[derive(Debug)]
pub enum BetterleaksFilterPrefix<'e> {
    /// The prefix discarded the candidate; do not evaluate the remainder.
    Complete(BetterleaksFilterOutcome),
    /// The original, unchanged continuation; evaluate it with normal context.
    Remainder(&'e BetterleaksExpr),
}

/// Reuses source-line regex results within one immutable source buffer.
/// Create a separate cache for each raw or decoded buffer. Line ranges must
/// identify the exact bytes used to construct `BetterleaksFilterContext::line`.
/// Retention is bounded; evicted results are reevaluated normally.
#[doc(hidden)]
#[derive(Default)]
pub struct BetterleaksFilterLineCache {
    matches_any: BTreeMap<LineCacheKey, Vec<CachedPatterns>>,
    // Count pattern sets, including separate entries sharing a hash-collision bucket.
    entries: usize,
    #[cfg(test)]
    scans: usize,
}

const SOURCE_LINE_CACHE_MAX_ENTRIES: usize = 4096;

/// Lazily prepares character coordinates for one immutable UTF-8 source fragment.
///
/// Reuse this object across every candidate in the fragment, but create a separate one for
/// decoded or lossy-converted content. Finding offsets remain byte offsets; expression slices
/// retain their existing Unicode-scalar indexing. Preparation is skipped unless a slice needs it.
#[doc(hidden)]
#[derive(Debug)]
pub struct BetterleaksFilterFragment<'a> {
    raw: &'a str,
    index: OnceLock<FragmentIndex>,
}

// A sparse index bounds each character-coordinate lookup to 127 scalar values without retaining
// a usize for every character in a potentially large, mostly-ASCII source buffer.
const FRAGMENT_INDEX_STRIDE: usize = 128;

#[derive(Debug)]
struct FragmentIndex {
    characters: usize,
    // Empty for ASCII; otherwise the byte offset of every FRAGMENT_INDEX_STRIDE-th character.
    checkpoints: Vec<usize>,
}

impl<'a> BetterleaksFilterFragment<'a> {
    pub fn new(fragment_raw: &'a str) -> Self {
        Self { raw: fragment_raw, index: OnceLock::new() }
    }

    fn character_range(&self, input: &str) -> Option<Range<usize>> {
        let start = (input.as_ptr() as usize).checked_sub(self.raw.as_ptr() as usize)?;
        let end = start.checked_add(input.len())?;
        if end > self.raw.len()
            || !self.raw.is_char_boundary(start)
            || !self.raw.is_char_boundary(end)
        {
            return None;
        }
        let index = self.index.get_or_init(|| FragmentIndex::new(self.raw));
        Some(index.byte_to_character(self.raw, start)..index.byte_to_character(self.raw, end))
    }

    fn byte_offset(&self, character: usize) -> usize {
        self.index
            .get()
            .expect("fragment coordinates were prepared")
            .character_to_byte(self.raw, character)
    }
}

impl FragmentIndex {
    fn new(raw: &str) -> Self {
        if raw.is_ascii() {
            return Self { characters: raw.len(), checkpoints: Vec::new() };
        }
        let mut checkpoints = Vec::new();
        let mut characters = 0;
        for (offset, _) in raw.char_indices() {
            if characters % FRAGMENT_INDEX_STRIDE == 0 {
                checkpoints.push(offset);
            }
            characters += 1;
        }
        Self { characters, checkpoints }
    }

    fn byte_to_character(&self, raw: &str, offset: usize) -> usize {
        if self.checkpoints.is_empty() || offset == raw.len() {
            return if offset == raw.len() { self.characters } else { offset };
        }
        let checkpoint = self.checkpoints.partition_point(|byte| *byte <= offset) - 1;
        checkpoint * FRAGMENT_INDEX_STRIDE
            + raw[self.checkpoints[checkpoint]..offset].chars().count()
    }

    fn character_to_byte(&self, raw: &str, character: usize) -> usize {
        if self.checkpoints.is_empty() {
            return character;
        }
        if character == self.characters {
            return raw.len();
        }
        let checkpoint = self.checkpoints[character / FRAGMENT_INDEX_STRIDE];
        checkpoint
            + raw[checkpoint..]
                .char_indices()
                .nth(character % FRAGMENT_INDEX_STRIDE)
                .expect("character index is in bounds")
                .0
    }
}

type LineCacheKey = (usize, usize, usize, usize, u128);
struct CachedPatterns {
    patterns: Vec<String>,
    matched: bool,
}

/// Vectorscan databases shared by every imported Betterleaks finding filter.
///
/// Betterleaks filter expressions contain regex helpers in addition to the main detection regex.
/// Compiling those helpers while evaluating each finding is prohibitively expensive, so the rule
/// database builds this engine once and each worker retains its own scratch arena.
pub(crate) struct BetterleaksFilterEngine {
    matches_any: Option<VectorscanRegexDatabase>,
    matches_any_empty: BTreeMap<String, Regex>,
    matches_any_unicode_word: BTreeMap<String, Regex>,
    find_match: Option<VectorscanRegexDatabase>,
    find_match_exact: BTreeMap<String, Regex>,
    dynamic_regex: bool,
    literal_arrays: LiteralArrays,
    // Exact retained root identity -> number of certified leading OR steps.
    secret_prefix_steps: BTreeMap<usize, usize>,
    // Keep the original AST allocations live for trusted literal-array identities. A clone of
    // a Rule/AST is not sufficient: its Vec/String allocations have different identities.
    _retained_rules: Vec<Arc<Rule>>,
}

impl BetterleaksFilterEngine {
    pub(crate) fn compile_for_rules(rules: &[Arc<Rule>]) -> Result<Self> {
        let retained_rules = rules.to_vec();
        let mut engine =
            Self::compile(retained_rules.iter().filter_map(|rule| rule.betterleaks_filter()))?;
        // This fresh cache contains only arrays collected from these exact retained roots.
        // Retaining strong Arcs prevents mutation in place, drops, and allocation reuse;
        // Arc::make_mut instead gives the caller a separate, untrusted AST allocation.
        engine.literal_arrays.trusted.extend(engine.literal_arrays.values.keys().copied());
        for expression in retained_rules.iter().filter_map(|rule| rule.betterleaks_filter()) {
            let mut remainder = expression;
            let mut steps = 0;
            while let BetterleaksExpr::Binary { operator, left, right } = remainder {
                if !matches!(operator.as_str(), "||" | "or") || !secret_prefix_is_safe(left) {
                    break;
                }
                steps += 1;
                remainder = right;
            }
            if steps != 0 {
                engine.secret_prefix_steps.insert(std::ptr::from_ref(expression) as usize, steps);
            }
        }
        engine._retained_rules = retained_rules;
        Ok(engine)
    }

    pub(crate) fn compile<'a>(
        expressions: impl IntoIterator<Item = &'a BetterleaksExpr>,
    ) -> Result<Self> {
        let mut matches_any_patterns = BTreeSet::new();
        let mut find_match_patterns = BTreeSet::new();
        let mut dynamic_regex = false;
        let mut literal_arrays = LiteralArrays::default();
        for expression in expressions {
            dynamic_regex |= has_dynamic_regex(expression);
            collect_filter_regex_patterns(
                expression,
                &mut matches_any_patterns,
                &mut find_match_patterns,
                &mut literal_arrays,
            )?;
        }
        let find_match_exact: BTreeMap<String, Regex> = find_match_patterns
            .iter()
            .map(|pattern| {
                compile_go_regex(pattern)
                    .with_context(|| format!("compile Betterleaks findMatch regex {pattern:?}"))
                    .map(|regex| (pattern.clone(), regex))
            })
            .collect::<Result<_>>()?;
        let mut matches_any_empty = BTreeMap::new();
        let mut matches_any_unicode_word = BTreeMap::new();
        for pattern in &matches_any_patterns {
            let regex = compile_go_regex(pattern)?;
            if regex.is_match("") {
                matches_any_empty.insert(pattern.clone(), regex);
            } else if go_regex_may_fold_word_class(pattern) {
                matches_any_unicode_word.insert(pattern.clone(), regex);
            }
        }
        matches_any_patterns.retain(|pattern| !matches_any_empty.contains_key(pattern));
        // These shared databases only test presence. Report each pattern once per scan, so an
        // unrelated broad pattern cannot flood a negative helper call with callbacks. findMatch
        // still uses its Rust regex below to select the exact leftmost match.
        Ok(Self {
            matches_any: VectorscanRegexDatabase::compile(
                matches_any_patterns.into_iter().map(|pattern| (pattern.clone(), pattern)),
                Flag::SINGLEMATCH,
                "matchesAny",
            )?,
            find_match: VectorscanRegexDatabase::compile(
                find_match_patterns.into_iter().map(|pattern| {
                    let compiled_pattern = if find_match_exact[&pattern].is_match("") {
                        // Vectorscan cannot report start-of-match for an empty-capable pattern,
                        // and ALLOWEMPTY makes these helper scans pathologically expensive. A
                        // one-byte candidate preserves the Vectorscan gate for non-empty inputs;
                        // the precompiled Rust regex below supplies exact leftmost-match semantics.
                        "(?s).".to_string()
                    } else {
                        pattern.clone()
                    };
                    (pattern, compiled_pattern)
                }),
                Flag::SINGLEMATCH,
                "findMatch",
            )?,
            find_match_exact,
            matches_any_empty,
            matches_any_unicode_word,
            dynamic_regex,
            literal_arrays,
            secret_prefix_steps: BTreeMap::new(),
            _retained_rules: Vec::new(),
        })
    }

    pub(crate) fn evaluate_prefix<'e>(
        &self,
        expression: &'e BetterleaksExpr,
        secret: &str,
    ) -> Result<Option<BetterleaksFilterPrefix<'e>>> {
        let Some(&steps) = self.secret_prefix_steps.get(&(std::ptr::from_ref(expression) as usize))
        else {
            return Ok(None);
        };
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = Evaluator {
            variables: BTreeMap::from([(
                "finding",
                Value::map(BTreeMap::from([("secret".into(), Value::string(secret))])),
            )]),
            filter_engine: self,
            source_line: "",
            line_range: 0..0,
            line_cache: None,
            fragment: &fragment,
        };
        let mut remainder = expression;
        for _ in 0..steps {
            let BetterleaksExpr::Binary { left, right, .. } = remainder else {
                unreachable!("retained secret-prefix plan must follow the original OR spine");
            };
            if evaluator.eval(left)?.truthy() {
                return Ok(Some(BetterleaksFilterPrefix::Complete(BetterleaksFilterOutcome {
                    discard: true,
                    confidence: None,
                })));
            }
            remainder = right;
        }
        Ok(Some(BetterleaksFilterPrefix::Remainder(remainder)))
    }

    fn matches_any(&self, input: &str, patterns: &[&str]) -> Result<bool> {
        if self
            .matches_any_empty
            .iter()
            .any(|(pattern, regex)| patterns.contains(&pattern.as_str()) && regex.is_match(input))
        {
            return Ok(true);
        }
        // Vectorscan's ASCII word shorthands do not acquire Go's Unicode simple
        // folds under (?i): long-s/Kelvin remain non-word there. Retain native
        // classes for ASCII inputs, but use precompiled exact regexes on Unicode.
        let unicode_word = !input.is_ascii();
        if unicode_word
            && self.matches_any_unicode_word.iter().any(|(pattern, regex)| {
                patterns.contains(&pattern.as_str()) && regex.is_match(input)
            })
        {
            return Ok(true);
        }
        let patterns: Vec<_> = patterns
            .iter()
            .copied()
            .filter(|pattern| {
                !self.matches_any_empty.contains_key(*pattern)
                    && !(unicode_word && self.matches_any_unicode_word.contains_key(*pattern))
            })
            .collect();
        if patterns.is_empty() {
            return Ok(false);
        }
        if self.dynamic_regex
            && self.matches_any.as_ref().is_none_or(|database| {
                patterns.iter().any(|pattern| !database.pattern_ids.contains_key(*pattern))
            })
        {
            let regexes = patterns
                .iter()
                .map(|pattern| compile_go_regex(pattern))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            return Ok(regexes.iter().any(|regex| regex.is_match(input)));
        }
        self.matches_any
            .as_ref()
            .ok_or_else(|| anyhow!("matchesAny patterns were not compiled"))?
            .matches_any(input.as_bytes(), &patterns)
    }

    fn find_match(&self, input: &str, pattern: &str) -> Result<String> {
        if self.dynamic_regex && !self.find_match_exact.contains_key(pattern) {
            return Ok(compile_go_regex(pattern)?
                .find(input)
                .map_or_else(String::new, |matched| matched.as_str().to_string()));
        }
        if (input.is_ascii() || !go_regex_may_fold_word_class(pattern))
            && !self
                .find_match
                .as_ref()
                .ok_or_else(|| anyhow!("findMatch pattern was not compiled"))?
                .matches_any(input.as_bytes(), &[pattern])?
        {
            return Ok(String::new());
        }
        let regex = self
            .find_match_exact
            .get(pattern)
            .ok_or_else(|| anyhow!("uncompiled Betterleaks findMatch regex {pattern:?}"))?;
        Ok(regex.find(input).map_or_else(String::new, |matched| matched.as_str().to_string()))
    }
}

fn secret_prefix_call(expression: &BetterleaksExpr) -> Option<(&str, &[BetterleaksExpr])> {
    let BetterleaksExpr::Call { callee, arguments } = expression else { return None };
    let name = match callee.as_ref() {
        BetterleaksExpr::Identifier { value } => value.strip_prefix("filter.").unwrap_or(value),
        // Namespace dispatch precedes method dispatch in Evaluator::call.
        BetterleaksExpr::Member { node, property, optional: false, .. } if matches!(node.as_ref(), BetterleaksExpr::Identifier { value } if value == "filter") =>
        {
            let BetterleaksExpr::String { value } = property.as_ref() else { return None };
            value.as_str()
        }
        _ => return None,
    };
    Some((name, arguments))
}

fn secret_prefix_is_secret(expression: &BetterleaksExpr) -> bool {
    matches!(
        expression,
        BetterleaksExpr::Member { node, property, optional: false, method: false }
            if matches!(node.as_ref(), BetterleaksExpr::Identifier { value } if value == "finding")
                && matches!(
                    property.as_ref(),
                    BetterleaksExpr::String { value } if value == "secret"
                )
    )
}

// Closed proof, not helper dependency inference. Unsupported forms retain full evaluation.
fn secret_prefix_is_safe(expression: &BetterleaksExpr) -> bool {
    let mut pending = vec![expression];
    for _ in 0..256 {
        let Some(expression) = pending.pop() else { return true };
        match expression {
            BetterleaksExpr::Bool { .. } => {}
            BetterleaksExpr::Unary { operator, node }
                if matches!(operator.as_str(), "!" | "not") =>
            {
                pending.push(node);
            }
            BetterleaksExpr::Binary { operator, left, right }
                if matches!(operator.as_str(), "||" | "or" | "&&" | "and") =>
            {
                pending.extend([left.as_ref(), right.as_ref()]);
            }
            BetterleaksExpr::Binary { operator, left, right } if operator == "<=" => {
                let Some(("entropy", [input])) = secret_prefix_call(left) else {
                    return false;
                };
                let finite_number = match right.as_ref() {
                    BetterleaksExpr::Integer { .. } => true,
                    BetterleaksExpr::Float { value } => {
                        value.parse::<f64>().is_ok_and(f64::is_finite)
                    }
                    _ => false,
                };
                if !secret_prefix_is_secret(input) || !finite_number {
                    return false;
                }
            }
            _ => match secret_prefix_call(expression) {
                Some(("matchesAny" | "containsAny", [input, BetterleaksExpr::Array { nodes }]))
                    if secret_prefix_is_secret(input)
                        && nodes
                            .iter()
                            .all(|node| matches!(node, BetterleaksExpr::String { .. })) => {}
                Some(("failsTokenEfficiency", [input])) if secret_prefix_is_secret(input) => {}
                _ => return false,
            },
        }
    }
    pending.is_empty() // Proof budget exhaustion conservatively retains full evaluation.
}

struct VectorscanRegexDatabase {
    pattern_ids: BTreeMap<String, u32>,
    scanners: ScannerPool,
    #[cfg(test)]
    callbacks: std::sync::atomic::AtomicUsize,
}

impl VectorscanRegexDatabase {
    fn compile(
        patterns: impl IntoIterator<Item = (String, String)>,
        flags: Flag,
        helper_name: &str,
    ) -> Result<Option<Self>> {
        let patterns = patterns.into_iter().collect::<Vec<_>>();
        if patterns.is_empty() {
            return Ok(None);
        }
        let mut pattern_ids = BTreeMap::new();
        let patterns = patterns
            .into_iter()
            .enumerate()
            .map(|(id, (source_pattern, compiled_pattern))| {
                let id = u32::try_from(id)?;
                pattern_ids.insert(source_pattern, id);
                // Go regexes match UTF-8 scalar values, but its Perl classes/boundaries are
                // ASCII. Do not enable UCP or disable Unicode on the original source strings.
                let compiled_pattern = normalize_go_regex(&compiled_pattern, false);
                Ok(Pattern::new(compiled_pattern.into_bytes(), flags | Flag::UTF8, Some(id)))
            })
            .collect::<Result<Vec<_>>>()?;
        let database = Arc::new(
            BlockDatabase::new(patterns)
                .with_context(|| format!("compile Betterleaks {helper_name} filters"))?,
        );
        Ok(Some(Self {
            pattern_ids,
            scanners: ScannerPool::new(database),
            #[cfg(test)]
            callbacks: std::sync::atomic::AtomicUsize::new(0),
        }))
    }

    fn matches_any(&self, input: &[u8], patterns: &[&str]) -> Result<bool> {
        let mut allowed_ids = patterns
            .iter()
            .map(|pattern| {
                self.pattern_ids
                    .get(*pattern)
                    .copied()
                    .ok_or_else(|| anyhow!("uncompiled Betterleaks matchesAny pattern {pattern:?}"))
            })
            .collect::<Result<Vec<_>>>()?;
        allowed_ids.sort_unstable();
        allowed_ids.dedup();

        let mut matched = false;
        self.scanners.try_with(|scanner| {
            scanner.scan(input, |id, _from, _to, _flags| {
                #[cfg(test)]
                self.callbacks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if allowed_ids.binary_search(&id).is_ok() {
                    matched = true;
                    Scan::Terminate
                } else {
                    Scan::Continue
                }
            })
        })??;
        Ok(matched)
    }
}

fn has_dynamic_regex(expression: &BetterleaksExpr) -> bool {
    match expression {
        BetterleaksExpr::Call { callee, arguments } => {
            let dynamic = match (expression_name(callee).as_deref(), arguments.as_slice()) {
                (
                    Some("matchesAny" | "filter.matchesAny"),
                    [_, BetterleaksExpr::Array { nodes }],
                ) => nodes.iter().any(|node| !matches!(node, BetterleaksExpr::String { .. })),
                (Some("matchesAny" | "filter.matchesAny"), _) => true,
                (Some("findMatch" | "filter.findMatch"), [_, BetterleaksExpr::String { .. }]) => {
                    false
                }
                (Some("findMatch" | "filter.findMatch"), _) => true,
                _ => false,
            };
            dynamic || arguments.iter().any(has_dynamic_regex)
        }
        BetterleaksExpr::Builtin { arguments: nodes, .. }
        | BetterleaksExpr::Array { nodes }
        | BetterleaksExpr::Sequence { nodes }
        | BetterleaksExpr::Map { pairs: nodes } => nodes.iter().any(has_dynamic_regex),
        BetterleaksExpr::Unary { node, .. }
        | BetterleaksExpr::Chain { node }
        | BetterleaksExpr::Predicate { node } => has_dynamic_regex(node),
        BetterleaksExpr::Binary { left, right, .. }
        | BetterleaksExpr::Pair { key: left, value: right } => {
            has_dynamic_regex(left) || has_dynamic_regex(right)
        }
        BetterleaksExpr::Member { node, property, .. } => {
            has_dynamic_regex(node) || has_dynamic_regex(property)
        }
        BetterleaksExpr::Slice { node, from, to } => {
            has_dynamic_regex(node) || has_dynamic_regex(from) || has_dynamic_regex(to)
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            has_dynamic_regex(cond) || has_dynamic_regex(exp1) || has_dynamic_regex(exp2)
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            has_dynamic_regex(value) || has_dynamic_regex(expr)
        }
        _ => false,
    }
}

fn collect_filter_regex_patterns(
    expression: &BetterleaksExpr,
    matches_any_patterns: &mut BTreeSet<String>,
    find_match_patterns: &mut BTreeSet<String>,
    literal_arrays: &mut LiteralArrays,
) -> Result<()> {
    if let BetterleaksExpr::Array { nodes } = expression {
        literal_arrays.prepare(nodes);
    }
    match expression {
        BetterleaksExpr::Call { callee, arguments } => {
            if let Some(name) = expression_name(callee) {
                match name.as_str() {
                    "filter.matchesAny" | "matchesAny" => {
                        let [_, patterns] = arguments.as_slice() else {
                            bail!("matchesAny expects two arguments");
                        };
                        if let BetterleaksExpr::Array { nodes } = patterns {
                            for node in nodes {
                                if let BetterleaksExpr::String { value } = node {
                                    matches_any_patterns.insert(value.clone());
                                }
                            }
                        }
                    }
                    "filter.findMatch" | "findMatch" => {
                        let [_, pattern] = arguments.as_slice() else {
                            bail!("findMatch expects two arguments");
                        };
                        if let BetterleaksExpr::String { value } = pattern {
                            find_match_patterns.insert(value.clone());
                        }
                    }
                    "filter.containsAny" | "containsAny" => {
                        if let [_, BetterleaksExpr::Array { nodes }] = arguments.as_slice() {
                            literal_arrays.prepare_contains_any(nodes);
                        }
                    }
                    _ => {}
                }
            }
            for argument in arguments {
                collect_filter_regex_patterns(
                    argument,
                    matches_any_patterns,
                    find_match_patterns,
                    literal_arrays,
                )?;
            }
        }
        BetterleaksExpr::Builtin { arguments, .. }
        | BetterleaksExpr::Sequence { nodes: arguments }
        | BetterleaksExpr::Array { nodes: arguments }
        | BetterleaksExpr::Map { pairs: arguments } => {
            for argument in arguments {
                collect_filter_regex_patterns(
                    argument,
                    matches_any_patterns,
                    find_match_patterns,
                    literal_arrays,
                )?;
            }
        }
        BetterleaksExpr::Unary { node, .. }
        | BetterleaksExpr::Chain { node }
        | BetterleaksExpr::Predicate { node } => collect_filter_regex_patterns(
            node,
            matches_any_patterns,
            find_match_patterns,
            literal_arrays,
        )?,
        BetterleaksExpr::Binary { left, right, .. } => {
            collect_filter_regex_patterns(
                left,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                right,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::Member { node, property, .. } => {
            collect_filter_regex_patterns(
                node,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                property,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::Slice { node, from, to } => {
            collect_filter_regex_patterns(
                node,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                from,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                to,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            collect_filter_regex_patterns(
                cond,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                exp1,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                exp2,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            collect_filter_regex_patterns(
                value,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                expr,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::Pair { key, value } => {
            collect_filter_regex_patterns(
                key,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
            collect_filter_regex_patterns(
                value,
                matches_any_patterns,
                find_match_patterns,
                literal_arrays,
            )?;
        }
        BetterleaksExpr::Nil
        | BetterleaksExpr::Identifier { .. }
        | BetterleaksExpr::Integer { .. }
        | BetterleaksExpr::Float { .. }
        | BetterleaksExpr::Bool { .. }
        | BetterleaksExpr::String { .. }
        | BetterleaksExpr::Pointer { .. } => {}
    }
    Ok(())
}

// Small literal lists are cheaper to probe directly; large containsAny lists share one matcher.
const CONTAINS_ANY_AUTOMATON_MIN_TERMS: usize = 32;

#[derive(Default)]
struct LiteralArrays {
    values: BTreeMap<usize, Arc<[Value<'static>]>>,
    lowercase: BTreeMap<usize, Vec<String>>,
    contains_any: BTreeMap<usize, AhoCorasick>,
    // Only keys collected by compile_for_rules from its exact, strongly retained roots.
    trusted: BTreeSet<usize>,
}

impl LiteralArrays {
    fn prepare(&mut self, nodes: &[BetterleaksExpr]) {
        if self.get(nodes).is_some() {
            return;
        }
        // Only immutable string literals may bypass evaluation. Mixed arrays must still evaluate
        // every element, in order, including helper return values and errors.
        let Some(strings) = nodes
            .iter()
            .map(|node| match node {
                BetterleaksExpr::String { value } => Some(value),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
        else {
            return;
        };
        let values: Arc<[Value<'static>]> =
            strings.iter().map(|value| Value::string((*value).clone())).collect();
        self.lowercase.insert(
            values.as_ptr() as usize,
            strings.iter().map(|value| value.to_lowercase()).collect(),
        );
        if let Some(previous) = self.values.insert(nodes.as_ptr() as usize, values) {
            // Prepared-set identities must always refer to live, engine-retained arrays.
            self.lowercase.remove(&(previous.as_ptr() as usize));
            self.contains_any.remove(&(previous.as_ptr() as usize));
        }
    }

    fn prepare_contains_any(&mut self, nodes: &[BetterleaksExpr]) {
        self.prepare(nodes);
        let Some(values) = self.get(nodes) else {
            return;
        };
        if values.len() < CONTAINS_ANY_AUTOMATON_MIN_TERMS {
            return;
        }
        let identity = values.as_ptr() as usize;
        if let Entry::Vacant(entry) = self.contains_any.entry(identity) {
            // Match the same Unicode-lowercased byte strings as str::contains, including empty
            // terms. A matcher size/build limit must not reject a previously valid filter:
            // retain the linear fallback if this optional optimization cannot be prepared.
            if let Ok(matcher) = AhoCorasick::new(&self.lowercase[&identity]) {
                entry.insert(matcher);
            }
        }
    }

    fn get(&self, nodes: &[BetterleaksExpr]) -> Option<&Arc<[Value<'static>]>> {
        let identity = nodes.as_ptr() as usize;
        let values = self.values.get(&identity)?;
        // Length remains necessary even for retained roots: a subslice may share its start.
        // Other borrowed/cloned ASTs keep the full check against stale/reused cache keys.
        (values.len() == nodes.len()
            && (self.trusted.contains(&identity)
                || nodes.iter().zip(values.iter()).all(|(node, value)| {
                    matches!(node, BetterleaksExpr::String { value: source }
                        if value.as_string().is_ok_and(|value| value == source))
                })))
        .then_some(values)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Value<'a> {
    Nil,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(Cow<'a, str>),
    Array(Arc<[Value<'a>]>),
    Map(Arc<BTreeMap<Cow<'a, str>, Value<'a>>>),
}

impl<'a> Value<'a> {
    fn string(value: impl Into<Cow<'a, str>>) -> Self {
        Self::String(value.into())
    }

    fn array(values: impl Into<Arc<[Value<'a>]>>) -> Self {
        Self::Array(values.into())
    }

    fn map(values: BTreeMap<Cow<'a, str>, Value<'a>>) -> Self {
        Self::Map(Arc::new(values))
    }

    fn truthy(&self) -> bool {
        match self {
            Self::Nil => false,
            Self::Bool(value) => *value,
            Self::Integer(value) => *value != 0,
            Self::Float(value) => *value != 0.0,
            Self::String(value) => !value.is_empty(),
            Self::Array(value) => !value.is_empty(),
            Self::Map(value) => !value.is_empty(),
        }
    }

    fn as_string(&self) -> Result<&str> {
        match self {
            Self::String(value) => Ok(value),
            other => bail!("expected string, found {other:?}"),
        }
    }

    fn into_string(self) -> Result<String> {
        match self {
            Self::String(value) => Ok(value.into_owned()),
            other => bail!("expected string, found {other:?}"),
        }
    }

    fn as_i64(&self) -> Result<i64> {
        match self {
            Self::Integer(value) => Ok(*value),
            Self::Float(value) => Ok(*value as i64),
            other => bail!("expected number, found {other:?}"),
        }
    }

    fn as_f64(&self) -> Result<f64> {
        match self {
            Self::Integer(value) => Ok(*value as f64),
            Self::Float(value) => Ok(*value),
            other => bail!("expected number, found {other:?}"),
        }
    }
}

struct Evaluator<'a, 'c> {
    variables: BTreeMap<&'a str, Value<'a>>,
    filter_engine: &'a BetterleaksFilterEngine,
    source_line: &'a str,
    line_range: Range<usize>,
    line_cache: Option<&'c mut BetterleaksFilterLineCache>,
    fragment: &'a BetterleaksFilterFragment<'a>,
}

/// Evaluate a Betterleaks filter against a candidate finding.
pub fn evaluate_filter(
    expression: &BetterleaksExpr,
    context: &BetterleaksFilterContext<'_>,
) -> Result<BetterleaksFilterOutcome> {
    let filter_engine = BetterleaksFilterEngine::compile(std::iter::once(expression))?;
    evaluate_filter_with_engine(expression, context, &filter_engine)
}

pub(crate) fn evaluate_filter_with_engine(
    expression: &BetterleaksExpr,
    context: &BetterleaksFilterContext<'_>,
    filter_engine: &BetterleaksFilterEngine,
) -> Result<BetterleaksFilterOutcome> {
    evaluate_filter_with_engine_and_line_cache(expression, context, filter_engine, 0..0, None)
}

pub(crate) fn evaluate_filter_with_engine_and_line_cache(
    expression: &BetterleaksExpr,
    context: &BetterleaksFilterContext<'_>,
    filter_engine: &BetterleaksFilterEngine,
    line_range: Range<usize>,
    line_cache: Option<&mut BetterleaksFilterLineCache>,
) -> Result<BetterleaksFilterOutcome> {
    let fragment = BetterleaksFilterFragment::new(context.fragment_raw);
    evaluate_filter_with_engine_and_fragment(
        expression,
        context,
        filter_engine,
        line_range,
        line_cache,
        &fragment,
    )
}

pub(crate) fn evaluate_filter_with_engine_and_fragment(
    expression: &BetterleaksExpr,
    context: &BetterleaksFilterContext<'_>,
    filter_engine: &BetterleaksFilterEngine,
    line_range: Range<usize>,
    line_cache: Option<&mut BetterleaksFilterLineCache>,
    fragment: &BetterleaksFilterFragment<'_>,
) -> Result<BetterleaksFilterOutcome> {
    let mut finding = BTreeMap::new();
    finding.insert("secret".into(), Value::string(context.secret));
    finding.insert("match".into(), Value::string(context.full_match));
    finding.insert("line".into(), Value::string(context.line));
    finding.insert("rule_id".into(), Value::string(context.rule_id));
    finding.insert("description".into(), Value::string(context.description));
    finding.insert("context".into(), Value::string(context.full_match));
    finding.insert("fragment_raw".into(), Value::string(context.fragment_raw));
    finding.insert("match_start_idx".into(), Value::Integer(context.match_start_idx as i64));
    finding.insert("match_end_idx".into(), Value::Integer(context.match_end_idx as i64));
    finding
        .insert("match_line_start_idx".into(), Value::Integer(context.match_line_start_idx as i64));
    finding.insert("match_line_end_idx".into(), Value::Integer(context.match_line_end_idx as i64));
    finding.insert(
        "captures".into(),
        Value::map(
            context
                .captures
                .iter()
                .map(|(key, value)| (Cow::Borrowed(key.as_str()), Value::string(value.as_str())))
                .collect(),
        ),
    );

    let mut attributes = context
        .attributes
        .into_iter()
        .flat_map(|attributes| attributes.iter())
        .map(|(key, value)| (Cow::Borrowed(key.as_str()), Value::string(value.as_str())))
        .collect::<BTreeMap<_, _>>();
    attributes.entry("path".into()).or_insert_with(|| Value::string(context.path));
    let variables =
        BTreeMap::from([("finding", Value::map(finding)), ("attributes", Value::map(attributes))]);
    let mut evaluator = Evaluator {
        variables,
        filter_engine,
        source_line: context.line,
        line_range,
        line_cache,
        fragment,
    };
    let discard = evaluator.eval(expression)?.truthy();
    Ok(BetterleaksFilterOutcome { discard, confidence: None })
}

/// Evaluate the Betterleaks source prefilter for one path.
///
/// Unlike finding filters, this runs once before any content matching. Betterleaks currently
/// supplies only `attributes["path"]` to this expression; the empty finding fields keep the
/// evaluator forward-compatible without conflating source and finding filtering.
pub fn evaluate_prefilter(expression: &BetterleaksExpr, path: &str) -> Result<bool> {
    let engine = BetterleaksFilterEngine::compile(std::iter::once(expression))?;
    evaluate_prefilter_with_engine(expression, path, &engine)
}

pub(crate) fn evaluate_prefilter_with_engine(
    expression: &BetterleaksExpr,
    path: &str,
    engine: &BetterleaksFilterEngine,
) -> Result<bool> {
    evaluate_prefilter_with_attributes(expression, path, None, engine)
}

pub(crate) fn evaluate_prefilter_with_attributes(
    expression: &BetterleaksExpr,
    path: &str,
    attributes: Option<&BTreeMap<String, String>>,
    engine: &BetterleaksFilterEngine,
) -> Result<bool> {
    Ok(evaluate_filter_with_engine(
        expression,
        &BetterleaksFilterContext {
            path,
            attributes,
            secret: "",
            full_match: "",
            line: "",
            fragment_raw: "",
            match_start_idx: 0,
            match_end_idx: 0,
            match_line_start_idx: 0,
            match_line_end_idx: 0,
            rule_id: "",
            description: "",
            captures: BTreeMap::new(),
        },
        engine,
    )?
    .discard)
}

impl<'a> Evaluator<'a, '_> {
    fn eval(&mut self, expression: &'a BetterleaksExpr) -> Result<Value<'a>> {
        match expression {
            BetterleaksExpr::Nil => Ok(Value::Nil),
            BetterleaksExpr::Identifier { value } => {
                Ok(self.variables.get(value.as_str()).cloned().unwrap_or(Value::Nil))
            }
            BetterleaksExpr::Integer { value } => Ok(Value::Integer(*value)),
            BetterleaksExpr::Float { value } => Ok(Value::Float(value.parse()?)),
            BetterleaksExpr::Bool { value } => Ok(Value::Bool(*value)),
            BetterleaksExpr::String { value } => Ok(Value::string(value.as_str())),
            BetterleaksExpr::Unary { operator, node } => {
                let value = self.eval(node)?;
                match operator.as_str() {
                    "!" | "not" => Ok(Value::Bool(!value.truthy())),
                    "-" => match value {
                        Value::Integer(value) => Ok(Value::Integer(-value)),
                        Value::Float(value) => Ok(Value::Float(-value)),
                        other => bail!("cannot negate {other:?}"),
                    },
                    other => bail!("unsupported unary filter operator {other:?}"),
                }
            }
            BetterleaksExpr::Binary { operator, left, right } => {
                self.eval_binary(operator, left, right)
            }
            BetterleaksExpr::Chain { node } => Ok(self.eval_chain(node)?.unwrap_or(Value::Nil)),
            BetterleaksExpr::Member { node, property, optional, method } => {
                if *method {
                    bail!("method reference was evaluated without being called");
                }
                let container = self.eval(node)?;
                if *optional && container == Value::Nil {
                    return Ok(Value::Nil);
                }
                let property = self.eval(property)?;
                self.member(container, property)
            }
            BetterleaksExpr::Slice { node, from, to } => {
                let value = self.eval(node)?;
                let from = self.eval(from)?.as_i64()?;
                let to = self.eval(to)?.as_i64()?;
                self.slice(value, from, to)
            }
            BetterleaksExpr::Call { callee, arguments } => self.call(callee, arguments),
            BetterleaksExpr::Builtin { name, arguments } => self.call_named(name, arguments),
            BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
                if self.eval(cond)?.truthy() {
                    self.eval(exp1)
                } else {
                    self.eval(exp2)
                }
            }
            BetterleaksExpr::VariableDeclarator { name, value, expr } => {
                let value = self.eval(value)?;
                let previous = self.variables.insert(name.as_str(), value);
                let result = self.eval(expr);
                if let Some(previous) = previous {
                    self.variables.insert(name.as_str(), previous);
                } else {
                    self.variables.remove(name.as_str());
                }
                result
            }
            BetterleaksExpr::Sequence { nodes } => {
                let mut value = Value::Nil;
                for node in nodes {
                    value = self.eval(node)?;
                }
                Ok(value)
            }
            BetterleaksExpr::Array { nodes } => {
                if let Some(values) = self.filter_engine.literal_arrays.get(nodes) {
                    return Ok(Value::Array(Arc::clone(values)));
                }
                nodes
                    .iter()
                    .map(|node| self.eval(node))
                    .collect::<Result<Vec<_>>>()
                    .map(Value::array)
            }
            BetterleaksExpr::Map { pairs } => {
                let mut values = BTreeMap::new();
                for pair in pairs {
                    let BetterleaksExpr::Pair { key, value } = pair else {
                        bail!("map contains a non-pair expression");
                    };
                    let key = match self.eval(key)? {
                        Value::String(key) => key,
                        other => bail!("expected string, found {other:?}"),
                    };
                    values.insert(key, self.eval(value)?);
                }
                Ok(Value::map(values))
            }
            BetterleaksExpr::Pair { .. } => bail!("pair evaluated outside a map"),
            BetterleaksExpr::Predicate { node } => self.eval(node),
            BetterleaksExpr::Pointer { name } => {
                Ok(self.variables.get(name.as_str()).cloned().unwrap_or(Value::Nil))
            }
        }
    }

    /// `None` is an optional receiver short-circuit and must skip later indexes and arguments.
    fn eval_chain(&mut self, expression: &'a BetterleaksExpr) -> Result<Option<Value<'a>>> {
        match expression {
            BetterleaksExpr::Member { node, property, optional, method: false } => {
                let Some(receiver) = self.eval_chain(node)? else { return Ok(None) };
                if *optional && receiver == Value::Nil {
                    return Ok(None);
                }
                let property = self.eval(property)?;
                self.member(receiver, property).map(Some)
            }
            BetterleaksExpr::Slice { node, from, to } => {
                let Some(receiver) = self.eval_chain(node)? else { return Ok(None) };
                let from = self.eval(from)?.as_i64()?;
                let to = self.eval(to)?.as_i64()?;
                self.slice(receiver, from, to).map(Some)
            }
            BetterleaksExpr::Call { callee, arguments } => {
                if let BetterleaksExpr::Member { node, property, optional, method: true } =
                    callee.as_ref()
                {
                    let Some(receiver) = self.eval_chain(node)? else { return Ok(None) };
                    if *optional && receiver == Value::Nil {
                        return Ok(None);
                    }
                    let method = self.eval(property)?.into_string()?;
                    let arguments = self.eval_arguments(arguments)?;
                    self.call_method(receiver, &method, arguments).map(Some)
                } else {
                    self.eval(expression).map(Some)
                }
            }
            _ => self.eval(expression).map(Some),
        }
    }

    fn eval_binary(
        &mut self,
        operator: &str,
        left: &'a BetterleaksExpr,
        right: &'a BetterleaksExpr,
    ) -> Result<Value<'a>> {
        let left = self.eval(left)?;
        match operator {
            "||" | "or" if left.truthy() => return Ok(Value::Bool(true)),
            "&&" | "and" if !left.truthy() => return Ok(Value::Bool(false)),
            "??" if left != Value::Nil => return Ok(left),
            _ => {}
        }
        let right = self.eval(right)?;
        match operator {
            "||" | "or" | "&&" | "and" => Ok(Value::Bool(right.truthy())),
            "??" => Ok(right),
            "==" => Ok(Value::Bool(values_equal(&left, &right))),
            "!=" => Ok(Value::Bool(!values_equal(&left, &right))),
            "<" | "<=" | ">" | ">=" => {
                let ordering = match (&left, &right) {
                    (Value::String(left), Value::String(right)) => left.cmp(right),
                    _ => left.as_f64()?.total_cmp(&right.as_f64()?),
                };
                Ok(Value::Bool(match operator {
                    "<" => ordering.is_lt(),
                    "<=" => ordering.is_le(),
                    ">" => ordering.is_gt(),
                    ">=" => ordering.is_ge(),
                    _ => unreachable!(),
                }))
            }
            "+" => match (left, right) {
                (Value::Integer(left), Value::Integer(right)) => Ok(Value::Integer(
                    left.checked_add(right).ok_or_else(|| anyhow!("integer overflow"))?,
                )),
                (Value::String(mut left), Value::String(right)) => {
                    left.to_mut().push_str(&right);
                    Ok(Value::String(left))
                }
                (left, right) => Ok(Value::Float(left.as_f64()? + right.as_f64()?)),
            },
            "-" => numeric_binary(left, right, |left, right| left - right),
            "*" => numeric_binary(left, right, |left, right| left * right),
            "/" => {
                let right = right.as_f64()?;
                if right == 0.0 {
                    bail!("division by zero");
                }
                Ok(Value::Float(left.as_f64()? / right))
            }
            "%" => Ok(Value::Integer(
                left.as_i64()?
                    .checked_rem(right.as_i64()?)
                    .ok_or_else(|| anyhow!("invalid integer remainder"))?,
            )),
            "**" | "^" => numeric_binary(left, right, f64::powf),
            ".." => {
                let from = left.as_i64()?;
                let to = right.as_i64()?;
                if to.saturating_sub(from) > 1_000_000 {
                    bail!("range exceeds expression collection limit");
                }
                Ok(Value::Array((from..=to).map(Value::Integer).collect()))
            }
            "contains" => Ok(Value::Bool(left.as_string()?.contains(right.as_string()?))),
            "startsWith" => Ok(Value::Bool(left.as_string()?.starts_with(right.as_string()?))),
            "endsWith" => Ok(Value::Bool(left.as_string()?.ends_with(right.as_string()?))),
            "matches" => {
                Ok(Value::Bool(compile_go_regex(right.as_string()?)?.is_match(left.as_string()?)))
            }
            "in" => Ok(Value::Bool(match right {
                Value::Array(values) => values.iter().any(|value| values_equal(&left, value)),
                Value::String(value) => value.contains(left.as_string()?),
                Value::Map(values) => values.contains_key(left.as_string()?),
                _ => false,
            })),
            other => bail!("unsupported binary filter operator {other:?}"),
        }
    }

    fn member(&self, container: Value<'a>, property: Value<'a>) -> Result<Value<'a>> {
        match (container, property) {
            (Value::Map(values), Value::String(key)) => {
                Ok(values.get(key.as_ref()).cloned().unwrap_or(Value::Nil))
            }
            (Value::Array(values), property) => {
                let index = usize::try_from(property.as_i64()?).ok();
                Ok(index.and_then(|index| values.get(index).cloned()).unwrap_or(Value::Nil))
            }
            (Value::String(value), property) => {
                let index = usize::try_from(property.as_i64()?).ok();
                Ok(index
                    .and_then(|index| value.as_bytes().get(index).copied())
                    .map(|byte| Value::string(char::from(byte).to_string()))
                    .unwrap_or(Value::Nil))
            }
            (Value::Nil, _) => Ok(Value::Nil),
            (container, property) => {
                bail!("cannot read member {property:?} from {container:?}")
            }
        }
    }

    fn slice(&self, value: Value<'a>, from: i64, to: i64) -> Result<Value<'a>> {
        let character_range = match &value {
            Value::String(value) => self.fragment.character_range(value),
            _ => None,
        };
        let length = match &value {
            Value::String(value) => {
                character_range.as_ref().map_or_else(|| value.chars().count(), |range| range.len())
            }
            Value::Array(values) => values.len(),
            _ => 0,
        };
        let index = |index: i64| {
            usize::try_from(if index < 0 {
                (length as i64).saturating_add(index).max(0)
            } else {
                index
            })
            .unwrap_or(usize::MAX)
            .min(length)
        };
        let from = index(from);
        let to = index(to).max(from);
        match value {
            Value::String(value) => {
                let bytes = if let Some(characters) = character_range {
                    let start = self.fragment.byte_offset(characters.start);
                    self.fragment.byte_offset(characters.start + from) - start
                        ..self.fragment.byte_offset(characters.start + to) - start
                } else {
                    let offset = |index| {
                        value.char_indices().nth(index).map_or(value.len(), |(byte, _)| byte)
                    };
                    offset(from)..offset(to)
                };
                Ok(Value::string(match value {
                    Cow::Borrowed(value) => Cow::Borrowed(&value[bytes]),
                    Cow::Owned(value) => Cow::Owned(value[bytes].to_string()),
                }))
            }
            Value::Array(values) => Ok(Value::array(values[from..to].to_vec())),
            other => bail!("cannot slice {other:?}"),
        }
    }

    fn call(
        &mut self,
        callee: &'a BetterleaksExpr,
        arguments: &'a [BetterleaksExpr],
    ) -> Result<Value<'a>> {
        if let Some(name) = expression_name(callee)
            && (name.starts_with("filter.") || name.starts_with("crypto."))
        {
            return self.call_named(&name, arguments);
        }
        if let BetterleaksExpr::Member { node, property, method: true, .. } = callee {
            let receiver = self.eval(node)?;
            let method = self.eval(property)?.into_string()?;
            let arguments = self.eval_arguments(arguments)?;
            return self.call_method(receiver, &method, arguments);
        }
        let name = expression_name(callee)
            .ok_or_else(|| anyhow!("unsupported dynamic Betterleaks filter call {callee:?}"))?;
        self.call_named(&name, arguments)
    }

    fn call_named(&mut self, name: &str, arguments: &'a [BetterleaksExpr]) -> Result<Value<'a>> {
        if matches!(
            name,
            "any"
                | "all"
                | "none"
                | "one"
                | "filter"
                | "map"
                | "count"
                | "find"
                | "findLast"
                | "findIndex"
                | "findLastIndex"
        ) {
            return self.call_collection(name, arguments);
        }
        let arguments = self.eval_arguments(arguments)?;
        match name {
            "malformedPrivateKey" => {
                let [input] = arguments.as_slice() else {
                    bail!("malformedPrivateKey expects one argument");
                };
                Ok(Value::Bool(crate::private_key::is_malformed(input.as_string()?)))
            }
            "filter.matchesAny" | "matchesAny" => self.matches_any(arguments),
            "filter.findMatch" | "findMatch" => self.find_match(arguments),
            "filter.containsAny" | "containsAny" => contains_any(arguments, self.filter_engine),
            "startsWithAny" => string_set_helper(arguments, "startsWithAny"),
            "intersects" => string_set_helper(arguments, "intersects"),
            "crypto.sha256" => {
                let [input] = arguments.as_slice() else {
                    bail!("crypto.sha256 expects one argument");
                };
                Ok(Value::string(hex::encode(Sha256::digest(input.as_string()?.as_bytes()))))
            }
            "filter.entropy" | "entropy" => entropy(arguments),
            "filter.tokenRatio" | "tokenRatio" => token_ratio(arguments),
            "filter.failsTokenEfficiency" | "failsTokenEfficiency" => {
                fails_token_efficiency(arguments)
            }
            "filter.setConfidence" | "setConfidence" => {
                // Legacy custom YAML/TOML expressions may use this call's string result in
                // rejection predicates. Keep it as a passthrough, never a confidence setter.
                let [value] = arguments.as_slice() else {
                    bail!("filter.setConfidence expects one argument");
                };
                value.as_string()?;
                Ok(value.clone())
            }
            "len" | "size" => length(arguments),
            "lower" | "upper" => {
                let [value] = arguments.as_slice() else {
                    bail!("lower expects one argument");
                };
                Ok(Value::string(if name == "lower" {
                    value.as_string()?.to_lowercase()
                } else {
                    value.as_string()?.to_uppercase()
                }))
            }
            "max" => min_or_max(arguments, true),
            "min" => min_or_max(arguments, false),
            "split" => split(arguments),
            "join" => join(arguments),
            "lastIndexOf" => last_index_of(arguments),
            "replace" => replace(arguments),
            "fromBase64" => from_base64(arguments),
            "type" | "string" | "int" | "float" | "trim" | "trimPrefix" | "trimSuffix"
            | "repeat" | "indexOf" | "hasPrefix" | "hasSuffix" | "keys" | "values" | "reverse"
            | "sort" | "uniq" | "flatten" | "concat" | "first" | "last" | "get" | "sum"
            | "mean" | "abs" | "ceil" | "floor" | "round" | "toJSON" | "fromJSON" => {
                simple_builtin(name, arguments)
            }
            other => bail!("unsupported Betterleaks filter function {other:?}"),
        }
    }

    fn eval_arguments(&mut self, arguments: &'a [BetterleaksExpr]) -> Result<Vec<Value<'a>>> {
        arguments.iter().map(|argument| self.eval(argument)).collect()
    }

    fn call_collection(
        &mut self,
        name: &str,
        arguments: &'a [BetterleaksExpr],
    ) -> Result<Value<'a>> {
        let [items, predicate] = arguments else {
            bail!("{name} expects two arguments");
        };
        let Value::Array(items) = self.eval(items)? else {
            bail!("first argument to {name} must be an array");
        };
        let previous = self.variables.get("#").cloned();
        let previous_index = self.variables.get("#index").cloned();
        let result = (|| {
            let mut output = Vec::new();
            let mut count = 0_i64;
            let mut found = Value::Nil;
            for (index, item) in items.iter().cloned().enumerate() {
                self.variables.insert("#", item.clone());
                self.variables.insert("#index", Value::Integer(index as i64));
                let value = self.eval(predicate)?;
                if name == "map" {
                    output.push(value);
                    continue;
                }
                if value.truthy() {
                    count += 1;
                    match name {
                        "any" => return Ok(Value::Bool(true)),
                        "none" => return Ok(Value::Bool(false)),
                        "one" if count > 1 => return Ok(Value::Bool(false)),
                        "find" => return Ok(item),
                        "findIndex" => return Ok(Value::Integer(index as i64)),
                        "findLast" => found = item,
                        "findLastIndex" => found = Value::Integer(index as i64),
                        "filter" => output.push(item),
                        _ => {}
                    }
                } else if name == "all" {
                    return Ok(Value::Bool(false));
                }
            }
            Ok(match name {
                "filter" | "map" => Value::array(output),
                "count" => Value::Integer(count),
                "find" | "findLast" | "findIndex" | "findLastIndex" => found,
                "all" | "none" => Value::Bool(true),
                "one" => Value::Bool(count == 1),
                _ => Value::Bool(false),
            })
        })();
        if let Some(previous) = previous {
            self.variables.insert("#", previous);
        } else {
            self.variables.remove("#");
        }
        if let Some(previous) = previous_index {
            self.variables.insert("#index", previous);
        } else {
            self.variables.remove("#index");
        }
        result
    }

    fn matches_any(&mut self, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
        let [input, patterns] = arguments.as_slice() else {
            bail!("matchesAny expects two arguments");
        };
        if let Value::Array(values) = input {
            if values.iter().any(|value| !matches!(value, Value::String(_))) {
                return Ok(Value::Bool(false));
            }
            for value in values.iter() {
                if self.matches_any(vec![value.clone(), patterns.clone()])? == Value::Bool(true) {
                    return Ok(Value::Bool(true));
                }
            }
            return Ok(Value::Bool(false));
        }
        let Ok(patterns) = strings(patterns) else {
            return Ok(Value::Bool(false));
        };
        let Ok(input) = input.as_string() else {
            return Ok(Value::Bool(false));
        };
        // Cache only the unmodified source line. Derived strings and shadowed
        // variables still evaluate normally, even when the helper appears in
        // an expression that otherwise refers to finding["line"]. The pointer
        // comparison establishes provenance within this evaluation. Include
        // source identity in the key too, so different live buffers cannot share
        // results merely because their line ranges coincide.
        let same_line =
            input.as_ptr() == self.source_line.as_ptr() && input.len() == self.source_line.len();
        if same_line && let Some(cache) = self.line_cache.as_deref_mut() {
            let mut hash = Xxh3::new();
            for pattern in &patterns {
                hash.update(&pattern.len().to_le_bytes());
                hash.update(pattern.as_bytes());
            }
            let key = (
                input.as_ptr() as usize,
                input.len(),
                self.line_range.start,
                self.line_range.end,
                hash.digest128(),
            );
            if let Some(results) = cache.matches_any.get(&key)
                && let Some(result) = results.iter().find(|result| {
                    result.patterns.len() == patterns.len()
                        && result.patterns.iter().zip(&patterns).all(|(a, b)| a == b)
                })
            {
                return Ok(Value::Bool(result.matched));
            }
            let matched = self.filter_engine.matches_any(input, &patterns)?;
            #[cfg(test)]
            {
                cache.scans += 1;
            }
            // Evict only when inserting a new result. Hits at capacity remain cheap, and an
            // error above cannot evict valid entries. A later miss just repeats the exact scan.
            if cache.entries >= SOURCE_LINE_CACHE_MAX_ENTRIES {
                cache.matches_any.clear();
                cache.entries = 0;
            }
            // Compare the actual list on hits: a hash collision must never
            // change filtering. Clone patterns only when populating the cache.
            cache.matches_any.entry(key).or_default().push(CachedPatterns {
                patterns: patterns.iter().map(|pattern| (*pattern).to_owned()).collect(),
                matched,
            });
            cache.entries += 1;
            return Ok(Value::Bool(matched));
        }
        Ok(Value::Bool(self.filter_engine.matches_any(input, &patterns)?))
    }

    fn find_match(&self, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
        let [input, pattern] = arguments.as_slice() else {
            bail!("findMatch expects two arguments");
        };
        Ok(Value::string(self.filter_engine.find_match(input.as_string()?, pattern.as_string()?)?))
    }

    fn call_method(
        &mut self,
        receiver: Value<'a>,
        name: &str,
        arguments: Vec<Value<'a>>,
    ) -> Result<Value<'a>> {
        match name {
            "contains" => {
                let [needle] = arguments.as_slice() else {
                    bail!("contains expects one argument");
                };
                Ok(Value::Bool(receiver.as_string()?.contains(needle.as_string()?)))
            }
            "startsWith" => {
                let [prefix] = arguments.as_slice() else {
                    bail!("startsWith expects one argument");
                };
                Ok(Value::Bool(receiver.as_string()?.starts_with(prefix.as_string()?)))
            }
            "endsWith" => {
                let [suffix] = arguments.as_slice() else {
                    bail!("endsWith expects one argument");
                };
                Ok(Value::Bool(receiver.as_string()?.ends_with(suffix.as_string()?)))
            }
            "substring" => substring(receiver, arguments),
            "lastIndexOf" => {
                let mut values = vec![receiver];
                values.extend(arguments);
                last_index_of(values)
            }
            "replace" => {
                let mut values = vec![receiver];
                values.extend(arguments);
                replace(values)
            }
            other => bail!("unsupported Betterleaks filter method {other:?}"),
        }
    }
}

/// Compile Go helper regex syntax without changing the original input or making `.`/Unicode
/// properties byte-oriented. Go's Perl character classes and word boundaries are ASCII, unlike
/// Rust's defaults; expanding only those constructs also avoids huge Unicode repetition programs.
#[doc(hidden)]
pub fn compile_go_regex(pattern: &str) -> Result<Regex> {
    Regex::new(&normalize_go_regex(pattern, true))
        .with_context(|| format!("invalid Betterleaks regex {pattern:?}"))
}

fn go_regex_may_fold_word_class(pattern: &str) -> bool {
    // Conservatively retaining an escaped/quoted occurrence is harmless. Avoid
    // parsing flags or recompiling regexes while evaluating individual findings.
    pattern.contains(r"\w") || pattern.contains(r"\W")
}

fn normalize_go_regex(pattern: &str, for_rust: bool) -> String {
    let mut normalized = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    let mut in_class = false;
    let mut class_content = false;
    let mut class_negated = false;
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    normalized.push(ch);
                    break;
                };
                let class = match escaped {
                    // Vectorscan already uses ASCII Perl classes. Keep them native,
                    // including their case-fold-before-negation behavior under (?i).
                    'd' | 'D' if for_rust => Some(("0-9", "[^0-9]")),
                    'w' | 'W' if for_rust => Some(("0-9A-Z_a-z", "[^0-9A-Z_a-z]")),
                    // Go excludes vertical tab from \s, unlike Vectorscan/PCRE.
                    's' | 'S' => Some((r"\t\n\f\r ", r"[^\t\n\f\r ]")),
                    _ => None,
                };
                if let Some((positive, negative)) = class {
                    if escaped.is_ascii_uppercase() {
                        if in_class && !for_rust {
                            // Native nested classes are not supported. No ASCII
                            // letters are excluded here, so case folding is harmless.
                            normalized.push_str(r"\x00-\x08\x0b\x0e-\x1f\x21-\x{10FFFF}");
                        } else {
                            // A nested negated class retains the order of folding
                            // and negation. Expanding \W into complement ranges would
                            // fold long-s/Kelvin back into the excluded ASCII s/k.
                            normalized.push_str(negative);
                        }
                    } else if in_class {
                        normalized.push_str(positive);
                    } else {
                        normalized.push('[');
                        normalized.push_str(positive);
                        normalized.push(']');
                    }
                } else if escaped == 'v' {
                    // Go's \v is one ASCII vertical tab, not PCRE vertical space.
                    normalized.push_str(r"\x0b");
                } else if matches!(escaped, 'b' | 'B') && !in_class && for_rust {
                    normalized.push_str(if escaped == 'b' { r"(?-u:\b)" } else { r"(?-u:\B)" });
                } else if escaped == 'Q' && !in_class {
                    let rest = &pattern[offset + 2..];
                    let end = rest.find(r"\E").unwrap_or(rest.len());
                    normalized.push_str(&regex::escape(&rest[..end]));
                    let consumed = offset + 2 + end + usize::from(end < rest.len()) * 2;
                    while chars.peek().is_some_and(|(index, _)| *index < consumed) {
                        chars.next();
                    }
                } else {
                    normalized.push(ch);
                    normalized.push(escaped);
                    // Do not treat Unicode property/hex braces as counted repetitions.
                    if matches!(escaped, 'p' | 'P' | 'x')
                        && chars.peek().is_some_and(|(_, ch)| *ch == '{')
                    {
                        for (_, ch) in chars.by_ref() {
                            normalized.push(ch);
                            if ch == '}' {
                                break;
                            }
                        }
                    }
                }
                class_content = true;
            }
            '[' if !in_class => {
                in_class = true;
                class_content = false;
                class_negated = false;
                normalized.push(ch);
            }
            '[' if chars.peek().is_some_and(|(_, ch)| *ch == ':') => {
                // POSIX classes contain their own closing bracket.
                normalized.push(ch);
                for (_, ch) in chars.by_ref() {
                    normalized.push(ch);
                    if ch == ']' {
                        break;
                    }
                }
                class_content = true;
            }
            '[' => {
                // Go treats an unescaped opening bracket inside a class as a literal.
                normalized.push_str(r"\[");
                class_content = true;
            }
            ']' if in_class && !class_content => {
                normalized.push_str(r"\]");
                class_content = true;
            }
            ']' => {
                in_class = false;
                normalized.push(ch);
            }
            '^' if in_class && !class_content && !class_negated => {
                class_negated = true;
                normalized.push(ch);
            }
            '{' if !in_class => {
                let rest = &pattern[offset + 1..];
                if let Some(end) = rest.find('}') {
                    let count = &rest[..end];
                    let valid = count.split_once(',').map_or_else(
                        || !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()),
                        |(from, to)| {
                            !from.is_empty()
                                && from.bytes().all(|byte| byte.is_ascii_digit())
                                && to.bytes().all(|byte| byte.is_ascii_digit())
                        },
                    );
                    if valid {
                        normalized.push('{');
                        normalized.push_str(count);
                        normalized.push('}');
                        while chars.peek().is_some_and(|(index, _)| *index <= offset + end + 1) {
                            chars.next();
                        }
                        continue;
                    }
                }
                normalized.push_str(r"\{");
            }
            '}' if !in_class => normalized.push_str(r"\}"),
            _ => {
                normalized.push(ch);
                class_content = true;
            }
        }
    }
    if !for_rust && let Ok(mut ast) = AstParser::new().parse(&normalized) {
        // PCRE/Vectorscan's non-multiline $ also accepts a final newline. Go and
        // Rust require the actual end of input. Parsing avoids touching escaped,
        // quoted, or class dollars, and respects both scoped and standalone flags.
        if normalize_go_end_assertions(&mut ast, &mut false) {
            return ast.to_string();
        }
    }
    normalized
}

fn normalize_go_end_assertions(ast: &mut Ast, multiline: &mut bool) -> bool {
    match ast {
        Ast::Assertion(assertion) => {
            if assertion.kind == AssertionKind::EndLine && !*multiline {
                assertion.kind = AssertionKind::EndText;
                return true;
            }
            false
        }
        Ast::Flags(flags) => {
            *multiline = flags.flags.flag_state(AstFlag::MultiLine).unwrap_or(*multiline);
            false
        }
        Ast::Group(group) => {
            let mut scoped = group
                .flags()
                .and_then(|flags| flags.flag_state(AstFlag::MultiLine))
                .unwrap_or(*multiline);
            normalize_go_end_assertions(&mut group.ast, &mut scoped)
        }
        Ast::Repetition(repetition) => normalize_go_end_assertions(&mut repetition.ast, multiline),
        Ast::Concat(concat) => concat
            .asts
            .iter_mut()
            .fold(false, |changed, child| normalize_go_end_assertions(child, multiline) | changed),
        Ast::Alternation(alternation) => alternation
            .asts
            .iter_mut()
            .fold(false, |changed, child| normalize_go_end_assertions(child, multiline) | changed),
        _ => false,
    }
}

fn expression_name(expression: &BetterleaksExpr) -> Option<String> {
    match expression {
        BetterleaksExpr::Identifier { value } => Some(value.clone()),
        BetterleaksExpr::Member { node, property, .. } => {
            let parent = expression_name(node)?;
            let BetterleaksExpr::String { value } = property.as_ref() else {
                return None;
            };
            Some(format!("{parent}.{value}"))
        }
        _ => None,
    }
}

fn numeric_binary<'a>(
    left: Value<'a>,
    right: Value<'a>,
    operation: fn(f64, f64) -> f64,
) -> Result<Value<'a>> {
    if let (Value::Integer(left), Value::Integer(right)) = (&left, &right) {
        let value = operation(*left as f64, *right as f64);
        if value.fract() == 0.0 {
            return Ok(Value::Integer(value as i64));
        }
    }
    Ok(Value::Float(operation(left.as_f64()?, right.as_f64()?)))
}

fn values_equal<'a>(left: &Value<'a>, right: &Value<'a>) -> bool {
    match (left, right) {
        (Value::Integer(left), Value::Float(right)) => (*left as f64) == *right,
        (Value::Float(left), Value::Integer(right)) => *left == (*right as f64),
        _ => left == right,
    }
}

fn strings<'v>(value: &'v Value<'_>) -> Result<Vec<&'v str>> {
    let Value::Array(values) = value else {
        bail!("expected an array of strings");
    };
    values.iter().map(Value::as_string).collect()
}

fn contains_any<'a>(
    arguments: Vec<Value<'a>>,
    engine: &BetterleaksFilterEngine,
) -> Result<Value<'a>> {
    let [input, terms] = arguments.as_slice() else {
        bail!("containsAny expects two arguments");
    };
    // Validate complete mixed arrays before checking any element, as the original helper did.
    if !matches!(input, Value::String(_))
        && !matches!(input, Value::Array(values)
            if values.iter().all(|value| matches!(value, Value::String(_))))
    {
        return Ok(Value::Bool(false));
    }
    let Value::Array(terms) = terms else {
        return Ok(Value::Bool(false));
    };
    let matcher = engine.literal_arrays.contains_any.get(&(terms.as_ptr() as usize));
    let terms =
        if let Some(lowercase) = engine.literal_arrays.lowercase.get(&(terms.as_ptr() as usize)) {
            Cow::Borrowed(lowercase.as_slice())
        } else {
            let Ok(lowercase) = terms
                .iter()
                .map(|term| term.as_string().map(str::to_lowercase))
                .collect::<Result<Vec<_>>>()
            else {
                return Ok(Value::Bool(false));
            };
            Cow::Owned(lowercase)
        };
    let contains = |input: &str| {
        let input = input.to_lowercase();
        match matcher {
            Some(matcher) => matcher.is_match(&input),
            None => terms.iter().any(|term| input.contains(term)),
        }
    };
    Ok(Value::Bool(match input {
        Value::String(input) => contains(input),
        Value::Array(inputs) => inputs.iter().any(|input| contains(input.as_string().unwrap())),
        _ => unreachable!("input type was validated"),
    }))
}

fn strings_or_single<'v>(value: &'v Value<'_>) -> Option<Vec<&'v str>> {
    match value {
        Value::String(value) => Some(vec![value.as_ref()]),
        Value::Array(_) => strings(value).ok(),
        _ => None,
    }
}

fn string_set_helper<'a>(arguments: Vec<Value<'a>>, name: &str) -> Result<Value<'a>> {
    let [input, terms] = arguments.as_slice() else {
        bail!("{name} expects two arguments");
    };
    let Some(input) = strings_or_single(input) else {
        return Ok(Value::Bool(false));
    };
    let Ok(terms) = strings(terms) else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(input.iter().any(|input| {
        terms
            .iter()
            .any(|term| if name == "intersects" { input == term } else { input.starts_with(term) })
    })))
}

fn entropy<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input] = arguments.as_slice() else {
        bail!("entropy expects one argument");
    };
    let bytes = input.as_string()?.as_bytes();
    if bytes.is_empty() {
        return Ok(Value::Float(0.0));
    }
    let mut frequencies = [0_usize; 256];
    for byte in bytes {
        frequencies[usize::from(*byte)] += 1;
    }
    let length = bytes.len() as f64;
    let entropy = frequencies
        .into_iter()
        .filter(|frequency| *frequency > 0)
        .map(|frequency| {
            let probability = frequency as f64 / length;
            -probability * probability.log2()
        })
        .sum();
    Ok(Value::Float(entropy))
}

fn token_ratio<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input] = arguments.as_slice() else {
        bail!("tokenRatio expects one argument");
    };
    let input = input.as_string()?;
    Ok(Value::Float(token_efficiency_ratio(input)))
}

#[doc(hidden)]
pub fn token_efficiency_ratio(input: &str) -> f64 {
    let mut normalized = String::new();
    let analyzed = normalize_efficiency_input(input, &mut normalized);
    let tokens = cl100k_base_singleton().encode_ordinary(analyzed).len();
    if tokens == 0 { 0.0 } else { analyzed.len() as f64 / tokens as f64 }
}

fn fails_token_efficiency<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input] = arguments.as_slice() else {
        bail!("failsTokenEfficiency expects one argument");
    };
    let input = input.as_string()?;
    Ok(Value::Bool(fails_token_efficiency_value(input)))
}

#[doc(hidden)]
pub fn fails_token_efficiency_value(input: &str) -> bool {
    let mut normalized = String::new();
    let analyzed = normalize_efficiency_input(input, &mut normalized);
    if analyzed.is_empty() {
        return false;
    }
    // The cl100k pattern covers every Unicode scalar, and its vocabulary includes
    // all 256 single-byte tokens: a nonempty input cannot have zero tokens.
    // Avoid BPE for the same dictionary positives, without another dictionary scan.
    if contains_dictionary_word(analyzed, 5) {
        return true;
    }
    let tokens = cl100k_base_singleton().encode_ordinary(analyzed).len();
    if tokens == 0 {
        return false;
    }
    let threshold =
        if analyzed.len() < 12 && contains_dictionary_word(analyzed, 4) { 2.1 } else { 2.5 };
    analyzed.len() as f64 / tokens as f64 >= threshold
}

fn normalize_efficiency_input<'a>(input: &'a str, normalized: &'a mut String) -> &'a str {
    if input.len() < 20 && (input.contains('\n') || input.contains('\r')) {
        *normalized = input.replace(['\n', '\r'], "");
        normalized.as_str()
    } else {
        input
    }
}

static EFFICIENCY_WORDS: LazyLock<BTreeMap<usize, rustc_hash::FxHashSet<String>>> =
    LazyLock::new(|| {
        use std::io::Read;
        let mut words = String::new();
        flate2::read::GzDecoder::new(include_bytes!("../data/betterleaks-words.txt.gz").as_slice())
            .read_to_string(&mut words)
            .expect("bundled Betterleaks wordlist is valid gzip/UTF-8");
        let mut by_length: BTreeMap<usize, rustc_hash::FxHashSet<String>> = BTreeMap::new();
        for word in words.lines().filter(|word| !word.is_empty()) {
            by_length.entry(word.len()).or_default().insert(word.to_string());
        }
        by_length
    });

fn contains_dictionary_word(input: &str, minimum: usize) -> bool {
    let input = input.to_lowercase();
    if input.len() < minimum {
        return false;
    }
    EFFICIENCY_WORDS.range(minimum..=input.len()).any(|(&length, words)| {
        (0..=input.len() - length)
            .any(|start| input.get(start..start + length).is_some_and(|part| words.contains(part)))
    })
}

fn length<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [value] = arguments.as_slice() else {
        bail!("len/size expects one argument");
    };
    let length = match value {
        Value::String(value) => value.chars().count(),
        Value::Array(value) => value.len(),
        Value::Map(value) => value.len(),
        other => bail!("cannot take length of {other:?}"),
    };
    Ok(Value::Integer(length as i64))
}

fn min_or_max<'a>(arguments: Vec<Value<'a>>, maximum: bool) -> Result<Value<'a>> {
    let [left, right] = arguments.as_slice() else {
        bail!("min/max expects two arguments");
    };
    let value = if maximum {
        left.as_f64()?.max(right.as_f64()?)
    } else {
        left.as_f64()?.min(right.as_f64()?)
    };
    if matches!((left, right), (Value::Integer(_), Value::Integer(_))) {
        Ok(Value::Integer(value as i64))
    } else {
        Ok(Value::Float(value))
    }
}

fn split<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input, separator] = arguments.as_slice() else {
        bail!("split expects two arguments");
    };
    Ok(Value::Array(
        input
            .as_string()?
            .split(separator.as_string()?)
            .map(|value| Value::string(value.to_string()))
            .collect(),
    ))
}

fn join<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [values, separator] = arguments.as_slice() else {
        bail!("join expects two arguments");
    };
    Ok(Value::string(strings(values)?.join(separator.as_string()?)))
}

fn substring<'a>(receiver: Value<'a>, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let input = receiver.as_string()?;
    let start = arguments.first().ok_or_else(|| anyhow!("substring expects a start index"))?;
    let start = usize::try_from(start.as_i64()?.max(0)).unwrap_or(usize::MAX).min(input.len());
    let end = arguments
        .get(1)
        .map(Value::as_i64)
        .transpose()?
        .and_then(|length| usize::try_from(length.max(0)).ok())
        .map(|length| start.saturating_add(length).min(input.len()))
        .unwrap_or(input.len());
    Ok(Value::string(String::from_utf8_lossy(&input.as_bytes()[start..end]).into_owned()))
}

fn last_index_of<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input, needle] = arguments.as_slice() else {
        bail!("lastIndexOf expects two arguments");
    };
    Ok(Value::Integer(
        input
            .as_string()?
            .rfind(needle.as_string()?)
            .and_then(|index| i64::try_from(index).ok())
            .unwrap_or(-1),
    ))
}

fn replace<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input, from, to, rest @ ..] = arguments.as_slice() else {
        bail!("replace expects three or four arguments");
    };
    if rest.len() > 1 {
        bail!("replace expects three or four arguments");
    }
    let output = if let Some(limit) = rest.first() {
        let limit = limit.as_i64()?;
        if limit < 0 {
            input.as_string()?.replace(from.as_string()?, to.as_string()?)
        } else {
            input.as_string()?.replacen(from.as_string()?, to.as_string()?, limit as usize)
        }
    } else {
        input.as_string()?.replace(from.as_string()?, to.as_string()?)
    };
    Ok(Value::string(output))
}

fn value_to_json(value: &Value<'_>) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Bool(value) => (*value).into(),
        Value::Integer(value) => (*value).into(),
        Value::Float(value) => serde_json::Number::from_f64(*value)
            .map_or(serde_json::Value::Null, serde_json::Value::Number),
        Value::String(value) => value.as_ref().into(),
        Value::Array(values) => values.iter().map(value_to_json).collect(),
        Value::Map(values) => {
            values.iter().map(|(key, value)| (key.to_string(), value_to_json(value))).collect()
        }
    }
}

fn value_from_json<'a>(value: serde_json::Value) -> Value<'a> {
    match value {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(value) => Value::Bool(value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(Value::Integer)
            .unwrap_or_else(|| Value::Float(value.as_f64().unwrap_or_default())),
        serde_json::Value::String(value) => Value::string(value),
        serde_json::Value::Array(values) => {
            Value::Array(values.into_iter().map(value_from_json).collect())
        }
        serde_json::Value::Object(values) => Value::map(
            values.into_iter().map(|(key, value)| (key.into(), value_from_json(value))).collect(),
        ),
    }
}

/// Expr uses Go's base64.StdEncoding: standard alphabet, required padding, CR/LF ignored,
/// and nonzero unused trailing bits accepted. Unlike Go byte strings, filter strings must be
/// UTF-8, so non-text decoded data is an explicit error rather than a lossy conversion.
fn from_base64<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    const DECODER: GeneralPurpose = GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let [input] = arguments.as_slice() else {
        bail!("fromBase64 expects one argument");
    };
    let input = input.as_string()?;
    // Decoding shrinks its input; bound it before allocating the CR/LF-normalized copy.
    if input.len() > MAX_EXPRESSION_STRING_BYTES {
        bail!("fromBase64 exceeds expression size limit");
    }
    let normalized: Cow<'_, [u8]> = if input.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        Cow::Owned(input.bytes().filter(|byte| !matches!(byte, b'\r' | b'\n')).collect())
    } else {
        Cow::Borrowed(input.as_bytes())
    };
    let decoded = DECODER.decode(normalized.as_ref()).context("invalid base64 in fromBase64")?;
    Ok(Value::string(
        String::from_utf8(decoded).context("fromBase64 decoded data is not valid UTF-8")?,
    ))
}

fn simple_builtin<'a>(name: &str, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let input = arguments.first().ok_or_else(|| anyhow!("{name} expects an argument"))?;
    let text = || input.as_string();
    let parameter =
        |index: usize| arguments.get(index).ok_or_else(|| anyhow!("missing argument to {name}"));
    match name {
        "type" => Ok(Value::string(match input {
            Value::Nil => "nil",
            Value::Bool(_) => "bool",
            Value::Integer(_) => "int",
            Value::Float(_) => "float",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Map(_) => "map",
        })),
        "string" => Ok(Value::string(match input {
            Value::String(value) => value.to_string(),
            _ => value_to_json(input).to_string(),
        })),
        "int" => Ok(Value::Integer(match input {
            Value::String(value) => value.parse()?,
            _ => input.as_i64()?,
        })),
        "float" => Ok(Value::Float(match input {
            Value::String(value) => value.parse()?,
            _ => input.as_f64()?,
        })),
        "trim" => Ok(Value::string(if let Some(characters) = arguments.get(1) {
            text()?
                .trim_matches(|ch| {
                    characters.as_string().is_ok_and(|characters| characters.contains(ch))
                })
                .to_string()
        } else {
            text()?.trim().to_string()
        })),
        "trimPrefix" => {
            let text = text()?;
            Ok(Value::string(
                text.strip_prefix(parameter(1)?.as_string()?).unwrap_or(text).to_string(),
            ))
        }
        "trimSuffix" => {
            let text = text()?;
            Ok(Value::string(
                text.strip_suffix(parameter(1)?.as_string()?).unwrap_or(text).to_string(),
            ))
        }
        "repeat" => {
            let count = usize::try_from(parameter(1)?.as_i64()?)?;
            if text()?.len().saturating_mul(count) > MAX_EXPRESSION_STRING_BYTES {
                bail!("repeat exceeds expression size limit");
            }
            Ok(Value::string(text()?.repeat(count)))
        }
        "indexOf" => {
            Ok(Value::Integer(text()?.find(parameter(1)?.as_string()?).map_or(-1, |index| {
                text().map(|text| text[..index].chars().count() as i64).unwrap_or(-1)
            })))
        }
        "hasPrefix" => Ok(Value::Bool(text()?.starts_with(parameter(1)?.as_string()?))),
        "hasSuffix" => Ok(Value::Bool(text()?.ends_with(parameter(1)?.as_string()?))),
        "keys" | "values" => {
            let Value::Map(values) = input else {
                bail!("{name} requires a map");
            };
            Ok(Value::Array(if name == "keys" {
                values.keys().cloned().map(Value::string).collect()
            } else {
                values.values().cloned().collect()
            }))
        }
        "get" => match input {
            Value::Map(values) => {
                Ok(values.get(parameter(1)?.as_string()?).cloned().unwrap_or(Value::Nil))
            }
            Value::Array(values) => {
                let index = parameter(1)?.as_i64()?;
                let index = if index < 0 { values.len() as i64 + index } else { index };
                Ok(usize::try_from(index)
                    .ok()
                    .and_then(|index| values.get(index))
                    .cloned()
                    .unwrap_or(Value::Nil))
            }
            _ => Ok(Value::Nil),
        },
        "abs" | "ceil" | "floor" | "round" => {
            let value = input.as_f64()?;
            Ok(Value::Float(match name {
                "abs" => value.abs(),
                "ceil" => value.ceil(),
                "floor" => value.floor(),
                _ => value.round(),
            }))
        }
        "toJSON" => Ok(Value::string(serde_json::to_string(&value_to_json(input))?)),
        "fromJSON" => Ok(value_from_json(serde_json::from_str(text()?)?)),
        _ => {
            let Value::Array(values) = input else {
                bail!("{name} expects an array");
            };
            match name {
                "first" => Ok(values.first().cloned().unwrap_or(Value::Nil)),
                "last" => Ok(values.last().cloned().unwrap_or(Value::Nil)),
                "reverse" => Ok(Value::Array(values.iter().rev().cloned().collect())),
                "concat" => {
                    let mut values = values.to_vec();
                    for argument in &arguments[1..] {
                        let Value::Array(extra) = argument else {
                            bail!("concat expects arrays");
                        };
                        values.extend(extra.iter().cloned());
                    }
                    Ok(Value::array(values))
                }
                "flatten" => {
                    fn flatten<'a>(value: Value<'a>, out: &mut Vec<Value<'a>>) {
                        if let Value::Array(values) = value {
                            for value in values.iter() {
                                flatten(value.clone(), out);
                            }
                        } else {
                            out.push(value);
                        }
                    }
                    let mut out = Vec::new();
                    for value in values.iter() {
                        flatten(value.clone(), &mut out);
                    }
                    Ok(Value::array(out))
                }
                "uniq" => {
                    let mut out = Vec::new();
                    for value in values.iter() {
                        if !out.iter().any(|seen| values_equal(seen, value)) {
                            out.push(value.clone());
                        }
                    }
                    Ok(Value::array(out))
                }
                "sort" => {
                    let mut values = values.to_vec();
                    values.sort_by(|left, right| match (left, right) {
                        (Value::String(left), Value::String(right)) => left.cmp(right),
                        _ => left
                            .as_f64()
                            .unwrap_or_default()
                            .total_cmp(&right.as_f64().unwrap_or_default()),
                    });
                    if arguments
                        .get(1)
                        .is_some_and(|value| value.as_string().is_ok_and(|value| value == "desc"))
                    {
                        values.reverse();
                    }
                    Ok(Value::array(values))
                }
                "sum" | "mean" => {
                    let sum = values
                        .iter()
                        .map(Value::as_f64)
                        .collect::<Result<Vec<_>>>()?
                        .iter()
                        .sum::<f64>();
                    Ok(Value::Float(if name == "mean" && !values.is_empty() {
                        sum / values.len() as f64
                    } else {
                        sum
                    }))
                }
                _ => bail!("unsupported filter builtin {name:?}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(source: &str) -> BetterleaksExpr {
        serde_json::from_value(crate::betterleaks::parse_custom_expression(source).unwrap())
            .unwrap()
    }

    fn evaluator_for_test<'a>(
        engine: &'a BetterleaksFilterEngine,
        fragment: &'a BetterleaksFilterFragment<'a>,
    ) -> Evaluator<'a, 'a> {
        Evaluator {
            variables: BTreeMap::new(),
            filter_engine: engine,
            source_line: fragment.raw,
            line_range: 0..fragment.raw.len(),
            line_cache: None,
            fragment,
        }
    }

    fn rule_with_filter(source: &str) -> Arc<Rule> {
        let mut syntax = crate::RuleSyntax::new("custom.literal-array", "Literal array", "token");
        syntax.betterleaks_filter = Some(parse(source));
        Arc::new(Rule::new(syntax))
    }

    fn array_nodes(expression: &BetterleaksExpr) -> &[BetterleaksExpr] {
        let BetterleaksExpr::Array { nodes } = expression else { panic!("expected array") };
        nodes
    }

    fn evaluate_secret_prefix_for_test(
        engine: &BetterleaksFilterEngine,
        expression: &BetterleaksExpr,
        context: &BetterleaksFilterContext<'_>,
    ) -> Result<BetterleaksFilterOutcome> {
        match engine.evaluate_prefix(expression, context.secret)? {
            Some(BetterleaksFilterPrefix::Complete(outcome)) => Ok(outcome),
            Some(BetterleaksFilterPrefix::Remainder(remainder)) => {
                evaluate_filter_with_engine(remainder, context, engine)
            }
            None => evaluate_filter_with_engine(expression, context, engine),
        }
    }

    #[test]
    fn secret_prefix_matches_full_outcomes_and_keeps_confidence_inert() {
        let rule = rule_with_filter(
            r#"
            (matchesAny(finding.secret, ["^$", "^placeholder$"])
                || containsAny(finding.secret, ["école"])) ||
            ((entropy(finding.secret) <= 3.5 || failsTokenEfficiency(finding.secret)) ||
                (setConfidence("high") == "high" && finding.line == "deny"))
            "#,
        );
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        for secret in
            ["", "placeholder", "ÉCOLE", "aaaa", "X9qB2mK7pR4zT8", "linkedinX9qB2mK7pR4zT8", "�"]
        {
            for line in ["deny", "allow"] {
                let mut context = context(secret, "source.rs");
                context.line = line;
                context.fragment_raw = line;
                let full = evaluate_filter_with_engine(expression, &context, &engine).unwrap();
                let staged =
                    evaluate_secret_prefix_for_test(&engine, expression, &context).unwrap();
                assert_eq!(full, staged, "{secret:?} {line:?}");
                assert_eq!(staged.confidence, None);
                if secret == "X9qB2mK7pR4zT8" && line == "allow" {
                    assert!(!staged.discard);
                }
            }
        }
    }

    #[test]
    fn secret_prefix_preserves_short_circuit_and_helper_errors() {
        let rule = rule_with_filter(r#"matchesAny(finding.secret, ["^hit$"]) || (1 / 0 == 0)"#);
        let mut engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        for secret in ["hit", "miss"] {
            let context = context(secret, "source.rs");
            let full = evaluate_filter_with_engine(expression, &context, &engine);
            let staged = evaluate_secret_prefix_for_test(&engine, expression, &context);
            assert_eq!(
                full.map_err(|error| error.to_string()),
                staged.map_err(|error| error.to_string())
            );
        }
        // Fault-inject a fallible compiled helper without changing its retained AST or plan.
        engine.matches_any = None;
        let full = evaluate_filter_with_engine(expression, &context("hit", "source.rs"), &engine)
            .unwrap_err();
        let prefix = engine.evaluate_prefix(expression, "hit").unwrap_err();
        assert_eq!(full.to_string(), prefix.to_string());
        assert!(prefix.to_string().contains("matchesAny patterns were not compiled"));
        let invalid = rule_with_filter(r#"matchesAny(finding.secret, ["("]) || true"#);
        assert!(BetterleaksFilterEngine::compile_for_rules(&[invalid]).is_err());
    }

    #[test]
    fn secret_prefix_retains_roots_and_rejects_cloned_mutated_or_borrowed_asts() {
        let mut external = rule_with_filter(r#"containsAny(finding.secret, ["needle"]) || false"#);
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&external)).unwrap();
        assert!(Arc::get_mut(&mut external).is_none());
        let mut borrowed = external.betterleaks_filter().unwrap().clone();
        assert!(engine.evaluate_prefix(&borrowed, "needle").unwrap().is_none());
        let borrowed_engine = BetterleaksFilterEngine::compile([&borrowed]).unwrap();
        assert!(borrowed_engine.evaluate_prefix(&borrowed, "needle").unwrap().is_none());
        let identity = std::ptr::from_ref(&borrowed) as usize;
        let BetterleaksExpr::Binary { left, .. } = &mut borrowed else { unreachable!() };
        **left = parse(r#"containsAny(finding.line, ["needle"])"#);
        assert_eq!(std::ptr::from_ref(&borrowed) as usize, identity);
        assert!(borrowed_engine.evaluate_prefix(&borrowed, "needle").unwrap().is_none());
        Arc::make_mut(&mut external).syntax.betterleaks_filter = Some(borrowed);
        assert!(
            engine
                .evaluate_prefix(external.betterleaks_filter().unwrap(), "needle")
                .unwrap()
                .is_none()
        );
        let original = engine._retained_rules[0].betterleaks_filter().unwrap();
        assert!(matches!(
            engine.evaluate_prefix(original, "needle").unwrap(),
            Some(BetterleaksFilterPrefix::Complete(BetterleaksFilterOutcome { discard: true, .. }))
        ));
    }

    #[test]
    fn secret_prefix_proof_budget_is_conservative() {
        let mut expression = BetterleaksExpr::Bool { value: false };
        for _ in 0..255 {
            expression =
                BetterleaksExpr::Unary { operator: "!".into(), node: Box::new(expression) };
        }
        assert!(secret_prefix_is_safe(&expression));
        expression = BetterleaksExpr::Unary { operator: "not".into(), node: Box::new(expression) };
        assert!(!secret_prefix_is_safe(&expression));
    }

    #[test]
    fn secret_prefix_unknown_or_context_dependent_leading_forms_fall_back() {
        for source in [
            r#"lower(finding.secret) == "needle" || true"#,
            r#"unknownHelper(finding.secret) || true"#,
            r#"setConfidence("high") || false"#,
            r#"let s = finding.secret; containsAny(s, ["needle"]) || true"#,
            r#"containsAny(finding.line, ["needle"]) || true"#,
            r#"containsAny(finding?.secret, ["needle"]) || true"#,
            r#"containsAny(finding.secret, ["needle", 1]) || true"#,
            r#"containsAny(finding.secret, [lower("NEEDLE")]) || true"#,
            r#"containsAny(finding.secret) || true"#,
            r#"finding.secret.contains("needle") || true"#,
            r#"other.containsAny(finding.secret, ["needle"]) || true"#,
            r#"filter["filter.containsAny"](finding.secret, ["needle"]) || true"#,
            r#"entropy(finding.secret) < 3.5 || true"#,
            r#"entropy(finding.secret) || true"#,
            r#"true && containsAny(finding.secret, ["needle"])"#,
        ] {
            let rule = rule_with_filter(source);
            let engine =
                BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
            let expression = rule.betterleaks_filter().unwrap();
            assert!(engine.evaluate_prefix(expression, "needle").unwrap().is_none(), "{source}");
            let context = context("needle", "source.rs");
            assert_eq!(
                evaluate_filter_with_engine(expression, &context, &engine)
                    .map_err(|error| error.to_string()),
                evaluate_secret_prefix_for_test(&engine, expression, &context)
                    .map_err(|error| error.to_string()),
                "{source}"
            );
        }
        for number in ["NaN", "inf", "not-a-number"] {
            let mut rule = rule_with_filter("entropy(finding.secret) <= 3.5 || true");
            let expression =
                Arc::get_mut(&mut rule).unwrap().syntax.betterleaks_filter.as_mut().unwrap();
            let BetterleaksExpr::Binary { left, .. } = expression else { unreachable!() };
            let BetterleaksExpr::Binary { right, .. } = left.as_mut() else { unreachable!() };
            **right = BetterleaksExpr::Float { value: number.into() };
            let engine =
                BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
            assert!(
                engine
                    .evaluate_prefix(rule.betterleaks_filter().unwrap(), "needle")
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn secret_prefix_namespace_and_boolean_composition_use_existing_dispatch() {
        for source in [
            r#"filter.containsAny(finding.secret, ["needle"]) || false"#,
            r#"filter.matchesAny(finding.secret, ["^needle$"]) || false"#,
            r#"filter.entropy(finding.secret) <= 3.5 || false"#,
            r#"filter.failsTokenEfficiency(finding.secret) || false"#,
            r#"not (false and matchesAny(finding.secret, [])) or finding.line == "allow""#,
        ] {
            let rule = rule_with_filter(source);
            let engine =
                BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
            let expression = rule.betterleaks_filter().unwrap();
            assert!(engine.evaluate_prefix(expression, "needle").unwrap().is_some());
            let context = context("needle", "source.rs");
            assert_eq!(
                evaluate_filter_with_engine(expression, &context, &engine).unwrap(),
                evaluate_secret_prefix_for_test(&engine, expression, &context).unwrap()
            );
        }
    }

    #[test]
    fn secret_prefix_generic_has_two_steps_and_bpe_rejects_before_context() {
        let rules = crate::get_builtin_rules(Some(Confidence::Low)).unwrap();
        let rule = Arc::new(Rule::new(rules.rules["betterleaks.generic-api-key"].clone()));
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        assert_eq!(
            engine.secret_prefix_steps.get(&(std::ptr::from_ref(expression) as usize)),
            Some(&2)
        );
        assert_eq!(rule.confidence(), Confidence::Low);
        let source_context: OnceLock<BetterleaksFilterFragment<'_>> = OnceLock::new();
        let secret = "linkedinX9qB2mK7pR4zT8";
        assert!(entropy(vec![Value::string(secret)]).unwrap().as_f64().unwrap() > 3.5);
        assert!(fails_token_efficiency_value(secret));
        assert!(matches!(
            engine.evaluate_prefix(expression, secret).unwrap(),
            Some(BetterleaksFilterPrefix::Complete(BetterleaksFilterOutcome {
                discard: true,
                confidence: None,
            }))
        ));
        assert!(source_context.get().is_none());
        let BetterleaksExpr::Binary { left, right, .. } = expression else { unreachable!() };
        let fragment = BetterleaksFilterFragment::new("");
        let mut first_step = evaluator_for_test(&engine, &fragment);
        first_step.variables.insert(
            "finding",
            Value::map(BTreeMap::from([("secret".into(), Value::string(secret))])),
        );
        assert!(!first_step.eval(left).unwrap().truthy());
        let BetterleaksExpr::Binary { right, .. } = right.as_ref() else { unreachable!() };
        assert!(matches!(right.as_ref(), BetterleaksExpr::VariableDeclarator { .. }));
        let Some(BetterleaksFilterPrefix::Remainder(remainder)) =
            engine.evaluate_prefix(expression, "X9qB2mK7pR4zT8").unwrap()
        else {
            panic!("random candidate must retain the entire context-dependent continuation");
        };
        assert!(std::ptr::eq(remainder, right.as_ref()));
        let context = context("X9qB2mK7pR4zT8", "source.rs");
        assert_eq!(
            evaluate_filter_with_engine(expression, &context, &engine).unwrap(),
            evaluate_filter_with_engine(remainder, &context, &engine).unwrap()
        );
    }

    #[test]
    fn secret_prefix_never_poisons_source_caches_or_repeats_prefix_helpers() {
        use std::sync::atomic::Ordering;

        let rule = rule_with_filter(
            r#"!matchesAny(finding.secret, ["needle"]) ||
                (matchesAny(finding.line, ["other"]) && finding.fragment_raw[0:2] == "é😊")"#,
        );
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        let raw = "é😊other";
        let mut context = context("needle", "source.rs");
        context.line = &raw[6..];
        context.fragment_raw = raw;
        let full = evaluate_filter_with_engine(expression, &context, &engine).unwrap();
        let native = engine.matches_any.as_ref().unwrap();
        native.callbacks.store(0, Ordering::Relaxed);
        let mut cache = BetterleaksFilterLineCache::default();
        let source_context: OnceLock<BetterleaksFilterFragment<'_>> = OnceLock::new();
        let Some(BetterleaksFilterPrefix::Remainder(remainder)) =
            engine.evaluate_prefix(expression, context.secret).unwrap()
        else {
            panic!("matching secret must continue with the original source-dependent expression");
        };
        assert!(source_context.get().is_none());
        assert_eq!(cache.entries, 0);
        assert_eq!(cache.scans, 0);
        let fragment = source_context.get_or_init(|| BetterleaksFilterFragment::new(raw));
        assert!(fragment.index.get().is_none());
        let staged = evaluate_filter_with_engine_and_fragment(
            remainder,
            &context,
            &engine,
            6..raw.len(),
            Some(&mut cache),
            fragment,
        )
        .unwrap();
        assert_eq!(staged, full);
        assert!(staged.discard);
        assert_eq!(fragment.raw, raw);
        assert!(fragment.index.get().is_some());
        assert_eq!(cache.entries, 1);
        assert_eq!(cache.scans, 1);
        assert_eq!(native.callbacks.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn secret_prefix_remainder_preserves_trusted_arrays_and_cached_outcomes() {
        let rule = rule_with_filter(
            r#"containsAny(finding.secret, ["needle"]) || matchesAny(finding.line, ["^other$"])"#,
        );
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&rule)).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        let Some(BetterleaksFilterPrefix::Remainder(remainder)) =
            engine.evaluate_prefix(expression, "miss").unwrap()
        else {
            panic!("nonmatching secret must retain the original line helper");
        };
        let BetterleaksExpr::Call { arguments, .. } = remainder else { unreachable!() };
        let nodes = array_nodes(&arguments[1]);
        let identity = nodes.as_ptr() as usize;
        assert!(engine.literal_arrays.trusted.contains(&identity));
        let prepared = engine.literal_arrays.get(nodes).unwrap();
        assert!(Arc::ptr_eq(prepared, &engine.literal_arrays.values[&identity]));
        assert!(
            !engine.secret_prefix_steps.contains_key(&(std::ptr::from_ref(remainder) as usize))
        );
        assert!(engine.evaluate_prefix(remainder, "miss").unwrap().is_none());
        let cloned = remainder.clone();
        let BetterleaksExpr::Call { arguments, .. } = &cloned else { unreachable!() };
        let cloned_nodes = array_nodes(&arguments[1]);
        assert!(!engine.literal_arrays.trusted.contains(&(cloned_nodes.as_ptr() as usize)));
        assert!(engine.literal_arrays.get(cloned_nodes).is_none());
        let source = "other";
        let mut context = context("miss", "source.rs");
        context.line = source;
        context.fragment_raw = source;
        let fragment = BetterleaksFilterFragment::new(source);
        let mut cache = BetterleaksFilterLineCache::default();
        let full = evaluate_filter_with_engine(expression, &context, &engine).unwrap();
        let staged = evaluate_filter_with_engine_and_fragment(
            remainder,
            &context,
            &engine,
            0..source.len(),
            Some(&mut cache),
            &fragment,
        )
        .unwrap();
        assert_eq!(full, staged);
        assert_eq!(full, evaluate_filter_with_engine(&cloned, &context, &engine).unwrap());
        assert_eq!(cache.entries, 1);
        assert_eq!(cache.scans, 1);
        assert!(Arc::ptr_eq(prepared, engine.literal_arrays.get(nodes).unwrap()));
    }

    #[test]
    fn secret_prefix_database_api_uses_its_existing_compiled_engine() {
        let mut syntax = crate::RuleSyntax::new("custom.prefix", "Prefix", "token");
        syntax.betterleaks_filter =
            Some(parse(r#"matchesAny(finding.secret, ["needle"]) || finding.line == "allow""#));
        let database = crate::RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap();
        let rule = database.get_rule(0).unwrap();
        let expression = rule.betterleaks_filter().unwrap();
        assert!(matches!(
            database.evaluate_betterleaks_filter_prefix(expression, "needle").unwrap(),
            Some(BetterleaksFilterPrefix::Complete(BetterleaksFilterOutcome { discard: true, .. }))
        ));
        let Some(BetterleaksFilterPrefix::Remainder(remainder)) =
            database.evaluate_betterleaks_filter_prefix(expression, "miss").unwrap()
        else {
            panic!("nonmatching candidate must continue");
        };
        let context = context("miss", "source.rs");
        assert_eq!(
            database.evaluate_betterleaks_filter(expression, &context).unwrap(),
            database.evaluate_betterleaks_filter(remainder, &context).unwrap()
        );
        assert!(
            database
                .evaluate_betterleaks_filter_prefix(&expression.clone(), "needle")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn trusted_literal_arrays_retain_exact_rule_roots_and_block_in_place_mutation() {
        let mut external = rule_with_filter(r#"["retained", "École"]"#);
        assert!(Arc::get_mut(&mut external).is_some());
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&external)).unwrap();
        assert_eq!(Arc::strong_count(&external), 2);
        assert!(Arc::get_mut(&mut external).is_none());
        let original_identity =
            array_nodes(external.betterleaks_filter().unwrap()).as_ptr() as usize;
        assert!(engine.literal_arrays.trusted.contains(&original_identity));
        let weak = Arc::downgrade(&external);
        drop(external);

        {
            let retained = weak.upgrade().expect("engine must keep the original rule alive");
            let expression = retained.betterleaks_filter().unwrap();
            let nodes = array_nodes(expression);
            assert_eq!(nodes.as_ptr() as usize, original_identity);
            let cached = engine.literal_arrays.get(nodes).unwrap();
            let fragment = BetterleaksFilterFragment::new("");
            let mut evaluator = evaluator_for_test(&engine, &fragment);
            let Value::Array(evaluated) = evaluator.eval(expression).unwrap() else {
                unreachable!()
            };
            assert!(Arc::ptr_eq(cached, &evaluated));
            assert_eq!(evaluated[0].as_string().unwrap(), "retained");
            assert_eq!(evaluated[1].as_string().unwrap(), "École");
        }
        drop(engine);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn trusted_literal_arrays_preserve_make_mut_and_cloned_ast_fallback() {
        let mut external = rule_with_filter(r#"["retained"]"#);
        let engine =
            BetterleaksFilterEngine::compile_for_rules(std::slice::from_ref(&external)).unwrap();
        let unmodified = external.betterleaks_filter().unwrap().clone();
        let mut cloned = unmodified.clone();
        let BetterleaksExpr::Array { nodes } = &mut cloned else { unreachable!() };
        nodes[0] = BetterleaksExpr::String { value: "cloned".into() };
        let BetterleaksExpr::Array { nodes } =
            Arc::make_mut(&mut external).syntax.betterleaks_filter.as_mut().unwrap()
        else {
            unreachable!()
        };
        nodes[0] = BetterleaksExpr::String { value: "make_mut".into() };
        assert!(Arc::get_mut(&mut external).is_some());
        let retained = engine._retained_rules[0].betterleaks_filter().unwrap();
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = evaluator_for_test(&engine, &fragment);
        for (expression, expected) in [
            (&unmodified, "retained"),
            (&cloned, "cloned"),
            (external.betterleaks_filter().unwrap(), "make_mut"),
        ] {
            let nodes = array_nodes(expression);
            assert_ne!(nodes.as_ptr(), array_nodes(retained).as_ptr());
            assert!(!engine.literal_arrays.trusted.contains(&(nodes.as_ptr() as usize)));
            assert!(engine.literal_arrays.get(nodes).is_none());
            let Value::Array(values) = evaluator.eval(expression).unwrap() else { unreachable!() };
            assert_eq!(values[0].as_string().unwrap(), expected);
        }
        let Value::Array(values) = evaluator.eval(retained).unwrap() else { unreachable!() };
        assert_eq!(values[0].as_string().unwrap(), "retained");
    }

    #[test]
    fn trusted_literal_arrays_do_not_trust_wrong_entries_for_arbitrary_asts() {
        let roots = [rule_with_filter(r#"["retained"]"#)];
        let mut engine = BetterleaksFilterEngine::compile_for_rules(&roots).unwrap();
        let original = array_nodes(roots[0].betterleaks_filter().unwrap());
        let wrong_values = Arc::clone(engine.literal_arrays.get(original).unwrap());
        let other = parse(r#"["other"]"#);
        let other_nodes = array_nodes(&other);
        let other_identity = other_nodes.as_ptr() as usize;
        engine.literal_arrays.values.insert(other_identity, wrong_values);
        assert!(!engine.literal_arrays.trusted.contains(&other_identity));
        assert!(engine.literal_arrays.get(other_nodes).is_none());
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = evaluator_for_test(&engine, &fragment);
        let Value::Array(values) = evaluator.eval(&other).unwrap() else { unreachable!() };
        assert_eq!(values[0].as_string().unwrap(), "other");
    }

    #[test]
    fn borrowed_literal_arrays_check_in_place_ast_mutation() {
        let mut expression = parse(r#"["original"]"#);
        let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
        assert!(engine.literal_arrays.trusted.is_empty());
        assert!(engine._retained_rules.is_empty());
        let original_identity = array_nodes(&expression).as_ptr();
        let BetterleaksExpr::Array { nodes } = &mut expression else { unreachable!() };
        nodes[0] = BetterleaksExpr::String { value: "changed".into() };
        assert_eq!(array_nodes(&expression).as_ptr(), original_identity);
        assert!(engine.literal_arrays.get(array_nodes(&expression)).is_none());
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = evaluator_for_test(&engine, &fragment);
        let Value::Array(values) = evaluator.eval(&expression).unwrap() else { unreachable!() };
        assert_eq!(values[0].as_string().unwrap(), "changed");
    }

    #[test]
    fn trusted_literal_arrays_keep_length_checks_and_empty_and_mixed_array_semantics() {
        let roots = [
            rule_with_filter(r#"["one", "two"]"#),
            rule_with_filter("[]"),
            rule_with_filter(r#"["literal", 42]"#),
        ];
        let engine = BetterleaksFilterEngine::compile_for_rules(&roots).unwrap();
        let nodes = array_nodes(roots[0].betterleaks_filter().unwrap());
        assert!(engine.literal_arrays.get(nodes).is_some());
        assert!(engine.literal_arrays.get(&nodes[..1]).is_none());
        assert!(engine.literal_arrays.get(&nodes[..0]).is_none());
        let empty = roots[1].betterleaks_filter().unwrap();
        assert!(engine.literal_arrays.get(array_nodes(empty)).unwrap().is_empty());
        let mixed = roots[2].betterleaks_filter().unwrap();
        let mixed_nodes = array_nodes(mixed);
        assert!(!engine.literal_arrays.trusted.contains(&(mixed_nodes.as_ptr() as usize)));
        assert!(engine.literal_arrays.get(mixed_nodes).is_none());
        let external_empty = parse("[]");
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = evaluator_for_test(&engine, &fragment);
        for expression in [empty, &external_empty] {
            let Value::Array(values) = evaluator.eval(expression).unwrap() else { unreachable!() };
            assert!(values.is_empty());
        }
        assert_eq!(
            evaluator.eval(mixed).unwrap(),
            Value::array(vec![Value::string("literal"), Value::Integer(42)])
        );
    }

    #[test]
    fn literal_strings_arrays_and_member_maps_share_immutable_storage() {
        let scalar = BetterleaksExpr::String { value: "Borrowed literal".into() };
        let array = parse(r#"["ABC", "É", "Straße"]"#);
        let engine = BetterleaksFilterEngine::compile([&scalar, &array, &array]).unwrap();
        assert_eq!(engine.literal_arrays.lowercase.len(), 1);
        let fragment = BetterleaksFilterFragment::new("");
        let mut evaluator = evaluator_for_test(&engine, &fragment);
        let Value::String(Cow::Borrowed(value)) = evaluator.eval(&scalar).unwrap() else {
            panic!("scalar literal must borrow its AST string");
        };
        let BetterleaksExpr::String { value: source } = &scalar else { unreachable!() };
        assert_eq!(value.as_ptr(), source.as_ptr());
        let Value::Array(first) = evaluator.eval(&array).unwrap() else { unreachable!() };
        let Value::Array(second) = evaluator.eval(&array).unwrap() else { unreachable!() };
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            engine.literal_arrays.lowercase[&(first.as_ptr() as usize)],
            ["abc", "é", "straße"]
        );
        let finding = Value::map(BTreeMap::from([("secret".into(), Value::string("token"))]));
        let Value::Map(first) = &finding else { unreachable!() };
        let Value::Map(second) = finding.clone() else { unreachable!() };
        assert!(Arc::ptr_eq(first, &second));
        evaluator.variables.insert("finding", finding);
        let member = parse("finding.secret");
        assert!(matches!(evaluator.eval(&member).unwrap(), Value::String(Cow::Borrowed("token"))));

        // Caller-owned/cloned ASTs still evaluate normally; reused addresses cannot substitute
        // different literal contents just because their allocations happen to have the same key.
        let original = vec![BetterleaksExpr::String { value: "first".into() }];
        let other = vec![BetterleaksExpr::String { value: "other".into() }];
        let mut cache = LiteralArrays::default();
        cache.prepare(&original);
        cache.values.insert(other.as_ptr() as usize, Arc::clone(cache.get(&original).unwrap()));
        assert!(cache.get(&other).is_none());
    }

    #[test]
    fn contains_any_preserves_unicode_mixed_arrays_short_circuit_and_legacy_returns() {
        for source in [
            r#"containsAny("PréFIX École", ["ÉCOLE", "missing"])"#,
            r#"containsAny(["missing", "éCOLE"], ["École"])"#,
            r#"let terms = ["École"]; containsAny("ÉCOLE", terms)"#,
            r#"!containsAny("match", ["match", 42])"#,
            r#"!containsAny(["match", 42], ["match"])"#,
            r#"!containsAny("anything", []) && !containsAny([], ["anything"])"#,
            r#"containsAny("HIGH", ["missing", filter.setConfidence("high")])"#,
            r#"containsAny([setConfidence("low"), "other"], ["low"])"#,
            r#"true || containsAny("match", [fromBase64("!")])"#,
            r#"true || setConfidence()"#,
            r#"!(false && filter.setConfidence(42))"#,
        ] {
            let outcome = evaluate_filter(&parse(source), &context("token", "source.rs")).unwrap();
            assert!(outcome.discard, "{source}");
            assert_eq!(outcome.confidence, None, "{source}");
        }
        for source in [
            r#"containsAny("match", ["match", fromBase64("!")])"#,
            r#"containsAny("match", ["match", filter.setConfidence(42)])"#,
        ] {
            assert!(
                evaluate_filter(&parse(source), &context("token", "source.rs")).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn large_literal_contains_any_matches_linear_unicode_and_empty_term_semantics() {
        for helper in ["containsAny", "filter.containsAny"] {
            for include_empty in [false, true] {
                let mut terms: Vec<String> = (0..CONTAINS_ANY_AUTOMATON_MIN_TERMS + 7)
                    .map(|index| format!("absent-term-{index:03}"))
                    .collect();
                terms.extend(
                    ["ÉCOLE", "Straße", "İSTANBUL", "ΟΣ", "😊", "abc\0xyz", "ÉCOLE"]
                        .into_iter()
                        .map(str::to_owned),
                );
                if include_empty {
                    terms.push(String::new());
                }
                let expression = parse(&format!(
                    "{helper}(finding.secret, {})",
                    serde_json::to_string(&terms).unwrap()
                ));
                let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
                assert_eq!(engine.literal_arrays.contains_any.len(), 1);
                let fallback = BetterleaksFilterEngine::compile(std::iter::empty()).unwrap();
                let cloned = expression.clone();
                for input in [
                    "",
                    "unmatched",
                    "préfix École",
                    "Straße",
                    "STRASSE",
                    "İSTANBUL",
                    "istanbul",
                    "ΟΣ",
                    "ΟΣΑ",
                    "Σ",
                    "x😊y",
                    "abc\0xyz",
                ] {
                    let lowercase = input.to_lowercase();
                    let expected =
                        terms.iter().any(|term| lowercase.contains(&term.to_lowercase()));
                    let context = context(input, "source.rs");
                    let optimized =
                        evaluate_filter_with_engine(&expression, &context, &engine).unwrap();
                    assert_eq!(
                        optimized.discard, expected,
                        "{helper} {input:?}, empty term: {include_empty}"
                    );
                    assert_eq!(
                        optimized,
                        evaluate_filter_with_engine(&expression, &context, &fallback).unwrap()
                    );
                    // A separately owned AST must take the content-checked fallback, not borrow
                    // another allocation's prepared literal-array identity.
                    assert_eq!(
                        optimized,
                        evaluate_filter_with_engine(&cloned, &context, &engine).unwrap()
                    );
                }
                let BetterleaksExpr::Call { arguments, .. } = &expression else { unreachable!() };
                let BetterleaksExpr::Array { nodes } = &arguments[1] else { unreachable!() };
                let cached_terms =
                    Value::array(Arc::clone(engine.literal_arrays.get(nodes).unwrap()));
                for (input, expected) in [
                    (Value::array(Vec::new()), false),
                    (Value::array(vec![Value::string("missing"), Value::string("ÉCOLE")]), true),
                    (Value::array(vec![Value::string("ÉCOLE"), Value::Integer(42)]), false),
                ] {
                    assert_eq!(
                        contains_any(vec![input, cached_terms.clone()], &engine).unwrap(),
                        Value::Bool(expected)
                    );
                }
            }
        }
    }

    #[test]
    fn large_contains_any_dynamic_arrays_still_evaluate_every_element() {
        let mut terms: Vec<String> = (0..CONTAINS_ANY_AUTOMATON_MIN_TERMS)
            .map(|index| format!("absent-term-{index:03}"))
            .collect();
        terms.push("ÉCOLE".into());
        let terms = serde_json::to_string(&terms).unwrap();
        let prefix = terms.strip_suffix(']').unwrap();
        for source in [
            format!("let terms = {terms}; containsAny(\"ÉCOLE\", terms)"),
            format!("containsAny(\"ÉCOLE\", {prefix}, lower(\"ÉCOLE\")])"),
            format!("!containsAny(\"ÉCOLE\", {prefix}, 42])"),
        ] {
            let expression = parse(&source);
            let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
            assert!(engine.literal_arrays.contains_any.is_empty());
            assert!(
                evaluate_filter_with_engine(&expression, &context("token", "source.rs"), &engine)
                    .unwrap()
                    .discard,
                "{source}"
            );
        }
        for suffix in [r#"fromBase64("!")"#, "filter.setConfidence(42)"] {
            let source = format!("containsAny(\"ÉCOLE\", {prefix}, {suffix}])");
            let expression = parse(&source);
            let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
            assert!(engine.literal_arrays.contains_any.is_empty());
            assert!(
                evaluate_filter_with_engine(&expression, &context("token", "source.rs"), &engine)
                    .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn legacy_confidence_calls_only_return_their_string_argument() {
        for helper in ["setConfidence", "filter.setConfidence"] {
            for value in ["low", "medium", "high", "not-a-confidence", ""] {
                let source = format!("{helper}({value:?}) == {value:?}");
                let outcome =
                    evaluate_filter(&parse(&source), &context("token", "source.rs")).unwrap();
                assert_eq!(
                    outcome,
                    BetterleaksFilterOutcome { discard: true, confidence: None },
                    "{source}"
                );
            }
        }
        for source in
            ["setConfidence()", r#"setConfidence("low", "high")"#, "filter.setConfidence(42)"]
        {
            assert!(
                evaluate_filter(&parse(source), &context("token", "source.rs")).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn fragment_slices_reuse_ascii_metadata_and_borrow_tiny_results() {
        let raw = "x".repeat(2 * 1024 * 1024);
        let fragment = BetterleaksFilterFragment::new(&raw);
        let engine = BetterleaksFilterEngine::compile(std::iter::empty()).unwrap();
        let evaluator = evaluator_for_test(&engine, &fragment);
        assert!(fragment.index.get().is_none());
        for _ in 0..1000 {
            let result = evaluator.slice(Value::string(raw.as_str()), -3, -1).unwrap();
            let Value::String(Cow::Borrowed(result)) = result else {
                panic!("source slices must retain their borrow");
            };
            assert_eq!(result, "xx");
            assert_eq!(result.as_ptr(), raw[raw.len() - 3..].as_ptr());
        }
        let index = fragment.index.get().unwrap();
        assert_eq!(index.characters, raw.len());
        assert!(index.checkpoints.is_empty());
        // A derived string must neither reuse unrelated coordinates nor prepare a fresh source.
        let unused = BetterleaksFilterFragment::new(&raw);
        let evaluator = evaluator_for_test(&engine, &unused);
        assert_eq!(
            evaluator
                .slice(Value::string("é😊Z".to_string()), -2, -1)
                .unwrap()
                .as_string()
                .unwrap(),
            "😊"
        );
        assert!(unused.index.get().is_none());
    }

    #[test]
    fn unicode_sparse_slices_preserve_negative_clamped_and_nested_ranges() {
        let raw = format!("{}é😊Z", "abé😊".repeat(1024));
        let characters: Vec<_> = raw.chars().collect();
        let fragment = BetterleaksFilterFragment::new(&raw);
        let engine = BetterleaksFilterEngine::compile(std::iter::empty()).unwrap();
        let evaluator = evaluator_for_test(&engine, &fragment);
        let length = characters.len() as i64;
        for from in [-length - 1, -129, -3, -1, 0, 1, 127, 128, 129, length, length + 1] {
            for to in [-length - 1, -128, -2, 0, 2, 127, 128, 129, length, length + 1] {
                let clamp = |index: i64| if index < 0 { (length + index).max(0) } else { index.min(length) } as usize;
                let start = clamp(from);
                let end = clamp(to).max(start);
                let expected: String = characters[start..end].iter().collect();
                let result = evaluator.slice(Value::string(raw.as_str()), from, to).unwrap();
                assert_eq!(result.as_string().unwrap(), expected, "{from}..{to}");
            }
        }
        let index = fragment.index.get().unwrap();
        assert_eq!(index.characters, characters.len());
        assert_eq!(index.checkpoints.len(), characters.len().div_ceil(FRAGMENT_INDEX_STRIDE));
        // An empty UTF-8 string can safely originate at a non-boundary of another byte slice.
        assert!(!raw.is_char_boundary(3));
        #[allow(
            clippy::string_from_utf8_as_bytes,
            reason = "a str slice would panic at this deliberately non-character boundary"
        )]
        let empty = std::str::from_utf8(&raw.as_bytes()[3..3]).unwrap();
        assert!(fragment.character_range(empty).is_none());
        assert_eq!(evaluator.slice(Value::string(empty), 0, 0).unwrap().as_string().unwrap(), "");
        let tiny = &raw[raw.len() - "é😊Z".len()..];
        let nested = evaluator.slice(Value::string(tiny), 1, 2).unwrap();
        assert_eq!(nested.as_string().unwrap(), "😊");
        assert_eq!(nested.as_string().unwrap().as_ptr(), tiny["é".len()..].as_ptr());

        let raw = "Aé😊Z";
        let fragment = BetterleaksFilterFragment::new(raw);
        let mut context = context(&raw[1..7], "source.rs");
        context.fragment_raw = raw;
        context.line = raw;
        context.match_start_idx = 1;
        context.match_end_idx = 7;
        let expression = parse(
            r#"finding.fragment_raw[1:-1][-1:] == "😊" && finding.match_start_idx == 1 && finding.match_end_idx == 7"#,
        );
        let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
        assert!(
            evaluate_filter_with_engine_and_fragment(
                &expression,
                &context,
                &engine,
                0..raw.len(),
                None,
                &fragment
            )
            .unwrap()
            .discard
        );
    }

    #[test]
    fn helper_boolean_gates_bound_unrelated_callbacks_and_preserve_leftmost_matches() {
        let expressions = [
            parse(r#"matchesAny("", [`(?s).+`, `[\w.-]+`, `é+`, `needle[0-9]+`, `^$`])"#),
            parse(r#"findMatch("", `needle[0-9]+|key[0-9]+`)"#),
            parse(r#"findMatch("", `(?s).+`)"#),
            parse(r#"findMatch("", `(?s).*`)"#),
            parse(r#"findMatch("", `[\w.-]{0,50}$`)"#),
        ];
        let engine = BetterleaksFilterEngine::compile(&expressions).unwrap();
        let input = "xxé😊".repeat(4096);
        assert!(!engine.matches_any(&input, &["needle[0-9]+"]).unwrap());
        let database = engine.matches_any.as_ref().unwrap();
        let callbacks = database.callbacks.load(std::sync::atomic::Ordering::Relaxed);
        assert!(callbacks > 0 && callbacks <= database.pattern_ids.len(), "{callbacks}");
        assert_eq!(engine.find_match(&input, "needle[0-9]+|key[0-9]+").unwrap(), "");
        let database = engine.find_match.as_ref().unwrap();
        let callbacks = database.callbacks.load(std::sync::atomic::Ordering::Relaxed);
        assert!(callbacks > 0 && callbacks <= database.pattern_ids.len(), "{callbacks}");

        assert!(engine.matches_any("", &["^$"]).unwrap());
        assert!(!engine.matches_any("xx", &["^$"]).unwrap());
        assert!(engine.matches_any("xxneedle27 needle1", &["needle[0-9]+"]).unwrap());
        for (pattern, exact) in &engine.find_match_exact {
            for input in ["", "xxé😊", "key123 needle456 needle7", "éneedle12\nkey345"] {
                assert_eq!(
                    engine.find_match(input, pattern).unwrap(),
                    exact.find(input).map_or("", |matched| matched.as_str()),
                    "{pattern:?} {input:?}"
                );
            }
        }
    }

    #[test]
    fn go_ascii_classes_boundaries_and_unicode_matching_agree_in_both_engines() {
        for (pattern, input, expected) in [
            (r"^\w+$", "token_1", true),
            (r"^\w+$", "é", false),
            (r"^\d+$", "٢", false),
            (r"^\s+$", "\t\n\u{c}\r ", true),
            (r"^\s+$", "\u{b}", false),
            (r"^\s+$", "\u{a0}", false),
            (r"^\S+$", "\u{b}\u{a0}", true),
            (r"^\D+$", "٢é", true),
            (r"^\W+$", "é😊", true),
            (r"^[^\D]+$", "123", true),
            (r"^[^\D]+$", "٢", false),
            (r"^[^\W]+$", "token_1", true),
            (r"^[^\W]+$", "é", false),
            (r"^[^\S]+$", "\t ", true),
            (r"^[^\S]+$", "\u{b}", false),
            (r"^[\D]+$", "٢é", true),
            (r"^[\W]+$", "é😊", true),
            (r"^[\S]+$", "\u{b}\u{a0}", true),
            (r"\bword\b", "éwordé", true),
            (r"\Bword\B", "éwordé", false),
            (r"^.$", "😊", true),
            (r"^\p{Greek}+$", "λΩ", true),
            (r"^é😊$", "é😊", true),
            (r"^\\w\\d\\s\\b$", r"\w\d\s\b", true),
            (r"^\Q\w[.]{x}\E$", r"\w[.]{x}", true),
            (r"^[[:alpha:]\d]+$", "abc42", true),
            (r"^[]a]+$", "]a", true),
            (r"^[[]+$", "[", true),
        ] {
            let exact = compile_go_regex(pattern).unwrap();
            assert_eq!(exact.is_match(input), expected, "Rust {pattern:?} {input:?}");
            let expression = regex_helper(BetterleaksExpr::String { value: input.into() }, pattern);
            let find_match = BetterleaksExpr::Call {
                callee: Box::new(BetterleaksExpr::Identifier { value: "findMatch".into() }),
                arguments: vec![
                    BetterleaksExpr::String { value: input.into() },
                    BetterleaksExpr::String { value: pattern.into() },
                ],
            };
            let engine = BetterleaksFilterEngine::compile([&expression, &find_match]).unwrap();
            assert_eq!(
                engine.matches_any(input, &[pattern]).unwrap(),
                expected,
                "native {pattern:?} {input:?}"
            );
            assert_eq!(
                engine.find_match(input, pattern).unwrap(),
                exact.find(input).map_or("", |matched| matched.as_str()),
                "findMatch gate {pattern:?} {input:?}"
            );
        }
    }

    #[test]
    fn go_case_insensitive_negated_word_classes_agree_in_both_engines() {
        for (pattern, word, non_word) in [
            (r"(?i)^\w+$", true, false),
            (r"(?i)^[\w]+$", true, false),
            (r"(?i)^\W+$", false, true),
            (r"(?i)^[\W]+$", false, true),
            (r"(?i)^[^\W_]+$", true, false),
        ] {
            // Go applies Unicode simple folding before negating its ASCII word class.
            for (input, expected) in [
                ("k", word),
                ("K", word),
                ("s", word),
                ("S", word),
                ("ſ", word),
                ("K", word),
                ("é", non_word),
                ("!", non_word),
            ] {
                assert_go_regex_engines_agree(pattern, input, expected);
            }
        }
        assert_go_regex_engines_agree(r"(?i)^[^\W_]+$", "_", false);
        assert_eq!(
            normalize_go_regex(r"(?i)^[^\W_]+$", false),
            r"(?i)^[^\W_]+\z",
            "native ASCII shorthands must not become case-folded complement ranges"
        );
    }

    #[test]
    fn go_unicode_word_fallback_still_respects_requested_helper_patterns() {
        let word = r"(?i)^\w+$";
        let nonword = r"(?i)^[\W]+$";
        let literal = "^é$";
        let unrelated = "(?s).+";
        let expressions: Vec<_> = [word, nonword, literal, unrelated]
            .into_iter()
            .map(|pattern| regex_helper(BetterleaksExpr::String { value: "ſ".into() }, pattern))
            .collect();
        let engine = BetterleaksFilterEngine::compile(&expressions).unwrap();
        assert!(!engine.matches_any("ſ", &[nonword]).unwrap());
        assert!(engine.matches_any("ſ", &[word]).unwrap());
        assert!(!engine.matches_any("ſ", &[nonword, literal]).unwrap());
        assert!(engine.matches_any("é", &[word, literal]).unwrap());
        assert!(!engine.matches_any("é", &[word]).unwrap());
    }

    #[test]
    fn go_end_assertions_preserve_multiline_scopes_and_literal_dollars() {
        for (pattern, input, expected) in [
            (r"^token$", "token", true),
            (r"^token$", "token\n", false),
            (r"^token$", "token\r\n", false),
            (r"(?m)^token$", "token\n", true),
            (r"(?m:^token$)", "before\ntoken\nafter", true),
            (r"(?m)(?-m:^token$)", "token\n", false),
            (r"(?m:^other$)|^token$", "token", true),
            (r"(?m:^other$)|^token$", "token\n", false),
            (r"(?m)(?-m:^other$)|^token$", "token\n", true),
            (r"(?m:^token$)|(?-m:^end$)", "end\n", false),
            (r"^other$|(?m)^token$", "token\n", true),
            (r"(?m)^other$|^token$", "token\n", true),
            (r"^token\$$", "token$", true),
            (r"^token[$]$", "token$", true),
            (r"^token\$$", "token$\n", false),
            (r"^token[$]$", "token$\n", false),
            (r"^\Qtoken$\E$", "token$", true),
            (r"^\Qtoken$\E$", "token$\n", false),
        ] {
            assert_go_regex_engines_agree(pattern, input, expected);
        }
    }

    #[test]
    fn go_end_assertion_translation_restores_multiline_state_after_groups() {
        // Some native versions reject embedded line anchors before consuming tails.
        // Independently verify normalization without broadening compiler support.
        assert_eq!(
            normalize_go_regex(r"(?m:^token$)(?-m:\nend$)", false),
            r"(?m:^token$)(?-m:\nend\z)"
        );
        assert_eq!(normalize_go_regex(r"(?m:^token$)\nend$", false), r"(?m:^token$)\nend\z");
    }

    #[test]
    fn go_vertical_tab_escape_is_not_a_vertical_whitespace_class() {
        for pattern in [r"^\v$", r"^[\v]$", r"^[^\v]$"] {
            for input in ["\u{b}", "\n", "\r", "\u{c}", "\u{85}", "\u{2028}", "\u{2029}"] {
                let expected = (input == "\u{b}") != pattern.contains("[^");
                assert_go_regex_engines_agree(pattern, input, expected);
            }
        }
        assert_go_regex_engines_agree(r"^\\v$", r"\v", true);
        assert_go_regex_engines_agree(r"^\Q\v\E$", r"\v", true);
    }

    fn assert_go_regex_engines_agree(pattern: &str, input: &str, expected: bool) {
        let exact = compile_go_regex(pattern).unwrap();
        assert_eq!(exact.is_match(input), expected, "Rust {pattern:?} {input:?}");
        let expression = regex_helper(BetterleaksExpr::String { value: input.into() }, pattern);
        let find_match = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "findMatch".into() }),
            arguments: vec![
                BetterleaksExpr::String { value: input.into() },
                BetterleaksExpr::String { value: pattern.into() },
            ],
        };
        let engine = BetterleaksFilterEngine::compile([&expression, &find_match])
            .unwrap_or_else(|error| panic!("{pattern:?}: {error:#}"));
        assert_eq!(
            engine.matches_any(input, &[pattern]).unwrap(),
            expected,
            "native {pattern:?} {input:?}"
        );
        assert_eq!(
            engine.find_match(input, pattern).unwrap(),
            exact.find(input).map_or("", |matched| matched.as_str()),
            "findMatch gate {pattern:?} {input:?}"
        );
    }

    #[test]
    fn unchanged_custom_generic_toml_helpers_compile_without_confidence_changes() {
        use std::io::Read;
        let mut decoded = String::new();
        flate2::read::GzDecoder::new(
            include_bytes!("../generated/upstream-sources.json.gz").as_slice(),
        )
        .read_to_string(&mut decoded)
        .unwrap();
        let sources: BTreeMap<String, Option<String>> = serde_json::from_str(&decoded).unwrap();
        let source = sources
            .iter()
            .find_map(|(url, source)| {
                url.ends_with("/config/betterleaks.toml").then_some(source.as_deref()).flatten()
            })
            .unwrap();
        let upstream: toml::Value = toml::from_str(source).unwrap();
        let generic = upstream["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["id"].as_str() == Some("generic-api-key"))
            .unwrap();
        let original_filter = generic["filter"].as_str().unwrap();
        assert!(original_filter.contains(r"\w"));
        let config = toml::Value::Table(toml::map::Map::from_iter([(
            "rules".into(),
            toml::Value::Array(vec![generic.clone()]),
        )]));
        let yaml = crate::betterleaks::import_custom_config(
            &toml::to_string(&config).unwrap(),
            "archived-generic.toml",
        )
        .unwrap();
        let rules = crate::Rules::from_paths_and_contents(
            [(std::path::Path::new("archived-generic.yml"), yaml.as_bytes())],
            Confidence::Low,
        )
        .unwrap();
        let generic = rules.iter_rules().next().unwrap();
        let expression = generic.betterleaks_filter.as_ref().unwrap();
        let engine = BetterleaksFilterEngine::compile([expression]).unwrap();
        assert!(engine.find_match_exact.keys().any(|pattern| pattern.contains(r"\w")));
        let outcome = evaluate_filter_with_engine(
            expression,
            &context("qZ7mR9vN2xP5kL8sT4wY", "source.rs"),
            &engine,
        )
        .unwrap();
        assert!(!outcome.discard);
        assert_eq!(outcome.confidence, None);
    }

    #[test]
    fn supports_v2_filter_helpers_and_native_collection_operations() {
        for source in [
            r#"startsWithAny(["read:repo", "write:user"], ["write:"])"#,
            r#"!startsWithAny("WRITE:user", ["write:"])"#,
            r#"intersects(["read", "admin"], ["admin"]) && !intersects("read:repo", ["read"])"#,
            r#"!intersects(["admin", 42], ["admin"]) && !containsAny(["admin", 42], ["admin"])"#,
            r#"containsAny(["read", "ADMIN"], ["admin"])"#,
            r#"matchesAny(["read", "admin"], [`^adm`]) && !matchesAny(["admin", 42], [`^adm`])"#,
            r#"matchesAny("", [`^$`]) && !matchesAny("abc", [`^$`]) && matchesAny("abc", [`^`])"#,
            r#"crypto.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad""#,
            r#"let patterns = [`^adm`]; matchesAny("admin", patterns)"#,
            r#"let pattern = `adm[a-z]+`; findMatch("an admin token", pattern) == "admin""#,
            r#"all(1..3, {# < 4}) && none([1,2], {# > 2}) && one([1,2], {# > 1})"#,
            r#"map(filter([1,2,3], {# > 1}), {# * 2}) == [4,6]"#,
            r#"findLast([1,2,3], {# < 3}) == 2 && findIndex([1,2], {# == 2}) == 1"#,
            r#"count([1,2,3], {# >= 2}) == 2 && findLastIndex([1,2,3], {# < 3}) == 1"#,
            r#"let xs = [1,2]; all(xs, {any(xs, {# == 2}) && # <= 2})"#,
            r#"len("é😊") == 2 && "é😊"[-1:] == "😊""#,
            r#""abc" startsWith "ab" && "abc" endsWith "bc" && "abc" matches `^a`"#,
            r#"replace("a-a-a", "a", "b", 2) == "b-b-a" && 2 ** 3 == 8"#,
            r#"sort(uniq(flatten([[3,1],[1,2]]))) == [1,2,3]"#,
            r#"keys({a:1}) == ["a"] && get({a:1}, "a") == 1 && "a" in {a:1}"#,
            r#"fromJSON(toJSON({a: [1,2]})).a == [1,2] && upper(trim(" abc ")) == "ABC""#,
        ] {
            assert!(
                evaluate_filter(&parse(source), &context("token", "source.rs")).unwrap().discard,
                "{source}"
            );
        }
    }

    #[test]
    fn from_base64_matches_expr_standard_padding_and_newline_semantics() {
        for (encoded, decoded) in [
            ("", ""),
            ("\r\n", ""),
            ("Zm9v", "foo"),
            ("Zm8=", "fo"),
            ("Zg==", "f"),
            ("Zh==", "f"), // Go StdEncoding does not require zero unused padding bits.
            ("Zm9=", "fo"),
            ("Z\r\ng=\r\n=\r\n", "f"),
            ("Pj4+Pz8/", ">>>???"),
            ("w6nwn5iK", "é😊"),
            ("AA==", "\0"),
        ] {
            let source = format!(
                "fromBase64({}) == {}",
                serde_json::to_string(encoded).unwrap(),
                serde_json::to_string(decoded).unwrap()
            );
            assert!(
                evaluate_filter(&parse(&source), &context("token", "source.rs")).unwrap().discard,
                "{source}"
            );
        }
    }

    #[test]
    fn from_base64_rejects_malformed_inputs_without_partial_results() {
        for encoded in [
            "Z",
            "Zg",
            "Zg=",
            "Zg===",
            "Z===",
            "=Zg=",
            "Z=g=",
            "Zm9v=",
            "Zg==Zg==",
            "Zm9v$",
            "Z g==",
            "Zg==\t",
            "Zg==\u{000b}",
            "Zg==\u{000c}",
            "Zg==\u{00a0}",
            "Pj4-",
            "Pz8_",
        ] {
            let source =
                format!("fromBase64({}) == \"foo\"", serde_json::to_string(encoded).unwrap());
            let error =
                evaluate_filter(&parse(&source), &context("token", "source.rs")).unwrap_err();
            assert!(
                error.to_string().contains("invalid base64 in fromBase64"),
                "{source}: {error:#}"
            );
        }
    }

    #[test]
    fn from_base64_reports_type_arity_and_non_utf8_errors() {
        for (source, message) in [
            ("fromBase64()", "fromBase64 expects one argument"),
            (r#"fromBase64("Zg==", "Zg==")"#, "fromBase64 expects one argument"),
            ("fromBase64(42)", "expected string"),
            ("fromBase64(nil)", "expected string"),
            ("fromBase64([])", "expected string"),
            (r#"fromBase64("/w==")"#, "fromBase64 decoded data is not valid UTF-8"),
            (r#"fromBase64("wyg=")"#, "fromBase64 decoded data is not valid UTF-8"),
        ] {
            let error =
                evaluate_filter(&parse(source), &context("token", "source.rs")).unwrap_err();
            assert!(error.to_string().contains(message), "{source}: {error:#}");
        }
    }

    #[test]
    fn from_base64_bounds_input_before_normalizing_or_decoding() {
        let expression = parse(r#"fromBase64(finding["secret"]) == """#);
        let oversized = "\r".repeat(MAX_EXPRESSION_STRING_BYTES + 1);
        let error = evaluate_filter(&expression, &context(&oversized, "source.rs")).unwrap_err();
        assert!(error.to_string().contains("fromBase64 exceeds expression size limit"));
    }

    #[test]
    fn from_base64_supports_exact_rc7_mapbox_url_safe_normalization() {
        // Both the public and secret token rules use this exact rc.7 filter.
        let expression = parse(
            r#"
let parts = split(finding["secret"], ".");
let payload = len(parts) == 3 ? parts[1] : "";
let padding = (4 - len(payload) % 4) % 4;
entropy(finding["secret"]) < 4 || len(payload) % 4 == 1 ||
 !(fromBase64(replace(replace(payload, "-", "+"), "_", "/") + repeat("=", padding)) matches
   '^\\{"u":"[^"\\\\\\x00-\\x1f]+"\\s*,\\s*"a"\\s*:\\s*"[A-Za-z0-9]+"\\s*\\}$')
"#,
        );
        let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
        for prefix in ["pk", "sk"] {
            for payload in [
                "{\"u\":\"alice\",\"a\":\"abc123\"}",
                "{\"u\":\"alice1\",\"a\":\"abc123\"}",
                "{\"u\":\"alice12\",\"a\":\"abc123\"}",
                "{\"u\":\"\u{10ffff}\",\"a\":\"abc123\"}",
            ] {
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
                if payload.contains('\u{10ffff}') {
                    assert!(encoded.contains('-') && encoded.contains('_'), "{encoded}");
                }
                let secret = format!("{prefix}.{encoded}.Z4xP8vN2qW6rT9mL5kJ3gA");
                assert!(
                    !evaluate_filter_with_engine(
                        &expression,
                        &context(&secret, "source.rs"),
                        &engine
                    )
                    .unwrap()
                    .discard,
                    "unexpected normalization decision for synthetic {prefix} fixture"
                );
            }
            for payload in [
                "{\"u\":\"alice\",\"a\":\"not-allowed\"}",
                "{\"a\":\"abc123\",\"u\":\"alice\"}",
                "{\"u\":\"\",\"a\":\"abc123\"}",
                "not-json",
            ] {
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
                let secret = format!("{prefix}.{encoded}.Z4xP8vN2qW6rT9mL5kJ3gA");
                assert!(
                    evaluate_filter_with_engine(
                        &expression,
                        &context(&secret, "source.rs"),
                        &engine
                    )
                    .unwrap()
                    .discard,
                    "unexpected normalization decision for synthetic {prefix} fixture"
                );
            }
        }
    }

    #[test]
    fn optional_chains_skip_later_indexes_and_arguments() {
        for source in [
            r#"({})?.missing?.captures[1 % 0] ?? "fallback" == "fallback""#,
            r#"let object = {}; (object.missing?.captures[1 % 0] ?? "fallback") == "fallback""#,
            r#"let object = {}; (object.missing?.replace(string(1 % 0), "x") ?? "fallback") == "fallback""#,
        ] {
            assert!(
                evaluate_filter(&parse(source), &context("token", "source.rs")).unwrap().discard,
                "{source}"
            );
        }
        assert!(evaluate_filter(&parse("1 % 0 == 0"), &context("token", "source.rs")).is_err());
    }

    #[test]
    fn token_efficiency_uses_upstream_wordlist_and_normalization() {
        let secret = "linkedinX9qB2mK7pR4zT8";
        assert!(fails_token_efficiency_value(secret));
        assert!(token_efficiency_ratio(secret) < 2.5);
        assert!(!fails_token_efficiency_value("X9qB2mK7pR4zT8"));
        assert_eq!(token_efficiency_ratio("test\r\n"), token_efficiency_ratio("test"));
        assert!(!fails_token_efficiency_value(""));
        assert!(contains_dictionary_word("1PASSword9", 5));
        assert!(!contains_dictionary_word("abc", 5));
    }

    // Keep the pre-optimization predicate literal for differential coverage.
    fn original_fails_token_efficiency_value(input: &str) -> bool {
        let mut normalized = String::new();
        let analyzed = normalize_efficiency_input(input, &mut normalized);
        let tokens = cl100k_base_singleton().encode_ordinary(analyzed).len();
        if tokens == 0 {
            return false;
        }
        if contains_dictionary_word(analyzed, 5) {
            return true;
        }
        let threshold =
            if analyzed.len() < 12 && contains_dictionary_word(analyzed, 4) { 2.1 } else { 2.5 };
        analyzed.len() as f64 / tokens as f64 >= threshold
    }

    fn assert_token_efficiency_matches_original(input: &str) {
        assert_eq!(
            fails_token_efficiency_value(input),
            original_fails_token_efficiency_value(input),
            "synthetic input {input:?}"
        );
    }

    #[test]
    fn token_efficiency_dictionary_first_matches_original_cases() {
        for input in [
            "",
            "\r",
            "\n",
            "\r\n",
            "\r\n\r\n",
            " ",
            "\t",
            "\0",
            "\u{7f}",
            "test",
            "password",
            "1PASSword9",
            "linkedinX9qB2mK7pR4zT8",
            "X9qB2mK7pR4zT8",
            "test\r\n",
            "pa\rss\nword",
            "we're I'LL they've can't",
            "café",
            "e\u{301}",
            "\u{301}",
            "İPASSword9",
            "日本語 中文 한국어",
            "Ⅻ½٣",
            "🦆",
            "👩‍💻",
            "\u{200b}",
            "\u{10ffff}",
            "\u{85}\u{a0}\u{1680}\u{2003}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}",
            "<|endoftext|><|fim_prefix|><|fim_middle|><|fim_suffix|><|endofprompt|>",
        ] {
            assert_token_efficiency_matches_original(input);
        }

        for (prefix, strip) in [
            ("x".repeat(17), true),
            ("x".repeat(18), false),
            ("x".repeat(19), false),
            ("é".repeat(8), true),
            ("é".repeat(9), false),
        ] {
            let input = format!("{prefix}\r\n");
            let expected = if strip { prefix.as_str() } else { input.as_str() };
            let mut normalized = String::new();
            assert_eq!(normalize_efficiency_input(&input, &mut normalized), expected);
            assert_token_efficiency_matches_original(&input);
        }
        for length in [19, 20, 21] {
            let input = "\r".repeat(length);
            assert_token_efficiency_matches_original(&input);
            if length < 20 {
                assert!(!fails_token_efficiency_value(&input));
            }
        }
    }

    #[test]
    fn token_efficiency_dictionary_first_preserves_thresholds() {
        assert!(contains_dictionary_word("test", 4));
        assert!(contains_dictionary_word("password", 5));
        for (input, ratio, expected) in [
            ("test1A", 2.0, false),
            ("test12A", 7.0 / 3.0, true),
            ("test123A12B", 11.0 / 5.0, true),
            ("test123A123B", 12.0 / 5.0, false),
            ("1234567", 7.0 / 3.0, false),
            ("1234567890", 2.5, true),
            ("12345678901", 11.0 / 4.0, true),
        ] {
            assert!(!contains_dictionary_word(input, 5), "{input}");
            if input.starts_with("test") {
                assert!(contains_dictionary_word(input, 4), "{input}");
            }
            assert_eq!(token_efficiency_ratio(input), ratio, "{input}");
            assert_eq!(fails_token_efficiency_value(input), expected, "{input}");
            assert_token_efficiency_matches_original(input);
        }
    }

    #[test]
    fn token_efficiency_dictionary_first_matches_original_seeded_inputs() {
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for case in 0..512 {
            let mut input = String::new();
            for _ in 0..next() % 64 {
                let scalar = if case % 2 == 0 { next() % 128 } else { next() % 0x11_0000 };
                input.push(char::from_u32(scalar as u32).unwrap_or('\u{fffd}'));
            }
            match case % 4 {
                0 => input.insert_str(0, "test"),
                1 => input.push_str("password"),
                2 => input.push_str("\r\n"),
                _ => {}
            }
            assert_token_efficiency_matches_original(&input);
        }
    }

    #[test]
    fn token_efficiency_dictionary_first_matches_original_long_base64_like_inputs() {
        let mixed = "X9qB2mK7pR4zT8+/".repeat(512);
        let letters = "qZyKpRwTjVbNcDfGhL".repeat(512);
        for input in [format!("{mixed}=="), format!("{letters}=="), format!("password{letters}==")]
        {
            assert!(input.len() > 150);
            assert_token_efficiency_matches_original(&input);
        }
    }

    #[test]
    fn token_efficiency_nonempty_cl100k_inputs_produce_tokens() {
        let tokenizer = cl100k_base_singleton();
        let mut single_bytes = [false; 256];
        for rank in 0..256 {
            let token = tokenizer.decode_bytes(&[rank]).unwrap();
            assert_eq!(token.len(), 1, "rank {rank}");
            single_bytes[usize::from(token[0])] = true;
        }
        assert!(single_bytes.into_iter().all(|present| present));
        assert!(tokenizer.encode_ordinary("").is_empty());
        for byte in 0_u8..=u8::MAX {
            let input = char::from(byte).to_string();
            assert!(!tokenizer.encode_ordinary(&input).is_empty(), "scalar {input:?}");
        }
        for input in [
            "é",
            "中",
            "Ⅻ",
            "½",
            "٣",
            "\u{301}",
            "🦆",
            "\u{200b}",
            "\u{10ffff}",
            "\u{1680}\u{2003}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}",
        ] {
            assert!(!tokenizer.encode_ordinary(input).is_empty(), "scalar {input:?}");
        }
    }

    #[test]
    fn go_literal_braces_preserve_helper_regex_semantics() {
        let regex = compile_go_regex(r"^\$(?:\d+|{\d+})$").unwrap();
        assert!(regex.is_match("${12}"));
        assert!(regex.is_match("$12"));
        assert!(!regex.is_match("$name"));
        assert!(compile_go_regex(r"^a{2,3}{literal}$").unwrap().is_match("aaa{literal}"));
        assert!(compile_go_regex("[").is_err());
    }

    #[test]
    fn finding_filters_can_use_supplied_source_metadata() {
        let attributes =
            BTreeMap::from([("git.author_email".into(), "automation@example.test".into())]);
        let mut context = context("token", "source.rs");
        context.attributes = Some(&attributes);
        assert!(evaluate_filter(&parse(r#"attributes["git.author_email"] == "automation@example.test" && attributes.path == "source.rs""#), &context).unwrap().discard);
    }

    fn context<'a>(secret: &'a str, path: &'a str) -> BetterleaksFilterContext<'a> {
        BetterleaksFilterContext {
            path,
            attributes: None,
            secret,
            full_match: secret,
            line: secret,
            fragment_raw: secret,
            match_start_idx: 0,
            match_end_idx: secret.len(),
            match_line_start_idx: 0,
            match_line_end_idx: secret.len(),
            rule_id: "betterleaks.test",
            description: "test",
            captures: BTreeMap::new(),
        }
    }

    fn finding_member(field: &str) -> BetterleaksExpr {
        BetterleaksExpr::Member {
            node: Box::new(BetterleaksExpr::Identifier { value: "finding".into() }),
            property: Box::new(BetterleaksExpr::String { value: field.into() }),
            optional: false,
            method: false,
        }
    }

    fn regex_helper(input: BetterleaksExpr, pattern: &str) -> BetterleaksExpr {
        BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".into() }),
            arguments: vec![
                input,
                BetterleaksExpr::Array {
                    nodes: vec![BetterleaksExpr::String { value: pattern.into() }],
                },
            ],
        }
    }

    #[test]
    fn dense_source_line_filters_scan_once_and_keep_candidate_results() {
        let line_filter = regex_helper(finding_member("line"), "competing-token");
        let expression = BetterleaksExpr::Binary {
            operator: "||".into(),
            left: Box::new(BetterleaksExpr::Binary {
                operator: "==".into(),
                left: Box::new(finding_member("secret")),
                right: Box::new(BetterleaksExpr::String { value: "discard-token".into() }),
            }),
            right: Box::new(line_filter),
        };
        let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
        let line = "candidate-token ".repeat(10_000);
        let mut cache = BetterleaksFilterLineCache::default();
        for secret in std::iter::repeat_n("keep-token", 1000).chain(["discard-token"]) {
            let mut context = context(secret, "dense.txt");
            context.line = &line;
            let expected = evaluate_filter_with_engine(&expression, &context, &engine).unwrap();
            let cached = evaluate_filter_with_engine_and_line_cache(
                &expression,
                &context,
                &engine,
                0..line.len(),
                Some(&mut cache),
            )
            .unwrap();
            assert_eq!(cached, expected);
            assert_eq!(cached.discard, secret == "discard-token");
        }
        assert_eq!(cache.scans, 1);
        assert_eq!(cache.matches_any.len(), 1);
    }

    #[test]
    fn source_line_cache_separates_live_buffers_with_identical_ranges() {
        let expression = regex_helper(finding_member("line"), "present");
        let engine = BetterleaksFilterEngine::compile([&expression]).unwrap();
        let first = String::from("present");
        let second = String::from("missing");
        let mut cache = BetterleaksFilterLineCache::default();
        for (line, discard) in [(&first, true), (&second, false), (&first, true)] {
            let mut context = context("secret", "source.txt");
            context.line = line;
            let result = evaluate_filter_with_engine_and_line_cache(
                &expression,
                &context,
                &engine,
                0..7,
                Some(&mut cache),
            )
            .unwrap();
            assert_eq!(result.discard, discard);
        }
        assert_eq!(cache.scans, 2);
    }

    #[test]
    fn source_line_cache_separates_ranges_patterns_and_derived_inputs() {
        let absent = regex_helper(finding_member("line"), "absent$");
        let present = regex_helper(finding_member("line"), "present$");
        let derived = regex_helper(
            BetterleaksExpr::Binary {
                operator: "+".into(),
                left: Box::new(finding_member("line")),
                right: Box::new(BetterleaksExpr::String { value: "absent".into() }),
            },
            "absent$",
        );
        let secret_filter = regex_helper(finding_member("secret"), "absent$");
        let engine =
            BetterleaksFilterEngine::compile([&absent, &present, &derived, &secret_filter])
                .unwrap();
        let mut context = context("absent", "source.txt");
        context.line = "present";
        let mut cache = BetterleaksFilterLineCache::default();
        for (expression, range, discard) in [
            (&absent, 0..7, false),
            (&absent, 0..7, false),
            (&absent, 8..15, false),
            (&present, 0..7, true),
            (&derived, 0..7, true),
            (&secret_filter, 0..7, true),
        ] {
            let result = evaluate_filter_with_engine_and_line_cache(
                expression,
                &context,
                &engine,
                range,
                Some(&mut cache),
            )
            .unwrap();
            assert_eq!(result.discard, discard);
        }
        assert_eq!(cache.scans, 3);
        assert_eq!(cache.matches_any.len(), 3);

        let uncompiled = regex_helper(finding_member("line"), "uncompiled");
        assert!(
            evaluate_filter_with_engine_and_line_cache(
                &uncompiled,
                &context,
                &engine,
                0..7,
                Some(&mut cache),
            )
            .is_err()
        );
        assert_eq!(cache.scans, 3);
        assert_eq!(cache.matches_any.len(), 3);
    }

    #[test]
    fn source_line_cache_evicts_only_on_insertion_and_reevaluates_exact_results() {
        let present = regex_helper(finding_member("line"), "present$");
        let absent = regex_helper(finding_member("line"), "absent$");
        let engine = BetterleaksFilterEngine::compile([&present, &absent]).unwrap();
        let repeated = "present\n";
        let source = format!("{}absent", repeated.repeat(SOURCE_LINE_CACHE_MAX_ENTRIES));
        let mut cache = BetterleaksFilterLineCache::default();
        let mut context = context("secret", "source.txt");
        for index in 0..SOURCE_LINE_CACHE_MAX_ENTRIES {
            let start = index * repeated.len();
            let range = start..start + "present".len();
            context.line = &source[range.clone()];
            assert!(
                evaluate_filter_with_engine_and_line_cache(
                    &present,
                    &context,
                    &engine,
                    range,
                    Some(&mut cache)
                )
                .unwrap()
                .discard
            );
        }
        assert_eq!(cache.entries, SOURCE_LINE_CACHE_MAX_ENTRIES);
        assert_eq!(cache.matches_any.len(), SOURCE_LINE_CACHE_MAX_ENTRIES);
        assert_eq!(cache.scans, SOURCE_LINE_CACHE_MAX_ENTRIES);
        // A hit must not evict a full cache.
        context.line = &source[.."present".len()];
        assert!(
            evaluate_filter_with_engine_and_line_cache(
                &present,
                &context,
                &engine,
                0.."present".len(),
                Some(&mut cache)
            )
            .unwrap()
            .discard
        );
        assert_eq!(cache.entries, SOURCE_LINE_CACHE_MAX_ENTRIES);
        assert_eq!(cache.scans, SOURCE_LINE_CACHE_MAX_ENTRIES);

        let last_start = SOURCE_LINE_CACHE_MAX_ENTRIES * repeated.len();
        for (expression, range, discard, new_scans) in [
            (&absent, 0.."present".len(), false, 1),
            (&present, 0.."present".len(), true, 2),
            (&present, last_start..source.len(), false, 3),
            (&absent, last_start..source.len(), true, 4),
            (&absent, 0.."present".len(), false, 4),
        ] {
            context.line = &source[range.clone()];
            let result = evaluate_filter_with_engine_and_line_cache(
                expression,
                &context,
                &engine,
                range,
                Some(&mut cache),
            )
            .unwrap();
            assert_eq!(result.discard, discard);
            assert_eq!(cache.scans, SOURCE_LINE_CACHE_MAX_ENTRIES + new_scans);
            assert_eq!(cache.entries, new_scans);
            assert_eq!(cache.matches_any.len(), new_scans);
        }
        assert_eq!(cache.entries, cache.matches_any.values().map(Vec::len).sum::<usize>());
    }

    #[test]
    fn borrowed_fragment_clones_share_storage_and_mutations_own_the_result() {
        let fragment = "source data".repeat(10000);
        let original = Value::string(fragment.as_str());
        let cloned = original.clone();
        assert_eq!(original.as_string().unwrap().as_ptr(), fragment.as_ptr());
        assert_eq!(cloned.as_string().unwrap().as_ptr(), fragment.as_ptr());
        let engine = BetterleaksFilterEngine::compile(std::iter::empty()).unwrap();
        let prepared_fragment = BetterleaksFilterFragment::new(&fragment);
        let mut evaluator = Evaluator {
            variables: BTreeMap::from([("source", original)]),
            filter_engine: &engine,
            source_line: "",
            line_range: 0..0,
            line_cache: None,
            fragment: &prepared_fragment,
        };
        let expr = BetterleaksExpr::Binary {
            operator: "+".into(),
            left: Box::new(BetterleaksExpr::Identifier { value: "source".into() }),
            right: Box::new(BetterleaksExpr::String { value: " suffix".into() }),
        };
        let result = evaluator.eval(&expr).unwrap();
        assert_eq!(result.as_string().unwrap(), format!("{fragment} suffix"));
        assert_eq!(evaluator.variables["source"].as_string().unwrap(), fragment);
    }

    #[test]
    fn evaluates_filter_helpers() {
        let expression = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Member {
                node: Box::new(BetterleaksExpr::Identifier { value: "filter".to_string() }),
                property: Box::new(BetterleaksExpr::String { value: "containsAny".to_string() }),
                optional: false,
                method: true,
            }),
            arguments: vec![
                BetterleaksExpr::String { value: "Example Secret".to_string() },
                BetterleaksExpr::Array {
                    nodes: vec![BetterleaksExpr::String { value: "example".to_string() }],
                },
            ],
        };
        assert!(evaluate_filter(&expression, &context("secret", "src/lib.rs")).unwrap().discard);
    }

    #[test]
    fn evaluates_regex_helpers_with_vectorscan() {
        let matches_any = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".to_string() }),
            arguments: vec![
                BetterleaksExpr::String { value: "token_1234".to_string() },
                BetterleaksExpr::Array {
                    nodes: vec![BetterleaksExpr::String { value: r"^token_[0-9]+$".to_string() }],
                },
            ],
        };
        assert!(evaluate_filter(&matches_any, &context("secret", "src/lib.rs")).unwrap().discard);

        let find_match = BetterleaksExpr::Binary {
            operator: "==".to_string(),
            left: Box::new(BetterleaksExpr::Call {
                callee: Box::new(BetterleaksExpr::Identifier { value: "findMatch".to_string() }),
                arguments: vec![
                    BetterleaksExpr::String { value: "xxaaay".to_string() },
                    BetterleaksExpr::String { value: "a+".to_string() },
                ],
            }),
            right: Box::new(BetterleaksExpr::String { value: "aaa".to_string() }),
        };
        assert!(evaluate_filter(&find_match, &context("secret", "src/lib.rs")).unwrap().discard);

        let empty_capable_find_match = BetterleaksExpr::Binary {
            operator: "==".to_string(),
            left: Box::new(BetterleaksExpr::Call {
                callee: Box::new(BetterleaksExpr::Identifier { value: "findMatch".to_string() }),
                arguments: vec![
                    BetterleaksExpr::String { value: "prefix.value".to_string() },
                    BetterleaksExpr::String { value: r"[\w.-]{0,50}$".to_string() },
                ],
            }),
            right: Box::new(BetterleaksExpr::String { value: "prefix.value".to_string() }),
        };
        assert!(
            evaluate_filter(&empty_capable_find_match, &context("secret", "src/lib.rs"))
                .unwrap()
                .discard
        );
    }

    #[test]
    fn exposes_the_complete_source_line() {
        let expression = BetterleaksExpr::Binary {
            operator: "==".to_string(),
            left: Box::new(BetterleaksExpr::Member {
                node: Box::new(BetterleaksExpr::Identifier { value: "finding".to_string() }),
                property: Box::new(BetterleaksExpr::String { value: "line".to_string() }),
                optional: false,
                method: false,
            }),
            right: Box::new(BetterleaksExpr::String { value: "prefix secret suffix".to_string() }),
        };
        let mut context = context("secret", "src/lib.rs");
        context.line = "prefix secret suffix";

        assert!(evaluate_filter(&expression, &context).unwrap().discard);
    }
}
