//! Runtime evaluation for filter expressions imported from Betterleaks.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    ops::Range,
    str::FromStr,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, Result, anyhow, bail};
use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern, Scan};
use regex::Regex;
use sha2::{Digest, Sha256};
use xxhash_rust::xxh3::Xxh3;

use crate::{
    BetterleaksExpr, Confidence, scanner_pool::ScannerPool, tokenizer::cl100k_base_singleton,
};

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
    /// Some generic rules dynamically refine their configured confidence.
    pub confidence: Option<Confidence>,
}

/// Reuses source-line regex results within one immutable source buffer.
/// Create a separate cache for each raw or decoded buffer. Line ranges must
/// identify the exact bytes used to construct `BetterleaksFilterContext::line`.
#[doc(hidden)]
#[derive(Default)]
pub struct BetterleaksFilterLineCache {
    matches_any: BTreeMap<LineCacheKey, Vec<CachedPatterns>>,
    #[cfg(test)]
    scans: usize,
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
    find_match: Option<VectorscanRegexDatabase>,
    find_match_exact: BTreeMap<String, Regex>,
    dynamic_regex: bool,
}

impl BetterleaksFilterEngine {
    pub(crate) fn compile<'a>(
        expressions: impl IntoIterator<Item = &'a BetterleaksExpr>,
    ) -> Result<Self> {
        let mut matches_any_patterns = BTreeSet::new();
        let mut find_match_patterns = BTreeSet::new();
        let mut dynamic_regex = false;
        for expression in expressions {
            dynamic_regex |= has_dynamic_regex(expression);
            collect_filter_regex_patterns(
                expression,
                &mut matches_any_patterns,
                &mut find_match_patterns,
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
        for pattern in &matches_any_patterns {
            let regex = compile_go_regex(pattern)?;
            if regex.is_match("") {
                matches_any_empty.insert(pattern.clone(), regex);
            }
        }
        matches_any_patterns.retain(|pattern| !matches_any_empty.contains_key(pattern));
        Ok(Self {
            matches_any: VectorscanRegexDatabase::compile(
                matches_any_patterns.into_iter().map(|pattern| (pattern.clone(), pattern)),
                Flag::default(),
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
                Flag::default(),
                "findMatch",
            )?,
            find_match_exact,
            matches_any_empty,
            dynamic_regex,
        })
    }

    fn matches_any(&self, input: &str, patterns: &[&str]) -> Result<bool> {
        if self
            .matches_any_empty
            .iter()
            .any(|(pattern, regex)| patterns.contains(&pattern.as_str()) && regex.is_match(input))
        {
            return Ok(true);
        }
        let patterns: Vec<_> = patterns
            .iter()
            .copied()
            .filter(|pattern| !self.matches_any_empty.contains_key(*pattern))
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
        if !self
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

struct VectorscanRegexDatabase {
    pattern_ids: BTreeMap<String, u32>,
    scanners: ScannerPool,
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
                Ok(Pattern::new(compiled_pattern.into_bytes(), flags, Some(id)))
            })
            .collect::<Result<Vec<_>>>()?;
        let database = Arc::new(
            BlockDatabase::new(patterns)
                .with_context(|| format!("compile Betterleaks {helper_name} filters"))?,
        );
        Ok(Some(Self { pattern_ids, scanners: ScannerPool::new(database) }))
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
) -> Result<()> {
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
                    _ => {}
                }
            }
            for argument in arguments {
                collect_filter_regex_patterns(argument, matches_any_patterns, find_match_patterns)?;
            }
        }
        BetterleaksExpr::Builtin { arguments, .. }
        | BetterleaksExpr::Sequence { nodes: arguments }
        | BetterleaksExpr::Array { nodes: arguments }
        | BetterleaksExpr::Map { pairs: arguments } => {
            for argument in arguments {
                collect_filter_regex_patterns(argument, matches_any_patterns, find_match_patterns)?;
            }
        }
        BetterleaksExpr::Unary { node, .. }
        | BetterleaksExpr::Chain { node }
        | BetterleaksExpr::Predicate { node } => {
            collect_filter_regex_patterns(node, matches_any_patterns, find_match_patterns)?
        }
        BetterleaksExpr::Binary { left, right, .. } => {
            collect_filter_regex_patterns(left, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(right, matches_any_patterns, find_match_patterns)?;
        }
        BetterleaksExpr::Member { node, property, .. } => {
            collect_filter_regex_patterns(node, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(property, matches_any_patterns, find_match_patterns)?;
        }
        BetterleaksExpr::Slice { node, from, to } => {
            collect_filter_regex_patterns(node, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(from, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(to, matches_any_patterns, find_match_patterns)?;
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            collect_filter_regex_patterns(cond, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(exp1, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(exp2, matches_any_patterns, find_match_patterns)?;
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            collect_filter_regex_patterns(value, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(expr, matches_any_patterns, find_match_patterns)?;
        }
        BetterleaksExpr::Pair { key, value } => {
            collect_filter_regex_patterns(key, matches_any_patterns, find_match_patterns)?;
            collect_filter_regex_patterns(value, matches_any_patterns, find_match_patterns)?;
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

#[derive(Debug, Clone, PartialEq)]
enum Value<'a> {
    Nil,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(Cow<'a, str>),
    Array(Vec<Value<'a>>),
    Map(BTreeMap<String, Value<'a>>),
}

impl<'a> Value<'a> {
    fn string(value: impl Into<Cow<'a, str>>) -> Self {
        Self::String(value.into())
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
    variables: BTreeMap<String, Value<'a>>,
    confidence: Option<Confidence>,
    filter_engine: &'a BetterleaksFilterEngine,
    source_line: &'a str,
    line_range: Range<usize>,
    line_cache: Option<&'c mut BetterleaksFilterLineCache>,
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
    let mut finding = BTreeMap::new();
    finding.insert("secret".to_string(), Value::string(context.secret));
    finding.insert("match".to_string(), Value::string(context.full_match));
    finding.insert("line".to_string(), Value::string(context.line));
    finding.insert("rule_id".to_string(), Value::string(context.rule_id));
    finding.insert("description".to_string(), Value::string(context.description));
    finding.insert("context".to_string(), Value::string(context.full_match));
    finding.insert("fragment_raw".to_string(), Value::string(context.fragment_raw));
    finding.insert("match_start_idx".to_string(), Value::Integer(context.match_start_idx as i64));
    finding.insert("match_end_idx".to_string(), Value::Integer(context.match_end_idx as i64));
    finding.insert(
        "match_line_start_idx".to_string(),
        Value::Integer(context.match_line_start_idx as i64),
    );
    finding.insert(
        "match_line_end_idx".to_string(),
        Value::Integer(context.match_line_end_idx as i64),
    );
    finding.insert(
        "captures".to_string(),
        Value::Map(
            context
                .captures
                .iter()
                .map(|(key, value)| (key.clone(), Value::string(value.clone())))
                .collect(),
        ),
    );

    let mut attributes = context
        .attributes
        .into_iter()
        .flat_map(|attributes| attributes.iter())
        .map(|(key, value)| (key.clone(), Value::string(value.as_str())))
        .collect::<BTreeMap<_, _>>();
    attributes.entry("path".to_string()).or_insert_with(|| Value::string(context.path));
    let variables = BTreeMap::from([
        ("finding".to_string(), Value::Map(finding)),
        ("attributes".to_string(), Value::Map(attributes)),
    ]);
    let mut evaluator = Evaluator {
        variables,
        confidence: None,
        filter_engine,
        source_line: context.line,
        line_range,
        line_cache,
    };
    let discard = evaluator.eval(expression)?.truthy();
    Ok(BetterleaksFilterOutcome { discard, confidence: evaluator.confidence })
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
    fn eval(&mut self, expression: &BetterleaksExpr) -> Result<Value<'a>> {
        match expression {
            BetterleaksExpr::Nil => Ok(Value::Nil),
            BetterleaksExpr::Identifier { value } => {
                Ok(self.variables.get(value).cloned().unwrap_or(Value::Nil))
            }
            BetterleaksExpr::Integer { value } => Ok(Value::Integer(*value)),
            BetterleaksExpr::Float { value } => Ok(Value::Float(value.parse()?)),
            BetterleaksExpr::Bool { value } => Ok(Value::Bool(*value)),
            BetterleaksExpr::String { value } => Ok(Value::string(value.clone())),
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
                let previous = self.variables.insert(name.clone(), value);
                let result = self.eval(expr);
                if let Some(previous) = previous {
                    self.variables.insert(name.clone(), previous);
                } else {
                    self.variables.remove(name);
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
            BetterleaksExpr::Array { nodes } => nodes
                .iter()
                .map(|node| self.eval(node))
                .collect::<Result<Vec<_>>>()
                .map(Value::Array),
            BetterleaksExpr::Map { pairs } => {
                let mut values = BTreeMap::new();
                for pair in pairs {
                    let BetterleaksExpr::Pair { key, value } = pair else {
                        bail!("map contains a non-pair expression");
                    };
                    let key = self.eval(key)?.into_string()?;
                    values.insert(key, self.eval(value)?);
                }
                Ok(Value::Map(values))
            }
            BetterleaksExpr::Pair { .. } => bail!("pair evaluated outside a map"),
            BetterleaksExpr::Predicate { node } => self.eval(node),
            BetterleaksExpr::Pointer { name } => {
                Ok(self.variables.get(name).cloned().unwrap_or(Value::Nil))
            }
        }
    }

    /// `None` is an optional receiver short-circuit and must skip later indexes and arguments.
    fn eval_chain(&mut self, expression: &BetterleaksExpr) -> Result<Option<Value<'a>>> {
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
        left: &BetterleaksExpr,
        right: &BetterleaksExpr,
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
        let length = match &value {
            Value::String(value) => value.chars().count(),
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
                Ok(Value::string(value.chars().skip(from).take(to - from).collect::<String>()))
            }
            Value::Array(values) => {
                let from = from.min(values.len());
                let to = to.min(values.len()).max(from);
                Ok(Value::Array(values[from..to].to_vec()))
            }
            other => bail!("cannot slice {other:?}"),
        }
    }

    fn call(
        &mut self,
        callee: &BetterleaksExpr,
        arguments: &[BetterleaksExpr],
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

    fn call_named(&mut self, name: &str, arguments: &[BetterleaksExpr]) -> Result<Value<'a>> {
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
            "filter.containsAny" | "containsAny" => contains_any(arguments),
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
            "filter.setConfidence" | "setConfidence" => self.set_confidence(arguments),
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
            "type" | "string" | "int" | "float" | "trim" | "trimPrefix" | "trimSuffix"
            | "repeat" | "indexOf" | "hasPrefix" | "hasSuffix" | "keys" | "values" | "reverse"
            | "sort" | "uniq" | "flatten" | "concat" | "first" | "last" | "get" | "sum"
            | "mean" | "abs" | "ceil" | "floor" | "round" | "toJSON" | "fromJSON" => {
                simple_builtin(name, arguments)
            }
            other => bail!("unsupported Betterleaks filter function {other:?}"),
        }
    }

    fn eval_arguments(&mut self, arguments: &[BetterleaksExpr]) -> Result<Vec<Value<'a>>> {
        arguments.iter().map(|argument| self.eval(argument)).collect()
    }

    fn call_collection(&mut self, name: &str, arguments: &[BetterleaksExpr]) -> Result<Value<'a>> {
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
            for (index, item) in items.into_iter().enumerate() {
                self.variables.insert("#".into(), item.clone());
                self.variables.insert("#index".into(), Value::Integer(index as i64));
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
                "filter" | "map" => Value::Array(output),
                "count" => Value::Integer(count),
                "find" | "findLast" | "findIndex" | "findLastIndex" => found,
                "all" | "none" => Value::Bool(true),
                "one" => Value::Bool(count == 1),
                _ => Value::Bool(false),
            })
        })();
        if let Some(previous) = previous {
            self.variables.insert("#".to_string(), previous);
        } else {
            self.variables.remove("#");
        }
        if let Some(previous) = previous_index {
            self.variables.insert("#index".into(), previous);
        } else {
            self.variables.remove("#index");
        }
        result
    }

    fn set_confidence(&mut self, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
        let [value] = arguments.as_slice() else {
            bail!("filter.setConfidence expects one argument");
        };
        let value = value.as_string()?;
        self.confidence = Some(Confidence::from_str(value)?);
        Ok(Value::string(value.to_string()))
    }

    fn matches_any(&mut self, arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
        let [input, patterns] = arguments.as_slice() else {
            bail!("matchesAny expects two arguments");
        };
        if let Value::Array(values) = input {
            if values.iter().any(|value| !matches!(value, Value::String(_))) {
                return Ok(Value::Bool(false));
            }
            for value in values {
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
            // Compare the actual list on hits: a hash collision must never
            // change filtering. Clone patterns only when populating the cache.
            cache.matches_any.entry(key).or_default().push(CachedPatterns {
                patterns: patterns.iter().map(|pattern| (*pattern).to_owned()).collect(),
                matched,
            });
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

/// Go treats braces that do not form a counted repetition as literals; Rust requires escaping.
/// Keep Vectorscan source patterns intact and normalize only the exact Rust helper fallback.
#[doc(hidden)]
pub fn compile_go_regex(pattern: &str) -> Result<Regex> {
    if let Ok(regex) = Regex::new(pattern) {
        return Ok(regex);
    }
    let mut normalized = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    let mut in_class = false;
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '\\' => {
                normalized.push(ch);
                if let Some((_, escaped)) = chars.next() {
                    normalized.push(escaped);
                }
            }
            '[' => {
                in_class = true;
                normalized.push(ch);
            }
            ']' => {
                in_class = false;
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
                normalized.push_str("\\{");
            }
            '}' if !in_class => normalized.push_str("\\}"),
            _ => normalized.push(ch),
        }
    }
    Regex::new(&normalized).with_context(|| format!("invalid Betterleaks regex {pattern:?}"))
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

fn contains_any<'a>(arguments: Vec<Value<'a>>) -> Result<Value<'a>> {
    let [input, terms] = arguments.as_slice() else {
        bail!("containsAny expects two arguments");
    };
    let Some(input) = strings_or_single(input) else {
        return Ok(Value::Bool(false));
    };
    let Ok(terms) = strings(terms) else {
        return Ok(Value::Bool(false));
    };
    Ok(Value::Bool(
        input.iter().any(|input| {
            terms.iter().any(|term| input.to_lowercase().contains(&term.to_lowercase()))
        }),
    ))
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
            values.iter().map(|(key, value)| (key.clone(), value_to_json(value))).collect()
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
        serde_json::Value::Object(values) => Value::Map(
            values.into_iter().map(|(key, value)| (key, value_from_json(value))).collect(),
        ),
    }
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
            if text()?.len().saturating_mul(count) > 16 * 1024 * 1024 {
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
                    let mut values = values.clone();
                    for argument in &arguments[1..] {
                        let Value::Array(extra) = argument else {
                            bail!("concat expects arrays");
                        };
                        values.extend(extra.iter().cloned());
                    }
                    Ok(Value::Array(values))
                }
                "flatten" => {
                    fn flatten<'a>(value: Value<'a>, out: &mut Vec<Value<'a>>) {
                        if let Value::Array(values) = value {
                            for value in values {
                                flatten(value, out);
                            }
                        } else {
                            out.push(value);
                        }
                    }
                    let mut out = Vec::new();
                    for value in values {
                        flatten(value.clone(), &mut out);
                    }
                    Ok(Value::Array(out))
                }
                "uniq" => {
                    let mut out = Vec::new();
                    for value in values {
                        if !out.iter().any(|seen| values_equal(seen, value)) {
                            out.push(value.clone());
                        }
                    }
                    Ok(Value::Array(out))
                }
                "sort" => {
                    let mut values = values.clone();
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
                    Ok(Value::Array(values))
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
    fn borrowed_fragment_clones_share_storage_and_mutations_own_the_result() {
        let fragment = "source data".repeat(10000);
        let original = Value::string(fragment.as_str());
        let cloned = original.clone();
        assert_eq!(original.as_string().unwrap().as_ptr(), fragment.as_ptr());
        assert_eq!(cloned.as_string().unwrap().as_ptr(), fragment.as_ptr());
        let engine = BetterleaksFilterEngine::compile(std::iter::empty()).unwrap();
        let mut evaluator = Evaluator {
            variables: BTreeMap::from([("source".into(), original)]),
            confidence: None,
            filter_engine: &engine,
            source_line: "",
            line_range: 0..0,
            line_cache: None,
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
