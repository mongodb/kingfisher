//! Runtime evaluation for filter expressions imported from Betterleaks.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use thread_local::ThreadLocal;
use tiktoken_rs::cl100k_base_singleton;
use vectorscan_rs::{BlockDatabase, BlockScanner, Flag, Pattern, Scan};

use crate::{BetterleaksExpr, Confidence};

/// Candidate data exposed to a Betterleaks filter expression.
#[derive(Debug)]
pub struct BetterleaksFilterContext<'a> {
    pub path: &'a str,
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

/// Vectorscan databases shared by every imported Betterleaks finding filter.
///
/// Betterleaks filter expressions contain regex helpers in addition to the main detection regex.
/// Compiling those helpers while evaluating each finding is prohibitively expensive, so the rule
/// database builds this engine once and each worker retains its own scratch arena.
pub(crate) struct BetterleaksFilterEngine {
    matches_any: Option<VectorscanRegexDatabase>,
    find_match: Option<VectorscanRegexDatabase>,
    find_match_exact: BTreeMap<String, Regex>,
}

impl BetterleaksFilterEngine {
    pub(crate) fn compile<'a>(
        expressions: impl IntoIterator<Item = &'a BetterleaksExpr>,
    ) -> Result<Self> {
        let mut matches_any_patterns = BTreeSet::new();
        let mut find_match_patterns = BTreeSet::new();
        for expression in expressions {
            collect_filter_regex_patterns(
                expression,
                &mut matches_any_patterns,
                &mut find_match_patterns,
            )?;
        }
        let find_match_exact: BTreeMap<String, Regex> = find_match_patterns
            .iter()
            .map(|pattern| {
                Regex::new(pattern)
                    .with_context(|| format!("compile Betterleaks findMatch regex {pattern:?}"))
                    .map(|regex| (pattern.clone(), regex))
            })
            .collect::<Result<_>>()?;
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
        })
    }

    fn matches_any(&self, input: &str, patterns: &[&str]) -> Result<bool> {
        if patterns.is_empty() {
            return Ok(false);
        }
        self.matches_any
            .as_ref()
            .ok_or_else(|| anyhow!("matchesAny patterns were not compiled"))?
            .matches_any(input.as_bytes(), patterns)
    }

    fn find_match(&self, input: &str, pattern: &str) -> Result<String> {
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
    database: Arc<BlockDatabase>,
    scanners: ThreadLocal<RefCell<BlockScanner<'static>>>,
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
        Ok(Some(Self { pattern_ids, database, scanners: ThreadLocal::new() }))
    }

    fn with_scanner<T>(&self, operation: impl FnOnce(&mut BlockScanner<'_>) -> T) -> T {
        let scanner = self.scanners.get_or(|| {
            // The Arc owns the database for at least as long as every thread-local scanner.
            let database = unsafe { &*(self.database.as_ref() as *const BlockDatabase) };
            RefCell::new(
                BlockScanner::new(database)
                    .expect("Vectorscan Betterleaks-filter scratch allocation"),
            )
        });
        operation(&mut scanner.borrow_mut())
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
        self.with_scanner(|scanner| {
            scanner.scan(input, |id, _from, _to, _flags| {
                if allowed_ids.binary_search(&id).is_ok() {
                    matched = true;
                    Scan::Terminate
                } else {
                    Scan::Continue
                }
            })
        })?;
        Ok(matched)
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
                        let BetterleaksExpr::Array { nodes } = patterns else {
                            bail!("Betterleaks matchesAny patterns must be a literal array");
                        };
                        for node in nodes {
                            let BetterleaksExpr::String { value } = node else {
                                bail!("Betterleaks matchesAny patterns must be string literals");
                            };
                            matches_any_patterns.insert(value.clone());
                        }
                    }
                    "filter.findMatch" | "findMatch" => {
                        let [_, pattern] = arguments.as_slice() else {
                            bail!("findMatch expects two arguments");
                        };
                        let BetterleaksExpr::String { value } = pattern else {
                            bail!("Betterleaks findMatch pattern must be a string literal");
                        };
                        find_match_patterns.insert(value.clone());
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
enum Value {
    Nil,
    Bool(bool),
    Integer(i64),
    Float(f64),
    String(String),
    Array(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
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
            Self::String(value) => Ok(value),
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

struct Evaluator<'a> {
    variables: BTreeMap<String, Value>,
    confidence: Option<Confidence>,
    filter_engine: &'a BetterleaksFilterEngine,
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
    let mut finding = BTreeMap::new();
    finding.insert("secret".to_string(), Value::String(context.secret.to_string()));
    finding.insert("match".to_string(), Value::String(context.full_match.to_string()));
    finding.insert("line".to_string(), Value::String(context.line.to_string()));
    finding.insert("rule_id".to_string(), Value::String(context.rule_id.to_string()));
    finding.insert("description".to_string(), Value::String(context.description.to_string()));
    finding.insert("context".to_string(), Value::String(context.full_match.to_string()));
    finding.insert("fragment_raw".to_string(), Value::String(context.fragment_raw.to_string()));
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
                .map(|(key, value)| (key.clone(), Value::String(value.clone())))
                .collect(),
        ),
    );

    let variables = BTreeMap::from([
        ("finding".to_string(), Value::Map(finding)),
        (
            "attributes".to_string(),
            Value::Map(BTreeMap::from([(
                "path".to_string(),
                Value::String(context.path.to_string()),
            )])),
        ),
    ]);
    let mut evaluator = Evaluator { variables, confidence: None, filter_engine };
    let discard = evaluator.eval(expression)?.truthy();
    Ok(BetterleaksFilterOutcome { discard, confidence: evaluator.confidence })
}

/// Evaluate the Betterleaks source prefilter for one path.
///
/// Unlike finding filters, this runs once before any content matching. Betterleaks currently
/// supplies only `attributes["path"]` to this expression; the empty finding fields keep the
/// evaluator forward-compatible without conflating source and finding filtering.
pub fn evaluate_prefilter(expression: &BetterleaksExpr, path: &str) -> Result<bool> {
    Ok(evaluate_filter(
        expression,
        &BetterleaksFilterContext {
            path,
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
    )?
    .discard)
}

impl Evaluator<'_> {
    fn eval(&mut self, expression: &BetterleaksExpr) -> Result<Value> {
        match expression {
            BetterleaksExpr::Nil => Ok(Value::Nil),
            BetterleaksExpr::Identifier { value } => {
                Ok(self.variables.get(value).cloned().unwrap_or(Value::Nil))
            }
            BetterleaksExpr::Integer { value } => Ok(Value::Integer(*value)),
            BetterleaksExpr::Float { value } => Ok(Value::Float(value.parse()?)),
            BetterleaksExpr::Bool { value } => Ok(Value::Bool(*value)),
            BetterleaksExpr::String { value } => Ok(Value::String(value.clone())),
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
            BetterleaksExpr::Chain { node } => self.eval(node),
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

    fn eval_binary(
        &mut self,
        operator: &str,
        left: &BetterleaksExpr,
        right: &BetterleaksExpr,
    ) -> Result<Value> {
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
                let ordering = left.as_f64()?.total_cmp(&right.as_f64()?);
                Ok(Value::Bool(match operator {
                    "<" => ordering.is_lt(),
                    "<=" => ordering.is_le(),
                    ">" => ordering.is_gt(),
                    ">=" => ordering.is_ge(),
                    _ => unreachable!(),
                }))
            }
            "+" => match (left, right) {
                (Value::Integer(left), Value::Integer(right)) => Ok(Value::Integer(left + right)),
                (Value::String(mut left), Value::String(right)) => {
                    left.push_str(&right);
                    Ok(Value::String(left))
                }
                (left, right) => Ok(Value::Float(left.as_f64()? + right.as_f64()?)),
            },
            "-" => numeric_binary(left, right, |left, right| left - right),
            "*" => numeric_binary(left, right, |left, right| left * right),
            "/" => Ok(Value::Float(left.as_f64()? / right.as_f64()?)),
            "%" => Ok(Value::Integer(left.as_i64()? % right.as_i64()?)),
            "contains" => Ok(Value::Bool(left.as_string()?.contains(right.as_string()?))),
            "in" => Ok(Value::Bool(match right {
                Value::Array(values) => values.iter().any(|value| values_equal(&left, value)),
                Value::String(value) => value.contains(left.as_string()?),
                _ => false,
            })),
            other => bail!("unsupported binary filter operator {other:?}"),
        }
    }

    fn member(&self, container: Value, property: Value) -> Result<Value> {
        match (container, property) {
            (Value::Map(values), Value::String(key)) => {
                Ok(values.get(&key).cloned().unwrap_or(Value::Nil))
            }
            (Value::Array(values), property) => {
                let index = usize::try_from(property.as_i64()?).ok();
                Ok(index.and_then(|index| values.get(index).cloned()).unwrap_or(Value::Nil))
            }
            (Value::String(value), property) => {
                let index = usize::try_from(property.as_i64()?).ok();
                Ok(index
                    .and_then(|index| value.as_bytes().get(index).copied())
                    .map(|byte| Value::String(char::from(byte).to_string()))
                    .unwrap_or(Value::Nil))
            }
            (Value::Nil, _) => Ok(Value::Nil),
            (container, property) => {
                bail!("cannot read member {property:?} from {container:?}")
            }
        }
    }

    fn slice(&self, value: Value, from: i64, to: i64) -> Result<Value> {
        let from = usize::try_from(from.max(0)).unwrap_or(usize::MAX);
        let to = usize::try_from(to.max(0)).unwrap_or(usize::MAX);
        match value {
            Value::String(value) => {
                let from = from.min(value.len());
                let to = to.min(value.len()).max(from);
                Ok(Value::String(String::from_utf8_lossy(&value.as_bytes()[from..to]).into_owned()))
            }
            Value::Array(values) => {
                let from = from.min(values.len());
                let to = to.min(values.len()).max(from);
                Ok(Value::Array(values[from..to].to_vec()))
            }
            other => bail!("cannot slice {other:?}"),
        }
    }

    fn call(&mut self, callee: &BetterleaksExpr, arguments: &[BetterleaksExpr]) -> Result<Value> {
        if let Some(name) = expression_name(callee)
            && name.starts_with("filter.")
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

    fn call_named(&mut self, name: &str, arguments: &[BetterleaksExpr]) -> Result<Value> {
        if name == "any" {
            return self.call_any(arguments);
        }
        let arguments = self.eval_arguments(arguments)?;
        match name {
            "filter.matchesAny" | "matchesAny" => self.matches_any(arguments),
            "filter.findMatch" | "findMatch" => self.find_match(arguments),
            "filter.containsAny" | "containsAny" => contains_any(arguments),
            "filter.entropy" | "entropy" => entropy(arguments),
            "filter.tokenRatio" | "tokenRatio" => token_ratio(arguments),
            "filter.failsTokenEfficiency" | "failsTokenEfficiency" => {
                fails_token_efficiency(arguments)
            }
            "filter.setConfidence" | "setConfidence" => self.set_confidence(arguments),
            "len" | "size" => length(arguments),
            "max" => min_or_max(arguments, true),
            "min" => min_or_max(arguments, false),
            "split" => split(arguments),
            "join" => join(arguments),
            "lastIndexOf" => last_index_of(arguments),
            "replace" => replace(arguments),
            other => bail!("unsupported Betterleaks filter function {other:?}"),
        }
    }

    fn eval_arguments(&mut self, arguments: &[BetterleaksExpr]) -> Result<Vec<Value>> {
        arguments.iter().map(|argument| self.eval(argument)).collect()
    }

    fn call_any(&mut self, arguments: &[BetterleaksExpr]) -> Result<Value> {
        let [items, predicate] = arguments else {
            bail!("any expects two arguments");
        };
        let Value::Array(items) = self.eval(items)? else {
            bail!("first argument to any must be an array");
        };
        let previous = self.variables.get("#").cloned();
        for item in items {
            self.variables.insert("#".to_string(), item);
            if self.eval(predicate)?.truthy() {
                if let Some(previous) = previous {
                    self.variables.insert("#".to_string(), previous);
                } else {
                    self.variables.remove("#");
                }
                return Ok(Value::Bool(true));
            }
        }
        if let Some(previous) = previous {
            self.variables.insert("#".to_string(), previous);
        } else {
            self.variables.remove("#");
        }
        Ok(Value::Bool(false))
    }

    fn set_confidence(&mut self, arguments: Vec<Value>) -> Result<Value> {
        let [value] = arguments.as_slice() else {
            bail!("filter.setConfidence expects one argument");
        };
        let value = value.as_string()?;
        self.confidence = Some(Confidence::from_str(value)?);
        Ok(Value::String(value.to_string()))
    }

    fn matches_any(&self, arguments: Vec<Value>) -> Result<Value> {
        let [input, patterns] = arguments.as_slice() else {
            bail!("matchesAny expects two arguments");
        };
        let patterns = strings(patterns)?;
        Ok(Value::Bool(self.filter_engine.matches_any(input.as_string()?, &patterns)?))
    }

    fn find_match(&self, arguments: Vec<Value>) -> Result<Value> {
        let [input, pattern] = arguments.as_slice() else {
            bail!("findMatch expects two arguments");
        };
        Ok(Value::String(self.filter_engine.find_match(input.as_string()?, pattern.as_string()?)?))
    }

    fn call_method(&mut self, receiver: Value, name: &str, arguments: Vec<Value>) -> Result<Value> {
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

fn numeric_binary(left: Value, right: Value, operation: fn(f64, f64) -> f64) -> Result<Value> {
    if let (Value::Integer(left), Value::Integer(right)) = (&left, &right) {
        let value = operation(*left as f64, *right as f64);
        if value.fract() == 0.0 {
            return Ok(Value::Integer(value as i64));
        }
    }
    Ok(Value::Float(operation(left.as_f64()?, right.as_f64()?)))
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Integer(left), Value::Float(right)) => (*left as f64) == *right,
        (Value::Float(left), Value::Integer(right)) => *left == (*right as f64),
        _ => left == right,
    }
}

fn strings(value: &Value) -> Result<Vec<&str>> {
    let Value::Array(values) = value else {
        bail!("expected an array of strings");
    };
    values.iter().map(Value::as_string).collect()
}

fn contains_any(arguments: Vec<Value>) -> Result<Value> {
    let [input, terms] = arguments.as_slice() else {
        bail!("containsAny expects two arguments");
    };
    let input = input.as_string()?.to_lowercase();
    Ok(Value::Bool(strings(terms)?.into_iter().any(|term| input.contains(&term.to_lowercase()))))
}

fn entropy(arguments: Vec<Value>) -> Result<Value> {
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

fn token_ratio(arguments: Vec<Value>) -> Result<Value> {
    let [input] = arguments.as_slice() else {
        bail!("tokenRatio expects one argument");
    };
    let input = input.as_string()?;
    let tokens = cl100k_base_singleton().encode_ordinary(input).len();
    let ratio = if tokens == 0 { 0.0 } else { input.len() as f64 / tokens as f64 };
    Ok(Value::Float(ratio))
}

fn fails_token_efficiency(arguments: Vec<Value>) -> Result<Value> {
    let [input] = arguments.as_slice() else {
        bail!("failsTokenEfficiency expects one argument");
    };
    let input = input.as_string()?;
    let normalized;
    let analyzed = if input.len() < 20 && (input.contains('\n') || input.contains('\r')) {
        normalized = input.replace(['\n', '\r'], "");
        &normalized
    } else {
        input
    };
    let tokens = cl100k_base_singleton().encode_ordinary(analyzed).len();
    let failed = tokens > 0 && analyzed.len() as f64 / tokens as f64 >= 2.5;
    Ok(Value::Bool(failed))
}

fn length(arguments: Vec<Value>) -> Result<Value> {
    let [value] = arguments.as_slice() else {
        bail!("len/size expects one argument");
    };
    let length = match value {
        Value::String(value) => value.len(),
        Value::Array(value) => value.len(),
        Value::Map(value) => value.len(),
        other => bail!("cannot take length of {other:?}"),
    };
    Ok(Value::Integer(length as i64))
}

fn min_or_max(arguments: Vec<Value>, maximum: bool) -> Result<Value> {
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

fn split(arguments: Vec<Value>) -> Result<Value> {
    let [input, separator] = arguments.as_slice() else {
        bail!("split expects two arguments");
    };
    Ok(Value::Array(
        input
            .as_string()?
            .split(separator.as_string()?)
            .map(|value| Value::String(value.to_string()))
            .collect(),
    ))
}

fn join(arguments: Vec<Value>) -> Result<Value> {
    let [values, separator] = arguments.as_slice() else {
        bail!("join expects two arguments");
    };
    Ok(Value::String(strings(values)?.join(separator.as_string()?)))
}

fn substring(receiver: Value, arguments: Vec<Value>) -> Result<Value> {
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
    Ok(Value::String(String::from_utf8_lossy(&input.as_bytes()[start..end]).into_owned()))
}

fn last_index_of(arguments: Vec<Value>) -> Result<Value> {
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

fn replace(arguments: Vec<Value>) -> Result<Value> {
    let [input, from, to] = arguments.as_slice() else {
        bail!("replace expects three arguments");
    };
    Ok(Value::String(input.as_string()?.replace(from.as_string()?, to.as_string()?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>(secret: &'a str, path: &'a str) -> BetterleaksFilterContext<'a> {
        BetterleaksFilterContext {
            path,
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
