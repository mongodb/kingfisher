use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::{
    cli,
    cli::commands::rules::RuleSpecifierArgs,
    defaults::get_builtin_rules,
    rules::{
        Rules,
        rule::{BetterleaksExpr, Confidence, Rule},
    },
    util::Counted,
};
#[derive(Error, Debug)]
pub enum RuleLoaderError {
    #[error("Failed to load builtin rules")]
    BuiltinLoadError,

    #[error("Failed to load rules from additional paths")]
    AdditionalPathLoadError,

    #[error("Unknown rule: `{0}`")]
    UnknownRule(String),
}
pub struct RuleLoader {
    load_builtins: bool,
    additional_load_paths: Vec<PathBuf>,
    enabled_rule_ids: Option<Vec<String>>,
    excluded_rule_ids: Vec<String>,
}

impl Default for RuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleLoader {
    pub fn new() -> Self {
        Self {
            load_builtins: true,
            additional_load_paths: Vec::new(),
            enabled_rule_ids: None, // None means "all rules enabled"
            excluded_rule_ids: Vec::new(),
        }
    }

    pub fn load_builtins(mut self, load_builtins: bool) -> Self {
        self.load_builtins = load_builtins;
        self
    }

    pub fn additional_rule_load_paths<P: AsRef<Path>, I: IntoIterator<Item = P>>(
        mut self,
        paths: I,
    ) -> Self {
        self.additional_load_paths.extend(paths.into_iter().map(|p| p.as_ref().to_owned()));
        self
    }

    pub fn enable_rule_ids<S: AsRef<str>, I: IntoIterator<Item = S>>(mut self, ids: I) -> Self {
        let ids: Vec<String> = ids.into_iter().map(|s| s.as_ref().to_string()).collect();
        if ids.iter().any(|id| id == "all") {
            self.enabled_rule_ids = None; // Reset to "all rules enabled"
        } else {
            self.enabled_rule_ids = Some(ids);
        }
        self
    }

    pub fn exclude_rule_ids<S: AsRef<str>, I: IntoIterator<Item = S>>(mut self, ids: I) -> Self {
        self.excluded_rule_ids.extend(ids.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    pub fn load(&self, args: &cli::commands::scan::ScanArgs) -> Result<LoadedRules> {
        let confidence = Confidence::from(args.confidence);
        self.load_with_confidence(confidence)
    }

    fn load_with_confidence(&self, confidence: Confidence) -> Result<LoadedRules> {
        let mut id_to_rule: BTreeMap<String, Rule> = BTreeMap::new();
        let mut betterleaks_prefilter = None;

        if self.load_builtins {
            let builtin_rules = get_builtin_rules(Some(Confidence::Low))
                .context(RuleLoaderError::BuiltinLoadError)?;
            betterleaks_prefilter = builtin_rules.betterleaks_prefilter.clone();
            for rule_syntax in builtin_rules {
                let id = rule_syntax.id.clone();
                id_to_rule.insert(id, Rule::new(rule_syntax));
            }
        }

        if !self.additional_load_paths.is_empty() {
            let custom_rules = Rules::from_paths(&self.additional_load_paths, Confidence::Low)
                .context(RuleLoaderError::AdditionalPathLoadError)?;
            if betterleaks_prefilter.is_none() {
                betterleaks_prefilter = custom_rules.betterleaks_prefilter.clone();
            }
            for rule_syntax in custom_rules {
                let id = rule_syntax.id.clone();
                id_to_rule.insert(id, Rule::new(rule_syntax));
            }
        }

        // Borrowing callers still receive the same runtime confidence behavior as the owned scan
        // path. Mark every helper reachable from a potentially reportable rule; selector-specific
        // resolution below narrows the compiled set further.
        let mut helper_ids = HashSet::new();
        let mut pending: Vec<String> = id_to_rule
            .values()
            .filter(|rule| {
                rule.confidence().is_at_least(&confidence)
                    || rule.betterleaks_filter().is_some_and(expression_can_set_confidence)
            })
            .map(|rule| rule.id().to_string())
            .collect();
        let mut traversed = HashSet::new();
        while let Some(rule_id) = pending.pop() {
            if !traversed.insert(rule_id.clone()) {
                continue;
            }
            let Some(rule) = id_to_rule.get(&rule_id) else {
                continue;
            };
            for dependency in rule.syntax().depends_on_rule.iter().flatten() {
                if id_to_rule.contains_key(&dependency.rule_id) {
                    helper_ids.insert(dependency.rule_id.clone());
                    pending.push(dependency.rule_id.clone());
                }
            }
        }
        for (id, rule) in &mut id_to_rule {
            rule.set_runtime_confidence_filter(confidence, helper_ids.contains(id));
        }

        let loaded = LoadedRules {
            id_to_rule,
            betterleaks_prefilter,
            minimum_confidence: confidence,
            enabled_rule_ids: self.enabled_rule_ids.clone(),
            excluded_rule_ids: self.excluded_rule_ids.clone(),
        };
        Ok(loaded)
    }

    pub fn from_rule_specifiers(specs: &RuleSpecifierArgs) -> Self {
        Self::new()
            .load_builtins(specs.load_builtins)
            .additional_rule_load_paths(specs.rules_path.as_slice())
            .enable_rule_ids(specs.rule.iter())
            .exclude_rule_ids(specs.exclude_rule.iter())
    }
}

pub struct LoadedRules {
    id_to_rule: BTreeMap<String, Rule>,
    betterleaks_prefilter: Option<BetterleaksExpr>,
    minimum_confidence: Confidence,
    enabled_rule_ids: Option<Vec<String>>,
    excluded_rule_ids: Vec<String>,
}

impl LoadedRules {
    #[inline]
    pub fn num_rules(&self) -> usize {
        self.id_to_rule.len()
    }

    #[inline]
    pub fn iter_rules(&self) -> impl Iterator<Item = &Rule> {
        self.id_to_rule.values()
    }

    /// Get a reference to the underlying rule map (rule ID -> Rule).
    #[inline]
    pub fn id_to_rule(&self) -> &BTreeMap<String, Rule> {
        &self.id_to_rule
    }

    /// Return the Betterleaks source prefilter when at least one selected rule is Betterleaks.
    pub fn betterleaks_prefilter_for<T: std::borrow::Borrow<Rule>>(
        &self,
        rules: &[T],
    ) -> Option<BetterleaksExpr> {
        let selected_betterleaks =
            rules.iter().any(|rule| rule.borrow().id().starts_with("betterleaks."));
        selected_betterleaks.then(|| self.betterleaks_prefilter.clone()).flatten()
    }

    fn selector_matches_rule(selector: &str, rule_id: &str) -> bool {
        selector == "all"
            || rule_id == selector
            || (rule_id.starts_with(selector)
                && matches!(rule_id.as_bytes().get(selector.len()), Some(b'.' | b'-')))
    }
    fn resolve_rule_selectors(&self, selectors: &[String]) -> Result<Vec<&Rule>> {
        let mut resolved = Vec::new();
        let mut seen = HashSet::new();

        for selector in selectors {
            let mut selectors_to_try = vec![std::borrow::Cow::Borrowed(selector.as_str())];
            if selector != "all"
                && !selector.starts_with("betterleaks.")
                && !selector.starts_with("kingfisher.")
            {
                selectors_to_try.push(std::borrow::Cow::Owned(format!("betterleaks.{selector}")));
                selectors_to_try.push(std::borrow::Cow::Owned(format!("kingfisher.{selector}")));
            }

            let mut matched_any = false;
            for selector_to_try in selectors_to_try {
                for (id, rule) in &self.id_to_rule {
                    if Self::selector_matches_rule(&selector_to_try, id) {
                        matched_any = true;
                        if seen.insert(id.clone()) {
                            resolved.push(rule);
                        }
                    }
                }
                if matched_any {
                    break;
                }
            }

            // A Kingfisher 1.x selector that matched nothing is far more likely to
            // be a stale CI config or `rules.disabled` entry than a typo, because
            // 2.0 renamed every built-in rule. Fall back to the alias table so
            // those keep working, and tell the operator what to migrate to.
            if !matched_any && let Some(replacements) = kingfisher_rules::replacements_for(selector)
            {
                for replacement in replacements {
                    for (id, rule) in &self.id_to_rule {
                        if Self::selector_matches_rule(replacement, id) {
                            matched_any = true;
                            if seen.insert(id.clone()) {
                                resolved.push(rule);
                            }
                        }
                    }
                }

                if matched_any {
                    warn_legacy_selector_once(selector, replacements);
                }
            }

            if !matched_any {
                if selector.starts_with(kingfisher_rules::LEGACY_RULE_PREFIX) {
                    error!(
                        "Unknown rule `{}`. This looks like a Kingfisher 1.x rule ID, but no \
                         built-in replacement is known and no `kingfisher.*` rules were loaded. \
                         Pass the 1.x catalog with `--rules-path`, or use a 2.x rule ID \
                         (see `kingfisher rules list`).",
                        selector
                    );
                } else {
                    error!("Unknown rule `{}` encountered", selector);
                }
                bail!(RuleLoaderError::UnknownRule(selector.clone()));
            }
        }

        Ok(resolved)
    }

    pub fn resolve_enabled_rules(&self) -> Result<Vec<&Rule>> {
        let (selected_ids, _) = self.resolved_rule_ids()?;
        Ok(self
            .id_to_rule
            .iter()
            .filter(|(id, _)| selected_ids.contains(*id))
            .map(|(_, rule)| rule)
            .collect())
    }

    pub fn resolve_enabled_rules_owned(&self) -> Result<Vec<Rule>> {
        let (selected_ids, helper_ids) = self.resolved_rule_ids()?;

        let resolved_rules: Vec<Rule> = self
            .id_to_rule
            .iter()
            .filter(|(id, _)| selected_ids.contains(*id))
            .map(|(id, rule)| {
                let mut rule = rule.clone();
                rule.set_runtime_confidence_filter(
                    self.minimum_confidence,
                    helper_ids.contains(id),
                );
                rule
            })
            .collect();

        info!("Loaded {}", Counted::regular(resolved_rules.len(), "rule"));
        for rule in &resolved_rules {
            trace!("Using rule `{}`: {}", rule.id(), rule.name());
        }
        Ok(resolved_rules)
    }

    fn resolved_rule_ids(&self) -> Result<(HashSet<String>, HashSet<String>)> {
        let primary_ids: HashSet<String> = self
            .resolve_selected_rules()?
            .into_iter()
            .filter(|rule| {
                rule.confidence().is_at_least(&self.minimum_confidence)
                    || rule.betterleaks_filter().is_some_and(expression_can_set_confidence)
            })
            .map(|rule| rule.id().to_string())
            .collect();
        let mut selected_ids = primary_ids.clone();
        let mut helper_ids = HashSet::new();
        let mut pending: Vec<String> = primary_ids.into_iter().collect();
        let excluded_ids = self.excluded_rule_ids()?;
        while let Some(rule_id) = pending.pop() {
            let Some(rule) = self.id_to_rule.get(&rule_id) else {
                continue;
            };
            for dependency in rule.syntax().depends_on_rule.iter().flatten() {
                if excluded_ids.contains(&dependency.rule_id) {
                    continue;
                }
                if self.id_to_rule.contains_key(&dependency.rule_id) {
                    helper_ids.insert(dependency.rule_id.clone());
                    if selected_ids.insert(dependency.rule_id.clone()) {
                        pending.push(dependency.rule_id.clone());
                    }
                }
            }
        }
        Ok((selected_ids, helper_ids))
    }

    fn resolve_selected_rules(&self) -> Result<Vec<&Rule>> {
        let mut resolved_rules = match &self.enabled_rule_ids {
            // No selectors ⇒ every rule is enabled
            None => {
                debug!("Using all available rules");
                self.iter_rules().collect()
            }

            // At least one selector was given
            Some(selectors) => self.resolve_rule_selectors(selectors)?,
        };

        let excluded_ids = self.excluded_rule_ids()?;
        resolved_rules.retain(|rule| !excluded_ids.contains(rule.id()));
        Ok(resolved_rules)
    }

    fn excluded_rule_ids(&self) -> Result<HashSet<String>> {
        if self.excluded_rule_ids.is_empty() {
            return Ok(HashSet::new());
        }
        Ok(self
            .resolve_rule_selectors(&self.excluded_rule_ids)?
            .into_iter()
            .map(|rule| rule.id().to_string())
            .collect())
    }
}

fn expression_can_set_confidence(expression: &BetterleaksExpr) -> bool {
    match expression {
        BetterleaksExpr::Identifier { value } => value == "setConfidence",
        BetterleaksExpr::Unary { node, .. }
        | BetterleaksExpr::Chain { node }
        | BetterleaksExpr::Predicate { node } => expression_can_set_confidence(node),
        BetterleaksExpr::Binary { left, right, .. } => {
            expression_can_set_confidence(left) || expression_can_set_confidence(right)
        }
        BetterleaksExpr::Member { node, property, .. } => {
            expression_can_set_confidence(node) || expression_can_set_confidence(property)
        }
        BetterleaksExpr::Slice { node, from, to } => {
            expression_can_set_confidence(node)
                || expression_can_set_confidence(from)
                || expression_can_set_confidence(to)
        }
        BetterleaksExpr::Call { callee, arguments } => {
            expression_can_set_confidence(callee)
                || arguments.iter().any(expression_can_set_confidence)
        }
        BetterleaksExpr::Builtin { name, arguments } => {
            name == "setConfidence" || arguments.iter().any(expression_can_set_confidence)
        }
        BetterleaksExpr::Conditional { cond, exp1, exp2 } => {
            expression_can_set_confidence(cond)
                || expression_can_set_confidence(exp1)
                || expression_can_set_confidence(exp2)
        }
        BetterleaksExpr::VariableDeclarator { value, expr, .. } => {
            expression_can_set_confidence(value) || expression_can_set_confidence(expr)
        }
        BetterleaksExpr::Sequence { nodes } | BetterleaksExpr::Array { nodes } => {
            nodes.iter().any(expression_can_set_confidence)
        }
        BetterleaksExpr::Map { pairs } => pairs.iter().any(expression_can_set_confidence),
        BetterleaksExpr::Pair { key, value } => {
            expression_can_set_confidence(key) || expression_can_set_confidence(value)
        }
        BetterleaksExpr::Pointer { name } => name == "setConfidence",
        BetterleaksExpr::String { value } => {
            value == "setConfidence" || value == "filter.setConfidence"
        }
        BetterleaksExpr::Nil
        | BetterleaksExpr::Integer { .. }
        | BetterleaksExpr::Float { .. }
        | BetterleaksExpr::Bool { .. } => false,
    }
}

/// Warn once per selector that a Kingfisher 1.x rule ID was resolved through the
/// alias table.
///
/// Selector resolution runs for both the enabled and excluded lists, and may run
/// more than once per scan, so the warning is deduplicated to keep it actionable
/// rather than noisy.
fn warn_legacy_selector_once(selector: &str, replacements: &[String]) {
    use std::sync::{Mutex, OnceLock};

    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let is_new = match warned.lock() {
        Ok(mut seen) => seen.insert(selector.to_string()),
        // A poisoned lock only means another thread panicked while warning;
        // warning again is harmless and better than swallowing it.
        Err(_) => true,
    };
    if !is_new {
        return;
    }

    warn!(
        "Rule selector `{}` is a Kingfisher 1.x ID. Kingfisher 2.0 renamed the built-in \
         catalog; resolving it as `{}` for now. Update your configuration - this fallback \
         will be removed in a future release.",
        selector,
        replacements.join("`, `")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Confidence, DependsOnRule, RuleSyntax};

    fn test_rule(id: &str) -> Rule {
        Rule::new(RuleSyntax {
            name: format!("Rule {id}"),
            id: id.to_string(),
            pattern: "(?x)(test_secret)".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: Vec::new(),
            negative_examples: Vec::new(),
            references: Vec::new(),
            validation: None,
            revocation: None,
            depends_on_rule: Vec::new(),
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })
    }

    fn test_rule_with(
        id: &str,
        confidence: Confidence,
        filter: Option<BetterleaksExpr>,
        dependencies: Vec<DependsOnRule>,
    ) -> Rule {
        let mut rule = test_rule(id);
        rule.syntax.confidence = confidence;
        rule.syntax.betterleaks_filter = filter;
        rule.syntax.depends_on_rule = dependencies.into_iter().map(Some).collect();
        Rule::new(rule.syntax)
    }

    fn loaded_rules(enabled: Option<Vec<&str>>, excluded: Vec<&str>) -> LoadedRules {
        let mut id_to_rule = BTreeMap::new();
        for id in
            ["betterleaks.demo-1", "betterleaks.demo-2", "custom.other.1", "kingfisher.legacy.1"]
        {
            id_to_rule.insert(id.to_string(), test_rule(id));
        }
        LoadedRules {
            id_to_rule,
            betterleaks_prefilter: None,
            minimum_confidence: Confidence::Low,
            enabled_rule_ids: enabled.map(|ids| ids.into_iter().map(str::to_string).collect()),
            excluded_rule_ids: excluded.into_iter().map(str::to_string).collect(),
        }
    }

    /// Rules named the way the real 2.x catalog names them, for legacy-alias tests.
    fn catalog_shaped_rules(enabled: Option<Vec<&str>>) -> LoadedRules {
        let mut id_to_rule = BTreeMap::new();
        for id in [
            "betterleaks.aws-access-token",
            "betterleaks.aws-secret-access-key",
            "betterleaks.microsoft-teams-webhook",
            "veles.secrets/slackappleveltoken",
            "betterleaks.slack-bot-token",
        ] {
            id_to_rule.insert(id.to_string(), test_rule(id));
        }
        LoadedRules {
            id_to_rule,
            betterleaks_prefilter: None,
            minimum_confidence: Confidence::Low,
            enabled_rule_ids: enabled.map(|ids| ids.into_iter().map(str::to_string).collect()),
            excluded_rule_ids: Vec::new(),
        }
    }

    #[test]
    fn legacy_selectors_resolve_through_the_alias_table() {
        // `--rule kingfisher.aws.1` in an existing CI config must keep working
        // after the 2.0 rename instead of hard-erroring.
        let loaded = catalog_shaped_rules(Some(vec!["kingfisher.aws.1"]));
        let mut ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();
        ids.sort();

        assert_eq!(ids, vec!["betterleaks.aws-access-token", "betterleaks.aws-secret-access-key"]);
    }

    #[test]
    fn legacy_selectors_resolve_across_both_namespaces() {
        let loaded = catalog_shaped_rules(Some(vec!["kingfisher.slack.6"]));
        let mut ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();
        ids.sort();

        assert_eq!(ids, vec!["betterleaks.slack-bot-token", "veles.secrets/slackappleveltoken"]);
    }

    #[test]
    fn legacy_selectors_follow_provider_renames() {
        let loaded = catalog_shaped_rules(Some(vec!["kingfisher.msteams.1"]));
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["betterleaks.microsoft-teams-webhook"]);
    }

    #[test]
    fn directly_loaded_legacy_rules_win_over_the_alias_table() {
        // When the operator brings the 1.x catalog via `--rules-path`, the exact
        // ID must match and the alias fallback must stay out of the way.
        let loaded = loaded_rules(Some(vec!["kingfisher.legacy.1"]), vec![]);
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["kingfisher.legacy.1"]);
    }

    #[test]
    fn unknown_legacy_selectors_still_error() {
        let loaded = catalog_shaped_rules(Some(vec!["kingfisher.no-such-provider.1"]));
        let error = loaded.resolve_enabled_rules().unwrap_err();

        assert!(
            error.to_string().contains("kingfisher.no-such-provider.1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolves_all_rules_except_excluded_ids() {
        let loaded = loaded_rules(None, vec!["betterleaks.demo-1"]);
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["betterleaks.demo-2", "custom.other.1", "kingfisher.legacy.1"]);
    }

    #[test]
    fn applies_exclusions_after_enabled_selectors() {
        let loaded = loaded_rules(Some(vec!["demo"]), vec!["betterleaks.demo-1"]);
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["betterleaks.demo-2"]);
    }

    #[test]
    fn resolves_multiple_enabled_and_excluded_selectors() {
        let loaded = loaded_rules(
            Some(vec!["demo", "custom.other"]),
            vec!["betterleaks.demo-1", "custom.other.1"],
        );
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["betterleaks.demo-2"]);
    }

    #[test]
    fn unknown_exclusion_selector_is_an_error() {
        let loaded = loaded_rules(None, vec!["betterleaks.missing"]);

        assert!(loaded.resolve_enabled_rules().is_err());
    }

    #[test]
    fn resolves_legacy_kingfisher_short_selector_after_betterleaks_fallback() {
        let loaded = loaded_rules(Some(vec!["legacy.1"]), Vec::new());
        let ids: Vec<_> =
            loaded.resolve_enabled_rules().unwrap().into_iter().map(Rule::id).collect();

        assert_eq!(ids, vec!["kingfisher.legacy.1"]);
    }

    #[test]
    fn builtins_are_namespaced_imported_rules() {
        let loaded =
            RuleLoader::new().load_builtins(true).load_with_confidence(Confidence::Low).unwrap();

        assert!(loaded.num_rules() >= 400);
        assert!(
            loaded.iter_rules().all(
                |rule| rule.id().starts_with("betterleaks.") || rule.id().starts_with("veles.")
            )
        );
    }

    #[test]
    fn betterleaks_prefilter_is_used_only_for_selected_betterleaks_rules() {
        let loaded =
            RuleLoader::new().load_with_confidence(Confidence::Low).expect("builtins should load");
        let betterleaks_rules = loaded.resolve_enabled_rules().unwrap();
        assert!(loaded.betterleaks_prefilter_for(&betterleaks_rules).is_some());

        let custom_rule = test_rule("custom.only");
        assert!(loaded.betterleaks_prefilter_for(&[&custom_rule]).is_none());
    }

    #[test]
    fn exact_aws_selector_includes_medium_component_at_high_confidence() {
        let loaded = RuleLoader::new()
            .enable_rule_ids(["betterleaks.aws-access-token"])
            .load_with_confidence(Confidence::High)
            .unwrap();

        let rules = loaded.resolve_enabled_rules_owned().unwrap();
        let ids: Vec<_> = rules.iter().map(Rule::id).collect();
        assert_eq!(ids, ["betterleaks.aws-access-token", "betterleaks.aws-secret-access-key"]);
        assert!(
            rules
                .iter()
                .find(|rule| rule.id() == "betterleaks.aws-secret-access-key")
                .unwrap()
                .is_runtime_dependency_helper()
        );
    }

    #[test]
    fn dependency_closure_is_transitive_and_explicit_exclusions_win() {
        let leaf = test_rule_with("custom.leaf", Confidence::Low, None, vec![]);
        let helper = test_rule_with(
            "custom.helper",
            Confidence::Medium,
            None,
            vec![DependsOnRule {
                rule_id: "custom.leaf".into(),
                variable: "LEAF".into(),
                optional: false,
                within: None,
            }],
        );
        let primary = test_rule_with(
            "custom.primary",
            Confidence::High,
            None,
            vec![DependsOnRule {
                rule_id: "custom.helper".into(),
                variable: "HELPER".into(),
                optional: false,
                within: None,
            }],
        );
        let loaded = LoadedRules {
            id_to_rule: [leaf, helper, primary]
                .into_iter()
                .map(|rule| (rule.id().to_string(), rule))
                .collect(),
            betterleaks_prefilter: None,
            minimum_confidence: Confidence::High,
            enabled_rule_ids: Some(vec!["custom.primary".into()]),
            excluded_rule_ids: vec![],
        };
        let resolved = loaded.resolve_enabled_rules_owned().unwrap();
        let ids: Vec<_> = resolved.iter().map(Rule::id).collect();
        assert_eq!(ids, ["custom.helper", "custom.leaf", "custom.primary"]);

        let excluded = LoadedRules { excluded_rule_ids: vec!["custom.helper".into()], ..loaded };
        let resolved = excluded.resolve_enabled_rules_owned().unwrap();
        let ids: Vec<_> = resolved.iter().map(Rule::id).collect();
        assert_eq!(ids, ["custom.primary"]);
    }

    #[test]
    fn dynamically_adjustable_rules_load_below_static_confidence() {
        let filter = BetterleaksExpr::Call {
            callee: Box::new(BetterleaksExpr::Member {
                node: Box::new(BetterleaksExpr::Identifier { value: "filter".into() }),
                property: Box::new(BetterleaksExpr::String { value: "setConfidence".into() }),
                optional: false,
                method: false,
            }),
            arguments: vec![BetterleaksExpr::String { value: "high".into() }],
        };
        let promoted = test_rule_with("custom.promoted", Confidence::Low, Some(filter), vec![]);
        let ordinary = test_rule_with("custom.ordinary", Confidence::Low, None, vec![]);
        let loaded = LoadedRules {
            id_to_rule: [promoted, ordinary]
                .into_iter()
                .map(|rule| (rule.id().to_string(), rule))
                .collect(),
            betterleaks_prefilter: None,
            minimum_confidence: Confidence::High,
            enabled_rule_ids: Some(vec!["custom.promoted".into()]),
            excluded_rule_ids: vec![],
        };

        let rules = loaded.resolve_enabled_rules_owned().unwrap();
        assert_eq!(rules.iter().map(Rule::id).collect::<Vec<_>>(), ["custom.promoted"]);
        assert_eq!(rules[0].runtime_minimum_confidence(), Confidence::High);
    }

    #[test]
    fn bundled_generic_rules_are_not_available() {
        let result = RuleLoader::new()
            .enable_rule_ids(["betterleaks.generic-api-key"])
            .load_with_confidence(Confidence::Low)
            .and_then(|loaded| loaded.resolve_enabled_rules_owned());

        assert!(result.is_err());
    }
}
