use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use thiserror::Error;
use tracing::{debug, error, info, trace};

use crate::{
    cli,
    cli::commands::rules::RuleSpecifierArgs,
    defaults::get_builtin_rules,
    rules::{
        rule::{Confidence, Rule},
        Rules,
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
    enabled_rule_ids: Option<HashSet<String>>,
}
impl RuleLoader {
    pub fn new() -> Self {
        Self {
            load_builtins: true,
            additional_load_paths: Vec::new(),
            enabled_rule_ids: None, // None means "all rules enabled"
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
        if ids.contains(&"all".to_string()) {
            self.enabled_rule_ids = None; // Reset to "all rules enabled"
        } else {
            self.enabled_rule_ids = Some(ids.into_iter().collect());
        }
        self
    }

    pub fn load(&self, args: &cli::commands::scan::ScanArgs) -> Result<LoadedRules> {
        let confidence = Confidence::from(args.confidence);
        let mut rules = Rules::new();
        if self.load_builtins {
            let builtin_rules =
                get_builtin_rules(Some(confidence)).context(RuleLoaderError::BuiltinLoadError)?;
            rules.update(builtin_rules);
        }
        if !self.additional_load_paths.is_empty() {
            let custom = Rules::from_paths(&self.additional_load_paths, confidence)
                .context(RuleLoaderError::AdditionalPathLoadError)?;
            rules.update(custom);
        }
        let mut rules = rules.rules;
        rules.sort_by(|r1, r2| r1.id.cmp(&r2.id));
        let id_to_rule: HashMap<String, Rule> =
            rules.into_iter().map(|r| (r.id.clone(), Rule::new(r))).collect();
        Ok(LoadedRules { id_to_rule, enabled_rule_ids: self.enabled_rule_ids.clone() })
    }

    pub fn from_rule_specifiers(specs: &RuleSpecifierArgs) -> Self {
        Self::new()
            .load_builtins(specs.load_builtins)
            .additional_rule_load_paths(specs.rules_path.as_slice())
            .enable_rule_ids(specs.rule.iter())
    }
}
pub struct LoadedRules {
    id_to_rule: HashMap<String, Rule>,
    enabled_rule_ids: Option<HashSet<String>>,
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

    pub fn resolve_enabled_rules(&self) -> Result<Vec<&Rule>> {
        let resolved_rules = match &self.enabled_rule_ids {
            // No selectors ⇒ every rule is enabled
            None => {
                debug!("Using all available rules");
                self.iter_rules().collect()
            }

            // At least one selector was given
            Some(selectors) => {
                let mut resolved = Vec::new();

                // For each selector, collect rules that match it
                for selector in selectors {
                    let mut matched_any = false;

                    for (id, rule) in &self.id_to_rule {
                        // Exact match OR “selector.” is a prefix of id
                        if id == selector
                            || (id.starts_with(selector)
                                && id.as_bytes().get(selector.len()) == Some(&b'.'))
                        {
                            resolved.push(rule);
                            matched_any = true;
                        }
                    }

                    // If nothing matched this selector, surface an error
                    if !matched_any {
                        error!("Unknown rule `{}` encountered", selector);
                        bail!(RuleLoaderError::UnknownRule(selector.clone()));
                    }
                }

                resolved
            }
        };

        // Deduplicate & sort for deterministic order
        let mut resolved_rules = resolved_rules;
        sort_and_deduplicate_rules(&mut resolved_rules);

        info!("Loaded {}", Counted::regular(resolved_rules.len(), "rule"),);
        for rule in &resolved_rules {
            trace!("Using rule `{}`: {}", rule.id(), rule.name());
        }
        Ok(resolved_rules)
    }
}
fn sort_and_deduplicate_rules(rules: &mut Vec<&Rule>) {
    rules.sort_by(|r1, r2| r1.id().cmp(r2.id()));
    rules.dedup_by(|r1, r2| r1.id() == r2.id());
}
