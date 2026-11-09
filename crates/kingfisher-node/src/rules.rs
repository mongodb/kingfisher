use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use kingfisher_rules::{Confidence, RuleCacheConfig, RuleCacheStatus, Rules, RulesDatabase};
use napi::{Env, Result, bindgen_prelude::PromiseRaw};
use napi_derive::napi;
use serde_json::{Value, json};

use crate::control::{NativeCancellationToken, blocking, control, failure, invalid};

#[napi(object)]
pub struct NativeRulesOptions {
    pub paths: Vec<String>,
    pub builtins: bool,
    pub confidence: String,
    pub include_dependencies: Option<bool>,
    pub cache: bool,
    pub cache_dir: Option<String>,
}

#[napi]
#[derive(Clone)]
pub struct NativeRules {
    pub(crate) db: Arc<RulesDatabase>,
}

#[napi]
impl NativeRules {
    #[napi(getter, catch_unwind)]
    pub fn length(&self) -> u32 {
        self.db.num_rules() as u32
    }

    #[napi(getter, catch_unwind)]
    pub fn cache_status(&self) -> &'static str {
        match self.db.cache_status() {
            RuleCacheStatus::Loaded => "loaded",
            RuleCacheStatus::Stored => "stored",
            _ => "bypassed",
        }
    }

    #[napi(catch_unwind)]
    pub fn metadata(&self) -> Value {
        Value::Array(self.db.rules().iter().map(|rule| json!({
            "id": rule.id(), "name": rule.name(), "visible": rule.syntax().visible,
            "validation": rule.syntax().validation.is_some(),
            "revocation": rule.syntax().revocation.is_some()
                || rule.syntax().fallbacks.iter().any(|fallback| fallback.revocation.is_some()),
        })).collect())
    }

    #[napi(catch_unwind)]
    pub fn detail(&self, rule_id: String) -> Result<Value> {
        let (index, rule) = self
            .db
            .rules()
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.id() == rule_id)
            .ok_or_else(|| invalid("unknown exact rule ID"))?;
        let mut detail = serde_json::to_value(rule.syntax().redacted_for_inspection())
            .map_err(|_| failure("KF_RULES", "rule inspection failed"))?;
        detail["validation"] = serde_json::to_value(
            rule.syntax()
                .validation
                .as_ref()
                .map(kingfisher_rules::Validation::redacted_for_inspection),
        )
        .map_err(|_| failure("KF_RULES", "rule inspection failed"))?;
        detail["detection_regex"] = json!(self.db.anchored_regexes()[index].as_str());
        Ok(detail)
    }
}

/// Keep only threshold-selected roots and their declared dependency closure.
/// This opt-in selection happens before native regex compilation; unrelated low
/// rules never become detectors merely because a selected rule needs a helper.
fn retain_dependencies(rules: &mut Rules, confidence: Confidence) {
    let mut selected: BTreeSet<_> = rules
        .rules
        .iter()
        .filter(|(_, rule)| rule.confidence.is_at_least(&confidence))
        .map(|(id, _)| id.clone())
        .collect();
    let mut pending: Vec<_> = selected.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        if let Some(rule) = rules.rules.get(&id) {
            for dependency in rule.depends_on_rule.iter().flatten() {
                if selected.insert(dependency.rule_id.clone()) {
                    pending.push(dependency.rule_id.clone());
                }
            }
        }
    }
    rules.rules.retain(|id, _| selected.contains(id));
}

#[napi(catch_unwind)]
pub fn load_rules<'env>(
    env: &'env Env,
    options: NativeRulesOptions,
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<PromiseRaw<'env, NativeRules>> {
    let control = control(timeout_ms, token)?;
    let confidence = match options.confidence.as_str() {
        "low" => Confidence::Low,
        "medium" => Confidence::Medium,
        "high" => Confidence::High,
        _ => return Err(invalid("confidence must be low, medium, or high")),
    };
    let include_dependencies = options.include_dependencies.unwrap_or(false);
    let load_confidence = if include_dependencies { Confidence::Low } else { confidence };
    env.spawn_future(blocking(control, move |control| {
        crate::control::compilation_stack(move || {
            let mut rules = if options.builtins {
                kingfisher_rules::get_builtin_rules(Some(load_confidence))
                    .map_err(|_| failure("KF_RULES", "built-in catalog could not be loaded"))?
            } else {
                Rules::new()
            };
            control.check().map_err(crate::control::interrupted)?;
            if !options.paths.is_empty() {
                rules.update(
                    Rules::from_paths(options.paths, load_confidence)
                        .map_err(|_| failure("KF_RULES", "custom rules could not be loaded"))?,
                );
            }
            if include_dependencies {
                retain_dependencies(&mut rules, confidence);
            }
            if rules.is_empty() {
                return Err(invalid("no rules loaded"));
            }
            let database = if options.cache {
                RulesDatabase::from_rule_collection_with_cache(
                    rules,
                    &RuleCacheConfig::from_dir_or_env(options.cache_dir.map(PathBuf::from)),
                )
            } else {
                RulesDatabase::from_rule_collection(rules)
            }
            .map_err(|_| failure("KF_RULES", "rule compilation failed"))?;
            control.check().map_err(crate::control::interrupted)?;
            Ok(NativeRules { db: Arc::new(database) })
        })
    }))
}
