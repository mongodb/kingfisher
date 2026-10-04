//! Load rules, manage their compiled cache, and record rule metadata.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use indicatif::ProgressBar;
use tracing::info;

use crate::{
    cli::commands::scan,
    findings_store::FindingsStore,
    rule_loader::RuleLoader,
    rules_database::{
        RuleCacheConfig, RuleCachePruneConfig, RulesDatabase, compute_rule_cache_key,
        prune_rule_cache,
    },
};

/// Load selected rules, compile their database, and record metadata in the datastore.
///
/// # Errors
///
/// Returns rule loading, selection, regex/filter compilation, and native allocation errors.
///
/// # Panics
///
/// Panics if the caller's datastore mutex has been poisoned.
pub fn load_and_record_rules(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    use_progress: bool,
) -> Result<RulesDatabase> {
    let init_progress =
        if use_progress { ProgressBar::new_spinner() } else { ProgressBar::hidden() };
    let rules_db = {
        let loaded = RuleLoader::from_rule_specifiers(&args.rules)
            .load(args)
            .context("Failed to load rules")?;
        let resolved = loaded.resolve_enabled_rules_owned().context("Failed to resolve rules")?;
        let betterleaks_prefilter = loaded.betterleaks_prefilter_for(&resolved);
        // Apply min_entropy override if specified
        let rules: Vec<_> = resolved
            .into_iter()
            .map(|mut rule| {
                if let Some(min_entropy) = args.min_entropy {
                    let _ = rule.set_entropy(min_entropy);
                }
                rule
            })
            .collect();
        if args.rule_cache.enabled() {
            let cache = RuleCacheConfig::from_dir_or_env(args.rule_cache.rule_cache_dir.clone());
            info!(cache_dir = %cache.cache_dir().display(), "Using Vectorscan rule cache");
            if args.rule_cache.prune_rule_cache {
                let protected_cache_key = compute_rule_cache_key(&rules);
                let summary = prune_rule_cache(
                    &cache,
                    &RuleCachePruneConfig {
                        max_entries: args.rule_cache.rule_cache_max_entries,
                        max_age: args.rule_cache.rule_cache_max_age,
                        protected_cache_key: Some(protected_cache_key),
                        dry_run: false,
                    },
                );
                info!(
                    cache_dir = %cache.cache_dir().display(),
                    scanned_entries = summary.scanned_entries,
                    valid_entries = summary.valid_entries,
                    removed_entries = summary.removed_entries,
                    removed_bytes = summary.removed_bytes,
                    removal_errors = summary.removal_errors,
                    "Pruned Vectorscan rule cache"
                );
            }
            RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
                rules,
                &cache,
                betterleaks_prefilter,
            )
            .context("Failed to compile rules with Vectorscan cache")?
        } else {
            RulesDatabase::from_rules_with_betterleaks_prefilter(rules, betterleaks_prefilter)
                .context("Failed to compile rules")?
        }
    };
    init_progress.set_message("Recording rules...");
    datastore.lock().unwrap().record_rules(rules_db.rules());
    Ok(rules_db)
}
