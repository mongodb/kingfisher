//! Compiled rules database for pattern matching.
//!
//! This module re-exports types from [`kingfisher_rules::rules_database`].

pub use kingfisher_rules::rules_database::{
    DEFAULT_RULE_CACHE_MAX_AGE, DEFAULT_RULE_CACHE_MAX_ENTRIES, RuleCacheConfig,
    RuleCachePruneConfig, RuleCachePruneSummary, RulesDatabase, compute_rule_cache_key,
    format_regex_pattern, prune_rule_cache,
};
