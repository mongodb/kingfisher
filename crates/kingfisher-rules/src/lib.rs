#![doc = include_str!("../README.md")]

#[path = "../build_support/betterleaks.rs"]
mod betterleaks;
pub mod betterleaks_filter;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build_support/builtin_docs.rs"]
mod builtin_docs;
pub mod defaults;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build_support/imported_capabilities.rs"]
mod imported_capabilities;
pub mod legacy_aliases;
pub mod liquid_filters;
pub mod rule;
pub mod rules;
pub mod rules_database;
#[doc(hidden)]
pub mod scanner_pool;
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build_support/veles.rs"]
mod veles;

pub use rule::{
    BetterleaksAccessMap, BetterleaksAccessMapHandler, BetterleaksCapabilities, BetterleaksExpr,
    BetterleaksRevocationBindings, BetterleaksValidation, ChecksumActual, ChecksumRequirement,
    Confidence, DependsOnRule, EthereumValidation, GrpcRequest, GrpcValidation,
    HttpMultiStepRevocation, HttpRequest, HttpValidation, MultipartConfig, MultipartPart,
    PatternRequirementContext, PatternRequirements, PatternValidationResult, RULE_COMMENTS_PATTERN,
    ReportResponseData, ResponseExtractor, ResponseMatcher, Revocation, RevocationStep, Rule,
    RuleSyntax, TlsMode, Validation,
};

pub use rules::{Rules, RulesError};

pub use rules_database::{RuleCacheConfig, RuleCacheStatus, RulesDatabase, format_regex_pattern};

pub use defaults::{
    get_betterleaks_rule_files, get_betterleaks_rules, get_builtin_rule_files, get_builtin_rules,
};

pub use legacy_aliases::{LEGACY_RULE_PREFIX, legacy_aliases, legacy_family, replacements_for};

pub use liquid_filters::register_all as register_liquid_filters;
