//! Rule definitions and database for the Kingfisher secret scanner.
//!
//! This crate provides:
//! - [`Rule`] and [`RuleSyntax`] - Rule definitions
//! - [`RulesDatabase`] - Compiled rules ready for scanning
//! - [`Confidence`] - Rule confidence levels
//! - [`Rules`] - Rule collection and loading
//! - YAML parsing for rule files
//! - Betterleaks- and Veles-derived default rules embedded in the crate

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
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build_support/veles.rs"]
mod veles;

// Re-export rule types
pub use rule::{
    BetterleaksAccessMap, BetterleaksAccessMapHandler, BetterleaksCapabilities, BetterleaksExpr,
    BetterleaksRevocationBindings, BetterleaksValidation, ChecksumActual, ChecksumRequirement,
    Confidence, DependsOnRule, EthereumValidation, GrpcRequest, GrpcValidation,
    HttpMultiStepRevocation, HttpRequest, HttpValidation, MultipartConfig, MultipartPart,
    PatternRequirementContext, PatternRequirements, PatternValidationResult, RULE_COMMENTS_PATTERN,
    ReportResponseData, ResponseExtractor, ResponseMatcher, Revocation, RevocationStep, Rule,
    RuleSyntax, TlsMode, Validation,
};

// Re-export Rules collection
pub use rules::{Rules, RulesError};

// Re-export RulesDatabase
pub use rules_database::{RuleCacheConfig, RulesDatabase, format_regex_pattern};

// Re-export defaults
pub use defaults::{
    get_betterleaks_rule_files, get_betterleaks_rules, get_builtin_rule_files, get_builtin_rules,
};

// Re-export legacy 1.x rule-selector aliases
pub use legacy_aliases::{LEGACY_RULE_PREFIX, legacy_aliases, legacy_family, replacements_for};

// Re-export liquid_filters registration
pub use liquid_filters::register_all as register_liquid_filters;
