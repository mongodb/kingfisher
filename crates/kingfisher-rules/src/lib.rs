//! Rule definitions and database for the Kingfisher secret scanner.
//!
//! This crate provides:
//! - [`Rule`] and [`RuleSyntax`] - Rule definitions
//! - [`RulesDatabase`] - Compiled rules ready for scanning
//! - [`Confidence`] - Rule confidence levels
//! - [`Rules`] - Rule collection and loading
//! - YAML parsing for rule files
//! - Builtin rules embedded in the crate

pub mod defaults;
pub mod liquid_filters;
pub mod rule;
pub mod rules;
pub mod rules_database;

// Re-export rule types
pub use rule::{
    ChecksumActual, ChecksumRequirement, Confidence, DependsOnRule, GrpcRequest, GrpcValidation,
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
pub use defaults::get_builtin_rules;

// Re-export liquid_filters registration
pub use liquid_filters::register_all as register_liquid_filters;
