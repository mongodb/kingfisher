//! Rule definitions for secret detection.
//!
//! This module re-exports types from [`kingfisher_rules`].

// Re-export the rule module
pub mod rule {
    pub use kingfisher_rules::rule::*;
}

// Re-export everything from the rules module
pub use kingfisher_rules::rule::Revocation;
pub use kingfisher_rules::rules::{Rules, RulesError};
pub use kingfisher_rules::{
    BetterleaksAccessMap, BetterleaksAccessMapHandler, BetterleaksCapabilities, BetterleaksExpr,
    BetterleaksRevocationBindings, BetterleaksValidation, ChecksumActual, ChecksumRequirement,
    Confidence, DependsOnRule, GrpcRequest, GrpcValidation, HttpRequest, HttpValidation,
    MultipartConfig, MultipartPart, PatternRequirementContext, PatternRequirements,
    PatternValidationResult, RULE_COMMENTS_PATTERN, ReportResponseData, ResponseMatcher, Rule,
    RuleSyntax, Validation,
};
