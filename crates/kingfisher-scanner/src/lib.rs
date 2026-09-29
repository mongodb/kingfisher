#![doc = include_str!("../README.md")]

mod finding;
#[doc(hidden)]
pub mod primitives;
mod scanner;
mod scanner_pool;

// Validation module (feature-gated)
#[cfg(any(
    feature = "validation",
    feature = "validation-http",
    feature = "validation-aws",
    feature = "validation-azure",
    feature = "validation-coinbase",
    feature = "validation-gcp",
    feature = "validation-jwt",
    feature = "validation-database",
    feature = "validation-ethereum",
    feature = "validation-all",
))]
pub mod validation;

pub use finding::{Finding, FindingLocation, SerializableCapture, SerializableCaptures};
pub use scanner::{Scanner, ScannerConfig};
pub use scanner_pool::ScannerPool;

// Re-export commonly needed types from dependencies
pub use kingfisher_core::{
    Blob, BlobId, Location, OffsetSpan, SourcePoint, SourceSpan, ValidationOutcome,
};
pub use kingfisher_rules::{Confidence, Rule, RuleSyntax, RulesDatabase, get_builtin_rules};

#[cfg(feature = "validation-http")]
pub use validation::{ValidatedFinding, ValidationReason, Validator, ValidatorBuilder};
