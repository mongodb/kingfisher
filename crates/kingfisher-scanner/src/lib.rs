#![doc = include_str!("../README.md")]

mod finding;
#[doc(hidden)]
pub mod primitives;
mod scan_control;
mod scanner;
mod scanner_pool;

#[cfg(feature = "validation")]
pub mod validation;

pub use finding::{Finding, FindingLocation, SerializableCapture, SerializableCaptures};
pub use scan_control::{CancellationToken, ScanAborted, ScanControl};
pub use scanner::{Scanner, ScannerConfig};
pub use scanner_pool::ScannerPool;

pub use kingfisher_core::{
    Blob, BlobId, Location, OffsetSpan, SourcePoint, SourceSpan, ValidationOutcome,
};
pub use kingfisher_rules::{Confidence, Rule, RuleSyntax, RulesDatabase, get_builtin_rules};

#[cfg(feature = "validation")]
pub use validation::{ValidatedFinding, ValidationReason, Validator, ValidatorBuilder};

#[cfg(feature = "validation")]
pub use validation::{Revoker, revocation::DirectRevocationResult};
