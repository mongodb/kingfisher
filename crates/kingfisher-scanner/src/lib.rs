//! High-level scanning API for the Kingfisher secret scanner.
//!
//! This crate provides a clean, ergonomic API for scanning content for secrets:
//!
//! # Quick Start
//!
//! ```ignore
//! use kingfisher_scanner::{Scanner, ScannerConfig};
//! use kingfisher_rules::{RulesDatabase, Rule, RuleSyntax, Confidence};
//! use std::sync::Arc;
//!
//! // Create a simple rule
//! let rules = vec![Rule::new(RuleSyntax {
//!     id: "test.api_key".to_string(),
//!     name: "Test API Key".to_string(),
//!     pattern: r#"api_key\s*=\s*['"]([a-zA-Z0-9]{32})['"]"#.to_string(),
//!     min_entropy: 3.0,
//!     confidence: Confidence::Medium,
//!     visible: true,
//!     examples: vec![],
//!     negative_examples: vec![],
//!     references: vec![],
//!     validation: None,
//!     revocation: None,
//!     depends_on_rule: vec![],
//!     pattern_requirements: None,
//! })];
//!
//! // Compile the rules
//! let rules_db = Arc::new(RulesDatabase::from_rules(rules).unwrap());
//!
//! // Create scanner
//! let scanner = Scanner::new(rules_db);
//!
//! // Scan content
//! let findings = scanner.scan_bytes(b"api_key = 'abcdefghijklmnopqrstuvwxyz123456'");
//! ```
//!
//! # Features
//!
//! - **Buffer scanning**: Scan in-memory bytes directly
//! - **File scanning**: Scan files from disk with automatic memory mapping
//! - **Base64 decoding**: Automatically detect and decode Base64-encoded secrets
//! - **Deduplication**: Skip duplicate findings across multiple scans
//! - **Thread safety**: Safe to use from multiple threads
//!
//! # Optional Features
//!
//! - **validation**: Enable credential validation support
//! - **validation-http**: HTTP-based validation (included in `validation`)
//! - **validation-ethereum**: Network-free Ethereum key parsing and address derivation
//! - **validation-aws**: AWS credential validation via STS
//! - **validation-all**: Enable all validation features

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

pub use finding::{Finding, FindingLocation, SerializableCapture, SerializableCaptures, intern};
pub use scanner::{Scanner, ScannerConfig};
pub use scanner_pool::ScannerPool;

// Re-export commonly needed types from dependencies
pub use kingfisher_core::{
    Blob, BlobId, Location, OffsetSpan, SourcePoint, SourceSpan, ValidationOutcome,
};
pub use kingfisher_rules::{Confidence, Rule, RulesDatabase};
