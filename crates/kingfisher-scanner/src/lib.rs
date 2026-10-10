#![doc = include_str!("../README.md")]

mod components;
mod confirmation;
mod finding;
mod line_index;
mod postprocess;
#[doc(hidden)]
pub mod primitives;
mod scan_control;
mod scanner;
mod scanner_pool;

#[cfg(feature = "validation")]
pub mod validation;

#[cfg(feature = "git")]
pub mod git;

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

#[cfg(feature = "archives")]
pub mod archive;

#[cfg(feature = "context")]
pub mod context;
#[cfg(feature = "extraction")]
pub mod extraction;

/// Internal CLI integration. This feature and every item here may change without notice.
/// Embedders should use `Scanner` and the supported detection-options APIs.
#[cfg(feature = "__cli-internals")]
#[doc(hidden)]
pub mod __cli_internals {
    pub use crate::components::dependency_keep;
    pub use crate::confirmation::IndexedCaptures;
    pub use crate::line_index::LineIndex;
    pub use crate::postprocess::*;

    /// Internal CLI tree-diff adapter; no blob reads or rename detection.
    #[cfg(feature = "git")]
    pub fn git_tree_changes(
        repo: &gix::Repository,
        current: &gix::Tree<'_>,
        base: Option<&gix::Tree<'_>>,
        control: &crate::ScanControl,
    ) -> anyhow::Result<Vec<gix::diff::tree::recorder::Change>> {
        crate::git::cli_tree_changes(repo, current, base, control)
    }

    #[cfg(feature = "context")]
    pub mod inline_ignore {
        pub use crate::context::inline_ignore::*;
    }

    #[cfg(feature = "context")]
    pub mod parser {
        pub use crate::context::parser::*;
    }

    pub fn candidate_index(
        db: &crate::RulesDatabase,
        rule: usize,
        input: &[u8],
        range: std::ops::Range<usize>,
    ) -> crate::primitives::CandidateMatchIndex {
        crate::primitives::CandidateMatchIndex::new_in_range_with_maximum_len(
            &db.anchored_regexes()[rule],
            input,
            range,
            db.confirmation_maximum_len(rule),
            db.confirmation_match_maximum_len(rule),
            db.confirmation_prefix_stable(rule),
        )
    }

    pub fn confirm<'r, 'h>(
        index: &crate::primitives::CandidateMatchIndex,
        regex: &'r regex::bytes::Regex,
        endpoint: Option<&regex::bytes::Regex>,
        haystack: &'h [u8],
        start: usize,
    ) -> IndexedCaptures<'r, 'h> {
        index
            .captures_with_control(regex, endpoint, haystack, start, &crate::ScanControl::default())
            .expect("unlimited scan cannot be cancelled")
    }

    pub fn confirmation_needs_wider_window(
        confirmed: bool,
        window_start: usize,
        window_end: usize,
        maximum_match_len: Option<usize>,
    ) -> bool {
        crate::primitives::confirmation_needs_wider_window(
            confirmed,
            window_start,
            window_end,
            maximum_match_len,
        )
    }
}
