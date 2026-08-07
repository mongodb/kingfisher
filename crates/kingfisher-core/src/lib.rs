//! `kingfisher-core` provides the foundational types and traits shared across
//! the Kingfisher secret scanning library.
//!
//! This crate contains:
//! - [`Blob`] - Representation of scannable content (files, buffers, git objects)
//! - [`Location`] - Source location tracking (byte offsets and line/column)
//! - [`Origin`] - Provenance tracking (where content came from)
//! - Utility functions for entropy calculation, string escaping, etc.

pub mod blob;
pub mod bstring_escape;
pub mod content_type;
pub mod entropy;
pub mod error;
pub mod git_commit_metadata;
pub mod location;
pub mod origin;
pub mod validation;

// Re-export commonly used types at the crate root
pub use blob::{
    Blob, BlobAppearance, BlobAppearanceSet, BlobData, BlobId, BlobIdMap, BlobMetadata,
};
pub use bstring_escape::Escaped;
pub use content_type::{ContentInspector, ContentType};
pub use entropy::calculate_shannon_entropy;
pub use error::{Error, Result};
pub use git_commit_metadata::CommitMetadata;
pub use location::{Location, LocationMapping, OffsetSpan, SourcePoint, SourceSpan};
pub use origin::{CommitOrigin, ExtendedOrigin, FileOrigin, GitRepoOrigin, Origin, OriginSet};
pub use validation::ValidationOutcome;
