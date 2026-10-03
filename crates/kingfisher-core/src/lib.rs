#![doc = include_str!("../README.md")]

pub mod blob;
pub mod bstring_escape;
pub mod content_type;
mod encoding;
pub mod entropy;
pub mod error;
pub mod git_commit_metadata;
pub mod location;
pub mod origin;
pub mod validation;

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
