//! Full Kingfisher application library, including CLI scan orchestration and providers.
//!
//! For a focused embedding API, use [`kingfisher_scanner::Scanner`] and its
//! configuration, findings, validation, and revocation types. Shared content types
//! live in [`kingfisher_core`]; rule loading and compilation live in [`kingfisher_rules`].
//! The application modules below remain public for existing consumers. New command
//! implementations belong in private binary modules; scanner implementation modules
//! stay private behind the [`scanner`] façade.
//!
//! See the runnable `embedded_application` example for the focused scanner API
//! through this crate's re-exports, and `docs/LIBRARY.md` for integration guidance.

pub use kingfisher_core;
pub use kingfisher_rules;
pub use kingfisher_scanner;

pub mod access_map;
pub mod alerts;
pub mod azure;
pub mod baseline;
pub mod binary;
pub mod bitbucket;
pub mod blob;
pub mod bstring_escape;
pub mod bstring_table;
pub mod cli;
pub mod confluence;
pub mod content_type;
pub mod decompress;
pub mod defaults;
pub mod direct_access_map;
pub mod direct_revoke;
pub mod direct_validate;
pub mod entropy;
pub mod finding_data;
pub mod findings_store;
pub mod gcs;
pub mod git_binary;
pub mod git_commit_metadata;
pub mod git_host;
pub mod git_metadata_graph;
mod git_repo_enumerator;
pub mod git_url;
pub mod gitea;
pub mod github;
pub(crate) mod github_auth;
pub mod gitlab;
pub mod grpc_validation;
pub mod huggingface;
pub mod inline_ignore;
pub mod jira;
pub mod limits;
pub mod liquid_filters;
pub mod location;
pub mod matcher;
pub mod origin;
pub mod parser;
pub mod postman;
pub mod provider_endpoints;
pub mod pyc;
pub mod reporter;
pub mod rule_loader;
pub mod rule_profiling;
pub mod rules;
pub mod rules_database;
pub mod s3;
pub mod safe_list;
pub mod scan_audit;
pub mod scanner;
pub mod scanner_pool;
pub mod slack;
pub mod snippet;
pub mod sqlite;
pub mod teams;
pub(crate) mod template_vars;
pub mod toon;
pub mod update;
pub mod util;
pub mod validation;
pub mod validation_body;
pub mod validation_rate_limit;
#[cfg(feature = "gui")]
pub mod wizard;

mod input;

pub(crate) use input::build_exclude_globset;
pub use input::{
    DirectoryResult, EnumeratorFileResult, FileResult, FilesystemEnumerator, FoundInput,
    GitBlobSource, GitDiffConfig, GitRepoEnumerator, GitRepoResult, GitRepoWithMetadataEnumerator,
    Gitignore, GitignoreBuilder, Output, Repository, ThreadSafeRepository, gix, open_git_repo,
    open_git_repo_with_options,
};

mod scan_progress;
