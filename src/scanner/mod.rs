//! Public façade for the scanner subsystem.
pub(crate) use docker::{save_docker_archives, save_docker_images};
pub(crate) use enumerate::{enumerate_filesystem_inputs, reference_candidates};
pub(crate) use repos::{
    clone_or_update_git_repos_streaming, enumerate_azure_repos, enumerate_bitbucket_repos,
    enumerate_github_event_targets, enumerate_github_repos, enumerate_huggingface_repos,
};
pub use rule_loading::load_and_record_rules;
pub use runner::{run_async_scan, run_scan};
pub(crate) use validation::{
    AccessMapCollector, direct_access_map_requests, run_secret_validation,
};

/// Input discovery completed without finding any scan targets.
#[derive(Debug, thiserror::Error)]
#[error("No inputs to scan")]
pub struct NoScanInputsError;

mod discovery;
mod docker;
mod enumerate;
mod processing;
mod repos;
mod roots;
mod rule_loading;
mod runner;
mod storage;
mod summary;
mod util;
mod validation;
