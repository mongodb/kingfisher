//! Public façade for the scanner subsystem.
pub(crate) use docker::{save_docker_archives, save_docker_images};
pub(crate) use enumerate::enumerate_filesystem_inputs;
pub(crate) use repos::{
    clone_or_update_git_repos_streaming, enumerate_azure_repos, enumerate_bitbucket_repos,
    enumerate_github_repos, enumerate_huggingface_repos,
};
pub use runner::{load_and_record_rules, run_async_scan, run_scan};
pub(crate) use validation::{AccessMapCollector, run_secret_validation};

mod docker;
mod enumerate;
mod processing;
mod repos;
mod runner;
mod summary;
mod util;
mod validation;
