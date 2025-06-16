//! Public façade for the scanner subsystem.
pub(crate) use enumerate::enumerate_filesystem_inputs;
pub(crate) use repos::{clone_or_update_git_repos, enumerate_github_repos};
pub use runner::{load_and_record_rules, run_async_scan, run_scan};
pub(crate) use validation::run_secret_validation;

mod enumerate;
mod processing;
mod repos;
mod runner;
mod summary;
mod util;
mod validation;
