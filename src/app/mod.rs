//! Application commands and configuration, private to the CLI binary.

mod config;
mod config_init;
mod rules;

pub(crate) use config::{apply_config, load_project_config};
#[cfg(test)]
pub(crate) use config_init::build_config_yaml;
pub(crate) use config_init::run_config_command;
pub(crate) use rules::{
    run_rules_check, run_rules_compile_cache, run_rules_list, run_rules_prune_cache,
};
