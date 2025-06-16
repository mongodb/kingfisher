use std::path::PathBuf;

use clap::{ArgAction, Args, Subcommand, ValueEnum, ValueHint};
use strum::Display;

use crate::cli::commands::output::OutputArgs;

// -----------------------------------------------------------------------------
// Rule Specifiers
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone, Default)]
pub struct RuleSpecifierArgs {
    /// Load additional rules from file(s) or directories
    ///
    /// Directories are walked recursively for YAML files. This option
    /// can be repeated.
    #[arg(long, alias="rules", value_hint=ValueHint::AnyPath)]
    pub rules_path: Vec<PathBuf>,

    /// Enable the ruleset with the given ID (e.g. `all`, `default`, or custom)
    ///
    /// Repeating this disables the default set unless `default` is explicitly included.
    #[arg(long, default_values_t=["all".to_string()])]
    pub rule: Vec<String>,

    /// Load built-in rules
    #[arg(long, default_value_t=true, action=ArgAction::Set)]
    pub load_builtins: bool,
}

#[derive(Args, Debug)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub command: RulesCommand,
}

#[derive(Subcommand, Debug)]
pub enum RulesCommand {
    /// Check rules for problems
    Check(RulesCheckArgs),

    /// List available rules
    List(RulesListArgs),
}

#[derive(Args, Debug)]
pub struct RulesCheckArgs {
    /// Treat warnings as errors
    #[arg(long, short = 'W')]
    pub warnings_as_errors: bool,

    #[command(flatten)]
    pub rules: RuleSpecifierArgs,
}

#[derive(Args, Debug)]
pub struct RulesListArgs {
    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    #[command(flatten)]
    pub output_args: OutputArgs<RulesListOutputFormat>,
}

// -----------------------------------------------------------------------------
// Rules List Output Format
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum RulesListOutputFormat {
    /// A human-friendly text-based format
    Pretty,
    /// Pretty-printed JSON
    Json,
}
