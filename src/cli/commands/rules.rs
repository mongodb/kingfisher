use std::{path::PathBuf, time::Duration};

use clap::{ArgAction, Args, Subcommand, ValueEnum, ValueHint};
use strum::Display;

use crate::{
    cli::commands::{output::OutputArgs, scan::ConfidenceLevel},
    rules_database::{DEFAULT_RULE_CACHE_MAX_AGE, DEFAULT_RULE_CACHE_MAX_ENTRIES},
};

// -----------------------------------------------------------------------------
// Rule Specifiers
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone, Default)]
pub struct RuleSpecifierArgs {
    /// Load additional rules from file(s) or directories
    ///
    /// Directories are walked recursively for YAML files. This option
    /// can be repeated.
    #[arg(global = true, long, alias="rules", value_hint=ValueHint::AnyPath)]
    pub rules_path: Vec<PathBuf>,

    /// Enable the ruleset with the given ID (e.g. `all`, `default`, or custom)
    ///
    /// Repeating this disables the default set unless `default` is explicitly included.
    #[arg(global = true, long, default_values_t=["all".to_string()])]
    pub rule: Vec<String>,

    /// Load built-in rules
    #[arg(global = true, long, default_value_t=true, action=ArgAction::Set)]
    pub load_builtins: bool,
}

#[derive(Args, Debug, Clone)]
pub struct RuleCacheArgs {
    /// Cache the compiled Vectorscan rule database between runs (default)
    #[arg(
        global = true,
        long = "rule-cache",
        default_value_t = false,
        conflicts_with = "no_rule_cache",
        hide = true
    )]
    pub rule_cache: bool,

    /// Disable the compiled Vectorscan rule database cache
    #[arg(
        global = true,
        long = "no-rule-cache",
        default_value_t = false,
        conflicts_with = "rule_cache"
    )]
    pub no_rule_cache: bool,

    /// Directory for the compiled rule cache
    #[arg(
        global = true,
        long = "rule-cache-dir",
        env = "KF_RULE_CACHE_DIR",
        value_name = "PATH",
        value_hint = ValueHint::DirPath
    )]
    pub rule_cache_dir: Option<PathBuf>,

    /// Remove stale compiled rule cache entries before scanning
    #[arg(global = true, long = "prune-rule-cache", default_value_t = false)]
    pub prune_rule_cache: bool,

    /// Keep at least this many compiled rule cache entries when pruning
    #[arg(
        global = true,
        long = "rule-cache-max-entries",
        default_value_t = DEFAULT_RULE_CACHE_MAX_ENTRIES,
        value_name = "N"
    )]
    pub rule_cache_max_entries: usize,

    /// Remove only compiled rule cache entries older than this duration when pruning
    #[arg(
        global = true,
        long = "rule-cache-max-age",
        default_value = "30d",
        value_name = "DURATION",
        value_parser = parse_duration_arg
    )]
    pub rule_cache_max_age: Duration,
}

impl RuleCacheArgs {
    pub fn enabled(&self) -> bool {
        self.rule_cache || !self.no_rule_cache
    }
}

impl Default for RuleCacheArgs {
    fn default() -> Self {
        Self {
            rule_cache: false,
            no_rule_cache: false,
            rule_cache_dir: None,
            prune_rule_cache: false,
            rule_cache_max_entries: DEFAULT_RULE_CACHE_MAX_ENTRIES,
            rule_cache_max_age: DEFAULT_RULE_CACHE_MAX_AGE,
        }
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct RuleCacheDirArgs {
    /// Directory for the compiled rule cache
    #[arg(
        long = "rule-cache-dir",
        env = "KF_RULE_CACHE_DIR",
        value_name = "PATH",
        value_hint = ValueHint::DirPath
    )]
    pub rule_cache_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct RuleCachePruneArgs {
    #[command(flatten)]
    pub cache: RuleCacheDirArgs,

    /// Keep at least this many compiled rule cache entries
    #[arg(long = "rule-cache-max-entries", default_value_t = DEFAULT_RULE_CACHE_MAX_ENTRIES, value_name = "N")]
    pub max_entries: usize,

    /// Remove only compiled rule cache entries older than this duration
    #[arg(
        long = "rule-cache-max-age",
        default_value = "30d",
        value_name = "DURATION",
        value_parser = parse_duration_arg
    )]
    pub max_age: Duration,

    /// Report what would be removed without deleting files
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
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

    /// Compile and store the Vectorscan rule cache
    #[command(name = "compile-cache")]
    CompileCache(RulesCompileCacheArgs),

    /// Remove stale compiled Vectorscan rule cache entries
    #[command(name = "prune-cache")]
    PruneCache(RuleCachePruneArgs),

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

#[derive(Args, Debug)]
pub struct RulesCompileCacheArgs {
    #[command(flatten)]
    pub rules: RuleSpecifierArgs,

    /// Minimum confidence level for rules included in the cache
    #[arg(global = true, long, short = 'c', default_value = "medium")]
    pub confidence: ConfidenceLevel,

    #[command(flatten)]
    pub cache: RuleCacheDirArgs,
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

fn parse_duration_arg(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|err| err.to_string())
}
