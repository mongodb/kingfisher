use clap::{Args, ValueHint};
use std::path::PathBuf;

/// Directly revoke a known secret against a rule's revocation config
#[derive(Args, Debug, Clone)]
pub struct RevokeArgs {
    /// Rule ID or prefix to use for revocation (for example, a custom legacy rule ID).
    /// The `betterleaks.` prefix is optional for built-in rules.
    #[arg(long, required = true)]
    pub rule: String,

    /// The secret value to revoke (use '-' to read from stdin)
    #[arg(value_name = "SECRET")]
    pub secret: Option<String>,

    /// Additional values for revocation, auto-assigned to template variables.
    /// Values are assigned to non-TOKEN variables in alphabetical order.
    /// Example: --arg AKIAEXAMPLE assigns to the first required variable.
    #[arg(long = "arg", value_name = "VALUE")]
    pub args: Vec<String>,

    /// Named variables for revocation template (e.g., --var AKID=xxx).
    /// Use when you know the exact variable name. Overrides --arg assignments.
    #[arg(long = "var", value_name = "NAME=VALUE")]
    pub variables: Vec<String>,

    /// Timeout for revocation requests in seconds (1-60)
    #[arg(
        long = "timeout",
        default_value_t = 10,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..=60)
    )]
    pub timeout: u64,

    /// Number of retries for revocation requests (0-5)
    #[arg(
        long = "retries",
        default_value_t = 1,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(0..=5)
    )]
    pub retries: u32,

    /// Path to custom rules file or directory
    #[arg(long = "rules-path", value_hint = ValueHint::AnyPath)]
    pub rules_path: Vec<PathBuf>,

    /// Skip loading builtin rules (use only custom rules from --rules-path)
    #[arg(long = "no-builtins", default_value_t = false)]
    pub no_builtins: bool,

    /// Output format: text, json, or toon (`toon` is recommended for LLMs)
    #[arg(long, default_value = "text", value_parser = ["text", "json", "toon"])]
    pub format: String,
}
