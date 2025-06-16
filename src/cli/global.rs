use std::io::IsTerminal;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use once_cell::sync::Lazy;
use strum::Display;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use tracing::Level;

use crate::cli::commands::{
    github::GitHubArgs, gitlab::GitLabArgs, rules::RulesArgs, scan::ScanArgs,
};

#[deny(missing_docs)]
#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
/// Find secrets and sensitive information in textual data
pub struct CommandLineArgs {
    /// The command to execute
    #[command(subcommand)]
    pub command: Command,

    /// Global arguments that apply to all subcommands
    #[command(flatten)]
    pub global_args: GlobalArgs,
}
impl CommandLineArgs {
    /// Parse command-line arguments.
    ///
    /// Automatically respects `NO_COLOR` and maps `--quiet` into disabling progress bars.
    pub fn parse_args() -> Self {
        // Use standard `Parser::parse` for simplicity
        let mut args = CommandLineArgs::parse();

        // Apply NO_COLOR environment variable
        if std::env::var("NO_COLOR").is_ok() {
            args.global_args.color = Mode::Never;
        }

        // If quiet is enabled, disable progress
        if args.global_args.quiet {
            args.global_args.progress = Mode::Never;
        }

        args
    }
}

/// Top-level subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan content for secrets and sensitive information
    Scan(ScanArgs),

    /// Interact with the GitHub API
    #[command(name = "github")]
    GitHub(GitHubArgs),

    /// Interact with the GitLab API
    #[command(name = "gitlab")]
    GitLab(GitLabArgs),

    /// Manage rules
    #[command(alias = "rule")]
    Rules(RulesArgs),
}

pub static RAM_GB: Lazy<Option<f64>> = Lazy::new(|| {
    if sysinfo::IS_SUPPORTED_SYSTEM {
        let s = System::new_with_specifics(
            RefreshKind::new().with_memory(MemoryRefreshKind::new().with_ram()),
        );
        Some(s.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0)
    } else {
        None
    }
});

/// Advanced global options unlikely to be used in normal scenarios.
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Advanced Global Options")]
pub struct AdvancedArgs {
    /// Set the rlimit for the number of open files
    #[arg(long, default_value_t = 16384, value_name = "LIMIT")]
    pub rlimit_nofile: u64,
}

/// Top-level global CLI arguments
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Global Options")]
pub struct GlobalArgs {
    /// Enable verbose output (up to 3 times for more detail)
    #[arg(global = true, long = "verbose", short = 'v', action = ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-error messages and disable progress bars
    #[arg(global = true, long, short)]
    pub quiet: bool,

    /// Ignore TLS certificate validation
    #[arg(global = true, long)]
    pub ignore_certs: bool,

    #[command(flatten)]
    pub advanced: AdvancedArgs,

    // Internal fields (not CLI arguments)
    #[clap(skip)]
    pub color: Mode,

    #[clap(skip)]
    pub progress: Mode,
}

impl Default for GlobalArgs {
    fn default() -> Self {
        Self {
            verbose: 0,
            quiet: false,
            ignore_certs: false,
            advanced: AdvancedArgs { rlimit_nofile: 16384 },
            color: Mode::Auto,
            progress: Mode::Auto,
        }
    }
}

impl GlobalArgs {
    pub fn use_color<T: IsTerminal>(&self, out: T) -> bool {
        match self.color {
            Mode::Never => false,
            Mode::Always => true,
            Mode::Auto => out.is_terminal(),
        }
    }

    pub fn use_progress(&self) -> bool {
        match self.progress {
            Mode::Never => false,
            Mode::Always => true,
            Mode::Auto => std::io::stderr().is_terminal(),
        }
    }

    pub fn log_level(&self) -> Level {
        if self.quiet {
            Level::INFO
        } else {
            match self.verbose {
                0 => Level::INFO,  // Default level if no `-v` is provided
                1 => Level::DEBUG, // `-v`
                2 => Level::TRACE, // `-vv`
                _ => Level::TRACE, // `-vvv` or more
            }
        }
    }
}

/// Mode for enabling or disabling features based on terminal capabilities
/// Generic mode with `auto/never/always`.
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum Mode {
    #[default]
    Auto,
    Never,
    Always,
}
