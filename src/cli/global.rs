use std::io::IsTerminal;
use std::path::PathBuf;

use std::sync::LazyLock;

use clap::{
    ArgAction, ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
};
use strum::Display;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use tracing::Level;

use crate::cli::commands::{
    access_map::AccessMapArgs, config_command::ConfigArgs, revoke::RevokeArgs, rules::RulesArgs,
    scan::ScanCommandArgs, validate::ValidateArgs, view::ViewArgs,
};

#[deny(missing_docs)]
#[derive(Parser, Debug)]
#[command(version = env!("CARGO_PKG_VERSION"))]
/// Kingfisher - Detect and validate secrets across files and full Git history
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
        Self::parse_args_with_matches().0
    }

    /// Parse command-line arguments and also return the raw [`ArgMatches`] so
    /// callers can use [`ArgMatches::value_source`] to distinguish "user
    /// supplied this flag" from "clap filled in a default" — required for
    /// project-config precedence (`CLI > env > config > built-in default`).
    pub fn parse_args_with_matches() -> (Self, ArgMatches) {
        let matches = CommandLineArgs::command().get_matches();
        let mut args = CommandLineArgs::from_arg_matches(&matches)
            .expect("clap-derive guarantees a successful round-trip");

        // Apply NO_COLOR environment variable
        if std::env::var("NO_COLOR").is_ok() {
            args.global_args.color = Mode::Never;
        }

        // If quiet is enabled, disable progress
        if args.global_args.quiet {
            args.global_args.progress = Mode::Never;
        }

        // Handle deprecated --ignore-certs flag as alias for --tls-mode=off
        if args.global_args.ignore_certs {
            args.global_args.tls_mode = TlsMode::Off;
        }

        if let Some(suffix) = args.global_args.user_agent_suffix.as_mut() {
            let trimmed = suffix.trim();
            if trimmed.is_empty() {
                args.global_args.user_agent_suffix = None;
            } else if trimmed.len() != suffix.len() {
                *suffix = trimmed.to_string();
            }
        }

        (args, matches)
    }
}

/// Top-level subcommands
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan content for secrets and sensitive information
    Scan(ScanCommandArgs),

    /// Manage rules
    #[command(alias = "rule")]
    Rules(RulesArgs),

    /// Directly validate a known secret against a rule's validator (bypasses pattern matching)
    Validate(ValidateArgs),

    /// Directly revoke a known secret against a rule's revocation config
    Revoke(RevokeArgs),

    /// Map a cloud credential to its identity, permissions, and blast radius
    #[command(name = "access-map", aliases = ["access_map", "blast-radius", "blast_radius"])]
    AccessMap(AccessMapArgs),

    /// View Kingfisher JSON/JSONL reports in a local web UI
    View(ViewArgs),

    /// Generate or inspect `kingfisher.yaml` project config files
    Config(ConfigArgs),

    /// Update the Kingfisher binary
    #[command(name = "update", alias = "self-update")]
    SelfUpdate,
}

pub static RAM_GB: LazyLock<Option<f64>> = LazyLock::new(|| {
    if sysinfo::IS_SUPPORTED_SYSTEM {
        let s = System::new_with_specifics(
            RefreshKind::nothing().with_memory(MemoryRefreshKind::nothing().with_ram()),
        );
        Some(s.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0)
    } else {
        None
    }
});

/// Top-level global CLI arguments
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Global Options")]
pub struct GlobalArgs {
    /// Enable verbose output (up to 3 times for more detail)
    #[arg(global = true, long = "verbose", alias = "debug", short = 'v', action = ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-error messages and disable progress bars
    #[arg(global = true, long, short)]
    pub quiet: bool,

    /// TLS certificate validation mode for secret validation requests.
    ///
    /// - strict: Full WebPKI validation (default)
    /// - lax: Accept self-signed/unknown CA, but enforce hostname + expiry
    /// - off: Disable all certificate validation
    #[arg(global = true, long, value_enum, default_value = "strict")]
    pub tls_mode: TlsMode,

    /// Allow validation requests to internal/private IP addresses.
    ///
    /// By default, Kingfisher blocks HTTP requests to loopback, private,
    /// and link-local addresses during credential validation to prevent SSRF.
    /// Use this flag when scanning infrastructure that uses internal endpoints.
    #[arg(global = true, long = "allow-internal-ips", default_value_t = false)]
    pub allow_internal_ips: bool,

    /// Disable TLS certificate validation (deprecated: use --tls-mode=off)
    #[arg(global = true, long, hide = true)]
    pub ignore_certs: bool,

    /// Update the Kingfisher binary to the latest release
    #[arg(global = true, long = "self-update", alias = "update", default_value_t = false)]
    pub self_update: bool,

    /// Disable automatic update checks
    #[arg(global = true, long = "no-update-check", default_value_t = false)]
    pub no_update_check: bool,

    /// Append a custom suffix to the default Kingfisher user-agent string
    #[arg(global = true, long = "user-agent-suffix", value_name = "SUFFIX")]
    pub user_agent_suffix: Option<String>,

    /// Override provider API endpoints for validation/revocation (PROVIDER=URL), repeatable.
    ///
    /// Supported providers: github, gitlab, gitea, jira, jira-cloud, confluence, artifactory.
    #[arg(global = true, long = "endpoint", value_name = "PROVIDER=URL")]
    pub endpoint: Vec<String>,

    /// YAML file containing provider endpoint overrides.
    #[arg(global = true, long = "endpoint-config", value_name = "FILE")]
    pub endpoint_config: Option<PathBuf>,

    /// Path to a `kingfisher.yaml` project config file.
    ///
    /// **No auto-discovery** — the file is loaded only when this flag is
    /// passed explicitly. List-typed config values are concatenated onto
    /// matching CLI flags; scalar config values are applied only when the
    /// matching `--flag` was not passed (precedence: CLI > env > config >
    /// built-in default). See `docs/CONFIG.md` for the full schema.
    #[arg(global = true, long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

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
            tls_mode: TlsMode::Strict,
            allow_internal_ips: false,
            ignore_certs: false,
            self_update: false,
            no_update_check: false,
            user_agent_suffix: None,
            endpoint: Vec::new(),
            endpoint_config: None,
            config: None,
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

/// TLS certificate validation mode for secret validation requests.
///
/// Controls how TLS certificates are validated when connecting to endpoints
/// during credential validation (e.g., database connections, API calls).
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
#[strum(serialize_all = "kebab-case")]
pub enum TlsMode {
    /// Full WebPKI certificate validation: trusted CA chain, hostname match, not expired.
    /// This is the default and most secure mode.
    #[default]
    Strict,

    /// Accept self-signed or unknown CA certificates, but still enforce:
    /// - Hostname must match certificate's CN/SAN
    /// - Certificate must not be expired
    /// - TLS 1.2 or higher required
    ///
    /// Useful for database connections (PostgreSQL, MySQL, MongoDB) that often use
    /// self-signed certificates or private CAs (e.g., Amazon RDS).
    Lax,

    /// Disable all TLS certificate validation. Use with extreme caution.
    /// Equivalent to the legacy `--ignore-certs` flag.
    Off,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_mode_default_is_strict() {
        assert_eq!(TlsMode::default(), TlsMode::Strict);
    }

    #[test]
    fn tls_mode_display_formats_correctly() {
        assert_eq!(TlsMode::Strict.to_string(), "strict");
        assert_eq!(TlsMode::Lax.to_string(), "lax");
        assert_eq!(TlsMode::Off.to_string(), "off");
    }

    #[test]
    fn global_args_default_has_strict_tls() {
        let args = GlobalArgs::default();
        assert_eq!(args.tls_mode, TlsMode::Strict);
        assert!(!args.ignore_certs);
    }

    #[test]
    fn tls_mode_ordering_is_correct() {
        // Strict < Lax < Off (more secure modes sort before less secure)
        assert!(TlsMode::Strict < TlsMode::Lax);
        assert!(TlsMode::Lax < TlsMode::Off);
    }

    #[test]
    fn mode_default_is_auto() {
        assert_eq!(Mode::default(), Mode::Auto);
    }
}
