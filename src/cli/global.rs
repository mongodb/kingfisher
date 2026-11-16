use std::io::IsTerminal;
use std::path::PathBuf;

use std::sync::LazyLock;

use clap::{
    ArgAction, ArgMatches, Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum,
};
use tracing::Level;

use crate::cli::commands::{
    blast_radius::BlastRadiusArgs, config_command::ConfigArgs, revoke::RevokeArgs,
    rules::RulesArgs, scan::ScanCommandArgs, validate::ValidateArgs, view::ViewArgs,
};

#[deny(missing_docs)]
#[derive(Parser, Debug)]
#[command(name = "kingfisher", version = env!("CARGO_PKG_VERSION"))]
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
#[allow(clippy::large_enum_variant)]
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

    /// Map a credential's identity, permissions, and blast radius, including risk and coverage
    #[command(name = "blast-radius", visible_alias = "access-map", aliases = ["blast_radius", "access_map"])]
    BlastRadius(BlastRadiusArgs),

    /// View JSON, JSONL, and SARIF reports in a local web UI
    View(ViewArgs),

    /// Generate a reusable `kingfisher.yaml` project config
    Config(ConfigArgs),

    /// Update the Kingfisher binary
    #[command(name = "update", alias = "self-update")]
    SelfUpdate,
}

pub static RAM_GB: LazyLock<Option<f64>> =
    LazyLock::new(|| physical_memory_bytes().map(|bytes| bytes as f64 / 1024.0 / 1024.0 / 1024.0));

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn physical_memory_bytes() -> Option<u64> {
    let mut mib = [libc::CTL_HW, libc::HW_MEMSIZE];
    let mut bytes = 0u64;
    let mut size = std::mem::size_of::<u64>();
    // SAFETY: the MIB and output pointers address initialized, correctly sized
    // buffers. Passing a null new-value pointer makes this a read-only query.
    let status = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            (&mut bytes as *mut u64).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && size == std::mem::size_of::<u64>() && bytes != 0).then_some(bytes)
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd"
))]
fn physical_memory_bytes() -> Option<u64> {
    // SAFETY: sysconf takes only a constant selector and does not access Rust memory.
    let pages = u64::try_from(unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) }).ok()?;
    // SAFETY: as above. A negative/error result is rejected before multiplication.
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
    pages.checked_mul(page_size).filter(|bytes| *bytes != 0)
}

#[cfg(windows)]
fn physical_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    let mut memory = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: memory is initialized, and dwLength is the exact buffer size required by Windows.
    let status = unsafe { GlobalMemoryStatusEx(&mut memory) };
    (status != 0 && memory.ullTotalPhys != 0).then_some(memory.ullTotalPhys)
}

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd"
)))]
fn physical_memory_bytes() -> Option<u64> {
    None
}

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
    /// - lax: Bypass certificate verification for rules that explicitly opt in
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

    /// Enable configured fallback environments; revoke validates first and acts only on the verified environment.
    /// Primary only by default; scan/validate never revoke automatically, and revocation never fails over mutations.
    #[arg(global = true, long = "fallbacks", default_value_t = false)]
    pub http_fallbacks: bool,

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
            http_fallbacks: false,
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Default)]
pub enum TlsMode {
    /// Full WebPKI certificate validation: trusted CA chain, hostname match, not expired.
    /// This is the default and most secure mode.
    #[default]
    Strict,

    /// Permit certificate-verification bypass when both the global policy and
    /// the rule opt into lax mode. Validators configure their own transports;
    /// hostname and expiry checks are not guaranteed in this mode.
    Lax,

    /// Disable all TLS certificate validation. Use with extreme caution.
    /// Equivalent to the legacy `--ignore-certs` flag.
    Off,
}

crate::cli::impl_value_enum_display!(Mode, TlsMode);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(
        windows,
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    #[test]
    fn cli_utility_ram_size_is_available_for_scan_job_sizing() {
        let ram_gb = RAM_GB.expect("supported platforms should report their physical RAM");
        assert!(ram_gb.is_finite() && ram_gb > 0.0, "invalid RAM size: {ram_gb}");
    }

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
