// ────────────────────────────────────────────────────────────
// Global allocator setup
//   * Default  - mimalloc (`use-mimalloc`)
//   * Opt-in   - jemalloc (`use-jemalloc`) for one-off debugging
//   * Explicit - system allocator on Darwin (`system-alloc`)
// ────────────────────────────────────────────────────────────

#[cfg(all(feature = "use-jemalloc", feature = "system-alloc"))]
compile_error!("`use-jemalloc` and `system-alloc` are mutually exclusive");

#[cfg(all(feature = "use-jemalloc", feature = "use-mimalloc"))]
compile_error!("`use-jemalloc` and `use-mimalloc` are mutually exclusive");

#[cfg(all(feature = "system-alloc", not(target_os = "macos")))]
compile_error!("`system-alloc` is only supported on Darwin targets");

// --- jemalloc (opt-in) ---
#[cfg(feature = "use-jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// --- mimalloc (default) ---
#[cfg(all(
    not(feature = "use-jemalloc"),
    not(feature = "system-alloc"),
    any(feature = "use-mimalloc", target_os = "linux", target_os = "windows")
))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// --- system allocator (fallback, explicit on Darwin) ---
#[cfg(any(
    feature = "system-alloc",
    all(
        not(feature = "use-jemalloc"),
        not(feature = "system-alloc"),
        not(any(feature = "use-mimalloc", target_os = "linux", target_os = "windows"))
    )
))]
use std::alloc::System;
#[cfg(any(
    feature = "system-alloc",
    all(
        not(feature = "use-jemalloc"),
        not(feature = "system-alloc"),
        not(any(feature = "use-mimalloc", target_os = "linux", target_os = "windows"))
    )
))]
#[global_allocator]
static GLOBAL: System = System;

use std::{
    io::{IsTerminal, Read, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use console::Term;
use kingfisher::{
    access_map, azure, bitbucket,
    cli::{
        self, CommandLineArgs, GlobalArgs,
        commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::{
                RuleCacheArgs, RuleCachePruneArgs, RuleSpecifierArgs, RulesCheckArgs, RulesCommand,
                RulesCompileCacheArgs, RulesListArgs, RulesListOutputFormat,
            },
        },
        global::Command,
    },
    direct_revoke, direct_validate, findings_store,
    findings_store::FindingsStore,
    gitea, github, huggingface,
    reporter::{DetailsReporter, ScanAuditContext, styles::Styles},
    rule_loader::RuleLoader,
    rules_database::{RuleCacheConfig, RuleCachePruneConfig, RulesDatabase, prune_rule_cache},
    scanner::{load_and_record_rules, run_scan},
    update::{check_for_update_async, rewrite_argv_for_reexec},
    util::tokio_blocking_threads_limit,
    validation::set_user_agent_suffix,
};
use serde_json::json;
use tempfile::TempDir;
use tokio::runtime::Builder;
use tracing::{error, info, warn};
use tracing_core::metadata::LevelFilter;
use tracing_subscriber::{
    self, fmt, prelude::__tracing_subscriber_SubscriberExt, registry, util::SubscriberInitExt,
};
use url::Url;

use crate::cli::commands::{
    azure::AzureRepoType,
    bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
    gitea::GiteaRepoType,
    gitlab::GitLabRepoType,
    scan::{ListRepositoriesCommand, ScanOperation},
    view,
};

fn main() -> anyhow::Result<()> {
    raise_nproc_soft_limit();
    color_backtrace::install();

    // Run the real entry point on a thread with an explicit, larger stack so that
    // deeply-nested async state machines (validation pipeline) cannot overflow the
    // default main-thread stack.
    const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MiB
    let builder =
        std::thread::Builder::new().name("kingfisher-main".to_string()).stack_size(STACK_SIZE);

    let handler = builder.spawn(run).expect("failed to spawn main thread");
    handler.join().unwrap_or_else(|e| std::panic::resume_unwind(e))
}

/// Outcome of `async_main`. Used to signal that the runtime should be torn down
/// and the process should re-exec into a freshly self-updated binary.
enum AsyncMainOutcome {
    Done,
    Reexec,
}

/// Best-effort raise of the soft `RLIMIT_NPROC` (per-user thread/process cap)
/// to the current hard limit. Many users hit `pthread_create` failures
/// (`EAGAIN` / `WouldBlock`) under heavy validation because the default soft
/// limit on macOS is well below the hard limit. Failures here are intentionally
/// silent — this is a quality-of-life nudge, not a correctness requirement.
#[cfg(unix)]
fn raise_nproc_soft_limit() {
    // SAFETY: `getrlimit`/`setrlimit` are FFI calls. We pass pointers to
    // properly initialized `libc::rlimit` values with the correct layout, only
    // read `rl` after `getrlimit` reports success, and treat `setrlimit`
    // failure as best-effort by ignoring its return value.
    unsafe {
        let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NPROC, &mut rl) != 0 {
            return;
        }
        if rl.rlim_cur < rl.rlim_max {
            let new = libc::rlimit { rlim_cur: rl.rlim_max, rlim_max: rl.rlim_max };
            let _ = libc::setrlimit(libc::RLIMIT_NPROC, &new);
        }
    }
}

#[cfg(not(unix))]
fn raise_nproc_soft_limit() {}

fn run() -> anyhow::Result<()> {
    // Rustls 0.23 requires an explicit crypto provider selection when multiple
    // providers are present in the dependency graph.
    match rustls::crypto::ring::default_provider().install_default() {
        Ok(()) => {}
        Err(_already_installed) => {
            // Another crate already installed a provider. This is unusual for a CLI, but
            // surfacing it makes later TLS issues much easier to diagnose.
            warn!("rustls crypto provider was already installed; keeping existing provider");
        }
    }
    // Parse command-line arguments. We keep the raw `ArgMatches` so
    // `apply_config` can distinguish a user-provided flag from a clap default
    // and apply project-config scalars only when the user did not pass the
    // matching CLI flag (precedence: CLI > env > config > built-in default).
    let (CommandLineArgs { command, global_args }, matches) =
        CommandLineArgs::parse_args_with_matches();

    set_user_agent_suffix(global_args.user_agent_suffix.clone());

    let args = CommandLineArgs { command, global_args };

    // Determine the number of jobs, defaulting to the number of CPUs
    let num_jobs = match &args.command {
        Command::Scan(scan_args) => scan_args.scan_args.num_jobs,
        Command::SelfUpdate => 1, // Self-update doesn't need a thread pool
        Command::Rules(_) => std::thread::available_parallelism().map_or(1, |n| n.get()), // Default for Rules commands
        Command::Validate(_) => 1, // Single validation request
        Command::Revoke(_) => 1,   // Single revocation request
        Command::AccessMap(_) => 1,
        Command::View(_) => 1,
        Command::Config(_) => 1,
    };

    // Set up the Tokio runtime with the specified number of threads.
    // Worker threads need larger stacks because async state machines (validation
    // pipeline) can produce large poll stack frames. 8 MiB is sufficient now that
    // the validators are split into separate async fns.
    // Bound the blocking-thread pool. Tokio's default is 512 per runtime; the
    // helper scales with --jobs but caps each runtime below that default so the
    // main and artifact-fetcher runtimes cannot both grow huge blocking pools.
    let max_blocking = tokio_blocking_threads_limit(num_jobs);
    let runtime = Builder::new_multi_thread()
        .worker_threads(num_jobs)
        .max_blocking_threads(max_blocking)
        .thread_stack_size(8 * 1024 * 1024) // 8 MiB per worker
        .enable_all()
        .build()
        .context("Failed to create Tokio runtime")?;
    let outcome = runtime.block_on(async_main(args, matches))?;
    // Drop the Tokio runtime before re-exec so background tasks, file descriptors,
    // and signal handlers are torn down cleanly. On Unix `exec()` replaces the process
    // image regardless, but draining the runtime first avoids surprising shutdown
    // ordering when the re-exec happens to fail.
    drop(runtime);

    match outcome {
        AsyncMainOutcome::Done => Ok(()),
        AsyncMainOutcome::Reexec => {
            // On Unix, a successful exec() never returns; on Windows, reexec_with_new_binary
            // calls process::exit. We only reach here if the re-exec failed before transferring
            // control. The on-disk binary is now the updated version, so re-running the same
            // command will work — but the original command has NOT executed, so we must not
            // exit 0 and let CI think the run succeeded.
            if let Err(e) = reexec_with_new_binary() {
                error!(
                    "Binary was updated but re-exec failed: {e}. The original command did not \
                     run. Re-run the command to use the new binary."
                );
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

/// Re-exec the current process into the binary at `current_exe()` so a freshly
/// self-updated binary takes over the current invocation.
///
/// Argv is rewritten via [`rewrite_argv_for_reexec`] to prevent loops and to skip the
/// next update check.
///
/// On Unix this calls `exec()` which replaces the process image — same PID, parent
/// shell sees the new binary's exit code directly.
///
/// On Windows there is no true `exec()`. Standard practice (rustup, cargo) is to spawn
/// the new binary, wait, and propagate its exit code. This adds a parent process layer
/// but preserves the parent shell's child-process tracking.
fn reexec_with_new_binary() -> std::io::Result<()> {
    use std::process::Command;

    let exe = std::env::current_exe()?;
    let argv: Vec<std::ffi::OsString> = rewrite_argv_for_reexec(std::env::args_os());

    // Defensive: rewrite_argv_for_reexec returns an empty Vec only when args_os() was empty,
    // which shouldn't happen for a real CLI invocation but would produce a child process with
    // no argv[0]. Bail rather than spawn something nonsensical.
    if argv.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cannot re-exec: process started with empty argv",
        ));
    }

    // Make sure prior stderr/stdout output (e.g. "Updated to version X") is committed
    // before we either replace the process image (Unix) or spawn the child (Windows). On
    // Windows the child inherits the same handles, so leftover buffered output from the
    // parent could otherwise interleave with the child's output unpredictably.
    let _ = std::io::stdout().flush();
    let _ = writeln!(std::io::stderr(), "Restarting with updated binary...");
    let _ = std::io::stderr().flush();

    // Safe by the is_empty() guard above.
    let argv0 = argv[0].clone();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&exe).args(argv.iter().skip(1)).arg0(&argv0).exec();
        // exec() returns only on failure.
        Err(err)
    }

    #[cfg(windows)]
    {
        // arg0 spoofing isn't available on Windows; the child sees the resolved exe path
        // as argv[0]. The user-visible difference is cosmetic.
        let _ = argv0;
        let status = Command::new(&exe).args(argv.iter().skip(1)).status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (exe, argv0);
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "re-exec is not supported on this platform",
        ))
    }
}

fn setup_logging(global_args: &GlobalArgs) {
    // Determine log level based on global verbosity
    let (level, all_targets) = if global_args.quiet {
        (LevelFilter::ERROR, false)
    } else {
        let level = match global_args.verbose {
            0 => LevelFilter::INFO,  // Default level if no `-v` is provided
            1 => LevelFilter::DEBUG, // `-v`
            2 => LevelFilter::TRACE, // `-vv`
            _ => LevelFilter::TRACE, // `-vvv` or more
        };
        let all_targets = global_args.verbose > 2; // Enable all targets for `-vvv` or more
        (level, all_targets)
    };
    // Create a filter for logging
    let filter = if all_targets {
        // Enable TRACE for all modules
        tracing_subscriber::filter::Targets::new().with_default(LevelFilter::TRACE)
    } else {
        // Per-target filtering, only TRACE for `kingfisher`
        tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::ERROR) // Default for all modules
            .with_target("kingfisher", level) // Replace `kingfisher` with your
        // crate's name
    };
    // Configure the formatter layer
    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr) // Write logs to stderr
        .with_target(true) // Enable target filtering
        .with_ansi(std::io::stderr().is_terminal()) // Emit ANSI colours when stderr is a TTY
        .without_time(); // Remove timestamps
    // Build and initialize the registry
    registry()
        .with(fmt_layer) // Attach the formatter layer
        .with(filter) // Attach the filter
        .init();
}

/// Resolve and read a `kingfisher.yaml` project config.
///
/// The config file is loaded **only** when the user passes `--config <PATH>`
/// explicitly. There is intentionally no auto-discovery — relying on a
/// `kingfisher.yaml` that happens to sit in the cwd (or any ancestor
/// directory) makes scan results depend on where the binary was invoked
/// from, which is too easy to get wrong in CI. If the explicit path is
/// missing or fails to parse, that is a fatal error.
fn load_project_config(
    explicit: Option<&std::path::Path>,
) -> Result<Option<kingfisher::cli::config::KingfisherConfig>> {
    let Some(p) = explicit else { return Ok(None) };
    let bytes = std::fs::read(p).with_context(|| format!("read config {}", p.display()))?;
    let yaml =
        String::from_utf8(bytes).with_context(|| format!("config {} is not UTF-8", p.display()))?;
    let cfg = kingfisher::cli::config::parse_str(&yaml)
        .with_context(|| format!("parse config {}", p.display()))?;
    info!("loaded config from {}", p.display());
    Ok(Some(cfg))
}

/// Merge config-file values into clap-parsed args.
///
/// **Lists/maps**: always concatenated onto the CLI value (additive).
///
/// **Scalars**: applied only when the user did not pass the matching CLI
/// flag, detected via [`clap::ArgMatches::value_source`]. A `Some(_)` config
/// value still loses to a CLI-supplied flag or an explicit env-var, but wins
/// over a clap `default_value_t`. This preserves precedence
/// **CLI > env > config > built-in default**.
fn apply_config(
    scan_args: &mut cli::commands::scan::ScanArgs,
    global_args: &mut GlobalArgs,
    cfg: &kingfisher::cli::config::KingfisherConfig,
    scan_matches: Option<&clap::ArgMatches>,
) {
    use clap::parser::ValueSource;

    /// True when the named arg was either absent or filled in with its clap
    /// default — i.e. the user did not pass `--<flag>` on the CLI and did
    /// not set its `env = ...`. In those cases the config value should win.
    fn config_wins(matches: Option<&clap::ArgMatches>, id: &str) -> bool {
        matches!(matches.and_then(|m| m.value_source(id)), None | Some(ValueSource::DefaultValue))
    }

    /// Like `config_wins`, but also inspects a nested provider subcommand's
    /// `--api-url` flag. The github/gitlab provider subcommands carry their
    /// own `api_url` arg (id `api_url`) that gets propagated to
    /// `scan_args.input_specifier_args.{github,gitlab}_api_url` in
    /// `into_operation()`. If that nested flag was user-supplied, the config
    /// must NOT clobber it.
    fn api_url_config_wins(
        matches: Option<&clap::ArgMatches>,
        outer_id: &str,
        subcommand: &str,
    ) -> bool {
        if !config_wins(matches, outer_id) {
            return false;
        }
        let sub = matches.and_then(|m| m.subcommand_matches(subcommand));
        config_wins(sub, "api_url")
    }

    // ---------- Filters: existing v1 list-typed merges ----------------------
    scan_args.skip_word.extend(cfg.filters.skip_words.iter().cloned());
    scan_args.skip_regex.extend(cfg.filters.skip_regex.iter().cloned());
    scan_args.content_filtering_args.exclude.extend(cfg.filters.exclude.iter().cloned());

    // ---------- scan: behavioral scalars ------------------------------------
    if let Some(c) = cfg.scan.confidence
        && config_wins(scan_matches, "confidence")
    {
        scan_args.confidence = c.into();
    }
    if let Some(e) = cfg.scan.min_entropy
        && config_wins(scan_matches, "min_entropy")
    {
        scan_args.min_entropy = Some(e);
    }
    if let Some(v) = cfg.scan.no_validate
        && config_wins(scan_matches, "no_validate")
    {
        scan_args.no_validate = v;
    }
    if let Some(v) = cfg.scan.only_valid
        && config_wins(scan_matches, "only_valid")
    {
        scan_args.only_valid = v;
    }
    if let Some(v) = cfg.scan.redact
        && config_wins(scan_matches, "redact")
    {
        scan_args.redact = v;
    }
    if let Some(v) = cfg.scan.no_dedup
        && config_wins(scan_matches, "no_dedup")
    {
        scan_args.no_dedup = v;
    }
    if let Some(v) = cfg.scan.turbo
        && config_wins(scan_matches, "turbo")
    {
        scan_args.turbo = v;
    }
    if let Some(v) = cfg.scan.no_base64
        && config_wins(scan_matches, "no_base64")
    {
        scan_args.no_base64 = v;
    }
    if let Some(v) = cfg.scan.access_map
        && config_wins(scan_matches, "access_map")
    {
        scan_args.access_map = v;
    }
    if let Some(v) = cfg.scan.rule_stats
        && config_wins(scan_matches, "rule_stats")
    {
        scan_args.rule_stats = v;
    }
    if let Some(j) = cfg.scan.jobs
        && config_wins(scan_matches, "num_jobs")
    {
        scan_args.num_jobs = j;
    }
    if let Some(t) = cfg.scan.git_repo_timeout
        && config_wins(scan_matches, "git_repo_timeout")
    {
        scan_args.git_repo_timeout = t;
    }

    // ---------- rules ------------------------------------------------------
    // `rule` and `rules_path` are list-typed; concatenate. Note: clap's default
    // for `--rule` is `["all"]`, so unconditionally appending could grow the
    // selection in surprising ways. Only append when the user did not pass
    // `--rule` (i.e. the default is in effect).
    if !cfg.rules.enabled.is_empty() {
        if config_wins(scan_matches, "rule") {
            // Replace the synthetic clap default with the config selection.
            scan_args.rules.rule = cfg.rules.enabled.clone();
        } else {
            scan_args.rules.rule.extend(cfg.rules.enabled.iter().cloned());
        }
    }
    scan_args.rules.rules_path.extend(cfg.rules.paths.iter().cloned());
    if let Some(v) = cfg.rules.load_builtins
        && config_wins(scan_matches, "load_builtins")
    {
        scan_args.rules.load_builtins = v;
    }
    if let Some(v) = cfg.rules.cache
        && config_wins(scan_matches, "rule_cache")
        && config_wins(scan_matches, "no_rule_cache")
    {
        scan_args.rule_cache.rule_cache = v;
        scan_args.rule_cache.no_rule_cache = !v;
    }
    if let Some(path) = &cfg.rules.cache_dir
        && config_wins(scan_matches, "rule_cache_dir")
    {
        scan_args.rule_cache.rule_cache_dir = Some(path.clone());
    }

    // ---------- validation -------------------------------------------------
    if let Some(t) = cfg.validation.timeout
        && config_wins(scan_matches, "validation_timeout")
    {
        scan_args.validation_timeout = t;
    }
    if let Some(r) = cfg.validation.retries
        && config_wins(scan_matches, "validation_retries")
    {
        scan_args.validation_retries = r;
    }
    if let Some(rps) = cfg.validation.rps
        && config_wins(scan_matches, "validation_rps")
    {
        scan_args.validation_rps = Some(rps);
    }
    for (rule, rps) in &cfg.validation.rps_per_rule {
        scan_args.validation_rps_rule.push(format!("{rule}={rps}"));
    }
    if let Some(v) = cfg.validation.full_response
        && config_wins(scan_matches, "full_validation_response")
    {
        scan_args.full_validation_response = v;
    }
    if let Some(n) = cfg.validation.max_response_length
        && config_wins(scan_matches, "max_validation_response_length")
    {
        scan_args.max_validation_response_length = n;
    }

    // ---------- filters (v2 scalars + extra additive lists) ----------------
    if let Some(mb) = cfg.filters.max_file_size_mb
        && config_wins(scan_matches, "max_file_size_mb")
    {
        scan_args.content_filtering_args.max_file_size_mb = mb;
    }
    if let Some(v) = cfg.filters.no_binary
        && config_wins(scan_matches, "no_binary")
    {
        scan_args.content_filtering_args.no_binary = v;
    }
    if let Some(v) = cfg.filters.no_extract_archives
        && config_wins(scan_matches, "no_extract_archives")
    {
        scan_args.content_filtering_args.no_extract_archives = v;
    }
    if let Some(d) = cfg.filters.extraction_depth
        && config_wins(scan_matches, "extraction_depth")
    {
        scan_args.content_filtering_args.extraction_depth = d;
    }
    if let Some(v) = cfg.filters.no_inline_ignore
        && config_wins(scan_matches, "no_inline_ignore")
    {
        scan_args.no_inline_ignore = v;
    }
    if let Some(v) = cfg.filters.no_ignore_if_contains
        && config_wins(scan_matches, "no_ignore_if_contains")
    {
        scan_args.no_ignore_if_contains = v;
    }
    scan_args.extra_ignore_comments.extend(cfg.filters.extra_ignore_comments.iter().cloned());
    scan_args.skip_aws_account.extend(cfg.filters.skip_aws_accounts.iter().cloned());
    if let Some(p) = &cfg.filters.skip_aws_account_file
        && config_wins(scan_matches, "skip_aws_account_file")
    {
        scan_args.skip_aws_account_file = Some(p.clone());
    }

    // ---------- output -----------------------------------------------------
    if let Some(f) = cfg.output.format
        && config_wins(scan_matches, "format")
    {
        scan_args.output_args.format = f.into();
    }
    if let Some(p) = &cfg.output.path
        && config_wins(scan_matches, "output")
    {
        scan_args.output_args.output = Some(p.clone());
    }

    // ---------- baseline ---------------------------------------------------
    if let Some(p) = &cfg.baseline.file
        && config_wins(scan_matches, "baseline_file")
    {
        scan_args.baseline_file = Some(p.clone());
    }
    if let Some(v) = cfg.baseline.manage
        && config_wins(scan_matches, "manage_baseline")
    {
        scan_args.manage_baseline = v;
    }

    // ---------- alerts.defaults: feed the global --alert-* fields ----------
    if let Some(f) = cfg.alerts.defaults.format
        && config_wins(scan_matches, "alert_format")
    {
        scan_args.alert_format = Some(f);
    }
    if let Some(o) = cfg.alerts.defaults.on
        && config_wins(scan_matches, "alert_on")
    {
        scan_args.alert_on = o;
    }
    if let Some(c) = cfg.alerts.defaults.min_confidence
        && config_wins(scan_matches, "alert_min_confidence")
    {
        scan_args.alert_min_confidence = c.into();
    }
    if let Some(v) = cfg.alerts.defaults.include_secret
        && config_wins(scan_matches, "alert_include_secret")
    {
        scan_args.alert_include_secret = v;
    }
    if let Some(u) = &cfg.alerts.defaults.report_url
        && config_wins(scan_matches, "alert_report_url")
    {
        scan_args.alert_report_url = Some(u.clone());
    }
    if let Some(d) = cfg.alerts.defaults.detail
        && config_wins(scan_matches, "alert_detail")
    {
        scan_args.alert_detail = d;
    }

    // ---------- alerts.webhooks: append URLs (existing v1 behavior) --------
    for w in &cfg.alerts.webhooks {
        scan_args.alert_webhook.push(w.url.clone());
        scan_args.config_webhook_overrides.push(
            kingfisher::cli::commands::scan::ConfigWebhookOverride {
                format: w.format,
                on: w.on,
                min_confidence: w.min_confidence.map(Into::into),
                include_secret: w.include_secret,
                report_url: w.report_url.clone(),
                detail: w.detail,
            },
        );
    }

    // ---------- global -----------------------------------------------------
    if let Some(m) = cfg.global.tls_mode
        && config_wins(scan_matches, "tls_mode")
    {
        global_args.tls_mode = m.into();
    }
    if let Some(v) = cfg.global.allow_internal_ips
        && config_wins(scan_matches, "allow_internal_ips")
    {
        global_args.allow_internal_ips = v;
    }
    if let Some(v) = cfg.global.no_update_check
        && config_wins(scan_matches, "no_update_check")
    {
        global_args.no_update_check = v;
    }
    if let Some(s) = &cfg.global.user_agent_suffix
        && config_wins(scan_matches, "user_agent_suffix")
    {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            global_args.user_agent_suffix = Some(trimmed.to_string());
        }
    }
    global_args.endpoint.extend(cfg.global.endpoints.iter().cloned());
    if let Some(p) = &cfg.global.endpoint_config
        && config_wins(scan_matches, "endpoint_config")
    {
        global_args.endpoint_config = Some(p.clone());
    }

    // ---------- git --------------------------------------------------------
    if let Some(p) = &cfg.git.clone_dir
        && config_wins(scan_matches, "git_clone_dir")
    {
        scan_args.input_specifier_args.git_clone_dir = Some(p.clone());
    }
    if let Some(v) = cfg.git.keep_clones
        && config_wins(scan_matches, "keep_clones")
    {
        scan_args.input_specifier_args.keep_clones = v;
    }
    if let Some(n) = cfg.git.repo_clone_limit
        && config_wins(scan_matches, "repo_clone_limit")
    {
        scan_args.input_specifier_args.repo_clone_limit = Some(n);
    }
    if let Some(v) = cfg.git.include_contributors
        && config_wins(scan_matches, "include_contributors")
    {
        scan_args.input_specifier_args.include_contributors = v;
    }
    // Provider API roots for enumeration / cloning. We accept the YAML value
    // as `String` (the schema serializer keeps it stable across `Url`'s
    // trailing-slash normalization), then parse to a `Url` for the runtime
    // field. parse_str() already validated this — `unwrap_or_default()`
    // would mask a real config bug, so we re-parse and *fail loud* if the
    // string somehow does not parse here.
    //
    // The provider subcommands (`scan github`, `scan gitlab`) expose their
    // own `--api-url` flag whose value is propagated into the same runtime
    // field by `into_operation()`. `api_url_config_wins` checks both the
    // outer hidden alias and the nested subcommand flag so an explicit
    // `kingfisher scan github --api-url ...` is never overridden by the
    // config file.
    if let Some(u) = &cfg.git.github_api_url
        && api_url_config_wins(scan_matches, "github_api_url", "github")
        && let Ok(parsed) = url::Url::parse(u)
    {
        scan_args.input_specifier_args.github_api_url = parsed;
    }
    if let Some(u) = &cfg.git.gitlab_api_url
        && api_url_config_wins(scan_matches, "gitlab_api_url", "gitlab")
        && let Ok(parsed) = url::Url::parse(u)
    {
        scan_args.input_specifier_args.gitlab_api_url = parsed;
    }
}

/// Run `kingfisher config <subcommand>`.
fn run_config_command(
    config_args: kingfisher::cli::commands::config_command::ConfigArgs,
    global_args: &GlobalArgs,
    top_matches: &clap::ArgMatches,
) -> Result<()> {
    use kingfisher::cli::commands::config_command::ConfigSubcommand;

    match config_args.command {
        ConfigSubcommand::Init(init_args) => {
            let init_matches = top_matches
                .subcommand_matches("config")
                .and_then(|m| m.subcommand_matches("init"))
                .ok_or_else(|| anyhow::anyhow!("internal: missing `config init` matches"))?;

            let yaml = build_config_yaml(&init_args.scan_args, global_args, init_matches)?;

            match init_args.out.as_deref() {
                Some(path) => {
                    if !init_args.force && path.exists() {
                        anyhow::bail!(
                            "{} already exists. Pass --force to overwrite.",
                            path.display()
                        );
                    }
                    std::fs::write(path, &yaml)
                        .with_context(|| format!("write {}", path.display()))?;
                    info!("wrote {}", path.display());
                }
                None => {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(yaml.as_bytes())?;
                }
            }
        }
    }
    Ok(())
}

/// Reverse of `apply_config`: walk the user-supplied flags from `ArgMatches`
/// and emit a [`KingfisherConfig`] containing only the flags the user
/// actually passed (CLI defaults are left out so the YAML stays minimal).
fn build_config_yaml(
    scan_args: &cli::commands::scan::ScanArgs,
    global_args: &GlobalArgs,
    sub_matches: &clap::ArgMatches,
) -> Result<String> {
    use clap::parser::ValueSource;
    use kingfisher::cli::config::{
        AlertsConfig, AlertsDefaultsConfig, BaselineConfig, FiltersConfig, GitConfig, GlobalConfig,
        KingfisherConfig, OutputConfig, RulesConfig, ScanConfig, ValidationConfig, WebhookConfig,
    };
    use std::collections::BTreeMap;

    fn user_set(matches: &clap::ArgMatches, id: &str) -> bool {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    }

    let mut cfg = KingfisherConfig::default();

    // ---------- scan ----------------------------------------------------
    let mut scan = ScanConfig::default();
    if user_set(sub_matches, "confidence") {
        scan.confidence = Some(scan_args.confidence.into());
    }
    if user_set(sub_matches, "min_entropy")
        && let Some(e) = scan_args.min_entropy
    {
        scan.min_entropy = Some(e);
    }
    if user_set(sub_matches, "no_validate") {
        scan.no_validate = Some(scan_args.no_validate);
    }
    if user_set(sub_matches, "only_valid") {
        scan.only_valid = Some(scan_args.only_valid);
    }
    if user_set(sub_matches, "redact") {
        scan.redact = Some(scan_args.redact);
    }
    if user_set(sub_matches, "no_dedup") {
        scan.no_dedup = Some(scan_args.no_dedup);
    }
    if user_set(sub_matches, "turbo") {
        scan.turbo = Some(scan_args.turbo);
    }
    if user_set(sub_matches, "no_base64") {
        scan.no_base64 = Some(scan_args.no_base64);
    }
    if user_set(sub_matches, "access_map") {
        scan.access_map = Some(scan_args.access_map);
    }
    if user_set(sub_matches, "rule_stats") {
        scan.rule_stats = Some(scan_args.rule_stats);
    }
    if user_set(sub_matches, "num_jobs") {
        scan.jobs = Some(scan_args.num_jobs);
    }
    if user_set(sub_matches, "git_repo_timeout") {
        scan.git_repo_timeout = Some(scan_args.git_repo_timeout);
    }
    cfg.scan = scan;

    // ---------- rules ---------------------------------------------------
    let mut rules = RulesConfig::default();
    if user_set(sub_matches, "rule") {
        rules.enabled = scan_args.rules.rule.clone();
    }
    if !scan_args.rules.rules_path.is_empty() {
        rules.paths = scan_args.rules.rules_path.clone();
    }
    if user_set(sub_matches, "load_builtins") {
        rules.load_builtins = Some(scan_args.rules.load_builtins);
    }
    if user_set(sub_matches, "rule_cache") {
        rules.cache = Some(true);
    }
    if user_set(sub_matches, "no_rule_cache") {
        rules.cache = Some(false);
    }
    if user_set(sub_matches, "rule_cache_dir") {
        rules.cache_dir = scan_args.rule_cache.rule_cache_dir.clone();
    }
    cfg.rules = rules;

    // ---------- validation ---------------------------------------------
    let mut validation = ValidationConfig::default();
    if user_set(sub_matches, "validation_timeout") {
        validation.timeout = Some(scan_args.validation_timeout);
    }
    if user_set(sub_matches, "validation_retries") {
        validation.retries = Some(scan_args.validation_retries);
    }
    if user_set(sub_matches, "validation_rps")
        && let Some(rps) = scan_args.validation_rps
    {
        validation.rps = Some(rps);
    }
    if !scan_args.validation_rps_rule.is_empty() {
        let mut map = BTreeMap::new();
        for entry in &scan_args.validation_rps_rule {
            let (rule, rps) = entry
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid --validation-rps-rule entry: {entry:?}"))?;
            let rps: f64 = rps.parse().with_context(|| format!("invalid RPS in {entry:?}"))?;
            map.insert(rule.trim().to_string(), rps);
        }
        validation.rps_per_rule = map;
    }
    if user_set(sub_matches, "full_validation_response") {
        validation.full_response = Some(scan_args.full_validation_response);
    }
    if user_set(sub_matches, "max_validation_response_length") {
        validation.max_response_length = Some(scan_args.max_validation_response_length);
    }
    cfg.validation = validation;

    // ---------- filters --------------------------------------------------
    let mut filters = FiltersConfig::default();
    if !scan_args.skip_word.is_empty() {
        filters.skip_words = scan_args.skip_word.clone();
    }
    if !scan_args.skip_regex.is_empty() {
        filters.skip_regex = scan_args.skip_regex.clone();
    }
    if !scan_args.content_filtering_args.exclude.is_empty() {
        filters.exclude = scan_args.content_filtering_args.exclude.clone();
    }
    if user_set(sub_matches, "max_file_size_mb") {
        filters.max_file_size_mb = Some(scan_args.content_filtering_args.max_file_size_mb);
    }
    if user_set(sub_matches, "no_binary") {
        filters.no_binary = Some(scan_args.content_filtering_args.no_binary);
    }
    if user_set(sub_matches, "no_extract_archives") {
        filters.no_extract_archives = Some(scan_args.content_filtering_args.no_extract_archives);
    }
    if user_set(sub_matches, "extraction_depth") {
        filters.extraction_depth = Some(scan_args.content_filtering_args.extraction_depth);
    }
    if user_set(sub_matches, "no_inline_ignore") {
        filters.no_inline_ignore = Some(scan_args.no_inline_ignore);
    }
    if user_set(sub_matches, "no_ignore_if_contains") {
        filters.no_ignore_if_contains = Some(scan_args.no_ignore_if_contains);
    }
    if !scan_args.extra_ignore_comments.is_empty() {
        filters.extra_ignore_comments = scan_args.extra_ignore_comments.clone();
    }
    if !scan_args.skip_aws_account.is_empty() {
        filters.skip_aws_accounts = scan_args.skip_aws_account.clone();
    }
    if user_set(sub_matches, "skip_aws_account_file")
        && let Some(p) = &scan_args.skip_aws_account_file
    {
        filters.skip_aws_account_file = Some(p.clone());
    }
    cfg.filters = filters;

    // ---------- output ---------------------------------------------------
    let mut output = OutputConfig::default();
    if user_set(sub_matches, "format") {
        output.format = Some(scan_args.output_args.format.into());
    }
    if user_set(sub_matches, "output")
        && let Some(p) = &scan_args.output_args.output
    {
        output.path = Some(p.clone());
    }
    cfg.output = output;

    // ---------- baseline ------------------------------------------------
    let mut baseline = BaselineConfig::default();
    if user_set(sub_matches, "baseline_file")
        && let Some(p) = &scan_args.baseline_file
    {
        baseline.file = Some(p.clone());
    }
    if user_set(sub_matches, "manage_baseline") {
        baseline.manage = Some(scan_args.manage_baseline);
    }
    cfg.baseline = baseline;

    // ---------- alerts (defaults + webhooks via --alert-webhook) -------
    let mut alerts = AlertsConfig::default();
    let mut defaults = AlertsDefaultsConfig::default();
    if user_set(sub_matches, "alert_format") {
        defaults.format = scan_args.alert_format;
    }
    if user_set(sub_matches, "alert_on") {
        defaults.on = Some(scan_args.alert_on);
    }
    if user_set(sub_matches, "alert_min_confidence") {
        defaults.min_confidence = Some(scan_args.alert_min_confidence.into());
    }
    if user_set(sub_matches, "alert_include_secret") {
        defaults.include_secret = Some(scan_args.alert_include_secret);
    }
    if user_set(sub_matches, "alert_report_url")
        && let Some(u) = &scan_args.alert_report_url
    {
        defaults.report_url = Some(u.clone());
    }
    if user_set(sub_matches, "alert_detail") {
        defaults.detail = Some(scan_args.alert_detail);
    }
    alerts.defaults = defaults;
    // Each --alert-webhook URL becomes a webhook entry. Per-webhook overrides
    // (slack vs teams, on=always, etc.) cannot be expressed as positional CLI
    // flags, so the emitted entry just carries the URL — operators can edit
    // the file to add per-sink behavior afterward.
    for url in &scan_args.alert_webhook {
        alerts.webhooks.push(WebhookConfig {
            url: url.clone(),
            format: None,
            on: None,
            min_confidence: None,
            include_secret: None,
            report_url: None,
            detail: None,
        });
    }
    cfg.alerts = alerts;

    // ---------- global --------------------------------------------------
    let mut g = GlobalConfig::default();
    if user_set(sub_matches, "tls_mode") {
        g.tls_mode = Some(global_args.tls_mode.into());
    }
    if user_set(sub_matches, "allow_internal_ips") {
        g.allow_internal_ips = Some(global_args.allow_internal_ips);
    }
    if user_set(sub_matches, "no_update_check") {
        g.no_update_check = Some(global_args.no_update_check);
    }
    if user_set(sub_matches, "user_agent_suffix")
        && let Some(s) = &global_args.user_agent_suffix
    {
        g.user_agent_suffix = Some(s.clone());
    }
    if !global_args.endpoint.is_empty() {
        g.endpoints = global_args.endpoint.clone();
    }
    if user_set(sub_matches, "endpoint_config")
        && let Some(p) = &global_args.endpoint_config
    {
        g.endpoint_config = Some(p.clone());
    }
    cfg.global = g;

    // ---------- git ----------------------------------------------------
    let mut git = GitConfig::default();
    if user_set(sub_matches, "git_clone_dir")
        && let Some(p) = &scan_args.input_specifier_args.git_clone_dir
    {
        git.clone_dir = Some(p.clone());
    }
    if user_set(sub_matches, "keep_clones") {
        git.keep_clones = Some(scan_args.input_specifier_args.keep_clones);
    }
    if user_set(sub_matches, "repo_clone_limit")
        && let Some(n) = scan_args.input_specifier_args.repo_clone_limit
    {
        git.repo_clone_limit = Some(n);
    }
    if user_set(sub_matches, "include_contributors") {
        git.include_contributors = Some(scan_args.input_specifier_args.include_contributors);
    }
    // Provider API roots are stored as `Url` on the runtime side; the YAML
    // schema is a `String` so the emitted file matches exactly what the
    // user typed. `Url::to_string()` adds a trailing `/` on bare-host URLs
    // (e.g. `https://gitlab.example.com` → `https://gitlab.example.com/`),
    // which would silently rewrite the user's input on every `config init`
    // round-trip. Pull the raw CLI/env string from `ArgMatches` instead so
    // the emitted YAML matches what the user actually passed.
    fn raw_arg_string(matches: &clap::ArgMatches, id: &str) -> Option<String> {
        matches.get_raw(id).and_then(|mut v| v.next()).and_then(|s| s.to_str()).map(str::to_owned)
    }
    if user_set(sub_matches, "github_api_url") {
        git.github_api_url = raw_arg_string(sub_matches, "github_api_url");
    }
    if user_set(sub_matches, "gitlab_api_url") {
        git.gitlab_api_url = raw_arg_string(sub_matches, "gitlab_api_url");
    }
    cfg.git = git;

    // Serialize, then prune null/empty mappings so the YAML is concise.
    let mut value =
        serde_yaml::to_value(&cfg).context("serialize KingfisherConfig to YAML value")?;
    prune_empty(&mut value);
    let mut yaml = serde_yaml::to_string(&value).context("emit YAML")?;

    if yaml.trim() == "{}" || yaml.trim().is_empty() {
        // Avoid emitting "{}" — a no-op YAML is more confusing than empty.
        yaml = String::from("# kingfisher.yaml — no flags supplied; nothing to emit.\n");
    } else {
        let header = "# kingfisher.yaml — generated by `kingfisher config init`.\n\
                      # Edit freely; CLI flags always override config values.\n";
        yaml = format!("{header}{yaml}");
    }
    Ok(yaml)
}

/// Recursively drop `null` values, empty sequences, and empty mappings from
/// a [`serde_yaml::Value`]. Used by `build_config_yaml` to keep the output
/// file as small as the user's actual flag set.
fn prune_empty(value: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    match value {
        Value::Mapping(map) => {
            let keys: Vec<_> = map.keys().cloned().collect();
            for k in keys {
                if let Some(v) = map.get_mut(&k) {
                    prune_empty(v);
                    let drop = match v {
                        Value::Null => true,
                        Value::Sequence(s) => s.is_empty(),
                        Value::Mapping(m) => m.is_empty(),
                        _ => false,
                    };
                    if drop {
                        map.remove(&k);
                    }
                }
            }
        }
        Value::Sequence(s) => {
            for v in s.iter_mut() {
                prune_empty(v);
            }
        }
        _ => {}
    }
}

/// Build a human-readable description of what the scan is targeting, for use
/// in alert payloads (`Target:` header). The previous implementation looked
/// only at the first local path, so scans that used git URLs, GitHub orgs,
/// S3 buckets, etc. produced an empty target line. This walks the input
/// specifiers in priority order and returns the first one that's set.
fn describe_scan_target(args: &InputSpecifierArgs) -> Option<String> {
    fn join_brief<T: std::fmt::Display>(items: &[T], label: &str) -> String {
        match items.len() {
            0 => String::new(),
            1 => items[0].to_string(),
            n if n <= 3 => items.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", "),
            n => format!("{} {label}", n),
        }
    }

    // Local paths — the most common scan target.
    if !args.path_inputs.is_empty() {
        let s = if args.path_inputs.len() == 1 {
            args.path_inputs[0].display().to_string()
        } else if args.path_inputs.len() <= 3 {
            args.path_inputs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
        } else {
            format!("{} paths", args.path_inputs.len())
        };
        return Some(s);
    }
    if !args.git_url.is_empty() {
        return Some(join_brief(&args.git_url, "git URLs"));
    }
    if !args.github_user.is_empty() {
        return Some(format!("github user: {}", join_brief(&args.github_user, "github users")));
    }
    if !args.github_organization.is_empty() {
        return Some(format!(
            "github org: {}",
            join_brief(&args.github_organization, "github orgs")
        ));
    }
    if args.all_github_organizations {
        return Some("all GitHub organizations".to_string());
    }
    if !args.gitlab_user.is_empty() {
        return Some(format!("gitlab user: {}", join_brief(&args.gitlab_user, "gitlab users")));
    }
    if !args.gitlab_group.is_empty() {
        return Some(format!("gitlab group: {}", join_brief(&args.gitlab_group, "gitlab groups")));
    }
    if !args.huggingface_user.is_empty() || !args.huggingface_organization.is_empty() {
        return Some("huggingface".to_string());
    }
    if !args.gitea_user.is_empty() || !args.gitea_organization.is_empty() {
        return Some("gitea".to_string());
    }
    if !args.bitbucket_user.is_empty() || !args.bitbucket_workspace.is_empty() {
        return Some("bitbucket".to_string());
    }
    if !args.azure_organization.is_empty() {
        return Some(format!("azure: {}", join_brief(&args.azure_organization, "azure orgs")));
    }
    if let Some(b) = &args.s3_bucket {
        return Some(format!("s3://{}{}", b, args.s3_prefix.as_deref().unwrap_or("")));
    }
    if let Some(b) = &args.gcs_bucket {
        return Some(format!("gs://{}{}", b, args.gcs_prefix.as_deref().unwrap_or("")));
    }
    if !args.docker_image.is_empty() || !args.docker_archive.is_empty() {
        let mut docker_targets = Vec::new();
        if !args.docker_image.is_empty() {
            docker_targets.push(join_brief(&args.docker_image, "images"));
        }
        if !args.docker_archive.is_empty() {
            let archives =
                args.docker_archive.iter().map(|p| p.display().to_string()).collect::<Vec<_>>();
            docker_targets.push(join_brief(&archives, "archives"));
        }
        return Some(format!("docker: {}", docker_targets.join(", ")));
    }
    if let Some(u) = &args.jira_url {
        return Some(format!("jira: {}", u));
    }
    if let Some(u) = &args.confluence_url {
        return Some(format!("confluence: {}", u));
    }
    if args.slack_query.is_some() {
        return Some("slack search".to_string());
    }
    if args.teams_query.is_some() {
        return Some("teams search".to_string());
    }
    if !args.postman_workspaces.is_empty()
        || !args.postman_collections.is_empty()
        || args.postman_all
    {
        return Some("postman".to_string());
    }
    None
}

/// Build the resolved list of alert sinks from CLI flags + config overrides.
/// `scan_args.config_webhook_overrides` aligns with the trailing entries of
/// `scan_args.alert_webhook` (those that came from `kingfisher.yaml`); CLI URLs
/// always come first and use the scalar CLI flags.
fn build_alert_sinks(
    scan_args: &cli::commands::scan::ScanArgs,
) -> Vec<kingfisher::alerts::AlertSink> {
    let cli_count =
        scan_args.alert_webhook.len().saturating_sub(scan_args.config_webhook_overrides.len());
    scan_args
        .alert_webhook
        .iter()
        .enumerate()
        .map(|(i, url)| {
            let override_ = if i >= cli_count {
                scan_args.config_webhook_overrides.get(i - cli_count).cloned().unwrap_or_default()
            } else {
                cli::commands::scan::ConfigWebhookOverride::default()
            };
            let format = override_
                .format
                .or(scan_args.alert_format)
                .unwrap_or_else(|| kingfisher::alerts::AlertFormat::infer_from_url(url));
            kingfisher::alerts::AlertSink {
                url: url.clone(),
                format,
                on: override_.on.unwrap_or(scan_args.alert_on),
                min_confidence: override_.min_confidence.unwrap_or(scan_args.alert_min_confidence),
                include_secret: override_.include_secret.unwrap_or(scan_args.alert_include_secret),
                report_url: override_
                    .report_url
                    .clone()
                    .or_else(|| scan_args.alert_report_url.clone()),
                detail: override_.detail.unwrap_or(scan_args.alert_detail),
            }
        })
        .collect()
}

pub fn determine_exit_code(datastore: &Arc<Mutex<findings_store::FindingsStore>>) -> i32 {
    // exit with code 200 if _any_ findings are discovered
    // exit with code 205 if VALIDATED findings are discovered
    // exit with code 0 if there are NO findings discovered
    let ds = datastore.lock().unwrap();
    // Get all matches
    // let all_matches = ds.get_matches();

    // Only consider visible matches when determining the exit code
    let all_matches = ds
        .get_matches()
        .iter()
        .filter(|msg| {
            let (_, _, match_item) = &***msg;
            match_item.visible
        })
        .collect::<Vec<_>>();

    if all_matches.is_empty() {
        // No findings discovered
        0
    } else {
        // Check if there are any validated findings
        let validated_matches = all_matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &****msg;
                match_item.validation_success
            })
            .count();
        if validated_matches > 0 {
            // Validated findings discovered
            205
        } else {
            // Findings discovered, but not validated
            200
        }
    }
}

async fn async_main(args: CommandLineArgs, matches: clap::ArgMatches) -> Result<AsyncMainOutcome> {
    setup_logging(&args.global_args);
    let global_args = args.global_args.clone();

    match args.command {
        Command::SelfUpdate => {
            // The explicit `kingfisher self-update` subcommand intentionally does NOT
            // re-exec after updating: it has no further work to do, so simply exiting
            // is the correct end-of-run behavior. The re-exec path is reserved for the
            // global `--self-update` flag combined with another command (e.g. `scan`).
            let mut g = global_args;
            g.self_update = true;
            g.no_update_check = false;
            let _ = check_for_update_async(&g, None).await;
            Ok(AsyncMainOutcome::Done)
        }
        Command::View(view_args) => view::run(view_args).await.map(|_| AsyncMainOutcome::Done),
        Command::AccessMap(identity_args) => {
            access_map::run(identity_args).await.map(|_| AsyncMainOutcome::Done)
        }
        Command::Config(config_args) => {
            run_config_command(config_args, &global_args, &matches)?;
            Ok(AsyncMainOutcome::Done)
        }
        Command::Validate(validate_args) => {
            let results =
                direct_validate::run_direct_validation(&validate_args, &global_args).await?;
            let use_color = global_args.use_color(std::io::stdout());
            direct_validate::print_results(&results, &validate_args.format, use_color);
            // Exit with code 0 if any result is valid, 1 if all invalid
            if direct_validate::any_valid(&results) {
                Ok(AsyncMainOutcome::Done)
            } else {
                std::process::exit(1);
            }
        }
        Command::Revoke(revoke_args) => {
            let results = direct_revoke::run_direct_revocation(&revoke_args, &global_args).await?;
            let use_color = global_args.use_color(std::io::stdout());
            direct_revoke::print_results(&results, &revoke_args.format, use_color);
            // Exit with code 0 if any result revoked, 1 if all failed
            if direct_revoke::any_revoked(&results) {
                Ok(AsyncMainOutcome::Done)
            } else {
                std::process::exit(1);
            }
        }
        command => {
            let update_status = check_for_update_async(&global_args, None).await;
            // If the on-disk binary was just replaced by --self-update, return early so
            // fn run() can drop the runtime and re-exec into the new binary. The current
            // invocation will resume with the new code (e.g. updated rule set).
            if update_status.was_self_updated {
                return Ok(AsyncMainOutcome::Reexec);
            }
            match command {
                Command::Scan(scan_command) => match scan_command.into_operation()? {
                    ScanOperation::Scan(mut scan_args) => {
                        // Resolve and merge kingfisher.yaml. Lists are concatenated onto CLI
                        // flags; scalar fields are applied only when the user did not pass
                        // the matching CLI flag (clap `ValueSource` lookup). Errors only
                        // when --config explicitly points at a file we cannot parse.
                        // Auto-discovery failures are silent.
                        let loaded_config = load_project_config(global_args.config.as_deref())?;
                        let scan_matches = matches.subcommand_matches("scan");
                        let mut effective_global_args = global_args.clone();
                        if let Some(cfg) = &loaded_config {
                            apply_config(
                                &mut scan_args,
                                &mut effective_global_args,
                                cfg,
                                scan_matches,
                            );
                            // Re-publish the user-agent suffix in case the config supplied it
                            // — the initial set_user_agent_suffix call ran before config load.
                            set_user_agent_suffix(effective_global_args.user_agent_suffix.clone());
                        }
                        let global_args = effective_global_args;
                        if scan_args.view_report {
                            view::ensure_port_available(
                                scan_args.view_report_port,
                                &scan_args.view_report_address,
                                "--view-report-port",
                            )?;
                        }
                        let view_scan_started_at = chrono::Local::now();
                        let view_scan_start_time = Instant::now();
                        let temp_dir =
                            TempDir::new().context("Failed to create temporary directory")?;
                        let temp_dir_path = temp_dir.path().to_path_buf();
                        let clone_dir = if let Some(clone_dir) =
                            scan_args.input_specifier_args.git_clone_dir.as_ref()
                        {
                            std::fs::create_dir_all(clone_dir)?;
                            clone_dir.to_path_buf()
                        } else {
                            temp_dir_path.clone()
                        };
                        let keep_clones = scan_args.input_specifier_args.keep_clones
                            && scan_args.input_specifier_args.git_clone_dir.is_none();
                        // When clones go into the temp dir and the user hasn't asked to
                        // keep them, delete each clone as soon as it has been scanned so
                        // disk usage stays bounded for very large fan-outs (e.g.
                        // --include-contributors expanding to thousands of repos).
                        let auto_cleanup_clones = !scan_args.input_specifier_args.keep_clones
                            && scan_args.input_specifier_args.git_clone_dir.is_none();

                        let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
                        info!(
                            "Launching with {} concurrent scan jobs. Use --num-jobs to override.",
                            &scan_args.num_jobs
                        );
                        let paths = &scan_args.input_specifier_args.path_inputs;
                        let is_dash = paths.iter().any(|p| p.as_os_str() == "-");
                        if (paths.is_empty() || is_dash) && !std::io::stdin().is_terminal() {
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            let stdin_file = temp_dir_path.join("stdin_input");
                            std::fs::write(&stdin_file, buf)?;
                            scan_args.input_specifier_args.path_inputs = vec![stdin_file];
                        }

                        let rules_db = Arc::new(load_and_record_rules(
                            &scan_args,
                            &datastore,
                            global_args.use_progress(),
                        )?);
                        run_scan(
                            &global_args,
                            &scan_args,
                            &rules_db,
                            Arc::clone(&datastore),
                            &update_status,
                            auto_cleanup_clones,
                        )
                        .await?;
                        if update_status.is_outdated
                            && let Some(styled) = &update_status.styled_message
                        {
                            let _ = writeln!(std::io::stderr(), "{}", styled);
                        }
                        let exit_code = determine_exit_code(&datastore);

                        // Dispatch alert webhooks (best-effort; failures are warned, not fatal).
                        if !scan_args.alert_webhook.is_empty() {
                            let alert_reporter = DetailsReporter {
                                datastore: Arc::clone(&datastore),
                                styles: Styles::new(global_args.use_color(std::io::stdout())),
                                only_valid: scan_args.only_valid,
                                audit_context: None,
                            };
                            match alert_reporter.build_finding_records(&scan_args) {
                                Ok(records) => {
                                    let target =
                                        describe_scan_target(&scan_args.input_specifier_args);
                                    let sinks: Vec<_> = build_alert_sinks(&scan_args)
                                        .into_iter()
                                        .filter(|sink| {
                                            match kingfisher::alerts::validate_webhook_url(
                                                &sink.url,
                                            ) {
                                                Ok(()) => true,
                                                Err(e) => {
                                                    warn!("alert dispatch: skipping sink: {}", e);
                                                    false
                                                }
                                            }
                                        })
                                        .collect();
                                    kingfisher::alerts::dispatch(&sinks, &records, target).await;
                                }
                                Err(e) => warn!("alert dispatch: failed to build findings: {}", e),
                            }
                        }

                        if scan_args.view_report {
                            let audit_context = ScanAuditContext {
                                scan_timestamp: Some(view_scan_started_at.to_rfc3339()),
                                scan_duration_seconds: Some(
                                    view_scan_start_time.elapsed().as_secs_f64(),
                                ),
                                rules_applied: Some(rules_db.num_rules()),
                                successful_validations: None,
                                failed_validations: None,
                                skipped_validations: None,
                                blobs_scanned: None,
                                bytes_scanned: None,
                                running_version: Some(update_status.running_version.clone()),
                                latest_version: update_status.latest_version.clone(),
                                update_check_status: Some(
                                    update_status.check_status.as_str().to_string(),
                                ),
                            };
                            let reporter = DetailsReporter {
                                datastore: Arc::clone(&datastore),
                                styles: Styles::new(global_args.use_color(std::io::stdout())),
                                only_valid: scan_args.only_valid,
                                audit_context: Some(audit_context),
                            };
                            let envelope = reporter.build_report_envelope(&scan_args)?;
                            let report_bytes = serde_json::to_vec_pretty(&envelope)?;
                            let view_args = view::ViewArgs {
                                reports: vec![],
                                port: scan_args.view_report_port,
                                address: scan_args.view_report_address.clone(),
                                open_browser: true,
                                report_bytes: Some(report_bytes),
                            };
                            view::run(view_args).await?;
                        }

                        if keep_clones {
                            let _kept_path = temp_dir.keep(); // consumes TempDir; prevents auto-delete
                        } else if let Err(e) = temp_dir.close() {
                            eprintln!("Failed to close temporary directory: {}", e);
                        }

                        std::process::exit(exit_code);
                    }
                    ScanOperation::ListRepositories(list_command) => match list_command {
                        ListRepositoriesCommand::Github { api_url, specifiers } => {
                            github::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.organization,
                                specifiers.all_organizations,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Gitlab { api_url, specifiers } => {
                            kingfisher::gitlab::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.group,
                                specifiers.all_groups,
                                specifiers.include_subgroups,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Gitea { api_url, specifiers } => {
                            gitea::list_repositories(
                                api_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.organization,
                                specifiers.all_organizations,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Bitbucket { api_url, specifiers } => {
                            let auth_config = bitbucket::AuthConfig::from_env();
                            bitbucket::list_repositories(
                                api_url,
                                auth_config,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.user,
                                &specifiers.workspace,
                                &specifiers.project,
                                specifiers.all_workspaces,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Azure { base_url, specifiers } => {
                            azure::list_repositories(
                                base_url,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                                &specifiers.organization,
                                &specifiers.project,
                                specifiers.all_projects,
                                &specifiers.exclude_repos,
                                specifiers.repo_type.into(),
                            )
                            .await?;
                        }
                        ListRepositoriesCommand::Huggingface { specifiers } => {
                            let repo_specifiers = huggingface::RepoSpecifiers {
                                user: specifiers.user.clone(),
                                organization: specifiers.organization.clone(),
                                model: specifiers.model.clone(),
                                dataset: specifiers.dataset.clone(),
                                space: specifiers.space.clone(),
                                exclude: specifiers.exclude.clone(),
                            };
                            let auth = huggingface::AuthConfig::from_env();
                            huggingface::list_repositories(
                                &repo_specifiers,
                                &auth,
                                global_args.ignore_certs,
                                global_args.use_progress(),
                            )
                            .await?;
                        }
                    },
                },
                Command::Rules(ref rule_args) => match &rule_args.command {
                    RulesCommand::Check(check_args) => {
                        run_rules_check(check_args)?;
                    }
                    RulesCommand::CompileCache(cache_args) => {
                        run_rules_compile_cache(cache_args)?;
                    }
                    RulesCommand::PruneCache(prune_args) => {
                        run_rules_prune_cache(prune_args)?;
                    }
                    RulesCommand::List(list_args) => {
                        run_rules_list(list_args)?;
                    }
                },
                Command::View(_) => {
                    anyhow::bail!("View command should not reach this branch")
                }
                Command::AccessMap(_) => {
                    anyhow::bail!("AccessMap command should not reach this branch")
                }
                Command::Validate(_) => {
                    anyhow::bail!("Validate command should not reach this branch")
                }
                Command::Revoke(_) => {
                    anyhow::bail!("Revoke command should not reach this branch")
                }
                Command::SelfUpdate => {
                    anyhow::bail!("SelfUpdate command should not reach this branch")
                }
                Command::Config(_) => {
                    anyhow::bail!("Config command should not reach this branch")
                }
            }
            if let Some(message) = &update_status.message {
                info!("{}", message);
            }
            Ok(AsyncMainOutcome::Done)
        }
    }
}

/// Create a default ScanArgs instance for rule loading
fn create_default_scan_args() -> cli::commands::scan::ScanArgs {
    use cli::commands::scan::*;
    ScanArgs {
        num_jobs: 1,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        rule_cache: RuleCacheArgs::default(),
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            git_clone_dir: None,
            keep_clones: false,
            repo_clone_limit: None,
            include_contributors: false,
            github_user: Vec::new(),
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: url::Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::All,
            gitlab_include_subgroups: false,

            huggingface_user: Vec::new(),
            huggingface_organization: Vec::new(),
            huggingface_model: Vec::new(),
            huggingface_dataset: Vec::new(),
            huggingface_space: Vec::new(),
            huggingface_exclude: Vec::new(),

            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),

            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
            azure_repo_type: AzureRepoType::Source,

            jira_url: None,
            jql: None,
            jira_include_comments: false,
            jira_include_changelog: false,
            confluence_url: None,
            cql: None,
            max_results: 100,

            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            // Slack query
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            // Teams query
            teams_query: None,
            teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),

            postman_workspaces: Vec::new(),
            postman_collections: Vec::new(),
            postman_environments: Vec::new(),
            postman_all: false,
            postman_include_mocks_monitors: false,
            postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
            // Docker image scanning
            docker_image: Vec::new(),
            docker_archive: Vec::new(),

            // git clone / history options
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
            branch_root: false,
            branch_root_commit: None,
            staged: false,
        },
        extra_ignore_comments: Vec::new(),
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: true,
            extraction_depth: 2,
            exclude: Vec::new(), // Exclude patterns
            no_binary: true,
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: true,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800,
        no_dedup: false,
        view_report: false,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
        skip_aws_account: Vec::new(),
        skip_aws_account_file: None,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_base64: false,
        turbo: false,
        no_inline_ignore: false,
        no_ignore_if_contains: false,
        view_report_port: view::DEFAULT_PORT,
        view_report_address: view::DEFAULT_ADDRESS.to_string(),
        validation_timeout: 10,
        validation_retries: 1,
        validation_rps: None,
        validation_rps_rule: Vec::new(),
        full_validation_response: false,
        max_validation_response_length: 2048,
        alert_webhook: Vec::new(),
        alert_format: None,
        alert_on: kingfisher::alerts::AlertOn::Findings,
        alert_min_confidence: kingfisher::cli::commands::scan::ConfidenceLevel::Medium,
        alert_include_secret: false,
        alert_report_url: None,
        alert_detail: kingfisher::alerts::AlertDetail::Auto,
        config_webhook_overrides: Vec::new(),
    }
}
/// Run the rules compile-cache command
pub fn run_rules_compile_cache(args: &RulesCompileCacheArgs) -> Result<()> {
    let mut scan_args = create_default_scan_args();
    scan_args.confidence = args.confidence;

    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&scan_args).context("Failed to load rules")?;
    let resolved = loaded.resolve_enabled_rules().context("Failed to resolve rules")?;
    let cache = RuleCacheConfig::from_dir_or_env(args.cache.rule_cache_dir.clone());
    info!(cache_dir = %cache.cache_dir().display(), "Using Vectorscan rule cache");
    let rules_db =
        RulesDatabase::from_rules_with_cache(resolved.into_iter().cloned().collect(), &cache)
            .context("Failed to compile rules with Vectorscan cache")?;

    println!("Rule cache ready: {} rules in {}", rules_db.num_rules(), cache.cache_dir().display());
    Ok(())
}

/// Run the rules prune-cache command
pub fn run_rules_prune_cache(args: &RuleCachePruneArgs) -> Result<()> {
    let cache = RuleCacheConfig::from_dir_or_env(args.cache.rule_cache_dir.clone());
    let summary = prune_rule_cache(
        &cache,
        &RuleCachePruneConfig {
            max_entries: args.max_entries,
            max_age: args.max_age,
            protected_cache_key: None,
            dry_run: args.dry_run,
        },
    );

    let action = if args.dry_run { "would remove" } else { "removed" };
    println!(
        "Rule cache prune {action} {} entries ({} bytes) from {}; scanned {} entries, {} valid, {} invalid, {} protected, {} removal errors",
        if args.dry_run { summary.candidate_entries } else { summary.removed_entries },
        if args.dry_run { summary.candidate_bytes } else { summary.removed_bytes },
        cache.cache_dir().display(),
        summary.scanned_entries,
        summary.valid_entries,
        summary.invalid_entries,
        summary.protected_entries,
        summary.removal_errors
    );
    Ok(())
}

/// Run the rules check command
pub fn run_rules_check(args: &RulesCheckArgs) -> Result<()> {
    let mut num_errors = 0;
    let mut num_warnings = 0;
    // Load and check rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?;

    // Check each rule
    for (rule_index, rule) in rules_db.rules().iter().enumerate() {
        let rule_syntax = rule.syntax();
        // Basic rule validation checks
        if rule.name().len() < 3 {
            warn!("Rule '{}' has a very short name", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().pattern.len() < 5 {
            warn!("Rule '{}' has a very short pattern", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().examples.is_empty() {
            warn!("Rule '{}' has no examples", rule.name());
            num_warnings += 1;
            continue;
        }
        // Check regex compilation
        if let Err(e) = rule.syntax().as_regex() {
            error!("Rule '{}' has invalid regex: {}", rule.name(), e);
            num_errors += 1;
            continue;
        }
        // Test each example against regex and pattern_requirements
        for (example_index, example) in rule_syntax.examples.iter().enumerate() {
            // Get the regex using the public method
            let re =
                rules_db.get_regex_by_rule_id(rule.id()).expect("Failed to get regex for rule");

            // Check if the example matches the pattern
            let example_bytes = example.as_bytes();
            let regex_matched = re.is_match(example_bytes);

            if !regex_matched {
                println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                println!("  Processing example {}", example_index + 1);
                println!("    [!] Pattern mismatch detected for example: {}", example);
                println!("    Regex match: {}", regex_matched);
                num_errors += 1;
                continue;
            }

            // If the rule has pattern_requirements, validate them against the match
            if let Some(pattern_reqs) = rule.pattern_requirements() {
                // Get the captures from the match
                if let Some(captures) = re.captures(example_bytes) {
                    // Get the full match (group 0)
                    let full_capture = captures.get(0).expect("Group 0 should always exist");
                    let full_bytes = full_capture.as_bytes();

                    // Determine which bytes to validate (same logic as in matcher.rs)
                    // Find the primary capture group for validation
                    let matching_input_for_validation = 'block: {
                        // 1. Look for a named capture "secret" (case-insensitive).
                        if let Some(secret_cap) =
                            captures.name("secret").or_else(|| captures.name("SECRET"))
                        {
                            break 'block secret_cap;
                        }

                        // 2. Look for any other named capture.
                        if let Some(named_cap) = (1..captures.len()).find_map(|i| {
                            let name_opt = re.capture_names().nth(i).and_then(|n| n);
                            name_opt.and_then(|_| captures.get(i))
                        }) {
                            break 'block named_cap;
                        }

                        // 3. Fall back to first positional capture (group 1) if it exists.
                        if let Some(pos_cap) = captures.get(1) {
                            break 'block pos_cap;
                        }

                        // 4. Finally, fall back to the full match (group 0).
                        break 'block full_capture;
                    };

                    let validation_bytes = matching_input_for_validation.as_bytes();

                    // Create context for pattern requirements validation
                    use kingfisher_rules::PatternRequirementContext;
                    let context = PatternRequirementContext {
                        regex: re,
                        captures: &captures,
                        full_match: full_bytes,
                    };

                    // Validate pattern requirements (without respect_ignore_if_contains for examples)
                    use kingfisher_rules::PatternValidationResult;
                    match pattern_reqs.validate(validation_bytes, Some(context), false) {
                        PatternValidationResult::Passed => {
                            // All requirements met
                        }
                        PatternValidationResult::Failed => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Pattern requirements not met for example: {}",
                                example
                            );
                            println!(
                                "    The match does not satisfy the character requirements (min_digits, min_uppercase, etc.)"
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::FailedChecksum { actual_len, expected_len } => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!("    [!] Checksum validation failed for example: {}", example);
                            println!(
                                "    Actual checksum length: {}, Expected checksum length: {}",
                                actual_len, expected_len
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::IgnoredBySubstring { matched_term } => {
                            // For examples, we don't want to treat this as an error in check mode
                            // since ignore_if_contains is meant for runtime filtering
                            // But we can warn about it
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Example would be ignored due to containing term: {}",
                                matched_term
                            );
                            println!("    Example: {}", example);
                            num_warnings += 1;
                        }
                    }
                }
            }
        }
    }
    // Print summary
    if num_errors > 0 || num_warnings > 0 {
        println!("\nCheck Summary:");
        println!("  Errors: {}", num_errors);
        println!("  Warnings: {}", num_warnings);
        println!("\nError types include:");
        println!("  - Invalid regex patterns");
        println!("  - Examples that don't match their patterns");
        println!("\nWarning types include:");
        println!("  - Rules with very short names");
        println!("  - Rules with very short patterns");
        println!("  - Rules without examples");
    } else {
        println!("\nAll rules passed validation successfully!");
    }
    // Exit with error if there are errors or if warnings are treated as errors
    if num_errors > 0 || (args.warnings_as_errors && num_warnings > 0) {
        std::process::exit(1);
    }
    Ok(())
}
/// Run the rules list command
pub fn run_rules_list(args: &RulesListArgs) -> Result<()> {
    // Load rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let mut writer = args.output_args.get_writer()?;
    match args.output_args.format {
        RulesListOutputFormat::Pretty => {
            // Determine terminal width if possible, otherwise use default
            let term_width = usize::from(Term::stdout().size().1);
            // First pass: calculate column widths
            let max_name_width = resolved.iter().map(|r| r.name().len()).max().unwrap_or(0).max(4); // "Rule" header
            let max_id_width = resolved.iter().map(|r| r.id().len()).max().unwrap_or(0).max(2); // "ID" header
            let max_conf_width = resolved
                .iter()
                .map(|r| format!("{:?}", r.confidence()).len())
                .max()
                .unwrap_or(0)
                .max(10); // "Confidence" header
            // Calculate pattern width based on terminal width
            let reserved_width = max_name_width + max_id_width + max_conf_width + 10;
            let pattern_width = term_width.saturating_sub(reserved_width);
            // Format pattern on a single line
            let format_pattern = |pattern: &str| {
                let single_line = pattern
                    .replace(['\n', '\r'], " ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if single_line.len() > pattern_width {
                    format!("{}...", &single_line[..pattern_width.saturating_sub(3)])
                } else {
                    single_line
                }
            };
            // Print header
            writeln!(
                writer,
                "\n{:name_width$} │ {:id_width$} │ {:conf_width$} │ Pattern",
                "Rule",
                "ID",
                "Confidence",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width
            )?;
            // Print separator
            writeln!(
                writer,
                "{0:─<name_width$} ┼ {0:─<id_width$} ┼ {0:─<conf_width$} ┼ {0:─<pattern_width$}",
                "",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width,
                pattern_width = pattern_width
            )?;
            // Print each rule
            for rule in resolved {
                let formatted_pattern = format_pattern(&rule.syntax().pattern);
                writeln!(
                    writer,
                    "{:name_width$} │ {:id_width$} │ {:conf_width$} │ {}",
                    rule.name(),
                    rule.id(),
                    format!("{:?}", rule.confidence()),
                    formatted_pattern,
                    name_width = max_name_width,
                    id_width = max_id_width,
                    conf_width = max_conf_width
                )?;
            }
            writeln!(writer)?;
        }
        RulesListOutputFormat::Json => {
            // Create JSON format
            let rules_json: Vec<_> = resolved
                .iter()
                .map(|rule| {
                    json!({
                        "name": rule.name(),
                        "id": rule.id(),
                        "pattern": rule.syntax().pattern,
                        "confidence": rule.confidence(),
                        "examples": rule.syntax().examples,
                        "visible": rule.visible(),
                    })
                })
                .collect();
            serde_json::to_writer_pretty(&mut writer, &rules_json)?;
            writeln!(writer)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod apply_config_tests {
    //! End-to-end precedence tests for `apply_config` — confirm that:
    //!   * a user-supplied `--flag` always wins over a config-file value, and
    //!   * a config-file value wins over the clap `default_value_t` when the
    //!     user did not pass the flag.
    //!
    //! The test parses a real `ArgMatches` via clap so the same code path
    //! `value_source` reads from is exercised.

    use clap::{ArgMatches, CommandFactory, FromArgMatches};
    use kingfisher::cli::CommandLineArgs;
    use kingfisher::cli::commands::output::ReportOutputFormat;
    use kingfisher::cli::commands::scan::{ConfidenceLevel, ScanOperation};
    use kingfisher::cli::config::{KingfisherConfig, parse_str};
    use kingfisher::cli::global::Command;

    fn parse(argv: &[&str]) -> (CommandLineArgs, ArgMatches) {
        let matches =
            CommandLineArgs::command().try_get_matches_from(argv).expect("argv should parse");
        let args = CommandLineArgs::from_arg_matches(&matches).unwrap();
        (args, matches)
    }

    fn into_scan(args: CommandLineArgs) -> kingfisher::cli::commands::scan::ScanArgs {
        let cmd = match args.command {
            Command::Scan(c) => c,
            _ => panic!("expected scan subcommand"),
        };
        match cmd.into_operation().unwrap() {
            ScanOperation::Scan(s) => s,
            ScanOperation::ListRepositories(_) => panic!("expected scan op"),
        }
    }

    #[test]
    fn config_wins_when_cli_uses_default() {
        let yaml = r#"
scan:
  confidence: high
  redact: true
output:
  format: json
"#;
        let cfg: KingfisherConfig = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(scan_args.confidence, ConfidenceLevel::High);
        assert!(scan_args.redact);
        assert_eq!(scan_args.output_args.format, ReportOutputFormat::Json);
    }

    #[test]
    fn cli_beats_config_for_scalars() {
        let yaml = r#"
scan:
  confidence: high
  redact: true
output:
  format: json
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) =
            parse(&["kingfisher", "scan", "--confidence", "low", "--format", "toon", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        // CLI wins
        assert_eq!(scan_args.confidence, ConfidenceLevel::Low);
        assert_eq!(scan_args.output_args.format, ReportOutputFormat::Toon);
        // Bool with no CLI flag still picks up config
        assert!(scan_args.redact);
    }

    #[test]
    fn lists_are_concatenated_with_cli() {
        let yaml = r#"
filters:
  skip_words: ["FROM_CONFIG"]
  exclude: ["vendor/"]
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&[
            "kingfisher",
            "scan",
            "--skip-word",
            "FROM_CLI",
            "--exclude",
            "node_modules/",
            ".",
        ]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(scan_args.skip_word.contains(&"FROM_CLI".to_string()));
        assert!(scan_args.skip_word.contains(&"FROM_CONFIG".to_string()));
        assert!(scan_args.content_filtering_args.exclude.contains(&"vendor/".to_string()));
        assert!(scan_args.content_filtering_args.exclude.contains(&"node_modules/".to_string()));
    }

    #[test]
    fn rules_enabled_replaces_default_but_appends_to_user_selection() {
        // Case A: user passes --rule, config appends.
        let yaml = r#"
rules:
  enabled: ["custom"]
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "--rule", "default", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(scan_args.rules.rule.contains(&"default".to_string()));
        assert!(scan_args.rules.rule.contains(&"custom".to_string()));

        // Case B: user did not pass --rule (CLI default `["all"]` in effect),
        // config replaces — otherwise users could never *narrow* the
        // selection from the config.
        let (args, matches) = parse(&["kingfisher", "scan", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(scan_args.rules.rule, vec!["custom".to_string()]);
    }

    #[test]
    fn rule_cache_config_and_cli_precedence_respects_opt_out() {
        let cfg = parse_str(
            r#"
rules:
  cache: false
"#,
        )
        .unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(!scan_args.rule_cache.enabled(), "config rules.cache=false should disable cache");

        let cfg = parse_str(
            r#"
rules:
  cache: true
"#,
        )
        .unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "--no-rule-cache", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(!scan_args.rule_cache.enabled(), "CLI --no-rule-cache should beat config");

        let cfg = parse_str(
            r#"
rules:
  cache: false
"#,
        )
        .unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "--rule-cache", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(scan_args.rule_cache.enabled(), "CLI --rule-cache should beat config");
    }

    #[test]
    fn validation_rps_per_rule_appended_as_strings() {
        let yaml = r#"
validation:
  rps_per_rule:
    kingfisher.aws: 1.5
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) =
            parse(&["kingfisher", "scan", "--validation-rps-rule", "kingfisher.gcp=2.0", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert!(scan_args.validation_rps_rule.contains(&"kingfisher.gcp=2.0".to_string()));
        assert!(scan_args.validation_rps_rule.contains(&"kingfisher.aws=1.5".to_string()));
    }

    #[test]
    fn alerts_defaults_set_alert_globals_when_cli_default() {
        let yaml = r#"
alerts:
  defaults:
    min_confidence: high
    include_secret: true
    detail: summary
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(scan_args.alert_min_confidence, ConfidenceLevel::High);
        assert!(scan_args.alert_include_secret);
        assert_eq!(scan_args.alert_detail, kingfisher::alerts::AlertDetail::Summary);
    }

    #[test]
    fn cli_alert_flag_beats_config_default() {
        let yaml = r#"
alerts:
  defaults:
    min_confidence: high
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "--alert-min-confidence", "low", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(scan_args.alert_min_confidence, ConfidenceLevel::Low);
    }

    #[test]
    fn config_init_round_trips_supplied_flags_only() {
        // Take a CLI invocation, build a YAML config, parse it back, and
        // check that the resulting KingfisherConfig has *only* what we passed
        // (CLI defaults must not be reified into the config — that would
        // freeze an arbitrary moment in time as a "user choice").
        use kingfisher::cli::config::{ConfigConfidence, ConfigReportFormat, parse_str};

        let argv = &[
            "kingfisher",
            "config",
            "init",
            "--confidence",
            "high",
            "--redact",
            "--exclude",
            "vendor/",
            "--skip-word",
            "EXAMPLE",
            "--format",
            "toon",
            "--alert-min-confidence",
            "high",
            "--alert-webhook",
            "https://hooks.slack.com/services/T0/B0/AAA",
            "--tls-mode",
            "lax",
        ];
        let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
        let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
        let global_args = parsed.global_args.clone();

        let init_matches =
            matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();

        // Recover the ScanArgs from the parsed `Config(Init(...))` branch.
        let scan_args = match parsed.command {
            Command::Config(c) => match c.command {
                kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                    args.scan_args
                }
            },
            _ => panic!("expected config init"),
        };

        let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
        let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");

        // Exact set of keys that should be present.
        assert!(matches!(cfg.scan.confidence, Some(ConfigConfidence::High)));
        assert_eq!(cfg.scan.redact, Some(true));
        assert!(cfg.scan.no_dedup.is_none(), "should not emit unset bools");
        assert!(cfg.scan.jobs.is_none(), "should not emit clap-default scalars");

        assert_eq!(cfg.filters.exclude, vec!["vendor/".to_string()]);
        assert_eq!(cfg.filters.skip_words, vec!["EXAMPLE".to_string()]);
        assert!(cfg.filters.max_file_size_mb.is_none(), "should not emit unset filters");

        assert!(matches!(cfg.output.format, Some(ConfigReportFormat::Toon)));
        assert!(cfg.output.path.is_none());

        assert!(matches!(cfg.alerts.defaults.min_confidence, Some(ConfigConfidence::High)));
        assert_eq!(cfg.alerts.webhooks.len(), 1);
        assert_eq!(cfg.alerts.webhooks[0].url, "https://hooks.slack.com/services/T0/B0/AAA");

        assert!(matches!(cfg.global.tls_mode, Some(kingfisher::cli::config::ConfigTlsMode::Lax)));
    }

    /// Regression: `config init --github-api-url ... --gitlab-api-url ...`
    /// must round-trip the strings the user typed. `Url::to_string()` adds
    /// a trailing `/` to bare-host URLs, so re-serializing the parsed `Url`
    /// would silently rewrite `https://gitlab.example.com` →
    /// `https://gitlab.example.com/` on every `config init` run.
    #[test]
    fn config_init_preserves_raw_api_url_strings() {
        use kingfisher::cli::config::parse_str;

        let argv = &[
            "kingfisher",
            "config",
            "init",
            // Bare host (no trailing slash) — `Url::to_string()` would add one.
            "--github-api-url",
            "https://ghe.corp.example.com/api/v3",
            "--gitlab-api-url",
            "https://gitlab.corp.example.com",
        ];
        let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
        let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
        let global_args = parsed.global_args.clone();
        let init_matches =
            matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();
        let scan_args = match parsed.command {
            Command::Config(c) => match c.command {
                kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                    args.scan_args
                }
            },
            _ => panic!("expected config init"),
        };

        let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
        let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");

        assert_eq!(
            cfg.git.github_api_url.as_deref(),
            Some("https://ghe.corp.example.com/api/v3"),
            "github_api_url must preserve user input verbatim, no trailing-slash rewrite",
        );
        assert_eq!(
            cfg.git.gitlab_api_url.as_deref(),
            Some("https://gitlab.corp.example.com"),
            "gitlab_api_url must preserve user input verbatim, no trailing-slash rewrite",
        );

        // Sanity: when the user *does* pass a trailing slash, that's preserved too.
        let argv = &[
            "kingfisher",
            "config",
            "init",
            "--github-api-url",
            "https://ghe.corp.example.com/api/v3/",
        ];
        let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
        let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
        let global_args = parsed.global_args.clone();
        let init_matches =
            matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();
        let scan_args = match parsed.command {
            Command::Config(c) => match c.command {
                kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                    args.scan_args
                }
            },
            _ => panic!("expected config init"),
        };
        let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
        let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");
        assert_eq!(
            cfg.git.github_api_url.as_deref(),
            Some("https://ghe.corp.example.com/api/v3/"),
            "github_api_url must preserve a user-supplied trailing slash",
        );
    }

    #[test]
    fn config_init_with_no_flags_emits_placeholder_comment() {
        // Edge case: user runs `kingfisher config init` with no flags. The
        // emitted file should still be valid YAML / a clear no-op rather
        // than a bare `{}`.
        let argv = &["kingfisher", "config", "init"];
        let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
        let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
        let global_args = parsed.global_args.clone();

        let init_matches =
            matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();

        let scan_args = match parsed.command {
            Command::Config(c) => match c.command {
                kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                    args.scan_args
                }
            },
            _ => panic!("expected config init"),
        };

        let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
        assert!(yaml.contains("no flags supplied"), "expected no-op header, got:\n{yaml}");
        assert!(!yaml.trim().ends_with("{}"));
    }

    #[test]
    fn global_section_updates_global_args_when_cli_default() {
        let yaml = r#"
global:
  tls_mode: lax
  allow_internal_ips: true
  endpoints:
    - github=https://ghe.example.com/api/v3/
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "."]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(global_args.tls_mode, kingfisher::cli::global::TlsMode::Lax);
        assert!(global_args.allow_internal_ips);
        assert_eq!(global_args.endpoint.len(), 1);
    }

    /// Regression test: an explicit `--api-url` on the `scan github`
    /// subcommand must beat `git.github_api_url` from the config file. The
    /// flag lives on `GithubScanArgs` (id `api_url`), not on the outer scan
    /// command — checking only the outer matches misses it and the config
    /// silently overrode the CLI value.
    #[test]
    fn github_subcommand_api_url_beats_config() {
        let yaml = r#"
git:
  github_api_url: https://ghe-from-config.example.com/api/v3/
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&[
            "kingfisher",
            "scan",
            "github",
            "--organization",
            "my-org",
            "--api-url",
            "https://ghe-from-cli.example.com/api/v3/",
        ]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(
            scan_args.input_specifier_args.github_api_url.as_str(),
            "https://ghe-from-cli.example.com/api/v3/",
        );
    }

    /// And the inverse: when the user did NOT pass `--api-url` at all,
    /// `git.github_api_url` from the config should still win over the
    /// built-in default `https://api.github.com/`.
    #[test]
    fn github_config_wins_when_subcommand_api_url_default() {
        let yaml = r#"
git:
  github_api_url: https://ghe-from-config.example.com/api/v3/
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&["kingfisher", "scan", "github", "--organization", "my-org"]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(
            scan_args.input_specifier_args.github_api_url.as_str(),
            "https://ghe-from-config.example.com/api/v3/",
        );
    }

    /// Same precedence story for `scan gitlab --api-url`.
    #[test]
    fn gitlab_subcommand_api_url_beats_config() {
        let yaml = r#"
git:
  gitlab_api_url: https://gitlab-from-config.example.com/
"#;
        let cfg = parse_str(yaml).unwrap();
        let (args, matches) = parse(&[
            "kingfisher",
            "scan",
            "gitlab",
            "--group",
            "my-group",
            "--api-url",
            "https://gitlab-from-cli.example.com/",
        ]);
        let mut global_args = args.global_args.clone();
        let mut scan_args = into_scan(args);
        super::apply_config(
            &mut scan_args,
            &mut global_args,
            &cfg,
            matches.subcommand_matches("scan"),
        );
        assert_eq!(
            scan_args.input_specifier_args.gitlab_api_url.as_str(),
            "https://gitlab-from-cli.example.com/",
        );
    }
}
