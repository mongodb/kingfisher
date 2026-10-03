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
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result};
use kingfisher::{
    access_map, azure, bitbucket,
    cli::{
        self, CommandLineArgs, GlobalArgs,
        commands::{inputs::InputSpecifierArgs, rules::RulesCommand},
        global::Command,
    },
    direct_access_map, direct_revoke, direct_validate, findings_store,
    findings_store::FindingsStore,
    gitea, github, huggingface,
    reporter::{DetailsReporter, ScanAuditContext, styles::Styles},
    scanner::{load_and_record_rules, run_scan},
    update::{check_for_update_async, rewrite_argv_for_reexec},
    util::tokio_blocking_threads_limit,
    validation::set_user_agent_suffix,
};
use tempfile::TempDir;
use tokio::runtime::Builder;
use tracing::{error, info, warn};
use tracing_core::metadata::LevelFilter;
use tracing_subscriber::{
    self, fmt, prelude::__tracing_subscriber_SubscriberExt, registry, util::SubscriberInitExt,
};

use crate::cli::commands::{
    scan::{ListRepositoriesCommand, ScanOperation},
    view,
};

mod app;

#[cfg(test)]
use app::build_config_yaml;
use app::{
    apply_config, load_project_config, run_config_command, run_rules_check,
    run_rules_compile_cache, run_rules_list, run_rules_prune_cache,
};

fn main() -> anyhow::Result<()> {
    raise_nproc_soft_limit();
    const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MiB
    // Clap's derived parser can overflow Windows' main-thread stack in debug builds.
    // Box its result so transferring the large command enum also stays off that stack.
    let parser = std::thread::Builder::new()
        .name("kingfisher-args".to_string())
        .stack_size(STACK_SIZE)
        .spawn(|| {
            let (args, matches) = CommandLineArgs::parse_args_with_matches();
            (Box::new(args), matches)
        })
        .context("Failed to spawn argument parser thread")?;
    let (args, matches) = parser.join().unwrap_or_else(|e| std::panic::resume_unwind(e));

    // GPUI must run on the OS main thread. Keep the raw matches when handing other
    // commands to the larger-stack worker so config precedence still distinguishes
    // explicit flags from clap defaults.
    if let Command::Wizard(wizard) = &args.command {
        #[cfg(feature = "gui")]
        return kingfisher::wizard::run(
            wizard.target.clone(),
            wizard.report.clone(),
            kingfisher::wizard::global_values(&matches),
        );
        #[cfg(not(feature = "gui"))]
        {
            let _ = wizard;
            anyhow::bail!(
                "This build does not include the native wizard. Build with `cargo build --release --features gui --bin kingfisher`, then run `kingfisher wizard` (alias: `kingfisher gui`)."
            );
        }
    }
    // Run the real entry point on a thread with an explicit, larger stack so that
    // deeply-nested async state machines (validation pipeline) cannot overflow the
    // default main-thread stack.
    let builder =
        std::thread::Builder::new().name("kingfisher-main".to_string()).stack_size(STACK_SIZE);

    let handler = builder.spawn(move || run(*args, matches)).expect("failed to spawn main thread");
    let result = handler.join().unwrap_or_else(|e| std::panic::resume_unwind(e));
    if let Err(error) = &result
        && error.is::<kingfisher::scanner::NoScanInputsError>()
    {
        eprintln!("Error: {error:?}");
        std::process::exit(3);
    }
    result
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

fn run(args: CommandLineArgs, matches: clap::ArgMatches) -> anyhow::Result<()> {
    // Install the AWS-LC Rustls provider before initializing any TLS clients.
    match rustls::crypto::aws_lc_rs::default_provider().install_default() {
        Ok(()) => {}
        Err(_already_installed) => {
            // Another crate already installed a provider. This is unusual for a CLI, but
            // surfacing it makes later TLS issues much easier to diagnose.
            warn!("rustls crypto provider was already installed; keeping existing provider");
        }
    }
    set_user_agent_suffix(args.global_args.user_agent_suffix.clone());

    // Select runtime parallelism for the command; scans use their resolved job count.
    let num_jobs = match &args.command {
        Command::Scan(scan_args) => scan_args.scan_args.num_jobs,
        Command::SelfUpdate => 1, // Self-update doesn't need a thread pool
        Command::Rules(_) => std::thread::available_parallelism().map_or(1, |n| n.get()), // Default for Rules commands
        Command::Validate(_) => 1, // Single validation request
        Command::Revoke(_) => 1,   // Single revocation request
        Command::BlastRadius(_) => 1,
        Command::View(_) | Command::Wizard(_) => 1,
        Command::Config(_) => 1,
    };

    // Set up the Tokio runtime with the specified number of threads.
    // Validation futures can produce large poll stack frames, so worker threads
    // use an 8 MiB stack.
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
    let filter = if all_targets {
        // Enable TRACE for all modules
        tracing_subscriber::filter::Targets::new().with_default(LevelFilter::TRACE)
    } else {
        // Limit non-Kingfisher targets to errors at normal verbosity.
        tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::ERROR) // Default for all modules
            .with_target("kingfisher", level)
    };
    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_target(true) // Include the tracing target in each log line
        .with_ansi(std::io::stderr().is_terminal()) // Emit ANSI colours when stderr is a TTY
        .without_time();
    registry().with(fmt_layer).with(filter).init();
}

/// Describe the first configured scan target, in priority order, for alert payloads.
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
    if !args.github_event_user.is_empty() {
        return Some(format!(
            "github public events: {}",
            join_brief(&args.github_event_user, "github users")
        ));
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
    if !args.huggingface_user.is_empty()
        || !args.huggingface_organization.is_empty()
        || !args.huggingface_model.is_empty()
        || !args.huggingface_dataset.is_empty()
        || !args.huggingface_space.is_empty()
        || !args.huggingface_bucket.is_empty()
    {
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

/// Return whether stdin should be staged as a scan input.
///
/// `-` is the only way to ask for a stdin scan: `ScanCommandArgs::into_operation`
/// rejects an invocation that names no input at all, so an empty `path_inputs`
/// means some *other* source (a Git URL, an org, a bucket, ...) was selected and
/// must not be silently replaced by whatever happens to be on a redirected stdin.
fn should_stage_stdin(input_args: &InputSpecifierArgs, stdin_is_terminal: bool) -> bool {
    !stdin_is_terminal && input_args.path_inputs.iter().any(is_stdin_placeholder)
}

fn is_stdin_placeholder(path: impl AsRef<std::path::Path>) -> bool {
    path.as_ref().as_os_str() == "-"
}

/// Swap the `-` placeholders in `path_inputs` for the staged stdin file.
///
/// Repeated `-` arguments collapse onto the single staged file, and any sibling
/// paths (`kingfisher scan - ./src`) keep their position instead of being
/// dropped.
fn replace_stdin_placeholders(path_inputs: &mut Vec<PathBuf>, stdin_file: PathBuf) {
    let mut staged = false;
    let mut resolved = Vec::with_capacity(path_inputs.len());
    for path in path_inputs.drain(..) {
        if is_stdin_placeholder(&path) {
            if !std::mem::replace(&mut staged, true) {
                resolved.push(stdin_file.clone());
            }
        } else {
            resolved.push(path);
        }
    }
    *path_inputs = resolved;
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
            let finding_filter = override_.finding_filter.unwrap_or(scan_args.alert_finding_filter);
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
                finding_filter,
                prevent_empty: override_.prevent_empty.unwrap_or(scan_args.alert_prevent_empty),
            }
        })
        .collect()
}

/// Warn about alert configurations that will silently produce nothing, before
/// the scan starts.
///
/// `build_alert_sinks` runs only after the scan completes, so a check placed
/// there would tell the operator their filter was unusable only once they had
/// already paid for a full scan.
fn warn_on_alert_misconfiguration(scan_args: &cli::commands::scan::ScanArgs) {
    if scan_args.alert_webhook.is_empty() {
        return;
    }
    for sink in build_alert_sinks(scan_args) {
        if sink.finding_filter == kingfisher::alerts::AlertFindingFilter::AccessMapOnly
            && !scan_args.access_map
        {
            warn!(
                "alert sink {} uses access-map-only filtering but --blast-radius was not enabled; \
                 this sink will not include findings (use --alert-prevent-empty to suppress \
                 empty filtered alerts)",
                kingfisher::alerts::redact_webhook(&sink.url)
            );
        }
    }
}

pub fn determine_exit_code(datastore: &Arc<Mutex<findings_store::FindingsStore>>) -> i32 {
    // exit with code 200 if _any_ findings are discovered
    // exit with code 205 if VALIDATED findings are discovered
    // exit with code 0 if there are NO findings discovered
    let ds = datastore.lock().unwrap();

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
                match_item.rule.syntax().is_authoritative()
                    && match_item.validation_outcome.is_verified_active()
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
        Command::BlastRadius(blast_radius_args) => {
            if blast_radius_args.rule.is_none() {
                let view_report = blast_radius_args.view_report;
                let provider = blast_radius_args
                    .input
                    .as_deref()
                    .ok_or_else(|| {
                        anyhow::anyhow!("a provider is required for standalone mapping")
                    })?
                    .parse::<cli::commands::access_map::AccessMapProvider>()
                    .map_err(|error| anyhow::anyhow!(error))?;
                let format = match blast_radius_args.format.as_str() {
                    "json" => cli::commands::access_map::AccessMapOutputFormat::Json,
                    "html" => cli::commands::access_map::AccessMapOutputFormat::Html,
                    _ if blast_radius_args.view_report => {
                        cli::commands::access_map::AccessMapOutputFormat::Json
                    }
                    _ => anyhow::bail!(
                        "standalone blast-radius mapping supports only json and html output"
                    ),
                };
                let access_map_args = cli::commands::access_map::AccessMapArgs {
                    provider,
                    credential_path: blast_radius_args.credential_path,
                    output_args: cli::commands::access_map::AccessMapOutputArgs {
                        output: blast_radius_args.output,
                        format,
                    },
                };
                if view_report {
                    let result = access_map::map_credential(&access_map_args).await?;
                    let report_bytes = direct_access_map::build_viewer_report_bytes(&[
                        direct_access_map::DirectAccessMapResult {
                            rule_id: format!("standalone.{}", result.cloud),
                            rule_name: format!("Standalone {} credential", result.cloud),
                            result,
                        },
                    ])?;
                    view::run(view::ViewArgs {
                        reports: Vec::new(),
                        port: view::DEFAULT_PORT,
                        address: view::DEFAULT_ADDRESS.to_string(),
                        open_browser: true,
                        report_bytes: Some(report_bytes),
                    })
                    .await?;
                } else {
                    access_map::run(access_map_args).await?;
                }
                return Ok(AsyncMainOutcome::Done);
            }
            let results =
                direct_access_map::run_direct_access_map(&blast_radius_args, &global_args).await?;
            if blast_radius_args.view_report {
                let report_bytes = direct_access_map::build_viewer_report_bytes(&results)?;
                view::run(view::ViewArgs {
                    reports: Vec::new(),
                    port: view::DEFAULT_PORT,
                    address: view::DEFAULT_ADDRESS.to_string(),
                    open_browser: true,
                    report_bytes: Some(report_bytes),
                })
                .await?;
            } else {
                direct_access_map::print_results(
                    &results,
                    &blast_radius_args.format,
                    blast_radius_args.output.as_deref(),
                )?;
            }
            Ok(AsyncMainOutcome::Done)
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
            // Offline local derivation is a successful validation operation even though it does
            // not claim the material is an active credential.
            if direct_validate::any_actionable(&results) {
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
                        // Load only the explicitly selected config. Scalars respect CLI/env
                        // precedence; list values are additive, except that configured rules
                        // replace Clap's synthetic `all` default.
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
                        // Config merging can introduce `output_args.output`
                        // (output.path) after CLI validation already ran, so
                        // re-check the effective --audit-log / --output paths
                        // against the merged values.
                        scan_args.validate_audit_log_collisions(
                            global_args.endpoint_config.as_deref(),
                            global_args.config.as_deref(),
                        )?;
                        warn_on_alert_misconfiguration(&scan_args);
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
                            "Launching with {} concurrent scan jobs. Use --jobs to override.",
                            &scan_args.num_jobs
                        );
                        if should_stage_stdin(
                            &scan_args.input_specifier_args,
                            std::io::stdin().is_terminal(),
                        ) {
                            let mut buf = Vec::new();
                            std::io::stdin().read_to_end(&mut buf)?;
                            let stdin_file = temp_dir_path.join("stdin_input");
                            std::fs::write(&stdin_file, buf)?;
                            replace_stdin_placeholders(
                                &mut scan_args.input_specifier_args.path_inputs,
                                stdin_file,
                            );
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
                                validation_filter: scan_args.effective_validation_filter(),
                                audit_context: None,
                            };
                            match alert_reporter.build_finding_records(&scan_args) {
                                Ok(records) => {
                                    let target =
                                        describe_scan_target(&scan_args.input_specifier_args);
                                    let access_map =
                                        alert_reporter.build_alert_access_map_entries(&scan_args);
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
                                    kingfisher::alerts::dispatch_with_context(
                                        &sinks,
                                        &records,
                                        &access_map,
                                        target,
                                        scan_args.alert_dry_run,
                                    )
                                    .await;
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
                                validation_filter: scan_args.effective_validation_filter(),
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
                                specifiers.include_gists,
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
                                specifiers.include_snippets,
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
                                specifiers.include_snippets,
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
                                bucket: specifiers.bucket.clone(),
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
                Command::View(_) | Command::Wizard(_) => {
                    anyhow::bail!("View and wizard commands should not reach this branch")
                }
                Command::BlastRadius(_) => {
                    anyhow::bail!("BlastRadius command should not reach this branch")
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

#[cfg(test)]
#[path = "app/config_tests.rs"]
mod apply_config_tests;
