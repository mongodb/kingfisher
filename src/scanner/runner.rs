use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use crossbeam_channel;
use crossbeam_skiplist::SkipMap;
use indicatif::ProgressBar;
use tokio::runtime::Handle;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, trace};

use crate::{
    access_map,
    cli::{commands::scan, global},
    findings_store,
    findings_store::{FindingsStore, FindingsStoreMessage},
    github,
    liquid_filters::register_all,
    matcher::MatcherStats,
    provider_endpoints::ProviderEndpointOverrides,
    reporter::styles::Styles,
    rule_profiling::ConcurrentRuleProfiler,
    rules::rule::Validation,
    rules_database::RulesDatabase,
    safe_list,
    scan_audit::{RepositoryScanStats, ScanAuditCollector, SharedScanAudit, combine_git_snapshots},
    scanner::{
        AccessMapCollector, enumerate_filesystem_inputs, enumerate_github_event_targets,
        repos::{
            enumerate_huggingface_buckets, fetch_gcs_objects, fetch_huggingface_objects,
            fetch_s3_objects,
        },
        run_secret_validation,
        summary::{compute_scan_totals, print_scan_summary},
    },
    util::set_redaction_enabled,
    validation::CachedResponse,
    validation_rate_limit::ValidationRateLimiter,
};

use super::{
    discovery::{
        ArtifactFetchHandle, github_event_targets_by_root, scan_args_for_github_event_target,
        start_discovery_and_artifact_fetching, start_repo_cloning,
    },
    roots::{expand_repo_roots, is_git_repository_root},
};

/// Shared validation dependencies:
/// (liquid parser, HTTP clients, validation cache, rate limiter, provider endpoint overrides).
type ValidationDeps = Arc<(
    liquid::Parser,
    crate::validation::ValidationClients,
    Arc<SkipMap<String, CachedResponse>>,
    Option<Arc<ValidationRateLimiter>>,
    Arc<ProviderEndpointOverrides>,
)>;

static SCAN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Keep process-wide validation results alive for the duration of one scan.
///
/// Parallel repository scans run validation in separate phases. The findings
/// remain intentionally duplicated when `--no-dedup` is set, but those
/// duplicates should still share one validation request. Clearing this cache
/// at the end of each phase would make the result unavailable to the next
/// repository phase, so the lifetime is tied to the complete scan instead.
struct ValidationCacheLifetime {
    // Hold the lock until Drop has cleared the process-wide caches.
    _scan_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl ValidationCacheLifetime {
    async fn begin() -> Self {
        // Overlapping scans must not retire another scan's in-flight validators.
        let scan_guard = SCAN_LOCK.lock().await;
        // A caller may reuse the library in one process. Do not carry results
        // from a previous scan into the current scan.
        crate::validation::clear_validation_caches();
        Self { _scan_guard: scan_guard }
    }
}

impl Drop for ValidationCacheLifetime {
    fn drop(&mut self) {
        crate::validation::clear_validation_caches();
    }
}

/// Run an application scan, adding command-level context to failures.
///
/// # Errors
///
/// Returns the errors documented by [`run_async_scan`].
///
/// # Panics
///
/// Has the same runtime and worker requirements as [`run_async_scan`].
pub async fn run_scan(
    global_args: &global::GlobalArgs,
    scan_args: &scan::ScanArgs,
    rules_db: &RulesDatabase,
    datastore: Arc<Mutex<FindingsStore>>,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    run_async_scan(
        global_args,
        scan_args,
        Arc::clone(&datastore),
        rules_db,
        update_status,
        auto_cleanup_clones,
    )
    .await
    .context("Failed to run scan command")
}

/// Discover inputs, scan content, and run configured validation and reporting phases.
///
/// This application API requires a Tokio runtime and uses process-wide scan
/// configuration. Overlapping calls serialize their validation-cache lifetimes.
/// Use [`kingfisher_scanner::Scanner`] for independent synchronous embedding.
///
/// # Errors
///
/// Returns input/configuration, discovery, matching, validation setup, storage,
/// and reporting errors. Empty discovery returns an error containing
/// [`super::NoScanInputsError`]. Individual provider outcomes remain finding data.
///
/// # Panics
///
/// Panics if polled without a Tokio runtime, the OS cannot spawn a required
/// worker thread, or a shared datastore/audit mutex has been poisoned.
pub async fn run_async_scan(
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    kingfisher_scanner::validation::limits::NetworkLimits {
        no_timeouts: args.content_filtering_args.no_limits,
        unlimited_response: args.content_filtering_args.no_limits,
        unlimited_results: args.content_filtering_args.no_limits,
    }
    .scope(run_async_scan_inner(
        global_args,
        args,
        datastore,
        rules_db,
        update_status,
        auto_cleanup_clones,
    ))
    .await
}

async fn run_async_scan_inner(
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    let scan_started_at = chrono::Local::now();
    let mut timed_args = args.clone();
    timed_args.input_specifier_args.history_time_range =
        args.input_specifier_args.history_time_range.or_else(|| {
            args.input_specifier_args.since_hours.map(|hours| {
                let end = scan_started_at.timestamp();
                (end - i64::from(hours) * 3600, end)
            })
        });
    if timed_args.content_filtering_args.no_limits {
        timed_args.input_specifier_args.repo_clone_limit = None;
        timed_args.validation_timeout = 0;
        timed_args.max_validation_response_length = 0;
    }
    let args = &timed_args;
    let _validation_cache_lifetime =
        if args.no_validate { None } else { Some(ValidationCacheLifetime::begin().await) };

    let _wizard_progress = crate::scan_progress::start();

    // ── Phase 1: Input validation and environment setup ──────────────────
    validate_inputs(args)?;
    if args.disk_offload {
        datastore.lock().unwrap().enable_spilling()?;
    }
    register_safe_list_patterns(args)?;

    let start_time = Instant::now();
    let audit_log = args.audit_log.as_deref().map(crate::util::expand_tilde);
    let scan_audit: SharedScanAudit = Arc::new(Mutex::new(ScanAuditCollector::new(
        scan_started_at.to_rfc3339(),
        audit_log.as_deref(),
    )?));

    trace!("Args:\n{global_args:#?}\n{args:#?}");
    let progress_enabled = global_args.use_progress();
    initialize_environment(progress_enabled, args.num_jobs)?;

    set_redaction_enabled(args.redact);

    // ── Phase 2: Repository enumeration ─────────────────────────────────
    crate::scan_progress::phase(
        "Discovering repositories and fetching inputs",
        0,
        crate::scan_progress::PhaseKind::Other,
    );
    // Event selectors must be ready before scanning, since they determine refs.
    let github_event_targets = enumerate_github_event_targets(args, global_args).await?;
    let github_event_targets_by_root =
        Arc::new(github_event_targets_by_root(&github_event_targets, &datastore));
    let huggingface_buckets = enumerate_huggingface_buckets(args, global_args).await?;

    let mut input_roots = args.input_specifier_args.path_inputs.clone();
    // Bound the channel feeding the scan loop. Both the cloner pool and the
    // artifact-fetching task push into this channel; bounding it caps how
    // many cloned-but-unscanned repos sit on disk while the scanner catches
    // up. Combined with the inner cloner→dispatcher channel (also
    // 2*num_jobs) and the per-repo cleanup after scan, the worst-case
    // on-disk count is roughly 6*num_jobs (inner queue + outer queue +
    // active cloners + active scans), i.e. O(num_jobs).
    let scan_channel_cap = std::cmp::max(2, args.num_jobs * 2);
    let (repo_tx, repo_rx) = crossbeam_channel::bounded(scan_channel_cap);

    // ── Phase 3: Spawn cloning + artifact-fetching concurrently ─────────
    // The scan loop will start consuming from `repo_rx` as soon as we get
    // there in Phase 5; both producers feed it as their work completes.
    let (url_tx, url_rx) = crossbeam_channel::bounded(scan_channel_cap);
    let repo_clone_handle =
        start_repo_cloning(url_rx, args, global_args, &datastore, &scan_audit, repo_tx.clone());
    let artifact_handle = start_discovery_and_artifact_fetching(
        args,
        global_args,
        github_event_targets,
        url_tx,
        &scan_audit,
        !huggingface_buckets.is_empty(),
        &datastore,
        repo_tx.clone(),
        progress_enabled,
    );
    // Drop the local sender so the channel closes once all producers finish.
    drop(repo_tx);

    // ── Phase 4: Scan configuration ─────────────────────────────────────
    let shared_profiler = Arc::new(ConcurrentRuleProfiler::new());
    let enable_profiling = args.rule_stats;
    let matcher_stats = Arc::new(Mutex::new(MatcherStats::default()));

    fetch_huggingface_objects(
        args,
        global_args,
        &huggingface_buckets,
        &datastore,
        rules_db,
        matcher_stats.as_ref(),
        enable_profiling,
        Arc::clone(&shared_profiler),
        progress_enabled,
    )
    .await?;

    // Fetch S3 objects if requested (scanned immediately)
    fetch_s3_objects(
        args,
        &datastore,
        rules_db,
        matcher_stats.as_ref(),
        enable_profiling,
        Arc::clone(&shared_profiler),
        progress_enabled,
    )
    .await?;

    fetch_gcs_objects(
        args,
        &datastore,
        rules_db,
        matcher_stats.as_ref(),
        enable_profiling,
        Arc::clone(&shared_profiler),
        progress_enabled,
    )
    .await?;

    let baseline_path = Arc::new(
        args.baseline_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("baseline-file.yaml")),
    );
    let baseline = Arc::new(
        if (args.baseline_file.is_some() || args.manage_baseline) && baseline_path.exists() {
            crate::baseline::load_baseline(baseline_path.as_ref())?
        } else {
            crate::baseline::BaselineFile::default()
        },
    );

    let skip_aws_accounts = load_skip_aws_accounts(args)?;
    crate::validation::set_skip_aws_account_ids(skip_aws_accounts);

    let mut access_map_collector =
        if args.access_map { Some(AccessMapCollector::default()) } else { None };

    // Use the same --exclude semantics as the filesystem walker so the
    // discovery pre-scan skips exactly the trees the scan will skip: this
    // avoids paying startup traversal for excluded dependency/build trees and
    // keeps excluded repositories out of the audit manifest.
    let exclude_globset = crate::build_exclude_globset(&args.content_filtering_args.exclude)?;
    let (repo_roots, discovered_repos) = if args.input_specifier_args.scan_nested_repos {
        expand_repo_roots(&input_roots, exclude_globset.as_ref())?
    } else {
        let roots =
            input_roots.iter().filter(|root| is_git_repository_root(root)).cloned().collect();
        (input_roots.clone(), roots)
    };
    let discovered_repos = Arc::new(discovered_repos);
    {
        let mut audit = scan_audit.lock().unwrap();
        for root in &repo_roots {
            if is_git_repository_root(root) {
                audit.discover_local(root);
            }
        }
    }
    let git_repo_count = repo_roots.iter().filter(|root| is_git_repository_root(root)).count()
        + args.input_specifier_args.git_url.len();
    // Discovery is still running, so the final repository count is not known.
    let input = &args.input_specifier_args;
    let use_parallel_repo_scan = git_repo_count > 10
        || input.has_repository_discovery()
        || input.include_contributors
        || github_event_targets_by_root.len() > 10;

    let validation_rate_limiter =
        ValidationRateLimiter::from_cli(args.validation_rps, &args.validation_rps_rule)?
            .map(Arc::new);
    let provider_endpoints = Arc::new(ProviderEndpointOverrides::from_global_args(global_args)?);

    let validation_deps: Option<ValidationDeps> = if !args.no_validate {
        Some(Arc::new((
            register_all(liquid::ParserBuilder::with_stdlib()).build()?,
            crate::validation::ValidationClients::with_timeout(
                global_args.tls_mode,
                global_args.allow_internal_ips,
                Duration::from_secs(args.validation_timeout),
                args.content_filtering_args.no_limits,
            )?
            .with_unlimited_results(args.content_filtering_args.no_limits),
            Arc::new(SkipMap::new()),
            validation_rate_limiter.clone(),
            Arc::clone(&provider_endpoints),
        )))
    } else {
        None
    };

    // ── Phase 5: Scanning ───────────────────────────────────────────────
    if !use_parallel_repo_scan {
        run_sequential_scan(
            args,
            global_args,
            &datastore,
            rules_db,
            &mut input_roots,
            &repo_roots,
            Arc::clone(&discovered_repos),
            repo_rx,
            repo_clone_handle,
            artifact_handle,
            Arc::clone(&github_event_targets_by_root),
            &shared_profiler,
            enable_profiling,
            &matcher_stats,
            &baseline_path,
            &baseline,
            &validation_deps,
            &mut access_map_collector,
            progress_enabled,
            start_time,
            scan_started_at,
            update_status,
            auto_cleanup_clones,
            Arc::clone(&scan_audit),
        )
        .await?;
        return Ok(());
    }

    run_parallel_scan(
        args,
        global_args,
        &datastore,
        rules_db,
        &repo_roots,
        Arc::clone(&discovered_repos),
        repo_rx,
        repo_clone_handle,
        artifact_handle,
        Arc::clone(&github_event_targets_by_root),
        &shared_profiler,
        enable_profiling,
        &matcher_stats,
        &baseline_path,
        &baseline,
        &validation_deps,
        &mut access_map_collector,
        progress_enabled,
        start_time,
        scan_started_at,
        update_status,
        auto_cleanup_clones,
        Arc::clone(&scan_audit),
    )
    .await
}

// =================================================================================================
// Phase helpers
// =================================================================================================

/// Validates that all provided input paths exist.
fn validate_inputs(args: &scan::ScanArgs) -> Result<()> {
    let input = &args.input_specifier_args;
    if let Some(hours) = input.since_hours {
        if hours == 0 {
            bail!("--since-hours must be at least 1");
        }
        if input.git_history != crate::cli::commands::github::GitHistoryMode::Full {
            bail!("--since-hours requires --git-history full");
        }
        if input.since_commit.is_some()
            || input.staged
            || input.branch_root
            || input.branch_root_commit.is_some()
        {
            bail!(
                "--since-hours cannot be combined with --since-commit, --staged, or branch-root options"
            );
        }
        if !input.github_event_user.is_empty() {
            bail!(
                "--since-hours cannot be combined with GitHub public-event scanning; use --event-lookback-hours for event timestamps"
            );
        }
    }
    for path in &args.input_specifier_args.path_inputs {
        if !path.exists() {
            error!("Specified input path does not exist: {}", path.display());
            bail!("Invalid input: Path does not exist - {}", path.display());
        }
    }
    Ok(())
}

/// Registers user-provided allow-list patterns (skip-regex and skip-word).
fn register_safe_list_patterns(args: &scan::ScanArgs) -> Result<()> {
    for pattern in &args.skip_regex {
        safe_list::add_user_regex(pattern)
            .map_err(|e| anyhow::anyhow!("Invalid skip-regex '{pattern}': {e}"))?;
    }
    for word in &args.skip_word {
        safe_list::add_user_skipword(word);
    }
    Ok(())
}

/// Loads AWS account IDs to skip from CLI args and optional file.
fn load_skip_aws_accounts(args: &scan::ScanArgs) -> Result<Vec<String>> {
    let mut skip_aws_accounts = args.skip_aws_account.clone();

    if let Some(path) = args.skip_aws_account_file.as_ref() {
        let contents = fs::read_to_string(path).with_context(|| {
            format!("Failed to read --skip-aws-account-file {}", path.display())
        })?;

        for line in contents.lines() {
            let content = line.split('#').next().unwrap_or("");
            for value in content.split(|c: char| c.is_ascii_whitespace() || c == ',' || c == ';') {
                let trimmed = value.trim();
                if !trimmed.is_empty() {
                    skip_aws_accounts.push(trimmed.to_string());
                }
            }
        }
    }

    Ok(skip_aws_accounts)
}

/// Deduplicates matches in the datastore starting from `start_index`.
fn deduplicate_new_matches(
    store: &Arc<Mutex<FindingsStore>>,
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    start_index: usize,
) -> Result<()> {
    if args.no_dedup {
        return Ok(());
    }

    let reporter = crate::reporter::DetailsReporter {
        datastore: Arc::clone(store),
        styles: Styles::new(global_args.use_color(std::io::stdout())),
        validation_filter: args.effective_validation_filter(),
        audit_context: None,
    };

    let all_matches = reporter.get_unfiltered_matches(Some(scan::ValidationFilter::All))?;
    if start_index >= all_matches.len() {
        return Ok(());
    }

    let slice = if start_index == 0 { all_matches } else { all_matches[start_index..].to_vec() };
    let deduped_matches = reporter.deduplicate_matches(slice, args.no_dedup);

    let deduped_arcs: Vec<Arc<FindingsStoreMessage>> = deduped_matches
        .into_iter()
        .map(|rm| Arc::new((Arc::new(rm.origin), Arc::new(rm.blob_metadata), rm.m)))
        .collect();

    let mut ds = store.lock().unwrap();
    if start_index == 0 {
        ds.replace_matches(deduped_arcs);
    } else {
        let mut preserved = ds.get_matches()[..start_index].to_vec();
        preserved.extend(deduped_arcs);
        ds.replace_matches(preserved);
    }
    Ok(())
}

fn build_scan_audit_context(
    args: &scan::ScanArgs,
    rules_db: &RulesDatabase,
    matcher_stats: &Arc<Mutex<MatcherStats>>,
    datastore: &Arc<Mutex<FindingsStore>>,
    start_time: Instant,
    scan_started_at: chrono::DateTime<chrono::Local>,
    update_status: &crate::update::UpdateStatus,
) -> crate::reporter::ScanAuditContext {
    let totals = compute_scan_totals(datastore, args, matcher_stats.as_ref());
    crate::reporter::ScanAuditContext {
        scan_timestamp: Some(scan_started_at.to_rfc3339()),
        scan_duration_seconds: Some(start_time.elapsed().as_secs_f64()),
        rules_applied: Some(rules_db.num_rules()),
        successful_validations: Some(totals.successful_validations),
        failed_validations: Some(totals.failed_validations),
        skipped_validations: Some(totals.skipped_validations),
        blobs_scanned: Some(totals.blobs_scanned),
        bytes_scanned: Some(totals.bytes_scanned),
        running_version: Some(update_status.running_version.clone()),
        latest_version: update_status.latest_version.clone(),
        update_check_status: Some(update_status.check_status.as_str().to_string()),
    }
}

fn audit_snapshot_for_root(
    args: &scan::ScanArgs,
    root: &Path,
    event_targets: Option<&[github::GitHubEventScanTarget]>,
    fetched: bool,
) -> Option<crate::scan_audit::GitAuditSnapshot> {
    if !is_git_repository_root(root) {
        return None;
    }

    let snapshots = event_targets
        .filter(|targets| !targets.is_empty())
        .map(|targets| {
            targets
                .iter()
                .map(|target| {
                    let selector = format!("{:?}", target.selector);
                    let target_args = scan_args_for_github_event_target(args, target);
                    (selector, crate::scan_audit::git_snapshot(root, &target_args, fetched))
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![("default".to_string(), crate::scan_audit::git_snapshot(root, args, fetched))]
        });
    combine_git_snapshots(snapshots)
}

/// Applies baseline filtering if configured.
fn apply_baseline_if_configured(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    baseline: &crate::baseline::BaselineFile,
    roots: &[PathBuf],
) -> Result<()> {
    if args.baseline_file.is_some() || args.manage_baseline {
        let mut ds = datastore.lock().unwrap();
        crate::baseline::apply_loaded_baseline(&mut ds, baseline, roots)?;
    }
    Ok(())
}

fn update_baseline_if_configured(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    baseline_path: &std::path::Path,
    baseline: &crate::baseline::BaselineFile,
    roots: &[PathBuf],
) -> Result<()> {
    if !args.manage_baseline {
        return Ok(());
    }

    let updated = {
        let ds = datastore.lock().unwrap();
        crate::baseline::build_managed_baseline(&ds, baseline, roots)?
    };
    if updated != *baseline || !baseline_path.exists() {
        crate::baseline::save_baseline(baseline_path, &updated)?;
    }
    Ok(())
}

fn effective_max_validation_body_len(args: &scan::ScanArgs) -> usize {
    if args.full_validation_response { 0 } else { args.max_validation_response_length }
}

/// Runs the validation phase on matches in the datastore.
async fn run_validation_phase(
    datastore: &Arc<Mutex<FindingsStore>>,
    validation_deps: &Option<ValidationDeps>,
    args: &scan::ScanArgs,
    match_range: Option<std::ops::Range<usize>>,
    access_map_collector: Option<AccessMapCollector>,
) -> Result<()> {
    if let Some(validation) = validation_deps {
        let (parser, clients, cache, rate_limiter, provider_endpoints) =
            (&validation.0, &validation.1, &validation.2, &validation.3, &validation.4);
        run_secret_validation(
            Arc::clone(datastore),
            parser,
            clients,
            cache,
            args.num_jobs,
            match_range,
            access_map_collector,
            rate_limiter.clone(),
            provider_endpoints.clone(),
            Duration::from_secs(args.validation_timeout),
            args.validation_retries,
            effective_max_validation_body_len(args),
        )
        .await?;
    }
    Ok(())
}

// =================================================================================================
// Sequential scan path
// =================================================================================================

#[expect(clippy::too_many_arguments)]
async fn run_sequential_scan(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    rules_db: &RulesDatabase,
    input_roots: &mut Vec<PathBuf>,
    repo_roots: &[PathBuf],
    discovered_repos: Arc<Vec<PathBuf>>,
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
    mut artifact_handle: ArtifactFetchHandle,
    github_event_targets_by_root: Arc<HashMap<PathBuf, Vec<github::GitHubEventScanTarget>>>,
    shared_profiler: &Arc<ConcurrentRuleProfiler>,
    enable_profiling: bool,
    matcher_stats: &Arc<Mutex<MatcherStats>>,
    baseline_path: &Arc<PathBuf>,
    baseline: &Arc<crate::baseline::BaselineFile>,
    validation_deps: &Option<ValidationDeps>,
    access_map_collector: &mut Option<AccessMapCollector>,
    progress_enabled: bool,
    start_time: Instant,
    scan_started_at: chrono::DateTime<chrono::Local>,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
    scan_audit: SharedScanAudit,
) -> Result<()> {
    let mut streamed_roots = Vec::new();
    // Run the scan loop in a closure so that, even if a per-repo
    // `enumerate_filesystem_inputs` returns Err and short-circuits via `?`,
    // we still drop `repo_rx` and join the cloning + artifact-fetching
    // threads before returning. Without this, the producer threads would
    // continue cloning into the artifact directory after the scan has already failed.
    let scan_result: Result<()> = (|| {
        for root in repo_roots {
            // Only Git repositories have a git boundary to snapshot; ordinary
            // directories and files skip the subprocess work entirely.
            let snapshot = is_git_repository_root(root)
                .then(|| crate::scan_audit::git_snapshot(root, args, false));
            let audit_key = scan_audit.lock().unwrap().scan_started_with_snapshot(root, snapshot);
            let repo_datastore =
                Arc::new(Mutex::new(FindingsStore::new(datastore.lock().unwrap().clone_root())));
            let repo_rules = datastore.lock().unwrap().get_rules()?;
            let repo_link = datastore.lock().unwrap().repo_links().get(root).cloned();
            {
                let mut ds = repo_datastore.lock().unwrap();
                ds.record_rules(&repo_rules);
                if let Some(repo_link) = repo_link {
                    ds.register_repo_link(root.clone(), repo_link);
                }
            }
            let repo_matcher_stats = Mutex::new(MatcherStats::default());
            match enumerate_filesystem_inputs(
                args,
                Arc::clone(&repo_datastore),
                std::slice::from_ref(root),
                &discovered_repos,
                progress_enabled,
                rules_db,
                enable_profiling,
                Arc::clone(shared_profiler),
                &repo_matcher_stats,
            ) {
                Ok(partial) => {
                    deduplicate_new_matches(&repo_datastore, global_args, args, 0)?;
                    apply_baseline_if_configured(
                        args,
                        &repo_datastore,
                        baseline.as_ref(),
                        std::slice::from_ref(root),
                    )?;
                    let local_stats = repo_matcher_stats.lock().unwrap().clone();
                    let findings = repo_datastore.lock().unwrap().get_matches().len();
                    matcher_stats.lock().unwrap().update(&local_stats);
                    datastore
                        .lock()
                        .unwrap()
                        .merge_from(&repo_datastore.lock().unwrap(), !args.no_dedup);
                    datastore.lock().unwrap().spill_pending()?;
                    if let Some(key) = audit_key {
                        let stats = RepositoryScanStats {
                            findings,
                            blobs_scanned: local_stats.blobs_scanned,
                            bytes_scanned: local_stats.bytes_scanned,
                        };
                        if partial {
                            scan_audit.lock().unwrap().scan_partial(
                                &key,
                                stats,
                                "one or more repository inputs could not be enumerated",
                            );
                        } else {
                            scan_audit.lock().unwrap().scan_completed(&key, stats);
                        }
                    }
                }
                Err(error) => {
                    if let Some(key) = audit_key {
                        scan_audit.lock().unwrap().scan_failed(&key, &format!("{error:#}"));
                    }
                    return Err(error);
                }
            }
        }

        for repo_root in repo_rx.iter() {
            let event_targets = github_event_targets_by_root.get(&repo_root);
            let snapshot =
                audit_snapshot_for_root(args, &repo_root, event_targets.map(Vec::as_slice), true);
            let audit_key =
                scan_audit.lock().unwrap().scan_started_with_snapshot(&repo_root, snapshot);
            let repo_datastore =
                Arc::new(Mutex::new(FindingsStore::new(datastore.lock().unwrap().clone_root())));
            let repo_rules = datastore.lock().unwrap().get_rules()?;
            let repo_link = datastore.lock().unwrap().repo_links().get(&repo_root).cloned();
            {
                let mut ds = repo_datastore.lock().unwrap();
                ds.record_rules(&repo_rules);
                if let Some(repo_link) = repo_link {
                    ds.register_repo_link(repo_root.clone(), repo_link);
                }
            }
            let repo_matcher_stats = Mutex::new(MatcherStats::default());
            let result: Result<()> = (|| {
                let mut partial = false;
                if let Some(targets) = github_event_targets_by_root.get(&repo_root) {
                    for target in targets {
                        let target_args = scan_args_for_github_event_target(args, target);
                        partial |= enumerate_filesystem_inputs(
                            &target_args,
                            Arc::clone(&repo_datastore),
                            std::slice::from_ref(&repo_root),
                            &discovered_repos,
                            progress_enabled,
                            rules_db,
                            enable_profiling,
                            Arc::clone(shared_profiler),
                            &repo_matcher_stats,
                        )?;
                    }
                } else {
                    partial = enumerate_filesystem_inputs(
                        args,
                        Arc::clone(&repo_datastore),
                        std::slice::from_ref(&repo_root),
                        &discovered_repos,
                        progress_enabled,
                        rules_db,
                        enable_profiling,
                        Arc::clone(shared_profiler),
                        &repo_matcher_stats,
                    )?;
                }
                deduplicate_new_matches(&repo_datastore, global_args, args, 0)?;
                apply_baseline_if_configured(
                    args,
                    &repo_datastore,
                    baseline.as_ref(),
                    std::slice::from_ref(&repo_root),
                )?;
                let local_stats = repo_matcher_stats.lock().unwrap().clone();
                let findings = repo_datastore.lock().unwrap().get_matches().len();
                matcher_stats.lock().unwrap().update(&local_stats);
                datastore
                    .lock()
                    .unwrap()
                    .merge_from(&repo_datastore.lock().unwrap(), !args.no_dedup);
                datastore.lock().unwrap().spill_pending()?;
                if let Some(key) = &audit_key {
                    let stats = RepositoryScanStats {
                        findings,
                        blobs_scanned: local_stats.blobs_scanned,
                        bytes_scanned: local_stats.bytes_scanned,
                    };
                    if partial {
                        scan_audit.lock().unwrap().scan_partial(
                            key,
                            stats,
                            "one or more repository inputs could not be enumerated",
                        );
                    } else {
                        scan_audit.lock().unwrap().scan_completed(key, stats);
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                if let Some(key) = &audit_key {
                    scan_audit.lock().unwrap().scan_failed(key, &format!("{error:#}"));
                }
                return Err(error);
            }
            if auto_cleanup_clones && let Err(e) = fs::remove_dir_all(&repo_root) {
                debug!("Failed to remove scanned clone {}: {e}", repo_root.display());
            }
            streamed_roots.push(repo_root);
        }
        Ok(())
    })();
    input_roots.extend(streamed_roots);

    // Drop the receiver before joining producers. If `scan_result` is Err,
    // the loop exited early and producers could be blocked on `send` against
    // a full bounded channel; dropping `repo_rx` makes those sends return Err
    // so the threads can exit and `join()` doesn't deadlock.
    drop(repo_rx);

    artifact_handle.cancel();
    if let Some(handle) = repo_clone_handle {
        let _ = handle.join();
    }
    let artifact_result = match artifact_handle.join() {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("artifact fetch thread panicked")),
    };

    // Surface the scan error first; if scanning succeeded, surface any
    // artifact-fetching error.
    scan_result?;
    artifact_result.map_err(|e| e.context("repository discovery or artifact fetching failed"))?;

    datastore
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock datastore while restoring spilled findings"))?
        .restore_spilled()?;
    deduplicate_new_matches(datastore, global_args, args, 0)?;
    apply_baseline_if_configured(args, datastore, baseline.as_ref(), input_roots)?;
    update_baseline_if_configured(
        args,
        datastore,
        baseline_path.as_ref(),
        baseline.as_ref(),
        input_roots,
    )?;

    run_validation_phase(datastore, validation_deps, args, None, access_map_collector.clone())
        .await?;

    if let Some(collector) = access_map_collector.take() {
        finalize_access_map(datastore, collector, args).await?;
    }

    let repository_audit = scan_audit.lock().unwrap().finish()?;
    // Every target needs terminal coverage, including non-Git and empty sources.
    datastore.lock().unwrap().set_scan_audit(repository_audit.clone());

    let audit_context = build_scan_audit_context(
        args,
        rules_db,
        matcher_stats,
        datastore,
        start_time,
        scan_started_at,
        update_status,
    );
    crate::scan_progress::phase("Writing report", 0, crate::scan_progress::PhaseKind::Other);
    crate::reporter::run(global_args, Arc::clone(datastore), args, Some(audit_context))
        .context("Failed to run report command")?;
    print_scan_summary(
        start_time,
        scan_started_at,
        datastore,
        global_args,
        args,
        rules_db,
        matcher_stats.as_ref(),
        if enable_profiling { Some(shared_profiler.as_ref()) } else { None },
        update_status,
        None,
        None,
    );
    maybe_hint_access_map(datastore, args);
    Ok(())
}

// =================================================================================================
// Parallel scan path
// =================================================================================================

#[expect(clippy::too_many_arguments)]
async fn run_parallel_scan(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    rules_db: &RulesDatabase,
    repo_roots: &[PathBuf],
    discovered_repos: Arc<Vec<PathBuf>>,
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
    mut artifact_handle: ArtifactFetchHandle,
    github_event_targets_by_root: Arc<HashMap<PathBuf, Vec<github::GitHubEventScanTarget>>>,
    shared_profiler: &Arc<ConcurrentRuleProfiler>,
    enable_profiling: bool,
    matcher_stats: &Arc<Mutex<MatcherStats>>,
    baseline_path: &Arc<PathBuf>,
    baseline: &Arc<crate::baseline::BaselineFile>,
    validation_deps: &Option<ValidationDeps>,
    access_map_collector: &mut Option<AccessMapCollector>,
    progress_enabled: bool,
    start_time: Instant,
    scan_started_at: chrono::DateTime<chrono::Local>,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
    scan_audit: SharedScanAudit,
) -> Result<()> {
    deduplicate_new_matches(datastore, global_args, args, 0)?;
    apply_baseline_if_configured(args, datastore, baseline.as_ref(), repo_roots)?;

    // Validate initial (non-repo) matches
    if let Some(validation) = validation_deps {
        let (parser, clients, cache, rate_limiter, provider_endpoints) =
            (&validation.0, &validation.1, &validation.2, &validation.3, &validation.4);
        let initial_match_count = { datastore.lock().unwrap().get_matches().len() };
        if initial_match_count > 0 {
            run_secret_validation(
                Arc::clone(datastore),
                parser,
                clients,
                cache,
                args.num_jobs,
                Some(0..initial_match_count),
                access_map_collector.clone(),
                rate_limiter.clone(),
                provider_endpoints.clone(),
                Duration::from_secs(args.validation_timeout),
                args.validation_retries,
                effective_max_validation_body_len(args),
            )
            .await?;
        }
    }

    // Parallel per-repo scanning
    let repo_concurrency = std::cmp::max(1, args.num_jobs);
    let rt_handle = Handle::current();

    let base_clone_root = { datastore.lock().unwrap().clone_root() };
    let repo_rules = datastore.lock().unwrap().get_rules()?;

    let ran_repo_scan = Arc::new(AtomicBool::new(false));
    let repo_errors: Arc<Mutex<Vec<anyhow::Error>>> = Arc::new(Mutex::new(Vec::new()));
    let successful_roots: Arc<Mutex<Vec<PathBuf>>> = Arc::new(Mutex::new(Vec::new()));
    let output_to_file = args.output_args.output.is_some();

    // Bound concurrent in-flight repo scans. The bounded `repo_rx` only caps
    // repos sitting on the channel; without an in-flight permit here the loop
    // below would drain `repo_rx` as fast as cloners produce and queue every
    // streamed repo into rayon's unbounded work queue. The permit forces the
    // receiver to block once rayon is saturated, which restores backpressure
    // through `repo_rx` to the cloner's bounded internal `ready_tx` channel.
    // Sized at 2× the rayon worker count so workers always have a few ready
    // repos staged and pick up the next as soon as one finishes.
    let scan_inflight_cap = std::cmp::max(repo_concurrency * 2, repo_concurrency + 4);
    let (permit_return, permit_take) = crossbeam_channel::bounded::<()>(scan_inflight_cap);
    for _ in 0..scan_inflight_cap {
        permit_return.try_send(()).expect("permit channel sized for cap");
    }

    let active_scans = Arc::new(AtomicUsize::new(0));

    // Optional saturation tracker — gated on `-v` (DEBUG level). One thread,
    // not per-task. Logs every ~15s while the scan is active so a future hang
    // is diagnosable from logs alone without needing to attach gdb to the
    // running process.
    let tracker_stop = Arc::new(AtomicBool::new(false));
    let tracker_handle = if global_args.verbose >= 1 {
        let stop = Arc::clone(&tracker_stop);
        let active = Arc::clone(&active_scans);
        let rx = repo_rx.clone();
        let permits = permit_return.clone();
        let cap = scan_inflight_cap;
        std::thread::Builder::new()
            .name("kf-scan-tracker".to_string())
            .spawn(move || {
                // Sleep in 500ms slices so shutdown after the rayon scope ends
                // is prompt — at most ~500ms wait for join, not a full tick.
                loop {
                    for _ in 0..30 {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                    debug!(
                        "scan-saturation: active_repo_scans={} repo_channel_depth={} permits_available={} inflight_cap={}",
                        active.load(Ordering::Relaxed),
                        rx.len(),
                        permits.len(),
                        cap,
                    );
                }
            })
            .ok()
    } else {
        None
    };

    // RAII: guarantee the tracker thread is stopped and joined on *every* exit
    // path, including an early `?` return from the pool build below. Without
    // this, a build failure would leak the thread (it holds clones of
    // `repo_rx`, the permit pool, and `active_scans`). On the normal path we
    // still call `shutdown()` explicitly to control ordering vs. the summary.
    struct TrackerGuard {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl TrackerGuard {
        fn shutdown(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }
    impl Drop for TrackerGuard {
        fn drop(&mut self) {
            self.shutdown();
        }
    }
    let mut tracker = TrackerGuard { stop: tracker_stop, handle: tracker_handle };

    rayon::ThreadPoolBuilder::new()
        .num_threads(repo_concurrency)
        .build()
        .context("Failed to build repo scan thread pool")?
        // Keep the channel-reading coordinator off the scan workers. Discovery
        // can wait for scan backpressure, including with --jobs 1.
        .in_place_scope(|scope| {
            // Distinguishes user-supplied `repo_roots` (must be preserved)
            // from clones / artifact dirs that arrive via `repo_rx` and
            // are eligible for post-scan cleanup.
            #[derive(Clone, Copy)]
            enum ScanRootSource {
                UserPath,
                Streamed,
            }
            let spawn_repo_scan =
                |root: PathBuf,
                 source: ScanRootSource,
                 event_targets: Option<Vec<github::GitHubEventScanTarget>>| {
                    // Acquire one permit from the pool before queueing into rayon.
                    // This is the load-bearing call for backpressure: when rayon
                    // is saturated and no scan has finished to release a permit,
                    // this `recv` blocks the for-loop driving `repo_rx.iter()`,
                    // which causes the bounded `repo_rx` to fill, which causes
                    // the cloner's bounded `ready_tx` send to block, which slows
                    // the cloner pool. Without it, 5,000 closures pile into
                    // rayon's unbounded work queue and the only thing limiting
                    // memory is process death.
                    permit_take.recv().expect("permit pool closed unexpectedly");

                    let repo_rules = repo_rules.clone();
                    let discovered_repos = Arc::clone(&discovered_repos);
                    let base_clone_root = base_clone_root.clone();
                    let baseline = Arc::clone(baseline);
                    let shared_profiler = Arc::clone(shared_profiler);
                    let args = args.clone();
                    let root = root.clone();
                    let event_targets = event_targets.clone();
                    let validation_deps = validation_deps.clone();
                    let matcher_stats = Arc::clone(matcher_stats);
                    let rt_handle = rt_handle.clone();
                    let ran_repo_scan = Arc::clone(&ran_repo_scan);
                    let repo_errors = Arc::clone(&repo_errors);
                    let successful_roots = Arc::clone(&successful_roots);
                    let datastore = Arc::clone(datastore);
                    let scan_audit = Arc::clone(&scan_audit);
                    let access_map = access_map_collector.clone();
                    let permit_release = permit_return.clone();
                    let scan_counter = Arc::clone(&active_scans);

                    scan_counter.fetch_add(1, Ordering::Relaxed);

                    scope.spawn(move |_| {
                        // Release the permit and decrement the active-scan
                        // counter when this closure exits — including via early
                        // return, error, or unwinding panic in debug builds.
                        // (`panic = "abort"` in release means the process dies
                        // before Drop runs, but that's fine: the permit pool
                        // dies with it.)
                        struct ScanGuard {
                            permit_release: crossbeam_channel::Sender<()>,
                            scan_counter: Arc<AtomicUsize>,
                        }
                        impl Drop for ScanGuard {
                            fn drop(&mut self) {
                                self.scan_counter.fetch_sub(1, Ordering::Relaxed);
                                // Bounded to the same cap we pre-filled, and we
                                // only send one permit per `recv`, so this can
                                // never fail with `Full`. Use `try_send` so a
                                // logic bug surfaces immediately rather than
                                // blocking a worker thread on cleanup. A failure
                                // here means the permit accounting is broken, so
                                // assert in debug/test builds; in release we log
                                // instead of panicking, since unwinding out of a
                                // `Drop` (this guard drops during panic unwind)
                                // would abort the process.
                                if let Err(err) = self.permit_release.try_send(()) {
                                    debug_assert!(
                                        false,
                                        "permit pool overflowed or disconnected on cleanup: {err}"
                                    );
                                    tracing::error!(
                                        "permit pool overflowed or disconnected on cleanup: {err}"
                                    );
                                }
                            }
                        }
                        let _guard = ScanGuard { permit_release, scan_counter };

                        // Gather the git snapshot before taking the audit
                        // mutex: it runs blocking Git subprocesses, and
                        // holding the lock here would serialize the startup
                        // of every parallel scan worker behind them.
                        let snapshot = audit_snapshot_for_root(
                            &args,
                            &root,
                            event_targets.as_deref(),
                            matches!(source, ScanRootSource::Streamed),
                        );
                        let audit_key =
                            scan_audit.lock().unwrap().scan_started_with_snapshot(&root, snapshot);

                        let result: Result<()> = (|| {
                            let repo_datastore =
                                Arc::new(Mutex::new(FindingsStore::new(base_clone_root.clone())));
                            {
                                let repo_link =
                                    datastore.lock().unwrap().repo_links().get(&root).cloned();
                                let mut ds = repo_datastore.lock().unwrap();
                                ds.record_rules(&repo_rules);
                                if let Some(repo_link) = repo_link {
                                    ds.register_repo_link(root.clone(), repo_link);
                                }
                            }

                            let repo_matcher_stats = Mutex::new(MatcherStats::default());

                            let mut partial = false;
                            if let Some(event_targets) = &event_targets {
                                for target in event_targets {
                                    let target_args =
                                        scan_args_for_github_event_target(&args, target);
                                    partial |= enumerate_filesystem_inputs(
                                        &target_args,
                                        Arc::clone(&repo_datastore),
                                        std::slice::from_ref(&root),
                                        &discovered_repos,
                                        progress_enabled,
                                        rules_db,
                                        enable_profiling,
                                        Arc::clone(&shared_profiler),
                                        &repo_matcher_stats,
                                    )?;
                                }
                            } else {
                                partial = enumerate_filesystem_inputs(
                                    &args,
                                    Arc::clone(&repo_datastore),
                                    std::slice::from_ref(&root),
                                    &discovered_repos,
                                    progress_enabled,
                                    rules_db,
                                    enable_profiling,
                                    Arc::clone(&shared_profiler),
                                    &repo_matcher_stats,
                                )?;
                            }
                            deduplicate_new_matches(&repo_datastore, global_args, &args, 0)?;

                            if args.baseline_file.is_some() || args.manage_baseline {
                                let mut ds = repo_datastore.lock().unwrap();
                                crate::baseline::apply_loaded_baseline(
                                    &mut ds,
                                    baseline.as_ref(),
                                    std::slice::from_ref(&root),
                                )?;
                            }

                            if let Some(validation) = validation_deps.clone() {
                                let (parser, clients, cache, rate_limiter, provider_endpoints) = (
                                    &validation.0,
                                    &validation.1,
                                    &validation.2,
                                    &validation.3,
                                    &validation.4,
                                );
                                let match_count =
                                    { repo_datastore.lock().unwrap().get_matches().len() };
                                if match_count > 0 {
                                    rt_handle.block_on(run_secret_validation(
                                        Arc::clone(&repo_datastore),
                                        parser,
                                        clients,
                                        cache,
                                        args.num_jobs,
                                        Some(0..match_count),
                                        access_map.clone(),
                                        rate_limiter.clone(),
                                        provider_endpoints.clone(),
                                        Duration::from_secs(args.validation_timeout),
                                        args.validation_retries,
                                        effective_max_validation_body_len(&args),
                                    ))?;
                                }
                            }

                            {
                                let mut global_stats = matcher_stats.lock().unwrap();
                                global_stats.update(&repo_matcher_stats.lock().unwrap());
                            }

                            if let Some(key) = &audit_key {
                                let findings = repo_datastore.lock().unwrap().get_matches().len();
                                let local_stats = repo_matcher_stats.lock().unwrap().clone();
                                let mut audit = scan_audit.lock().unwrap();
                                let stats = RepositoryScanStats {
                                    findings,
                                    blobs_scanned: local_stats.blobs_scanned,
                                    bytes_scanned: local_stats.bytes_scanned,
                                };
                                if partial {
                                    audit.scan_partial(
                                        key,
                                        stats,
                                        "one or more repository inputs could not be enumerated",
                                    );
                                } else {
                                    audit.scan_completed(key, stats);
                                }
                                let manifest = audit.snapshot().for_repository(key);
                                repo_datastore.lock().unwrap().set_scan_audit(manifest);
                            }

                            if !output_to_file {
                                // Per-repo emit goes to stdout from many rayon
                                // threads in parallel. Render the report into
                                // an in-memory buffer first (CPU work, no
                                // contention), then take the stdout lock only
                                // around the final atomic write+flush so two
                                // threads' envelopes can't interleave and
                                // corrupt JSONL output.
                                let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
                                crate::reporter::run_with_writer(
                                    global_args,
                                    Arc::clone(&repo_datastore),
                                    &args,
                                    None,
                                    &mut buf,
                                )
                                .context("Failed to run report command")?;
                                if !buf.is_empty() {
                                    use std::io::Write;
                                    let mut stdout = std::io::stdout().lock();
                                    // Treat a closed downstream pipe (e.g.
                                    // `kingfisher scan ... | head`) as a normal
                                    // early exit, matching `summary.rs::safe_println!`.
                                    // Any other I/O error is a real failure.
                                    if let Err(err) = stdout.write_all(&buf) {
                                        if err.kind() == std::io::ErrorKind::BrokenPipe {
                                            std::process::exit(0);
                                        }
                                        return Err(err.into());
                                    }
                                    if let Err(err) = stdout.flush() {
                                        if err.kind() == std::io::ErrorKind::BrokenPipe {
                                            std::process::exit(0);
                                        }
                                        return Err(err.into());
                                    }
                                }
                            }

                            {
                                let mut ds = datastore.lock().unwrap();
                                ds.merge_from(&repo_datastore.lock().unwrap(), !args.no_dedup);
                                ds.spill_pending()?;
                            }

                            successful_roots.lock().unwrap().push(root.clone());
                            ran_repo_scan.store(true, Ordering::Relaxed);
                            Ok(())
                        })();

                        if let Err(e) = result {
                            if let Some(key) = &audit_key {
                                scan_audit.lock().unwrap().scan_failed(key, &format!("{e:#}"));
                            }
                            error!("Repository scan failed: {e}");
                            repo_errors.lock().unwrap().push(e);
                        }

                        if matches!(source, ScanRootSource::Streamed)
                            && auto_cleanup_clones
                            && let Err(e) = fs::remove_dir_all(&root)
                        {
                            debug!("Failed to remove scanned clone {}: {e}", root.display());
                        }
                    });
                };

            for root in repo_roots.iter().cloned() {
                spawn_repo_scan(root, ScanRootSource::UserPath, None);
            }

            for root in repo_rx.iter() {
                let event_targets = github_event_targets_by_root.get(&root).cloned();
                spawn_repo_scan(root, ScanRootSource::Streamed, event_targets);
            }
        });

    // Stop the saturation tracker before joining downstream handles so its
    // periodic output doesn't interleave with the scan-completion summary.
    tracker.shutdown();

    artifact_handle.cancel();
    if let Some(handle) = repo_clone_handle {
        let _ = handle.join();
    }
    // Surface artifact-fetching errors after all per-repo scans have finished.
    match artifact_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.context("repository discovery or artifact fetching failed")),
        Err(_) => return Err(anyhow::anyhow!("artifact fetch thread panicked")),
    }

    if let Some(err) = repo_errors.lock().unwrap().pop() {
        return Err(err);
    }

    datastore
        .lock()
        .map_err(|_| anyhow::anyhow!("Failed to lock datastore while restoring spilled findings"))?
        .restore_spilled()?;
    if ran_repo_scan.load(Ordering::Relaxed) {
        let scanned_roots = successful_roots.lock().unwrap().clone();
        update_baseline_if_configured(
            args,
            datastore,
            baseline_path.as_ref(),
            baseline.as_ref(),
            &scanned_roots,
        )?;
    }

    if let Some(collector) = access_map_collector.take() {
        finalize_access_map(datastore, collector, args).await?;
    }

    let repository_audit = scan_audit.lock().unwrap().finish()?;
    // Every target needs terminal coverage, including non-Git and empty sources.
    datastore.lock().unwrap().set_scan_audit(repository_audit.clone());

    if output_to_file && ran_repo_scan.load(Ordering::Relaxed) {
        let audit_context = build_scan_audit_context(
            args,
            rules_db,
            matcher_stats,
            datastore,
            start_time,
            scan_started_at,
            update_status,
        );
        crate::scan_progress::phase("Writing report", 0, crate::scan_progress::PhaseKind::Other);
        crate::reporter::run(global_args, Arc::clone(datastore), args, Some(audit_context))
            .context("Failed to run report command")?;
    } else if ran_repo_scan.load(Ordering::Relaxed) {
        let audit_only =
            Arc::new(Mutex::new(FindingsStore::new(datastore.lock().unwrap().clone_root())));
        audit_only.lock().unwrap().set_scan_audit(repository_audit);
        let mut buf = Vec::with_capacity(8 * 1024);
        crate::reporter::run_with_writer(global_args, audit_only, args, None, &mut buf)
            .context("Failed to render final repository audit")?;
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        if let Err(error) = stdout.write_all(&buf) {
            if error.kind() == std::io::ErrorKind::BrokenPipe {
                std::process::exit(0);
            }
            return Err(error.into());
        }
        stdout.flush()?;
    }

    if !ran_repo_scan.load(Ordering::Relaxed) {
        deduplicate_new_matches(datastore, global_args, args, 0)?;
        apply_baseline_if_configured(args, datastore, baseline.as_ref(), repo_roots)?;
        update_baseline_if_configured(
            args,
            datastore,
            baseline_path.as_ref(),
            baseline.as_ref(),
            repo_roots,
        )?;

        run_validation_phase(datastore, validation_deps, args, None, access_map_collector.clone())
            .await?;

        if let Some(collector) = access_map_collector.take() {
            finalize_access_map(datastore, collector, args).await?;
        }

        let audit_context = build_scan_audit_context(
            args,
            rules_db,
            matcher_stats,
            datastore,
            start_time,
            scan_started_at,
            update_status,
        );
        crate::scan_progress::phase("Writing report", 0, crate::scan_progress::PhaseKind::Other);
        crate::reporter::run(global_args, Arc::clone(datastore), args, Some(audit_context))
            .context("Failed to run report command")?;
    }

    let aggregate_summary = if ran_repo_scan.load(Ordering::Relaxed) {
        let totals = compute_scan_totals(datastore, args, matcher_stats.as_ref());
        let mut sorted: Vec<_> = datastore
            .lock()
            .unwrap()
            .get_summary(args.include_hidden_findings)
            .into_iter()
            .collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
        Some((totals, sorted))
    } else {
        None
    };

    print_scan_summary(
        start_time,
        scan_started_at,
        datastore,
        global_args,
        args,
        rules_db,
        matcher_stats.as_ref(),
        if enable_profiling { Some(shared_profiler.as_ref()) } else { None },
        update_status,
        None,
        aggregate_summary,
    );

    if access_map_collector.is_none() {
        maybe_hint_access_map(datastore, args);
    }
    Ok(())
}

// =================================================================================================
// Access-map finalization and scan setup helpers
// =================================================================================================

async fn finalize_access_map(
    datastore: &Arc<Mutex<FindingsStore>>,
    collector: AccessMapCollector,
    _args: &scan::ScanArgs,
) -> Result<()> {
    let requests = collector.into_collected_requests();

    if requests.is_empty() {
        debug!(
            "access-map enabled but no validated AWS, GCP, or Azure credentials were collected; skipping report output"
        );
        let mut ds = datastore.lock().unwrap();
        ds.set_access_map_results(Vec::new());
        return Ok(());
    }

    crate::scan_progress::phase(
        "Mapping credential access",
        0,
        crate::scan_progress::PhaseKind::Other,
    );
    let results = access_map::map_collected_requests(requests).await;

    {
        let mut ds = datastore.lock().unwrap();
        ds.set_access_map_results(results.clone());
    }

    Ok(())
}

fn maybe_hint_access_map(datastore: &Arc<Mutex<FindingsStore>>, args: &scan::ScanArgs) {
    if args.access_map || args.no_validate {
        return;
    }

    let has_mappable_identities = {
        let ds = datastore.lock().unwrap();
        ds.get_matches().iter().any(|entry| {
            let rule = &entry.2.rule;
            rule.syntax().is_authoritative()
                && entry.2.validation_outcome.is_verified_active()
                && (matches!(rule.syntax().validation, Some(Validation::AWS | Validation::GCP))
                    || matches!(
                        &rule.syntax().validation,
                        Some(Validation::Betterleaks(validation))
                            if validation.capabilities.access_map.is_some()
                    ))
        })
    };

    if has_mappable_identities {
        info!(
            "Blast radius mapping not requested. Rerun with --blast-radius to include resource-level permissions, if authorized."
        );
    }
}

fn initialize_environment(use_progress: bool, num_jobs: usize) -> Result<()> {
    let init_progress =
        if use_progress { ProgressBar::new_spinner() } else { ProgressBar::hidden() };
    init_progress.set_message("Initializing thread pool...");
    let num_threads = num_jobs.max(1);
    // Attempt to initialize the global thread pool only if it hasn't been
    // initialized yet.
    let result = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|idx| format!("rayon-{idx}"))
        .build_global();
    match result {
        Ok(_) => {
            init_progress.set_message("Thread pool initialized successfully.");
        }
        Err(e) if e.to_string().contains("The global thread pool has already been initialized") => {
            // Log a warning or simply indicate that initialization was skipped.
            init_progress.set_message("Thread pool was already initialized. Continuing...");
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to initialize Rayon: {}", e));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[tokio::test]
    async fn validation_cache_lifetimes_serialize_overlapping_scans() {
        let first = super::ValidationCacheLifetime::begin().await;
        let second = super::ValidationCacheLifetime::begin();
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut second).await.is_err()
        );
        drop(first);
        let _second = tokio::time::timeout(std::time::Duration::from_secs(1), second)
            .await
            .expect("next scan should acquire the cache after the previous scan ends");
    }

    #[test]
    fn recent_history_window_falls_back_for_direct_callers_and_preserves_fixed_windows() {
        let command = crate::cli::CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            ".",
            "--since-hours",
            "2",
        ])
        .unwrap();
        let crate::cli::global::Command::Scan(command) = command.command else { panic!() };
        let crate::cli::commands::scan::ScanOperation::Scan(mut args) =
            command.into_operation().unwrap()
        else {
            panic!()
        };
        let input = &mut args.input_specifier_args;
        let before = chrono::Utc::now().timestamp();
        let (start, end) = input.resolved_history_time_range().unwrap();
        assert_eq!(end - start, 7200);
        assert!(end >= before && end <= chrono::Utc::now().timestamp());
        input.history_time_range = Some((100, 7300));
        assert_eq!(input.resolved_history_time_range(), Some((100, 7300)));
    }

    #[test]
    fn local_repository_audit_snapshot_does_not_claim_clone_mode() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        let command_line = crate::cli::CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            root.to_str().unwrap(),
        ])
        .unwrap();
        let args = match command_line.command {
            crate::cli::global::Command::Scan(command) => match command.into_operation().unwrap() {
                crate::cli::commands::scan::ScanOperation::Scan(args) => args,
                crate::cli::commands::scan::ScanOperation::ListRepositories(_) => {
                    panic!("expected scan operation")
                }
            },
            _ => panic!("expected scan command"),
        };

        let snapshot = super::audit_snapshot_for_root(&args, &root, None, false).unwrap();
        assert!(snapshot.clone_mode.is_none());
    }
}
