use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use crossbeam_channel;
use crossbeam_skiplist::SkipMap;
use indicatif::ProgressBar;
use tokio::runtime::Handle;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, error_span, info, trace};

use crate::{
    access_map, azure, bitbucket,
    cli::{commands::scan, global},
    findings_store,
    findings_store::{FindingsStore, FindingsStoreMessage},
    gitea, github, gitlab,
    liquid_filters::register_all,
    matcher::MatcherStats,
    provider_endpoints::ProviderEndpointOverrides,
    reporter::styles::Styles,
    rule_loader::RuleLoader,
    rule_profiling::ConcurrentRuleProfiler,
    rules::rule::Validation,
    rules_database::RulesDatabase,
    safe_list,
    scanner::{
        AccessMapCollector, clone_or_update_git_repos_streaming, enumerate_azure_repos,
        enumerate_bitbucket_repos, enumerate_filesystem_inputs, enumerate_github_repos,
        enumerate_huggingface_repos,
        repos::{
            enumerate_gitea_repos, enumerate_gitlab_repos, fetch_confluence_pages,
            fetch_gcs_objects, fetch_git_host_artifacts, fetch_jira_issues,
            fetch_postman_resources, fetch_s3_objects, fetch_slack_messages, fetch_teams_messages,
        },
        run_secret_validation, save_docker_archives, save_docker_images,
        summary::{compute_scan_totals, print_scan_summary},
    },
    util::{set_redaction_enabled, tokio_blocking_threads_limit},
    validation::CachedResponse,
    validation_rate_limit::ValidationRateLimiter,
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

pub async fn run_async_scan(
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    // ── Phase 1: Input validation and environment setup ──────────────────
    validate_inputs(args)?;
    register_safe_list_patterns(args)?;

    let start_time = Instant::now();
    let scan_started_at = chrono::Local::now();

    trace!("Args:\n{global_args:#?}\n{args:#?}");
    let progress_enabled = global_args.use_progress();
    initialize_environment(progress_enabled)?;

    set_redaction_enabled(args.redact);

    // ── Phase 2: Repository enumeration ─────────────────────────────────
    let repo_urls = enumerate_all_repos(args, global_args).await?;

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
    let repo_clone_handle = start_repo_cloning(
        &repo_urls,
        args,
        global_args,
        &datastore,
        repo_tx.clone(),
        progress_enabled,
    );
    let artifact_handle = start_artifact_fetching(
        args,
        global_args,
        &repo_urls,
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

    let has_remote_objects = args.input_specifier_args.s3_bucket.is_some()
        || args.input_specifier_args.gcs_bucket.is_some();
    // The artifact task pushes into `repo_rx` asynchronously, so we can't
    // observe its work via `input_roots`. Defer to the type to know which
    // flags schedule artifact fetching so this stays in sync as new sources
    // are added.
    if input_roots.is_empty()
        && repo_urls.is_empty()
        && !has_remote_objects
        && !args.input_specifier_args.has_artifact_sources()
    {
        bail!("No inputs to scan");
    }

    let baseline_path = Arc::new(
        args.baseline_file
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("baseline-file.yaml")),
    );

    let skip_aws_accounts = load_skip_aws_accounts(args)?;
    crate::validation::set_skip_aws_account_ids(skip_aws_accounts);

    let mut access_map_collector =
        if args.access_map { Some(AccessMapCollector::default()) } else { None };

    let repo_roots = expand_repo_roots(&input_roots)?;
    let git_repo_count =
        repo_roots.iter().filter(|p| p.join(".git").is_dir()).count() + repo_urls.len();
    let use_parallel_repo_scan = git_repo_count > 10;

    let validation_rate_limiter =
        ValidationRateLimiter::from_cli(args.validation_rps, &args.validation_rps_rule)?
            .map(Arc::new);
    let provider_endpoints = Arc::new(ProviderEndpointOverrides::from_global_args(global_args)?);

    let validation_deps: Option<ValidationDeps> = if !args.no_validate {
        info!("Starting secret validation phase...");
        Some(Arc::new((
            register_all(liquid::ParserBuilder::with_stdlib()).build()?,
            crate::validation::ValidationClients::new(
                global_args.tls_mode,
                global_args.allow_internal_ips,
            )?,
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
            repo_rx,
            repo_clone_handle,
            artifact_handle,
            &shared_profiler,
            enable_profiling,
            &matcher_stats,
            &baseline_path,
            &validation_deps,
            &mut access_map_collector,
            progress_enabled,
            start_time,
            scan_started_at,
            update_status,
            auto_cleanup_clones,
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
        repo_rx,
        repo_clone_handle,
        artifact_handle,
        &shared_profiler,
        enable_profiling,
        &matcher_stats,
        &baseline_path,
        &validation_deps,
        &mut access_map_collector,
        progress_enabled,
        start_time,
        scan_started_at,
        update_status,
        auto_cleanup_clones,
    )
    .await
}

// =================================================================================================
// Phase helpers
// =================================================================================================

/// Validates that all provided input paths exist.
fn validate_inputs(args: &scan::ScanArgs) -> Result<()> {
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

/// Enumerates repositories from all configured platforms, adds wiki URLs, and deduplicates.
async fn enumerate_all_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<crate::git_url::GitUrl>> {
    let mut repo_urls = enumerate_github_repos(args, global_args).await?;
    let gitlab_repo_urls = enumerate_gitlab_repos(args, global_args).await?;
    let gitea_repo_urls = enumerate_gitea_repos(args, global_args).await?;
    let huggingface_repo_urls = enumerate_huggingface_repos(args, global_args).await?;
    let bitbucket_repo_urls = enumerate_bitbucket_repos(args, global_args).await?;
    let azure_repo_urls = enumerate_azure_repos(args, global_args).await?;

    repo_urls.extend(gitlab_repo_urls);
    repo_urls.extend(gitea_repo_urls);
    repo_urls.extend(huggingface_repo_urls);
    repo_urls.extend(bitbucket_repo_urls);
    repo_urls.extend(azure_repo_urls);

    // Add wiki repositories for each URL when requested
    if args.input_specifier_args.repo_artifacts {
        let mut wiki_urls = Vec::new();
        for url in &repo_urls {
            if let Some(w) = github::wiki_url(url) {
                wiki_urls.push(w);
            }
            if let Some(w) = gitlab::wiki_url(url) {
                wiki_urls.push(w);
            }
            if let Some(w) = gitea::wiki_url(url) {
                wiki_urls.push(w);
            }
            if let Some(w) = bitbucket::wiki_url(url) {
                wiki_urls.push(w);
            }
            if let Some(w) = azure::wiki_url(url) {
                wiki_urls.push(w);
            }
        }
        repo_urls.extend(wiki_urls);
    }

    repo_urls.sort();
    repo_urls.dedup();

    Ok(repo_urls)
}

/// Spawns a background thread to clone/update git repositories, streaming results via a channel.
fn start_repo_cloning(
    repo_urls: &[crate::git_url::GitUrl],
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    repo_tx: crossbeam_channel::Sender<PathBuf>,
    _progress_enabled: bool,
) -> Option<std::thread::JoinHandle<()>> {
    if repo_urls.is_empty() {
        drop(repo_tx);
        return None;
    }

    let clone_args = args.clone();
    let clone_globals = global_args.clone();
    let clone_repo_urls = repo_urls.to_vec();
    let clone_datastore = Arc::clone(datastore);
    let clone_repo_tx = repo_tx.clone();

    let handle = std::thread::spawn(move || {
        if let Err(e) = clone_or_update_git_repos_streaming(
            &clone_args,
            &clone_globals,
            &clone_repo_urls,
            &clone_datastore,
            |path| {
                let _ = clone_repo_tx.send(path);
            },
        ) {
            error!("Failed to fetch one or more Git repositories: {e}");
        }
    });
    drop(repo_tx);
    Some(handle)
}

/// Spawns a dedicated thread (with its own multi-threaded tokio runtime)
/// that streams artifact directories into `out_tx` as each fetch completes.
/// Decoupling from the parent runtime ensures the artifact task can make
/// progress regardless of how the parent runtime is configured (including
/// `#[tokio::test]`'s default single-threaded runtime), while the scan
/// loops on the parent thread block on sync `repo_rx.iter()`.
///
/// # Panics
///
/// Panics if the OS refuses to spawn the worker thread (e.g. resource
/// exhaustion). This is treated as unrecoverable on the main scan path
/// because every other concurrent component would face the same limit.
fn start_artifact_fetching(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    repo_urls: &[crate::git_url::GitUrl],
    datastore: &Arc<Mutex<FindingsStore>>,
    out_tx: crossbeam_channel::Sender<PathBuf>,
    progress_enabled: bool,
) -> std::thread::JoinHandle<Result<()>> {
    let args = args.clone();
    let global_args = global_args.clone();
    let repo_urls = repo_urls.to_vec();
    let datastore = Arc::clone(datastore);
    std::thread::Builder::new()
        .name("artifact-fetcher".to_string())
        .spawn(move || -> Result<()> {
            let workers = args.num_jobs.max(1);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .max_blocking_threads(tokio_blocking_threads_limit(workers))
                .enable_all()
                .build()
                .context("Failed to build artifact-fetcher runtime")?;
            rt.block_on(fetch_all_artifacts(
                &args,
                &global_args,
                &repo_urls,
                &datastore,
                out_tx,
                progress_enabled,
            ))
        })
        .expect("failed to spawn artifact-fetcher thread")
}

/// Fetches artifacts from various platforms (issues, wikis, Jira, Confluence,
/// Slack, Docker) and streams each produced directory into `out_tx` as soon
/// as it is ready, so the scan loop can process them concurrently with
/// further fetches and with cloning. Returns when all sources are exhausted
/// or when the receiver has been dropped (scan aborted).
async fn fetch_all_artifacts(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    repo_urls: &[crate::git_url::GitUrl],
    datastore: &Arc<Mutex<FindingsStore>>,
    out_tx: crossbeam_channel::Sender<PathBuf>,
    progress_enabled: bool,
) -> Result<()> {
    let bitbucket_auth = bitbucket::AuthConfig::from_env();
    let bitbucket_host =
        args.input_specifier_args.bitbucket_api_url.host_str().map(|s| s.to_string());

    let push = |dir: PathBuf, tx: &crossbeam_channel::Sender<PathBuf>| -> bool {
        // send blocks on bounded channel (intended backpressure); errors
        // only happen if all receivers have been dropped (scan aborted).
        match tx.send(dir) {
            Ok(()) => true,
            Err(_) => {
                debug!("scan channel closed; stopping artifact fetcher");
                false
            }
        }
    };

    if args.input_specifier_args.repo_artifacts {
        fetch_git_host_artifacts(
            repo_urls,
            &args.input_specifier_args.bitbucket_api_url,
            &bitbucket_auth,
            bitbucket_host.clone(),
            global_args,
            datastore,
            args.num_jobs,
            out_tx.clone(),
        )
        .await?;
    }

    for d in fetch_jira_issues(args, global_args, datastore).await? {
        if !push(d, &out_tx) {
            return Ok(());
        }
    }

    for d in fetch_confluence_pages(args, global_args, datastore).await? {
        if !push(d, &out_tx) {
            return Ok(());
        }
    }

    for d in fetch_slack_messages(args, global_args, datastore).await? {
        if !push(d, &out_tx) {
            return Ok(());
        }
    }

    for d in fetch_teams_messages(args, global_args, datastore).await? {
        if !push(d, &out_tx) {
            return Ok(());
        }
    }

    for d in fetch_postman_resources(args, global_args, datastore).await? {
        if !push(d, &out_tx) {
            return Ok(());
        }
    }

    if !args.input_specifier_args.docker_image.is_empty()
        || !args.input_specifier_args.docker_archive.is_empty()
    {
        let clone_root = {
            let ds = datastore.lock().unwrap();
            ds.clone_root()
        };
        let mut docker_dirs = Vec::new();
        docker_dirs.extend(
            save_docker_images(
                &args.input_specifier_args.docker_image,
                &clone_root,
                progress_enabled,
            )
            .await?,
        );
        docker_dirs.extend(save_docker_archives(
            &args.input_specifier_args.docker_archive,
            &clone_root,
            progress_enabled,
        )?);
        for (dir, source) in docker_dirs {
            {
                let mut ds = datastore.lock().unwrap();
                ds.register_docker_image(dir.clone(), source);
            }
            if !push(dir, &out_tx) {
                return Ok(());
            }
        }
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
        only_valid: args.only_valid,
        audit_context: None,
    };

    let all_matches = reporter.get_unfiltered_matches(Some(false))?;
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

/// Applies baseline filtering if configured.
fn apply_baseline_if_configured(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    baseline_path: &std::path::Path,
    roots: &[PathBuf],
) -> Result<()> {
    if args.baseline_file.is_some() || args.manage_baseline {
        let mut ds = datastore.lock().unwrap();
        crate::baseline::apply_baseline(&mut ds, baseline_path, args.manage_baseline, roots)?;
    }
    Ok(())
}

fn effective_max_validation_body_len(args: &scan::ScanArgs) -> usize {
    if args.full_validation_response { 0 } else { args.max_validation_response_length }
}

/// Runs the validation phase on matches in the datastore.
#[expect(clippy::too_many_arguments)]
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
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
    artifact_handle: std::thread::JoinHandle<Result<()>>,
    shared_profiler: &Arc<ConcurrentRuleProfiler>,
    enable_profiling: bool,
    matcher_stats: &Arc<Mutex<MatcherStats>>,
    baseline_path: &Arc<PathBuf>,
    validation_deps: &Option<ValidationDeps>,
    access_map_collector: &mut Option<AccessMapCollector>,
    progress_enabled: bool,
    start_time: Instant,
    scan_started_at: chrono::DateTime<chrono::Local>,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    let mut streamed_roots = Vec::new();
    // Run the scan loop in a closure so that, even if a per-repo
    // `enumerate_filesystem_inputs` returns Err and short-circuits via `?`,
    // we still drop `repo_rx` and join the cloning + artifact-fetching
    // threads before returning. Without this, the producer threads would
    // continue cloning into `/tmp` after the scan has already failed.
    let scan_result: Result<()> = (|| {
        if !input_roots.is_empty() {
            let _inputs = enumerate_filesystem_inputs(
                args,
                datastore.clone(),
                input_roots,
                progress_enabled,
                rules_db,
                enable_profiling,
                Arc::clone(shared_profiler),
                matcher_stats.as_ref(),
            )?;
        }

        for repo_root in repo_rx.iter() {
            enumerate_filesystem_inputs(
                args,
                datastore.clone(),
                &[repo_root.clone()],
                progress_enabled,
                rules_db,
                enable_profiling,
                Arc::clone(shared_profiler),
                matcher_stats.as_ref(),
            )?;
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
    artifact_result.map_err(|e| e.context("artifact fetching failed"))?;

    deduplicate_new_matches(datastore, global_args, args, 0)?;
    apply_baseline_if_configured(args, datastore, baseline_path.as_ref(), input_roots)?;

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
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
    artifact_handle: std::thread::JoinHandle<Result<()>>,
    shared_profiler: &Arc<ConcurrentRuleProfiler>,
    enable_profiling: bool,
    matcher_stats: &Arc<Mutex<MatcherStats>>,
    baseline_path: &Arc<PathBuf>,
    validation_deps: &Option<ValidationDeps>,
    access_map_collector: &mut Option<AccessMapCollector>,
    progress_enabled: bool,
    start_time: Instant,
    scan_started_at: chrono::DateTime<chrono::Local>,
    update_status: &crate::update::UpdateStatus,
    auto_cleanup_clones: bool,
) -> Result<()> {
    deduplicate_new_matches(datastore, global_args, args, 0)?;
    apply_baseline_if_configured(args, datastore, baseline_path.as_ref(), repo_roots)?;

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
    let output_to_file = args.output_args.output.is_some();

    rayon::ThreadPoolBuilder::new()
        .num_threads(repo_concurrency)
        .build()
        .context("Failed to build repo scan thread pool")?
        .scope(|scope| {
            // Distinguishes user-supplied `repo_roots` (must be preserved)
            // from clones / artifact dirs that arrive via `repo_rx` and
            // are eligible for post-scan cleanup.
            #[derive(Clone, Copy)]
            enum ScanRootSource {
                UserPath,
                Streamed,
            }
            let spawn_repo_scan = |root: PathBuf, source: ScanRootSource| {
                let repo_rules = repo_rules.clone();
                let base_clone_root = base_clone_root.clone();
                let baseline_path = Arc::clone(baseline_path);
                let shared_profiler = Arc::clone(shared_profiler);
                let args = args.clone();
                let root = root.clone();
                let validation_deps = validation_deps.clone();
                let matcher_stats = Arc::clone(matcher_stats);
                let rt_handle = rt_handle.clone();
                let ran_repo_scan = Arc::clone(&ran_repo_scan);
                let repo_errors = Arc::clone(&repo_errors);
                let datastore = Arc::clone(datastore);
                let access_map = access_map_collector.clone();

                scope.spawn(move |_| {
                    let result: Result<()> = (|| {
                        let repo_datastore =
                            Arc::new(Mutex::new(FindingsStore::new(base_clone_root.clone())));
                        {
                            let mut ds = repo_datastore.lock().unwrap();
                            ds.record_rules(&repo_rules);
                        }

                        let repo_matcher_stats = Mutex::new(MatcherStats::default());

                        enumerate_filesystem_inputs(
                            &args,
                            Arc::clone(&repo_datastore),
                            &[root.clone()],
                            progress_enabled,
                            rules_db,
                            enable_profiling,
                            Arc::clone(&shared_profiler),
                            &repo_matcher_stats,
                        )
                        .and_then(|_| {
                            deduplicate_new_matches(&repo_datastore, global_args, &args, 0)
                        })?;

                        if args.baseline_file.is_some() || args.manage_baseline {
                            let mut ds = repo_datastore.lock().unwrap();
                            crate::baseline::apply_baseline(
                                &mut ds,
                                baseline_path.as_ref(),
                                args.manage_baseline,
                                &[root.clone()],
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
                        }

                        ran_repo_scan.store(true, Ordering::Relaxed);
                        Ok(())
                    })();

                    if let Err(e) = result {
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
                spawn_repo_scan(root, ScanRootSource::UserPath);
            }

            for root in repo_rx.iter() {
                spawn_repo_scan(root, ScanRootSource::Streamed);
            }
        });

    if let Some(handle) = repo_clone_handle {
        let _ = handle.join();
    }
    // Surface artifact-fetching errors after all per-repo scans have finished.
    match artifact_handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e.context("artifact fetching failed")),
        Err(_) => return Err(anyhow::anyhow!("artifact fetch thread panicked")),
    }

    if let Some(err) = repo_errors.lock().unwrap().pop() {
        return Err(err);
    }

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
        crate::reporter::run(global_args, Arc::clone(datastore), args, Some(audit_context))
            .context("Failed to run report command")?;
    }

    if !ran_repo_scan.load(Ordering::Relaxed) {
        deduplicate_new_matches(datastore, global_args, args, 0)?;
        apply_baseline_if_configured(args, datastore, baseline_path.as_ref(), repo_roots)?;

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
        crate::reporter::run(global_args, Arc::clone(datastore), args, Some(audit_context))
            .context("Failed to run report command")?;
    }

    let aggregate_summary = if ran_repo_scan.load(Ordering::Relaxed) {
        let totals = compute_scan_totals(datastore, args, matcher_stats.as_ref());
        let mut sorted: Vec<_> = datastore.lock().unwrap().get_summary().into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
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

    match access_map_collector.take() {
        Some(collector) => {
            finalize_access_map(datastore, collector, args).await?;
        }
        _ => {
            maybe_hint_access_map(datastore, args);
        }
    }
    Ok(())
}

// =================================================================================================
// Existing helper functions (unchanged)
// =================================================================================================

async fn finalize_access_map(
    datastore: &Arc<Mutex<FindingsStore>>,
    collector: AccessMapCollector,
    _args: &scan::ScanArgs,
) -> Result<()> {
    let requests = collector.into_requests();

    if requests.is_empty() {
        debug!(
            "access-map enabled but no validated AWS, GCP, or Azure credentials were collected; skipping report output"
        );
        let mut ds = datastore.lock().unwrap();
        ds.set_access_map_results(Vec::new());
        return Ok(());
    }

    let results = access_map::map_requests(requests).await;

    {
        let mut ds = datastore.lock().unwrap();
        ds.set_access_map_results(results.clone());
    }

    Ok(())
}

fn expand_repo_roots(input_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut repo_roots = Vec::new();

    for root in input_roots {
        if root.join(".git").is_dir() {
            repo_roots.push(root.clone());
            continue;
        }

        if !root.is_dir() {
            repo_roots.push(root.clone());
            continue;
        }

        let mut child_roots = Vec::new();
        let mut non_repo_children = Vec::new();
        for entry in fs::read_dir(root).with_context(|| {
            format!("Failed to read directory while expanding repo roots: {}", root.display())
        })? {
            let entry = entry?;
            let child_path = entry.path();
            if child_path.join(".git").is_dir() {
                child_roots.push(child_path);
            } else {
                non_repo_children.push(child_path);
            }
        }

        if child_roots.is_empty() {
            repo_roots.push(root.clone());
        } else {
            repo_roots.extend(child_roots);
            repo_roots.extend(non_repo_children);
        }
    }

    Ok(repo_roots)
}

fn maybe_hint_access_map(datastore: &Arc<Mutex<FindingsStore>>, args: &scan::ScanArgs) {
    if args.access_map || args.no_validate {
        return;
    }

    let has_mappable_identities = {
        let ds = datastore.lock().unwrap();
        ds.get_matches().iter().any(|entry| {
            let rule = &entry.2.rule;
            entry.2.validation_success
                && (matches!(rule.syntax().validation, Some(Validation::AWS | Validation::GCP))
                    || rule.id().starts_with("kingfisher.github.")
                    || rule.id().starts_with("kingfisher.gitlab."))
        })
    };

    if has_mappable_identities {
        info!(
            "Access map not requested. Rerun with --access-map to include resource-level permissions, if authorized."
        );
    }
}

fn initialize_environment(use_progress: bool) -> Result<()> {
    let init_progress =
        if use_progress { ProgressBar::new_spinner() } else { ProgressBar::hidden() };
    init_progress.set_message("Initializing thread pool...");
    let num_threads = std::thread::available_parallelism().map_or(1, |n| n.get());
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

pub fn create_datastore_channel(
    num_jobs: usize,
) -> (
    crossbeam_channel::Sender<findings_store::FindingsStoreMessage>,
    crossbeam_channel::Receiver<findings_store::FindingsStoreMessage>,
) {
    const BATCH_SIZE: usize = 1024;
    let channel_size = std::cmp::max(num_jobs * BATCH_SIZE, 16 * BATCH_SIZE);
    crossbeam_channel::bounded(channel_size)
}

pub fn spawn_datastore_writer_thread(
    datastore: Arc<Mutex<FindingsStore>>,
    recv_ds: crossbeam_channel::Receiver<findings_store::FindingsStoreMessage>,
    dedup: bool,
) -> Result<std::thread::JoinHandle<Result<(usize, usize)>>> {
    std::thread::Builder::new()
        .name("in-memory-storage".to_string())
        .spawn(move || -> Result<_> {
            let _span = error_span!("in-memory-storage").entered();
            let mut total_recording_time = Duration::default();
            let mut num_matches_added = 0;
            let mut total_messages = 0;
            // Increased batch size and commit interval
            const BATCH_SIZE: usize = 32 * 1024;
            const COMMIT_INTERVAL: Duration = Duration::from_secs(2);
            // Pre-allocate batch vector
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            let mut last_commit_time = Instant::now();
            'outer: loop {
                // Try to fill batch quickly without sleeping
                while batch.len() < BATCH_SIZE {
                    match recv_ds.try_recv() {
                        Ok(message) => {
                            total_messages += 1;
                            batch.push(message);
                        }
                        Err(crossbeam_channel::TryRecvError::Empty) => {
                            // Channel empty - check if we should commit
                            if !batch.is_empty()
                                && (batch.len() >= BATCH_SIZE
                                    || last_commit_time.elapsed() >= COMMIT_INTERVAL)
                            {
                                break;
                            }
                            // Sleep only when channel is empty
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(crossbeam_channel::TryRecvError::Disconnected) => {
                            break 'outer;
                        }
                    }
                }
                // Commit batch if we have messages
                if !batch.is_empty() {
                    let t1 = Instant::now();
                    // Take ownership of batch and replace with empty pre-allocated vec
                    let commit_batch =
                        std::mem::replace(&mut batch, Vec::with_capacity(BATCH_SIZE));
                    let num_added = datastore.lock().unwrap().record(commit_batch, dedup);
                    last_commit_time = Instant::now();
                    num_matches_added += num_added;
                    total_recording_time += t1.elapsed();
                }
            }
            // Final commit of any remaining items
            if !batch.is_empty() {
                let t1 = Instant::now();
                let num_added = datastore.lock().unwrap().record(batch, dedup);

                num_matches_added += num_added;
                total_recording_time += t1.elapsed();
            }
            let num_matches = datastore.lock().unwrap().get_num_matches();
            debug!(
                "Summary: recorded {num_matches} matches from {total_messages} messages in {:.6}s",
                total_recording_time.as_secs_f64(),
            );
            Ok((num_matches, num_matches_added))
        })
        .context("Failed to spawn datastore writer thread")
}

pub fn load_and_record_rules(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    use_progress: bool,
) -> Result<RulesDatabase> {
    let init_progress =
        if use_progress { ProgressBar::new_spinner() } else { ProgressBar::hidden() };
    let rules_db = {
        let loaded = RuleLoader::from_rule_specifiers(&args.rules)
            .load(args)
            .context("Failed to load rules")?;
        let resolved = loaded.resolve_enabled_rules().context("Failed to resolve rules")?;
        // Apply min_entropy override if specified
        let rules = resolved
            .into_iter()
            .cloned()
            .map(|mut rule| {
                if let Some(min_entropy) = args.min_entropy {
                    let _ = rule.set_entropy(min_entropy);
                }
                rule
            })
            .collect();
        RulesDatabase::from_rules(rules).context("Failed to compile rules")?
    };
    init_progress.set_message("Recording rules...");
    datastore
        .lock()
        .unwrap()
        .record_rules(rules_db.rules().iter().cloned().collect::<Vec<_>>().as_slice());
    Ok(rules_db)
}
