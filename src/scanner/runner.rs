use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{bail, Context, Result};
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
    reporter::styles::Styles,
    rule_loader::RuleLoader,
    rule_profiling::ConcurrentRuleProfiler,
    rules::rule::Validation,
    rules_database::RulesDatabase,
    safe_list,
    scanner::{
        clone_or_update_git_repos_streaming, enumerate_azure_repos, enumerate_bitbucket_repos,
        enumerate_filesystem_inputs, enumerate_github_repos, enumerate_huggingface_repos,
        repos::{
            enumerate_gitea_repos, enumerate_gitlab_repos, fetch_confluence_pages,
            fetch_gcs_objects, fetch_git_host_artifacts, fetch_jira_issues, fetch_s3_objects,
            fetch_slack_messages,
        },
        run_secret_validation, save_docker_images,
        summary::{compute_scan_totals, print_scan_summary},
        AccessMapCollector,
    },
    util::set_redaction_enabled,
    validation::CachedResponse,
    validation_rate_limit::ValidationRateLimiter,
};

/// Shared validation dependencies: (liquid parser, HTTP clients, validation cache, rate limiter).
type ValidationDeps = Arc<(
    liquid::Parser,
    crate::validation::ValidationClients,
    Arc<SkipMap<String, CachedResponse>>,
    Option<Arc<ValidationRateLimiter>>,
)>;

pub async fn run_scan(
    global_args: &global::GlobalArgs,
    scan_args: &scan::ScanArgs,
    rules_db: &RulesDatabase,
    datastore: Arc<Mutex<FindingsStore>>,
    update_status: &crate::update::UpdateStatus,
) -> Result<()> {
    run_async_scan(global_args, scan_args, Arc::clone(&datastore), rules_db, update_status)
        .await
        .context("Failed to run scan command")
}

pub async fn run_async_scan(
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    update_status: &crate::update::UpdateStatus,
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
    let (repo_tx, repo_rx) = crossbeam_channel::unbounded();
    let repo_clone_handle =
        start_repo_cloning(&repo_urls, args, global_args, &datastore, repo_tx, progress_enabled);

    // ── Phase 3: Artifact fetching ──────────────────────────────────────
    fetch_all_artifacts(
        args,
        global_args,
        &repo_urls,
        &datastore,
        &mut input_roots,
        progress_enabled,
    )
    .await?;

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
    if input_roots.is_empty() && repo_urls.is_empty() && !has_remote_objects {
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

    let validation_deps: Option<ValidationDeps> = if !args.no_validate {
        info!("Starting secret validation phase...");
        Some(Arc::new((
            register_all(liquid::ParserBuilder::with_stdlib()).build()?,
            crate::validation::ValidationClients::new(global_args.tls_mode)?,
            Arc::new(SkipMap::new()),
            validation_rate_limiter.clone(),
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

/// Fetches artifacts from various platforms (issues, wikis, Jira, Confluence, Slack, Docker).
async fn fetch_all_artifacts(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    repo_urls: &[crate::git_url::GitUrl],
    datastore: &Arc<Mutex<FindingsStore>>,
    input_roots: &mut Vec<PathBuf>,
    progress_enabled: bool,
) -> Result<()> {
    let bitbucket_auth = bitbucket::AuthConfig::from_env();
    let bitbucket_host =
        args.input_specifier_args.bitbucket_api_url.host_str().map(|s| s.to_string());

    if args.input_specifier_args.repo_artifacts {
        let repo_artifact_dirs = fetch_git_host_artifacts(
            repo_urls,
            &args.input_specifier_args.bitbucket_api_url,
            &bitbucket_auth,
            bitbucket_host.clone(),
            global_args,
            datastore,
        )
        .await?;
        input_roots.extend(repo_artifact_dirs);
    }

    // Fetch Jira issues if requested
    let jira_dirs = fetch_jira_issues(
        args,
        global_args,
        datastore,
        args.input_specifier_args.scan_comments,
        args.input_specifier_args.scan_changelog,
    )
    .await?;
    input_roots.extend(jira_dirs);

    // Fetch Confluence pages if requested
    let confluence_dirs = fetch_confluence_pages(args, global_args, datastore).await?;
    input_roots.extend(confluence_dirs);

    // Fetch Slack messages if requested
    let slack_dirs = fetch_slack_messages(args, global_args, datastore).await?;
    input_roots.extend(slack_dirs);

    // Save Docker images if specified
    if !args.input_specifier_args.docker_image.is_empty() {
        let clone_root = {
            let ds = datastore.lock().unwrap();
            ds.clone_root()
        };
        let docker_dirs = save_docker_images(
            &args.input_specifier_args.docker_image,
            &clone_root,
            progress_enabled,
        )
        .await?;
        for (dir, img) in docker_dirs {
            {
                let mut ds = datastore.lock().unwrap();
                ds.register_docker_image(dir.clone(), img);
            }
            input_roots.push(dir);
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

/// Runs the validation phase on matches in the datastore.
#[allow(clippy::too_many_arguments)]
async fn run_validation_phase(
    datastore: &Arc<Mutex<FindingsStore>>,
    validation_deps: &Option<ValidationDeps>,
    args: &scan::ScanArgs,
    match_range: Option<std::ops::Range<usize>>,
    access_map_collector: Option<AccessMapCollector>,
) -> Result<()> {
    if let Some(validation) = validation_deps {
        let (parser, clients, cache, rate_limiter) =
            (&validation.0, &validation.1, &validation.2, &validation.3);
        run_secret_validation(
            Arc::clone(datastore),
            parser,
            clients,
            cache,
            args.num_jobs,
            match_range,
            access_map_collector,
            rate_limiter.clone(),
            Duration::from_secs(args.validation_timeout),
            args.validation_retries,
        )
        .await?;
    }
    Ok(())
}

// =================================================================================================
// Sequential scan path
// =================================================================================================

#[allow(clippy::too_many_arguments)]
async fn run_sequential_scan(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    rules_db: &RulesDatabase,
    input_roots: &mut Vec<PathBuf>,
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
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
) -> Result<()> {
    let mut streamed_roots = Vec::new();
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
        streamed_roots.push(repo_root);
    }
    input_roots.extend(streamed_roots);

    if let Some(handle) = repo_clone_handle {
        let _ = handle.join();
    }

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

#[allow(clippy::too_many_arguments)]
async fn run_parallel_scan(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    rules_db: &RulesDatabase,
    repo_roots: &[PathBuf],
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
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
) -> Result<()> {
    deduplicate_new_matches(datastore, global_args, args, 0)?;
    apply_baseline_if_configured(args, datastore, baseline_path.as_ref(), repo_roots)?;

    // Validate initial (non-repo) matches
    if let Some(validation) = validation_deps {
        let (parser, clients, cache, rate_limiter) =
            (&validation.0, &validation.1, &validation.2, &validation.3);
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
                Duration::from_secs(args.validation_timeout),
                args.validation_retries,
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
            let spawn_repo_scan = |root: PathBuf| {
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
                            let (parser, clients, cache, rate_limiter) =
                                (&validation.0, &validation.1, &validation.2, &validation.3);
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
                                    Duration::from_secs(args.validation_timeout),
                                    args.validation_retries,
                                ))?;
                            }
                        }

                        {
                            let mut global_stats = matcher_stats.lock().unwrap();
                            global_stats.update(&repo_matcher_stats.lock().unwrap());
                        }

                        if !output_to_file {
                            crate::reporter::run(
                                global_args,
                                Arc::clone(&repo_datastore),
                                &args,
                                None,
                            )
                            .context("Failed to run report command")?;
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
                });
            };

            for root in repo_roots.iter().cloned() {
                spawn_repo_scan(root);
            }

            for root in repo_rx.iter() {
                spawn_repo_scan(root);
            }
        });

    if let Some(handle) = repo_clone_handle {
        let _ = handle.join();
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

    if let Some(collector) = access_map_collector.take() {
        finalize_access_map(datastore, collector, args).await?;
    } else {
        maybe_hint_access_map(datastore, args);
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
        debug!("access-map enabled but no validated AWS, GCP, or Azure credentials were collected; skipping report output");
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
    let num_threads = num_cpus::get();
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
