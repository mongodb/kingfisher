use std::{
    collections::{HashMap, HashSet},
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
    rules_database::{
        RuleCacheConfig, RuleCachePruneConfig, RulesDatabase, compute_rule_cache_key,
        prune_rule_cache,
    },
    safe_list,
    scan_audit::{RepositoryScanStats, ScanAuditCollector, SharedScanAudit, combine_git_snapshots},
    scanner::{
        AccessMapCollector, clone_or_update_git_repos_streaming, enumerate_azure_repos,
        enumerate_bitbucket_repos, enumerate_filesystem_inputs, enumerate_github_event_targets,
        enumerate_github_repos, enumerate_huggingface_repos,
        repos::{
            enumerate_gitea_repos, enumerate_gitlab_repos, enumerate_huggingface_buckets,
            fetch_confluence_pages, fetch_gcs_objects, fetch_git_host_artifacts,
            fetch_huggingface_objects, fetch_jira_issues, fetch_postman_resources,
            fetch_s3_objects, fetch_slack_messages, fetch_teams_messages,
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
    let scan_audit: SharedScanAudit = Arc::new(Mutex::new(ScanAuditCollector::new(
        scan_started_at.to_rfc3339(),
        args.audit_log.as_deref(),
    )?));

    trace!("Args:\n{global_args:#?}\n{args:#?}");
    let progress_enabled = global_args.use_progress();
    initialize_environment(progress_enabled, args.num_jobs)?;

    set_redaction_enabled(args.redact);

    // ── Phase 2: Repository enumeration ─────────────────────────────────
    let repo_enumeration = enumerate_all_repos(args, global_args).await?;
    let repo_urls = repo_enumeration.repo_urls;
    {
        let mut audit = scan_audit.lock().unwrap();
        for repo_url in &repo_urls {
            audit.discover_remote(repo_url.as_str());
        }
    }
    let github_event_targets_by_root =
        Arc::new(github_event_targets_by_root(&repo_enumeration.github_event_targets, &datastore));
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
    let repo_clone_handle = start_repo_cloning(
        &repo_urls,
        args,
        global_args,
        &datastore,
        &scan_audit,
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

    let has_remote_objects = args.input_specifier_args.s3_bucket.is_some()
        || args.input_specifier_args.gcs_bucket.is_some()
        || !huggingface_buckets.is_empty();
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
    let git_repo_count =
        repo_roots.iter().filter(|root| is_git_repository_root(root)).count() + repo_urls.len();
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

struct RepoEnumeration {
    repo_urls: Vec<crate::git_url::GitUrl>,
    github_event_targets: Vec<github::GitHubEventScanTarget>,
}

/// Enumerates repositories from all configured platforms, adds wiki URLs, and deduplicates.
async fn enumerate_all_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<RepoEnumeration> {
    let mut repo_urls = enumerate_github_repos(args, global_args).await?;
    let github_event_targets = enumerate_github_event_targets(args, global_args).await?;

    repo_urls.extend(github_event_targets.iter().map(|target| target.repo_url.clone()));
    repo_urls.extend(enumerate_gitlab_repos(args, global_args).await?);
    repo_urls.extend(enumerate_gitea_repos(args, global_args).await?);
    repo_urls.extend(enumerate_huggingface_repos(args, global_args).await?);
    repo_urls.extend(enumerate_bitbucket_repos(args, global_args).await?);
    repo_urls.extend(enumerate_azure_repos(args, global_args).await?);

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

    Ok(RepoEnumeration { repo_urls, github_event_targets })
}

fn github_event_targets_by_root(
    targets: &[github::GitHubEventScanTarget],
    datastore: &Arc<Mutex<FindingsStore>>,
) -> HashMap<PathBuf, Vec<github::GitHubEventScanTarget>> {
    let ds = datastore.lock().unwrap();
    let mut by_root: HashMap<PathBuf, Vec<github::GitHubEventScanTarget>> = HashMap::new();
    for target in targets {
        by_root.entry(ds.clone_destination(&target.repo_url)).or_default().push(target.clone());
    }
    for targets in by_root.values_mut() {
        targets.sort();
        targets.dedup();
    }
    by_root
}

fn scan_args_for_github_event_target(
    args: &scan::ScanArgs,
    target: &github::GitHubEventScanTarget,
) -> scan::ScanArgs {
    let mut target_args = args.clone();
    let input = &mut target_args.input_specifier_args;
    input.since_commit = None;
    input.staged = false;
    input.branch = None;
    input.branch_root = false;
    input.branch_root_commit = None;

    let (branch, branch_root_commit) = git_refs_for_github_event_selector(&target.selector);
    input.branch = branch;
    input.branch_root_commit = branch_root_commit;

    target_args
}

fn git_refs_for_github_event_selector(
    selector: &github::GitHubEventScanSelector,
) -> (Option<String>, Option<String>) {
    match selector {
        github::GitHubEventScanSelector::Repository => (None, None),
        github::GitHubEventScanSelector::Branch(ref_name) => (Some(ref_name.clone()), None),
        github::GitHubEventScanSelector::Commit(sha) => (Some(sha.clone()), Some(sha.clone())),
    }
}

/// Spawns a background thread to clone/update git repositories, streaming results via a channel.
fn start_repo_cloning(
    repo_urls: &[crate::git_url::GitUrl],
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    audit: &SharedScanAudit,
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
    let clone_audit = Arc::clone(audit);
    let clone_repo_tx = repo_tx.clone();

    let handle = std::thread::spawn(move || {
        if let Err(e) = clone_or_update_git_repos_streaming(
            &clone_args,
            &clone_globals,
            &clone_repo_urls,
            &clone_datastore,
            &clone_audit,
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
            &args.input_specifier_args.github_api_url,
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

fn repository_audit_applies(args: &scan::ScanArgs) -> bool {
    let input = &args.input_specifier_args;
    !input.path_inputs.is_empty()
        || !input.git_url.is_empty()
        || !input.github_user.is_empty()
        || !input.github_organization.is_empty()
        || input.all_github_organizations
        || !input.github_event_user.is_empty()
        || !input.gitlab_user.is_empty()
        || !input.gitlab_group.is_empty()
        || input.all_gitlab_groups
        || !input.gitea_user.is_empty()
        || !input.gitea_organization.is_empty()
        || input.all_gitea_organizations
        || !input.bitbucket_user.is_empty()
        || !input.bitbucket_workspace.is_empty()
        || !input.bitbucket_project.is_empty()
        || input.all_bitbucket_workspaces
        || !input.azure_organization.is_empty()
        || !input.azure_project.is_empty()
        || input.all_azure_projects
        || input.repo_artifacts
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
    artifact_handle: std::thread::JoinHandle<Result<()>>,
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
    // continue cloning into `/tmp` after the scan has already failed.
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
    if repository_audit.summary.discovered > 0 || repository_audit_applies(args) {
        datastore.lock().unwrap().set_scan_audit(repository_audit.clone());
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
    discovered_repos: Arc<Vec<PathBuf>>,
    repo_rx: crossbeam_channel::Receiver<PathBuf>,
    repo_clone_handle: Option<std::thread::JoinHandle<()>>,
    artifact_handle: std::thread::JoinHandle<Result<()>>,
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
        .scope(|scope| {
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
    if repository_audit.summary.discovered > 0 || repository_audit_applies(args) {
        datastore.lock().unwrap().set_scan_audit(repository_audit.clone());
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
// Existing helper functions (unchanged)
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

    let results = access_map::map_collected_requests(requests).await;

    {
        let mut ds = datastore.lock().unwrap();
        ds.set_access_map_results(results.clone());
    }

    Ok(())
}

/// Expands directory inputs into scan roots and discovered repositories.
///
/// Repositories found anywhere in a directory subtree become their own scan
/// roots (each with its own scan lifecycle and audit record); the input
/// directory itself also remains a scan root covering all non-repository
/// content, with the discovered repository subtrees excluded from its walk so
/// nothing is scanned twice. That grouped root keeps loose sibling files at
/// directory granularity instead of turning each into its own scan root, and
/// repository-free directory trees still collapse to a single root. Returns
/// `(scan_roots, repo_roots)`.
fn expand_repo_roots(
    input_roots: &[PathBuf],
    exclude_globset: Option<&std::sync::Arc<globset::GlobSet>>,
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut scan_roots = Vec::new();
    let mut repo_roots = Vec::new();

    for root in input_roots {
        if is_symlink(root) {
            scan_roots.push(root.clone());
            continue;
        }
        if is_git_repository_root(root) {
            scan_roots.push(root.clone());
            repo_roots.push(root.clone());
            continue;
        }
        if !root.is_dir() {
            scan_roots.push(root.clone());
            continue;
        }

        let (mut found, non_repo_content) = find_repo_roots_in_dir(root, exclude_globset)?;
        if found.is_empty() {
            scan_roots.push(root.clone());
            continue;
        }
        repo_roots.extend(found.iter().cloned());
        scan_roots.append(&mut found);
        if non_repo_content {
            // The grouped root covers every non-repository file and directory
            // in the subtree; the walker prunes the repository subtrees, which
            // are scanned through their own roots above.
            scan_roots.push(root.clone());
        }
    }

    Ok((deduplicate_paths(scan_roots), deduplicate_paths(repo_roots)))
}

fn deduplicate_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::with_capacity(paths.len());
    paths.into_iter().filter(|path| seen.insert(path.clone())).collect()
}

/// Collects the repository roots found under `dir`, not descending into a
/// discovered repository, skipping children matched by the `--exclude`
/// globset, and skipping symlinked directories (the filesystem walker runs
/// with `follow_links(false)` and would not traverse them either; a link is
/// reported as non-repository content so the grouped root covers it).
///
/// Returns the repository roots plus whether any non-repository content was
/// seen, so the caller can decide whether a grouped root is needed.
fn find_repo_roots_in_dir(
    dir: &Path,
    exclude_globset: Option<&std::sync::Arc<globset::GlobSet>>,
) -> Result<(Vec<PathBuf>, bool)> {
    let mut repos = Vec::new();
    // Mirror the filesystem walker, which logs and skips unreadable entries
    // instead of failing the scan: this pre-scan also runs before --exclude
    // filtering, so an unreadable — and possibly excluded — descendant must
    // not abort an otherwise valid scan.
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => {
            debug!(
                "Skipping unreadable directory while expanding repo roots: {}: {error}",
                dir.display()
            );
            return Ok((repos, true));
        }
    };
    let mut non_repo_content = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                debug!("Skipping entry while expanding repo roots: {error}");
                continue;
            }
        };
        let child_path = entry.path();
        if exclude_globset.as_ref().is_some_and(|globset| globset.is_match(&child_path)) {
            debug!("Skipping {} due to --exclude while expanding repo roots", child_path.display());
            continue;
        }
        if is_symlink(&child_path) {
            // Never classify a symlink as a repository root: the walker does
            // not descend into symlinked directories, so the link target
            // would be scanned (and audited) even though it is not part of
            // the tree. The grouped root still covers the link entry itself.
            non_repo_content = true;
            continue;
        }
        if is_git_repository_root(&child_path) {
            repos.push(child_path);
        } else if child_path.is_dir() {
            let (mut child_repos, child_content) =
                find_repo_roots_in_dir(&child_path, exclude_globset)?;
            repos.append(&mut child_repos);
            non_repo_content |= child_content;
        } else {
            non_repo_content = true;
        }
    }
    repos.sort();
    Ok((repos, non_repo_content))
}

fn is_git_repository_root(root: &Path) -> bool {
    !is_symlink(root)
        && (root.join(".git").exists()
            || (root.join("HEAD").is_file() && root.join("objects").is_dir()))
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
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
        let resolved = loaded.resolve_enabled_rules_owned().context("Failed to resolve rules")?;
        let betterleaks_prefilter = loaded.betterleaks_prefilter_for(&resolved);
        // Apply min_entropy override if specified
        let rules: Vec<_> = resolved
            .into_iter()
            .map(|mut rule| {
                if let Some(min_entropy) = args.min_entropy {
                    let _ = rule.set_entropy(min_entropy);
                }
                rule
            })
            .collect();
        if args.rule_cache.enabled() {
            let cache = RuleCacheConfig::from_dir_or_env(args.rule_cache.rule_cache_dir.clone());
            info!(cache_dir = %cache.cache_dir().display(), "Using Vectorscan rule cache");
            if args.rule_cache.prune_rule_cache {
                let protected_cache_key = compute_rule_cache_key(&rules);
                let summary = prune_rule_cache(
                    &cache,
                    &RuleCachePruneConfig {
                        max_entries: args.rule_cache.rule_cache_max_entries,
                        max_age: args.rule_cache.rule_cache_max_age,
                        protected_cache_key: Some(protected_cache_key),
                        dry_run: false,
                    },
                );
                info!(
                    cache_dir = %cache.cache_dir().display(),
                    scanned_entries = summary.scanned_entries,
                    valid_entries = summary.valid_entries,
                    removed_entries = summary.removed_entries,
                    removed_bytes = summary.removed_bytes,
                    removal_errors = summary.removal_errors,
                    "Pruned Vectorscan rule cache"
                );
            }
            RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
                rules,
                &cache,
                betterleaks_prefilter,
            )
            .context("Failed to compile rules with Vectorscan cache")?
        } else {
            RulesDatabase::from_rules_with_betterleaks_prefilter(rules, betterleaks_prefilter)
                .context("Failed to compile rules")?
        }
    };
    init_progress.set_message("Recording rules...");
    datastore.lock().unwrap().record_rules(rules_db.rules());
    Ok(rules_db)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::expand_repo_roots;
    use super::git_refs_for_github_event_selector;
    use crate::github::GitHubEventScanSelector;

    #[test]
    fn expand_repo_roots_discovers_nested_repositories() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        // workspace/services/api/.git — a repository two levels below the
        // input, plus a repository-free sibling subtree and a loose file.
        std::fs::create_dir_all(base.join("workspace/services/api/.git")).unwrap();
        std::fs::create_dir_all(base.join("workspace/docs")).unwrap();
        std::fs::write(base.join("workspace/docs/README.md"), b"x").unwrap();
        std::fs::create_dir_all(base.join("plain")).unwrap();
        std::fs::write(base.join("plain/notes.txt"), b"x").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        let nested = base.join("workspace/services/api");
        assert!(
            roots.contains(&nested),
            "nested repository must become its own scan root: {roots:?}"
        );
        assert!(repos.contains(&nested));
        // The input root stays a single grouped root covering the loose
        // sibling content instead of exploding into per-file roots.
        assert!(roots.contains(&base.to_path_buf()));
        // Intermediate directories are not roots of their own, and the
        // repository is not covered twice.
        assert!(!roots.contains(&base.join("workspace")));
        assert!(!roots.contains(&base.join("workspace/services")));
        assert_eq!(roots.len(), roots.iter().collect::<std::collections::HashSet<_>>().len());
    }

    #[test]
    fn expand_repo_roots_keeps_repository_free_tree_as_one_root() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("a/b/c")).unwrap();
        std::fs::write(base.join("a/b/c/file.txt"), b"x").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        assert_eq!(roots, vec![base.to_path_buf()]);
        assert!(repos.is_empty());
    }

    #[test]
    fn expand_repo_roots_skips_excluded_subtrees() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("deps/vendor/repo/.git")).unwrap();
        std::fs::create_dir_all(base.join("src/api/.git")).unwrap();

        // The same pattern expansion the filesystem walker applies via
        // --exclude: a literal pattern excludes the named directory anywhere
        // in the tree.
        let exclude_globset = crate::build_exclude_globset(&["deps".to_string()]).unwrap().unwrap();
        let (roots, repos) =
            expand_repo_roots(&[base.to_path_buf()], Some(&exclude_globset)).unwrap();

        // The excluded subtree is neither expanded nor emitted, so the
        // repository inside it stays out of the audit manifest exactly like
        // the filesystem walker keeps it out of the scan.
        assert!(!roots.contains(&base.join("deps/vendor/repo")));
        assert!(!roots.iter().any(|root| root.starts_with(base.join("deps"))));
        assert!(roots.contains(&base.join("src/api")));
        assert!(repos.contains(&base.join("src/api")));
    }

    #[test]
    fn expand_repo_roots_does_not_descend_into_found_repository() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        // A repository containing a nested-looking .git deeper inside: the
        // outer repository wins and the walk must not recurse into it.
        std::fs::create_dir_all(base.join("outer/.git")).unwrap();
        std::fs::create_dir_all(base.join("outer/vendor/inner/.git")).unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        assert_eq!(roots, vec![base.join("outer")]);
        assert_eq!(repos, vec![base.join("outer")]);
    }

    #[test]
    fn expand_repo_roots_deduplicates_overlapping_inputs() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let repo = base.join("workspace/repo");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::write(base.join("notes.txt"), b"notes").unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf(), repo.clone()], None).unwrap();

        assert_eq!(roots, vec![repo.clone(), base.to_path_buf()]);
        assert_eq!(repos, vec![repo]);
    }

    #[test]
    fn scan_nested_repositories_can_be_disabled() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let nested = base.join("workspace/repo");
        std::fs::create_dir_all(nested.join(".git")).unwrap();

        let roots = vec![base.to_path_buf()];
        let repos = roots
            .iter()
            .filter(|root| super::is_git_repository_root(root))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(roots, vec![base.to_path_buf()]);
        assert!(repos.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn expand_repo_roots_does_not_recurse_into_symlinked_directories() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("real/repo/.git")).unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();

        let (roots, repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();

        // The walker runs with follow_links(false), so a symlinked directory
        // is never turned into a repository root (even when it targets one);
        // the grouped root covers the link entry itself.
        assert!(roots.contains(&base.join("real/repo")));
        assert!(!roots.contains(&base.join("link")));
        assert!(!repos.contains(&base.join("link")));
        assert!(repos.contains(&base.join("real/repo")));
    }

    #[cfg(unix)]
    #[test]
    fn expand_repo_roots_skips_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        std::fs::create_dir_all(base.join("locked")).unwrap();
        std::fs::create_dir_all(base.join("open/repo/.git")).unwrap();
        std::fs::set_permissions(base.join("locked"), std::fs::Permissions::from_mode(0o000))
            .unwrap();

        // An unreadable descendant must not abort the pre-scan; the scanner's
        // own walker decides later whether to skip its contents, which the
        // grouped root covers.
        let (roots, _repos) = expand_repo_roots(&[base.to_path_buf()], None).unwrap();
        assert!(roots.contains(&base.join("open/repo")));
        assert!(roots.contains(&base.to_path_buf()));

        std::fs::set_permissions(base.join("locked"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    #[test]
    fn github_event_commit_selector_scans_commit_diff() {
        let sha = "0123456789abcdef0123456789abcdef01234567".to_string();

        let (branch, branch_root_commit) =
            git_refs_for_github_event_selector(&GitHubEventScanSelector::Commit(sha.clone()));

        assert_eq!(branch.as_deref(), Some(sha.as_str()));
        assert_eq!(branch_root_commit.as_deref(), Some(sha.as_str()));
    }

    #[test]
    fn github_event_branch_selector_scans_branch_tip() {
        let (branch, branch_root_commit) = git_refs_for_github_event_selector(
            &GitHubEventScanSelector::Branch("feature/secrets".to_string()),
        );

        assert_eq!(branch.as_deref(), Some("feature/secrets"));
        assert!(branch_root_commit.is_none());
    }

    #[test]
    fn github_event_repository_selector_uses_default_scan_scope() {
        let (branch, branch_root_commit) =
            git_refs_for_github_event_selector(&GitHubEventScanSelector::Repository);

        assert!(branch.is_none());
        assert!(branch_root_commit.is_none());
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
