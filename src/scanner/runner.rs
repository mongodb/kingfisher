use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use crossbeam_skiplist::SkipMap;
use indicatif::ProgressBar;
use tokio::time::{Duration, Instant};
use tracing::{debug, error, error_span, info, trace};

use crate::{
    cli::{commands::scan, global},
    findings_store,
    findings_store::{FindingsStore, FindingsStoreMessage},
    liquid_filters::register_all,
    matcher::MatcherStats,
    reporter::styles::Styles,
    rule_loader::RuleLoader,
    rule_profiling::ConcurrentRuleProfiler,
    rules_database::RulesDatabase,
    scanner::{
        clone_or_update_git_repos, enumerate_filesystem_inputs, enumerate_github_repos,
        repos::enumerate_gitlab_repos, run_secret_validation, summary::print_scan_summary,
    },
};

pub async fn run_scan(
    global_args: &global::GlobalArgs,
    scan_args: &scan::ScanArgs,
    rules_db: &RulesDatabase,
    datastore: Arc<Mutex<FindingsStore>>,
) -> Result<()> {
    run_async_scan(global_args, scan_args, Arc::clone(&datastore), rules_db)
        .await
        .context("Failed to run scan command")
}

pub async fn run_async_scan(
    global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    datastore: Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
) -> Result<()> {
    // Ensure all provided paths exist before proceeding
    for path in &args.input_specifier_args.path_inputs {
        if !path.exists() {
            error!("Specified input path does not exist: {}", path.display());
            bail!("Invalid input: Path does not exist - {}", path.display());
        }
    }

    let start_time = Instant::now();

    trace!("Args:\n{global_args:#?}\n{args:#?}");
    let progress_enabled = global_args.use_progress();
    initialize_environment()?;

    let mut repo_urls = enumerate_github_repos(args, global_args).await?;
    let gitlab_repo_urls = enumerate_gitlab_repos(args, global_args).await?;

    // Combine repository URLs
    repo_urls.extend(gitlab_repo_urls);
    repo_urls.sort();
    repo_urls.dedup();

    let input_roots = clone_or_update_git_repos(args, global_args, &repo_urls, &datastore)?;
    if input_roots.is_empty() {
        bail!("No inputs to scan");
    }
    let shared_profiler = Arc::new(ConcurrentRuleProfiler::new());
    let enable_profiling = args.rule_stats;
    let matcher_stats = Mutex::new(MatcherStats::default());
    let _inputs = enumerate_filesystem_inputs(
        args,
        datastore.clone(),
        &input_roots,
        progress_enabled,
        rules_db,
        enable_profiling,
        shared_profiler,
        &matcher_stats,
    )?;

    if !args.no_dedup {
        // Final deduplication step before validation (or before reporting)
        let reporter = crate::reporter::DetailsReporter {
            datastore: Arc::clone(&datastore),
            styles: Styles::new(global_args.use_color(std::io::stdout())),
            only_valid: args.only_valid,
        };

        // Retrieve all matches, regardless of filtering, from the datastore
        let all_matches = reporter.get_unfiltered_matches(Some(false))?;
        // Deduplicate the matches using the reporter’s helper
        let deduped_matches = reporter.deduplicate_matches(all_matches, args.no_dedup);

        let deduped_arcs: Vec<Arc<FindingsStoreMessage>> = deduped_matches
            .into_iter()
            .map(|rm| Arc::new((Arc::new(rm.origin), Arc::new(rm.blob_metadata), rm.m)))
            .collect();
        let mut ds = datastore.lock().unwrap();
        ds.replace_matches(deduped_arcs);
    }

    // If validation is enabled, run it as a second phase
    if !args.no_validate {
        info!("Starting secret validation phase...");
        // Create validation dependencies
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(global_args.ignore_certs)
            .timeout(Duration::from_secs(30))
            .build()?;
        let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
        let cache = Arc::new(SkipMap::new());
        // Run validation
        run_secret_validation(Arc::clone(&datastore), &parser, &client, &cache, args.num_jobs)
            .await?;
    }
    // // Call cmd_report here
    crate::reporter::run(global_args, Arc::clone(&datastore), args)
        .context("Failed to run report command")?;
    print_scan_summary(start_time, &datastore, global_args, args, rules_db, &matcher_stats);
    Ok(())
}

fn initialize_environment() -> Result<()> {
    let init_progress = ProgressBar::new_spinner();
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
    // const BATCH_SIZE: usize = 256;
    // let channel_size = std::cmp::max(num_jobs * BATCH_SIZE, 4096);
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
) -> Result<RulesDatabase> {
    let init_progress = ProgressBar::new_spinner();
    // init_progress.set_message("Compiling rules...");
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
                    // rule.syntax.min_entropy = min_entropy;
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
