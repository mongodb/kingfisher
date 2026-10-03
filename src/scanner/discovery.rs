//! Discover source-host repositories and stream fetched artifacts to scan workers.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use tracing::{debug, error};

use super::{
    NoScanInputsError, clone_or_update_git_repos_streaming, enumerate_azure_repos,
    enumerate_bitbucket_repos, enumerate_github_repos, enumerate_huggingface_repos,
    repos::{
        enumerate_gitea_repos, enumerate_gitlab_repos, fetch_confluence_pages,
        fetch_git_host_artifacts, fetch_jira_issues, fetch_postman_resources, fetch_slack_messages,
        fetch_teams_messages,
    },
    save_docker_archives, save_docker_images,
};
use crate::{
    azure, bitbucket,
    cli::{commands::scan, global},
    findings_store::FindingsStore,
    gitea, github, gitlab,
    scan_audit::SharedScanAudit,
    util::tokio_blocking_threads_limit,
};

async fn enumerate_all_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    github_event_targets: &[github::GitHubEventScanTarget],
    on_repo: &mut (dyn FnMut(crate::git_url::GitUrl) -> Result<()> + Send),
) -> Result<Vec<crate::git_url::GitUrl>> {
    let mut repo_urls = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut emit = |url: crate::git_url::GitUrl| -> Result<()> {
        let mut urls = vec![url.clone()];
        if args.input_specifier_args.repo_artifacts {
            urls.extend(
                [
                    github::wiki_url(&url),
                    gitlab::wiki_url(&url),
                    gitea::wiki_url(&url),
                    bitbucket::wiki_url(&url),
                    azure::wiki_url(&url),
                ]
                .into_iter()
                .flatten(),
            );
        }
        for url in urls {
            if seen.insert(url.clone()) {
                on_repo(url.clone())?;
                repo_urls.push(url);
            }
        }
        Ok(())
    };
    for url in &args.input_specifier_args.git_url {
        emit(url.clone())?;
    }
    for target in github_event_targets {
        emit(target.repo_url.clone())?;
    }
    enumerate_github_repos(args, global_args, &mut emit).await?;
    enumerate_gitlab_repos(args, global_args, &mut emit).await?;
    for url in enumerate_gitea_repos(args, global_args).await? {
        emit(url)?;
    }
    for url in enumerate_huggingface_repos(args, global_args).await? {
        emit(url)?;
    }
    for url in enumerate_bitbucket_repos(args, global_args).await? {
        emit(url)?;
    }
    for url in enumerate_azure_repos(args, global_args).await? {
        emit(url)?;
    }
    Ok(repo_urls)
}

pub(super) fn github_event_targets_by_root(
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

pub(super) fn scan_args_for_github_event_target(
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
pub(super) fn start_repo_cloning(
    repo_urls: crossbeam_channel::Receiver<crate::git_url::GitUrl>,
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<FindingsStore>>,
    audit: &SharedScanAudit,
    repo_tx: crossbeam_channel::Sender<PathBuf>,
) -> Option<std::thread::JoinHandle<()>> {
    let clone_args = args.clone();
    let clone_globals = global_args.clone();
    let clone_datastore = Arc::clone(datastore);
    let clone_audit = Arc::clone(audit);
    let clone_repo_tx = repo_tx.clone();

    // Tokio task-local policies do not cross native thread boundaries.
    let network_limits = kingfisher_scanner::validation::limits::NetworkLimits::current();
    let handle = std::thread::spawn(move || {
        network_limits.sync_scope(|| {
            if let Err(e) = clone_or_update_git_repos_streaming(
                &clone_args,
                &clone_globals,
                repo_urls,
                &clone_datastore,
                &clone_audit,
                |path| clone_repo_tx.send(path).is_ok(),
            ) {
                error!("Failed to fetch one or more Git repositories: {e}");
            }
        })
    });
    drop(repo_tx);
    Some(handle)
}

pub(super) struct ArtifactFetchHandle {
    thread: std::thread::JoinHandle<Result<()>>,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

impl ArtifactFetchHandle {
    pub(super) fn cancel(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
    }

    pub(super) fn join(self) -> std::thread::Result<Result<()>> {
        self.thread.join()
    }
}

/// Spawns a dedicated thread (with its own multi-threaded tokio runtime)
/// that discovers repositories into `url_tx`, then streams artifact directories
/// into `out_tx` as each fetch completes.
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
#[allow(clippy::too_many_arguments)]
pub(super) fn start_discovery_and_artifact_fetching(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    github_event_targets: Vec<github::GitHubEventScanTarget>,
    url_tx: crossbeam_channel::Sender<crate::git_url::GitUrl>,
    audit: &SharedScanAudit,
    has_huggingface_buckets: bool,
    datastore: &Arc<Mutex<FindingsStore>>,
    out_tx: crossbeam_channel::Sender<PathBuf>,
    progress_enabled: bool,
) -> ArtifactFetchHandle {
    let args = args.clone();
    let global_args = global_args.clone();
    let audit = Arc::clone(audit);
    let datastore = Arc::clone(datastore);
    let network_limits = kingfisher_scanner::validation::limits::NetworkLimits::current();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("artifact-fetcher".to_string())
        .spawn(move || -> Result<()> {
            let workers = args.num_jobs.max(1);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(workers)
                .max_blocking_threads(tokio_blocking_threads_limit(workers))
                .enable_all()
                .build()
                .context("Failed to build artifact-fetcher runtime")?;
            let work = network_limits.scope(async {
                let repo_urls =
                    enumerate_all_repos(&args, &global_args, &github_event_targets, &mut |url| {
                        audit.lock().unwrap().discover_remote(url.as_str());
                        url_tx.send(url).context("Repository cloning stopped during discovery")
                    })
                    .await?;
                drop(url_tx);
                let input = &args.input_specifier_args;
                if repo_urls.is_empty()
                    && input.path_inputs.is_empty()
                    && input.s3_bucket.is_none()
                    && input.gcs_bucket.is_none()
                    && !has_huggingface_buckets
                    && !input.has_artifact_sources()
                {
                    return Err(NoScanInputsError.into());
                }
                fetch_all_artifacts(
                    &args,
                    &global_args,
                    &repo_urls,
                    &datastore,
                    out_tx,
                    progress_enabled,
                )
                .await
            });
            let result = rt.block_on(async {
                tokio::select! {
                    biased;
                    result = work => result,
                    _ = cancel_rx => Err(anyhow::anyhow!("repository discovery or artifact fetching canceled")),
                }
            });
            if result.is_err() {
                audit.lock().unwrap().run_failed();
            }
            result
        })
        .expect("failed to spawn artifact-fetcher thread");
    ArtifactFetchHandle { thread, cancel: Some(cancel_tx) }
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
                args.content_filtering_args.resource_limits(),
            )
            .await?,
        );
        docker_dirs.extend(save_docker_archives(
            &args.input_specifier_args.docker_archive,
            &clone_root,
            progress_enabled,
            args.content_filtering_args.resource_limits(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{github::GitHubEventScanSelector, scan_audit::ScanAuditCollector};
    use clap::Parser;
    use tokio::time::Duration;

    #[tokio::test]
    async fn canceled_artifact_fetch_does_not_wait_for_provider_response() {
        use super::*;
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

        let server = MockServer::start().await;
        let received = Arc::new(tokio::sync::Notify::new());
        let observed = received.clone();
        Mock::given(path("/rest/api/content/search"))
            .respond_with(move |_: &wiremock::Request| {
                observed.notify_one();
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"results": [], "_links": {}}))
                    .set_delay(Duration::from_secs(30))
            })
            .mount(&server)
            .await;
        let command = crate::cli::CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            "confluence",
            "--url",
            &server.uri(),
            "--cql",
            "label = secret",
        ])
        .unwrap();
        let crate::cli::global::Command::Scan(scan) = command.command else { panic!() };
        let scan::ScanOperation::Scan(args) = scan.into_operation().unwrap() else { panic!() };
        let dir = tempfile::tempdir().unwrap();
        let datastore = Arc::new(Mutex::new(FindingsStore::new(dir.path().to_path_buf())));
        let audit = Arc::new(Mutex::new(
            ScanAuditCollector::new("2026-01-01T00:00:00Z".into(), None).unwrap(),
        ));
        let (url_tx, _url_rx) = crossbeam_channel::bounded(1);
        let (out_tx, _out_rx) = crossbeam_channel::bounded(1);
        temp_env::async_with_vars(
            [("KF_CONFLUENCE_TOKEN", Some("test-token")), ("KF_CONFLUENCE_USER", None)],
            async {
                let mut handle = start_discovery_and_artifact_fetching(
                    &args,
                    &command.global_args,
                    vec![],
                    url_tx,
                    &audit,
                    false,
                    &datastore,
                    out_tx,
                    false,
                );
                tokio::time::timeout(Duration::from_secs(5), received.notified()).await.unwrap();
                handle.cancel();
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    tokio::task::spawn_blocking(move || handle.join()),
                )
                .await
                .expect("cancellation must interrupt provider I/O")
                .unwrap()
                .unwrap();
                assert!(result.unwrap_err().to_string().contains("canceled"));
            },
        )
        .await;
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
}
