use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use crossbeam_channel;
use indicatif::{HumanCount, ProgressBar, ProgressStyle};
use rayon::ThreadPoolBuilder;
use tokio::time::Duration;
use tracing::{debug, error, info};
use url::Url;

use crate::blob::BlobIdMap;
use crate::{
    PathBuf, azure,
    binary::is_binary,
    bitbucket,
    blob::BlobMetadata,
    cli::{
        commands::{github::GitCloneMode, github::GitHistoryMode, scan},
        global,
    },
    confluence, findings_store, gcs,
    git_binary::{CloneMode, Git, ProviderHosts},
    git_url::GitUrl,
    gitea, github, gitlab, huggingface, jira,
    matcher::{Match, Matcher, MatcherStats},
    origin::{Origin, OriginSet},
    postman,
    rules_database::RulesDatabase,
    s3,
    scanner::processing::BlobProcessor,
    scanner_pool::ScannerPool,
    slack, teams,
};

pub type DatastoreMessage = (OriginSet, BlobMetadata, Vec<(Option<f64>, Match)>);

fn repo_host_contains(repo_url: &GitUrl, needle: &str) -> bool {
    Url::parse(repo_url.as_str())
        .ok()
        .and_then(|url| url.host_str().map(|host| host.to_lowercase()))
        .map(|host| host.contains(needle))
        .unwrap_or(false)
}

/// Map a configured API/base URL to the host `git clone` actually contacts,
/// including a non-default port. The SaaS API subdomains are folded back to
/// their public clone hosts; every other host (i.e. self-hosted/enterprise) is
/// already the clone host.
fn clone_host(url: &Url) -> Option<String> {
    let host = match url.host_str()?.to_ascii_lowercase().as_str() {
        "api.github.com" => "github.com".to_string(),
        "api.bitbucket.org" => "bitbucket.org".to_string(),
        other => other.to_string(),
    };
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// Parse an `--endpoint` URL (which may omit the scheme) and return its clone host.
fn endpoint_clone_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let url = Url::parse(trimmed).or_else(|_| Url::parse(&format!("https://{trimmed}"))).ok()?;
    clone_host(&url)
}

/// Derive the per-provider HTTPS hosts that credential helpers may target.
///
/// Starts from the public SaaS hosts and adds any host the user explicitly
/// configured for a provider via `--<provider>-api-url`, `--azure-base-url`, or
/// `--endpoint <provider>=URL`. Tokens are then offered only to these hosts,
/// never to an arbitrary (possibly attacker-controlled) scan target.
fn provider_hosts(args: &scan::ScanArgs, global_args: &global::GlobalArgs) -> ProviderHosts {
    let mut hosts = ProviderHosts::saas_defaults();
    let isa = &args.input_specifier_args;

    for (list, url) in [
        (&mut hosts.github, &isa.github_api_url),
        (&mut hosts.gitlab, &isa.gitlab_api_url),
        (&mut hosts.gitea, &isa.gitea_api_url),
        (&mut hosts.bitbucket, &isa.bitbucket_api_url),
        (&mut hosts.azure, &isa.azure_base_url),
    ] {
        if let Some(host) = clone_host(url) {
            ProviderHosts::add(list, &host);
        }
    }

    // `--endpoint PROVIDER=URL` only supports github/gitlab/gitea for git hosts.
    for entry in &global_args.endpoint {
        let Some((provider, url)) = entry.split_once('=') else {
            continue;
        };
        let Some(host) = endpoint_clone_host(url) else {
            continue;
        };
        match provider.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "github" => ProviderHosts::add(&mut hosts.github, &host),
            "gitlab" => ProviderHosts::add(&mut hosts.gitlab, &host),
            "gitea" => ProviderHosts::add(&mut hosts.gitea, &host),
            _ => {}
        }
    }

    hosts
}

fn apply_repo_clone_limit(
    repo_urls: &mut Vec<GitUrl>,
    limit: Option<usize>,
    predicate: impl Fn(&GitUrl) -> bool,
) {
    let Some(limit) = limit else {
        return;
    };
    let mut limited = Vec::new();
    let mut remaining = Vec::new();
    for url in repo_urls.drain(..) {
        if predicate(&url) {
            limited.push(url);
        } else {
            remaining.push(url);
        }
    }
    limited.sort();
    limited.dedup();
    if limited.len() > limit {
        limited.truncate(limit);
    }
    limited.extend(remaining);
    limited.sort();
    limited.dedup();
    *repo_urls = limited;
}

/// Run independent jobs on a bounded Rayon pool and stream successful results
/// back to the calling thread.
///
/// The receiver must stay outside a Rayon scope: Rayon executes a scope's
/// coordinator closure on a pool worker, so a coordinator that blocks on the
/// result channel deadlocks when the pool has exactly one worker.
fn stream_parallel_results<I, O, Items, Worker, Consumer>(
    num_threads: usize,
    items: Items,
    worker: Worker,
    mut consume: Consumer,
) -> Result<()>
where
    I: Send + 'static,
    O: Send + 'static,
    Items: IntoIterator<Item = I>,
    Worker: Fn(I) -> Option<O> + Send + Sync + 'static,
    Consumer: FnMut(O),
{
    let num_threads = num_threads.max(1);
    let pool = ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .context("Failed to build git clone thread pool")?;
    let (result_tx, result_rx) = crossbeam_channel::bounded(std::cmp::max(2, num_threads * 2));
    let worker = Arc::new(worker);

    for item in items {
        let result_tx = result_tx.clone();
        let worker = Arc::clone(&worker);
        pool.spawn(move || {
            if let Some(result) = worker(item) {
                let _ = result_tx.send(result);
            }
        });
    }
    drop(result_tx);

    for result in result_rx {
        consume(result);
    }

    Ok(())
}

pub fn clone_or_update_git_repos_streaming<F>(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    repo_urls: &[GitUrl],
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    mut on_repo_ready: F,
) -> Result<()>
where
    F: FnMut(PathBuf) + Send,
{
    if repo_urls.is_empty() {
        return Ok(());
    }

    info!("{} Git URLs to fetch", repo_urls.len());
    for repo_url in repo_urls {
        debug!("Need to fetch {repo_url}")
    }

    let clone_mode = if args.input_specifier_args.git_history == GitHistoryMode::None {
        CloneMode::Checkout
    } else {
        match args.input_specifier_args.git_clone {
            GitCloneMode::Mirror => CloneMode::Mirror,
            GitCloneMode::Bare => CloneMode::Bare,
        }
    };

    let progress = if global_args.use_progress() {
        let style = ProgressStyle::with_template(
            "{msg} {bar} {percent:>3}% {pos}/{len} [{elapsed_precise}]",
        )
        .expect("progress bar style template should compile");
        let pb = ProgressBar::new(repo_urls.len() as u64)
            .with_style(style)
            .with_message("Fetching Git repos");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let clone_concurrency = std::cmp::max(1, args.num_jobs);
    let ignore_certs = global_args.ignore_certs;
    let provider_hosts = provider_hosts(args, global_args);
    let datastore = Arc::clone(datastore);
    let worker_progress = progress.clone();

    // The helper's bounded result channel prevents cloners from racing ahead
    // of the scanner and filling the clone directory with completed work.
    stream_parallel_results(
        clone_concurrency,
        repo_urls.iter().cloned(),
        move |repo_url| {
            let git = Git::with_provider_hosts(ignore_certs, &provider_hosts);
            let output_dir = {
                let datastore = datastore.lock().unwrap();
                datastore.clone_destination(&repo_url)
            };

            if output_dir.is_dir() {
                worker_progress.suspend(|| info!("Updating clone of {repo_url}..."));
                match git.update_clone(&repo_url, &output_dir) {
                    Ok(()) => {
                        {
                            let mut ds = datastore.lock().unwrap();
                            ds.register_repo_link(output_dir.clone(), repo_url.to_string());
                        }
                        worker_progress.inc(1);
                        return Some(output_dir);
                    }
                    Err(e) => {
                        worker_progress.suspend(|| {
                            debug!(
                                "Failed to update clone of {repo_url} at {}: {e}",
                                output_dir.display()
                            )
                        });
                        if let Err(e) = std::fs::remove_dir_all(&output_dir) {
                            worker_progress.suspend(|| {
                                debug!(
                                    "Failed to remove clone directory at {}: {e}",
                                    output_dir.display()
                                )
                            });
                        }
                    }
                }
            }

            worker_progress.suspend(|| info!("Cloning {repo_url}..."));
            if let Err(e) = git.create_fresh_clone(&repo_url, &output_dir, clone_mode) {
                worker_progress.suspend(|| {
                    if repo_url.as_str().ends_with(".wiki.git") {
                        info!("Wiki repository not found for {repo_url}, skipping");
                        debug!("Failed to clone {repo_url} to {}: {e}", output_dir.display());
                    } else {
                        error!("Failed to clone {repo_url} to {}: {e}", output_dir.display());
                    }
                    debug!("Skipping scan of {repo_url}");
                });
                worker_progress.inc(1);
                return None;
            }

            {
                let mut ds = datastore.lock().unwrap();
                ds.register_repo_link(output_dir.clone(), repo_url.to_string());
            }

            worker_progress.inc(1);
            Some(output_dir)
        },
        &mut on_repo_ready,
    )?;

    progress.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, thread, time::Duration};

    use super::stream_parallel_results;

    #[test]
    fn streaming_pool_makes_progress_with_one_worker() {
        let (done_tx, done_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut streamed = Vec::new();
            let result = stream_parallel_results(
                1,
                0..4,
                |value| Some(value * 2),
                |value| streamed.push(value),
            );
            done_tx.send((result, streamed)).expect("test receiver should remain open");
        });

        let (result, mut streamed) = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("one-worker streaming pool should not deadlock");
        result.expect("streaming jobs should succeed");
        streamed.sort_unstable();
        assert_eq!(streamed, vec![0, 2, 4, 6]);
        handle.join().expect("streaming thread should not panic");
    }
}

pub async fn enumerate_github_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = github::RepoSpecifiers {
        user: args.input_specifier_args.github_user.clone(),
        organization: args.input_specifier_args.github_organization.clone(),
        all_organizations: args.input_specifier_args.all_github_organizations,
        repo_filter: args.input_specifier_args.github_repo_type.into(),
        exclude_repos: args.input_specifier_args.github_exclude.clone(),
    };
    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if args.input_specifier_args.include_contributors {
        for repo_url in &args.input_specifier_args.git_url {
            if !repo_host_contains(repo_url, "github") {
                continue;
            }
            match github::enumerate_contributor_repo_urls(
                repo_url,
                &args.input_specifier_args.github_api_url,
                global_args.ignore_certs,
                &args.input_specifier_args.github_exclude,
                args.input_specifier_args.repo_clone_limit,
                global_args.use_progress(),
                args.input_specifier_args.github_repo_type.into(),
            )
            .await
            {
                Ok(contributor_urls) => {
                    for repo_string in contributor_urls {
                        match GitUrl::from_str(&repo_string) {
                            Ok(repo_url) => repo_urls.push(repo_url),
                            Err(e) => {
                                error!(
                                    "Failed to parse contributor repo URL from {repo_string}: {e}"
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    error!(
                        "Failed to enumerate GitHub contributor repositories for {repo_url}: {err}"
                    );
                }
            }
        }
    }
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating GitHub repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };
        let mut num_found: u64 = 0;
        let api_url = args.input_specifier_args.github_api_url.clone();
        let repo_strings = github::enumerate_repo_urls(
            &repo_specifiers,
            api_url,
            global_args.ignore_certs,
            Some(&mut progress),
        )
        .await
        .context("Failed to enumerate GitHub repositories")?;
        for repo_string in repo_strings {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }
        progress.finish_with_message(format!(
            "Found {} repositories from GitHub",
            HumanCount(num_found)
        ));
    }
    apply_repo_clone_limit(&mut repo_urls, args.input_specifier_args.repo_clone_limit, |url| {
        repo_host_contains(url, "github")
    });
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn enumerate_github_event_targets(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<github::GitHubEventScanTarget>> {
    let users = &args.input_specifier_args.github_event_user;
    if users.is_empty() {
        return Ok(Vec::new());
    }

    let mut progress = if global_args.use_progress() {
        let style = ProgressStyle::with_template("{spinner} {msg} {pos}/{len} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new(users.len() as u64)
            .with_style(style)
            .with_message("Enumerating GitHub public events...");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let targets = github::enumerate_public_event_targets(
        users,
        args.input_specifier_args.github_event_lookback_hours,
        args.input_specifier_args.github_api_url.clone(),
        global_args.ignore_certs,
        &args.input_specifier_args.github_exclude,
        args.input_specifier_args.repo_clone_limit,
        Some(&mut progress),
    )
    .await
    .context("Failed to enumerate GitHub public events")?;

    progress.finish_with_message(format!(
        "Found {} GitHub public event scan targets",
        HumanCount(targets.len() as u64)
    ));
    Ok(targets)
}

pub async fn enumerate_gitlab_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = gitlab::RepoSpecifiers {
        user: args.input_specifier_args.gitlab_user.clone(),
        group: args.input_specifier_args.gitlab_group.clone(),
        all_groups: args.input_specifier_args.all_gitlab_groups,
        include_subgroups: args.input_specifier_args.gitlab_include_subgroups,
        repo_filter: args.input_specifier_args.gitlab_repo_type.into(),
        exclude_repos: args.input_specifier_args.gitlab_exclude.clone(),
    };

    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if args.input_specifier_args.include_contributors {
        for repo_url in &args.input_specifier_args.git_url {
            if !repo_host_contains(repo_url, "gitlab") {
                continue;
            }
            match gitlab::enumerate_contributor_repo_urls(
                repo_url,
                &args.input_specifier_args.gitlab_api_url,
                global_args.ignore_certs,
                &args.input_specifier_args.gitlab_exclude,
                args.input_specifier_args.repo_clone_limit,
                global_args.use_progress(),
            )
            .await
            {
                Ok(contributor_urls) => {
                    for repo_string in contributor_urls {
                        match GitUrl::from_str(&repo_string) {
                            Ok(repo_url) => repo_urls.push(repo_url),
                            Err(e) => {
                                error!(
                                    "Failed to parse contributor repo URL from {repo_string}: {e}"
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    error!(
                        "Failed to enumerate GitLab contributor repositories for {repo_url}: {err}"
                    );
                }
            }
        }
    }
    if !repo_specifiers.is_empty() {
        let progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating GitLab repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };

        let mut num_found: u64 = 0;
        let api_url = args.input_specifier_args.gitlab_api_url.clone();
        let gitlab_repos = gitlab::enumerate_repo_urls(
            &repo_specifiers,
            api_url,
            global_args.ignore_certs,
            Some(progress.clone()),
        )
        .await
        .context("Failed to enumerate GitLab repositories")?;

        for repo_string in gitlab_repos {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }

        progress.finish_with_message(format!(
            "Found {} repositories from GitLab",
            HumanCount(num_found)
        ));
    }
    apply_repo_clone_limit(&mut repo_urls, args.input_specifier_args.repo_clone_limit, |url| {
        repo_host_contains(url, "gitlab")
    });
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn enumerate_gitea_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = gitea::RepoSpecifiers {
        user: args.input_specifier_args.gitea_user.clone(),
        organization: args.input_specifier_args.gitea_organization.clone(),
        all_organizations: args.input_specifier_args.all_gitea_organizations,
        repo_filter: args.input_specifier_args.gitea_repo_type.into(),
        exclude_repos: args.input_specifier_args.gitea_exclude.clone(),
    };

    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating Gitea repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };

        let mut num_found: u64 = 0;
        let api_url = args.input_specifier_args.gitea_api_url.clone();
        let repo_strings = gitea::enumerate_repo_urls(
            &repo_specifiers,
            api_url,
            global_args.ignore_certs,
            Some(&mut progress),
        )
        .await
        .context("Failed to enumerate Gitea repositories")?;

        for repo_string in repo_strings {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }

        progress.finish_with_message(format!(
            "Found {} repositories from Gitea",
            HumanCount(num_found)
        ));
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn enumerate_huggingface_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = huggingface_specifiers(args);

    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating Hugging Face repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };

        let mut num_found: u64 = 0;
        let auth = huggingface::AuthConfig::from_env();
        let repo_strings = huggingface::enumerate_repo_urls(
            &repo_specifiers,
            &auth,
            global_args.ignore_certs,
            Some(&mut progress),
        )
        .await
        .context("Failed to enumerate Hugging Face repositories")?;

        for repo_string in repo_strings {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }

        progress.finish_with_message(format!(
            "Found {} repositories from Hugging Face",
            HumanCount(num_found)
        ));
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

fn huggingface_specifiers(args: &scan::ScanArgs) -> huggingface::RepoSpecifiers {
    huggingface::RepoSpecifiers {
        user: args.input_specifier_args.huggingface_user.clone(),
        organization: args.input_specifier_args.huggingface_organization.clone(),
        model: args.input_specifier_args.huggingface_model.clone(),
        dataset: args.input_specifier_args.huggingface_dataset.clone(),
        space: args.input_specifier_args.huggingface_space.clone(),
        bucket: args.input_specifier_args.huggingface_bucket.clone(),
        exclude: args.input_specifier_args.huggingface_exclude.clone(),
    }
}

pub async fn enumerate_huggingface_buckets(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<huggingface::BucketTarget>> {
    let specifiers = huggingface_specifiers(args);
    if specifiers.user.is_empty()
        && specifiers.organization.is_empty()
        && specifiers.bucket.is_empty()
    {
        return Ok(Vec::new());
    }

    let mut progress = if global_args.use_progress() {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Enumerating Hugging Face buckets...");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let auth = huggingface::AuthConfig::from_env();
    let buckets = huggingface::enumerate_bucket_targets(
        &specifiers,
        &auth,
        global_args.ignore_certs,
        Some(&mut progress),
    )
    .await
    .context("Failed to enumerate Hugging Face buckets")?;

    progress.finish_with_message(format!(
        "Found {} buckets from Hugging Face",
        HumanCount(buckets.len() as u64)
    ));
    Ok(buckets)
}

pub async fn enumerate_bitbucket_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = bitbucket::RepoSpecifiers {
        user: args.input_specifier_args.bitbucket_user.clone(),
        workspace: args.input_specifier_args.bitbucket_workspace.clone(),
        project: args.input_specifier_args.bitbucket_project.clone(),
        all_workspaces: args.input_specifier_args.all_bitbucket_workspaces,
        repo_filter: args.input_specifier_args.bitbucket_repo_type.into(),
        exclude_repos: args.input_specifier_args.bitbucket_exclude.clone(),
    };
    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating Bitbucket repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };
        let mut num_found: u64 = 0;
        let api_url = args.input_specifier_args.bitbucket_api_url.clone();
        let auth = bitbucket::AuthConfig::from_env();
        let repo_strings = bitbucket::enumerate_repo_urls(
            &repo_specifiers,
            api_url,
            &auth,
            global_args.ignore_certs,
            Some(&mut progress),
        )
        .await
        .context("Failed to enumerate Bitbucket repositories")?;
        for repo_string in repo_strings {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }
        progress.finish_with_message(format!(
            "Found {} repositories from Bitbucket",
            HumanCount(num_found)
        ));
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn enumerate_azure_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = azure::RepoSpecifiers {
        organization: args.input_specifier_args.azure_organization.clone(),
        project: args.input_specifier_args.azure_project.clone(),
        all_projects: args.input_specifier_args.all_azure_projects,
        repo_filter: args.input_specifier_args.azure_repo_type.into(),
        exclude_repos: args.input_specifier_args.azure_exclude.clone(),
    };

    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
            let style =
                ProgressStyle::with_template("{spinner} {msg} {human_len} [{elapsed_precise}]")
                    .expect("progress bar style template should compile");
            let pb = ProgressBar::new_spinner()
                .with_style(style)
                .with_message("Enumerating Azure Repos repositories...");
            pb.enable_steady_tick(Duration::from_millis(500));
            pb
        } else {
            ProgressBar::hidden()
        };

        let mut num_found: u64 = 0;
        let base_url = args.input_specifier_args.azure_base_url.clone();
        let repo_strings = azure::enumerate_repo_urls(
            &repo_specifiers,
            base_url,
            global_args.ignore_certs,
            Some(&mut progress),
        )
        .await
        .context("Failed to enumerate Azure repositories")?;

        for repo_string in repo_strings {
            match GitUrl::from_str(&repo_string) {
                Ok(repo_url) => {
                    repo_urls.push(repo_url);
                    num_found += 1;
                }
                Err(e) => {
                    progress.suspend(|| {
                        error!("Failed to parse repo URL from {repo_string}: {e}");
                    });
                }
            }
        }

        progress.finish_with_message(format!(
            "Found {} repositories from Azure Repos",
            HumanCount(num_found)
        ));
    }

    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn fetch_jira_issues(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let Some(jira_url) = args.input_specifier_args.jira_url.clone() else {
        return Ok(Vec::new());
    };
    let Some(jql) = args.input_specifier_args.jql.as_deref() else {
        return Ok(Vec::new());
    };
    let max_results = args.input_specifier_args.max_results;
    let output_dir = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let output_dir = output_dir.join("jira_issues");
    let _paths = jira::download_issues_to_dir(
        &jira_url,
        jql,
        max_results,
        global_args.ignore_certs,
        &output_dir,
        jira::DownloadIssueArtifactsOptions {
            include_comments: args.input_specifier_args.jira_include_comments,
            include_changelog: args.input_specifier_args.jira_include_changelog,
        },
    )
    .await?;
    Ok(vec![output_dir])
}

pub async fn fetch_confluence_pages(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let Some(confluence_url) = args.input_specifier_args.confluence_url.clone() else {
        return Ok(Vec::new());
    };
    let Some(cql) = args.input_specifier_args.cql.as_deref() else {
        return Ok(Vec::new());
    };
    let max_results = args.input_specifier_args.max_results;
    let output_root = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let output_dir = output_root.join("confluence_pages");
    let paths = confluence::download_pages_to_dir(
        confluence_url,
        cql,
        max_results,
        global_args.ignore_certs,
        &output_dir,
    )
    .await?;
    {
        let mut ds = datastore.lock().unwrap();
        for (path, link) in &paths {
            ds.register_confluence_page(path.clone(), link.clone());
        }
    }
    Ok(vec![output_dir])
}

pub async fn fetch_slack_messages(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let Some(query) = args.input_specifier_args.slack_query.as_deref() else {
        return Ok(Vec::new());
    };
    let api_url = args.input_specifier_args.slack_api_url.clone();
    let max_results = args.input_specifier_args.max_results;
    let output_root = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let message_output_dir = output_root.join("slack_messages");
    let message_paths = slack::download_messages_to_dir(
        api_url.clone(),
        query,
        max_results,
        global_args.ignore_certs,
        &message_output_dir,
    )
    .await?;
    let file_output_dir = output_root.join("slack_files");
    let file_paths = slack::download_files_to_dir(
        api_url,
        query,
        max_results,
        global_args.ignore_certs,
        &file_output_dir,
        args.content_filtering_args.max_file_size_bytes(),
    )
    .await?;
    {
        let mut ds = datastore.lock().unwrap();
        for (path, link) in message_paths.iter().chain(&file_paths) {
            ds.register_slack_message(path.clone(), link.clone());
        }
    }
    Ok(vec![message_output_dir, file_output_dir])
}

pub async fn fetch_postman_resources(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let selectors = postman::PostmanSelectors {
        workspaces: args.input_specifier_args.postman_workspaces.clone(),
        collections: args.input_specifier_args.postman_collections.clone(),
        environments: args.input_specifier_args.postman_environments.clone(),
        all: args.input_specifier_args.postman_all,
        include_mocks_monitors: args.input_specifier_args.postman_include_mocks_monitors,
    };
    if selectors.is_empty() {
        return Ok(Vec::new());
    }
    let api_url = args.input_specifier_args.postman_api_url.clone();
    let max_results = args.input_specifier_args.max_results;
    let output_root = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let output_dir = output_root.join("postman");
    let paths = postman::download_postman_to_dir(
        api_url,
        selectors,
        max_results,
        global_args.ignore_certs,
        &output_dir,
    )
    .await?;
    {
        let mut ds = datastore.lock().unwrap();
        for (path, link) in &paths {
            ds.register_postman_resource(path.clone(), link.clone());
        }
    }
    Ok(vec![output_dir])
}

pub async fn fetch_teams_messages(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let Some(query) = args.input_specifier_args.teams_query.as_deref() else {
        return Ok(Vec::new());
    };
    let api_url = args.input_specifier_args.teams_api_url.clone();
    let max_results = args.input_specifier_args.max_results;
    let output_root = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let output_dir = output_root.join("teams_messages");
    let paths = teams::download_messages_to_dir(
        api_url,
        query,
        max_results,
        global_args.ignore_certs,
        &output_dir,
    )
    .await?;
    {
        let mut ds = datastore.lock().unwrap();
        for (path, link) in &paths {
            ds.register_teams_message(path.clone(), link.clone());
        }
    }
    Ok(vec![output_dir])
}

/// Streams per-repo artifact directories (issues/PRs/wikis) into `out_tx`
/// as soon as each one is fetched, rather than collecting all results before
/// returning. This lets the scan loop start consuming artifact dirs while
/// remote fetches for other repos are still in flight.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_git_host_artifacts(
    repo_urls: &[GitUrl],
    bitbucket_api_url: &Url,
    bitbucket_auth: &bitbucket::AuthConfig,
    bitbucket_host: Option<String>,
    global_args: &global::GlobalArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    concurrency: usize,
    out_tx: crossbeam_channel::Sender<PathBuf>,
) -> Result<()> {
    use futures::stream::{self, StreamExt};

    let output_root = {
        let ds = datastore.lock().unwrap();
        ds.clone_root()
    };
    let concurrency = std::cmp::max(1, concurrency);

    // Fan out per-repo artifact fetches concurrently. Each completed fetch
    // pushes its dirs into `out_tx` immediately so the scanner can pick them
    // up while the remaining fetches are still running.
    let mut stream = stream::iter(repo_urls.iter().cloned())
        .map(|repo_url| {
            let bitbucket_api_url = bitbucket_api_url.clone();
            let bitbucket_auth = bitbucket_auth.clone();
            let bitbucket_host = bitbucket_host.clone();
            let output_root = output_root.clone();
            let datastore = Arc::clone(datastore);
            let ignore_certs = global_args.ignore_certs;
            async move {
                let host = Url::parse(repo_url.as_str())
                    .ok()
                    .and_then(|u| u.host_str().map(|s| s.to_string()))
                    .unwrap_or_default();
                if host.contains("github") {
                    github::fetch_repo_items(&repo_url, ignore_certs, &output_root, &datastore)
                        .await
                } else if host.contains("gitlab") {
                    gitlab::fetch_repo_items(&repo_url, ignore_certs, &output_root, &datastore)
                        .await
                } else if host.contains("bitbucket")
                    || bitbucket_host
                        .as_deref()
                        .map(|expected| expected.eq_ignore_ascii_case(&host))
                        .unwrap_or(false)
                {
                    bitbucket::fetch_repo_items(
                        &repo_url,
                        &bitbucket_api_url,
                        &bitbucket_auth,
                        ignore_certs,
                        &output_root,
                        &datastore,
                    )
                    .await
                } else if host.contains("dev.azure") || host.contains("visualstudio.com") {
                    azure::fetch_repo_items(&repo_url, ignore_certs, &output_root, &datastore).await
                } else {
                    Ok(Vec::new())
                }
            }
        })
        .buffer_unordered(concurrency);

    while let Some(result) = stream.next().await {
        let dirs = result?;
        for d in dirs {
            // Send may block if the bounded channel is full; that's the
            // intended backpressure. Errors only occur if the receiver has
            // been dropped (scan aborted), in which case we stop producing.
            if out_tx.send(d).is_err() {
                debug!("scan channel closed; stopping git-host artifact fetcher");
                return Ok(());
            }
        }
    }
    Ok(())
}

pub async fn fetch_s3_objects(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    matcher_stats: &Mutex<MatcherStats>,
    enable_profiling: bool,
    shared_profiler: Arc<crate::rule_profiling::ConcurrentRuleProfiler>,
    progress_enabled: bool,
) -> Result<()> {
    let Some(bucket) = args.input_specifier_args.s3_bucket.as_deref() else {
        return Ok(());
    };
    let prefix = args.input_specifier_args.s3_prefix.as_deref();
    let role_arn = args.input_specifier_args.role_arn.as_deref();
    let profile = args.input_specifier_args.aws_local_profile.as_deref();

    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
    let seen_blobs = BlobIdMap::new();
    let matcher = Matcher::new(
        rules_db,
        scanner_pool,
        &seen_blobs,
        Some(matcher_stats),
        enable_profiling,
        if enable_profiling { Some(shared_profiler.clone()) } else { None },
        &args.extra_ignore_comments,
        args.no_inline_ignore,
        !args.no_ignore_if_contains,
    )?;
    let mut processor = BlobProcessor { matcher };

    let progress = if progress_enabled {
        let style =
            ProgressStyle::with_template("{spinner} {msg} ({pos} objects) [{elapsed_precise}]")
                .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching S3 objects");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let pb = progress.clone();

    let bucket_name = bucket.to_string();

    s3::visit_bucket_objects(bucket, prefix, role_arn, profile, move |key, bytes| {
        let origin = OriginSet::new(
            Origin::from_extended(serde_json::json!({
                "path": format!("s3://{}/{}", bucket_name, key)
            })),
            Vec::new(),
        );
        let blob = crate::blob::Blob::from_bytes(bytes);

        if let Some((origin, blob_md, scored_matches)) =
            processor.run(origin, blob, args.no_dedup, args.redact, args.no_base64, args.turbo)?
        {
            // Wrap origin & metadata once:
            let origin_arc = Arc::new(origin);
            let blob_arc = Arc::new(blob_md);

            // Now build a batch of exactly one FindingsStoreMessage per Match
            let mut batch = Vec::with_capacity(scored_matches.len());
            for (_score, m) in scored_matches {
                batch.push((origin_arc.clone(), blob_arc.clone(), m));
            }

            // Call record with the right type
            let added = datastore.lock().unwrap().record(batch, !args.no_dedup);
            debug!("Added {} new S3 blobs", added);
        }
        pb.inc(1);
        Ok(())
    })
    .await?;

    let total = progress.position();
    progress.finish_with_message(format!("Fetched {} S3 objects", total));

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn fetch_huggingface_objects(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    buckets: &[huggingface::BucketTarget],
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    matcher_stats: &Mutex<MatcherStats>,
    enable_profiling: bool,
    shared_profiler: Arc<crate::rule_profiling::ConcurrentRuleProfiler>,
    progress_enabled: bool,
) -> Result<()> {
    if buckets.is_empty() {
        return Ok(());
    }

    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
    let seen_blobs = BlobIdMap::new();
    let matcher = Matcher::new(
        rules_db,
        scanner_pool,
        &seen_blobs,
        Some(matcher_stats),
        enable_profiling,
        if enable_profiling { Some(shared_profiler.clone()) } else { None },
        &args.extra_ignore_comments,
        args.no_inline_ignore,
        !args.no_ignore_if_contains,
    )?;
    let mut processor = BlobProcessor { matcher };

    let progress = if progress_enabled {
        let style =
            ProgressStyle::with_template("{spinner} {msg} ({pos} objects) [{elapsed_precise}]")
                .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner()
            .with_style(style)
            .with_message("Fetching Hugging Face bucket objects");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let pb = progress.clone();
    let auth = huggingface::AuthConfig::from_env();

    huggingface::visit_bucket_objects(
        buckets,
        &auth,
        global_args.ignore_certs,
        args.content_filtering_args.max_file_size_bytes(),
        &args.content_filtering_args.exclude,
        move |bucket, key, bytes| {
            pb.inc(1);
            if args.content_filtering_args.no_binary && is_binary(&bytes) {
                debug!("Skipping binary Hugging Face bucket object {}/{}", bucket.bucket_id(), key);
                return Ok(());
            }

            let origin = OriginSet::new(
                Origin::from_extended(serde_json::json!({
                    "path": bucket.object_uri(&key)
                })),
                Vec::new(),
            );
            let blob = crate::blob::Blob::from_bytes(bytes);

            if let Some((origin, blob_md, scored_matches)) = processor.run(
                origin,
                blob,
                args.no_dedup,
                args.redact,
                args.no_base64,
                args.turbo,
            )? {
                let origin_arc = Arc::new(origin);
                let blob_arc = Arc::new(blob_md);
                let mut batch = Vec::with_capacity(scored_matches.len());
                for (_score, m) in scored_matches {
                    batch.push((origin_arc.clone(), blob_arc.clone(), m));
                }

                let added = datastore.lock().unwrap().record(batch, !args.no_dedup);
                debug!("Added {} new Hugging Face bucket blobs", added);
            }
            Ok(())
        },
    )
    .await?;

    let total = progress.position();
    progress.finish_with_message(format!("Fetched {} Hugging Face bucket objects", total));
    Ok(())
}

pub async fn fetch_gcs_objects(
    args: &scan::ScanArgs,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    rules_db: &RulesDatabase,
    matcher_stats: &Mutex<MatcherStats>,
    enable_profiling: bool,
    shared_profiler: Arc<crate::rule_profiling::ConcurrentRuleProfiler>,
    progress_enabled: bool,
) -> Result<()> {
    let Some(bucket) = args.input_specifier_args.gcs_bucket.as_deref() else {
        return Ok(());
    };
    let prefix = args.input_specifier_args.gcs_prefix.as_deref();
    let service_account = args.input_specifier_args.gcs_service_account.as_deref();

    let scanner_pool = Arc::new(ScannerPool::new(Arc::new(rules_db.vectorscan_db().clone())));
    let seen_blobs = BlobIdMap::new();
    let matcher = Matcher::new(
        rules_db,
        scanner_pool,
        &seen_blobs,
        Some(matcher_stats),
        enable_profiling,
        if enable_profiling { Some(shared_profiler.clone()) } else { None },
        &args.extra_ignore_comments,
        args.no_inline_ignore,
        !args.no_ignore_if_contains,
    )?;
    let mut processor = BlobProcessor { matcher };

    let progress = if progress_enabled {
        let style =
            ProgressStyle::with_template("{spinner} {msg} ({pos} objects) [{elapsed_precise}]")
                .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching GCS objects");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };

    let pb = progress.clone();

    let bucket_name = bucket.to_string();

    gcs::visit_bucket_objects(bucket, prefix, service_account, move |key, bytes| {
        let origin = OriginSet::new(
            Origin::from_extended(serde_json::json!({
                "path": format!("gs://{}/{}", bucket_name, key)
            })),
            Vec::new(),
        );
        let blob = crate::blob::Blob::from_bytes(bytes);

        if let Some((origin, blob_md, scored_matches)) =
            processor.run(origin, blob, args.no_dedup, args.redact, args.no_base64, args.turbo)?
        {
            let origin_arc = Arc::new(origin);
            let blob_arc = Arc::new(blob_md);

            let mut batch = Vec::with_capacity(scored_matches.len());
            for (_score, m) in scored_matches {
                batch.push((origin_arc.clone(), blob_arc.clone(), m));
            }

            let added = datastore.lock().unwrap().record(batch, !args.no_dedup);
            debug!("Added {} new GCS blobs", added);
        }
        pb.inc(1);
        Ok(())
    })
    .await?;

    let total = progress.position();
    progress.finish_with_message(format!("Fetched {} GCS objects", total));

    Ok(())
}
