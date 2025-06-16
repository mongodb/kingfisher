use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use indicatif::{HumanCount, ProgressBar, ProgressStyle};
use tokio::time::Duration;
use tracing::{debug, error, info};

use crate::{
    blob::BlobMetadata,
    cli::{
        commands::{
            github::{GitCloneMode, GitHistoryMode},
            scan,
        },
        global,
    },
    findings_store,
    git_binary::{CloneMode, Git},
    git_url::GitUrl,
    github, gitlab,
    matcher::Match,
    origin::OriginSet,
    PathBuf,
};
pub type DatastoreMessage = (OriginSet, BlobMetadata, Vec<(Option<f64>, Match)>);

pub fn clone_or_update_git_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
    repo_urls: &[GitUrl],
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
) -> Result<Vec<PathBuf>> {
    let mut input_roots = args.input_specifier_args.path_inputs.clone();
    if repo_urls.is_empty() || args.input_specifier_args.git_history == GitHistoryMode::None {
        return Ok(input_roots);
    }
    info!("{} Git URLs to fetch", repo_urls.len());
    for repo_url in repo_urls {
        debug!("Need to fetch {repo_url}")
    }
    let clone_mode = match args.input_specifier_args.git_clone {
        GitCloneMode::Mirror => CloneMode::Mirror,
        GitCloneMode::Bare => CloneMode::Bare,
    };
    let git = Git::new(global_args.ignore_certs);

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
    for repo_url in repo_urls {
        let output_dir = {
            let datastore = datastore.lock().unwrap();
            datastore.clone_destination(repo_url)
        };
        if output_dir.is_dir() {
            progress.suspend(|| info!("Updating clone of {repo_url}..."));
            match git.update_clone(repo_url, &output_dir) {
                Ok(()) => {
                    input_roots.push(output_dir);
                    progress.inc(1);
                    continue;
                }
                Err(e) => {
                    progress.suspend(|| {
                        debug!(
                            "Failed to update clone of {repo_url} at {}: {e}",
                            output_dir.display()
                        )
                    });
                    if let Err(e) = std::fs::remove_dir_all(&output_dir) {
                        progress.suspend(|| {
                            debug!(
                                "Failed to remove clone directory at {}: {e}",
                                output_dir.display()
                            )
                        });
                    }
                }
            }
        }
        progress.suspend(|| info!("Cloning {repo_url}..."));
        if let Err(e) = git.create_fresh_clone(repo_url, &output_dir, clone_mode) {
            progress.suspend(|| {
                error!("Failed to clone {repo_url} to {}: {e}", output_dir.display());
                debug!("Skipping scan of {repo_url}");
            });
            progress.inc(1);
            continue;
        }
        input_roots.push(output_dir);
        progress.inc(1);
    }
    progress.finish();
    Ok(input_roots)
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
    };
    let mut repo_urls = args.input_specifier_args.git_url.clone();
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
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}

pub async fn enumerate_gitlab_repos(
    args: &scan::ScanArgs,
    global_args: &global::GlobalArgs,
) -> Result<Vec<GitUrl>> {
    let repo_specifiers = gitlab::RepoSpecifiers {
        user: args.input_specifier_args.gitlab_user.clone(),
        group: args.input_specifier_args.gitlab_group.clone(),
        all_groups: args.input_specifier_args.all_gitlab_groups,
        repo_filter: args.input_specifier_args.gitlab_repo_type.into(),
    };

    let mut repo_urls = args.input_specifier_args.git_url.clone();
    if !repo_specifiers.is_empty() {
        let mut progress = if global_args.use_progress() {
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
            Some(&mut progress),
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
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}
