use std::{env, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use indicatif::{ProgressBar, ProgressStyle};
use octorust::{
    auth::Credentials,
    types::{Order, ReposListOrgSort, ReposListOrgType, ReposListUserType},
    Client,
};
use url::Url;

#[derive(Debug)]
pub struct RepoSpecifiers {
    pub user: Vec<String>,
    pub organization: Vec<String>,
    pub all_organizations: bool,
    pub repo_filter: RepoType,
}
impl RepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.organization.is_empty() && !self.all_organizations
    }
}
#[derive(Debug, Clone)]
pub enum RepoType {
    All,
    Source,
    Fork,
}
impl From<RepoType> for ReposListUserType {
    fn from(repo_type: RepoType) -> Self {
        match repo_type {
            RepoType::All => ReposListUserType::All,
            RepoType::Source => ReposListUserType::Owner,
            RepoType::Fork => ReposListUserType::Member,
        }
    }
}
impl From<RepoType> for ReposListOrgType {
    fn from(repo_type: RepoType) -> Self {
        match repo_type {
            RepoType::All => ReposListOrgType::All,
            RepoType::Source => ReposListOrgType::Sources,
            RepoType::Fork => ReposListOrgType::Forks,
        }
    }
}
fn create_github_client(github_url: &url::Url, ignore_certs: bool) -> Result<Arc<Client>> {
    // Try personal access token
    let credentials = if let Ok(token) = env::var("KF_GITHUB_TOKEN") {
        Credentials::Token(token)
    } else {
        Credentials::Token("".to_string()) // Anonymous access
    };

    let mut client_builder = reqwest::Client::builder();
    if ignore_certs {
        client_builder = client_builder.danger_accept_invalid_certs(ignore_certs);
    }

    let reqwest_client = client_builder.build().context("Failed to build HTTP client")?;

    let http_client = reqwest_middleware::ClientBuilder::new(reqwest_client).build();

    let mut client = Client::custom(
        concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION")),
        credentials,
        http_client,
    );

    // Override host if not using api.github.com
    if github_url.host_str() != Some("api.github.com") {
        client.with_host_override(github_url.as_str());
    }
    Ok(Arc::new(client))
}
pub async fn enumerate_repo_urls(
    repo_specifiers: &RepoSpecifiers,
    github_url: url::Url,
    ignore_certs: bool,
    mut progress: Option<&mut ProgressBar>,
) -> Result<Vec<String>> {
    let client = create_github_client(&github_url, ignore_certs)?;
    let mut repo_urls = Vec::new();
    let user_repo_type: ReposListUserType = repo_specifiers.repo_filter.clone().into();
    let org_repo_type: ReposListOrgType = repo_specifiers.repo_filter.clone().into();
    for username in &repo_specifiers.user {
        let repos = client
            .repos()
            .list_all_for_user(
                username,
                user_repo_type.clone(),
                ReposListOrgSort::Created,
                Order::Desc,
            )
            .await?;
        repo_urls.extend(repos.body.into_iter().filter_map(|repo| Some(repo.clone_url)));
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    let orgs = if repo_specifiers.all_organizations {
        let mut all_orgs = Vec::new();
        let org_list = client.orgs().list_all(100).await?;
        all_orgs.extend(org_list.body.into_iter().map(|org| org.login));
        all_orgs
    } else {
        repo_specifiers.organization.clone()
    };
    for org_name in orgs {
        let repos = client
            .repos()
            .list_all_for_org(
                &org_name,
                org_repo_type.clone(),
                ReposListOrgSort::Created,
                Order::Desc,
            )
            .await?;
        repo_urls.extend(repos.body.into_iter().filter_map(|repo| Some(repo.clone_url)));
        if let Some(progress) = progress.as_mut() {
            progress.inc(1);
        }
    }
    repo_urls.sort();
    repo_urls.dedup();
    Ok(repo_urls)
}
pub async fn list_repositories(
    api_url: Url,
    ignore_certs: bool,
    progress_enabled: bool,
    users: &[String],
    orgs: &[String],
    all_orgs: bool,
    repo_filter: RepoType,
) -> Result<()> {
    let repo_specifiers = RepoSpecifiers {
        user: users.to_vec(),
        organization: orgs.to_vec(),
        all_organizations: all_orgs,
        repo_filter,
    };
    // Create a progress bar just for displaying status
    // let mut progress = ProgressBar::new_spinner("Fetching repositories...",
    // true,);
    let mut progress = if progress_enabled {
        let style = ProgressStyle::with_template("{spinner} {msg} [{elapsed_precise}]")
            .expect("progress bar style template should compile");
        let pb = ProgressBar::new_spinner().with_style(style).with_message("Fetching repositories");
        pb.enable_steady_tick(Duration::from_millis(500));
        pb
    } else {
        ProgressBar::hidden()
    };
    let repo_urls =
        enumerate_repo_urls(&repo_specifiers, api_url, ignore_certs, Some(&mut progress)).await?;
    // Print repositories
    for url in repo_urls {
        println!("{}", url);
    }
    Ok(())
}
