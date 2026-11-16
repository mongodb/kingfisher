use clap::{Args, Subcommand, ValueEnum, ValueHint};
use url::Url;

use crate::cli::commands::output::OutputArgs;

use super::github::GitHubOutputFormat;

/// Top-level Gitea command group
#[derive(Args, Debug)]
pub struct GiteaArgs {
    #[command(subcommand)]
    pub command: GiteaCommand,

    /// Override Gitea API URL (e.g. self-hosted)
    #[arg(global = true, long, default_value = "https://gitea.com/api/v1/", value_hint = ValueHint::Url)]
    pub gitea_api_url: Url,
}

#[derive(Subcommand, Debug)]
pub enum GiteaCommand {
    /// Interact with Gitea repositories
    #[command(subcommand)]
    Repos(GiteaReposCommand),
}

#[derive(Subcommand, Debug)]
pub enum GiteaReposCommand {
    /// List repositories for a user or organization
    List(GiteaReposListArgs),
}

/// `kingfisher gitea repos`
#[derive(Args, Debug, Clone)]
pub struct GiteaReposListArgs {
    #[command(flatten)]
    pub repo_specifiers: GiteaRepoSpecifiers,

    #[command(flatten)]
    pub output_args: OutputArgs<GiteaOutputFormat>,
}

/// Options for selecting Gitea repos
#[derive(Args, Debug, Clone)]
pub struct GiteaRepoSpecifiers {
    /// Repositories belonging to these users
    #[arg(long, alias = "gitea-user")]
    pub user: Vec<String>,

    /// Repositories belonging to these organizations
    #[arg(long, alias = "org", alias = "gitea-organization", alias = "gitea-org")]
    pub organization: Vec<String>,

    /// Skip repositories when enumerating Gitea users or organizations (format: owner/repo)
    #[arg(long = "gitea-exclude", alias = "gitea-exclude-repo", value_name = "OWNER/REPO")]
    pub exclude_repos: Vec<String>,

    /// Repositories for all organizations accessible to the authenticated user
    #[arg(long, alias = "all-gitea-organizations", alias = "all-gitea-orgs")]
    pub all_organizations: bool,

    /// Filter by repository type
    #[arg(long, default_value_t = GiteaRepoType::Source, alias = "gitea-repo-type")]
    pub repo_type: GiteaRepoType,
}

impl GiteaRepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.organization.is_empty() && !self.all_organizations
    }
}

/// Gitea repository type filter
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum GiteaRepoType {
    /// Only source repositories (not forks)
    Source,
    /// Only fork repositories
    #[value(alias = "forks")]
    Fork,
    /// Include all repositories
    All,
}

crate::cli::impl_value_enum_display!(GiteaRepoType);

pub type GiteaOutputFormat = GitHubOutputFormat;

impl From<GiteaRepoType> for crate::gitea::RepoType {
    fn from(val: GiteaRepoType) -> Self {
        match val {
            GiteaRepoType::Source => crate::gitea::RepoType::Source,
            GiteaRepoType::Fork => crate::gitea::RepoType::Fork,
            GiteaRepoType::All => crate::gitea::RepoType::All,
        }
    }
}
