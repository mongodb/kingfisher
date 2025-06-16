use clap::{Args, Subcommand, ValueEnum, ValueHint};
use strum_macros::Display;
use url::Url;

use crate::cli::commands::output::OutputArgs;

/// Top-level GitHub command group
#[derive(Args, Debug)]
pub struct GitHubArgs {
    #[command(subcommand)]
    pub command: GitHubCommand,

    /// Override GitHub API URL (e.g. Enterprise)
    #[arg(global = true, long, default_value = "https://api.github.com/", value_hint = ValueHint::Url)]
    pub github_api_url: Url,
}

#[derive(Subcommand, Debug)]
pub enum GitHubCommand {
    /// Interact with GitHub repositories
    #[command(subcommand)]
    Repos(GitHubReposCommand),
}

#[derive(Subcommand, Debug)]
pub enum GitHubReposCommand {
    /// List repositories for a user or organization
    List(GitHubReposListArgs),
}

/// `kingfisher github repos`
#[derive(Args, Debug, Clone)]
pub struct GitHubReposListArgs {
    #[command(flatten)]
    pub repo_specifiers: GitHubRepoSpecifiers,

    #[command(flatten)]
    pub output_args: OutputArgs<GitHubOutputFormat>,
}

/// Options for selecting GitHub repos
#[derive(Args, Debug, Clone)]
pub struct GitHubRepoSpecifiers {
    /// Repositories belonging to these users
    #[arg(long, alias = "github-user")]
    pub user: Vec<String>,

    /// Repositories belonging to these organizations
    #[arg(long, alias = "org", alias = "github-organization", alias = "github-org")]
    pub organization: Vec<String>,

    /// Repositories for all organizations (Enterprise only)
    #[arg(
        long,
        alias = "all-orgs",
        alias = "all-github-organizations",
        alias = "all-github-orgs",
        requires = "github_api_url"
    )]
    pub all_organizations: bool,

    /// Filter by repository type
    #[arg(long, default_value_t = GitHubRepoType::Source, alias = "github-repo-type")]
    pub repo_type: GitHubRepoType,
}

impl GitHubRepoSpecifiers {
    /// Check if no GitHub sources are specified
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.organization.is_empty() && !self.all_organizations
    }
}

/// GitHub repository type filter
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum GitHubRepoType {
    /// Both source and fork repositories
    All,
    /// Only source repositories (not forks)
    Source,
    /// Only fork repositories
    #[value(alias = "forks")]
    Fork,
}

impl From<GitHubRepoType> for crate::github::RepoType {
    fn from(val: GitHubRepoType) -> Self {
        match val {
            GitHubRepoType::All => crate::github::RepoType::All,
            GitHubRepoType::Source => crate::github::RepoType::Source,
            GitHubRepoType::Fork => crate::github::RepoType::Fork,
        }
    }
}

/// Output formats for GitHub commands
#[derive(Copy, Clone, Debug, ValueEnum, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum GitHubOutputFormat {
    Pretty,
    Json,
    Jsonl,
    Bson,
    Sarif,
}

// -----------------------------------------------------------------------------
// Git Repository Cloning/History
// -----------------------------------------------------------------------------
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum GitCloneMode {
    /// Equivalent to `git clone --bare`
    Bare,
    /// Equivalent to `git clone --mirror`, often clones extra objects
    Mirror,
}

/// Specifies how to handle a repository's Git history.
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum GitHistoryMode {
    /// Scan all history
    Full,
    /// Ignore history entirely
    None,
}
