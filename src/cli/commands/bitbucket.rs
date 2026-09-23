use clap::{Args, Subcommand, ValueEnum, ValueHint};
use strum::Display;
use url::Url;

use crate::cli::commands::output::OutputArgs;

#[derive(Args, Debug, Clone, Default)]
pub struct BitbucketAuthArgs {
    /// Bitbucket credentials are sourced from KF_BITBUCKET_* environment variables.
    #[arg(skip)]
    _env_only: (),
}

/// Top-level Bitbucket command group
#[derive(Args, Debug)]
pub struct BitbucketArgs {
    #[command(subcommand)]
    pub command: BitbucketCommand,

    /// Override Bitbucket API URL (Cloud or self-hosted)
    #[arg(
        global = true,
        long,
        default_value = "https://api.bitbucket.org/2.0/",
        value_hint = ValueHint::Url
    )]
    pub bitbucket_api_url: Url,
}

#[derive(Subcommand, Debug)]
pub enum BitbucketCommand {
    /// Interact with Bitbucket repositories
    #[command(subcommand)]
    Repos(BitbucketReposCommand),
}

#[derive(Subcommand, Debug)]
pub enum BitbucketReposCommand {
    /// List repositories for users, workspaces, or projects
    List(BitbucketReposListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct BitbucketReposListArgs {
    #[command(flatten)]
    pub repo_specifiers: BitbucketRepoSpecifiers,

    #[command(flatten)]
    pub output_args: OutputArgs<BitbucketOutputFormat>,

    #[command(flatten)]
    pub auth: BitbucketAuthArgs,
}

#[derive(Args, Debug, Clone)]
pub struct BitbucketRepoSpecifiers {
    /// Repositories belonging to these users
    #[arg(long, alias = "bitbucket-user")]
    pub user: Vec<String>,

    /// Include accessible workspace snippets (Bitbucket Cloud only)
    #[arg(long)]
    pub include_snippets: bool,

    /// Repositories belonging to these workspaces or teams
    #[arg(long, alias = "bitbucket-workspace", alias = "bitbucket-team")]
    pub workspace: Vec<String>,

    /// Repositories belonging to these Bitbucket Server projects
    #[arg(long, alias = "bitbucket-project")]
    pub project: Vec<String>,

    /// Skip specific repositories during enumeration (format: owner/repo)
    #[arg(long = "bitbucket-exclude", value_name = "OWNER/REPO")]
    pub exclude_repos: Vec<String>,

    /// Enumerate all accessible workspaces or projects
    #[arg(long, alias = "all-bitbucket-workspaces", requires = "api_url")]
    pub all_workspaces: bool,

    /// Filter repositories by type
    #[arg(long, default_value_t = BitbucketRepoType::Source, alias = "bitbucket-repo-type")]
    pub repo_type: BitbucketRepoType,
}

impl BitbucketRepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.user.is_empty()
            && self.workspace.is_empty()
            && self.project.is_empty()
            && !self.all_workspaces
    }
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum BitbucketRepoType {
    /// Source repositories (exclude forks)
    Source,
    /// Fork repositories only
    #[value(alias = "forks")]
    Fork,
    /// All repositories (source and forks)
    All,
}

pub type BitbucketOutputFormat = crate::cli::commands::output::GitHubOutputFormat;

impl From<BitbucketRepoType> for crate::bitbucket::RepoType {
    fn from(value: BitbucketRepoType) -> Self {
        match value {
            BitbucketRepoType::All => crate::bitbucket::RepoType::All,
            BitbucketRepoType::Source => crate::bitbucket::RepoType::Source,
            BitbucketRepoType::Fork => crate::bitbucket::RepoType::Fork,
        }
    }
}
