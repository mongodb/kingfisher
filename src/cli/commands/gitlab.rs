use clap::{Args, Subcommand, ValueEnum, ValueHint};
use strum_macros::Display;
use url::Url;

use crate::cli::commands::output::{GitHubOutputFormat, OutputArgs};

/// Top-level GitLab command group
#[derive(Args, Debug)]
pub struct GitLabArgs {
    #[command(subcommand)]
    pub command: GitLabCommand,

    /// Override GitLab API URL (e.g. Enterprise)
    #[arg(global = true, long, default_value = "https://gitlab.com/", value_hint = ValueHint::Url)]
    pub gitlab_api_url: Url,
}

#[derive(Subcommand, Debug)]
pub enum GitLabCommand {
    /// Interact with GitLab repositories
    #[command(subcommand)]
    Repos(GitLabReposCommand),
}

#[derive(Subcommand, Debug)]
pub enum GitLabReposCommand {
    /// List repositories for a user or group
    List(GitLabReposListArgs),
}

/// `kingfisher gitlab repos`
#[derive(Args, Debug, Clone)]
pub struct GitLabReposListArgs {
    #[command(flatten)]
    pub repo_specifiers: GitLabRepoSpecifiers,

    #[command(flatten)]
    pub output_args: OutputArgs<GitLabOutputFormat>,
}

/// Options for selecting GitLab repos
#[derive(Args, Debug, Clone)]
pub struct GitLabRepoSpecifiers {
    /// Repositories belonging to these users
    #[arg(long, alias = "gitlab-user")]
    pub user: Vec<String>,

    /// Repositories belonging to these groups
    #[arg(long, alias = "gitlab-group")]
    pub group: Vec<String>,

    /// Repositories for all groups (Enterprise only)
    #[arg(long, alias = "all-groups", alias = "all-gitlab-groups", requires = "gitlab_api_url")]
    pub all_groups: bool,

    /// Filter by repository type
    #[arg(long, default_value_t = GitLabRepoType::All, alias = "gitlab-repo-type")]
    pub repo_type: GitLabRepoType,
}

impl GitLabRepoSpecifiers {
    /// Check if no GitLab sources are specified
    pub fn is_empty(&self) -> bool {
        self.user.is_empty() && self.group.is_empty() && !self.all_groups
    }
}

/// GitLab repository type filter
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum GitLabRepoType {
    /// All repositories the user/group has access to
    All,
    /// Only repositories owned by the user/group
    Owner,
    /// Only repositories where the user is a member
    Member,
}

/// Output formats for GitLab commands - reusing GitHub's formats
pub type GitLabOutputFormat = GitHubOutputFormat;

impl From<GitLabRepoType> for crate::gitlab::RepoType {
    fn from(val: GitLabRepoType) -> Self {
        match val {
            GitLabRepoType::All => crate::gitlab::RepoType::All,
            GitLabRepoType::Owner => crate::gitlab::RepoType::Owner,
            GitLabRepoType::Member => crate::gitlab::RepoType::Member,
        }
    }
}
