use std::path::PathBuf;

use clap::{Args, ValueHint};
use url::Url;

use crate::{
    cli::commands::{
        github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
        gitlab::GitLabRepoType,
    },
    git_url::GitUrl,
};

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct InputSpecifierArgs {
    /// Scan this file, directory, or local Git repository
    #[arg(
        required_unless_present_any([
            "github_user",
            "github_organization",
            "gitlab_user",
            "gitlab_group",
            "git_url",
            "all_github_organizations",
            "all_gitlab_groups"
        ]),
        value_hint = ValueHint::AnyPath
    )]
    pub path_inputs: Vec<PathBuf>,

    /// Clone and scan the Git repository at the given URL
    #[arg(long, value_hint = ValueHint::Url)]
    pub git_url: Vec<GitUrl>,

    /// Scan repositories belonging to the specified GitHub user
    #[arg(long)]
    pub github_user: Vec<String>,

    /// Scan repositories belonging to the specified GitHub organization
    #[arg(long, alias = "github-org")]
    pub github_organization: Vec<String>,

    /// Scan repositories from all GitHub organizations (requires non-default --github-api-url)
    #[arg(long, alias = "all-github-orgs", requires = "github_api_url")]
    pub all_github_organizations: bool,

    /// Use the specified URL for GitHub API access (e.g. for GitHub Enterprise)
    #[arg(
        long,
        alias="api-url",
        default_value = "https://api.github.com/",
        value_hint = ValueHint::Url
    )]
    pub github_api_url: Url,

    #[arg(long, default_value_t = GitHubRepoType::Source)]
    pub github_repo_type: GitHubRepoType,

    // GitLab Options
    /// Scan repositories belonging to the specified GitLab user
    #[arg(long)]
    pub gitlab_user: Vec<String>,

    /// Scan repositories belonging to the specified GitLab group
    #[arg(long, alias = "gitlab-group")]
    pub gitlab_group: Vec<String>,

    /// Scan repositories from all GitLab groups (requires non-default --gitlab-api-url)
    #[arg(long, alias = "all-gitlab-groups", requires = "gitlab_api_url")]
    pub all_gitlab_groups: bool,

    /// Use the specified URL for GitLab API access (e.g. for GitLab self-hosted)
    #[arg(
        long,
        alias="gitlab-api-url",
        default_value = "https://gitlab.com/",
        value_hint = ValueHint::Url
    )]
    pub gitlab_api_url: Url,

    #[arg(long, default_value_t = GitLabRepoType::Owner)]
    pub gitlab_repo_type: GitLabRepoType,

    /// Select how to clone Git repositories
    #[arg(long, default_value_t=GitCloneMode::Bare, alias="git-clone-mode")]
    pub git_clone: GitCloneMode,

    /// Select whether to scan full Git history or not
    #[arg(long, default_value_t=GitHistoryMode::Full)]
    pub git_history: GitHistoryMode,

    /// Include detailed Git commit context (author, date, commit hash) for findings.
    /// Set to 'false' to disable.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, help_heading = "Git Options")]
    pub commit_metadata: bool,

    /// Enable or disable scanning nested git repositories
    #[arg(long, default_value_t = true)]
    pub scan_nested_repos: bool,
}

// -----------------------------------------------------------------------------
// Content Filtering
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct ContentFilteringArgs {
    /// Ignore files larger than the given size in MB
    #[arg(long("max-file-size"), default_value_t = 25.0)]
    pub max_file_size_mb: f64,

    /// Use custom path-based ignore rules from the given file(s)
    #[arg(long, short, value_hint = ValueHint::FilePath)]
    pub ignore: Vec<PathBuf>,

    /// If true, do NOT extract archive files
    #[arg(long("no-extract-archives"), default_value_t = false)]
    pub no_extract_archives: bool,

    /// Maximum allowed depth for extracting nested archives
    #[arg(long("extraction-depth"), default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=25))]
    pub extraction_depth: u8,

    /// If true, do NOT scan binary files
    #[arg(long("no-binary"), default_value_t = false)]
    pub no_binary: bool,
}

impl ContentFilteringArgs {
    /// Convert the maximum file size in MB to bytes
    pub fn max_file_size_bytes(&self) -> Option<u64> {
        if self.max_file_size_mb < 0.0 {
            Some(25 * 1024 * 1024) // default 25 MB if negative
        } else {
            Some((self.max_file_size_mb * 1024.0 * 1024.0) as u64)
        }
    }
}
