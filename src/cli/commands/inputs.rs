use std::path::PathBuf;

use clap::{Args, ValueHint};
use tracing::warn;
use url::Url;

use crate::{
    cli::commands::{
        azure::AzureRepoType,
        bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
        gitea::GiteaRepoType,
        github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
        gitlab::GitLabRepoType,
    },
    git_url::GitUrl,
};

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";
const DEFAULT_GITLAB_API_URL: &str = "https://gitlab.com/";
const DEFAULT_GITEA_API_URL: &str = "https://gitea.com/api/v1/";
const DEFAULT_BITBUCKET_API_URL: &str = "https://api.bitbucket.org/2.0/";
const DEFAULT_AZURE_BASE_URL: &str = "https://dev.azure.com/";
const DEFAULT_SLACK_API_URL: &str = "https://slack.com/api/";
const DEFAULT_TEAMS_API_URL: &str = "https://graph.microsoft.com/";
const DEFAULT_POSTMAN_API_URL: &str = "https://api.getpostman.com/";

// -----------------------------------------------------------------------------
// Inputs
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct InputSpecifierArgs {
    /// Scan this file, directory, or local Git repository
    #[arg(num_args = 0.., value_hint = ValueHint::AnyPath)]
    pub path_inputs: Vec<PathBuf>,

    /// Deprecated: clone and scan a Git repository URL. Prefer positional targets: `kingfisher scan github.com/org/repo`
    #[arg(long = "git-url", value_hint = ValueHint::Url)]
    pub git_url: Vec<GitUrl>,

    /// Parent directory for cloned Git repositories and scan artifacts
    #[arg(long = "git-clone-dir", value_hint = ValueHint::DirPath, help_heading = "Git Options")]
    pub git_clone_dir: Option<PathBuf>,

    /// Keep cloned Git repositories on disk after the scan completes
    #[arg(long = "keep-clones", default_value_t = false, help_heading = "Git Options")]
    pub keep_clones: bool,

    /// Limit the number of GitHub/GitLab repositories cloned during enumeration
    #[arg(long = "repo-clone-limit", value_name = "COUNT")]
    pub repo_clone_limit: Option<usize>,

    /// Include contributor repositories when scanning GitHub or GitLab git URLs
    #[arg(long = "include-contributors", default_value_t = false)]
    pub include_contributors: bool,

    /// Scan repositories belonging to the specified GitHub user
    #[arg(long, hide = true)]
    pub github_user: Vec<String>,

    /// Scan repositories belonging to the specified GitHub organization
    #[arg(long, alias = "github-org", hide = true)]
    pub github_organization: Vec<String>,

    /// Skip repositories when enumerating GitHub users or organizations (format: owner/repo)
    #[arg(
        long = "github-exclude",
        alias = "github-exclude-repo",
        value_name = "OWNER/REPO",
        hide = true
    )]
    pub github_exclude: Vec<String>,

    /// Scan repositories from all GitHub organizations (requires non-default --github-api-url)
    #[arg(long, alias = "all-github-orgs", requires = "github_api_url", hide = true)]
    pub all_github_organizations: bool,

    /// Use the specified URL for GitHub API access (e.g. for GitHub Enterprise)
    #[arg(
        long,
        alias = "api-url",
        default_value = "https://api.github.com/",
        value_hint = ValueHint::Url,
        hide = true
    )]
    pub github_api_url: Url,

    #[arg(long, default_value_t = GitHubRepoType::Source, hide = true)]
    pub github_repo_type: GitHubRepoType,

    // GitLab Options
    /// Scan repositories belonging to the specified GitLab user
    #[arg(long, hide = true)]
    pub gitlab_user: Vec<String>,

    /// Scan repositories belonging to the specified GitLab group
    #[arg(long, alias = "gitlab-group", hide = true)]
    pub gitlab_group: Vec<String>,

    /// Skip repositories when enumerating GitLab users or groups (format: group/project)
    #[arg(
        long = "gitlab-exclude",
        alias = "gitlab-exclude-project",
        alias = "gitlab-exclude-repo",
        value_name = "GROUP/PROJECT",
        hide = true
    )]
    pub gitlab_exclude: Vec<String>,

    /// Scan repositories from all GitLab groups (requires non-default --gitlab-api-url)
    #[arg(long, alias = "all-gitlab-groups", requires = "gitlab_api_url", hide = true)]
    pub all_gitlab_groups: bool,

    /// Use the specified URL for GitLab API access (e.g. for GitLab self-hosted)
    #[arg(
        long,
        alias="gitlab-api-url",
        default_value = "https://gitlab.com/",
        value_hint = ValueHint::Url,
        hide = true
    )]
    pub gitlab_api_url: Url,

    #[arg(long, default_value_t = GitLabRepoType::All, hide = true)]
    pub gitlab_repo_type: GitLabRepoType,

    /// Include projects from GitLab subgroups when scanning groups
    #[arg(long, alias = "include-subgroups", hide = true)]
    pub gitlab_include_subgroups: bool,

    /// Scan models, datasets, and Spaces belonging to the specified Hugging Face users
    #[arg(long = "huggingface-user", hide = true)]
    pub huggingface_user: Vec<String>,

    /// Scan models, datasets, and Spaces belonging to the specified Hugging Face organizations
    #[arg(long = "huggingface-organization", alias = "huggingface-org", hide = true)]
    pub huggingface_organization: Vec<String>,

    /// Scan a specific Hugging Face model (format: owner/name or full URL)
    #[arg(long = "huggingface-model", hide = true)]
    pub huggingface_model: Vec<String>,

    /// Scan a specific Hugging Face dataset (format: owner/name or full URL)
    #[arg(long = "huggingface-dataset", hide = true)]
    pub huggingface_dataset: Vec<String>,

    /// Scan a specific Hugging Face Space (format: owner/name or full URL)
    #[arg(long = "huggingface-space", hide = true)]
    pub huggingface_space: Vec<String>,

    /// Skip specific Hugging Face repositories during enumeration (accepts optional prefixes like model:, dataset:, or space:)
    #[arg(long = "huggingface-exclude", value_name = "IDENTIFIER", hide = true)]
    pub huggingface_exclude: Vec<String>,

    // Gitea Options
    /// Scan repositories belonging to the specified Gitea user
    #[arg(long, hide = true)]
    pub gitea_user: Vec<String>,

    /// Scan repositories belonging to the specified Gitea organization
    #[arg(long, alias = "gitea-org", hide = true)]
    pub gitea_organization: Vec<String>,

    /// Skip repositories when enumerating Gitea users or organizations (format: owner/repo)
    #[arg(
        long = "gitea-exclude",
        alias = "gitea-exclude-repo",
        value_name = "OWNER/REPO",
        hide = true
    )]
    pub gitea_exclude: Vec<String>,

    /// Scan repositories from all accessible Gitea organizations (requires KF_GITEA_TOKEN)
    #[arg(long, alias = "all-gitea-orgs", hide = true)]
    pub all_gitea_organizations: bool,

    /// Use the specified URL for Gitea API access (e.g. for self-hosted instances)
    #[arg(
        long,
        alias="gitea-api-url",
        default_value = "https://gitea.com/api/v1/",
        value_hint = ValueHint::Url,
        hide = true
    )]
    pub gitea_api_url: Url,

    #[arg(long, default_value_t = GiteaRepoType::Source, hide = true)]
    pub gitea_repo_type: GiteaRepoType,

    // Bitbucket Options
    /// Scan repositories belonging to the specified Bitbucket users
    #[arg(long, hide = true)]
    pub bitbucket_user: Vec<String>,

    /// Scan repositories belonging to the specified Bitbucket workspaces or teams
    #[arg(long, alias = "bitbucket-workspace", alias = "bitbucket-team", hide = true)]
    pub bitbucket_workspace: Vec<String>,

    /// Scan repositories belonging to the specified Bitbucket Server projects
    #[arg(long, alias = "bitbucket-project", hide = true)]
    pub bitbucket_project: Vec<String>,

    /// Skip repositories when enumerating Bitbucket sources (format: owner/repo)
    #[arg(long = "bitbucket-exclude", value_name = "OWNER/REPO", hide = true)]
    pub bitbucket_exclude: Vec<String>,

    /// Scan repositories from all accessible Bitbucket workspaces or projects
    #[arg(long, alias = "all-bitbucket-workspaces", requires = "bitbucket_api_url", hide = true)]
    pub all_bitbucket_workspaces: bool,

    /// Use the specified URL for Bitbucket API access (Cloud or self-hosted)
    #[arg(
        long,
        default_value = "https://api.bitbucket.org/2.0/",
        value_hint = ValueHint::Url,
        hide = true
    )]
    pub bitbucket_api_url: Url,

    #[arg(long, default_value_t = BitbucketRepoType::Source, hide = true)]
    pub bitbucket_repo_type: BitbucketRepoType,

    #[command(flatten)]
    pub bitbucket_auth: BitbucketAuthArgs,

    // Azure DevOps Options
    /// Scan repositories belonging to the specified Azure DevOps organizations or collections
    #[arg(long = "azure-organization", hide = true)]
    pub azure_organization: Vec<String>,

    /// Scan repositories belonging to the specified Azure DevOps projects (format: ORGANIZATION/PROJECT)
    #[arg(long = "azure-project", value_name = "ORGANIZATION/PROJECT", hide = true)]
    pub azure_project: Vec<String>,

    /// Skip repositories when enumerating Azure Repos sources (format: ORGANIZATION/PROJECT/REPOSITORY)
    #[arg(
        long = "azure-exclude",
        alias = "azure-exclude-repo",
        value_name = "ORGANIZATION/PROJECT/REPOSITORY",
        hide = true
    )]
    pub azure_exclude: Vec<String>,

    /// Include repositories from every project within the specified Azure organizations
    #[arg(long = "all-azure-projects", hide = true)]
    pub all_azure_projects: bool,

    /// Use the specified base URL for Azure DevOps (e.g. Azure DevOps Server)
    #[arg(
        long = "azure-base-url",
        default_value = "https://dev.azure.com/",
        value_hint = ValueHint::Url,
        hide = true
    )]
    pub azure_base_url: Url,

    #[arg(long = "azure-repo-type", default_value_t = AzureRepoType::Source, hide = true)]
    pub azure_repo_type: AzureRepoType,

    /// Jira base URL (e.g. https://jira.example.com)
    #[arg(long, value_hint = ValueHint::Url, requires = "jql", hide = true)]
    pub jira_url: Option<Url>,

    /// JQL query to select Jira issues
    #[arg(long, requires = "jira_url", hide = true)]
    pub jql: Option<String>,

    /// Include Jira issue comments in the scan
    #[arg(long = "jira-include-comments", requires = "jira_url", hide = true)]
    pub jira_include_comments: bool,

    /// Include Jira issue changelog entries in the scan
    #[arg(long = "jira-include-changelog", requires = "jira_url", hide = true)]
    pub jira_include_changelog: bool,

    /// Confluence base URL (e.g. https://confluence.example.com)
    #[arg(long, value_hint = ValueHint::Url, requires = "cql", hide = true)]
    pub confluence_url: Option<Url>,

    /// CQL query to select Confluence pages
    #[arg(long, requires = "confluence_url", hide = true)]
    pub cql: Option<String>,

    /// Slack search query
    #[arg(long, hide = true)]
    pub slack_query: Option<String>,

    /// Use the specified URL for Slack API access
    #[arg(long, default_value = "https://slack.com/api/", value_hint = ValueHint::Url, hide = true)]
    pub slack_api_url: Url,

    /// Microsoft Teams search query
    #[arg(long, hide = true)]
    pub teams_query: Option<String>,

    /// Use the specified URL for Microsoft Graph API access
    #[arg(long, default_value = "https://graph.microsoft.com/", value_hint = ValueHint::Url, hide = true)]
    pub teams_api_url: Url,

    /// Scan a Postman workspace by ID or web URL (repeatable)
    #[arg(long = "postman-workspace", value_name = "ID_OR_URL", hide = true)]
    pub postman_workspaces: Vec<String>,

    /// Scan a single Postman collection by UID or web URL (repeatable)
    #[arg(long = "postman-collection", value_name = "UID_OR_URL", hide = true)]
    pub postman_collections: Vec<String>,

    /// Scan a single Postman environment by UID (repeatable)
    #[arg(long = "postman-environment", value_name = "UID", hide = true)]
    pub postman_environments: Vec<String>,

    /// Scan every workspace, collection, and environment visible to the API key
    #[arg(
        long = "postman-all",
        hide = true,
        conflicts_with_all = ["postman_workspaces", "postman_collections", "postman_environments"],
    )]
    pub postman_all: bool,

    /// Include Postman mocks and monitors when scanning a workspace (off by default)
    #[arg(long = "postman-include-mocks-monitors", hide = true)]
    pub postman_include_mocks_monitors: bool,

    /// Use the specified base URL for the Postman API (e.g. self-hosted)
    #[arg(
        long = "postman-api-url",
        default_value = DEFAULT_POSTMAN_API_URL,
        value_hint = ValueHint::Url,
        hide = true,
    )]
    pub postman_api_url: Url,

    /// Maximum number of Slack, Teams, Jira, Confluence, or Postman results to fetch
    #[arg(long, default_value_t = 100, hide = true)]
    pub max_results: usize,

    /// Scan the specified S3 bucket
    #[arg(long, hide = true)]
    pub s3_bucket: Option<String>,

    /// Optional prefix within the S3 bucket
    #[arg(long, requires = "s3_bucket", hide = true)]
    pub s3_prefix: Option<String>,

    /// AWS IAM role ARN to assume for S3 access
    #[arg(long, requires = "s3_bucket", hide = true)]
    pub role_arn: Option<String>,

    /// Use credentials from a local AWS profile in ~/.aws/config
    #[arg(long, requires = "s3_bucket", hide = true)]
    pub aws_local_profile: Option<String>,

    /// Scan the specified Google Cloud Storage bucket
    #[arg(long, hide = true)]
    pub gcs_bucket: Option<String>,

    /// Optional prefix within the GCS bucket
    #[arg(long, requires = "gcs_bucket", hide = true)]
    pub gcs_prefix: Option<String>,

    /// Path to a service account JSON file for GCS authentication
    #[arg(long, value_hint = ValueHint::FilePath, requires = "gcs_bucket", hide = true)]
    pub gcs_service_account: Option<PathBuf>,

    /// Docker/OCI images to scan (no local Docker required)
    #[arg(long = "docker-image", hide = true)]
    pub docker_image: Vec<String>,

    /// Docker image archives provided by the docker subcommand
    #[arg(skip)]
    pub docker_archive: Vec<PathBuf>,

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

    /// Also scan repository host artifacts like issues, wikis, and gists/snippets
    #[arg(long, help_heading = "Git Options")]
    pub repo_artifacts: bool,

    /// Enable or disable scanning nested git repositories
    #[arg(long, default_value_t = true)]
    pub scan_nested_repos: bool,

    /// Limit Git scanning to changes made since this commit or ref
    #[arg(long = "since-commit", value_name = "GIT-REF", help_heading = "Git Options")]
    pub since_commit: Option<String>,

    /// Scan only staged changes by synthesizing a temporary commit and diffing it
    /// against the current HEAD (or an empty tree when no commits exist).
    #[arg(
        long,
        help_heading = "Git Options",
        conflicts_with = "branch_root",
        conflicts_with = "branch_root_commit"
    )]
    pub staged: bool,

    /// Branch, tag, or commit to scan or compare against (defaults to HEAD)
    #[arg(
        long,
        value_name = "GIT-REF",
        help_heading = "Git Options",
        alias = "ref",
        visible_alias = "ref"
    )]
    pub branch: Option<String>,

    /// Treat the `--branch` commit or ref as the inclusive root for the scan.
    ///
    /// When enabled, Kingfisher diffs from the parent of the selected commit
    /// through the current HEAD of the repository, ensuring the chosen commit
    /// and every descendant is scanned exactly once. Providing
    /// `--branch-root-commit` will also enable this behaviour automatically.
    #[arg(
        long = "branch-root",
        help_heading = "Git Options",
        requires = "branch",
        conflicts_with = "since_commit",
        action = clap::ArgAction::SetTrue
    )]
    pub branch_root: bool,

    /// Explicit commit or ref to use as the inclusive branch root. Supplying
    /// this flag implicitly enables branch-root scanning even if `--branch-root`
    /// is omitted.
    #[arg(
        long = "branch-root-commit",
        value_name = "GIT-REF",
        help_heading = "Git Options",
        conflicts_with = "since_commit"
    )]
    pub branch_root_commit: Option<String>,
}

impl InputSpecifierArgs {
    /// Return true when any scan input has been specified.
    pub fn has_any_input(&self) -> bool {
        !self.path_inputs.is_empty()
            || !self.git_url.is_empty()
            || !self.github_user.is_empty()
            || !self.github_organization.is_empty()
            || self.all_github_organizations
            || !self.gitlab_user.is_empty()
            || !self.gitlab_group.is_empty()
            || self.all_gitlab_groups
            || !self.gitea_user.is_empty()
            || !self.gitea_organization.is_empty()
            || self.all_gitea_organizations
            || !self.huggingface_user.is_empty()
            || !self.huggingface_organization.is_empty()
            || !self.huggingface_model.is_empty()
            || !self.huggingface_dataset.is_empty()
            || !self.huggingface_space.is_empty()
            || !self.bitbucket_user.is_empty()
            || !self.bitbucket_workspace.is_empty()
            || !self.bitbucket_project.is_empty()
            || self.all_bitbucket_workspaces
            || !self.azure_organization.is_empty()
            || !self.azure_project.is_empty()
            || self.all_azure_projects
            || self.jira_url.is_some()
            || self.confluence_url.is_some()
            || self.slack_query.is_some()
            || self.teams_query.is_some()
            || !self.postman_workspaces.is_empty()
            || !self.postman_collections.is_empty()
            || !self.postman_environments.is_empty()
            || self.postman_all
            || self.s3_bucket.is_some()
            || self.gcs_bucket.is_some()
            || !self.docker_image.is_empty()
            || !self.docker_archive.is_empty()
    }

    /// Return true when any flag has been set that schedules artifact
    /// fetching (issues/PRs/wikis, Jira, Confluence, Slack, Teams, Postman,
    /// or Docker images). Used by the scan runner to decide whether the
    /// "no inputs" guard should bail out, since artifact dirs arrive via
    /// the streaming scan channel rather than via `input_roots`.
    pub fn has_artifact_sources(&self) -> bool {
        self.repo_artifacts
            || self.jira_url.is_some()
            || self.confluence_url.is_some()
            || self.slack_query.is_some()
            || self.teams_query.is_some()
            || !self.postman_workspaces.is_empty()
            || !self.postman_collections.is_empty()
            || !self.postman_environments.is_empty()
            || self.postman_all
            || !self.docker_image.is_empty()
            || !self.docker_archive.is_empty()
    }

    /// Emit deprecation warnings for legacy top-level provider flags.
    pub fn emit_deprecated_warnings(&self, used_legacy_git_url_flag: bool) {
        if used_legacy_git_url_flag {
            warn_deprecated_provider(
                "Git URL",
                "Passing repository URLs with `--git-url` is deprecated. Pass the URL as a positional scan target instead, e.g. `kingfisher scan github.com/org/repo`.",
            );
        }

        if self.using_legacy_github_flags() {
            warn_deprecated_provider(
                "GitHub",
                "Use `kingfisher scan github …` instead of the legacy `--github-*` flags.",
            );
        }

        if self.using_legacy_gitlab_flags() {
            warn_deprecated_provider(
                "GitLab",
                "Use `kingfisher scan gitlab …` instead of the legacy `--gitlab-*` flags.",
            );
        }

        if self.using_legacy_gitea_flags() {
            warn_deprecated_provider(
                "Gitea",
                "Use `kingfisher scan gitea …` instead of the legacy `--gitea-*` flags.",
            );
        }

        if self.using_legacy_bitbucket_flags() {
            warn_deprecated_provider(
                "Bitbucket",
                "Use `kingfisher scan bitbucket …` instead of the legacy `--bitbucket-*` flags.",
            );
        }

        if self.using_legacy_azure_flags() {
            warn_deprecated_provider(
                "Azure DevOps",
                "Use `kingfisher scan azure …` instead of the legacy `--azure-*` flags.",
            );
        }

        if self.using_legacy_huggingface_flags() {
            warn_deprecated_provider(
                "Hugging Face",
                "Use `kingfisher scan huggingface …` instead of the legacy `--huggingface-*` flags.",
            );
        }

        if self.slack_query.is_some() || self.slack_api_url.as_str() != DEFAULT_SLACK_API_URL {
            warn_deprecated_provider(
                "Slack",
                "Use `kingfisher scan slack …` instead of the legacy `--slack-*` flags.",
            );
        }

        if self.teams_query.is_some() || self.teams_api_url.as_str() != DEFAULT_TEAMS_API_URL {
            warn_deprecated_provider(
                "Microsoft Teams",
                "Use `kingfisher scan teams …` instead of the legacy `--teams-*` flags.",
            );
        }

        if self.jira_url.is_some() || self.jql.is_some() {
            warn_deprecated_provider(
                "Jira",
                "Use `kingfisher scan jira …` instead of the legacy `--jira-*` flags.",
            );
        }

        if self.confluence_url.is_some() || self.cql.is_some() {
            warn_deprecated_provider(
                "Confluence",
                "Use `kingfisher scan confluence …` instead of the legacy `--confluence-*` flags.",
            );
        }

        if self.using_legacy_s3_flags() {
            warn_deprecated_provider(
                "Amazon S3",
                "Use `kingfisher scan s3 …` instead of the legacy `--s3-*` flags.",
            );
        }

        if self.using_legacy_gcs_flags() {
            warn_deprecated_provider(
                "Google Cloud Storage",
                "Use `kingfisher scan gcs …` instead of the legacy `--gcs-*` flags.",
            );
        }

        if !self.docker_image.is_empty() {
            warn_deprecated_provider(
                "Docker",
                "Use `kingfisher scan docker …` instead of the legacy `--docker-image` flag.",
            );
        }
    }

    fn using_legacy_github_flags(&self) -> bool {
        !self.github_user.is_empty()
            || !self.github_organization.is_empty()
            || !self.github_exclude.is_empty()
            || self.all_github_organizations
            || self.github_repo_type != GitHubRepoType::Source
            || self.github_api_url.as_str() != DEFAULT_GITHUB_API_URL
    }

    fn using_legacy_gitlab_flags(&self) -> bool {
        !self.gitlab_user.is_empty()
            || !self.gitlab_group.is_empty()
            || !self.gitlab_exclude.is_empty()
            || self.all_gitlab_groups
            || self.gitlab_include_subgroups
            || self.gitlab_repo_type != GitLabRepoType::All
            || self.gitlab_api_url.as_str() != DEFAULT_GITLAB_API_URL
    }

    fn using_legacy_gitea_flags(&self) -> bool {
        !self.gitea_user.is_empty()
            || !self.gitea_organization.is_empty()
            || !self.gitea_exclude.is_empty()
            || self.all_gitea_organizations
            || self.gitea_repo_type != GiteaRepoType::Source
            || self.gitea_api_url.as_str() != DEFAULT_GITEA_API_URL
    }

    fn using_legacy_bitbucket_flags(&self) -> bool {
        !self.bitbucket_user.is_empty()
            || !self.bitbucket_workspace.is_empty()
            || !self.bitbucket_project.is_empty()
            || !self.bitbucket_exclude.is_empty()
            || self.all_bitbucket_workspaces
            || self.bitbucket_repo_type != BitbucketRepoType::Source
            || self.bitbucket_api_url.as_str() != DEFAULT_BITBUCKET_API_URL
    }

    fn using_legacy_azure_flags(&self) -> bool {
        !self.azure_organization.is_empty()
            || !self.azure_project.is_empty()
            || !self.azure_exclude.is_empty()
            || self.all_azure_projects
            || self.azure_repo_type != AzureRepoType::Source
            || self.azure_base_url.as_str() != DEFAULT_AZURE_BASE_URL
    }

    fn using_legacy_huggingface_flags(&self) -> bool {
        !self.huggingface_user.is_empty()
            || !self.huggingface_organization.is_empty()
            || !self.huggingface_model.is_empty()
            || !self.huggingface_dataset.is_empty()
            || !self.huggingface_space.is_empty()
            || !self.huggingface_exclude.is_empty()
    }

    fn using_legacy_s3_flags(&self) -> bool {
        self.s3_bucket.is_some()
            || self.s3_prefix.is_some()
            || self.role_arn.is_some()
            || self.aws_local_profile.is_some()
    }

    fn using_legacy_gcs_flags(&self) -> bool {
        self.gcs_bucket.is_some() || self.gcs_prefix.is_some() || self.gcs_service_account.is_some()
    }
}

fn warn_deprecated_provider(provider: &str, guidance: &str) {
    warn!(
        "{provider} legacy scan flags are deprecated and will be removed in a future release. {guidance}",
        provider = provider,
        guidance = guidance
    );
}

// -----------------------------------------------------------------------------
// Content Filtering
// -----------------------------------------------------------------------------
#[derive(Args, Debug, Clone)]
pub struct ContentFilteringArgs {
    /// Ignore files larger than the given size in MB
    #[arg(
        global = true,
        long = "max-file-size",
        visible_alias = "max-filesize",      // also show in --help
        default_value_t = 256.0,
        value_name = "MB"
    )]
    pub max_file_size_mb: f64,

    /// Skip any file or directory whose path matches this glob pattern. Multiple
    /// patterns may be provided by repeating the flag.
    #[arg(global = true, long, value_name = "PATTERN")]
    pub exclude: Vec<String>,

    /// If true, do NOT extract archive files
    #[arg(global = true, long = "no-extract-archives", default_value_t = false)]
    pub no_extract_archives: bool,

    /// Maximum allowed depth for extracting nested archives
    #[arg(global = true, long = "extraction-depth", default_value_t = 2, value_parser = clap::value_parser!(u8).range(1..=25))]
    pub extraction_depth: u8,

    /// If true, do NOT scan binary files
    #[arg(global = true, long = "no-binary", default_value_t = false)]
    pub no_binary: bool,
}

impl ContentFilteringArgs {
    /// Convert the maximum file size in MB to bytes
    pub fn max_file_size_bytes(&self) -> Option<u64> {
        if self.max_file_size_mb < 0.0 {
            Some(256 * 1024 * 1024) // default 256 MB if negative
        } else {
            Some((self.max_file_size_mb * 1024.0 * 1024.0) as u64)
        }
    }
}
