use clap::{Args, Subcommand, ValueEnum, ValueHint};
use url::Url;

use crate::cli::commands::output::OutputArgs;

#[derive(Args, Debug)]
pub struct AzureArgs {
    #[command(subcommand)]
    pub command: AzureCommand,

    /// Override Azure DevOps base URL (e.g. for Azure DevOps Server)
    #[arg(global = true, long, default_value = "https://dev.azure.com/", value_hint = ValueHint::Url)]
    pub azure_base_url: Url,
}

#[derive(Subcommand, Debug)]
pub enum AzureCommand {
    /// Interact with Azure DevOps repositories
    #[command(subcommand)]
    Repos(AzureReposCommand),
}

#[derive(Subcommand, Debug)]
pub enum AzureReposCommand {
    /// List repositories for organizations or projects
    List(AzureReposListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct AzureReposListArgs {
    #[command(flatten)]
    pub repo_specifiers: AzureRepoSpecifiers,

    #[command(flatten)]
    pub output_args: OutputArgs<AzureOutputFormat>,
}

#[derive(Args, Debug, Clone)]
pub struct AzureRepoSpecifiers {
    /// Repositories belonging to these Azure DevOps organizations or collections
    #[arg(long = "azure-organization", alias = "organization", value_name = "ORGANIZATION")]
    pub organization: Vec<String>,

    /// Repositories belonging to the specified Azure DevOps projects (format: ORGANIZATION/PROJECT)
    #[arg(long = "azure-project", alias = "project", value_name = "ORGANIZATION/PROJECT")]
    pub project: Vec<String>,

    /// Include repositories from all projects within the specified organizations
    #[arg(long = "all-projects", alias = "azure-all-projects")]
    pub all_projects: bool,

    /// Skip repositories when enumerating Azure sources (format: ORGANIZATION/PROJECT/REPOSITORY)
    #[arg(
        long = "azure-exclude",
        alias = "azure-exclude-repo",
        value_name = "ORGANIZATION/PROJECT/REPOSITORY"
    )]
    pub exclude_repos: Vec<String>,

    /// Filter by repository type
    #[arg(long = "repo-type", alias = "azure-repo-type", default_value_t = AzureRepoType::Source)]
    pub repo_type: AzureRepoType,
}

impl AzureRepoSpecifiers {
    pub fn is_empty(&self) -> bool {
        self.organization.is_empty() && self.project.is_empty()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum AzureRepoType {
    Source,
    Fork,
    All,
}

impl From<AzureRepoType> for crate::azure::RepoType {
    fn from(value: AzureRepoType) -> Self {
        match value {
            AzureRepoType::Source => crate::azure::RepoType::Source,
            AzureRepoType::Fork => crate::azure::RepoType::Fork,
            AzureRepoType::All => crate::azure::RepoType::All,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AzureOutputFormat {
    Pretty,
    Json,
    Jsonl,
    Bson,
    Sarif,
}

crate::cli::impl_value_enum_display!(AzureRepoType, AzureOutputFormat);
