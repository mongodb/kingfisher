use std::path::PathBuf;

use clap::{Args, ValueEnum, ValueHint};
use strum::Display;

use crate::util::get_writer_for_file_or_stdout;

/// Inspect a cloud credential and derive the effective identity and blast radius.
#[derive(Args, Debug)]
pub struct AccessMapArgs {
    /// Cloud provider for identity mapping
    #[clap(value_parser, value_name = "PROVIDER")]
    pub provider: AccessMapProvider,

    /// Path to a credential artifact (e.g. GCP service account key JSON)
    #[clap(value_parser, value_name = "CREDENTIAL", required = false)]
    pub credential_path: Option<PathBuf>,

    #[command(flatten)]
    pub output_args: AccessMapOutputArgs,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Output Options")]
pub struct AccessMapOutputArgs {
    /// Write output to the specified path (stdout if not given)
    #[arg(long, short = 'o', value_hint = ValueHint::FilePath)]
    pub output: Option<PathBuf>,

    /// Output format
    #[arg(long, short = 'f', default_value = "json")]
    pub format: AccessMapOutputFormat,
}

impl AccessMapOutputArgs {
    /// Return a writer for the specified output destination
    pub fn get_writer(&self) -> std::io::Result<Box<dyn std::io::Write>> {
        get_writer_for_file_or_stdout(self.output.as_ref())
    }
}

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[strum(serialize_all = "kebab-case")]
pub enum AccessMapOutputFormat {
    /// Pretty-printed JSON
    Json,

    /// Standalone HTML access-map report
    Html,
}

/// Supported cloud providers for identity mapping.
#[derive(Clone, Debug, ValueEnum)]
pub enum AccessMapProvider {
    /// Amazon Web Services
    Aws,
    /// Google Cloud Platform
    Gcp,
    /// Microsoft Azure
    Azure,
    /// GitHub
    Github,
    /// GitLab
    Gitlab,
    /// Slack
    Slack,
    /// PostgreSQL database
    Postgres,
    /// MongoDB database
    #[clap(alias = "mongo")]
    Mongodb,
    /// Hugging Face
    #[clap(alias = "hf")]
    Huggingface,
    /// Gitea
    Gitea,
    /// Bitbucket
    Bitbucket,
    /// Buildkite
    Buildkite,
    /// Harness
    Harness,
    /// OpenAI
    Openai,
    /// Anthropic
    Anthropic,
    /// Salesforce
    Salesforce,
    /// Weights & Biases
    #[clap(alias = "wandb")]
    Weightsandbiases,
    /// Microsoft Teams
    #[clap(alias = "msteams")]
    Microsoftteams,
    /// Airtable
    Airtable,
    /// Alibaba Cloud
    #[clap(alias = "aliyun")]
    Alibaba,
    /// CircleCI
    Circleci,
    /// DigitalOcean
    #[clap(alias = "do")]
    Digitalocean,
    /// Fastly
    Fastly,
    /// HubSpot
    Hubspot,
    /// IBM Cloud
    #[clap(alias = "ibm")]
    Ibmcloud,
    /// SendGrid
    Sendgrid,
    /// Brevo (Sendinblue)
    #[clap(alias = "brevo")]
    Sendinblue,
    /// Stripe
    Stripe,
    /// Terraform Cloud
    #[clap(alias = "tfc")]
    Terraform,
    /// Square
    Square,
    /// Jira
    #[clap(alias = "jira")]
    Jira,
    /// MySQL database
    #[clap(alias = "mysql")]
    Mysql,
    /// Algolia
    #[clap(alias = "algolia")]
    Algolia,
    /// Auth0
    #[clap(alias = "auth0")]
    Auth0,
    /// PayPal
    #[clap(alias = "paypal")]
    Paypal,
    /// Plaid
    #[clap(alias = "plaid")]
    Plaid,
    /// Shopify
    #[clap(alias = "shopify")]
    Shopify,
    /// Zendesk
    #[clap(alias = "zendesk")]
    Zendesk,
    /// JFrog Artifactory
    #[clap(alias = "jfrog-art")]
    Artifactory,
    /// JFrog Xray
    #[clap(alias = "jfrog-xray")]
    Xray,
    /// monday.com
    #[clap(alias = "monday.com")]
    Monday,
    /// Asana
    Asana,
    /// Pinecone
    #[clap(alias = "pinecone.io")]
    Pinecone,
}
