use std::path::PathBuf;
use std::str::FromStr;

use clap::{
    Args, ValueEnum, ValueHint,
    builder::{PossibleValue, PossibleValuesParser, TypedValueParser},
};
use strum::Display;

use crate::util::get_writer_for_file_or_stdout;

/// Inspect a cloud credential and derive the effective identity and blast radius.
#[derive(Args, Debug)]
pub struct AccessMapArgs {
    /// Cloud provider for identity mapping
    #[clap(
        value_parser = access_map_provider_parser(),
        value_name = "PROVIDER",
        ignore_case = true
    )]
    pub provider: AccessMapProvider,

    /// Path to a credential artifact (for example, a GCP key or Azure credential document)
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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    Mongodb,
    /// Hugging Face
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
    Weightsandbiases,
    /// Microsoft Teams
    Microsoftteams,
    /// Airtable
    Airtable,
    /// Alibaba Cloud
    Alibaba,
    /// CircleCI
    Circleci,
    /// DigitalOcean
    Digitalocean,
    /// Fastly
    Fastly,
    /// HubSpot
    Hubspot,
    /// IBM Cloud
    Ibmcloud,
    /// SendGrid
    Sendgrid,
    /// Brevo (Sendinblue)
    Sendinblue,
    /// Stripe
    Stripe,
    /// Terraform Cloud
    Terraform,
    /// Square
    Square,
    /// Jira
    Jira,
    /// MySQL database
    Mysql,
    /// Algolia
    Algolia,
    /// Auth0
    Auth0,
    /// PayPal
    Paypal,
    /// Plaid
    Plaid,
    /// Shopify
    Shopify,
    /// Zendesk
    Zendesk,
    /// JFrog Artifactory
    Artifactory,
    /// JFrog Xray
    Xray,
    /// monday.com
    Monday,
    /// Asana
    Asana,
    /// Pinecone
    Pinecone,
}

impl FromStr for AccessMapProvider {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "aws" => Ok(Self::Aws),
            "gcp" => Ok(Self::Gcp),
            "azure" => Ok(Self::Azure),
            "github" => Ok(Self::Github),
            "gitlab" => Ok(Self::Gitlab),
            "slack" => Ok(Self::Slack),
            "postgres" => Ok(Self::Postgres),
            "mongodb" | "mongo" => Ok(Self::Mongodb),
            "huggingface" | "hf" => Ok(Self::Huggingface),
            "gitea" => Ok(Self::Gitea),
            "bitbucket" => Ok(Self::Bitbucket),
            "buildkite" => Ok(Self::Buildkite),
            "harness" => Ok(Self::Harness),
            "openai" => Ok(Self::Openai),
            "anthropic" => Ok(Self::Anthropic),
            "salesforce" => Ok(Self::Salesforce),
            "weightsandbiases" | "weights-and-biases" | "wandb" => Ok(Self::Weightsandbiases),
            "microsoftteams" | "microsoft-teams" | "msteams" => Ok(Self::Microsoftteams),
            "airtable" => Ok(Self::Airtable),
            "alibaba" | "aliyun" => Ok(Self::Alibaba),
            "circleci" => Ok(Self::Circleci),
            "digitalocean" | "digital-ocean" | "do" => Ok(Self::Digitalocean),
            "fastly" => Ok(Self::Fastly),
            "hubspot" | "hub-spot" => Ok(Self::Hubspot),
            "ibmcloud" | "ibm-cloud" | "ibm" => Ok(Self::Ibmcloud),
            "sendgrid" | "send-grid" => Ok(Self::Sendgrid),
            "sendinblue" | "send-in-blue" | "brevo" => Ok(Self::Sendinblue),
            "stripe" => Ok(Self::Stripe),
            "terraform" | "tfc" => Ok(Self::Terraform),
            "square" => Ok(Self::Square),
            "jira" => Ok(Self::Jira),
            "mysql" => Ok(Self::Mysql),
            "algolia" => Ok(Self::Algolia),
            "auth0" => Ok(Self::Auth0),
            "paypal" | "pay-pal" => Ok(Self::Paypal),
            "plaid" => Ok(Self::Plaid),
            "shopify" => Ok(Self::Shopify),
            "zendesk" => Ok(Self::Zendesk),
            "artifactory" | "jfrog-art" => Ok(Self::Artifactory),
            "xray" | "jfrog-xray" => Ok(Self::Xray),
            "monday" | "monday.com" => Ok(Self::Monday),
            "asana" => Ok(Self::Asana),
            "pinecone" | "pinecone.io" => Ok(Self::Pinecone),
            _ => Err(format!(
                "invalid provider `{raw}`; expected one of: {}",
                ACCESS_MAP_PROVIDER_NAMES.join(", ")
            )),
        }
    }
}

const ACCESS_MAP_PROVIDER_NAMES: &[&str] = &[
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "slack",
    "postgres",
    "mongodb",
    "huggingface",
    "gitea",
    "bitbucket",
    "buildkite",
    "harness",
    "openai",
    "anthropic",
    "salesforce",
    "weightsandbiases",
    "microsoftteams",
    "airtable",
    "alibaba",
    "circleci",
    "digitalocean",
    "fastly",
    "hubspot",
    "ibmcloud",
    "sendgrid",
    "sendinblue",
    "stripe",
    "terraform",
    "square",
    "jira",
    "mysql",
    "algolia",
    "auth0",
    "paypal",
    "plaid",
    "shopify",
    "zendesk",
    "artifactory",
    "xray",
    "monday",
    "asana",
    "pinecone",
];

fn access_map_provider_parser() -> impl TypedValueParser<Value = AccessMapProvider> {
    PossibleValuesParser::new(access_map_provider_values()).map(|raw| {
        parse_access_map_provider(&raw)
            .expect("access-map provider possible values must parse successfully")
    })
}

fn access_map_provider_values() -> Vec<PossibleValue> {
    vec![
        PossibleValue::new("aws"),
        PossibleValue::new("gcp"),
        PossibleValue::new("azure"),
        PossibleValue::new("github"),
        PossibleValue::new("gitlab"),
        PossibleValue::new("slack"),
        PossibleValue::new("postgres"),
        PossibleValue::new("mongodb").alias("mongo"),
        PossibleValue::new("huggingface").alias("hf"),
        PossibleValue::new("gitea"),
        PossibleValue::new("bitbucket"),
        PossibleValue::new("buildkite"),
        PossibleValue::new("harness"),
        PossibleValue::new("openai"),
        PossibleValue::new("anthropic"),
        PossibleValue::new("salesforce"),
        PossibleValue::new("weightsandbiases").aliases(["weights-and-biases", "wandb"]),
        PossibleValue::new("microsoftteams").aliases(["microsoft-teams", "msteams"]),
        PossibleValue::new("airtable"),
        PossibleValue::new("alibaba").alias("aliyun"),
        PossibleValue::new("circleci"),
        PossibleValue::new("digitalocean").aliases(["digital-ocean", "do"]),
        PossibleValue::new("fastly"),
        PossibleValue::new("hubspot").alias("hub-spot"),
        PossibleValue::new("ibmcloud").aliases(["ibm-cloud", "ibm"]),
        PossibleValue::new("sendgrid").alias("send-grid"),
        PossibleValue::new("sendinblue").aliases(["send-in-blue", "brevo"]),
        PossibleValue::new("stripe"),
        PossibleValue::new("terraform").alias("tfc"),
        PossibleValue::new("square"),
        PossibleValue::new("jira"),
        PossibleValue::new("mysql"),
        PossibleValue::new("algolia"),
        PossibleValue::new("auth0"),
        PossibleValue::new("paypal").alias("pay-pal"),
        PossibleValue::new("plaid"),
        PossibleValue::new("shopify"),
        PossibleValue::new("zendesk"),
        PossibleValue::new("artifactory").alias("jfrog-art"),
        PossibleValue::new("xray").alias("jfrog-xray"),
        PossibleValue::new("monday").alias("monday.com"),
        PossibleValue::new("asana"),
        PossibleValue::new("pinecone").alias("pinecone.io"),
    ]
}

fn parse_access_map_provider(raw: &str) -> Result<AccessMapProvider, String> {
    AccessMapProvider::from_str(raw)
}
