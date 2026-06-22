use std::io::Write;

use anyhow::Result;
use schemars::JsonSchema;
use serde::Serialize;

use crate::cli::commands::access_map::{AccessMapArgs, AccessMapOutputFormat, AccessMapProvider};

mod airtable;
mod algolia;
mod alibaba;
mod anthropic;
mod artifactory;
mod asana;
mod auth0;
mod aws;
mod azure;
mod azure_devops;
mod bitbucket;
mod buildkite;
mod circleci;
mod digitalocean;
mod fastly;
mod gcp;
mod gitea;
mod github;
mod gitlab;
mod harness;
mod hubspot;
mod huggingface;
mod ibm_cloud;
mod jira;
mod microsoft_teams;
mod monday;
pub(crate) mod mongodb;
pub(crate) mod mysql;
mod openai;
mod paypal;
mod pinecone;
mod plaid;
pub(crate) mod postgres;
mod report;
mod salesforce;
mod sendgrid;
mod sendinblue;
mod shopify;
mod slack;
mod square;
mod stripe;
mod terraform;
mod weightsandbiases;
mod xray;
mod zendesk;

/// Trait for access map providers that map a single token to an access profile.
///
/// This covers the majority of providers (GitHub, GitLab, Slack, HuggingFace,
/// Gitea, Bitbucket). Providers with more complex credentials (AWS, GCP, Azure,
/// Postgres, MongoDB) use their own custom interfaces.
pub trait TokenAccessMapper: Send + Sync {
    /// The cloud/platform name for results (e.g., `"github"`, `"slack"`).
    fn cloud_name(&self) -> &'static str;

    /// Maps a single token to an access map result.
    fn map_access_from_token(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<AccessMapResult>> + Send;
}

/// Run the identity mapping workflow for the selected cloud provider.
pub async fn run(args: AccessMapArgs) -> Result<()> {
    let result = match args.provider {
        AccessMapProvider::Gcp => gcp::map_access(args.credential_path.as_deref()).await?,
        AccessMapProvider::Aws => aws::map_access(&args).await?,
        AccessMapProvider::Azure => azure::map_access(&args).await?,
        AccessMapProvider::Github => github::map_access(&args).await?,
        AccessMapProvider::Gitlab => gitlab::map_access(&args).await?,
        AccessMapProvider::Slack => slack::map_access(&args).await?,
        AccessMapProvider::Postgres => postgres::map_access(&args).await?,
        AccessMapProvider::Mongodb => mongodb::map_access(&args).await?,
        AccessMapProvider::Huggingface => huggingface::map_access(&args).await?,
        AccessMapProvider::Gitea => gitea::map_access(&args).await?,
        AccessMapProvider::Bitbucket => bitbucket::map_access(&args).await?,
        AccessMapProvider::Buildkite => buildkite::map_access(&args).await?,
        AccessMapProvider::Harness => harness::map_access(&args).await?,
        AccessMapProvider::Openai => openai::map_access(&args).await?,
        AccessMapProvider::Anthropic => anthropic::map_access(&args).await?,
        AccessMapProvider::Salesforce => salesforce::map_access(&args).await?,
        AccessMapProvider::Weightsandbiases => weightsandbiases::map_access(&args).await?,
        AccessMapProvider::Microsoftteams => microsoft_teams::map_access(&args).await?,
        AccessMapProvider::Airtable => airtable::map_access(&args).await?,
        AccessMapProvider::Alibaba => alibaba::map_access(&args).await?,
        AccessMapProvider::Circleci => circleci::map_access(&args).await?,
        AccessMapProvider::Digitalocean => digitalocean::map_access(&args).await?,
        AccessMapProvider::Fastly => fastly::map_access(&args).await?,
        AccessMapProvider::Hubspot => hubspot::map_access(&args).await?,
        AccessMapProvider::Ibmcloud => ibm_cloud::map_access(&args).await?,
        AccessMapProvider::Sendgrid => sendgrid::map_access(&args).await?,
        AccessMapProvider::Sendinblue => sendinblue::map_access(&args).await?,
        AccessMapProvider::Stripe => stripe::map_access(&args).await?,
        AccessMapProvider::Terraform => terraform::map_access(&args).await?,
        AccessMapProvider::Square => square::map_access(&args).await?,
        AccessMapProvider::Jira => jira::map_access(&args).await?,
        AccessMapProvider::Mysql => mysql::map_access(&args).await?,
        AccessMapProvider::Algolia => algolia::map_access(&args).await?,
        AccessMapProvider::Auth0 => auth0::map_access(&args).await?,
        AccessMapProvider::Paypal => paypal::map_access(&args).await?,
        AccessMapProvider::Plaid => plaid::map_access(&args).await?,
        AccessMapProvider::Shopify => shopify::map_access(&args).await?,
        AccessMapProvider::Zendesk => zendesk::map_access(&args).await?,
        AccessMapProvider::Artifactory => artifactory::map_access(&args).await?,
        AccessMapProvider::Xray => xray::map_access(&args).await?,
        AccessMapProvider::Monday => monday::map_access(&args).await?,
        AccessMapProvider::Asana => asana::map_access(&args).await?,
        AccessMapProvider::Pinecone => pinecone::map_access(&args).await?,
    };

    let mut writer = args.output_args.get_writer()?;
    match args.output_args.format {
        AccessMapOutputFormat::Json => {
            serde_json::to_writer_pretty(&mut writer, &result)?;
            writeln!(writer)?;
        }
        AccessMapOutputFormat::Html => {
            let html = report::render_html_report_multi(&[result])?;
            writer.write_all(html.as_bytes())?;
        }
    }

    Ok(())
}

/// A validated credential that can be mapped to an identity.
#[derive(Clone, Debug)]
pub enum AccessMapRequest {
    /// AWS access key credentials.
    Aws {
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        fingerprint: String,
    },
    /// A GCP service account JSON document.
    Gcp { credential_json: String, fingerprint: String },
    /// An Azure storage account JSON document.
    Azure { credential_json: String, containers: Option<Vec<String>>, fingerprint: String },
    /// An Azure DevOps personal access token with organization.
    AzureDevops { token: String, organization: String, fingerprint: String },
    /// A GitHub token.
    Github { token: String, fingerprint: String },
    /// A GitLab token.
    Gitlab { token: String, fingerprint: String },
    /// A Slack token.
    Slack { token: String, fingerprint: String },
    /// A Postgres connection URI.
    Postgres { uri: String, fingerprint: String },
    /// A MongoDB connection URI.
    MongoDB { uri: String, fingerprint: String },
    /// A Hugging Face token.
    HuggingFace { token: String, fingerprint: String },
    /// A Gitea token.
    Gitea { token: String, fingerprint: String },
    /// A Bitbucket token.
    Bitbucket { token: String, fingerprint: String },
    /// A Buildkite token.
    Buildkite { token: String, fingerprint: String },
    /// A Harness API token (x-api-key).
    Harness { token: String, fingerprint: String },
    /// An OpenAI API token.
    OpenAI { token: String, fingerprint: String },
    /// An Anthropic API token.
    Anthropic { token: String, fingerprint: String },
    /// A Salesforce access token plus instance domain.
    Salesforce { token: String, instance: String, fingerprint: String },
    /// A Weights & Biases API token.
    WeightsAndBiases { token: String, fingerprint: String },
    /// A Microsoft Teams Incoming Webhook URL.
    MicrosoftTeams { webhook_url: String, fingerprint: String },
    /// An Airtable API token.
    Airtable { token: String, fingerprint: String },
    /// Alibaba Cloud access key credentials.
    Alibaba {
        access_key: String,
        secret_key: String,
        session_token: Option<String>,
        fingerprint: String,
    },
    /// A CircleCI API token.
    CircleCI { token: String, fingerprint: String },
    /// A DigitalOcean API token.
    DigitalOcean { token: String, fingerprint: String },
    /// A Fastly API token.
    Fastly { token: String, fingerprint: String },
    /// A HubSpot API token.
    HubSpot { token: String, fingerprint: String },
    /// An IBM Cloud API key.
    IbmCloud { token: String, fingerprint: String },
    /// A SendGrid API token.
    SendGrid { token: String, fingerprint: String },
    /// A Brevo (Sendinblue) API token.
    Sendinblue { token: String, fingerprint: String },
    /// A Stripe API key.
    Stripe { token: String, fingerprint: String },
    /// A Terraform Cloud API token.
    Terraform { token: String, fingerprint: String },
    /// A Square API token.
    Square { token: String, fingerprint: String },
    /// A Jira API token with base URL.
    Jira { token: String, base_url: String, fingerprint: String },
    /// A MySQL connection URI.
    MySQL { uri: String, fingerprint: String },
    /// An Algolia app_id + api_key pair.
    Algolia { app_id: String, api_key: String, fingerprint: String },
    /// Auth0 client credentials (client_id + client_secret + domain).
    Auth0 { client_id: String, client_secret: String, domain: String, fingerprint: String },
    /// PayPal client credentials (client_id + client_secret).
    PayPal { client_id: String, client_secret: String, fingerprint: String },
    /// Plaid API credentials (client_id + secret).
    Plaid { client_id: String, secret: String, fingerprint: String },
    /// A Shopify access token with store subdomain.
    Shopify { token: String, subdomain: String, fingerprint: String },
    /// A Zendesk API token with subdomain.
    Zendesk { token: String, subdomain: String, fingerprint: String },
    /// A JFrog Artifactory token with optional base URL.
    Artifactory { token: String, base_url: Option<String>, fingerprint: String },
    /// A JFrog Xray token with optional base URL.
    Xray { token: String, base_url: Option<String>, fingerprint: String },
    /// A monday.com API token.
    Monday { token: String, fingerprint: String },
    /// An Asana personal access token / OAuth token.
    Asana { token: String, fingerprint: String },
    /// A Pinecone API key.
    Pinecone { token: String, fingerprint: String },
}

/// Structured output describing the resolved identity and its risk profile.
#[derive(Debug, Serialize, Clone)]
pub struct AccessMapResult {
    /// Cloud name such as "gcp", "aws", or "azure".
    pub cloud: String,

    /// Unique fingerprint of the finding.
    pub fingerprint: Option<String>,

    /// Summary of the resolved identity.
    pub identity: AccessSummary,

    /// Roles or bindings directly associated with the identity.
    pub roles: Vec<RoleBinding>,
    /// Aggregated permission findings.
    pub permissions: PermissionSummary,

    /// Resources impacted by the credential.
    pub resources: Vec<ResourceExposure>,

    /// Overall severity score.
    pub severity: Severity,
    /// Guidance for remediation.
    pub recommendations: Vec<String>,
    /// Additional risk notes derived from permissions and impersonation exposure.
    pub risk_notes: Vec<String>,

    /// Optional access token metadata (for GitHub/GitLab).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_details: Option<AccessTokenDetails>,
    /// Optional provider metadata (for GitLab instance details, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_metadata: Option<ProviderMetadata>,
}

/// Identity details such as email or ARN.
#[derive(Debug, Serialize, Clone)]
pub struct AccessSummary {
    /// A stable identifier for the identity (email, ARN, or SPN).
    pub id: String,
    /// Identity type such as service account or user.
    pub access_type: String,
    /// Optional project or subscription identifier.
    pub project: Option<String>,
    /// Optional tenant identifier.
    pub tenant: Option<String>,
    /// Optional AWS-style account identifier.
    pub account_id: Option<String>,
}

/// A single role or binding and its permissions.
#[derive(Debug, Serialize, Clone)]
pub struct RoleBinding {
    /// Name of the role (for example, `roles/editor`).
    pub name: String,
    /// Source of the role (direct, inherited, etc.).
    pub source: String,
    /// Expanded permissions associated with the role.
    pub permissions: Vec<String>,
}

/// Summarized permissions grouped by risk profile.
#[derive(Debug, Serialize, Default, Clone, JsonSchema)]
pub struct PermissionSummary {
    /// Administrator or owner-level permissions.
    pub admin: Vec<String>,
    /// Permissions that allow privilege escalation.
    pub privilege_escalation: Vec<String>,
    /// Risky permissions with broad or sensitive access.
    pub risky: Vec<String>,
    /// Lower-risk read-only permissions.
    pub read_only: Vec<String>,
}

impl PermissionSummary {
    pub fn is_empty(&self) -> bool {
        self.admin.is_empty()
            && self.privilege_escalation.is_empty()
            && self.risky.is_empty()
            && self.read_only.is_empty()
    }

    pub fn total(&self) -> usize {
        self.admin.len() + self.privilege_escalation.len() + self.risky.len() + self.read_only.len()
    }
}

/// Exposed resources and their assessed risk.
#[derive(Debug, Serialize, Clone)]
pub struct ResourceExposure {
    /// Resource type such as project or bucket.
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Permissions that grant visibility or access to the resource.
    pub permissions: Vec<String>,
    /// Risk level.
    pub risk: String,
    /// Human-readable justification.
    pub reason: String,
}

/// Severity classification for the credential.
#[derive(Debug, Serialize, Clone, Copy)]
pub enum Severity {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
    /// Critical risk.
    Critical,
}

/// Optional metadata for access tokens.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AccessTokenDetails {
    pub name: Option<String>,
    pub username: Option<String>,
    pub account_type: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub url: Option<String>,
    pub token_type: Option<String>,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub scopes: Vec<String>,
}

/// Optional metadata about the provider instance.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct ProviderMetadata {
    pub version: Option<String>,
    pub enterprise: Option<bool>,
}

/// Map a batch of credentials to their effective identities.
pub async fn map_requests(requests: Vec<AccessMapRequest>) -> Vec<AccessMapResult> {
    let mut results = Vec::new();

    for request in requests {
        let (mut mapped, fp) = match request {
            AccessMapRequest::Aws { access_key, secret_key, session_token, fingerprint } => (
                aws::map_access_with_credentials(
                    &access_key,
                    &secret_key,
                    session_token.as_deref(),
                )
                .await
                .unwrap_or_else(|err| build_failed_result("aws", &access_key, err)),
                fingerprint,
            ),
            AccessMapRequest::Gcp { credential_json, fingerprint } => (
                gcp::map_access_from_json(&credential_json)
                    .await
                    .unwrap_or_else(|err| build_failed_result("gcp", "service_account", err)),
                fingerprint,
            ),
            AccessMapRequest::Azure { credential_json, containers, fingerprint } => (
                azure::map_access_from_json_with_hints(&credential_json, containers.as_deref())
                    .await
                    .unwrap_or_else(|err| build_failed_result("azure", "storage_account", err)),
                fingerprint,
            ),
            AccessMapRequest::AzureDevops { token, organization, fingerprint } => (
                azure_devops::map_access_from_token(&token, &organization)
                    .await
                    .unwrap_or_else(|err| build_failed_result("azure_devops", "pat", err)),
                fingerprint,
            ),
            AccessMapRequest::Github { token, fingerprint } => {
                (map_token(&GithubMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Gitlab { token, fingerprint } => {
                (map_token(&GitlabMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Slack { token, fingerprint } => {
                (map_token(&SlackMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Postgres { uri, fingerprint } => (
                postgres::map_access_from_uri(&uri)
                    .await
                    .unwrap_or_else(|err| build_failed_result("postgres", "uri", err)),
                fingerprint,
            ),
            AccessMapRequest::MongoDB { uri, fingerprint } => (
                mongodb::map_access_from_uri(&uri)
                    .await
                    .unwrap_or_else(|err| build_failed_result("mongodb", "uri", err)),
                fingerprint,
            ),
            AccessMapRequest::HuggingFace { token, fingerprint } => {
                (map_token(&HuggingFaceMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Gitea { token, fingerprint } => {
                (map_token(&GiteaMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Bitbucket { token, fingerprint } => {
                (map_token(&BitbucketMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Buildkite { token, fingerprint } => {
                (map_token(&BuildkiteMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Harness { token, fingerprint } => {
                (map_token(&HarnessMapper, &token).await, fingerprint)
            }
            AccessMapRequest::OpenAI { token, fingerprint } => {
                (map_token(&OpenAiMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Anthropic { token, fingerprint } => {
                (map_token(&AnthropicMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Salesforce { token, instance, fingerprint } => (
                salesforce::map_access_from_token_and_instance(&token, &instance)
                    .await
                    .unwrap_or_else(|err| build_failed_result("salesforce", "token", err)),
                fingerprint,
            ),
            AccessMapRequest::WeightsAndBiases { token, fingerprint } => {
                (map_token(&WeightsAndBiasesMapper, &token).await, fingerprint)
            }
            AccessMapRequest::MicrosoftTeams { webhook_url, fingerprint } => (
                microsoft_teams::map_access_from_webhook_url(&webhook_url)
                    .await
                    .unwrap_or_else(|err| build_failed_result("microsoft_teams", "webhook", err)),
                fingerprint,
            ),
            AccessMapRequest::Airtable { token, fingerprint } => {
                (map_token(&AirtableMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Alibaba { access_key, secret_key, session_token, fingerprint } => (
                alibaba::map_access_with_credentials(
                    &access_key,
                    &secret_key,
                    session_token.as_deref(),
                )
                .await
                .unwrap_or_else(|err| build_failed_result("alibaba", &access_key, err)),
                fingerprint,
            ),
            AccessMapRequest::CircleCI { token, fingerprint } => {
                (map_token(&CircleCiMapper, &token).await, fingerprint)
            }
            AccessMapRequest::DigitalOcean { token, fingerprint } => {
                (map_token(&DigitalOceanMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Fastly { token, fingerprint } => {
                (map_token(&FastlyMapper, &token).await, fingerprint)
            }
            AccessMapRequest::HubSpot { token, fingerprint } => {
                (map_token(&HubSpotMapper, &token).await, fingerprint)
            }
            AccessMapRequest::IbmCloud { token, fingerprint } => {
                (map_token(&IbmCloudMapper, &token).await, fingerprint)
            }
            AccessMapRequest::SendGrid { token, fingerprint } => {
                (map_token(&SendGridMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Sendinblue { token, fingerprint } => {
                (map_token(&SendinblueMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Stripe { token, fingerprint } => {
                (map_token(&StripeMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Terraform { token, fingerprint } => {
                (map_token(&TerraformMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Square { token, fingerprint } => {
                (map_token(&SquareMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Jira { token, base_url, fingerprint } => (
                jira::map_access_from_token_and_url(&token, &base_url)
                    .await
                    .unwrap_or_else(|err| build_failed_result("jira", "token", err)),
                fingerprint,
            ),
            AccessMapRequest::MySQL { uri, fingerprint } => (
                mysql::map_access_from_uri(&uri)
                    .await
                    .unwrap_or_else(|err| build_failed_result("mysql", "uri", err)),
                fingerprint,
            ),
            AccessMapRequest::Algolia { app_id, api_key, fingerprint } => (
                algolia::map_access_from_credentials(&app_id, &api_key)
                    .await
                    .unwrap_or_else(|err| build_failed_result("algolia", &app_id, err)),
                fingerprint,
            ),
            AccessMapRequest::Auth0 { client_id, client_secret, domain, fingerprint } => (
                auth0::map_access_from_credentials(&client_id, &client_secret, &domain)
                    .await
                    .unwrap_or_else(|err| build_failed_result("auth0", &client_id, err)),
                fingerprint,
            ),
            AccessMapRequest::PayPal { client_id, client_secret, fingerprint } => (
                paypal::map_access_from_credentials(&client_id, &client_secret)
                    .await
                    .unwrap_or_else(|err| build_failed_result("paypal", &client_id, err)),
                fingerprint,
            ),
            AccessMapRequest::Plaid { client_id, secret, fingerprint } => (
                plaid::map_access_from_credentials(&client_id, &secret)
                    .await
                    .unwrap_or_else(|err| build_failed_result("plaid", &client_id, err)),
                fingerprint,
            ),
            AccessMapRequest::Shopify { token, subdomain, fingerprint } => (
                shopify::map_access_from_token_and_subdomain(&token, &subdomain)
                    .await
                    .unwrap_or_else(|err| build_failed_result("shopify", &subdomain, err)),
                fingerprint,
            ),
            AccessMapRequest::Zendesk { token, subdomain, fingerprint } => (
                zendesk::map_access_from_token_and_subdomain(&token, &subdomain)
                    .await
                    .unwrap_or_else(|err| build_failed_result("zendesk", &subdomain, err)),
                fingerprint,
            ),
            AccessMapRequest::Artifactory { token, base_url, fingerprint } => {
                let res: Result<AccessMapResult> = match base_url {
                    Some(url) => artifactory::map_access_from_token_and_url(&token, &url).await,
                    None => artifactory::map_access_from_token(&token).await,
                };
                (
                    res.unwrap_or_else(|err| build_failed_result("artifactory", "token", err)),
                    fingerprint,
                )
            }
            AccessMapRequest::Xray { token, base_url, fingerprint } => {
                let res: Result<AccessMapResult> = match base_url {
                    Some(url) => xray::map_access_from_token_and_url(&token, &url).await,
                    None => xray::map_access_from_token(&token).await,
                };
                (
                    res.unwrap_or_else(|err| build_failed_result("jfrog_xray", "token", err)),
                    fingerprint,
                )
            }
            AccessMapRequest::Monday { token, fingerprint } => {
                (map_token(&MondayMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Asana { token, fingerprint } => {
                (map_token(&AsanaMapper, &token).await, fingerprint)
            }
            AccessMapRequest::Pinecone { token, fingerprint } => {
                (map_token(&PineconeMapper, &token).await, fingerprint)
            }
        };

        mapped.fingerprint = Some(fp);
        results.push(mapped);
    }

    results
}

/// Maps a token credential using a `TokenAccessMapper`, with fallback error handling.
async fn map_token(mapper: &impl TokenAccessMapper, token: &str) -> AccessMapResult {
    mapper
        .map_access_from_token(token)
        .await
        .unwrap_or_else(|err| build_failed_result(mapper.cloud_name(), "token", err))
}

/// Write HTML/JSON outputs for a collection of identity map results.
pub fn write_reports(results: &[AccessMapResult], html_out: &std::path::Path) -> Result<()> {
    report::generate_html_report_multi(results, html_out)?;
    Ok(())
}

// -------------------------------------------------------------------------------------------------
// TokenAccessMapper implementations
// -------------------------------------------------------------------------------------------------

/// GitHub access mapper.
pub struct GithubMapper;

impl TokenAccessMapper for GithubMapper {
    fn cloud_name(&self) -> &'static str {
        "github"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        github::map_access_from_token(token).await
    }
}

/// GitLab access mapper.
pub struct GitlabMapper;

impl TokenAccessMapper for GitlabMapper {
    fn cloud_name(&self) -> &'static str {
        "gitlab"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        gitlab::map_access_from_token(token).await
    }
}

/// Slack access mapper.
pub struct SlackMapper;

impl TokenAccessMapper for SlackMapper {
    fn cloud_name(&self) -> &'static str {
        "slack"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        slack::map_access_from_token(token).await
    }
}

/// HuggingFace access mapper.
pub struct HuggingFaceMapper;

impl TokenAccessMapper for HuggingFaceMapper {
    fn cloud_name(&self) -> &'static str {
        "huggingface"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        huggingface::map_access_from_token(token).await
    }
}

/// Gitea access mapper.
pub struct GiteaMapper;

impl TokenAccessMapper for GiteaMapper {
    fn cloud_name(&self) -> &'static str {
        "gitea"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        gitea::map_access_from_token(token).await
    }
}

/// Bitbucket access mapper.
pub struct BitbucketMapper;

impl TokenAccessMapper for BitbucketMapper {
    fn cloud_name(&self) -> &'static str {
        "bitbucket"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        bitbucket::map_access_from_token(token).await
    }
}

/// Buildkite access mapper.
pub struct BuildkiteMapper;

impl TokenAccessMapper for BuildkiteMapper {
    fn cloud_name(&self) -> &'static str {
        "buildkite"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        buildkite::map_access_from_token(token).await
    }
}

/// Harness access mapper.
pub struct HarnessMapper;

impl TokenAccessMapper for HarnessMapper {
    fn cloud_name(&self) -> &'static str {
        "harness"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        harness::map_access_from_token(token).await
    }
}

/// OpenAI access mapper.
pub struct OpenAiMapper;

impl TokenAccessMapper for OpenAiMapper {
    fn cloud_name(&self) -> &'static str {
        "openai"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        openai::map_access_from_token(token).await
    }
}

/// Anthropic access mapper.
pub struct AnthropicMapper;

impl TokenAccessMapper for AnthropicMapper {
    fn cloud_name(&self) -> &'static str {
        "anthropic"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        anthropic::map_access_from_token(token).await
    }
}

/// Weights & Biases access mapper.
pub struct WeightsAndBiasesMapper;

impl TokenAccessMapper for WeightsAndBiasesMapper {
    fn cloud_name(&self) -> &'static str {
        "weightsandbiases"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        weightsandbiases::map_access_from_token(token).await
    }
}

/// Airtable access mapper.
pub struct AirtableMapper;

impl TokenAccessMapper for AirtableMapper {
    fn cloud_name(&self) -> &'static str {
        "airtable"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        airtable::map_access_from_token(token).await
    }
}

/// CircleCI access mapper.
pub struct CircleCiMapper;

impl TokenAccessMapper for CircleCiMapper {
    fn cloud_name(&self) -> &'static str {
        "circleci"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        circleci::map_access_from_token(token).await
    }
}

/// DigitalOcean access mapper.
pub struct DigitalOceanMapper;

impl TokenAccessMapper for DigitalOceanMapper {
    fn cloud_name(&self) -> &'static str {
        "digitalocean"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        digitalocean::map_access_from_token(token).await
    }
}

/// Fastly access mapper.
pub struct FastlyMapper;

impl TokenAccessMapper for FastlyMapper {
    fn cloud_name(&self) -> &'static str {
        "fastly"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        fastly::map_access_from_token(token).await
    }
}

/// HubSpot access mapper.
pub struct HubSpotMapper;

impl TokenAccessMapper for HubSpotMapper {
    fn cloud_name(&self) -> &'static str {
        "hubspot"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        hubspot::map_access_from_token(token).await
    }
}

/// IBM Cloud access mapper.
pub struct IbmCloudMapper;

impl TokenAccessMapper for IbmCloudMapper {
    fn cloud_name(&self) -> &'static str {
        "ibm_cloud"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        ibm_cloud::map_access_from_token(token).await
    }
}

/// SendGrid access mapper.
pub struct SendGridMapper;

impl TokenAccessMapper for SendGridMapper {
    fn cloud_name(&self) -> &'static str {
        "sendgrid"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        sendgrid::map_access_from_token(token).await
    }
}

/// Sendinblue (Brevo) access mapper.
pub struct SendinblueMapper;

impl TokenAccessMapper for SendinblueMapper {
    fn cloud_name(&self) -> &'static str {
        "sendinblue"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        sendinblue::map_access_from_token(token).await
    }
}

/// Stripe access mapper.
pub struct StripeMapper;

impl TokenAccessMapper for StripeMapper {
    fn cloud_name(&self) -> &'static str {
        "stripe"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        stripe::map_access_from_token(token).await
    }
}

/// Terraform Cloud access mapper.
pub struct TerraformMapper;

impl TokenAccessMapper for TerraformMapper {
    fn cloud_name(&self) -> &'static str {
        "terraform"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        terraform::map_access_from_token(token).await
    }
}

/// Square access mapper.
pub struct SquareMapper;

impl TokenAccessMapper for SquareMapper {
    fn cloud_name(&self) -> &'static str {
        "square"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        square::map_access_from_token(token).await
    }
}

/// monday.com access mapper.
pub struct MondayMapper;

impl TokenAccessMapper for MondayMapper {
    fn cloud_name(&self) -> &'static str {
        "monday"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        monday::map_access_from_token(token).await
    }
}

/// Asana access mapper.
pub struct AsanaMapper;

impl TokenAccessMapper for AsanaMapper {
    fn cloud_name(&self) -> &'static str {
        "asana"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        asana::map_access_from_token(token).await
    }
}

/// Pinecone access mapper.
pub struct PineconeMapper;

impl TokenAccessMapper for PineconeMapper {
    fn cloud_name(&self) -> &'static str {
        "pinecone"
    }

    async fn map_access_from_token(&self, token: &str) -> Result<AccessMapResult> {
        pinecone::map_access_from_token(token).await
    }
}

// -------------------------------------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------------------------------------

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn build_failed_result(cloud: &str, identity_label: &str, err: anyhow::Error) -> AccessMapResult {
    AccessMapResult {
        cloud: cloud.to_string(),
        identity: AccessSummary {
            id: identity_label.to_string(),
            access_type: "unknown".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles: Vec::new(),
        permissions: PermissionSummary::default(),
        resources: vec![build_default_resource(None, Severity::Medium)],
        severity: Severity::Medium,
        recommendations: build_recommendations(Severity::Medium),
        risk_notes: vec![format!("Identity mapping failed: {err}")],
        token_details: None,
        provider_metadata: None,
        fingerprint: None,
    }
}

pub(crate) fn build_default_resource(
    project_id: Option<&str>,
    severity: Severity,
) -> ResourceExposure {
    ResourceExposure {
        resource_type: "project".into(),
        name: project_id.unwrap_or_default().into(),
        permissions: Vec::new(),
        risk: severity_to_str(severity).to_string(),
        reason: "Project containing the provided credential".into(),
    }
}

pub(crate) fn build_default_account_resource(
    account_id: Option<&str>,
    severity: Severity,
) -> ResourceExposure {
    ResourceExposure {
        resource_type: "account".into(),
        name: account_id.unwrap_or_default().into(),
        permissions: Vec::new(),
        risk: severity_to_str(severity).to_string(),
        reason: "AWS account linked to the provided credential".into(),
    }
}

pub(crate) fn build_recommendations(severity: Severity) -> Vec<String> {
    let mut recs = vec![
        "Rotate the credential and audit recent usage".to_string(),
        "Apply the principle of least privilege to attached roles".to_string(),
    ];

    match severity {
        Severity::Critical | Severity::High => {
            recs.push("Investigate blast radius and revoke unused bindings".to_string())
        }
        Severity::Medium => {
            recs.push("Review write-level permissions and tighten scopes".to_string())
        }
        Severity::Low => recs.push("Maintain monitoring for anomalous access".to_string()),
    }

    recs
}

// /// Fallback handler for unsupported providers.
// async fn unsupported_provider(provider: &AccessMapProvider) -> Result<AccessMapResult> {
//     bail!("Identity mapping for {:?} is not implemented", provider)
// }
