use std::collections::BTreeMap;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;

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
pub(crate) mod report;
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
    let result = dispatch_cli_request(&args).await?;

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

type AccessMapResultFuture<'a> = Pin<Box<dyn Future<Output = Result<AccessMapResult>> + Send + 'a>>;
type MappedRequestFuture = Pin<Box<dyn Future<Output = (AccessMapAttempt, String)> + Send>>;

fn dispatch_cli_request(args: &AccessMapArgs) -> AccessMapResultFuture<'_> {
    match &args.provider {
        AccessMapProvider::Gcp => Box::pin(gcp::map_access(args.credential_path.as_deref())),
        AccessMapProvider::Aws => Box::pin(aws::map_access(args)),
        AccessMapProvider::Azure => Box::pin(azure::map_access(args)),
        AccessMapProvider::Github => Box::pin(github::map_access(args)),
        AccessMapProvider::Gitlab => Box::pin(gitlab::map_access(args)),
        AccessMapProvider::Slack => Box::pin(slack::map_access(args)),
        AccessMapProvider::Postgres => Box::pin(postgres::map_access(args)),
        AccessMapProvider::Mongodb => Box::pin(mongodb::map_access(args)),
        AccessMapProvider::Huggingface => Box::pin(huggingface::map_access(args)),
        AccessMapProvider::Gitea => Box::pin(gitea::map_access(args)),
        AccessMapProvider::Bitbucket => Box::pin(bitbucket::map_access(args)),
        AccessMapProvider::Buildkite => Box::pin(buildkite::map_access(args)),
        AccessMapProvider::Harness => Box::pin(harness::map_access(args)),
        AccessMapProvider::Openai => Box::pin(openai::map_access(args)),
        AccessMapProvider::Anthropic => Box::pin(anthropic::map_access(args)),
        AccessMapProvider::Salesforce => Box::pin(salesforce::map_access(args)),
        AccessMapProvider::Weightsandbiases => Box::pin(weightsandbiases::map_access(args)),
        AccessMapProvider::Microsoftteams => Box::pin(microsoft_teams::map_access(args)),
        AccessMapProvider::Airtable => Box::pin(airtable::map_access(args)),
        AccessMapProvider::Alibaba => Box::pin(alibaba::map_access(args)),
        AccessMapProvider::Circleci => Box::pin(circleci::map_access(args)),
        AccessMapProvider::Digitalocean => Box::pin(digitalocean::map_access(args)),
        AccessMapProvider::Fastly => Box::pin(fastly::map_access(args)),
        AccessMapProvider::Hubspot => Box::pin(hubspot::map_access(args)),
        AccessMapProvider::Ibmcloud => Box::pin(ibm_cloud::map_access(args)),
        AccessMapProvider::Sendgrid => Box::pin(sendgrid::map_access(args)),
        AccessMapProvider::Sendinblue => Box::pin(sendinblue::map_access(args)),
        AccessMapProvider::Stripe => Box::pin(stripe::map_access(args)),
        AccessMapProvider::Terraform => Box::pin(terraform::map_access(args)),
        AccessMapProvider::Square => Box::pin(square::map_access(args)),
        AccessMapProvider::Jira => Box::pin(jira::map_access(args)),
        AccessMapProvider::Mysql => Box::pin(mysql::map_access(args)),
        AccessMapProvider::Algolia => Box::pin(algolia::map_access(args)),
        AccessMapProvider::Auth0 => Box::pin(auth0::map_access(args)),
        AccessMapProvider::Paypal => Box::pin(paypal::map_access(args)),
        AccessMapProvider::Plaid => Box::pin(plaid::map_access(args)),
        AccessMapProvider::Shopify => Box::pin(shopify::map_access(args)),
        AccessMapProvider::Zendesk => Box::pin(zendesk::map_access(args)),
        AccessMapProvider::Artifactory => Box::pin(artifactory::map_access(args)),
        AccessMapProvider::Xray => Box::pin(xray::map_access(args)),
        AccessMapProvider::Monday => Box::pin(monday::map_access(args)),
        AccessMapProvider::Asana => Box::pin(asana::map_access(args)),
        AccessMapProvider::Pinecone => Box::pin(pinecone::map_access(args)),
    }
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
    /// An Azure Storage, Entra client-credential, or OAuth2 token document.
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

impl AccessMapRequest {
    /// Finding fingerprint attached to this credential occurrence.
    pub(crate) fn finding_fingerprint(&self) -> &str {
        match self {
            Self::Aws { fingerprint, .. }
            | Self::Gcp { fingerprint, .. }
            | Self::Azure { fingerprint, .. }
            | Self::AzureDevops { fingerprint, .. }
            | Self::Github { fingerprint, .. }
            | Self::Gitlab { fingerprint, .. }
            | Self::Slack { fingerprint, .. }
            | Self::Postgres { fingerprint, .. }
            | Self::MongoDB { fingerprint, .. }
            | Self::HuggingFace { fingerprint, .. }
            | Self::Gitea { fingerprint, .. }
            | Self::Bitbucket { fingerprint, .. }
            | Self::Buildkite { fingerprint, .. }
            | Self::Harness { fingerprint, .. }
            | Self::OpenAI { fingerprint, .. }
            | Self::Anthropic { fingerprint, .. }
            | Self::Salesforce { fingerprint, .. }
            | Self::WeightsAndBiases { fingerprint, .. }
            | Self::MicrosoftTeams { fingerprint, .. }
            | Self::Airtable { fingerprint, .. }
            | Self::Alibaba { fingerprint, .. }
            | Self::CircleCI { fingerprint, .. }
            | Self::DigitalOcean { fingerprint, .. }
            | Self::Fastly { fingerprint, .. }
            | Self::HubSpot { fingerprint, .. }
            | Self::IbmCloud { fingerprint, .. }
            | Self::SendGrid { fingerprint, .. }
            | Self::Sendinblue { fingerprint, .. }
            | Self::Stripe { fingerprint, .. }
            | Self::Terraform { fingerprint, .. }
            | Self::Square { fingerprint, .. }
            | Self::Jira { fingerprint, .. }
            | Self::MySQL { fingerprint, .. }
            | Self::Algolia { fingerprint, .. }
            | Self::Auth0 { fingerprint, .. }
            | Self::PayPal { fingerprint, .. }
            | Self::Plaid { fingerprint, .. }
            | Self::Shopify { fingerprint, .. }
            | Self::Zendesk { fingerprint, .. }
            | Self::Artifactory { fingerprint, .. }
            | Self::Xray { fingerprint, .. }
            | Self::Monday { fingerprint, .. }
            | Self::Asana { fingerprint, .. }
            | Self::Pinecone { fingerprint, .. } => fingerprint,
        }
    }
}

/// One credential mapping request plus every finding occurrence that supplied it.
#[derive(Clone, Debug)]
pub(crate) struct CollectedAccessMapRequest {
    pub request: AccessMapRequest,
    pub finding_fingerprints: Vec<String>,
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

#[derive(Debug)]
pub(crate) struct AccessMapAttempt {
    pub result: AccessMapResult,
    pub succeeded: bool,
}

/// Access-map output retained by scans together with alert correlation metadata.
#[derive(Debug, Clone)]
pub(crate) struct ScanAccessMapResult {
    pub result: AccessMapResult,
    pub finding_fingerprints: Vec<String>,
    pub mapping_succeeded: bool,
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
#[derive(Debug, Serialize, Clone, JsonSchema)]
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
    /// Read-only evidence explaining how permissions and identity paths were derived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_evidence: Option<AuthorizationEvidence>,
}

/// Provider-neutral evidence retained alongside a blast-radius result.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AuthorizationEvidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<PolicyEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<AuthorizationPath>,
    /// Roles reachable through the recorded identity paths and the policy grants they add.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub role_impacts: Vec<RoleImpact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hierarchy: Vec<HierarchyScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

/// Permissions and resource scopes added by a role reachable through an identity transition.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct RoleImpact {
    /// Optional identity reached before this role applies, such as an impersonated service account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Stable provider identifier for the role, such as an AWS role ARN.
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Strongest observed path status: `potential`, `conditional`, or `trust_only`.
    pub status: String,
    /// Hop count for the summarized strongest path status.
    pub hop_count: usize,
    /// Effective role permissions summarized from the visible identity policies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    /// Statement-level permission/resource pairs retained without flattening their scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<AuthorizationGrant>,
}

/// One policy grant that contributes to a reachable role's blast radius.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AuthorizationGrant {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

/// Metadata resolved for the credential's effective principal.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct PrincipalEvidence {
    pub id: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
}

/// One policy document or binding and the entity through which it applies.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct PolicyEvidence {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub kind: String,
    pub attached_to: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_via: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statements: Vec<AuthorizationStatement>,
}

/// A normalized, redacted authorization-policy statement.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AuthorizationStatement {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    pub effect: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_resources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_principals: Vec<String>,
    /// Condition operator and key names. Values are intentionally not retained in reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub condition_keys: Vec<String>,
}

/// An inbound or outbound authorization-capability path involving the credential identity.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AuthorizationPath {
    /// Direction relative to the credential identity: `outbound` or `inbound`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hops: Vec<AuthorizationHop>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<String>,
}

/// One relationship in an authorization path.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct AuthorizationHop {
    pub from: String,
    pub to: String,
    pub relationship: String,
}

/// One visible scope in a provider's resource hierarchy.
#[derive(Debug, Serialize, Clone, Default, JsonSchema)]
pub struct HierarchyScope {
    pub kind: String,
    pub id: String,
}

/// Map a batch of credentials to their effective identities.
pub async fn map_requests(requests: Vec<AccessMapRequest>) -> Vec<AccessMapResult> {
    map_request_attempts(requests).await.into_iter().map(|attempt| attempt.result).collect()
}

/// Map a batch of credentials while preserving whether each provider request succeeded.
pub(crate) async fn map_request_attempts(requests: Vec<AccessMapRequest>) -> Vec<AccessMapAttempt> {
    let mut results = Vec::new();

    for request in requests {
        let (mut attempt, fp) = dispatch_access_map_request(request).await;

        attempt.result.fingerprint = Some(fp);
        results.push(attempt);
    }

    results
}

/// Map deduplicated scan credentials while preserving every finding occurrence and whether
/// identity mapping actually succeeded. The public `map_requests` API intentionally retains its
/// existing result shape; scan alerting uses this richer internal path.
pub(crate) async fn map_collected_requests(
    requests: Vec<CollectedAccessMapRequest>,
) -> Vec<ScanAccessMapResult> {
    let mut results = Vec::with_capacity(requests.len());

    for collected in requests {
        let (mut attempt, primary_fingerprint) =
            dispatch_access_map_request(collected.request).await;
        let mut finding_fingerprints = collected.finding_fingerprints;
        finding_fingerprints.push(primary_fingerprint);
        finding_fingerprints.sort_unstable();
        finding_fingerprints.dedup();
        attempt.result.fingerprint = finding_fingerprints.first().cloned();
        results.push(ScanAccessMapResult {
            result: attempt.result,
            finding_fingerprints,
            mapping_succeeded: attempt.succeeded,
        });
    }

    results
}

fn finish_mapping(
    result: Result<AccessMapResult>,
    cloud: &str,
    identity_label: &str,
) -> AccessMapAttempt {
    match result {
        Ok(result) => AccessMapAttempt { result, succeeded: true },
        Err(err) => AccessMapAttempt {
            result: build_failed_result(cloud, identity_label, err),
            succeeded: false,
        },
    }
}

fn dispatch_access_map_request(request: AccessMapRequest) -> MappedRequestFuture {
    match request {
        AccessMapRequest::Aws { access_key, secret_key, session_token, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    aws::map_access_with_credentials(
                        &access_key,
                        &secret_key,
                        session_token.as_deref(),
                    )
                    .await,
                    "aws",
                    &access_key,
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::Gcp { credential_json, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                gcp::map_access_from_json(&credential_json).await,
                "gcp",
                "service_account",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Azure { credential_json, containers, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    azure::map_access_from_json_with_hints(&credential_json, containers.as_deref())
                        .await,
                    "azure",
                    "credential",
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::AzureDevops { token, organization, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    azure_devops::map_access_from_token(&token, &organization).await,
                    "azure_devops",
                    "pat",
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::Github { token, fingerprint } => {
            Box::pin(async move { (map_token(&GithubMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Gitlab { token, fingerprint } => {
            Box::pin(async move { (map_token(&GitlabMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Slack { token, fingerprint } => {
            Box::pin(async move { (map_token(&SlackMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Postgres { uri, fingerprint } => Box::pin(async move {
            let mapped =
                finish_mapping(postgres::map_access_from_uri(&uri).await, "postgres", "uri");
            (mapped, fingerprint)
        }),
        AccessMapRequest::MongoDB { uri, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(mongodb::map_access_from_uri(&uri).await, "mongodb", "uri");
            (mapped, fingerprint)
        }),
        AccessMapRequest::HuggingFace { token, fingerprint } => {
            Box::pin(async move { (map_token(&HuggingFaceMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Gitea { token, fingerprint } => {
            Box::pin(async move { (map_token(&GiteaMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Bitbucket { token, fingerprint } => {
            Box::pin(async move { (map_token(&BitbucketMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Buildkite { token, fingerprint } => {
            Box::pin(async move { (map_token(&BuildkiteMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Harness { token, fingerprint } => {
            Box::pin(async move { (map_token(&HarnessMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::OpenAI { token, fingerprint } => {
            Box::pin(async move { (map_token(&OpenAiMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Anthropic { token, fingerprint } => {
            Box::pin(async move { (map_token(&AnthropicMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Salesforce { token, instance, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                salesforce::map_access_from_token_and_instance(&token, &instance).await,
                "salesforce",
                "token",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::WeightsAndBiases { token, fingerprint } => {
            Box::pin(async move { (map_token(&WeightsAndBiasesMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::MicrosoftTeams { webhook_url, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                microsoft_teams::map_access_from_webhook_url(&webhook_url).await,
                "microsoft_teams",
                "webhook",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Airtable { token, fingerprint } => {
            Box::pin(async move { (map_token(&AirtableMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Alibaba { access_key, secret_key, session_token, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    alibaba::map_access_with_credentials(
                        &access_key,
                        &secret_key,
                        session_token.as_deref(),
                    )
                    .await,
                    "alibaba",
                    &access_key,
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::CircleCI { token, fingerprint } => {
            Box::pin(async move { (map_token(&CircleCiMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::DigitalOcean { token, fingerprint } => {
            Box::pin(async move { (map_token(&DigitalOceanMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Fastly { token, fingerprint } => {
            Box::pin(async move { (map_token(&FastlyMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::HubSpot { token, fingerprint } => {
            Box::pin(async move { (map_token(&HubSpotMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::IbmCloud { token, fingerprint } => {
            Box::pin(async move { (map_token(&IbmCloudMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::SendGrid { token, fingerprint } => {
            Box::pin(async move { (map_token(&SendGridMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Sendinblue { token, fingerprint } => {
            Box::pin(async move { (map_token(&SendinblueMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Stripe { token, fingerprint } => {
            Box::pin(async move { (map_token(&StripeMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Terraform { token, fingerprint } => {
            Box::pin(async move { (map_token(&TerraformMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Square { token, fingerprint } => {
            Box::pin(async move { (map_token(&SquareMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Jira { token, base_url, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                jira::map_access_from_token_and_url(&token, &base_url).await,
                "jira",
                "token",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::MySQL { uri, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(mysql::map_access_from_uri(&uri).await, "mysql", "uri");
            (mapped, fingerprint)
        }),
        AccessMapRequest::Algolia { app_id, api_key, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                algolia::map_access_from_credentials(&app_id, &api_key).await,
                "algolia",
                &app_id,
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Auth0 { client_id, client_secret, domain, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    auth0::map_access_from_credentials(&client_id, &client_secret, &domain).await,
                    "auth0",
                    &client_id,
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::PayPal { client_id, client_secret, fingerprint } => {
            Box::pin(async move {
                let mapped = finish_mapping(
                    paypal::map_access_from_credentials(&client_id, &client_secret).await,
                    "paypal",
                    &client_id,
                );
                (mapped, fingerprint)
            })
        }
        AccessMapRequest::Plaid { client_id, secret, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                plaid::map_access_from_credentials(&client_id, &secret).await,
                "plaid",
                &client_id,
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Shopify { token, subdomain, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                shopify::map_access_from_token_and_subdomain(&token, &subdomain).await,
                "shopify",
                &subdomain,
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Zendesk { token, subdomain, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                zendesk::map_access_from_token_and_subdomain(&token, &subdomain).await,
                "zendesk",
                &subdomain,
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Artifactory { token, base_url, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                match base_url {
                    Some(url) => artifactory::map_access_from_token_and_url(&token, &url).await,
                    None => artifactory::map_access_from_token(&token).await,
                },
                "artifactory",
                "token",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Xray { token, base_url, fingerprint } => Box::pin(async move {
            let mapped = finish_mapping(
                match base_url {
                    Some(url) => xray::map_access_from_token_and_url(&token, &url).await,
                    None => xray::map_access_from_token(&token).await,
                },
                "jfrog_xray",
                "token",
            );
            (mapped, fingerprint)
        }),
        AccessMapRequest::Monday { token, fingerprint } => {
            Box::pin(async move { (map_token(&MondayMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Asana { token, fingerprint } => {
            Box::pin(async move { (map_token(&AsanaMapper, &token).await, fingerprint) })
        }
        AccessMapRequest::Pinecone { token, fingerprint } => {
            Box::pin(async move { (map_token(&PineconeMapper, &token).await, fingerprint) })
        }
    }
}

/// Maps a token credential using a `TokenAccessMapper`, retaining explicit success state.
async fn map_token(mapper: &impl TokenAccessMapper, token: &str) -> AccessMapAttempt {
    finish_mapping(mapper.map_access_from_token(token).await, mapper.cloud_name(), "token")
}

/// Write HTML/JSON outputs for a collection of identity map results.
pub fn write_reports(results: &[AccessMapResult], html_out: &std::path::Path) -> Result<()> {
    report::generate_html_report_multi(results, html_out)?;
    Ok(())
}

/// Map a provider credential without writing its result to an output stream.
pub async fn map_credential(args: &AccessMapArgs) -> Result<AccessMapResult> {
    dispatch_cli_request(args).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_metadata_omits_empty_authorization_evidence() {
        let metadata = ProviderMetadata::default();
        let json = serde_json::to_value(metadata).unwrap();

        assert!(json.get("authorization_evidence").is_none());
    }

    #[test]
    fn authorization_evidence_serializes_ordered_identity_path() {
        let metadata = ProviderMetadata {
            version: None,
            enterprise: None,
            authorization_evidence: Some(AuthorizationEvidence {
                paths: vec![AuthorizationPath {
                    direction: Some("outbound".into()),
                    status: "potential".into(),
                    hops: vec![
                        AuthorizationHop {
                            from: "source".into(),
                            to: "intermediate".into(),
                            relationship: "can_assume_role".into(),
                        },
                        AuthorizationHop {
                            from: "intermediate".into(),
                            to: "target".into(),
                            relationship: "can_assume_role".into(),
                        },
                    ],
                    evidence: vec!["policy#allow".into()],
                    conditions: Vec::new(),
                }],
                role_impacts: vec![RoleImpact {
                    target: Some("intermediate".into()),
                    role: "target".into(),
                    name: Some("TargetRole".into()),
                    status: "potential".into(),
                    hop_count: 2,
                    permissions: vec!["s3.getobject".into()],
                    grants: vec![AuthorizationGrant {
                        permissions: vec!["s3.getobject".into()],
                        resources: vec!["arn:aws:s3:::example/*".into()],
                        evidence: vec!["policy#objects".into()],
                        ..AuthorizationGrant::default()
                    }],
                }],
                ..AuthorizationEvidence::default()
            }),
        };

        let json = serde_json::to_value(metadata).unwrap();
        let hops = json["authorization_evidence"]["paths"][0]["hops"].as_array().unwrap();
        assert_eq!(hops[0]["from"], "source");
        assert_eq!(hops[1]["to"], "target");
        assert_eq!(
            json["authorization_evidence"]["role_impacts"][0]["grants"][0]["resources"][0],
            "arn:aws:s3:::example/*"
        );
    }
}

// /// Fallback handler for unsupported providers.
// async fn unsupported_provider(provider: &AccessMapProvider) -> Result<AccessMapResult> {
//     bail!("Identity mapping for {:?} is not implemented", provider)
// }
