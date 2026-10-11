//! AWS credential validation via STS GetCallerIdentity.
//!
//! This module provides functionality to validate AWS access keys by making
//! an STS GetCallerIdentity call.

use super::limits::timeout;
use kingfisher_core::ValidationOutcome;
use std::{
    collections::HashSet,
    sync::{LazyLock, OnceLock, RwLock},
    time::Duration,
};

use anyhow::{Result, anyhow};
use aws_config::{BehaviorVersion, SdkConfig, retry::RetryConfig};
use aws_credential_types::Credentials;
use aws_sdk_iam::{
    Client as IamClient, config::Builder as IamConfigBuilder, error::SdkError as IamSdkError,
    types::StatusType,
};
use aws_sdk_sts::{
    Client as StsClient, config::Builder as StsConfigBuilder, error::SdkError,
    operation::get_caller_identity::GetCallerIdentityError,
};
use aws_smithy_http_client::{
    Builder as HttpClientBuilder, ConnectorBuilder, proxy::ProxyConfig, tls,
};
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        http::SharedHttpClient,
        interceptors::{Intercept, context::BeforeTransmitInterceptorContextMut},
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use aws_types::region::Region;
use base32::Alphabet;
use byteorder::{BigEndian, ByteOrder};
use http::{
    StatusCode,
    header::{HeaderValue, USER_AGENT},
};
use rand::{RngExt, rng};
use regex::Regex;
use serde::Serialize;
use tokio::{sync::Semaphore, time::sleep};

use super::GLOBAL_USER_AGENT;

static AWS_VALIDATION_SEMAPHORE: OnceLock<Semaphore> = OnceLock::new();

const AWS_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const AWS_IDENTITY_MAX_ATTEMPTS: usize = 3;
const AWS_DEFAULT_REGION: &str = "us-east-1";

/// Built-in list of known canary/honeypot AWS account IDs that should be skipped.
const BUILTIN_SKIP_ACCOUNT_IDS: &[&str] = &[
    "052310077262",
    "171436882533",
    "528757803018",
    "534261010715",
    "538784191382",
    "595918472158",
    "729780141977",
    "893192397702",
    "992382622183",
];

static AWS_SKIP_ACCOUNT_IDS: LazyLock<RwLock<HashSet<String>>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.extend(BUILTIN_SKIP_ACCOUNT_IDS.iter().map(|id| id.to_string()));
    RwLock::new(set)
});

fn build_http_client() -> SharedHttpClient {
    HttpClientBuilder::new().build_with_connector_fn(|settings, runtime_components| {
        let mut conn_builder = ConnectorBuilder::default()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::AwsLc));

        conn_builder.set_connector_settings(settings.cloned());
        if let Some(components) = runtime_components {
            conn_builder.set_sleep_impl(components.sleep_impl());
        }
        conn_builder.set_proxy_config(Some(ProxyConfig::from_env()));
        conn_builder.build()
    })
}

async fn build_base_config(credentials: Credentials) -> SdkConfig {
    build_base_config_with_region(credentials, AWS_DEFAULT_REGION).await
}

async fn build_base_config_with_region(credentials: Credentials, region: &str) -> SdkConfig {
    let retry_config = RetryConfig::adaptive().with_max_attempts(3);
    let loader = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(region.to_owned()))
        .credentials_provider(credentials)
        .http_client(build_http_client())
        .retry_config(retry_config);
    let loader = if super::limits::NetworkLimits::current().no_timeouts {
        loader.timeout_config(aws_smithy_types::timeout::TimeoutConfig::disabled())
            .stalled_stream_protection(aws_smithy_runtime_api::client::stalled_stream_protection::StalledStreamProtectionConfig::disabled())
    } else {
        loader
    };
    loader.load().await
}

fn extract_account_id(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.len() == 12 && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Some(trimmed.to_string());
    }

    static ACCOUNT_ID_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\d{12})").expect("valid regex"));
    ACCOUNT_ID_RE.captures(trimmed).and_then(|caps| caps.get(1)).map(|m| m.as_str().to_string())
}

/// Set the maximum number of concurrent AWS validations. Call before first use.
pub fn set_aws_validation_concurrency(max: usize) {
    AWS_VALIDATION_SEMAPHORE.set(Semaphore::new(max)).ok();
}

fn aws_validation_semaphore() -> &'static Semaphore {
    AWS_VALIDATION_SEMAPHORE.get_or_init(|| Semaphore::new(15))
}

/// Configure the list of AWS account IDs to skip during validation.
///
/// This is useful for skipping known canary/honeypot accounts.
pub fn set_aws_skip_account_ids<I, S>(ids: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut guard = match AWS_SKIP_ACCOUNT_IDS.write() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clear();

    guard.extend(BUILTIN_SKIP_ACCOUNT_IDS.iter().map(|id| id.to_string()));

    for raw in ids.into_iter() {
        let value = raw.into();
        if value.trim().is_empty() {
            continue;
        }
        if let Some(normalized) = extract_account_id(&value) {
            guard.insert(normalized);
        } else {
            tracing::warn!("Ignoring invalid AWS account ID in skip list: {value}");
        }
    }
}

/// Check if an AWS access key should be skipped based on the skip list.
///
/// Returns `Some(account_id)` if the key should be skipped.
pub fn should_skip_aws_validation(access_key_id: &str) -> Option<String> {
    let guard = AWS_SKIP_ACCOUNT_IDS.read().ok()?;
    if guard.is_empty() {
        return None;
    }

    let account = aws_key_to_account_number(access_key_id).ok()?;
    if guard.contains(&account) { Some(account) } else { None }
}

#[derive(Debug)]
struct UaInterceptor;

impl Intercept for UaInterceptor {
    fn name(&self) -> &'static str {
        "ua"
    }

    fn modify_before_transmit(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _rc: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> std::result::Result<(), BoxError> {
        let req = context.request_mut();
        req.headers_mut().insert(
            USER_AGENT,
            HeaderValue::from_str(GLOBAL_USER_AGENT.as_str())
                .map_err(|e| format!("invalid USER_AGENT header: {e}"))?,
        );
        Ok(())
    }
}

/// Generate a standardized cache key for AWS validation attempts.
pub fn generate_aws_cache_key(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    session_token: Option<&str>,
) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(aws_access_key_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(aws_secret_access_key.as_bytes());
    if let Some(session_token) = session_token {
        hasher.update(b"\0");
        hasher.update(session_token.as_bytes());
    }
    format!("AWS:{}", hex::encode(hasher.finalize()))
}

/// Validate AWS credentials format before attempting validation.
pub fn validate_aws_credentials_input(access_key_id: &str, secret_key: &str) -> Result<(), String> {
    // Validate access key ID format (20 chars, usable AWS access-key prefixes including STS)
    if access_key_id.len() != 20 {
        return Err("Invalid AWS access key ID format".to_string());
    }
    if !access_key_id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("AWS access key ID contains invalid characters".to_string());
    }
    let prefix = &access_key_id[..4];
    // IAM principal IDs (for example AIDA/AROA) are deliberately rejected here:
    // they are not usable access-key IDs for STS credential validation.
    let valid_prefix = matches!(prefix, "AKIA" | "ASIA") || prefix.starts_with("A3T");
    if !valid_prefix {
        return Err("Invalid AWS access key ID format".to_string());
    }
    // Validate secret key format (should be at least 40 chars)
    if secret_key.len() < 40 {
        return Err("Invalid AWS secret key format".to_string());
    }

    Ok(())
}

fn is_transient_read_response(code: Option<&str>, status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::REQUEST_TIMEOUT
        || status.is_server_error()
        || code.is_some_and(|code| {
            code.contains("Throttl")
                || matches!(
                    code,
                    "InternalError"
                        | "InternalErrorException"
                        | "InternalFailure"
                        | "InternalFailureException"
                        | "RequestTimeout"
                        | "RequestTimeoutException"
                        | "ServiceUnavailable"
                        | "ServiceUnavailableException"
                )
        })
}

fn is_throttling_or_transient(e: &SdkError<GetCallerIdentityError>) -> bool {
    match e {
        SdkError::ServiceError(ctx) => {
            let status: StatusCode = ctx.raw().status().into();
            is_transient_read_response(ctx.err().meta().code(), status)
        }
        SdkError::DispatchFailure(df) => df.is_timeout() || df.is_io(),
        SdkError::TimeoutError(_) => true,
        SdkError::ResponseError(ctx) => {
            let status: StatusCode = ctx.raw().status().into();
            is_transient_read_response(None, status)
        }
        _ => false,
    }
}

/// IAM operation to use when revoking an AWS access key.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AwsRevocationAction {
    /// Disable the key while retaining it on the IAM user.
    #[default]
    Deactivate,
    /// Permanently delete the key.
    Delete,
}

impl std::fmt::Display for AwsRevocationAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Deactivate => "deactivate",
            Self::Delete => "delete",
        })
    }
}

/// Credentials that sign the IAM revocation request.
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub enum AwsRevocationCredentials<'a> {
    /// Sign with the discovered access key itself.
    #[default]
    SelfCredentials,
    /// Sign with an explicitly supplied SDK configuration, such as an incident-response profile.
    Responder(&'a SdkConfig),
}

impl std::fmt::Debug for AwsRevocationCredentials<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SelfCredentials => f.write_str("SelfCredentials"),
            Self::Responder(_) => f.write_str("Responder(..)"),
        }
    }
}

/// Identifies which credentials signed an AWS revocation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AwsRevocationActor {
    /// The discovered credential signed its own deactivation request.
    SelfCredentials,
    /// Separately supplied responder credentials signed the request.
    Responder,
}

impl std::fmt::Display for AwsRevocationActor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SelfCredentials => "self_credentials",
            Self::Responder => "responder",
        })
    }
}

/// Options for detailed AWS access-key revocation.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct AwsRevocationOptions<'a> {
    /// IAM operation to perform. Deactivation is the safe default.
    pub action: AwsRevocationAction,
    /// Credentials that sign the IAM request.
    pub credentials: AwsRevocationCredentials<'a>,
    /// Target IAM user name. With self credentials, it must match the STS-resolved identity.
    pub target_user_name: Option<&'a str>,
    /// Explicit AWS region used for STS and IAM endpoint resolution.
    ///
    /// When omitted, responder credentials retain their configured region and self credentials
    /// use `us-east-1`. Select a region in the target partition for AWS GovCloud or AWS China.
    pub region: Option<&'a str>,
    /// Timeout applied independently to each STS lookup and IAM mutation attempt.
    pub attempt_timeout: Duration,
}

impl<'a> Default for AwsRevocationOptions<'a> {
    fn default() -> Self {
        Self {
            action: AwsRevocationAction::default(),
            credentials: AwsRevocationCredentials::default(),
            target_user_name: None,
            region: None,
            attempt_timeout: AWS_ATTEMPT_TIMEOUT,
        }
    }
}

impl<'a> AwsRevocationOptions<'a> {
    /// Construct options that use separately supplied responder credentials.
    pub fn responder(config: &'a SdkConfig) -> Self {
        Self { credentials: AwsRevocationCredentials::Responder(config), ..Self::default() }
    }

    /// Select the IAM action to perform.
    pub fn with_action(mut self, action: AwsRevocationAction) -> Self {
        self.action = action;
        self
    }

    /// Supply the IAM user that owns the target key.
    pub fn with_target_user_name(mut self, user_name: &'a str) -> Self {
        self.target_user_name = Some(user_name);
        self
    }

    /// Select the AWS region used to resolve STS and IAM endpoints.
    pub fn with_region(mut self, region: &'a str) -> Self {
        self.region = Some(region);
        self
    }

    /// Set the timeout for each individual AWS request.
    ///
    /// A zero duration is rejected before any network request is made.
    pub fn with_attempt_timeout(mut self, attempt_timeout: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self
    }
}

fn effective_revocation_region(
    options: &AwsRevocationOptions<'_>,
) -> std::result::Result<String, &'static str> {
    let explicit_region = match options.region.map(str::trim) {
        Some("") => return Err("AWS revocation region must not be empty"),
        region => region,
    };
    let configured_responder_region = match options.credentials {
        AwsRevocationCredentials::Responder(config) => {
            config.region().map(|region| region.as_ref())
        }
        AwsRevocationCredentials::SelfCredentials => None,
    };
    let region = explicit_region.or(configured_responder_region).unwrap_or(AWS_DEFAULT_REGION);
    let parts: Vec<_> = region.split('-').collect();
    if parts.len() < 3
        || parts[0].len() != 2
        || !parts[..parts.len() - 1]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
        || !parts
            .last()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("AWS revocation region has an invalid format");
    }
    Ok(region.to_string())
}

/// Semantic outcome of an AWS access-key revocation attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AwsRevocationStatus {
    /// AWS confirmed that the requested IAM mutation succeeded.
    Succeeded,
    /// The signing principal was not authorized or its credentials were rejected.
    NotAuthorized,
    /// The target user or access key did not exist.
    NotFound,
    /// The credential or caller type cannot be revoked through this API.
    Unsupported,
    /// The operation failed before AWS could perform the mutation.
    Failed,
    /// The mutation might have reached AWS, so its outcome must be verified before retrying.
    Unknown,
}

impl std::fmt::Display for AwsRevocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Succeeded => "succeeded",
            Self::NotAuthorized => "not_authorized",
            Self::NotFound => "not_found",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        })
    }
}

/// Detailed result of an AWS access-key revocation attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct AwsRevocationResult {
    /// Semantic outcome of the attempt.
    pub status: AwsRevocationStatus,
    /// IAM operation that was requested.
    pub action: AwsRevocationAction,
    /// Credentials that signed (or would have signed) the request.
    pub actor: AwsRevocationActor,
    /// Human-readable explanation suitable for logs and CLI output.
    pub message: String,
    /// Target AWS account, when it could be determined.
    pub account_id: Option<String>,
    /// Target IAM user, when it could be determined.
    pub user_name: Option<String>,
    /// AWS service error code, when AWS returned one.
    pub error_code: Option<String>,
    /// AWS request ID, when AWS returned one.
    pub request_id: Option<String>,
}

impl AwsRevocationResult {
    /// Whether AWS confirmed the requested IAM mutation.
    pub fn succeeded(&self) -> bool {
        self.status == AwsRevocationStatus::Succeeded
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AwsAccessKeyKind {
    LongTerm,
    Temporary,
    Unknown,
}

fn classify_access_key(access_key_id: &str) -> AwsAccessKeyKind {
    if access_key_id.len() != 20
        || !access_key_id.chars().all(|character| character.is_ascii_alphanumeric())
    {
        return AwsAccessKeyKind::Unknown;
    }

    if access_key_id.starts_with("ASIA") {
        AwsAccessKeyKind::Temporary
    } else if access_key_id.starts_with("AKIA") || access_key_id.starts_with("A3T") {
        AwsAccessKeyKind::LongTerm
    } else {
        AwsAccessKeyKind::Unknown
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AwsPrincipal {
    User { account_id: String, user_name: String },
    Root { account_id: String },
    AssumedRole { account_id: String },
    FederatedUser { account_id: String },
    Other { account_id: String },
}

fn principal_account_id(principal: &AwsPrincipal) -> &str {
    match principal {
        AwsPrincipal::User { account_id, .. }
        | AwsPrincipal::Root { account_id }
        | AwsPrincipal::AssumedRole { account_id }
        | AwsPrincipal::FederatedUser { account_id }
        | AwsPrincipal::Other { account_id } => account_id,
    }
}

fn responder_can_address_root(target_account_id: &str, responder: &AwsPrincipal) -> bool {
    matches!(
        responder,
        AwsPrincipal::Root { account_id } if account_id == target_account_id
    )
}

fn parse_aws_principal_arn(arn: &str) -> std::result::Result<AwsPrincipal, String> {
    let mut parts = arn.splitn(6, ':');
    let prefix = parts.next();
    let partition = parts.next();
    let service = parts.next();
    let _region = parts.next();
    let account_id = parts.next();
    let resource = parts.next();

    let (Some("arn"), Some(partition), Some(service), Some(account_id), Some(resource)) =
        (prefix, partition, service, account_id, resource)
    else {
        return Err(format!("invalid AWS principal ARN: {arn}"));
    };
    if partition.is_empty()
        || account_id.len() != 12
        || !account_id.chars().all(|character| character.is_ascii_digit())
    {
        return Err(format!("invalid AWS principal ARN: {arn}"));
    }

    let account_id = account_id.to_string();
    match (service, resource) {
        ("iam", "root") => Ok(AwsPrincipal::Root { account_id }),
        ("iam", resource) if resource.starts_with("user/") => {
            let user_name = resource
                .strip_prefix("user/")
                .and_then(|path| path.rsplit('/').next())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| format!("invalid IAM user ARN: {arn}"))?;
            Ok(AwsPrincipal::User { account_id, user_name: user_name.to_string() })
        }
        ("sts", resource) if resource.starts_with("assumed-role/") => {
            Ok(AwsPrincipal::AssumedRole { account_id })
        }
        ("sts", resource) if resource.starts_with("federated-user/") => {
            Ok(AwsPrincipal::FederatedUser { account_id })
        }
        _ => Ok(AwsPrincipal::Other { account_id }),
    }
}

#[derive(Debug)]
struct AwsIdentity {
    arn: String,
    account_id: Option<String>,
}

#[derive(Debug)]
struct AwsIdentityFailure {
    status: AwsRevocationStatus,
    message: String,
    error_code: Option<String>,
    request_id: Option<String>,
}

fn aws_request_id<E>(error: &SdkError<E>) -> Option<String> {
    let raw = match error {
        SdkError::ServiceError(context) => Some(context.raw()),
        SdkError::ResponseError(context) => Some(context.raw()),
        _ => None,
    }?;
    raw.headers()
        .get("x-amzn-requestid")
        .or_else(|| raw.headers().get("x-amz-request-id"))
        .map(str::to_string)
}

fn aws_error_code<E: ProvideErrorMetadata>(error: &SdkError<E>) -> Option<String> {
    match error {
        SdkError::ServiceError(context) => context.err().meta().code().map(str::to_string),
        _ => None,
    }
}

fn revocation_status_for_service_code(code: Option<&str>) -> AwsRevocationStatus {
    match code {
        Some(
            "AccessDenied"
            | "AccessDeniedException"
            | "AuthFailure"
            | "ExpiredToken"
            | "ExpiredTokenException"
            | "IncompleteSignature"
            | "InvalidAccessKeyId"
            | "InvalidClientTokenId"
            | "InvalidSignatureException"
            | "MissingAuthenticationToken"
            | "SignatureDoesNotMatch"
            | "TokenRefreshRequired"
            | "Unauthorized"
            | "UnauthorizedException"
            | "UnrecognizedClientException",
        ) => AwsRevocationStatus::NotAuthorized,
        Some("NoSuchEntity" | "NoSuchEntityException") => AwsRevocationStatus::NotFound,
        _ => AwsRevocationStatus::Failed,
    }
}

fn revocation_status_for_iam_service_error(
    code: Option<&str>,
    http_status: StatusCode,
) -> AwsRevocationStatus {
    if http_status.is_server_error()
        || http_status == StatusCode::REQUEST_TIMEOUT
        || matches!(
            code,
            Some(
                "InternalError"
                    | "InternalErrorException"
                    | "InternalFailure"
                    | "InternalFailureException"
                    | "RequestTimeout"
                    | "RequestTimeoutException"
                    | "ServiceFailure"
                    | "ServiceFailureException"
                    | "ServiceUnavailable"
                    | "ServiceUnavailableException"
            )
        )
    {
        AwsRevocationStatus::Unknown
    } else {
        revocation_status_for_service_code(code)
    }
}

fn identity_failure_from_sdk_error(error: &SdkError<GetCallerIdentityError>) -> AwsIdentityFailure {
    let error_code = aws_error_code(error);
    let status = revocation_status_for_service_code(error_code.as_deref());
    AwsIdentityFailure {
        status,
        message: format!("AWS identity lookup failed: {error}"),
        request_id: aws_request_id(error),
        error_code,
    }
}

async fn lookup_aws_identity(
    config: &SdkConfig,
    region: &str,
    attempt_timeout: Duration,
) -> std::result::Result<AwsIdentity, AwsIdentityFailure> {
    // Keep read retries explicit and bounded. IAM mutations use a separate, single-attempt client.
    let sts_config = StsConfigBuilder::from(config)
        .region(Region::new(region.to_owned()))
        .retry_config(RetryConfig::adaptive().with_max_attempts(1))
        .interceptor(UaInterceptor)
        .build();
    let client = StsClient::from_conf(sts_config);

    for attempt in 1..=AWS_IDENTITY_MAX_ATTEMPTS {
        match timeout(attempt_timeout, client.get_caller_identity().send()).await {
            Ok(Ok(identity)) => {
                let Some(arn) = identity.arn.filter(|arn| !arn.is_empty()) else {
                    return Err(AwsIdentityFailure {
                        status: AwsRevocationStatus::Failed,
                        message: "AWS GetCallerIdentity returned no ARN".to_string(),
                        error_code: None,
                        request_id: None,
                    });
                };
                return Ok(AwsIdentity {
                    arn,
                    account_id: identity.account.filter(|account| !account.is_empty()),
                });
            }
            Ok(Err(error)) => {
                if !is_throttling_or_transient(&error) || attempt == AWS_IDENTITY_MAX_ATTEMPTS {
                    return Err(identity_failure_from_sdk_error(&error));
                }
            }
            Err(_) if attempt == AWS_IDENTITY_MAX_ATTEMPTS => {
                return Err(AwsIdentityFailure {
                    status: AwsRevocationStatus::Failed,
                    message: "AWS identity lookup timed out".to_string(),
                    error_code: None,
                    request_id: None,
                });
            }
            Err(_) => {}
        }

        let max_delay = 100u64 * 2u64.pow((attempt - 1) as u32);
        sleep(Duration::from_millis(rng().random_range(0..=max_delay))).await;
    }

    unreachable!("identity lookup loop always returns")
}

fn base_revocation_result(
    status: AwsRevocationStatus,
    action: AwsRevocationAction,
    actor: AwsRevocationActor,
    message: impl Into<String>,
    account_id: Option<String>,
    user_name: Option<String>,
) -> AwsRevocationResult {
    AwsRevocationResult {
        status,
        action,
        actor,
        message: message.into(),
        account_id,
        user_name,
        error_code: None,
        request_id: None,
    }
}

fn identity_failure_result(
    failure: AwsIdentityFailure,
    action: AwsRevocationAction,
    actor: AwsRevocationActor,
    account_id: Option<String>,
    user_name: Option<String>,
) -> AwsRevocationResult {
    AwsRevocationResult {
        status: failure.status,
        action,
        actor,
        message: failure.message,
        account_id,
        user_name,
        error_code: failure.error_code,
        request_id: failure.request_id,
    }
}

fn is_definitive_iam_throttling<E: ProvideErrorMetadata>(error: &IamSdkError<E>) -> bool {
    let IamSdkError::ServiceError(context) = error else {
        return false;
    };
    let status: StatusCode = context.raw().status().into();
    // Never repeat an ambiguous timeout or server failure, even with a throttling code.
    !status.is_server_error()
        && status != StatusCode::REQUEST_TIMEOUT
        && (status == StatusCode::TOO_MANY_REQUESTS
            || matches!(
                context.err().meta().code(),
                Some(
                    "Throttling"
                        | "ThrottlingException"
                        | "ThrottledException"
                        | "TooManyRequestsException"
                        | "RequestLimitExceeded"
                )
            ))
}

async fn retry_iam_throttling<T, E, F, Fut>(
    attempt_timeout: Duration,
    mut request: F,
) -> std::result::Result<std::result::Result<T, IamSdkError<E>>, tokio::time::error::Elapsed>
where
    E: ProvideErrorMetadata,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, IamSdkError<E>>>,
{
    for attempt in 1..=3 {
        let result = timeout(attempt_timeout, request()).await;
        if attempt == 3 || !matches!(&result, Ok(Err(error)) if is_definitive_iam_throttling(error))
        {
            return result;
        }
        sleep(Duration::from_millis(100 * (1 << (attempt - 1)))).await;
    }
    unreachable!("bounded IAM retry loop always returns")
}

fn iam_failure_result<E>(
    error: &IamSdkError<E>,
    action: AwsRevocationAction,
    actor: AwsRevocationActor,
    account_id: Option<String>,
    user_name: Option<String>,
) -> AwsRevocationResult
where
    E: ProvideErrorMetadata + std::fmt::Display,
{
    let error_code = aws_error_code(error);
    let request_id = aws_request_id(error);
    let status = match error {
        IamSdkError::TimeoutError(_)
        | IamSdkError::DispatchFailure(_)
        | IamSdkError::ResponseError(_) => AwsRevocationStatus::Unknown,
        IamSdkError::ServiceError(context) => revocation_status_for_iam_service_error(
            error_code.as_deref(),
            context.raw().status().into(),
        ),
        IamSdkError::ConstructionFailure(_) => AwsRevocationStatus::Failed,
        _ => AwsRevocationStatus::Failed,
    };
    let message = if status == AwsRevocationStatus::Unknown {
        format!(
            "AWS {action} outcome is unknown because the IAM request may have been sent: {error}. Verify the access key state before retrying."
        )
    } else if status == AwsRevocationStatus::NotAuthorized {
        let permission = match action {
            AwsRevocationAction::Deactivate => "iam:UpdateAccessKey",
            AwsRevocationAction::Delete => "iam:DeleteAccessKey",
        };
        format!(
            "AWS access-key {action} was not authorized: {error}. The signing principal needs {permission} for the target IAM user."
        )
    } else {
        format!("AWS access-key {action} failed: {error}")
    };

    AwsRevocationResult {
        status,
        action,
        actor,
        message,
        account_id,
        user_name,
        error_code,
        request_id,
    }
}

/// Revoke an AWS access key with an explicit action and signing-credential strategy.
///
/// Identity lookups are safely retried. IAM mutations retry only definitive throttling responses
/// (at most three attempts), with SDK retries disabled. A timeout or transport failure is reported as
/// [`AwsRevocationStatus::Unknown`] so callers do not blindly repeat an irreversible operation.
pub async fn revoke_aws_access_key_with_options(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    options: AwsRevocationOptions<'_>,
) -> Result<AwsRevocationResult> {
    revoke_aws_access_key_impl(aws_access_key_id, aws_secret_access_key, options, None).await
}

async fn revoke_aws_access_key_impl(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    options: AwsRevocationOptions<'_>,
    target_config: Option<&SdkConfig>,
) -> Result<AwsRevocationResult> {
    let action = options.action;
    let actor = match options.credentials {
        AwsRevocationCredentials::SelfCredentials => AwsRevocationActor::SelfCredentials,
        AwsRevocationCredentials::Responder(_) => AwsRevocationActor::Responder,
    };
    let effective_region = match effective_revocation_region(&options) {
        Ok(region) => region,
        Err(message) => {
            return Ok(base_revocation_result(
                AwsRevocationStatus::Failed,
                action,
                actor,
                message,
                None,
                None,
            ));
        }
    };
    let region = effective_region.as_str();
    if options.attempt_timeout.is_zero() {
        return Ok(base_revocation_result(
            AwsRevocationStatus::Failed,
            action,
            actor,
            "AWS revocation attempt timeout must be greater than zero",
            None,
            None,
        ));
    }
    let attempt_timeout = options.attempt_timeout;

    match classify_access_key(aws_access_key_id) {
        AwsAccessKeyKind::Temporary => {
            return Ok(base_revocation_result(
                AwsRevocationStatus::Unsupported,
                action,
                actor,
                "AWS STS session credentials (ASIA) cannot be revoked with IAM access-key APIs",
                None,
                None,
            ));
        }
        AwsAccessKeyKind::Unknown => {
            return Ok(base_revocation_result(
                AwsRevocationStatus::Unsupported,
                action,
                actor,
                "Unsupported AWS access key ID format",
                None,
                None,
            ));
        }
        AwsAccessKeyKind::LongTerm => {}
    }

    let encoded_account_id = aws_key_to_account_number(aws_access_key_id).ok();
    let target_credentials = Credentials::new(
        aws_access_key_id,
        aws_secret_access_key,
        None,
        None,
        "kingfisher-revocation-target",
    );

    let (iam_config_source, account_id, user_name) = match options.credentials {
        AwsRevocationCredentials::SelfCredentials => {
            let target_config = match target_config {
                Some(config) => config.clone(),
                None => build_base_config_with_region(target_credentials, region).await,
            };
            let identity = match lookup_aws_identity(&target_config, region, attempt_timeout).await
            {
                Ok(identity) => identity,
                Err(failure) => {
                    return Ok(identity_failure_result(
                        failure,
                        action,
                        actor,
                        encoded_account_id,
                        None,
                    ));
                }
            };
            let principal = match parse_aws_principal_arn(&identity.arn) {
                Ok(principal) => principal,
                Err(message) => {
                    return Ok(base_revocation_result(
                        AwsRevocationStatus::Unsupported,
                        action,
                        actor,
                        message,
                        identity.account_id,
                        None,
                    ));
                }
            };
            match principal {
                AwsPrincipal::User { account_id, user_name } => {
                    if let Some(supplied_user_name) = options.target_user_name.map(str::trim)
                        && supplied_user_name != user_name
                    {
                        return Ok(base_revocation_result(
                            AwsRevocationStatus::Unsupported,
                            action,
                            actor,
                            format!(
                                "Supplied target user {supplied_user_name:?} does not match caller identity {user_name:?}"
                            ),
                            Some(account_id),
                            Some(user_name),
                        ));
                    }
                    (target_config, Some(account_id), Some(user_name))
                }
                AwsPrincipal::Root { account_id } => {
                    if options.target_user_name.is_some() {
                        return Ok(base_revocation_result(
                            AwsRevocationStatus::Unsupported,
                            action,
                            actor,
                            "A target user name cannot be used with AWS root credentials",
                            Some(account_id),
                            None,
                        ));
                    }
                    (target_config, Some(account_id), None)
                }
                AwsPrincipal::AssumedRole { account_id } => {
                    return Ok(base_revocation_result(
                        AwsRevocationStatus::Unsupported,
                        action,
                        actor,
                        "AWS assumed-role credentials cannot revoke an IAM access key as self",
                        Some(account_id),
                        None,
                    ));
                }
                AwsPrincipal::FederatedUser { account_id } => {
                    return Ok(base_revocation_result(
                        AwsRevocationStatus::Unsupported,
                        action,
                        actor,
                        "AWS federated-user credentials cannot revoke an IAM access key as self",
                        Some(account_id),
                        None,
                    ));
                }
                AwsPrincipal::Other { account_id } => {
                    return Ok(base_revocation_result(
                        AwsRevocationStatus::Unsupported,
                        action,
                        actor,
                        format!("Unsupported AWS caller identity: {}", identity.arn),
                        Some(account_id),
                        None,
                    ));
                }
            }
        }
        AwsRevocationCredentials::Responder(responder_config) => {
            let explicit_user_name = options
                .target_user_name
                .map(str::trim)
                .filter(|user_name| !user_name.is_empty())
                .map(str::to_string);

            let (target_account_id, target_user_name, target_is_root) = if let Some(user_name) =
                explicit_user_name
            {
                // Access-key account decoding is useful context, but it is not an AWS-supported
                // authorization check and is unavailable for some legacy keys. Only an STS result
                // may establish the target account for the mismatch guard below.
                (None, Some(user_name), false)
            } else {
                let target_config = match target_config {
                    Some(config) => config.clone(),
                    None => build_base_config_with_region(target_credentials, region).await,
                };
                let identity =
                    match lookup_aws_identity(&target_config, region, attempt_timeout).await {
                        Ok(identity) => identity,
                        Err(failure) => {
                            return Ok(identity_failure_result(failure, action, actor, None, None));
                        }
                    };
                match parse_aws_principal_arn(&identity.arn) {
                    Ok(AwsPrincipal::User { account_id, user_name }) => {
                        (Some(account_id), Some(user_name), false)
                    }
                    Ok(AwsPrincipal::Root { account_id }) => (Some(account_id), None, true),
                    Ok(
                        AwsPrincipal::AssumedRole { account_id }
                        | AwsPrincipal::FederatedUser { account_id }
                        | AwsPrincipal::Other { account_id },
                    ) => {
                        return Ok(base_revocation_result(
                            AwsRevocationStatus::Unsupported,
                            action,
                            actor,
                            format!("Target credential has no IAM user identity: {}", identity.arn),
                            Some(account_id),
                            None,
                        ));
                    }
                    Err(message) => {
                        return Ok(base_revocation_result(
                            AwsRevocationStatus::Unsupported,
                            action,
                            actor,
                            message,
                            identity.account_id,
                            None,
                        ));
                    }
                }
            };

            let responder_identity =
                match lookup_aws_identity(responder_config, region, attempt_timeout).await {
                    Ok(identity) => identity,
                    Err(failure) => {
                        return Ok(identity_failure_result(
                            failure,
                            action,
                            actor,
                            target_account_id,
                            target_user_name,
                        ));
                    }
                };
            let responder_principal = parse_aws_principal_arn(&responder_identity.arn).ok();
            let responder_account_id = responder_identity.account_id.or_else(|| {
                responder_principal
                    .as_ref()
                    .map(|principal| principal_account_id(principal).to_string())
            });
            if let (Some(target), Some(responder)) =
                (target_account_id.as_deref(), responder_account_id.as_deref())
                && target != responder
            {
                return Ok(base_revocation_result(
                    AwsRevocationStatus::Unsupported,
                    action,
                    actor,
                    format!("Responder account {responder} does not match target account {target}"),
                    target_account_id,
                    target_user_name,
                ));
            }
            if target_is_root {
                let Some(target_account_id) = target_account_id.as_deref() else {
                    unreachable!("root target identity always has an account")
                };
                if !responder_principal.as_ref().is_some_and(|principal| {
                    responder_can_address_root(target_account_id, principal)
                }) {
                    return Ok(base_revocation_result(
                        AwsRevocationStatus::Unsupported,
                        action,
                        actor,
                        "A root access key can only be revoked without UserName by root credentials in the same account",
                        Some(target_account_id.to_string()),
                        None,
                    ));
                }
            }

            (responder_config.clone(), target_account_id, target_user_name)
        }
    };

    let iam_config = IamConfigBuilder::from(&iam_config_source)
        .region(Region::new(region.to_owned()))
        .retry_config(RetryConfig::adaptive().with_max_attempts(1))
        .interceptor(UaInterceptor)
        .build();
    let iam_client = IamClient::from_conf(iam_config);

    match action {
        AwsRevocationAction::Deactivate => {
            let mut request = iam_client
                .update_access_key()
                .access_key_id(aws_access_key_id)
                .status(StatusType::Inactive);
            if let Some(user_name) = user_name.as_deref() {
                request = request.user_name(user_name);
            }

            match retry_iam_throttling(attempt_timeout, || request.clone().send()).await {
                Ok(Ok(_)) => Ok(base_revocation_result(
                    AwsRevocationStatus::Succeeded,
                    action,
                    actor,
                    "AWS access key set to Inactive",
                    account_id,
                    user_name,
                )),
                Ok(Err(error)) => {
                    Ok(iam_failure_result(&error, action, actor, account_id, user_name))
                }
                Err(_) => Ok(base_revocation_result(
                    AwsRevocationStatus::Unknown,
                    action,
                    actor,
                    "AWS deactivate outcome is unknown because the IAM request timed out after it may have been sent. Verify the access key state before retrying.",
                    account_id,
                    user_name,
                )),
            }
        }
        AwsRevocationAction::Delete => {
            let mut request = iam_client.delete_access_key().access_key_id(aws_access_key_id);
            if let Some(user_name) = user_name.as_deref() {
                request = request.user_name(user_name);
            }

            match retry_iam_throttling(attempt_timeout, || request.clone().send()).await {
                Ok(Ok(_)) => Ok(base_revocation_result(
                    AwsRevocationStatus::Succeeded,
                    action,
                    actor,
                    "AWS access key deleted",
                    account_id,
                    user_name,
                )),
                Ok(Err(error)) => {
                    Ok(iam_failure_result(&error, action, actor, account_id, user_name))
                }
                Err(_) => Ok(base_revocation_result(
                    AwsRevocationStatus::Unknown,
                    action,
                    actor,
                    "AWS delete outcome is unknown because the IAM request timed out after it may have been sent. Verify the access key state before retrying.",
                    account_id,
                    user_name,
                )),
            }
        }
    }
}

/// Revoke (deactivate) an AWS access key via IAM using the key's own credentials.
///
/// This compatibility wrapper preserves the original API. New callers should use
/// [`revoke_aws_access_key_with_options`] to inspect structured outcomes or supply responder
/// credentials.
pub async fn revoke_aws_access_key(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
) -> Result<(bool, String)> {
    let result = revoke_aws_access_key_with_options(
        aws_access_key_id,
        aws_secret_access_key,
        AwsRevocationOptions::default(),
    )
    .await?;
    match result.status {
        AwsRevocationStatus::Unknown => Err(anyhow!(result.message)),
        _ => Ok((result.succeeded(), result.message)),
    }
}

/// Validate AWS credentials by calling STS GetCallerIdentity.
///
/// Returns `(is_valid, message)` where message is the ARN on success or an error message.
pub async fn validate_aws_credentials(
    aws_access_key_id: &str,
    aws_secret_access_key: &str,
    session_token: Option<&str>,
) -> Result<(bool, String)> {
    let _permit = aws_validation_semaphore().acquire().await.expect("semaphore closed");

    // Create static credentials
    let credentials = Credentials::new(
        aws_access_key_id,
        aws_secret_access_key,
        session_token.map(str::to_owned),
        None,     // expiry
        "static", // provider name
    );
    let config = build_base_config(credentials).await;

    // Create STS client
    let sts_config = StsConfigBuilder::from(&config).interceptor(UaInterceptor).build();
    let sts_client = StsClient::from_conf(sts_config);

    const MAX_ATTEMPTS: usize = 3;
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

    for attempt in 1..=MAX_ATTEMPTS {
        let result = timeout(ATTEMPT_TIMEOUT, sts_client.get_caller_identity().send()).await;
        match result {
            Ok(Ok(identity)) => {
                let arn = identity.arn.unwrap_or_else(|| "Unknown".to_string());
                return Ok((true, arn));
            }
            Ok(Err(e)) => {
                if is_throttling_or_transient(&e) {
                    if attempt == MAX_ATTEMPTS {
                        return Err(anyhow!("AWS validation failed: {}", e));
                    }
                } else {
                    return Ok((false, e.to_string()));
                }
            }
            Err(_) => {
                if attempt == MAX_ATTEMPTS {
                    return Err(anyhow!("AWS validation timed out"));
                }
            }
        }
        let max_delay = 100u64 * 2u64.pow((attempt - 1) as u32);
        let sleep_ms = rng().random_range(0..=max_delay);
        sleep(Duration::from_millis(sleep_ms)).await;
    }
    Err(anyhow!("AWS validation failed"))
}

/// Converts an AWS Key ID to an AWS Account Number.
///
/// It assumes that the Key ID has a specific format and extracts the account
/// number encoded within it.
///
/// Reference: <https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489>
pub fn aws_key_to_account_number(aws_key_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !aws_key_id.is_ascii() {
        return Err("AWSKeyID must contain only ASCII characters".into());
    }
    // Ensure the AWS Key ID is at least 5 characters long
    if aws_key_id.len() < 5 {
        return Err("AWSKeyID is too short".into());
    }

    // Check if the 5th character is 'I' or 'J'
    let fifth_char = aws_key_id.as_bytes()[4] as char;
    if fifth_char == 'I' || fifth_char == 'J' {
        let err_msg =
            format!("Not possible to retrieve account number for {} keys", &aws_key_id[..5]);
        return Err(err_msg.into());
    }

    // Remove the Key ID prefix (first 4 characters)
    let trimmed_aws_key_id = &aws_key_id[4..];

    // Decode the trimmed Key ID from base32
    let decoded =
        base32::decode(Alphabet::Rfc4648 { padding: false }, &trimmed_aws_key_id.to_uppercase())
            .ok_or("Error decoding AWSKeyID")?;

    if decoded.len() < 6 {
        return Err("Decoded AWSKeyID is too short".into());
    }

    // Create an 8-byte array initialized to zeros
    let mut data = [0u8; 8];
    // Copy decoded[0..6] into data[2..8]
    data[2..8].copy_from_slice(&decoded[0..6]);

    // Interpret data as a big-endian u64
    let z = BigEndian::read_u64(&data);

    // Define the mask
    const MASK: u64 = 0x7FFFFFFFFF80;

    // Calculate the account number
    let account_num = (z & MASK) >> 7;

    // Return the account number formatted as a 12-digit string
    Ok(format!("{:012}", account_num))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_config(endpoint: &str, key: &str) -> SdkConfig {
        aws_config::defaults(BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                key,
                "fixtureSecretKeyLongEnoughForSigning1234567890",
                None,
                None,
                "test",
            ))
            .region(Region::new("us-east-1"))
            .endpoint_url(endpoint)
            .load()
            .await
    }

    #[tokio::test]
    async fn aws_safety_guards_send_no_mutations() {
        use axum::{Router, body::Bytes, http::HeaderMap, response::IntoResponse, routing::post};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        for (target_arn, responder_arn, explicit_user, key, expected_reads) in [
            (
                "arn:aws:iam::123456789012:user/target",
                "arn:aws:iam::123456789012:user/responder",
                Some("different"),
                "AKIAIOSFODNN7EXAMPLE",
                1,
            ),
            (
                "arn:aws:iam::123456789012:root",
                "arn:aws:iam::123456789012:user/responder",
                None,
                "AKIAIOSFODNN7EXAMPLE",
                2,
            ),
            (
                "arn:aws:iam::123456789012:user/target",
                "arn:aws:iam::999999999999:user/responder",
                None,
                "AKIAIOSFODNN7EXAMPLE",
                2,
            ),
            (
                "arn:aws:iam::123456789012:user/target",
                "arn:aws:iam::123456789012:user/responder",
                None,
                "ASIAIOSFODNN7EXAMPLE",
                0,
            ),
        ] {
            let mutations = Arc::new(AtomicUsize::new(0));
            let reads = Arc::new(AtomicUsize::new(0));
            let observed_mutations = mutations.clone();
            let observed_reads = reads.clone();
            let app = Router::new().route("/", post(move |headers: HeaderMap, body: Bytes| {
                let mutations = observed_mutations.clone();
                let reads = observed_reads.clone();
                async move {
                    if !String::from_utf8_lossy(&body).contains("Action=GetCallerIdentity") {
                        mutations.fetch_add(1, Ordering::SeqCst);
                        return StatusCode::NO_CONTENT.into_response();
                    }
                    reads.fetch_add(1, Ordering::SeqCst);
                    let arn = if headers["authorization"].to_str().unwrap().contains("AKIARESPONDER") { responder_arn } else { target_arn };
                    (StatusCode::OK, [("content-type", "text/xml")], format!("<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>{arn}</Arn><Account>{}</Account><UserId>AIDAEXAMPLE</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>", arn.split(':').nth(4).unwrap())).into_response()
                }
            }));
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let target = test_config(&endpoint, key).await;
            let responder = test_config(&endpoint, "AKIARESPONDEREXAMPLE").await;
            let options = if let Some(user) = explicit_user {
                AwsRevocationOptions::default().with_target_user_name(user)
            } else {
                AwsRevocationOptions::responder(&responder)
            };
            let result = revoke_aws_access_key_impl(key, "fixtureSecret", options, Some(&target))
                .await
                .unwrap();
            server.abort();
            assert_eq!(result.status, AwsRevocationStatus::Unsupported);
            assert_eq!(mutations.load(Ordering::SeqCst), 0);
            assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
        }
    }

    #[test]
    fn non_ascii_key_ids_and_malformed_regions_are_rejected() {
        for key in ["AKIéEXAMPLE", "ééééé", "AKIAXéAMPLE"] {
            assert!(aws_key_to_account_number(key).is_err());
        }
        for region in
            ["https://example.com", "us-east-1/path", "US-EAST-1", "us--east-1", "us-east"]
        {
            assert!(
                effective_revocation_region(&AwsRevocationOptions::default().with_region(region))
                    .is_err()
            );
        }
        for region in ["us-east-1", "us-gov-west-1", "us-iso-east-1", "eu-isoe-west-1"] {
            assert_eq!(
                effective_revocation_region(&AwsRevocationOptions::default().with_region(region))
                    .unwrap(),
                region
            );
        }
    }

    #[test]
    fn test_aws_key_to_account_number() {
        // Known test case from the original implementation
        let result = aws_key_to_account_number("AKIAXYZDQCEN4B6JSJQI");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "534261010715");
    }

    #[test]
    fn test_invalid_key_length() {
        let result = aws_key_to_account_number("AKIA");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_credentials_format() {
        assert!(
            validate_aws_credentials_input(
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
            .is_ok()
        );
        assert!(validate_aws_credentials_input("short", "secret").is_err());
        assert!(validate_aws_credentials_input("AKIAIOSFODNN7EXAMPLE", "short").is_err());
    }

    #[test]
    fn aws_session_credentials_use_a_distinct_cache_key() {
        let static_key = generate_aws_cache_key(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None,
        );
        let session_key = generate_aws_cache_key(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("session-token"),
        );

        assert_ne!(static_key, session_key);
    }

    #[test]
    fn classifies_access_key_kinds_without_network_access() {
        assert_eq!(classify_access_key("AKIAIOSFODNN7EXAMPLE"), AwsAccessKeyKind::LongTerm);
        assert_eq!(classify_access_key("ASIAIOSFODNN7EXAMPLE"), AwsAccessKeyKind::Temporary);
        assert_eq!(classify_access_key("A3TAXYZDQCEN4B6JSJQI"), AwsAccessKeyKind::LongTerm);
        assert_eq!(classify_access_key("AROA1234567890123456"), AwsAccessKeyKind::Unknown);
        assert_eq!(classify_access_key("AKIA-short"), AwsAccessKeyKind::Unknown);
    }

    #[test]
    fn parses_iam_user_arns_across_partitions_and_paths() {
        assert_eq!(
            parse_aws_principal_arn("arn:aws:iam::123456789012:user/service/backup").unwrap(),
            AwsPrincipal::User {
                account_id: "123456789012".to_string(),
                user_name: "backup".to_string(),
            }
        );
        assert_eq!(
            parse_aws_principal_arn("arn:aws-us-gov:iam::210987654321:user/incident-responder")
                .unwrap(),
            AwsPrincipal::User {
                account_id: "210987654321".to_string(),
                user_name: "incident-responder".to_string(),
            }
        );
        assert_eq!(
            parse_aws_principal_arn("arn:aws-cn:iam::111122223333:root").unwrap(),
            AwsPrincipal::Root { account_id: "111122223333".to_string() }
        );
    }

    #[test]
    fn identifies_unsupported_sts_principals() {
        assert_eq!(
            parse_aws_principal_arn(
                "arn:aws:sts::123456789012:assumed-role/incident-response/session"
            )
            .unwrap(),
            AwsPrincipal::AssumedRole { account_id: "123456789012".to_string() }
        );
        assert_eq!(
            parse_aws_principal_arn("arn:aws:sts::123456789012:federated-user/alice").unwrap(),
            AwsPrincipal::FederatedUser { account_id: "123456789012".to_string() }
        );
    }

    #[test]
    fn only_same_account_root_credentials_can_address_a_root_target() {
        let same_account_root = parse_aws_principal_arn("arn:aws:iam::123456789012:root").unwrap();
        let other_account_root = parse_aws_principal_arn("arn:aws:iam::210987654321:root").unwrap();
        let iam_user = parse_aws_principal_arn("arn:aws:iam::123456789012:user/responder").unwrap();

        assert!(responder_can_address_root("123456789012", &same_account_root));
        assert!(!responder_can_address_root("123456789012", &other_account_root));
        assert!(!responder_can_address_root("123456789012", &iam_user));
    }

    #[test]
    fn maps_iam_service_codes_to_structured_statuses() {
        assert_eq!(
            revocation_status_for_service_code(Some("AccessDenied")),
            AwsRevocationStatus::NotAuthorized
        );
        assert_eq!(
            revocation_status_for_service_code(Some("NoSuchEntity")),
            AwsRevocationStatus::NotFound
        );
        assert_eq!(
            revocation_status_for_service_code(Some("ServiceFailure")),
            AwsRevocationStatus::Failed
        );
        assert_eq!(revocation_status_for_service_code(None), AwsRevocationStatus::Failed);

        assert_eq!(
            revocation_status_for_iam_service_error(
                Some("ServiceFailure"),
                StatusCode::BAD_REQUEST
            ),
            AwsRevocationStatus::Unknown
        );
        assert_eq!(
            revocation_status_for_iam_service_error(None, StatusCode::INTERNAL_SERVER_ERROR),
            AwsRevocationStatus::Unknown
        );
        assert_eq!(
            revocation_status_for_iam_service_error(None, StatusCode::REQUEST_TIMEOUT),
            AwsRevocationStatus::Unknown
        );
        assert_eq!(
            revocation_status_for_iam_service_error(
                Some("RequestTimeout"),
                StatusCode::BAD_REQUEST
            ),
            AwsRevocationStatus::Unknown
        );
        assert_eq!(
            revocation_status_for_iam_service_error(Some("ExpiredToken"), StatusCode::FORBIDDEN),
            AwsRevocationStatus::NotAuthorized
        );
        assert_eq!(
            revocation_status_for_iam_service_error(Some("NoSuchEntity"), StatusCode::NOT_FOUND),
            AwsRevocationStatus::NotFound
        );
    }

    #[test]
    fn retries_transient_sts_responses() {
        assert!(is_transient_read_response(Some("ThrottlingException"), StatusCode::BAD_REQUEST));
        assert!(is_transient_read_response(Some("InternalError"), StatusCode::BAD_REQUEST));
        assert!(is_transient_read_response(None, StatusCode::BAD_GATEWAY));
        assert!(is_transient_read_response(None, StatusCode::GATEWAY_TIMEOUT));
        assert!(is_transient_read_response(None, StatusCode::REQUEST_TIMEOUT));
        assert!(!is_transient_read_response(Some("AccessDenied"), StatusCode::FORBIDDEN));
    }

    #[test]
    fn structured_values_have_stable_lowercase_names() {
        assert_eq!(AwsRevocationAction::default().to_string(), "deactivate");
        assert_eq!(AwsRevocationStatus::NotAuthorized.to_string(), "not_authorized");
        assert_eq!(AwsRevocationActor::Responder.to_string(), "responder");
        assert_eq!(serde_json::to_string(&AwsRevocationAction::Delete).unwrap(), "\"delete\"");
    }

    #[test]
    fn revocation_options_have_safe_region_and_timeout_defaults() {
        let options = AwsRevocationOptions::default();
        assert_eq!(effective_revocation_region(&options).unwrap(), "us-east-1");
        assert_eq!(options.attempt_timeout, Duration::from_secs(5));

        let responder_config = SdkConfig::builder().region(Region::new("us-gov-west-1")).build();
        let responder = AwsRevocationOptions::responder(&responder_config);
        assert_eq!(effective_revocation_region(&responder).unwrap(), "us-gov-west-1");

        let explicit =
            responder.with_region("cn-north-1").with_attempt_timeout(Duration::from_secs(12));
        assert_eq!(effective_revocation_region(&explicit).unwrap(), "cn-north-1");
        assert_eq!(explicit.attempt_timeout, Duration::from_secs(12));
    }

    #[tokio::test]
    async fn zero_revocation_timeout_is_rejected_before_network_access() {
        let result = revoke_aws_access_key_with_options(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            AwsRevocationOptions::default().with_attempt_timeout(Duration::ZERO),
        )
        .await
        .unwrap();

        assert_eq!(result.status, AwsRevocationStatus::Failed);
        assert!(result.message.contains("greater than zero"));
    }
}

#[derive(Debug)]
pub struct AwsCredentialValidation {
    pub is_valid: bool,
    pub status: StatusCode,
    pub outcome: ValidationOutcome,
    pub message: String,
    pub identity: Option<String>,
    pub account_id: Option<String>,
}

/// Validate one explicit AWS credential pair using the policy shared by scan and direct paths.
pub async fn validate_aws_credential_pair(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
) -> AwsCredentialValidation {
    let account_id = aws_key_to_account_number(access_key_id).ok();

    if let Some(account_id) = should_skip_aws_validation(access_key_id) {
        return AwsCredentialValidation {
            is_valid: false,
            status: StatusCode::PRECONDITION_REQUIRED,
            outcome: ValidationOutcome::Skipped,
            message: format!(
                "(skip list entry) AWS validation not attempted for account {}.",
                account_id
            ),
            identity: None,
            account_id: Some(account_id),
        };
    }

    if let Err(message) = validate_aws_credentials_input(access_key_id, secret_access_key) {
        return AwsCredentialValidation {
            is_valid: false,
            status: StatusCode::BAD_REQUEST,
            outcome: ValidationOutcome::Unavailable,
            message,
            identity: None,
            account_id,
        };
    }

    match validate_aws_credentials(access_key_id, secret_access_key, session_token).await {
        Ok((true, identity)) => AwsCredentialValidation {
            is_valid: true,
            status: StatusCode::OK,
            outcome: ValidationOutcome::VerifiedActive,
            message: identity.clone(),
            identity: Some(identity),
            account_id,
        },
        Ok((false, message)) => AwsCredentialValidation {
            is_valid: false,
            status: StatusCode::FORBIDDEN,
            outcome: ValidationOutcome::VerifiedInactive,
            message,
            identity: None,
            account_id,
        },
        Err(error) => AwsCredentialValidation {
            is_valid: false,
            status: StatusCode::BAD_GATEWAY,
            outcome: ValidationOutcome::Unavailable,
            message: error.to_string(),
            identity: None,
            account_id,
        },
    }
}
