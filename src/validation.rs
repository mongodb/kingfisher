use std::{
    collections::BTreeMap,
    fs,
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};

use std::sync::{LazyLock, OnceLock};

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use futures::FutureExt;
use http::StatusCode;
use kingfisher_core::ValidationOutcome;
use liquid::Object;
use liquid_core::{Value, ValueView};
use percent_encoding::percent_decode_str;
use reqwest::{
    Client, Url, header,
    header::{HeaderMap, HeaderValue},
    multipart,
};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::{sync::Notify, time};
use tracing::{debug, warn};

use crate::{
    cli::global::TlsMode,
    location::OffsetSpan,
    matcher::{OwnedBlobMatch, SerializableCaptures},
    provider_endpoints::{
        ProviderEndpointOverrides, endpoint_var_names, hydrate_endpoint_globals_for_rule,
    },
    rules::rule::{Rule, Validation},
    validation_body::{self},
};

use crate::grpc_validation;
use crate::validation_rate_limit::should_rate_limit_validation;

// Re-export TlsMode from kingfisher_rules for use in client_for_rule
pub use kingfisher_rules::TlsMode as RuleTlsMode;

pub use kingfisher_scanner::validation::CachedResponse;
pub use kingfisher_scanner::validation::aws;
pub use kingfisher_scanner::validation::http_validation as httpvalidation;
pub use kingfisher_scanner::validation::mysql::validate_mysql;
pub use kingfisher_scanner::validation::postgres::validate_postgres;
pub use kingfisher_scanner::validation::{
    azure, coinbase, gcp, jdbc, jwt, mongodb, mysql, postgres,
};
pub mod utils;

const VALIDATION_CACHE_SECONDS: u64 = 1200; // 20 minutes

fn truncate_to_char_boundary(s: &mut String, max_len: usize) {
    if s.len() <= max_len {
        return;
    }

    let mut new_len = max_len;
    while new_len > 0 && !s.is_char_boundary(new_len) {
        new_len -= 1;
    }

    s.truncate(new_len);
}

/// Build a truncated preview from `body` without cloning the full string.
/// When `max_len` is 0, truncation is disabled and the full body is returned.
fn truncate_preview(body: &str, max_len: usize) -> String {
    if max_len == 0 || body.len() <= max_len {
        return body.to_string();
    }
    let mut end = max_len;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_string()
}

static USER_AGENT_SUFFIX: OnceLock<String> = OnceLock::new();

const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36";

fn build_user_agent() -> String {
    let base = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    if let Some(suffix) = USER_AGENT_SUFFIX.get() {
        format!("{base} {suffix} {BROWSER_USER_AGENT}")
    } else {
        format!("{base} {BROWSER_USER_AGENT}")
    }
}

pub static GLOBAL_USER_AGENT: LazyLock<String> = LazyLock::new(build_user_agent);

/// Configure a user-agent suffix that is appended after the Kingfisher package name/version.
///
/// The suffix is inserted before the browser portion of the user-agent. Empty or whitespace-only
/// values are ignored. This should be called once near program start prior to accessing
/// [`GLOBAL_USER_AGENT`].
pub fn set_user_agent_suffix<S: Into<String>>(suffix: Option<S>) {
    if let Some(suffix) = suffix {
        let trimmed = suffix.into().trim().to_string();
        if trimmed.is_empty() {
            return;
        }

        let _ = USER_AGENT_SUFFIX.set(trimmed.clone());
        kingfisher_scanner::validation::set_user_agent_suffix(Some(trimmed));
    }
}

/// Holds HTTP clients for different TLS validation modes.
///
/// This struct is created once at scan startup and passed through the validation chain.
/// The appropriate client is selected based on the global TLS mode and each rule's
/// declared `tls_mode` setting.
#[derive(Clone)]
pub struct ValidationClients {
    /// Client with full TLS certificate validation (WebPKI chain, hostname, expiry).
    strict: Client,
    /// Strict-TLS client that never follows redirects, used when sending URI credentials.
    strict_credential_uri: Client,
    /// Client that accepts self-signed or invalid certificates.
    /// Used when `--tls-mode=lax` AND the rule opts into lax validation,
    /// or when `--tls-mode=off`.
    lax: Client,
    /// Lax-TLS client that never follows redirects, used when sending URI credentials.
    lax_credential_uri: Client,
    /// The global TLS mode from CLI arguments.
    pub global_mode: TlsMode,
    /// When true, skip SSRF IP validation and allow requests to internal/private addresses.
    pub allow_internal_ips: bool,
}

/// Build a redirect policy that validates redirect targets against SSRF rules.
///
/// Each redirect hop is checked: IP-literal targets are validated directly via
/// `is_ssrf_safe_ip`, and hostname targets are resolved synchronously via
/// `std::net::ToSocketAddrs` so that all resolved IPs can be checked. This
/// significantly reduces the hostname-redirect SSRF risk (e.g., a public URL
/// that 302s to an attacker-controlled hostname resolving to `169.254.169.254`).
/// This is a best-effort check: reqwest performs its own DNS resolution when
/// connecting, so a malicious DNS server could return different IPs between
/// this check and the actual request (DNS rebinding / TOCTOU). A future
/// hardening step would be a pinned/custom resolver so that validated IPs are
/// exactly those used for the outbound connection.
///
/// **Note:** reqwest runs redirect callbacks on Tokio worker threads. The DNS
/// lookup uses `tokio::task::block_in_place` so the runtime can compensate
/// (e.g., spawn additional worker threads) rather than silently stalling.
pub(crate) fn ssrf_safe_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        // Cap redirect depth (reqwest default is 10)
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        // Extract URL info before potentially moving `attempt`.
        let url = attempt.url().clone();
        if let Some(host) = url.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                // IP-literal: check directly without DNS.
                if !kingfisher_scanner::validation::is_ssrf_safe_ip(&ip) {
                    return attempt.error(format!(
                        "SSRF protection: redirect to non-public IP {} blocked",
                        ip
                    ));
                }
            } else {
                // Hostname: resolve and check all resolved IPs. We use
                // block_in_place to signal Tokio that this thread is about to
                // block on synchronous DNS, so the runtime can compensate.
                let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
                let dns_result = tokio::task::block_in_place(|| {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                });
                match dns_result {
                    Ok(addrs) => {
                        for addr in addrs {
                            if !kingfisher_scanner::validation::is_ssrf_safe_ip(&addr.ip()) {
                                return attempt.error(format!(
                                    "SSRF protection: redirect to '{}' resolves to non-public IP {} — blocked",
                                    host,
                                    addr.ip()
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        // Fail closed: if we cannot resolve the hostname, we
                        // cannot guarantee the redirect target is SSRF-safe.
                        return attempt.error(format!(
                            "SSRF protection: cannot resolve redirect host '{}' ({}) — blocked",
                            host, e
                        ));
                    }
                }
            }
        }
        attempt.follow()
    })
}

impl ValidationClients {
    /// Create validation clients based on the global TLS mode.
    pub fn new(global_mode: TlsMode, allow_internal_ips: bool) -> anyhow::Result<Self> {
        let timeout = std::time::Duration::from_secs(30);

        let strict = Client::builder()
            .danger_accept_invalid_certs(false)
            .redirect(if allow_internal_ips {
                reqwest::redirect::Policy::default()
            } else {
                ssrf_safe_redirect_policy()
            })
            .timeout(timeout)
            .build()?;

        let lax = Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(if allow_internal_ips {
                reqwest::redirect::Policy::default()
            } else {
                ssrf_safe_redirect_policy()
            })
            .timeout(timeout)
            .build()?;

        let strict_credential_uri = build_credential_uri_client(false, timeout)?;
        let lax_credential_uri = build_credential_uri_client(true, timeout)?;

        Ok(Self {
            strict,
            strict_credential_uri,
            lax,
            lax_credential_uri,
            global_mode,
            allow_internal_ips,
        })
    }

    /// Get the appropriate client for a given rule's TLS mode.
    ///
    /// The effective TLS mode depends on both the global setting and the rule's preference:
    /// - If global mode is `Off`, always use the lax client (no validation).
    /// - If global mode is `Lax` and the rule declares `tls_mode: lax`, use lax client.
    /// - Otherwise, use the strict client.
    pub fn client_for_rule(&self, rule_tls_mode: Option<kingfisher_rules::TlsMode>) -> &Client {
        match self.global_mode {
            TlsMode::Off => &self.lax,
            TlsMode::Lax => {
                // Convert rule's TlsMode to CLI TlsMode for comparison
                let rule_wants_lax = matches!(rule_tls_mode, Some(kingfisher_rules::TlsMode::Lax));
                if rule_wants_lax { &self.lax } else { &self.strict }
            }
            TlsMode::Strict => &self.strict,
        }
    }

    /// Get a redirect-disabled client for credential-bearing URI validation.
    pub fn credential_uri_client_for_rule(
        &self,
        rule_tls_mode: Option<kingfisher_rules::TlsMode>,
    ) -> &Client {
        if self.should_use_lax(rule_tls_mode) {
            &self.lax_credential_uri
        } else {
            &self.strict_credential_uri
        }
    }

    /// Check if lax TLS should be used for a rule.
    ///
    /// This is useful for non-HTTP validators (Postgres, MySQL, etc.) that need to
    /// configure their own TLS settings.
    pub fn should_use_lax(&self, rule_tls_mode: Option<kingfisher_rules::TlsMode>) -> bool {
        match self.global_mode {
            TlsMode::Off => true,
            TlsMode::Lax => matches!(rule_tls_mode, Some(kingfisher_rules::TlsMode::Lax)),
            TlsMode::Strict => false,
        }
    }
}

/// Build a client that cannot forward URI credentials through an automatic redirect.
pub(crate) fn build_credential_uri_client(use_lax_tls: bool, timeout: Duration) -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(use_lax_tls)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()?)
}

// Use SkipMap-based cache instead of a mutex-wrapped FxHashMap.
type Cache = kingfisher_scanner::validation::Cache;

/// Returns an opaque key for internal validation deduplication.
///
/// This is an INTERNAL key used only for validation deduplication within a single scan.
/// It uses `captures.get(0)` to get the primary secret value. Rules with dependent
/// variables also include blob location because validation can depend on nearby context
/// such as an AWS access-key ID paired with a secret access key.
///
/// **Important**: This is distinct from the EXTERNAL `finding_fingerprint` used for:
/// - Baseline comparisons across scans
/// - Deduplication entries in external systems
/// - Reporting output
///
/// The external fingerprint uses `get(1).or_else(get(0))` for backward compatibility
/// and must remain stable. This internal key can evolve independently.
fn validation_dedup_key(m: &OwnedBlobMatch) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kingfisher.validation-dedup.v1\0");
    hash_key_part(&mut hasher, m.rule.syntax().id.as_bytes());

    // CredentialUri reports the password as TOKEN but validates the complete URI. Use the actual
    // validator input so two endpoints that happen to share a password never share a result.
    let capture_value = if matches!(&m.rule.syntax().validation, Some(Validation::CredentialUri)) {
        m.captures
            .captures
            .iter()
            .find(|capture| capture.name.is_some_and(|name| name.eq_ignore_ascii_case("URI")))
            .or_else(|| m.captures.captures.first())
            .map(|capture| capture.raw_value())
    } else {
        m.captures.captures.first().map(|capture| capture.raw_value())
    };
    if let Some(val) = capture_value {
        hash_key_part(&mut hasher, val.as_bytes());
    }

    if !m.rule.syntax().depends_on_rule.is_empty() {
        hash_key_part(&mut hasher, m.blob_id.to_string().as_bytes());
        hash_key_part(&mut hasher, &m.matching_input_offset_span.start.to_le_bytes());
        hash_key_part(&mut hasher, &m.matching_input_offset_span.end.to_le_bytes());
    }

    *hasher.finalize().as_bytes()
}

fn hash_key_part(hasher: &mut blake3::Hasher, part: &[u8]) {
    hasher.update(&(part.len() as u64).to_le_bytes());
    hasher.update(part);
}

static VALIDATION_CACHE: OnceLock<DashMap<[u8; 32], CachedResponse>> = OnceLock::new();
static IN_FLIGHT: OnceLock<DashMap<[u8; 32], Arc<Notify>>> = OnceLock::new();

fn cache_validation_result(fp: [u8; 32], m: &OwnedBlobMatch) {
    VALIDATION_CACHE.get_or_init(DashMap::new).insert(
        fp,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: m.validation_outcome,
            timestamp: Instant::now(),
        },
    );
}

fn clear_in_flight_validation(fp: [u8; 32]) {
    if let Some((_, notify)) = IN_FLIGHT.get_or_init(DashMap::new).remove(&fp) {
        notify.notify_waiters();
    }
}

/// Call this once near program start (e.g. in `main()`)
pub fn init_validation_caches() {
    VALIDATION_CACHE.set(DashMap::new()).ok();
    IN_FLIGHT.set(DashMap::new()).ok();
    aws::set_aws_validation_concurrency(15);
}

/// Clear the static validation caches to reclaim memory after validation completes.
pub fn clear_validation_caches() {
    if let Some(c) = VALIDATION_CACHE.get() {
        c.clear();
        c.shrink_to_fit();
    }
    if let Some(c) = IN_FLIGHT.get() {
        c.clear();
        c.shrink_to_fit();
    }
}

pub fn set_skip_aws_account_ids<I, S>(ids: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    aws::set_aws_skip_account_ids(ids);
}

#[derive(Debug)]
pub(crate) struct AwsCredentialValidation {
    pub is_valid: bool,
    pub status: StatusCode,
    pub outcome: ValidationOutcome,
    pub message: String,
    pub identity: Option<String>,
    pub account_id: Option<String>,
}

/// Validate one explicit AWS credential pair using the policy shared by scan and direct paths.
pub(crate) async fn validate_aws_credential_pair(
    access_key_id: &str,
    secret_access_key: &str,
    session_token: Option<&str>,
) -> AwsCredentialValidation {
    let account_id = aws::aws_key_to_account_number(access_key_id).ok();

    if let Some(account_id) = aws::should_skip_aws_validation(access_key_id) {
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

    if let Err(message) = aws::validate_aws_credentials_input(access_key_id, secret_access_key) {
        return AwsCredentialValidation {
            is_valid: false,
            status: StatusCode::BAD_REQUEST,
            outcome: ValidationOutcome::Unavailable,
            message,
            identity: None,
            account_id,
        };
    }

    match aws::validate_aws_credentials(access_key_id, secret_access_key, session_token).await {
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

/// Returns `true` if the provided string can be parsed as a MongoDB connection URI.
pub fn is_parseable_mongodb_uri(uri: &str) -> bool {
    mongodb::looks_like_mongodb_uri(uri)
}

/// Returns `true` if the provided string can be parsed as a Postgres connection URI.
pub fn is_parseable_postgres_uri(uri: &str) -> bool {
    postgres::parse_postgres_url(uri).is_ok()
}

/// Returns `true` if the provided string can be parsed as a MySQL connection URI.
pub fn is_parseable_mysql_uri(uri: &str) -> bool {
    mysql::parse_mysql_url(uri).is_ok()
}

/// A validator target selected from a credential-bearing URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CredentialUriTarget {
    Http(String),
    MongoDB(String),
    MySQL(String),
    Postgres(String),
    Jdbc(String),
    Unsupported(String),
}

impl CredentialUriTarget {
    pub(crate) fn scheme(&self) -> &str {
        match self {
            Self::Http(uri) => uri.split_once("://").map(|(scheme, _)| scheme).unwrap_or("http"),
            Self::MongoDB(_) => "mongodb",
            Self::MySQL(_) => "mysql",
            Self::Postgres(_) => "postgresql",
            Self::Jdbc(_) => "jdbc",
            Self::Unsupported(scheme) => scheme,
        }
    }

    pub(crate) fn is_parseable(&self) -> bool {
        match self {
            Self::Http(uri) => Url::parse(uri).is_ok_and(|url| {
                url.host_str().is_some_and(|host| !host.is_empty())
                    && !url.username().is_empty()
                    && url.password().is_some_and(|password| !password.is_empty())
            }),
            Self::MongoDB(uri) => is_parseable_mongodb_uri(uri),
            Self::MySQL(uri) => is_parseable_mysql_uri(uri),
            Self::Postgres(uri) => is_parseable_postgres_uri(uri),
            // The JDBC validator performs subprotocol-specific parsing. Treat the outer prefix as
            // structurally valid here so direct validation can return its precise diagnostic.
            Self::Jdbc(uri) => uri.len() > "jdbc:".len(),
            Self::Unsupported(_) => true,
        }
    }
}

fn normalize_uri_scheme(uri: &str, scheme: &str) -> Option<String> {
    let (_, rest) = uri.split_once("://")?;
    Some(format!("{scheme}://{rest}"))
}

/// Classify a credential URI without performing network I/O.
///
/// The scheme is normalized before it reaches case-sensitive database drivers. MariaDB URLs use
/// the MySQL wire protocol and are normalized to the `mysql://` spelling accepted by
/// `mysql_async`.
pub(crate) fn classify_credential_uri(uri: &str, scheme_hint: Option<&str>) -> CredentialUriTarget {
    let uri = uri.trim();
    let scheme = scheme_hint
        .map(str::trim)
        .filter(|scheme| !scheme.is_empty())
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            uri.split_once("://").map(|(scheme, _)| scheme.to_ascii_lowercase()).or_else(|| {
                uri.get(..5)
                    .filter(|prefix| prefix.eq_ignore_ascii_case("jdbc:"))
                    .map(|_| "jdbc".to_string())
            })
        })
        .unwrap_or_default();

    match scheme.as_str() {
        "http" | "https" => normalize_uri_scheme(uri, &scheme)
            .map(CredentialUriTarget::Http)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "mongodb" => normalize_uri_scheme(uri, "mongodb")
            .map(CredentialUriTarget::MongoDB)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "mongodb+srv" => normalize_uri_scheme(uri, "mongodb+srv")
            .map(CredentialUriTarget::MongoDB)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "mysql" | "mariadb" => normalize_uri_scheme(uri, "mysql")
            .map(CredentialUriTarget::MySQL)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "postgres" => normalize_uri_scheme(uri, "postgres")
            .map(CredentialUriTarget::Postgres)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "postgresql" => normalize_uri_scheme(uri, "postgresql")
            .map(CredentialUriTarget::Postgres)
            .unwrap_or_else(|| CredentialUriTarget::Unsupported(scheme)),
        "jdbc" => CredentialUriTarget::Jdbc(uri.to_string()),
        _ => CredentialUriTarget::Unsupported(scheme),
    }
}

/// Return whether a supported credential URI can be parsed by its target database driver.
/// Unsupported schemes remain reportable and are intentionally left unvalidated.
pub(crate) fn is_parseable_credential_uri(uri: &str, scheme: Option<&str>) -> bool {
    classify_credential_uri(uri, scheme).is_parseable()
}

fn has_basic_auth_challenge(headers: &HeaderMap) -> bool {
    headers.get_all(header::WWW_AUTHENTICATE).iter().filter_map(|value| value.to_str().ok()).any(
        |value| {
            // A comma can separate either challenges or parameters within one challenge. Only
            // accept Basic when it is the unambiguous first scheme in a field value; rejecting a
            // valid later challenge is safer than sending credentials in response to a parameter
            // that happens to start with "basic".
            let challenge = value.trim_start();
            challenge.get(..5).is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic"))
                && challenge.as_bytes().get(5).is_none_or(|byte| byte.is_ascii_whitespace())
        },
    )
}

fn received_basic_auth_challenge(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::UNAUTHORIZED && has_basic_auth_challenge(headers)
}

/// Validate an HTTPS credential URI using the username and password as HTTP Basic Auth.
///
/// The credentials are removed from the request URL before dispatch so they cannot be echoed in
/// request errors, redirects, or debug output. Credentials are sent only after an unauthenticated
/// request receives an explicit Basic Auth challenge. A subsequent successful response proves that
/// the endpoint accepted them; only HTTP 401 is authoritative rejection, while other response
/// statuses are reported as inconclusive by the caller.
pub(crate) async fn validate_http_credential_uri(
    uri: &str,
    client: &Client,
    timeout: Duration,
    retries: u32,
    allow_internal_ips: bool,
) -> Result<(bool, StatusCode, String)> {
    let mut url =
        Url::parse(uri).map_err(|error| anyhow!("Invalid HTTP credential URI: {error}"))?;
    if url.scheme() != "https" {
        return Err(anyhow!("HTTP credential URI validation requires HTTPS"));
    }

    let username = percent_decode_str(url.username())
        .decode_utf8()
        .map_err(|_| anyhow!("HTTP credential URI username is not valid UTF-8"))?
        .into_owned();
    let password = url
        .password()
        .filter(|password| !password.is_empty())
        .ok_or_else(|| anyhow!("HTTP credential URI is missing a password"))?;
    let password = percent_decode_str(password)
        .decode_utf8()
        .map_err(|_| anyhow!("HTTP credential URI password is not valid UTF-8"))?
        .into_owned();
    if username.is_empty() {
        return Err(anyhow!("HTTP credential URI is missing a username"));
    }
    if username.contains(':') {
        return Err(anyhow!("HTTP Basic Auth usernames cannot contain ':'"));
    }

    httpvalidation::check_url_resolvable(&url, allow_internal_ips)
        .await
        .map_err(|error| anyhow!("HTTP credential URI resolution failed: {error}"))?;

    url.set_username("").map_err(|_| anyhow!("Failed to remove HTTP URI username"))?;
    url.set_password(None).map_err(|_| anyhow!("Failed to remove HTTP URI password"))?;

    let unauthenticated = httpvalidation::retry_request(
        client
            .get(url.clone())
            .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
            .timeout(timeout),
        retries,
        Duration::from_millis(500),
        Duration::from_secs(2),
    )
    .await
    .map_err(|error| anyhow!("HTTP credential URI challenge request failed: {error}"))?;

    let challenge_status = unauthenticated.status();
    if unauthenticated.url() != &url {
        return Ok((
            false,
            StatusCode::BAD_GATEWAY,
            "HTTP Basic Auth validation was inconclusive: challenge request was redirected"
                .to_string(),
        ));
    }
    if !received_basic_auth_challenge(challenge_status, unauthenticated.headers()) {
        return Ok((
            false,
            StatusCode::BAD_GATEWAY,
            format!(
                "HTTP Basic Auth validation was inconclusive: unauthenticated request did not receive a Basic challenge (HTTP {challenge_status})"
            ),
        ));
    }
    drop(unauthenticated);

    let authenticated = httpvalidation::retry_request(
        client
            .get(url.clone())
            .basic_auth(username, Some(password))
            .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
            .timeout(timeout),
        retries,
        Duration::from_millis(500),
        Duration::from_secs(2),
    )
    .await
    .map_err(|error| anyhow!("HTTP credential URI request failed: {error}"))?;

    let response_status = authenticated.status();
    if authenticated.url() != &url {
        return Ok((
            false,
            StatusCode::BAD_GATEWAY,
            format!(
                "HTTP Basic Auth validation was inconclusive: authenticated request was redirected (HTTP {response_status})"
            ),
        ));
    }
    let valid = response_status.is_success();
    let status = if valid || response_status == StatusCode::UNAUTHORIZED {
        response_status
    } else {
        // A generic endpoint cannot distinguish a bad credential from a missing route,
        // authorization policy, or a server failure. Keep those responses inconclusive.
        StatusCode::BAD_GATEWAY
    };
    let message = if valid {
        format!("HTTP Basic Auth accepted (HTTP {status})")
    } else if response_status == StatusCode::UNAUTHORIZED {
        "HTTP Basic Auth rejected (HTTP 401 Unauthorized)".to_string()
    } else {
        format!("HTTP Basic Auth validation was inconclusive (HTTP {})", response_status)
    };
    Ok((valid, status, message))
}

/// Collect dependent variables and missing dependencies from the provided matches.
#[allow(clippy::type_complexity)]
pub fn collect_variables_and_dependencies(
    matches: &[OwnedBlobMatch],
) -> (FxHashMap<String, Vec<(String, OffsetSpan)>>, FxHashMap<String, Vec<String>>) {
    let mut variable_map: FxHashMap<String, Vec<(String, OffsetSpan)>> = FxHashMap::default();
    let mut missing_deps: FxHashMap<String, Vec<String>> = FxHashMap::default();

    for m in matches {
        let rule_id = m.rule.syntax().id.clone();
        for dependency in m.rule.syntax().depends_on_rule.iter().flatten() {
            if dependency.within.is_some() {
                let variable = dependency.variable.to_uppercase();
                if let Some(value) = m.dependent_captures.get(&variable) {
                    variable_map
                        .entry(variable)
                        .or_default()
                        .push((value.clone(), m.matching_input_offset_span));
                } else if !dependency.optional {
                    missing_deps
                        .entry(rule_id.clone())
                        .or_default()
                        .push(dependency.rule_id.clone());
                }
                continue;
            }
            let dependency_rule_id = &dependency.rule_id;
            // Use iterator adapter to get all matching dependencies.
            let matching_dependencies: Vec<_> =
                matches.iter().filter(|x| x.rule.syntax().id == *dependency_rule_id).collect();

            if !matching_dependencies.is_empty() {
                for other_match in matching_dependencies {
                    // VALIDATION: Use get(0) for the primary capture value when collecting
                    // dependent variables. This ensures we get the main captured value rather
                    // than inner unnamed groups from nested captures like (?<REGEX>...(ABC)...).
                    //
                    // Note: This differs from fingerprint/reporting code which uses
                    // get(1).or_else(get(0)) for backward compatibility.
                    let matching_input = other_match
                        .captures
                        .captures
                        .first()
                        .expect("Expected at least one capture");
                    variable_map.entry(dependency.variable.to_uppercase()).or_default().push((
                        matching_input.raw_value().to_string(),
                        other_match.matching_input_offset_span,
                    ));
                }
            } else if !dependency.optional {
                missing_deps.entry(rule_id.clone()).or_default().push(dependency.rule_id.clone());
            }
        }
    }
    (variable_map, missing_deps)
}

/// Render a template and parse the resulting string as a URL.
async fn render_and_parse_url(
    parser: &liquid::Parser,
    globals: &liquid::Object,
    rule_name: &str,
    template_url: &str,
    allow_internal_ips: bool,
) -> Result<Url, String> {
    let rendered_url_str =
        render_template(parser, globals, rule_name, template_url).await.map_err(|e| {
            let error_msg = format!("Error rendering URL template: <{}> {}", rule_name, e);
            debug!("{}", error_msg);
            error_msg
        })?;

    let url = Url::parse(&rendered_url_str).map_err(|e| {
        let error_msg = format!("Error parsing rendered URL: {}", e);
        debug!("{}", error_msg);
        error_msg
    })?;

    // Check if the URL is resolvable (with SSRF protection).
    utils::check_url_resolvable(&url, allow_internal_ips).await.map_err(|e| {
        // Rendered URLs can carry the candidate secret in a query string.
        // This error is persisted in reports, so do not include the URL.
        let error_msg = format!("Validation endpoint resolution failed: {}", e);
        error_msg
    })?;

    Ok(url)
}

/// Render a template string using Liquid.
async fn render_template(
    parser: &liquid::Parser,
    globals: &liquid::Object,
    rule_name: &str,
    template_str: &str,
) -> Result<String, String> {
    parser
        .parse(template_str)
        .map_err(|e| {
            let msg = format!("Error parsing template for rule <{}>: {}", rule_name, e);
            debug!("{}", msg);
            msg
        })
        .and_then(|template| {
            template.render(globals).map_err(|e| {
                let msg = format!("Error rendering template for rule <{}>: {}", rule_name, e);
                debug!("{}", msg);
                msg
            })
        })
}

/// Validate a single match with a configurable timeout.
#[allow(clippy::too_many_arguments)]
pub async fn validate_single_match(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    clients: &ValidationClients,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
    validation_timeout: Duration,
    validation_retries: u32,
    rate_limiter: Option<&crate::validation_rate_limit::ValidationRateLimiter>,
    provider_endpoints: &ProviderEndpointOverrides,
    max_body_len: usize,
) {
    if !m.rule.syntax().is_authoritative() {
        m.validation_success = false;
        m.validation_response_status = StatusCode::CONTINUE;
        m.validation_response_body = None;
        m.validation_outcome = ValidationOutcome::NotAttempted;
        return;
    }

    let fp = validation_dedup_key(m);
    // Keep the unwind boundary inside this module so the process-wide
    // validation de-dupe state is cleared before the caller observes a panic.
    // The panic branch below overwrites the match with a deterministic failure.
    let timeout_result = time::timeout(
        validation_timeout,
        AssertUnwindSafe(
            timed_validate_single_match(
                m,
                parser,
                clients,
                dependent_variables,
                missing_dependencies,
                cache,
                validation_timeout,
                validation_retries,
                rate_limiter,
                provider_endpoints,
                max_body_len,
            )
            .boxed(),
        )
        .catch_unwind(),
    )
    .await;

    match timeout_result {
        Ok(Ok(())) => {}
        Ok(Err(_panic_payload)) => {
            warn!(
                rule_id = %m.rule.syntax().id,
                "validator panicked; marking match as failed",
            );
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "Validation panicked for rule {}",
                m.rule.syntax().id
            ));
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            cache_validation_result(fp, m);
            clear_in_flight_validation(fp);
        }
        Err(_) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "Validation timed out after {} seconds",
                validation_timeout.as_secs()
            ));
            m.validation_response_status = StatusCode::REQUEST_TIMEOUT;
            cache_validation_result(fp, m);
            clear_in_flight_validation(fp);
        }
    }
    m.refresh_validation_outcome();
}

/// Perform the actual validation of a match.
/// Guarantees that each <RULE-ID>|<secret> is validated only once per process,
/// even when `--no-dedup` is used.
#[allow(clippy::too_many_arguments)]
async fn timed_validate_single_match(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    clients: &ValidationClients,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
    validation_timeout: Duration,
    validation_retries: u32,
    rate_limiter: Option<&crate::validation_rate_limit::ValidationRateLimiter>,
    provider_endpoints: &ProviderEndpointOverrides,
    max_body_len: usize,
) {
    // Select the appropriate HTTP client based on rule's TLS mode preference
    let rule_tls_mode = m.rule.tls_mode();
    let client = clients.client_for_rule(rule_tls_mode);
    let use_lax_tls = clients.should_use_lax(rule_tls_mode);
    // ──────────────────────────────────────────────────────────
    // 1. process-wide fingerprint de-dup
    // ──────────────────────────────────────────────────────────
    let fp = validation_dedup_key(m);

    if let Some(entry) = VALIDATION_CACHE.get_or_init(DashMap::new).get(&fp)
        && entry.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS)
    {
        m.validation_success = entry.is_valid;
        m.validation_response_body = entry.body.clone();
        m.validation_response_status = entry.status;
        m.validation_outcome = entry.outcome;
        return;
    }
    if let Some(wait) =
        IN_FLIGHT.get_or_init(DashMap::new).get(&fp).map(|entry| entry.value().clone())
    {
        wait.notified().await;
        if let Some(entry) = VALIDATION_CACHE.get().unwrap().get(&fp) {
            m.validation_success = entry.is_valid;
            m.validation_response_body = entry.body.clone();
            m.validation_response_status = entry.status;
            m.validation_outcome = entry.outcome;
        }
        return;
    }
    IN_FLIGHT.get().unwrap().insert(fp, Arc::new(Notify::new()));

    // helper to persist result + notify waiters
    let commit_and_return = |m: &OwnedBlobMatch| {
        cache_validation_result(fp, m);
        clear_in_flight_validation(fp);
    };
    // ──────────────────────────────────────────────────────────

    // 2. dependency check
    if let Some(missing) = missing_dependencies.get(&m.rule.syntax().id)
        && !missing.is_empty()
    {
        m.validation_success = false;
        m.validation_response_body = validation_body::from_string(format!(
            "Validation skipped - missing dependent rules: {}",
            missing.join(", ")
        ));
        m.validation_response_status = StatusCode::PRECONDITION_REQUIRED;
        commit_and_return(m);
        return;
    }

    // 3. capture processing
    let match_re_result = m.rule.syntax().as_anchored_regex();
    let mut captured_values: Vec<(String, String, usize, usize)> = match match_re_result {
        Ok(_) => utils::process_captures(&m.captures),
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Regex error: {}", e));
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            commit_and_return(m);
            return;
        }
    };

    for dep in m.rule.syntax().depends_on_rule.iter().flatten() {
        // Skip adding captured values for TOKEN dependencies
        if dep.variable.eq_ignore_ascii_case("TOKEN") {
            continue;
        }
        let dep_name = dep.variable.to_uppercase();
        if let Some(value) = m.dependent_captures.get(&dep_name).cloned() {
            captured_values.push((
                dep_name.clone(),
                value,
                m.matching_input_offset_span.start,
                m.matching_input_offset_span.end,
            ));
            continue;
        }
        if let Some(vals) = dependent_variables.get(&dep_name)
            && let Some((val, span)) =
                select_closest_dependency_value(vals, m.matching_input_offset_span)
        {
            captured_values.push((dep_name.clone(), val.clone(), span.start, span.end));
            // Store the dependent capture for later use in reporting
            // (e.g., generating validate/revoke commands)
            m.dependent_captures.insert(dep_name, val);
        }
    }

    let mut globals = Object::new();
    populate_globals_from_captures(&mut globals, &captured_values);
    hydrate_endpoint_globals_for_rule(m.rule.id(), &mut globals);
    provider_endpoints.apply_scan_overrides(&mut globals);

    // Persist named captures (non-TOKEN) for validate/revoke command generation.
    // This is especially important for gRPC validators like Modal where TOKEN_ID is required.
    for (k, v, ..) in &captured_values {
        if k.eq_ignore_ascii_case("TOKEN") {
            continue;
        }
        m.dependent_captures.entry(k.to_uppercase()).or_insert_with(|| v.clone());
    }
    for endpoint_var in endpoint_var_names() {
        if let Some(value) = globals.get(*endpoint_var).and_then(|v| v.as_scalar()) {
            m.dependent_captures
                .entry((*endpoint_var).to_string())
                .or_insert_with(|| value.to_kstr().to_string());
        }
    }

    {
        let rule_syntax = m.rule.syntax();
        if let (Some(limiter), Some(validation)) = (rate_limiter, rule_syntax.validation.as_ref())
            && should_rate_limit_validation(validation)
        {
            limiter.wait_for_rule(m.rule.id()).await;
        }
    }

    // ──────────────────────────────────────────────────────────
    // 4. validator dispatch
    //
    // Each validator lives in its own async fn so LLVM compiles
    // a separate, smaller poll function for each one.  This
    // prevents the combined stack frame from blowing the stack
    // on large concurrent workloads.
    //
    // We clone the validation enum to release the immutable
    // borrow on `m` before passing `m` mutably to each helper.
    // ──────────────────────────────────────────────────────────
    let rule_name = m.rule.syntax().name.clone();
    let validation = m.rule.syntax().validation.clone();
    let rule_tls_mode_for_raw = m.rule.syntax().tls_mode;

    match &validation {
        Some(Validation::Assumed) => {
            // Assumed validation intentionally produces no live validation result.
        }
        Some(Validation::Ethereum(kind)) => {
            let token = captured_values
                .iter()
                .find(|(name, ..)| name.eq_ignore_ascii_case("TOKEN"))
                .or_else(|| captured_values.first())
                .map(|(_, value, ..)| value.as_str());
            if let Some(token) = token {
                let result = kingfisher_scanner::validation::ethereum::validate(*kind, token);
                m.validation_success = false;
                m.validation_response_body = validation_body::from_string(result.body);
                m.validation_response_status = StatusCode::CONTINUE;
                m.validation_outcome = result.outcome;
            } else {
                m.validation_success = false;
                m.validation_response_body =
                    validation_body::from_string("Ethereum validation requires TOKEN capture");
                m.validation_response_status = StatusCode::BAD_REQUEST;
                m.validation_outcome = ValidationOutcome::Unavailable;
            }
        }
        Some(Validation::Http(http_validation)) => {
            validate_http(
                m,
                http_validation,
                client,
                parser,
                &globals,
                cache,
                &rule_name,
                clients.allow_internal_ips,
                validation_timeout,
                validation_retries,
                max_body_len,
            )
            .await;
        }
        Some(Validation::Betterleaks(betterleaks_validation)) => {
            let outcome = crate::betterleaks_validation::validate(
                betterleaks_validation,
                &captured_values,
                &globals,
                client,
                clients.allow_internal_ips,
            )
            .await;
            m.validation_success = outcome.valid;
            m.validation_response_status = outcome.status;
            m.validation_response_body = validation_body::from_string(outcome.body);
            m.validation_outcome = outcome.outcome;
        }
        Some(Validation::Grpc(grpc_validation_cfg)) => {
            validate_grpc(
                m,
                grpc_validation_cfg,
                parser,
                &globals,
                &rule_name,
                clients.allow_internal_ips,
                validation_timeout,
                max_body_len,
            )
            .await;
        }
        Some(Validation::MongoDB) => {
            validate_mongodb_rule(m, &globals, cache, use_lax_tls, clients.allow_internal_ips)
                .await;
        }
        Some(Validation::MySQL) => {
            validate_mysql_rule(m, &globals, cache, use_lax_tls, clients.allow_internal_ips).await;
        }
        Some(Validation::AzureStorage) => {
            validate_azure_storage(m, &captured_values, cache).await;
        }
        Some(Validation::Jdbc) => {
            validate_jdbc_rule(m, &captured_values, cache, use_lax_tls, clients.allow_internal_ips)
                .await;
        }
        Some(Validation::CredentialUri) => {
            validate_credential_uri_rule(
                m,
                &captured_values,
                clients.credential_uri_client_for_rule(rule_tls_mode),
                cache,
                use_lax_tls,
                clients.allow_internal_ips,
                validation_timeout,
                validation_retries,
            )
            .await;
        }
        Some(Validation::Postgres) => {
            validate_postgres_rule(m, &globals, cache, use_lax_tls, clients.allow_internal_ips)
                .await;
        }
        Some(Validation::JWT) => {
            validate_jwt_rule(m, &captured_values, use_lax_tls, clients.allow_internal_ips).await;
        }
        Some(Validation::AWS) => {
            validate_aws_rule(m, &captured_values, dependent_variables, cache).await;
        }
        Some(Validation::GCP) => {
            validate_gcp_rule(m, &globals, cache).await;
        }
        Some(Validation::Coinbase) => {
            validate_coinbase_rule(m, &globals, client, parser, cache).await;
        }
        Some(Validation::Raw(raw)) => {
            validate_raw_rule(
                m,
                raw,
                &globals,
                client,
                clients.should_use_lax(rule_tls_mode_for_raw),
                clients.allow_internal_ips,
            )
            .await;
        }
        None => { /* no validation specified */ }
    }

    // 5. persist result for success path
    commit_and_return(m);
}

// ═══════════════════════════════════════════════════════════════
// Extracted validator functions
// ═══════════════════════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
async fn validate_http(
    m: &mut OwnedBlobMatch,
    http_validation: &kingfisher_rules::rule::HttpValidation,
    client: &Client,
    parser: &liquid::Parser,
    globals: &Object,
    cache: &Cache,
    rule_name: &str,
    allow_internal_ips: bool,
    validation_timeout: Duration,
    validation_retries: u32,
    max_body_len: usize,
) {
    let request_timeout = validation_timeout;
    let multipart_timeout = validation_timeout;
    let max_retries: u32 = validation_retries;
    let request_globals = httpvalidation::with_request_template_globals(globals);
    let cache_globals = httpvalidation::with_cache_key_template_globals(globals);

    let url = match render_and_parse_url(
        parser,
        &request_globals,
        rule_name,
        &http_validation.request.url,
        allow_internal_ips,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let request_builder = match httpvalidation::build_request_builder(
        client,
        &http_validation.request.method,
        &url,
        &http_validation.request.headers,
        &http_validation.request.body,
        request_timeout,
        parser,
        &request_globals,
    ) {
        Ok(rb) => rb,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let is_multipart = http_validation.request.multipart.is_some();
    let mut cache_key = String::new();

    if !is_multipart {
        let cache_url =
            render_template(parser, &cache_globals, rule_name, &http_validation.request.url)
                .await
                .unwrap_or_else(|_| http_validation.request.url.clone());

        let rendered_headers = httpvalidation::process_headers(
            &http_validation.request.headers,
            parser,
            &cache_globals,
            &url,
        )
        .unwrap_or_default();

        let mut header_map = BTreeMap::new();
        for (name, value) in rendered_headers.iter() {
            if let Ok(v) = value.to_str() {
                header_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        let rendered_body = http_validation.request.body.as_ref().and_then(|body_template| {
            parser
                .parse(body_template)
                .ok()
                .and_then(|template| template.render(&cache_globals).ok())
        });

        cache_key = httpvalidation::generate_http_cache_key_parts(
            http_validation.request.method.as_str(),
            &cache_url,
            &header_map,
            rendered_body.as_deref(),
        );
        if let Some(cached) = cache.get(&cache_key) {
            let c = cached.value();
            if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                m.validation_success = c.is_valid;
                m.validation_response_body = c.body.clone();
                m.validation_response_status = c.status;
                return;
            }
        }
    }

    let exec_single = |builder: reqwest::RequestBuilder| async {
        httpvalidation::retry_request(
            builder,
            max_retries,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .await
    };

    let resp_res = if is_multipart {
        let build_request = || async {
            let method = httpvalidation::parse_http_method(&http_validation.request.method)
                .unwrap_or(reqwest::Method::GET);

            let mut fresh_builder = client.request(method, url.clone()).timeout(multipart_timeout);

            if let Ok(mut headers) = httpvalidation::process_headers(
                &http_validation.request.headers,
                parser,
                &request_globals,
                &url,
            ) {
                let std_headers = [
                    (header::USER_AGENT, GLOBAL_USER_AGENT.as_str()),
                    (
                        header::ACCEPT,
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    ),
                    (header::ACCEPT_LANGUAGE, "en-US,en;q=0.5"),
                    (header::ACCEPT_ENCODING, "gzip, deflate, br"),
                    (header::CONNECTION, "keep-alive"),
                ];
                for (hn, hv) in &std_headers {
                    if let Ok(v) = HeaderValue::from_str(hv) {
                        headers.insert(hn.clone(), v);
                    }
                }
                fresh_builder = fresh_builder.headers(headers);
            }

            let mut form = multipart::Form::new();
            for part in http_validation.request.multipart.as_ref().unwrap().parts.iter() {
                match part.part_type.as_str() {
                    "file" => {
                        let path =
                            render_template(parser, &request_globals, rule_name, &part.content)
                                .await
                                .unwrap_or_default();
                        let bytes = fs::read(path).unwrap_or_default();
                        let p = multipart::Part::bytes(bytes)
                            .mime_str(
                                part.content_type.as_deref().unwrap_or("application/octet-stream"),
                            )
                            .unwrap_or_else(|_| multipart::Part::text("invalid"));
                        form = form.part(part.name.clone(), p);
                    }
                    "text" => {
                        let txt =
                            render_template(parser, &request_globals, rule_name, &part.content)
                                .await
                                .unwrap_or_default();
                        let p = multipart::Part::text(txt)
                            .mime_str(part.content_type.as_deref().unwrap_or("text/plain"))
                            .unwrap_or_else(|_| multipart::Part::text("invalid"));
                        form = form.part(part.name.clone(), p);
                    }
                    _ => { /* ignore */ }
                }
            }
            fresh_builder.multipart(form)
        };

        httpvalidation::retry_multipart_request(
            build_request,
            max_retries as usize,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .await
    } else {
        exec_single(request_builder).await
    };

    match resp_res {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body =
                        validation_body::from_string(format!("Error reading response: {}", e));
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                    return;
                }
            };
            let display_body = if http_validation.request.response_is_html {
                utils::format_response_body_for_display(&body, max_body_len, true)
            } else {
                truncate_preview(&body, max_body_len)
            };

            m.validation_response_status = status;
            let body_opt = validation_body::from_string(display_body.clone());
            m.validation_response_body = body_opt.clone();
            let matchers = match http_validation.request.response_matcher.as_ref() {
                Some(m) => m,
                None => {
                    m.validation_success = false;
                    m.validation_response_body = validation_body::from_string(format!(
                        "HTTP validation for rule '{}' is missing `response_matcher`",
                        rule_name
                    ));
                    m.validation_response_status = StatusCode::BAD_REQUEST;
                    return;
                }
            };

            m.validation_success = httpvalidation::validate_response(
                matchers,
                &body,
                &status,
                &headers,
                http_validation.request.response_is_html,
            );

            let cacheable_status = !(status.is_server_error()
                || status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::REQUEST_TIMEOUT);
            if !is_multipart && !cache_key.is_empty() && cacheable_status {
                cache.insert(
                    cache_key,
                    CachedResponse {
                        body: body_opt,
                        status,
                        is_valid: m.validation_success,
                        outcome: ValidationOutcome::from_legacy(
                            false,
                            m.validation_success,
                            status.as_u16(),
                        ),
                        timestamp: Instant::now(),
                    },
                );
            }
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("HTTP error: {:?}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn validate_grpc(
    m: &mut OwnedBlobMatch,
    grpc_validation_cfg: &kingfisher_rules::rule::GrpcValidation,
    parser: &liquid::Parser,
    globals: &Object,
    rule_name: &str,
    allow_internal_ips: bool,
    validation_timeout: Duration,
    max_body_len: usize,
) {
    let request_globals = httpvalidation::with_request_template_globals(globals);

    let url = match render_and_parse_url(
        parser,
        &request_globals,
        rule_name,
        &grpc_validation_cfg.request.url,
        allow_internal_ips,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let res = match grpc_validation::grpc_unary_call_from_rule(
        &url,
        &grpc_validation_cfg.request.headers,
        &grpc_validation_cfg.request.body,
        parser,
        &request_globals,
        validation_timeout,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!("gRPC error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
            return;
        }
    };

    let status = StatusCode::from_u16(res.http_status.as_u16()).unwrap_or(StatusCode::OK);
    let headers = res.headers;
    let mut body = String::from_utf8_lossy(&res.body_bytes).to_string();

    let grpc_status =
        headers.get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let grpc_message =
        headers.get("grpc-message").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if grpc_status == "0" {
        body = "grpc-status=0".to_string();
    } else if (body.trim().is_empty() && (!grpc_status.is_empty() || !grpc_message.is_empty()))
        || body.as_bytes().contains(&0)
    {
        body = format!("grpc-status={grpc_status} grpc-message={grpc_message}");
    }
    if max_body_len > 0 {
        truncate_to_char_boundary(&mut body, max_body_len);
    }

    m.validation_response_status = status;
    m.validation_response_body = validation_body::from_string(body.clone());

    let matchers = match grpc_validation_cfg.request.response_matcher.as_ref() {
        Some(m) => m,
        None => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "gRPC validation for rule '{}' is missing `response_matcher`",
                rule_name
            ));
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    m.validation_success =
        httpvalidation::validate_response(matchers, &body, &status, &headers, false);
}

async fn validate_mongodb_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let uri = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    validate_mongodb_uri(m, &uri, cache, use_lax_tls, allow_internal_ips).await;
}

async fn validate_mongodb_uri(
    m: &mut OwnedBlobMatch,
    uri: &str,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    if uri.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("MongoDB URI not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = mongodb::generate_mongodb_cache_key(uri);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match mongodb::validate_mongodb(uri, use_lax_tls, allow_internal_ips).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(msg);
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("MongoDB validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

async fn validate_mysql_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let mysql_url = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    validate_mysql_uri(m, &mysql_url, cache, use_lax_tls, allow_internal_ips).await;
}

async fn validate_mysql_uri(
    m: &mut OwnedBlobMatch,
    mysql_url: &str,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    if mysql_url.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("MySQL URL not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = mysql::generate_mysql_cache_key(mysql_url);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match mysql::validate_mysql(mysql_url, use_lax_tls, allow_internal_ips).await {
        Ok((ok, meta)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(if ok {
                format!("MySQL connection is valid. Metadata: {:?}", meta)
            } else {
                "MySQL connection failed.".to_string()
            });
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("MySQL error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }

    cache.insert(
        cache_key,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: ValidationOutcome::from_legacy(
                false,
                m.validation_success,
                m.validation_response_status.as_u16(),
            ),
            timestamp: Instant::now(),
        },
    );
}

async fn validate_azure_storage(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    cache: &Cache,
) {
    let storage_key = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();
    let storage_account =
        utils::find_closest_variable(captured_values, storage_key.as_str(), "TOKEN", "AZURENAME")
            .unwrap_or_default();

    if storage_account.is_empty() || storage_key.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing Azure Storage account or key.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let creds_json =
        format!(r#"{{"storage_account":"{}","storage_key":"{}"}}"#, storage_account, storage_key);
    let cache_key = azure::generate_azure_cache_key(&creds_json);

    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match azure::validate_azure_storage_credentials(&creds_json, cache).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = msg;
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Azure Storage error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
    cache.insert(
        cache_key,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: ValidationOutcome::from_legacy(
                false,
                m.validation_success,
                m.validation_response_status.as_u16(),
            ),
            timestamp: Instant::now(),
        },
    );
}

fn captured_value<'a>(
    captured_values: &'a [(String, String, usize, usize)],
    name: &str,
) -> Option<&'a str> {
    captured_values
        .iter()
        .find(|(capture_name, ..)| capture_name.eq_ignore_ascii_case(name))
        .map(|(_, value, ..)| value.as_str())
        .filter(|value| !value.is_empty())
}

#[allow(clippy::too_many_arguments)]
async fn validate_credential_uri_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    client: &Client,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
    validation_timeout: Duration,
    validation_retries: u32,
) {
    let Some(uri) =
        captured_value(captured_values, "URI").or_else(|| captured_value(captured_values, "TOKEN"))
    else {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Credential URI not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    };
    let target = classify_credential_uri(uri, captured_value(captured_values, "SCHEME"));
    if !target.is_parseable() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string(format!("Invalid {} credential URI.", target.scheme()));
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    match target {
        CredentialUriTarget::MongoDB(uri) => {
            validate_mongodb_uri(m, &uri, cache, use_lax_tls, allow_internal_ips).await;
        }
        CredentialUriTarget::MySQL(uri) => {
            validate_mysql_uri(m, &uri, cache, use_lax_tls, allow_internal_ips).await;
        }
        CredentialUriTarget::Postgres(uri) => {
            validate_postgres_uri(m, &uri, cache, use_lax_tls, allow_internal_ips).await;
        }
        CredentialUriTarget::Jdbc(uri) => {
            validate_jdbc_connection(m, &uri, cache, use_lax_tls, allow_internal_ips).await;
        }
        CredentialUriTarget::Http(uri) => {
            match validate_http_credential_uri(
                &uri,
                client,
                validation_timeout,
                validation_retries,
                allow_internal_ips,
            )
            .await
            {
                Ok((valid, status, message)) => {
                    m.validation_success = valid;
                    m.validation_response_status = status;
                    m.validation_response_body = validation_body::from_string(message);
                }
                Err(error) => {
                    m.validation_success = false;
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                    m.validation_response_body = validation_body::from_string(format!(
                        "HTTP credential URI validation error: {error}"
                    ));
                }
            }
        }
        CredentialUriTarget::Unsupported(scheme) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "No live validator is available for {} credential URIs.",
                if scheme.is_empty() { "this" } else { scheme.as_str() }
            ));
            m.validation_response_status = StatusCode::CONTINUE;
        }
    }
}

async fn validate_jdbc_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let jdbc_conn = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    validate_jdbc_connection(m, &jdbc_conn, cache, use_lax_tls, allow_internal_ips).await;
}

async fn validate_jdbc_connection(
    m: &mut OwnedBlobMatch,
    jdbc_conn: &str,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    if jdbc_conn.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("JDBC connection string not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = jdbc::generate_jdbc_cache_key(jdbc_conn);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match jdbc::validate_jdbc(jdbc_conn, use_lax_tls, allow_internal_ips).await {
        Ok(outcome) => {
            m.validation_success = outcome.valid;
            m.validation_response_body = validation_body::from_string(outcome.message);
            m.validation_response_status = outcome.status;
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("JDBC validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }

    cache.insert(
        cache_key,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: ValidationOutcome::from_legacy(
                false,
                m.validation_success,
                m.validation_response_status.as_u16(),
            ),
            timestamp: Instant::now(),
        },
    );
}

async fn validate_postgres_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let pg_url = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    validate_postgres_uri(m, &pg_url, cache, use_lax_tls, allow_internal_ips).await;
}

async fn validate_postgres_uri(
    m: &mut OwnedBlobMatch,
    pg_url: &str,
    cache: &Cache,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    if pg_url.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Postgres URL not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = postgres::generate_postgres_cache_key(pg_url);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match postgres::validate_postgres(pg_url, use_lax_tls, allow_internal_ips).await {
        Ok((ok, meta)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(if ok {
                format!("Postgres connection is valid. Metadata: {:?}", meta)
            } else {
                "Postgres connection failed.".to_string()
            });
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Postgres error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
    cache.insert(
        cache_key,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: ValidationOutcome::from_legacy(
                false,
                m.validation_success,
                m.validation_response_status.as_u16(),
            ),
            timestamp: Instant::now(),
        },
    );
}

async fn validate_jwt_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let token = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    if token.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("JWT token not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    match jwt::validate_jwt(&token, use_lax_tls, allow_internal_ips).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(msg);
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("JWT validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_REQUEST;
        }
    }
}

async fn validate_aws_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    cache: &Cache,
) {
    let token = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    let (secret, session_token) =
        aws_credential_shape(&m.rule, token, dependent_variables, m.matching_input_offset_span);

    if secret.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing AWS access-key ID or secret.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let akid_candidates = aws_akid_candidates(
        captured_values,
        dependent_variables.get("AKID"),
        m.matching_input_offset_span,
        &secret,
    );

    if akid_candidates.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing AWS access-key ID or secret.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let mut last_body = None;
    let mut last_status = StatusCode::UNAUTHORIZED;

    for akid in akid_candidates {
        let cache_key = aws::generate_aws_cache_key(&akid, &secret, session_token.as_deref());
        if let Some(cached) = cache.get(&cache_key) {
            let c = cached.value();
            if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                if c.is_valid {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    return;
                }
                last_body = Some(c.body.clone());
                last_status = c.status;
                continue;
            }
        }

        let result = validate_aws_credential_pair(&akid, &secret, session_token.as_deref()).await;
        let body = if let Some(identity) = result.identity.as_deref() {
            let mut body = format!("{} --- ARN: {}", akid, identity);
            if let Some(account_id) = result.account_id.as_deref() {
                body.push_str(&format!(" --- AWS Account Number: {account_id}"));
            }
            validation_body::from_string(body)
        } else if result.outcome == ValidationOutcome::Skipped {
            validation_body::from_string(result.message.clone())
        } else if result.status == StatusCode::BAD_REQUEST {
            validation_body::from_string(format!(
                "Invalid AWS credentials ({}): {}",
                akid, result.message
            ))
        } else {
            validation_body::from_string(format!(
                "AWS validation error ({}): {}",
                akid, result.message
            ))
        };

        if result.status != StatusCode::BAD_GATEWAY {
            cache.insert(
                cache_key,
                CachedResponse {
                    body: body.clone(),
                    status: result.status,
                    is_valid: result.is_valid,
                    outcome: result.outcome,
                    timestamp: Instant::now(),
                },
            );
        }

        if result.is_valid {
            m.validation_success = true;
            m.validation_response_body = body;
            m.validation_response_status = result.status;
            return;
        }

        last_body = Some(body);
        last_status = result.status;
    }

    m.validation_success = false;
    m.validation_response_body = last_body.unwrap_or_else(|| {
        validation_body::from_string("AWS validation failed for all nearby access-key IDs.")
    });
    m.validation_response_status = last_status;
}

pub(crate) fn is_aws_session_token_rule(rule: &Rule) -> bool {
    rule.id() == "kingfisher.aws.4"
        || rule
            .syntax()
            .depends_on_rule
            .iter()
            .flatten()
            .any(|dependency| dependency.variable.eq_ignore_ascii_case("AWS_SECRET_ACCESS_KEY"))
}

fn aws_credential_shape(
    rule: &Rule,
    token: String,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    target_span: OffsetSpan,
) -> (String, Option<String>) {
    if is_aws_session_token_rule(rule) {
        let secret =
            closest_dependent_value(dependent_variables.get("AWS_SECRET_ACCESS_KEY"), target_span)
                .unwrap_or_default();
        (secret, Some(token))
    } else {
        (token, None)
    }
}

fn closest_dependent_value(
    values: Option<&Vec<(String, OffsetSpan)>>,
    target_span: OffsetSpan,
) -> Option<String> {
    values?
        .iter()
        .min_by_key(|(_, span)| dependency_distance(*span, target_span))
        .map(|(value, _)| value.clone())
}

fn aws_akid_candidates(
    captured_values: &[(String, String, usize, usize)],
    dependent_akids: Option<&Vec<(String, OffsetSpan)>>,
    target_span: OffsetSpan,
    secret: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();

    if let Some(closest) = utils::find_closest_variable(captured_values, secret, "TOKEN", "AKID") {
        candidates.push((0usize, closest));
    }

    if let Some(values) = dependent_akids {
        candidates.extend(
            values
                .iter()
                .map(|(value, span)| (dependency_distance(*span, target_span), value.clone())),
        );
    }

    candidates.sort_by_key(|(distance, _)| *distance);

    let mut seen = FxHashSet::default();
    candidates
        .into_iter()
        .filter_map(|(_, value)| if seen.insert(value.clone()) { Some(value) } else { None })
        .take(64)
        .collect()
}

fn dependency_distance(span: OffsetSpan, target_span: OffsetSpan) -> usize {
    if span.end <= target_span.start {
        target_span.start - span.end
    } else {
        span.start.saturating_sub(target_span.end)
    }
}

async fn validate_gcp_rule(m: &mut OwnedBlobMatch, globals: &Object, cache: &Cache) {
    let gcp_json = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if gcp_json.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("GCP JSON not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = gcp::generate_gcp_cache_key(&gcp_json);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match gcp::GcpValidator::global() {
        Ok(validator) => match validator.validate_gcp_credentials(gcp_json.as_bytes()).await {
            Ok((ok, meta)) => {
                m.validation_success = ok;
                m.validation_response_body = validation_body::from_string(meta.join("\n"));
                m.validation_response_status =
                    if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
            }
            Err(e) => {
                m.validation_success = false;
                m.validation_response_body =
                    validation_body::from_string(format!("GCP validation error: {}", e));
                m.validation_response_status = StatusCode::BAD_GATEWAY;
            }
        },
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Failed to create GCP validator: {}", e));
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
        }
    }
    cache.insert(
        cache_key,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            outcome: ValidationOutcome::from_legacy(
                false,
                m.validation_success,
                m.validation_response_status.as_u16(),
            ),
            timestamp: Instant::now(),
        },
    );
}

async fn validate_coinbase_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    cache: &Cache,
) {
    let cred_name = globals
        .get("CRED_NAME")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();
    let private_key = globals
        .get("PRIVATE_KEY")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if cred_name.is_empty() || private_key.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing key name or private key.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    match coinbase::validate_cdp_api_key(&cred_name, &private_key, client, parser, cache).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = msg;
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Coinbase validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

async fn validate_raw_rule(
    m: &mut OwnedBlobMatch,
    raw: &str,
    globals: &Object,
    client: &Client,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    match kingfisher_scanner::validation::raw::validate_raw(
        raw,
        globals,
        client,
        use_lax_tls,
        allow_internal_ips,
    )
    .await
    {
        Ok(result) => {
            m.validation_success = result.valid;
            m.validation_response_body = validation_body::from_string(result.body);
            m.validation_response_status = result.status;
        }
        Err(e) => {
            debug!("Raw validation error for {}: {}", raw, e);
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Raw validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

fn populate_globals_from_captures(
    globals: &mut Object,
    captured_values: &[(String, String, usize, usize)],
) {
    let mut best_token: Option<&String> = None;

    for (k, v, ..) in captured_values {
        if k.eq_ignore_ascii_case("TOKEN") {
            if best_token.is_none_or(|best| v.len() >= best.len()) {
                best_token = Some(v);
            }
        } else {
            globals.insert(k.to_uppercase().into(), Value::scalar(v.clone()));
        }
    }

    if let Some(token) = best_token {
        globals.insert("TOKEN".into(), Value::scalar(token.clone()));
    }
}

fn select_closest_dependency_value(
    values: &[(String, OffsetSpan)],
    target_span: OffsetSpan,
) -> Option<(String, OffsetSpan)> {
    let mut best_before: Option<(usize, (String, OffsetSpan))> = None;
    let mut best_overlap: Option<(usize, (String, OffsetSpan))> = None;
    let mut best_after: Option<(usize, (String, OffsetSpan))> = None;

    for (value, span) in values {
        if span.end <= target_span.start {
            let distance = target_span.start - span.end;
            match &mut best_before {
                Some((best_distance, best_value)) if distance < *best_distance => {
                    *best_distance = distance;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_before = Some((distance, (value.clone(), *span)));
                }
                _ => {}
            }
        } else if span.start >= target_span.end {
            let distance = span.start - target_span.end;
            match &mut best_after {
                Some((best_distance, best_value)) if distance < *best_distance => {
                    *best_distance = distance;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_after = Some((distance, (value.clone(), *span)));
                }
                _ => {}
            }
        } else {
            match &mut best_overlap {
                Some((best_distance, best_value)) if 0 < *best_distance => {
                    *best_distance = 0;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_overlap = Some((0, (value.clone(), *span)));
                }
                _ => {}
            }
        }
    }

    best_before.or(best_overlap).or(best_after).map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::{Confidence, DependsOnRule, RuleSyntax};

    #[test]
    fn credential_uri_classifier_normalizes_supported_database_schemes() {
        assert_eq!(
            classify_credential_uri(
                "POSTGRESQL://alice:hunter2@db.internal:5432/app",
                Some("POSTGRESQL")
            ),
            CredentialUriTarget::Postgres(
                "postgresql://alice:hunter2@db.internal:5432/app".to_string()
            )
        );
        assert_eq!(
            classify_credential_uri(
                "MARIADB://alice:hunter2@db.internal:3306/app",
                Some("MARIADB")
            ),
            CredentialUriTarget::MySQL("mysql://alice:hunter2@db.internal:3306/app".to_string())
        );
        assert!(is_parseable_credential_uri(
            "mongodb://alice:hunter2@mongo.internal:27017/app",
            Some("mongodb")
        ));
    }

    #[test]
    fn credential_uri_classifier_accepts_http_basic_auth_uris() {
        assert_eq!(
            classify_credential_uri("https://alice:hunter2@service.internal", Some("https")),
            CredentialUriTarget::Http("https://alice:hunter2@service.internal".to_string())
        );
        assert!(is_parseable_credential_uri(
            "https://alice:hunter2@service.internal",
            Some("https")
        ));
        assert!(!is_parseable_credential_uri(
            "postgresql://alice:hunter2@db.internal:70000/app",
            Some("postgresql")
        ));

        let malformed_https =
            classify_credential_uri("https://alice@service.internal", Some("https"));
        assert_eq!(malformed_https.scheme(), "https");
        assert!(!malformed_https.is_parseable());
    }

    #[tokio::test]
    async fn credential_uri_client_does_not_follow_redirects() {
        use axum::{Router, response::Redirect, routing::get};

        let app = Router::new()
            .route("/challenge", get(|| async { Redirect::temporary("/target") }))
            .route("/target", get(|| async { "redirected" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = build_credential_uri_client(false, Duration::from_secs(5)).unwrap();
        let response = client.get(format!("http://{address}/challenge")).send().await.unwrap();
        server.abort();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.url().path(), "/challenge");
    }

    #[test]
    fn http_credential_uri_requires_basic_challenge_before_authentication() {
        let mut headers = HeaderMap::new();
        headers
            .append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Digest realm=\"example\""));
        assert!(!received_basic_auth_challenge(StatusCode::OK, &headers));
        assert!(!received_basic_auth_challenge(StatusCode::UNAUTHORIZED, &headers));

        headers.append(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Digest realm=\"example\", basic = \"metadata\""),
        );
        assert!(!received_basic_auth_challenge(StatusCode::UNAUTHORIZED, &headers));

        headers
            .append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic realm=\"example\""));
        assert!(received_basic_auth_challenge(StatusCode::UNAUTHORIZED, &headers));
    }

    #[tokio::test]
    async fn http_credential_uri_rejects_plaintext_transport() {
        let client = Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let result = validate_http_credential_uri(
            "http://alice:hunter2@service.internal/health",
            &client,
            Duration::from_secs(5),
            0,
            true,
        )
        .await
        .unwrap_err();

        assert!(result.to_string().contains("requires HTTPS"));
    }

    #[tokio::test]
    async fn http_credential_uri_rejects_ambiguous_or_invalid_userinfo() {
        let client = Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let cases = [
            (
                "https://alice%3Aadmin:hunter2@service.invalid/protected",
                "usernames cannot contain ':'",
            ),
            ("https://alice%FF:hunter2@service.invalid/protected", "username is not valid UTF-8"),
            ("https://alice:hunter%FF@service.invalid/protected", "password is not valid UTF-8"),
        ];

        for (uri, expected_error) in cases {
            let error = validate_http_credential_uri(uri, &client, Duration::from_secs(5), 0, true)
                .await
                .unwrap_err();

            assert!(error.to_string().contains(expected_error), "{error}");
        }
    }

    async fn run_https_basic_auth_flow(
        authenticated_status: StatusCode,
    ) -> ((bool, StatusCode, String), Vec<Option<String>>) {
        use rcgen::{CertifiedKey, generate_simple_self_signed};
        use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_rustls::TlsAcceptor;

        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key.into())
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut authorization_headers = Vec::new();
            for status in [StatusCode::UNAUTHORIZED, authenticated_status] {
                let (socket, _) = listener.accept().await.unwrap();
                let mut stream = acceptor.accept(socket).await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let request = String::from_utf8(request).unwrap();
                authorization_headers.push(
                    request
                        .lines()
                        .find_map(|line| line.strip_prefix("authorization: "))
                        .map(str::to_string),
                );

                let status_line = match status {
                    StatusCode::OK => "200 OK",
                    StatusCode::UNAUTHORIZED => "401 Unauthorized",
                    other => panic!("unsupported test status: {other}"),
                };
                let challenge = if status == StatusCode::UNAUTHORIZED {
                    "WWW-Authenticate: Basic realm=\"test\"\r\n"
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status_line}\r\n{challenge}Content-Length: 0\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            authorization_headers
        });

        let client = build_credential_uri_client(true, Duration::from_secs(5)).unwrap();
        let result = validate_http_credential_uri(
            &format!("https://alice:hunter2@{address}/protected"),
            &client,
            Duration::from_secs(5),
            0,
            true,
        )
        .await
        .unwrap();
        let authorization_headers = server.await.unwrap();
        (result, authorization_headers)
    }

    #[tokio::test]
    async fn http_credential_uri_sends_basic_auth_only_after_https_challenge() {
        let ((valid, status, _), authorization_headers) =
            run_https_basic_auth_flow(StatusCode::OK).await;

        assert!(valid);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(authorization_headers[0], None);
        assert_eq!(authorization_headers[1].as_deref(), Some("Basic YWxpY2U6aHVudGVyMg=="));
    }

    #[tokio::test]
    async fn http_credential_uri_treats_repeated_unauthorized_as_inactive() {
        let ((valid, status, _), authorization_headers) =
            run_https_basic_auth_flow(StatusCode::UNAUTHORIZED).await;

        assert!(!valid);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(authorization_headers[0], None);
        assert!(authorization_headers[1].is_some());
    }

    fn aws_rule(id: &str, secret_dependency: bool) -> Rule {
        Rule::new(RuleSyntax {
            name: id.to_string(),
            id: id.to_string(),
            pattern: "(secret)".to_string(),
            min_entropy: 0.0,
            confidence: Confidence::Low,
            visible: true,
            examples: Vec::new(),
            negative_examples: Vec::new(),
            references: Vec::new(),
            validation: Some(Validation::AWS),
            revocation: None,
            depends_on_rule: secret_dependency
                .then(|| DependsOnRule {
                    rule_id: "private.aws.secret".to_string(),
                    variable: "AWS_SECRET_ACCESS_KEY".to_string(),
                    optional: false,
                    within: None,
                })
                .into_iter()
                .map(Some)
                .collect(),
            pattern_requirements: None,
            tls_mode: None,
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })
    }

    #[test]
    fn populate_globals_prefers_longest_token() {
        let captured_values = vec![
            ("TOKEN".to_string(), "short".to_string(), 0usize, 5usize),
            ("BODY".to_string(), "body".to_string(), 0usize, 4usize),
            ("TOKEN".to_string(), "longervalue".to_string(), 0usize, 11usize),
        ];

        let mut globals = Object::new();
        populate_globals_from_captures(&mut globals, &captured_values);

        assert_eq!(globals.get("TOKEN"), Some(Value::scalar("longervalue")).as_ref());
        assert_eq!(globals.get("BODY"), Some(Value::scalar("body")).as_ref());
    }

    #[test]
    fn populate_globals_handles_missing_token() {
        let captured_values = vec![("CHECKSUM".to_string(), "123456".to_string(), 0usize, 6usize)];

        let mut globals = Object::new();
        populate_globals_from_captures(&mut globals, &captured_values);

        assert!(globals.get("TOKEN").is_none());
        assert_eq!(globals.get("CHECKSUM"), Some(Value::scalar("123456")).as_ref());
    }

    #[test]
    fn select_closest_dependency_value_prefers_nearest_preceding_dependency() {
        let values = vec![
            ("first".to_string(), OffsetSpan::from_range(10..20)),
            ("second".to_string(), OffsetSpan::from_range(40..50)),
            ("third".to_string(), OffsetSpan::from_range(80..90)),
        ];

        let selected =
            select_closest_dependency_value(&values, OffsetSpan::from_range(55..60)).unwrap();

        assert_eq!(selected.0, "second");
        assert_eq!(selected.1, OffsetSpan::from_range(40..50));
    }

    #[test]
    fn select_closest_dependency_value_falls_back_to_nearest_following_dependency() {
        let values = vec![
            ("first".to_string(), OffsetSpan::from_range(70..80)),
            ("second".to_string(), OffsetSpan::from_range(90..100)),
        ];

        let selected =
            select_closest_dependency_value(&values, OffsetSpan::from_range(55..60)).unwrap();

        assert_eq!(selected.0, "first");
        assert_eq!(selected.1, OffsetSpan::from_range(70..80));
    }

    #[test]
    fn associated_betterleaks_component_wins_over_other_blob_values() {
        use crate::{
            blob::BlobId,
            matcher::{SerializableCapture, SerializableCaptures},
            util::intern,
        };
        use smallvec::smallvec;

        let mut syntax = aws_rule("betterleaks.primary", false).syntax().clone();
        syntax.validation = None;
        syntax.depends_on_rule = vec![Some(DependsOnRule {
            rule_id: "betterleaks.component".into(),
            variable: "COMPONENT".into(),
            optional: false,
            within: Some("5L".into()),
        })];
        let mut primary = OwnedBlobMatch {
            rule: Arc::new(Rule::new(syntax)),
            blob_id: BlobId::new(b"associated-component"),
            finding_fingerprint: 1,
            matching_input_offset_span: OffsetSpan::from_range(20..27),
            captures: SerializableCaptures {
                captures: smallvec![SerializableCapture {
                    name: Some(intern("TOKEN")),
                    match_number: 1,
                    start: 20,
                    end: 27,
                    value: intern("primary"),
                }],
            },
            validation_response_body: None,
            validation_response_status: StatusCode::CONTINUE,
            validation_success: false,
            validation_outcome: ValidationOutcome::NotAttempted,
            calculated_entropy: 0.0,
            is_base64: false,
            dependent_captures: std::collections::BTreeMap::new(),
        };
        primary.dependent_captures.insert("COMPONENT".into(), "associated".into());

        let (variables, missing) = collect_variables_and_dependencies(&[primary]);
        assert_eq!(variables["COMPONENT"][0].0, "associated");
        assert!(missing.is_empty());
    }

    #[test]
    fn aws_akid_candidates_orders_by_proximity_and_deduplicates() {
        let captured_values = vec![
            ("TOKEN".to_string(), "secret".to_string(), 100usize, 140usize),
            ("AKID".to_string(), "closest_capture".to_string(), 80usize, 90usize),
        ];
        let dependent_akids = vec![
            ("far_before".to_string(), OffsetSpan::from_range(10..20)),
            ("near_after".to_string(), OffsetSpan::from_range(150..160)),
            ("overlap".to_string(), OffsetSpan::from_range(110..120)),
            ("closest_capture".to_string(), OffsetSpan::from_range(80..90)),
        ];

        let candidates = aws_akid_candidates(
            &captured_values,
            Some(&dependent_akids),
            OffsetSpan::from_range(100..140),
            "secret",
        );

        assert_eq!(candidates, vec!["closest_capture", "overlap", "near_after", "far_before"]);
    }

    #[test]
    fn aws_akid_candidates_caps_unique_candidates() {
        let dependent_akids = (0..70)
            .map(|i| (format!("akid{i}"), OffsetSpan::from_range((i * 2)..(i * 2 + 1))))
            .collect::<Vec<_>>();

        let candidates = aws_akid_candidates(
            &[],
            Some(&dependent_akids),
            OffsetSpan::from_range(1_000..1_010),
            "secret",
        );

        assert_eq!(candidates.len(), 64);
        assert_eq!(candidates.first().map(String::as_str), Some("akid69"));
        assert_eq!(candidates.last().map(String::as_str), Some("akid6"));
    }

    #[test]
    fn aws_credential_shape_is_rule_specific_with_static_and_session_rules_in_one_blob() {
        let static_rule = aws_rule("private.aws.static", false);
        let session_rule = aws_rule("private.aws.session", true);
        let dependent_variables = FxHashMap::from_iter([(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            vec![("static-secret".to_string(), OffsetSpan::from_range(20..60))],
        )]);
        let span = OffsetSpan::from_range(70..110);

        let static_shape = aws_credential_shape(
            &static_rule,
            "static-rule-token".to_string(),
            &dependent_variables,
            span,
        );
        let session_shape = aws_credential_shape(
            &session_rule,
            "session-token".to_string(),
            &dependent_variables,
            span,
        );

        assert_eq!(static_shape, ("static-rule-token".to_string(), None));
        assert_eq!(session_shape, ("static-secret".to_string(), Some("session-token".to_string())));
        assert!(is_aws_session_token_rule(&aws_rule("kingfisher.aws.4", false)));
    }

    #[test]
    fn betterleaks_aws_session_token_rule_is_detected_by_its_secret_dependency() {
        let rule = aws_rule("betterleaks.aws-session-token", true);

        assert!(is_aws_session_token_rule(&rule));
    }

    #[tokio::test]
    async fn shared_aws_validation_skips_canaries_before_network_access() {
        let result =
            validate_aws_credential_pair("AKIAXYZDQCEN4B6JSJQI", "not-a-real-secret-key", None)
                .await;

        assert!(!result.is_valid);
        assert_eq!(result.status, StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(result.outcome, ValidationOutcome::Skipped);
        assert_eq!(result.account_id.as_deref(), Some("534261010715"));
        assert!(result.message.starts_with("(skip list entry)"));
    }

    #[test]
    fn truncate_to_char_boundary_handles_multibyte_characters() {
        let max_len = 2048;
        let mut body = "a".repeat(max_len);
        body.push('é');

        truncate_to_char_boundary(&mut body, max_len);

        assert_eq!(body.len(), max_len);
        assert!(body.is_char_boundary(body.len()));
        assert!(body.ends_with('a'));
    }

    #[test]
    fn truncate_skipped_when_max_body_len_is_zero() {
        let original_len = 4096;
        let body = "x".repeat(original_len);

        let preview = truncate_preview(&body, 0);

        assert_eq!(preview.len(), original_len);
    }

    #[test]
    fn truncate_applies_custom_max_body_len() {
        let body = "y".repeat(5000);

        let preview = truncate_preview(&body, 1024);

        assert_eq!(preview.len(), 1024);
    }

    mod tls_mode_tests {
        use super::*;

        #[test]
        fn validation_clients_new_creates_both_clients() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();
            assert_eq!(clients.global_mode, TlsMode::Strict);

            let clients_lax = ValidationClients::new(TlsMode::Lax, false).unwrap();
            assert_eq!(clients_lax.global_mode, TlsMode::Lax);

            let clients_off = ValidationClients::new(TlsMode::Off, false).unwrap();
            assert_eq!(clients_off.global_mode, TlsMode::Off);
        }

        #[test]
        fn client_for_rule_strict_mode_always_returns_strict_client() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();

            // With no rule TLS mode
            let client1 = clients.client_for_rule(None);
            // With rule wanting lax
            let client2 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));
            // With rule wanting strict
            let client3 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict));

            // In strict mode, all should return the same strict client
            assert!(std::ptr::eq(client1, client2));
            assert!(std::ptr::eq(client2, client3));
        }

        #[test]
        fn client_for_rule_off_mode_always_returns_lax_client() {
            let clients = ValidationClients::new(TlsMode::Off, false).unwrap();

            // With no rule TLS mode
            let client1 = clients.client_for_rule(None);
            // With rule wanting lax
            let client2 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));
            // With rule wanting strict
            let client3 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict));

            // In off mode, all should return the same lax client
            assert!(std::ptr::eq(client1, client2));
            assert!(std::ptr::eq(client2, client3));
        }

        #[test]
        fn client_for_rule_lax_mode_respects_rule_preference() {
            let clients = ValidationClients::new(TlsMode::Lax, false).unwrap();

            // Get references to understand which is which
            let strict_client = clients.client_for_rule(None);
            let lax_client = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));

            // When rule doesn't specify, should get strict
            assert!(std::ptr::eq(clients.client_for_rule(None), strict_client));

            // When rule wants strict, should get strict
            assert!(std::ptr::eq(
                clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict)),
                strict_client
            ));

            // When rule wants lax, should get lax
            assert!(std::ptr::eq(
                clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax)),
                lax_client
            ));

            // Strict and lax clients should be different
            assert!(!std::ptr::eq(strict_client, lax_client));
        }

        #[test]
        fn should_use_lax_off_mode_always_returns_true() {
            let clients = ValidationClients::new(TlsMode::Off, false).unwrap();

            assert!(clients.should_use_lax(None));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }

        #[test]
        fn builtin_database_validators_opt_into_lax_tls() {
            // End-to-end: the capability overlay must actually reach the
            // runtime client/validator selection for the built-in rules that
            // legitimately talk to private-CA endpoints.
            let rules = kingfisher_rules::get_builtin_rules(None).unwrap();

            for id in ["betterleaks.mongodb-connection-string", "betterleaks.jwt"] {
                let tls_mode = rules.rules.get(id).unwrap().tls_mode;
                assert_eq!(tls_mode, Some(kingfisher_rules::TlsMode::Lax), "{id}");

                // Opt-in on both sides: the operator must also ask for it.
                assert!(
                    !ValidationClients::new(TlsMode::Strict, false)
                        .unwrap()
                        .should_use_lax(tls_mode),
                    "{id} must stay strict under the default --tls-mode strict"
                );
                assert!(
                    ValidationClients::new(TlsMode::Lax, false).unwrap().should_use_lax(tls_mode),
                    "{id} must go lax under --tls-mode lax"
                );
            }

            // A rule that does not declare lax stays strict even under --tls-mode lax.
            let private_key = rules.rules.get("betterleaks.private-key").unwrap();
            assert_eq!(private_key.tls_mode, None);
            assert!(
                !ValidationClients::new(TlsMode::Lax, false)
                    .unwrap()
                    .should_use_lax(private_key.tls_mode)
            );
        }

        #[test]
        fn should_use_lax_strict_mode_always_returns_false() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();

            assert!(!clients.should_use_lax(None));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }

        #[test]
        fn should_use_lax_lax_mode_respects_rule_preference() {
            let clients = ValidationClients::new(TlsMode::Lax, false).unwrap();

            // Only true when rule explicitly opts in
            assert!(!clients.should_use_lax(None));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }
    }
}
