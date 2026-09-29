//! Credential URI normalization and HTTPS Basic authentication.
use super::{GLOBAL_USER_AGENT, http_validation as httpvalidation};
#[cfg(feature = "validation-database")]
use super::{mongodb, mysql, postgres};
use anyhow::{Result, anyhow};
use percent_encoding::percent_decode_str;
use reqwest::{Client, StatusCode, Url, header, header::HeaderMap};
use std::time::Duration;
/// Returns `true` if the provided string can be parsed as a MongoDB connection URI.
#[cfg(feature = "validation-database")]
pub fn is_parseable_mongodb_uri(uri: &str) -> bool {
    mongodb::looks_like_mongodb_uri(uri)
}

/// Returns `true` if the provided string can be parsed as a Postgres connection URI.
#[cfg(feature = "validation-database")]
pub fn is_parseable_postgres_uri(uri: &str) -> bool {
    postgres::parse_postgres_url(uri).is_ok()
}

/// Returns `true` if the provided string can be parsed as a MySQL connection URI.
#[cfg(feature = "validation-database")]
pub fn is_parseable_mysql_uri(uri: &str) -> bool {
    mysql::parse_mysql_url(uri).is_ok()
}

/// A validator target selected from a credential-bearing URI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialUriTarget {
    Http(String),
    MongoDB(String),
    MySQL(String),
    Postgres(String),
    Jdbc(String),
    Unsupported(String),
}

impl CredentialUriTarget {
    pub fn scheme(&self) -> &str {
        match self {
            Self::Http(uri) => uri.split_once("://").map(|(scheme, _)| scheme).unwrap_or("http"),
            Self::MongoDB(_) => "mongodb",
            Self::MySQL(_) => "mysql",
            Self::Postgres(_) => "postgresql",
            Self::Jdbc(_) => "jdbc",
            Self::Unsupported(scheme) => scheme,
        }
    }

    pub fn is_parseable(&self) -> bool {
        match self {
            Self::Http(uri) => Url::parse(uri).is_ok_and(|url| {
                url.host_str().is_some_and(|host| !host.is_empty())
                    && !url.username().is_empty()
                    && url.password().is_some_and(|password| !password.is_empty())
            }),
            #[cfg(feature = "validation-database")]
            Self::MongoDB(uri) => is_parseable_mongodb_uri(uri),
            #[cfg(feature = "validation-database")]
            Self::MySQL(uri) => is_parseable_mysql_uri(uri),
            #[cfg(feature = "validation-database")]
            Self::Postgres(uri) => is_parseable_postgres_uri(uri),
            // The JDBC validator performs subprotocol-specific parsing. Treat the outer prefix as
            // structurally valid here so direct validation can return its precise diagnostic.
            #[cfg(not(feature = "validation-database"))]
            Self::MongoDB(uri) | Self::MySQL(uri) | Self::Postgres(uri) => Url::parse(uri).is_ok(),
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
pub fn classify_credential_uri(uri: &str, scheme_hint: Option<&str>) -> CredentialUriTarget {
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
pub fn is_parseable_credential_uri(uri: &str, scheme: Option<&str>) -> bool {
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

pub fn received_basic_auth_challenge(status: StatusCode, headers: &HeaderMap) -> bool {
    status == StatusCode::UNAUTHORIZED && has_basic_auth_challenge(headers)
}

/// Validate an HTTPS credential URI using the username and password as HTTP Basic Auth.
///
/// The credentials are removed from the request URL before dispatch so they cannot be echoed in
/// request errors, redirects, or debug output. Credentials are sent only after an unauthenticated
/// request receives an explicit Basic Auth challenge. A subsequent successful response proves that
/// the endpoint accepted them; only HTTP 401 is authoritative rejection, while other response
/// statuses are reported as inconclusive by the caller.
pub async fn validate_http_credential_uri(
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
