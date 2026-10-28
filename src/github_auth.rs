use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Once},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Url, header};
use serde::{Deserialize, Serialize};

use crate::validation::GLOBAL_USER_AGENT;

const GITHUB_API_VERSION: &str = "2022-11-28";
const APP_ID_ENV: &str = "KF_GITHUB_APP_ID";
const INSTALLATION_ID_ENV: &str = "KF_GITHUB_APP_INSTALLATION_ID";
const PRIVATE_KEY_ENV: &str = "KF_GITHUB_APP_PRIVATE_KEY";
const PRIVATE_KEY_PATH_ENV: &str = "KF_GITHUB_APP_PRIVATE_KEY_PATH";
const TOKEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_REFRESH_MARGIN: chrono::Duration = chrono::Duration::seconds(60);
const TOKEN_FAILURE_COOLDOWN: Duration = Duration::from_secs(60);

static JWT_CRYPTO_PROVIDER: Once = Once::new();
// API discovery and clone workers construct separate auth sources. Share only
// installation tokens for the exact same endpoint, credentials and TLS policy;
// neither tokens nor signing keys are persisted to disk.
static TOKEN_CACHES: LazyLock<parking_lot::Mutex<HashMap<TokenCacheKey, Arc<TokenCache>>>> =
    LazyLock::new(Default::default);

type TokenCache = tokio::sync::Mutex<InstallationTokenCache>;

#[derive(Hash, PartialEq, Eq)]
struct TokenCacheKey {
    api_base: Url,
    app_id: u64,
    installation_id: u64,
    private_key_digest: [u8; 32],
    ignore_certs: bool,
}

#[derive(Default)]
struct InstallationTokenCache {
    token: Option<CachedInstallationToken>,
    failure: Option<CachedTokenFailure>,
}

struct CachedInstallationToken {
    token: String,
    expires_at: DateTime<Utc>,
}

struct CachedTokenFailure {
    message: String,
    failed_at: Instant,
    cooldown: Duration,
}

impl InstallationTokenCache {
    fn cached_token(&self) -> Result<Option<String>> {
        if let Some(token) = &self.token
            && token.expires_at > Utc::now() + TOKEN_REFRESH_MARGIN
        {
            return Ok(Some(token.token.clone()));
        }
        if let Some(failure) = &self.failure
            && failure.failed_at.elapsed() < failure.cooldown
        {
            if let Some(token) = self.unexpired_token() {
                return Ok(Some(token));
            }
            bail!("GitHub App token refresh is cooling down: {}", failure.message);
        }
        Ok(None)
    }

    fn unexpired_token(&self) -> Option<String> {
        self.token
            .as_ref()
            .filter(|token| token.expires_at > Utc::now())
            .map(|token| token.token.clone())
    }

    fn finish_refresh(
        &mut self,
        result: Result<CachedInstallationToken>,
    ) -> Result<Option<String>> {
        match result {
            Ok(token) => {
                let value = token.token.clone();
                self.token = Some(token);
                self.failure = None;
                Ok(Some(value))
            }
            Err(error) => {
                // Share auth, rate-limit and exhausted server failures, but let
                // the next worker retry transport/decoding errors immediately.
                self.failure = error
                    .downcast_ref::<InstallationTokenError>()
                    .filter(|error| {
                        matches!(
                            error.status,
                            reqwest::StatusCode::UNAUTHORIZED
                                | reqwest::StatusCode::FORBIDDEN
                                | reqwest::StatusCode::TOO_MANY_REQUESTS
                        ) || error.status.is_server_error()
                    })
                    .map(|failure| CachedTokenFailure {
                        message: format!("{error:#}"),
                        failed_at: Instant::now(),
                        cooldown: failure.cooldown,
                    });
                // Refreshing early must not discard a token that is still
                // valid, even when the refresh failed or entered cooldown.
                if let Some(token) = self.unexpired_token() { Ok(Some(token)) } else { Err(error) }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("GitHub App installation-token request failed: HTTP {status} ({url}): {body}")]
struct InstallationTokenError {
    status: reqwest::StatusCode,
    url: Url,
    body: String,
    cooldown: Duration,
}

fn ensure_jwt_crypto_provider() {
    JWT_CRYPTO_PROVIDER.call_once(|| {
        let _ = jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.install_default();
    });
}

#[derive(Clone)]
struct GitHubAppCredentials {
    app_id: u64,
    installation_id: u64,
    encoding_key: Arc<EncodingKey>,
    token_cache: Arc<TokenCache>,
}

/// Authentication source for GitHub API requests and Git clones.
///
/// A complete GitHub App configuration takes precedence over KF_GITHUB_TOKEN.
/// Installation tokens are shared across API and clone workers, with a single
/// refresh when the cached token is within one minute of expiration.
pub(crate) struct GitHubAuth {
    fixed_token: Option<String>,
    app: Option<GitHubAppCredentials>,
    api_base: Url,
    ignore_certs: bool,
}

struct AuthOptions {
    fixed_token: Option<String>,
    app_id: Option<String>,
    installation_id: Option<String>,
    private_key: Option<String>,
    private_key_path: Option<PathBuf>,
}

#[derive(Serialize)]
struct GitHubAppClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: String,
}

impl InstallationTokenResponse {
    fn into_cached(self) -> Result<CachedInstallationToken> {
        let token = validate_installation_token(self.token)?;
        let expires_at = DateTime::parse_from_rfc3339(&self.expires_at)
            .context("GitHub App installation-token response contained an invalid expires_at")?
            .with_timezone(&Utc);
        if expires_at <= Utc::now() + TOKEN_REFRESH_MARGIN {
            bail!("GitHub App installation-token response expires too soon or is already expired");
        }
        Ok(CachedInstallationToken { token, expires_at })
    }
}

impl GitHubAuth {
    pub(crate) fn from_env(api_url: &Url, ignore_certs: bool) -> Result<Self> {
        let options = AuthOptions {
            fixed_token: env_value("KF_GITHUB_TOKEN"),
            app_id: env_value(APP_ID_ENV),
            installation_id: env_value(INSTALLATION_ID_ENV),
            private_key: env_value(PRIVATE_KEY_ENV),
            private_key_path: env_value(PRIVATE_KEY_PATH_ENV).map(PathBuf::from),
        };
        Self::from_options(api_url, ignore_certs, options)
    }

    fn from_options(api_url: &Url, ignore_certs: bool, options: AuthOptions) -> Result<Self> {
        let api_base = normalize_api_base(api_url);

        let app_configured = options.app_id.is_some()
            || options.installation_id.is_some()
            || options.private_key.is_some()
            || options.private_key_path.is_some();
        if !app_configured {
            return Ok(Self {
                fixed_token: options.fixed_token,
                app: None,
                api_base,
                ignore_certs,
            });
        }

        let app_id = parse_id(APP_ID_ENV, options.app_id)?;
        let installation_id = parse_id(INSTALLATION_ID_ENV, options.installation_id)?;
        let private_key = match (options.private_key, options.private_key_path) {
            (Some(_), Some(_)) => bail!(
                "Set only one of {PRIVATE_KEY_ENV} and {PRIVATE_KEY_PATH_ENV} for GitHub App authentication"
            ),
            (Some(private_key), None) => private_key.into_bytes(),
            (None, Some(path)) => {
                let path = expand_private_key_path(&path).with_context(|| {
                    format!("Failed to expand GitHub App private-key path ({PRIVATE_KEY_PATH_ENV})")
                })?;
                fs::read(&path).with_context(|| {
                    format!(
                        "Failed to read GitHub App private key from {} ({PRIVATE_KEY_PATH_ENV})",
                        path.display()
                    )
                })?
            }
            (None, None) => bail!(
                "GitHub App authentication requires {PRIVATE_KEY_ENV} or {PRIVATE_KEY_PATH_ENV}"
            ),
        };

        ensure_jwt_crypto_provider();
        let encoding_key = EncodingKey::from_rsa_pem(&private_key)
            .context("Failed to parse GitHub App RSA private key as PEM")?;

        let cache_key = TokenCacheKey {
            api_base: api_base.clone(),
            app_id,
            installation_id,
            private_key_digest: *blake3::hash(&private_key).as_bytes(),
            ignore_certs,
        };
        let token_cache = TOKEN_CACHES.lock().entry(cache_key).or_default().clone();

        Ok(Self {
            fixed_token: options.fixed_token,
            app: Some(GitHubAppCredentials {
                app_id,
                installation_id,
                encoding_key: Arc::new(encoding_key),
                token_cache,
            }),
            api_base,
            ignore_certs,
        })
    }

    /// Get a token for asynchronous GitHub API work.
    pub(crate) async fn token(&self, client: &reqwest::Client) -> Result<Option<String>> {
        let Some(app) = &self.app else {
            return Ok(self.fixed_token.clone());
        };

        let mut cache = app.token_cache.lock().await;
        if let Some(token) = cache.cached_token()? {
            return Ok(Some(token));
        }
        // Keep the guard through retries and response decoding: other async or
        // blocking workers must wait for this refresh instead of minting again.
        let result = async {
            let jwt = app_jwt(app)?;
            let url = installation_token_url(&self.api_base, app.installation_id)?;
            let request = client
                .post(url)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
                .bearer_auth(jwt);
            let response = crate::github::retry::send(request, "minting an installation token")
                .await
                .context("Failed to request a GitHub App installation token")?;
            let response = ensure_token_success_async(response).await?;
            let token: InstallationTokenResponse = response
                .json()
                .await
                .context("Failed to decode GitHub App installation token response")?;
            token.into_cached()
        }
        .await;
        cache.finish_refresh(result)
    }

    /// Get a cached token from a synchronous clone worker, refreshing once near expiry.
    /// Must be called outside an async runtime, just like reqwest's blocking client.
    pub(crate) fn token_blocking(&self) -> Result<Option<String>> {
        let Some(app) = &self.app else {
            return Ok(self.fixed_token.clone());
        };

        let mut cache = app.token_cache.blocking_lock();
        if let Some(token) = cache.cached_token()? {
            return Ok(Some(token));
        }
        let result = (|| {
            let jwt = app_jwt(app)?;
            let url = installation_token_url(&self.api_base, app.installation_id)?;
            let client = reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(self.ignore_certs)
                .resource_connect_timeout(TOKEN_CONNECT_TIMEOUT)
                .resource_timeout(TOKEN_REQUEST_TIMEOUT)
                .build()
                .context("Failed to build GitHub App HTTP client")?;
            let request = client
                .post(url)
                .header(header::ACCEPT, "application/vnd.github+json")
                .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
                .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
                .bearer_auth(jwt);
            let response =
                crate::github::retry::send_blocking(request, "minting an installation token")
                    .context("Failed to request a GitHub App installation token")?;
            let response = ensure_token_success_blocking(response)?;
            let token: InstallationTokenResponse = response
                .json()
                .context("Failed to decode GitHub App installation token response")?;
            token.into_cached()
        })();
        cache.finish_refresh(result)
    }

    /// Whether this auth source may be used for a repository on `clone_host`.
    ///
    /// Fixed tokens retain their existing behavior across configured GitHub hosts. App
    /// installation tokens are tied to the API base that minted them and must not be offered to
    /// another GitHub or GitHub Enterprise host.
    pub(crate) fn allows_clone_host(&self, clone_host: &str) -> bool {
        let Some(_) = &self.app else {
            return true;
        };

        let Some(api_host) = self.api_base.host_str() else {
            return false;
        };
        let api_host = if api_host.eq_ignore_ascii_case("api.github.com") {
            "github.com".to_string()
        } else {
            api_host.to_ascii_lowercase()
        };
        let api_host = match self.api_base.port() {
            Some(port) => format!("{api_host}:{port}"),
            None => api_host,
        };
        api_host.eq_ignore_ascii_case(clone_host)
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
    })
}

/// Expand the deliberately small path syntax accepted for the App private key.
///
/// This is a lexical, single-pass expansion. It never invokes a shell, does
/// not perform command substitution, and does not recursively expand values
/// read from the environment.
fn expand_private_key_path(path: &Path) -> Result<PathBuf> {
    let path = path
        .to_str()
        .context("GitHub App private-key path must contain valid Unicode for expansion")?;
    expand_private_key_path_with(path, |name| env::var(name).ok().filter(|value| !value.is_empty()))
}

fn expand_private_key_path_with<F>(path: &str, mut lookup: F) -> Result<PathBuf>
where
    F: FnMut(&str) -> Option<String>,
{
    if path == "~" || path.starts_with("~/") || path.starts_with("~\\") {
        let home = current_user_home(&mut lookup).filter(|value| !value.is_empty());
        let home = home.with_context(|| {
            format!(
                "Could not resolve the current user's home directory while expanding {PRIVATE_KEY_PATH_ENV}"
            )
        })?;
        let suffix = expand_environment_references(&path[1..], &mut lookup)?;
        // Replace only the leading '~'. Concatenation preserves shell-like
        // semantics when an expanded suffix happens to begin with a separator.
        return Ok(PathBuf::from(format!("{home}{suffix}")));
    }

    Ok(PathBuf::from(expand_environment_references(path, &mut lookup)?))
}

fn current_user_home<F>(lookup: &mut F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    current_user_home_for_platform(cfg!(windows), lookup)
}

fn current_user_home_for_platform<F>(windows: bool, lookup: &mut F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    if windows {
        if let Some(profile) = lookup("USERPROFILE") {
            return Some(profile);
        }
        if let (Some(drive), Some(path)) = (lookup("HOMEDRIVE"), lookup("HOMEPATH")) {
            return Some(format!("{drive}{path}"));
        }
    }

    lookup("HOME")
}

fn expand_environment_references<F>(input: &str, lookup: &mut F) -> Result<String>
where
    F: FnMut(&str) -> Option<String>,
{
    let mut output = String::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        let rest = &input[index..];
        let character = rest.chars().next().expect("index is on a character boundary");

        match character {
            '$' if rest.starts_with("$$") => {
                output.push('$');
                index += 2;
            }
            '$' if rest.starts_with("${") => {
                let close = rest[2..].find('}').with_context(|| {
                    format!("Unclosed environment-variable reference in {PRIVATE_KEY_PATH_ENV}")
                })?;
                let name = &rest[2..2 + close];
                validate_variable_name(name)?;
                output.push_str(&expanded_variable(name, lookup)?);
                index += close + 3;
            }
            '$' => {
                let name_len = environment_name_prefix_len(&rest[1..]);
                if name_len == 0 {
                    // '$(' and other shell constructs remain literal. They are
                    // never evaluated or treated as expansion syntax.
                    output.push('$');
                    index += 1;
                } else {
                    let name = &rest[1..1 + name_len];
                    output.push_str(&expanded_variable(name, lookup)?);
                    index += name_len + 1;
                }
            }
            '%' if rest.starts_with("%%") => {
                output.push('%');
                index += 2;
            }
            '%' => {
                let Some(close) = rest[1..].find('%') else {
                    output.push('%');
                    index += 1;
                    continue;
                };
                let name = &rest[1..1 + close];
                if is_variable_name(name) {
                    output.push_str(&expanded_variable(name, lookup)?);
                    index += close + 2;
                } else {
                    // Percent signs are common in filenames. Only a valid
                    // %NAME% pair is interpreted as an environment reference.
                    output.push('%');
                    index += 1;
                }
            }
            _ => {
                output.push(character);
                index += character.len_utf8();
            }
        }
    }

    Ok(output)
}

fn environment_name_prefix_len(input: &str) -> usize {
    let mut chars = input.char_indices();
    let Some((_, first)) = chars.next() else {
        return 0;
    };
    if !is_variable_name_start(first) {
        return 0;
    }

    let mut len = first.len_utf8();
    for (index, character) in chars {
        if !is_variable_name_continue(character) {
            break;
        }
        len = index + character.len_utf8();
    }
    len
}

fn validate_variable_name(name: &str) -> Result<()> {
    if !is_variable_name(name) {
        bail!(
            "Invalid environment-variable name in {PRIVATE_KEY_PATH_ENV}: names must use ASCII letters, digits, and underscores and cannot start with a digit"
        )
    }
    Ok(())
}

fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if is_variable_name_start(first))
        && chars.all(is_variable_name_continue)
}

fn is_variable_name_start(character: char) -> bool {
    character == '_' || character.is_ascii_alphabetic()
}

fn is_variable_name_continue(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}

fn expanded_variable<F>(name: &str, lookup: &mut F) -> Result<String>
where
    F: FnMut(&str) -> Option<String>,
{
    lookup(name).filter(|value| !value.is_empty()).with_context(|| {
        format!("{PRIVATE_KEY_PATH_ENV} references undefined or empty environment variable {name}")
    })
}

fn parse_id(name: &str, value: Option<String>) -> Result<u64> {
    let value = value.with_context(|| {
        format!(
            "Incomplete GitHub App authentication: set {APP_ID_ENV}, {INSTALLATION_ID_ENV}, and either {PRIVATE_KEY_ENV} or {PRIVATE_KEY_PATH_ENV}"
        )
    })?;
    value.parse::<u64>().with_context(|| format!("{name} must be a positive integer")).and_then(
        |id| {
            if id == 0 { bail!("{name} must be a positive integer") } else { Ok(id) }
        },
    )
}

fn normalize_api_base(api_url: &Url) -> Url {
    let mut base = api_url.clone();
    if !base.path().ends_with('/') {
        base.set_path(&format!("{}/", base.path()));
    }
    base
}

fn installation_token_url(api_base: &Url, installation_id: u64) -> Result<Url> {
    api_base
        .join(&format!("app/installations/{installation_id}/access_tokens"))
        .context("Failed to build GitHub App installation-token URL")
}

fn app_jwt(app: &GitHubAppCredentials) -> Result<String> {
    ensure_jwt_crypto_provider();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System clock is before the Unix epoch")?
        .as_secs();
    let claims = GitHubAppClaims {
        // GitHub recommends backdating iat by 60 seconds for clock drift.
        iat: now.saturating_sub(60),
        // Keep below GitHub's ten-minute maximum JWT lifetime.
        exp: now.saturating_add(9 * 60),
        iss: app.app_id.to_string(),
    };
    encode(&Header::new(Algorithm::RS256), &claims, &app.encoding_key)
        .context("Failed to sign GitHub App JWT")
}

async fn ensure_token_success_async(mut response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let mut error = installation_token_error(response.status(), response.url(), response.headers());
    let body = crate::github::retry::read_body_prefix(&mut response, 512).await.unwrap_or_default();
    error.body = truncated(String::from_utf8_lossy(&body).into_owned());
    Err(error.into())
}

fn ensure_token_success_blocking(
    mut response: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response> {
    use std::io::Read;

    if response.status().is_success() {
        return Ok(response);
    }
    let mut error = installation_token_error(response.status(), response.url(), response.headers());
    let mut body = Vec::new();
    let _ = (&mut response).take(512).read_to_end(&mut body);
    error.body = truncated(String::from_utf8_lossy(&body).into_owned());
    Err(error.into())
}

fn installation_token_error(
    status: reqwest::StatusCode,
    url: &Url,
    headers: &header::HeaderMap,
) -> InstallationTokenError {
    // The retry helper may return without waiting if the server asks for more
    // than its bounded wait budget. Retain that full cooldown for later callers.
    let cooldown = crate::github::retry::retry_delay(status, headers, &[], 0, Utc::now())
        .unwrap_or_default()
        .max(TOKEN_FAILURE_COOLDOWN);
    InstallationTokenError { status, url: url.clone(), body: String::new(), cooldown }
}

fn truncated(mut body: String) -> String {
    if body.len() > 512 {
        let mut end = 512;
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        body.truncate(end);
    }
    body
}

fn validate_installation_token(token: String) -> Result<String> {
    if token.trim().is_empty() {
        bail!("GitHub App installation-token response contained an empty token")
    }
    Ok(token)
}

trait BlockingResourceTimeout {
    fn resource_timeout(self, duration: Duration) -> Self;
    fn resource_connect_timeout(self, duration: Duration) -> Self;
}
impl BlockingResourceTimeout for reqwest::blocking::ClientBuilder {
    fn resource_timeout(self, duration: Duration) -> Self {
        if kingfisher_scanner::validation::limits::NetworkLimits::current().no_timeouts {
            self.timeout(None)
        } else {
            self.timeout(duration)
        }
    }
    fn resource_connect_timeout(self, duration: Duration) -> Self {
        if kingfisher_scanner::validation::limits::NetworkLimits::current().no_timeouts {
            self
        } else {
            self.connect_timeout(duration)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::{
        RsaPrivateKey,
        pkcs1::{EncodeRsaPrivateKey, LineEnding},
        rand_core::OsRng,
    };
    use serde_json::Value;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header_regex, method, path},
    };

    use super::*;

    fn test_private_key() -> String {
        RsaPrivateKey::new(&mut OsRng, 2048)
            .expect("generate RSA private key")
            .to_pkcs1_pem(LineEnding::LF)
            .expect("encode RSA private key")
            .to_string()
    }

    #[test]
    fn error_body_truncation_preserves_utf8_boundaries() {
        let body = format!("{}é trailing", "a".repeat(511));
        let truncated = truncated(body);

        assert_eq!(truncated, "a".repeat(511));
        assert!(truncated.len() <= 512);
    }

    fn app_auth(api_url: &Url, private_key: String) -> GitHubAuth {
        GitHubAuth::from_options(
            api_url,
            false,
            AuthOptions {
                fixed_token: Some("ignored-fixed-token".to_string()),
                app_id: Some("12345".to_string()),
                installation_id: Some("67890".to_string()),
                private_key: Some(private_key),
                private_key_path: None,
            },
        )
        .expect("valid GitHub App authentication")
    }

    fn expand_test_path(path: &str, variables: &[(&str, &str)]) -> Result<PathBuf> {
        let variables = variables.iter().copied().collect::<BTreeMap<_, _>>();
        expand_private_key_path_with(path, |name| variables.get(name).map(ToString::to_string))
    }

    #[test]
    fn private_key_path_expands_home_and_environment_variables() {
        let home = if cfg!(windows) { r"C:\Users\alice" } else { "/home/alice" };
        let expanded = expand_test_path(
            "~/$KEY_DIR/${KEY_FILE}",
            &[
                ("HOME", home),
                ("USERPROFILE", home),
                ("KEY_DIR", ".config/kingfisher"),
                ("KEY_FILE", "app.pem"),
            ],
        )
        .unwrap();

        assert_eq!(expanded, PathBuf::from(home).join(".config/kingfisher/app.pem"));
    }

    #[test]
    fn private_key_path_expands_windows_style_environment_variables() {
        let expanded = expand_test_path(
            r"%USERPROFILE%\AppData\Local\kingfisher\app.pem",
            &[("USERPROFILE", r"C:\Users\alice")],
        )
        .unwrap();

        assert_eq!(expanded, PathBuf::from(r"C:\Users\alice\AppData\Local\kingfisher\app.pem"));
    }

    #[test]
    fn windows_home_resolution_uses_native_environment_variables() {
        let mut profile = |name: &str| match name {
            "USERPROFILE" => Some(r"C:\Users\alice".to_string()),
            _ => None,
        };
        assert_eq!(
            current_user_home_for_platform(true, &mut profile).as_deref(),
            Some(r"C:\Users\alice")
        );

        let mut drive_and_path = |name: &str| match name {
            "HOMEDRIVE" => Some("D:".to_string()),
            "HOMEPATH" => Some(r"\Profiles\alice".to_string()),
            _ => None,
        };
        assert_eq!(
            current_user_home_for_platform(true, &mut drive_and_path).as_deref(),
            Some(r"D:\Profiles\alice")
        );
    }

    #[test]
    fn private_key_path_expansion_is_single_pass_and_never_executes_shell_syntax() {
        let expanded = expand_test_path(
            "$KEY_ROOT/$(touch should-not-exist)/app.pem",
            &[("KEY_ROOT", "$NESTED"), ("NESTED", "/tmp/keys")],
        )
        .unwrap();

        assert_eq!(expanded, PathBuf::from("$NESTED/$(touch should-not-exist)/app.pem"));
    }

    #[test]
    fn private_key_path_supports_literal_expansion_markers() {
        let expanded = expand_test_path("$$HOME/%%USERPROFILE%%/app.pem", &[]).unwrap();
        assert_eq!(expanded, PathBuf::from("$HOME/%USERPROFILE%/app.pem"));
    }

    #[test]
    fn private_key_path_rejects_undefined_or_empty_variables() {
        let undefined = expand_test_path("$MISSING/app.pem", &[]).unwrap_err();
        assert!(undefined.to_string().contains("undefined or empty environment variable MISSING"));

        let empty = expand_test_path("${EMPTY}/app.pem", &[("EMPTY", "")]).unwrap_err();
        assert!(empty.to_string().contains("undefined or empty environment variable EMPTY"));
    }

    #[test]
    fn app_auth_reads_private_key_from_expanded_path() {
        let tempdir = tempfile::tempdir().unwrap();
        let key_dir = tempdir.path().join("keys");
        std::fs::create_dir(&key_dir).unwrap();
        std::fs::write(key_dir.join("app.pem"), test_private_key()).unwrap();
        let root = tempdir.path().to_string_lossy().into_owned();

        temp_env::with_var("KF_TEST_GITHUB_APP_KEY_ROOT", Some(root.as_str()), || {
            let auth = GitHubAuth::from_options(
                &Url::parse("https://api.github.com/").unwrap(),
                false,
                AuthOptions {
                    fixed_token: None,
                    app_id: Some("12345".to_string()),
                    installation_id: Some("67890".to_string()),
                    private_key: None,
                    private_key_path: Some(PathBuf::from(
                        "$KF_TEST_GITHUB_APP_KEY_ROOT/keys/app.pem",
                    )),
                },
            )
            .expect("expanded private-key path should load");

            assert!(auth.app.is_some());
        });
    }

    #[test]
    fn app_jwt_has_required_claims() {
        let auth = app_auth(&Url::parse("https://api.github.com/").unwrap(), test_private_key());
        let token = app_jwt(auth.app.as_ref().unwrap()).expect("sign JWT");
        let payload = token.split('.').nth(1).expect("JWT payload");
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(payload).expect("base64-decode JWT payload"),
        )
        .expect("decode JWT claims");

        assert_eq!(claims["iss"], "12345");
        assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
        assert!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap() <= 600);
    }

    #[test]
    fn app_auth_is_scoped_to_configured_clone_host() {
        let auth =
            app_auth(&Url::parse("https://ghe.example.com/api/v3/").unwrap(), test_private_key());

        assert!(auth.allows_clone_host("ghe.example.com"));
        assert!(!auth.allows_clone_host("github.com"));
    }

    #[test]
    fn public_app_auth_maps_api_host_to_clone_host() {
        let auth = app_auth(&Url::parse("https://api.github.com/").unwrap(), test_private_key());

        assert!(auth.allows_clone_host("github.com"));
        assert!(!auth.allows_clone_host("api.github.com"));
    }

    #[tokio::test]
    async fn async_token_exchange_uses_installation_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/67890/access_tokens"))
            .and(header_regex("authorization", r"^Bearer eyJ"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_async-token",
                "expires_at": "2099-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api_url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = app_auth(&api_url, test_private_key());
        let client = reqwest::Client::new();
        assert_eq!(auth.token(&client).await.unwrap().as_deref(), Some("ghs_async-token"));
    }

    #[tokio::test]
    async fn get_retry_refreshes_installation_token_that_expires_during_quota_wait() {
        let server = MockServer::start().await;
        let auth = app_auth(&Url::parse(&server.uri()).unwrap(), test_private_key());
        let cache = auth.app.as_ref().unwrap().token_cache.clone();
        cache.lock().await.token = Some(CachedInstallationToken {
            token: "ghs_before-wait".into(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        });
        Mock::given(method("GET"))
            .and(path("/repos"))
            .and(header_regex("authorization", r"^Bearer ghs_before-wait$"))
            .respond_with(move |_: &wiremock::Request| {
                // Simulate expiry before the retry without waiting an hour.
                cache.try_lock().unwrap().token.as_mut().unwrap().expires_at =
                    Utc::now() - chrono::Duration::seconds(1);
                ResponseTemplate::new(403)
                    .insert_header("retry-after", "0")
                    .insert_header("x-ratelimit-remaining", "0")
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/app/installations/67890/access_tokens"))
            .and(header_regex("authorization", r"^Bearer eyJ"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_after-wait", "expires_at": "2099-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos"))
            .and(header_regex("authorization", r"^Bearer ghs_after-wait$"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let response = crate::github::github_get(
            &reqwest::Client::new(),
            Url::parse(&format!("{}/repos?page=2", server.uri())).unwrap(),
            &auth,
            "testing token refresh after a quota wait",
        )
        .await
        .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = server.received_requests().await.unwrap();
        let gets: Vec<_> = requests.iter().filter(|request| request.method == "GET").collect();
        assert_eq!(gets.len(), 2);
        assert_eq!(gets[0].url, gets[1].url);
        assert_eq!(gets[0].url.query(), Some("page=2"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_token_exchange_reuses_cached_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/67890/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_clone-token",
                "expires_at": "2099-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let api_url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Arc::new(app_auth(&api_url, test_private_key()));
        let thread_auth = Arc::clone(&auth);
        let tokens = tokio::task::spawn_blocking(move || {
            [thread_auth.token_blocking().unwrap(), thread_auth.token_blocking().unwrap()]
        })
        .await
        .unwrap();

        assert_eq!(tokens[0].as_deref(), Some("ghs_clone-token"));
        assert_eq!(tokens[1].as_deref(), Some("ghs_clone-token"));
    }

    async fn concurrent_token_requests(auth: Arc<GitHubAuth>) -> Vec<Result<Option<String>>> {
        let barrier = Arc::new(tokio::sync::Barrier::new(32));
        let tasks = (0..32).map(|index| {
            let auth = Arc::clone(&auth);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                if index % 2 == 0 {
                    tokio::task::spawn_blocking(move || auth.token_blocking()).await.unwrap()
                } else {
                    auth.token(&reqwest::Client::new()).await
                }
            })
        });
        futures::future::join_all(tasks).await.into_iter().map(Result::unwrap).collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_workers_share_initial_and_near_expiry_refreshes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v3/app/installations/67890/access_tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_delay(Duration::from_millis(20)).set_body_json(
                    serde_json::json!({
                        "token": "ghs_shared-token", "expires_at": "2099-01-01T00:00:00Z"
                    }),
                ),
            )
            .expect(3)
            .mount(&server)
            .await;
        let api_url = Url::parse(&format!("{}/api/v3", server.uri())).unwrap();
        let key = test_private_key();
        let auth = Arc::new(app_auth(&api_url, key.clone()));
        for offset in [None, Some(30), Some(-1)] {
            if let Some(seconds) = offset {
                auth.app
                    .as_ref()
                    .unwrap()
                    .token_cache
                    .lock()
                    .await
                    .token
                    .as_mut()
                    .unwrap()
                    .expires_at = Utc::now() + chrono::Duration::seconds(seconds);
            }
            for result in concurrent_token_requests(Arc::clone(&auth)).await {
                assert_eq!(result.unwrap().as_deref(), Some("ghs_shared-token"));
            }
            // A separately constructed auth source (as used by API discovery)
            // must reuse the clone workers' token, including after refresh.
            let separate = app_auth(&api_url, key.clone());
            assert_eq!(
                separate.token(&reqwest::Client::new()).await.unwrap().as_deref(),
                Some("ghs_shared-token")
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn terminal_refresh_failure_is_shared_and_recovers_after_cooldown() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3600"))
            .expect(1)
            .mount(&server)
            .await;
        let auth = Arc::new(app_auth(&Url::parse(&server.uri()).unwrap(), test_private_key()));
        for result in concurrent_token_requests(Arc::clone(&auth)).await {
            assert!(result.unwrap_err().to_string().contains("HTTP 429"));
        }
        {
            let mut cache = auth.app.as_ref().unwrap().token_cache.lock().await;
            let failure = cache.failure.as_mut().unwrap();
            assert_eq!(failure.cooldown, Duration::from_secs(3600));
            failure.failed_at = Instant::now() - failure.cooldown;
        }
        server.reset().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_recovered", "expires_at": "2099-01-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        for result in concurrent_token_requests(auth).await {
            assert_eq!(result.unwrap().as_deref(), Some("ghs_recovered"));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_exchanges_retry_transient_failures_before_caching() {
        for blocking in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
                .up_to_n_times(1)
                .expect(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "token": "ghs_retried", "expires_at": "2099-01-01T00:00:00Z"
                })))
                .expect(1)
                .with_priority(2)
                .mount(&server)
                .await;
            let auth = app_auth(&Url::parse(&server.uri()).unwrap(), test_private_key());
            let token = if blocking {
                tokio::task::spawn_blocking(move || auth.token_blocking()).await.unwrap()
            } else {
                auth.token(&reqwest::Client::new()).await
            };
            assert_eq!(token.unwrap().as_deref(), Some("ghs_retried"));
        }
    }

    async fn request_token(auth: Arc<GitHubAuth>, blocking: bool) -> Result<Option<String>> {
        if blocking {
            tokio::task::spawn_blocking(move || auth.token_blocking()).await.unwrap()
        } else {
            auth.token(&reqwest::Client::new()).await
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_failures_allow_immediate_refresh_retry() {
        for blocking in [false, true] {
            for cached in [false, true] {
                // Keep ownership of the port while switching from a dropped
                // connection to a healthy server; no port-rebinding race.
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                let api_url =
                    Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
                let auth = Arc::new(app_auth(&api_url, test_private_key()));
                if cached {
                    auth.app.as_ref().unwrap().token_cache.lock().await.token =
                        Some(CachedInstallationToken {
                            token: "ghs_still-valid".into(),
                            expires_at: Utc::now() + chrono::Duration::seconds(30),
                        });
                }
                let failing_listener = listener.try_clone().unwrap();
                let failed_connection = tokio::task::spawn_blocking(move || {
                    drop(failing_listener.accept().unwrap().0);
                });
                let result = request_token(Arc::clone(&auth), blocking).await;
                failed_connection.await.unwrap();
                if cached {
                    assert_eq!(result.unwrap().as_deref(), Some("ghs_still-valid"));
                } else {
                    assert!(result.unwrap_err().downcast_ref::<reqwest::Error>().is_some());
                }
                assert!(auth.app.as_ref().unwrap().token_cache.lock().await.failure.is_none());

                let server = MockServer::builder().listener(listener).start().await;
                Mock::given(method("POST"))
                    .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                        "token": "ghs_recovered", "expires_at": "2099-01-01T00:00:00Z"
                    })))
                    .expect(1)
                    .mount(&server)
                    .await;
                assert_eq!(
                    request_token(auth, blocking).await.unwrap().as_deref(),
                    Some("ghs_recovered")
                );
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_errors_and_cooldown_use_only_unexpired_tokens() {
        for blocking in [false, true] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "3600"))
                .expect(1)
                .mount(&server)
                .await;
            let auth = Arc::new(app_auth(&Url::parse(&server.uri()).unwrap(), test_private_key()));
            auth.app.as_ref().unwrap().token_cache.lock().await.token =
                Some(CachedInstallationToken {
                    token: "ghs_still-valid".into(),
                    expires_at: Utc::now() + chrono::Duration::seconds(30),
                });

            for _ in 0..2 {
                assert_eq!(
                    request_token(Arc::clone(&auth), blocking).await.unwrap().as_deref(),
                    Some("ghs_still-valid")
                );
            }
            auth.app
                .as_ref()
                .unwrap()
                .token_cache
                .lock()
                .await
                .token
                .as_mut()
                .unwrap()
                .expires_at = Utc::now() - chrono::Duration::seconds(1);
            assert!(
                request_token(auth, blocking)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("cooling down")
            );
        }
    }

    #[test]
    fn only_auth_rate_limit_and_server_errors_enter_cooldown() {
        let url =
            Url::parse("https://api.github.com/app/installations/67890/access_tokens").unwrap();
        for (code, should_cooldown) in [
            (400, false),
            (401, true),
            (403, true),
            (404, false),
            (422, false),
            (429, true),
            (500, true),
            (503, true),
            (599, true),
        ] {
            let mut cache = InstallationTokenCache::default();
            let error = installation_token_error(
                reqwest::StatusCode::from_u16(code).unwrap(),
                &url,
                &header::HeaderMap::new(),
            );
            assert!(cache.finish_refresh(Err(error.into())).is_err());
            assert_eq!(cache.failure.is_some(), should_cooldown, "HTTP {code}");
            if should_cooldown {
                assert!(cache.cached_token().is_err(), "HTTP {code}");
            } else {
                assert_eq!(cache.cached_token().unwrap(), None, "HTTP {code}");
            }
        }
    }

    #[test]
    fn refresh_errors_never_return_expired_tokens_or_cache_untyped_failures() {
        for seconds in [-1, 30] {
            let mut cache = InstallationTokenCache {
                token: Some(CachedInstallationToken {
                    token: "ghs_cached".into(),
                    expires_at: Utc::now() + chrono::Duration::seconds(seconds),
                }),
                // A non-HTTP failure after an old cooldown must not renew it.
                failure: Some(CachedTokenFailure {
                    message: "old failure".into(),
                    failed_at: Instant::now() - TOKEN_FAILURE_COOLDOWN,
                    cooldown: TOKEN_FAILURE_COOLDOWN,
                }),
            };
            let result = cache.finish_refresh(Err(anyhow::anyhow!("failed to decode response")));
            if seconds > 0 {
                assert_eq!(result.unwrap().as_deref(), Some("ghs_cached"));
            } else {
                assert!(result.is_err());
            }
            assert!(cache.failure.is_none());
            assert_eq!(cache.cached_token().unwrap(), None);
        }
    }

    #[test]
    fn fresh_credentials_isolate_cached_state_when_mock_endpoints_are_reused() {
        let url = Url::parse("http://127.0.0.1:12345/").unwrap();
        let previous_key = test_private_key();
        let previous = app_auth(&url, previous_key.clone());
        previous.app.as_ref().unwrap().token_cache.try_lock().unwrap().token =
            Some(CachedInstallationToken {
                token: "ghs_previous-test".into(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            });
        drop(previous);

        // Fresh RSA material is the per-test namespace, even if a mock server
        // reuses an earlier test's port. Do not clear the process-global map:
        // that would race other tests and stop exercising production sharing.
        let next = app_auth(&url, test_private_key());
        assert_eq!(
            next.app.as_ref().unwrap().token_cache.try_lock().unwrap().cached_token().unwrap(),
            None
        );
        let same_credentials = app_auth(&url, previous_key);
        assert_eq!(
            same_credentials
                .app
                .as_ref()
                .unwrap()
                .token_cache
                .try_lock()
                .unwrap()
                .cached_token()
                .unwrap()
                .as_deref(),
            Some("ghs_previous-test")
        );
    }

    #[test]
    fn invalid_expiry_or_empty_tokens_are_rejected() {
        for body in [
            serde_json::json!({"token":"valid"}),
            serde_json::json!({"token":"valid", "expires_at":"invalid"}),
            serde_json::json!({"token":"valid", "expires_at":"2000-01-01T00:00:00Z"}),
            serde_json::json!({"token":"valid", "expires_at":
                (Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()}),
            serde_json::json!({"token":"  ", "expires_at":"2099-01-01T00:00:00Z"}),
        ] {
            let result = serde_json::from_value::<InstallationTokenResponse>(body)
                .map_err(anyhow::Error::from)
                .and_then(InstallationTokenResponse::into_cached);
            assert!(result.is_err());
        }
    }

    #[test]
    fn cache_is_scoped_to_endpoint_and_app_credentials() {
        let url = Url::parse("https://ghe.example.com/api/v3").unwrap();
        let key = test_private_key();
        let baseline = app_auth(&url, key.clone());
        let same = app_auth(&normalize_api_base(&url), key.clone());
        let baseline_cache = &baseline.app.as_ref().unwrap().token_cache;
        assert!(Arc::ptr_eq(baseline_cache, &same.app.as_ref().unwrap().token_cache));
        for changed in [
            app_auth(&Url::parse("https://other.example.com/api/v3/").unwrap(), key.clone()),
            app_auth(&Url::parse("https://ghe.example.com:8443/api/v3/").unwrap(), key.clone()),
            app_auth(&Url::parse("https://ghe.example.com/other/").unwrap(), key.clone()),
            app_auth(&url, test_private_key()),
        ] {
            assert!(!Arc::ptr_eq(baseline_cache, &changed.app.as_ref().unwrap().token_cache));
        }
        for (app_id, installation_id, ignore_certs) in
            [("12346", "67890", false), ("12345", "67891", false), ("12345", "67890", true)]
        {
            let changed = GitHubAuth::from_options(
                &url,
                ignore_certs,
                AuthOptions {
                    fixed_token: None,
                    app_id: Some(app_id.into()),
                    installation_id: Some(installation_id.into()),
                    private_key: Some(key.clone()),
                    private_key_path: None,
                },
            )
            .unwrap();
            assert!(!Arc::ptr_eq(baseline_cache, &changed.app.as_ref().unwrap().token_cache));
        }
    }

    #[tokio::test]
    async fn fixed_token_and_anonymous_auth_do_not_exchange_tokens() {
        for fixed_token in [None, Some("fixed-token".to_string())] {
            let auth = GitHubAuth::from_options(
                &Url::parse("https://api.github.com/").unwrap(),
                false,
                AuthOptions {
                    fixed_token: fixed_token.clone(),
                    app_id: None,
                    installation_id: None,
                    private_key: None,
                    private_key_path: None,
                },
            )
            .unwrap();
            assert_eq!(auth.token(&reqwest::Client::new()).await.unwrap(), fixed_token);
            assert_eq!(auth.token_blocking().unwrap(), fixed_token);
        }
    }

    #[test]
    fn partial_app_configuration_is_rejected() {
        let err = GitHubAuth::from_options(
            &Url::parse("https://api.github.com/").unwrap(),
            false,
            AuthOptions {
                fixed_token: None,
                app_id: Some("12345".to_string()),
                installation_id: None,
                private_key: None,
                private_key_path: None,
            },
        )
        .err()
        .expect("partial configuration should fail");

        assert!(err.to_string().contains("Incomplete GitHub App authentication"));
    }
}
