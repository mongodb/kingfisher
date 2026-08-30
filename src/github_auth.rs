use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, Once},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
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

static JWT_CRYPTO_PROVIDER: Once = Once::new();

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
}

/// Authentication source for GitHub API requests and Git clones.
///
/// A complete GitHub App configuration takes precedence over KF_GITHUB_TOKEN.
/// App installation tokens are minted on demand, allowing clone workers to get
/// a new token immediately before each repository operation.
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

        Ok(Self {
            fixed_token: options.fixed_token,
            app: Some(GitHubAppCredentials {
                app_id,
                installation_id,
                encoding_key: Arc::new(encoding_key),
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

        let jwt = app_jwt(app)?;
        let url = installation_token_url(&self.api_base, app.installation_id)?;
        let response = client
            .post(url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
            .bearer_auth(jwt)
            .timeout(TOKEN_REQUEST_TIMEOUT)
            .send()
            .await
            .context("Failed to request a GitHub App installation token")?;

        let response = ensure_token_success_async(response).await?;
        let token: InstallationTokenResponse = response
            .json()
            .await
            .context("Failed to decode GitHub App installation token response")?;
        validate_installation_token(token.token).map(Some)
    }

    /// Get a token from a synchronous clone worker.
    ///
    /// This intentionally performs a new installation-token exchange for every
    /// call. Clone workers invoke it immediately before an update or fresh clone,
    /// so an organization scan can run longer than GitHub's one-hour token lifetime.
    pub(crate) fn token_blocking(&self) -> Result<Option<String>> {
        let Some(app) = &self.app else {
            return Ok(self.fixed_token.clone());
        };

        let jwt = app_jwt(app)?;
        let url = installation_token_url(&self.api_base, app.installation_id)?;
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(self.ignore_certs)
            .connect_timeout(TOKEN_CONNECT_TIMEOUT)
            .timeout(TOKEN_REQUEST_TIMEOUT)
            .build()
            .context("Failed to build GitHub App HTTP client")?;
        let response = client
            .post(url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
            .header(header::USER_AGENT, GLOBAL_USER_AGENT.as_str())
            .bearer_auth(jwt)
            .send()
            .context("Failed to request a GitHub App installation token")?;

        let response = ensure_token_success_blocking(response)?;
        let token: InstallationTokenResponse =
            response.json().context("Failed to decode GitHub App installation token response")?;
        validate_installation_token(token.token).map(Some)
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

async fn ensure_token_success_async(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let url = response.url().clone();
    let body = truncated(response.text().await.unwrap_or_default());
    bail!("GitHub App installation-token request failed: HTTP {status} ({url}): {body}")
}

fn ensure_token_success_blocking(
    response: reqwest::blocking::Response,
) -> Result<reqwest::blocking::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let url = response.url().clone();
    let body = truncated(response.text().unwrap_or_default());
    bail!("GitHub App installation-token request failed: HTTP {status} ({url}): {body}")
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_token_exchange_mints_on_every_call() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/67890/access_tokens"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "ghs_clone-token",
                "expires_at": "2099-01-01T00:00:00Z"
            })))
            .expect(2)
            .mount(&server)
            .await;

        let api_url = Url::parse(&format!("{}/", server.uri())).unwrap();
        let auth = Arc::new(app_auth(&api_url, test_private_key()));
        let thread_auth = Arc::clone(&auth);
        let tokens = std::thread::spawn(move || {
            [thread_auth.token_blocking().unwrap(), thread_auth.token_blocking().unwrap()]
        })
        .join()
        .unwrap();

        assert_eq!(tokens[0].as_deref(), Some("ghs_clone-token"));
        assert_eq!(tokens[1].as_deref(), Some("ghs_clone-token"));
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
