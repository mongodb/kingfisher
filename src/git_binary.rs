use std::{
    path::Path,
    process::{Command, ExitStatus, Output, Stdio},
};

use tracing::{debug, debug_span};
use url::Url;

use crate::{bitbucket::is_bitbucket_access_token, git_url::GitUrl};

const BITBUCKET_CREDENTIAL_HELPER: &str = r#"!_bbcreds() {
    if [ -n "$KF_BITBUCKET_OAUTH_TOKEN" ]; then
        echo username="x-token-auth";
        echo password="$KF_BITBUCKET_OAUTH_TOKEN";
        return;
    fi
    if [ -n "$KF_BITBUCKET_ACCESS_TOKEN" ]; then
        echo username="x-token-auth";
        echo password="$KF_BITBUCKET_ACCESS_TOKEN";
        return;
    fi
    if [ -n "$KF_BITBUCKET_USERNAME" ]; then
        bb_pass="${KF_BITBUCKET_APP_PASSWORD:-${KF_BITBUCKET_TOKEN:-${KF_BITBUCKET_PASSWORD:-}}}";
        if [ -n "$bb_pass" ]; then
            echo username="$KF_BITBUCKET_USERNAME";
            echo password="$bb_pass";
            return;
        fi
    fi
}; _bbcreds"#;

const GITEA_CREDENTIAL_HELPER: &str = r#"!_gteacreds() {
    if [ -n "$KF_GITEA_TOKEN" ]; then
        user="${KF_GITEA_USERNAME:-gitea}";
        echo username="$user";
        echo password="$KF_GITEA_TOKEN";
    fi
}; _gteacreds"#;

const AZURE_CREDENTIAL_HELPER: &str = r#"!_azcreds() {
    token="${KF_AZURE_TOKEN:-${KF_AZURE_PAT:-}}";
    if [ -n "$token" ]; then
        user="${KF_AZURE_USERNAME:-pat}";
        echo username="$user";
        echo password="$token";
    fi
}; _azcreds"#;

const HUGGINGFACE_CREDENTIAL_HELPER: &str = r#"!_hfcreds() {
    token="$KF_HUGGINGFACE_TOKEN";
    if [ -n "$token" ]; then
        user="${KF_HUGGINGFACE_USERNAME:-hf_user}";
        echo username="$user";
        echo password="$token";
    fi
}; _hfcreds"#;

const GITHUB_CREDENTIAL_HELPER: &str =
    r#"!_ghcreds() { echo username="kingfisher"; echo password="$KF_GITHUB_TOKEN"; }; _ghcreds"#;

const GITLAB_CREDENTIAL_HELPER: &str =
    r#"!_glcreds() { echo username="oauth2"; echo password="$KF_GITLAB_TOKEN"; }; _glcreds"#;

/// HTTPS hosts that each provider's credential helper is allowed to target.
///
/// Credential helpers echo provider tokens to whatever remote `git` is talking
/// to. Installing them as unscoped `credential.helper` entries leaks those
/// tokens to any HTTP(S) remote that issues an auth challenge — including an
/// attacker-controlled scan target. Each helper is therefore bound to a
/// `credential.https://<host>.helper` key so `git` only invokes it for the
/// provider's own host(s).
#[derive(Debug, Clone, Default)]
pub struct ProviderHosts {
    pub github: Vec<String>,
    pub gitlab: Vec<String>,
    pub gitea: Vec<String>,
    pub bitbucket: Vec<String>,
    pub azure: Vec<String>,
    pub huggingface: Vec<String>,
}

impl ProviderHosts {
    /// Well-known public SaaS clone hosts for each supported provider.
    pub fn saas_defaults() -> Self {
        Self {
            github: vec!["github.com".to_string()],
            gitlab: vec!["gitlab.com".to_string()],
            gitea: vec!["gitea.com".to_string()],
            bitbucket: vec!["bitbucket.org".to_string()],
            azure: vec!["dev.azure.com".to_string()],
            huggingface: vec!["huggingface.co".to_string()],
        }
    }

    /// Add a trusted host to `list`, normalizing case and de-duplicating.
    pub fn add(list: &mut Vec<String>, host: &str) {
        let host = host.trim().to_ascii_lowercase();
        if !host.is_empty() && !list.iter().any(|existing| existing == &host) {
            list.push(host);
        }
    }
}

/// Represents errors that can occur when interacting with the `git` CLI.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git execution failed: {0}")]
    IOError(#[from] std::io::Error),

    #[error(
        "git execution failed (status: {status}){summary}",
        status = format_exit_status(.status),
        summary = format_git_error_summary(.stdout.as_slice(), .stderr.as_slice())
    )]
    GitError { stdout: Vec<u8>, stderr: Vec<u8>, status: ExitStatus },
}

fn format_exit_status(status: &ExitStatus) -> String {
    status.code().map(|code| code.to_string()).unwrap_or_else(|| status.to_string())
}

fn format_git_error_summary(stdout: &[u8], stderr: &[u8]) -> String {
    let mut messages = Vec::new();
    if let Some(line) = summarize_output(stderr) {
        messages.push(line);
    }
    if let Some(line) = summarize_output(stdout) {
        messages.push(line);
    }
    if messages.is_empty() { String::new() } else { format!(": {}", messages.join(" | ")) }
}

fn summarize_output(output: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(output);
    text.lines().map(str::trim).find(|line| !line.is_empty()).map(|line| line.to_owned())
}

/// A helper struct for running `git` commands.
///
/// It supports optional GitHub, GitLab, Gitea, and Bitbucket credentials passed via
/// environment variables and optionally ignores TLS certificate validation if
/// requested.
pub struct Git {
    credentials: Vec<String>,
    ignore_certs: bool,
    bitbucket_access_token: Option<String>,
    bitbucket_env: Vec<(String, String)>,
    bitbucket_basic_auth: Option<(String, String)>,
}

impl Git {
    /// Create a new `Git` instance that trusts only the public SaaS hosts.
    ///
    /// * `ignore_certs`: If `true`, disables SSL certificate verification for `git` operations.
    pub fn new(ignore_certs: bool) -> Self {
        Self::with_provider_hosts(ignore_certs, &ProviderHosts::saas_defaults())
    }

    /// Create a new `Git` instance whose credential helpers are scoped to the
    /// hosts in `provider_hosts`. Each provider token is offered only to that
    /// provider's configured HTTPS host(s), never to an arbitrary scan target.
    ///
    /// * `ignore_certs`: If `true`, disables SSL certificate verification for `git` operations.
    pub fn with_provider_hosts(ignore_certs: bool, provider_hosts: &ProviderHosts) -> Self {
        let mut credentials = Vec::new();

        fn normalized_env_var(name: &str) -> Option<String> {
            std::env::var(name)
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        }

        let bitbucket_username = normalized_env_var("KF_BITBUCKET_USERNAME");
        let bitbucket_app_password = normalized_env_var("KF_BITBUCKET_APP_PASSWORD");
        let bitbucket_token = normalized_env_var("KF_BITBUCKET_TOKEN");
        let bitbucket_password = normalized_env_var("KF_BITBUCKET_PASSWORD");
        let bitbucket_oauth_token = normalized_env_var("KF_BITBUCKET_OAUTH_TOKEN");

        let mut bitbucket_env = Vec::new();
        for (key, value) in [
            ("KF_BITBUCKET_USERNAME", bitbucket_username.as_ref()),
            ("KF_BITBUCKET_APP_PASSWORD", bitbucket_app_password.as_ref()),
            ("KF_BITBUCKET_TOKEN", bitbucket_token.as_ref()),
            ("KF_BITBUCKET_PASSWORD", bitbucket_password.as_ref()),
            ("KF_BITBUCKET_OAUTH_TOKEN", bitbucket_oauth_token.as_ref()),
        ] {
            if let Some(value) = value {
                bitbucket_env.push((key.to_string(), value.to_string()));
            }
        }

        let has_github_token =
            matches!(std::env::var("KF_GITHUB_TOKEN"), Ok(token) if !token.is_empty());
        let has_gitlab_token =
            matches!(std::env::var("KF_GITLAB_TOKEN"), Ok(token) if !token.is_empty());
        let has_gitea_token =
            matches!(std::env::var("KF_GITEA_TOKEN"), Ok(token) if !token.is_empty());
        let bitbucket_access_token =
            bitbucket_token.as_ref().filter(|token| is_bitbucket_access_token(token)).cloned();
        let bitbucket_basic_password = bitbucket_app_password
            .clone()
            .or(bitbucket_token.clone())
            .or(bitbucket_password.clone());
        let bitbucket_basic_auth = if let Some(token) = bitbucket_oauth_token.clone() {
            Some(("x-token-auth".to_string(), token))
        } else if let Some(token) = bitbucket_access_token.clone() {
            Some(("x-token-auth".to_string(), token))
        } else if let (Some(username), Some(password)) =
            (bitbucket_username.clone(), bitbucket_basic_password.clone())
        {
            Some((username, password))
        } else if let Some(token) = bitbucket_token.clone() {
            // Allow token-only authentication (common for x-token-auth URLs).
            Some(("x-token-auth".to_string(), token))
        } else {
            None
        };
        let has_bitbucket_username = bitbucket_username.is_some();
        let has_bitbucket_password = bitbucket_app_password.is_some()
            || bitbucket_token.is_some()
            || bitbucket_password.is_some();
        let has_bitbucket_oauth_token = bitbucket_oauth_token.is_some();
        let has_bitbucket_credentials = has_bitbucket_oauth_token
            || bitbucket_access_token.is_some()
            || bitbucket_token.is_some()
            || (has_bitbucket_username && has_bitbucket_password);
        let has_azure_token = ["KF_AZURE_TOKEN", "KF_AZURE_PAT"]
            .iter()
            .any(|key| matches!(std::env::var(key), Ok(value) if !value.is_empty()));
        let has_huggingface_token =
            matches!(std::env::var("KF_HUGGINGFACE_TOKEN"), Ok(value) if !value.is_empty());

        // If credentials are provided via environment variables, clear existing helpers first.
        if has_github_token
            || has_gitlab_token
            || has_gitea_token
            || has_bitbucket_credentials
            || has_azure_token
            || has_huggingface_token
        {
            credentials.push("-c".into());
            credentials.push(r#"credential.helper="#.into());
        }

        // Install each provider's helper scoped to that provider's HTTPS
        // host(s). `git` consults a `credential.https://<host>.helper` entry
        // only for remotes matching that host, so a provider token is never
        // echoed to an unrelated (possibly attacker-controlled) clone target.
        let mut push_scoped = |hosts: &[String], snippet: &str| {
            for host in hosts {
                credentials.push("-c".into());
                credentials.push(format!("credential.https://{host}.helper={snippet}"));
            }
        };

        if has_github_token {
            push_scoped(&provider_hosts.github, GITHUB_CREDENTIAL_HELPER);
        }
        if has_gitlab_token {
            push_scoped(&provider_hosts.gitlab, GITLAB_CREDENTIAL_HELPER);
        }
        if has_gitea_token {
            push_scoped(&provider_hosts.gitea, GITEA_CREDENTIAL_HELPER);
        }
        if has_bitbucket_credentials {
            push_scoped(&provider_hosts.bitbucket, BITBUCKET_CREDENTIAL_HELPER);
        }
        if has_azure_token {
            push_scoped(&provider_hosts.azure, AZURE_CREDENTIAL_HELPER);
        }
        if has_huggingface_token {
            push_scoped(&provider_hosts.huggingface, HUGGINGFACE_CREDENTIAL_HELPER);
        }

        Self {
            credentials,
            ignore_certs,
            bitbucket_access_token,
            bitbucket_env,
            bitbucket_basic_auth,
        }
    }

    /// Create a basic `git` `Command` with environment variables set to
    /// limit config usage and (optionally) ignore certs. Includes credentials
    /// if GitHub, GitLab, or Bitbucket tokens are present.
    fn git(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
        cmd.env("GIT_CONFIG_NOSYSTEM", "1");
        cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
        cmd.env("GIT_TERMINAL_PROMPT", "0");
        if self.ignore_certs {
            cmd.env("GIT_SSL_NO_VERIFY", "1");
        }
        for (key, value) in &self.bitbucket_env {
            cmd.env(key, value);
        }
        if let Some(token) = &self.bitbucket_access_token {
            cmd.env("KF_BITBUCKET_ACCESS_TOKEN", token);
        }
        cmd.args(&self.credentials);
        cmd.stdin(Stdio::null());
        cmd
    }

    /// Helper to run the constructed `git` command and capture its output.
    ///
    /// Returns an error if the command fails or exits with a non-zero status.
    fn run_cmd(&self, mut cmd: Command) -> Result<(), GitError> {
        debug!("{cmd:#?}");
        let output: Output = cmd.output()?;
        if !output.status.success() {
            return Err(GitError::GitError {
                stdout: output.stdout,
                stderr: output.stderr,
                status: output.status,
            });
        }
        Ok(())
    }

    /// Update an existing bare or mirror clone by running `git remote update --prune`.
    ///
    /// * `repo_url`: The remote repository URL (only used for logging).
    /// * `output_dir`: The path to the existing bare/mirror clone.
    pub fn update_clone(&self, repo_url: &GitUrl, output_dir: &Path) -> Result<(), GitError> {
        let _span = debug_span!("git_update", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to update clone of {repo_url} at {}", output_dir.display());
        let mut cmd = self.git();
        if output_dir.join(".git").is_dir() {
            cmd.arg("-C");
            cmd.arg(output_dir);
        } else {
            cmd.arg("--git-dir");
            cmd.arg(output_dir);
        }
        cmd.arg("remote");
        cmd.arg("update");
        cmd.arg("--prune");
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }

    /// Create a fresh clone of the specified repository in either bare or mirror mode.
    ///
    /// * `repo_url`: The remote repository URL.
    /// * `output_dir`: Where to place the newly created clone.
    /// * `clone_mode`: Whether to clone as `--bare` or `--mirror`.
    pub fn create_fresh_clone(
        &self,
        repo_url: &GitUrl,
        output_dir: &Path,
        clone_mode: CloneMode,
    ) -> Result<(), GitError> {
        let _span = debug_span!("git_clone", "{repo_url} {}", output_dir.display()).entered();
        debug!("Attempting to create fresh clone of {} at {}", repo_url, output_dir.display());
        let mut cmd = self.git();
        cmd.arg("clone");
        if let Some(arg) = clone_mode.arg() {
            cmd.arg(arg);
        }
        cmd.arg("--quiet");
        cmd.arg("-c");
        cmd.arg("remote.origin.fetch=+refs/*:refs/remotes/origin/*");
        cmd.arg(self.repo_arg_for_clone(repo_url));
        cmd.arg(output_dir);
        debug!("{cmd:#?}");
        self.run_cmd(cmd)
    }

    fn repo_arg_for_clone(&self, repo_url: &GitUrl) -> String {
        if let Some((username, password)) = &self.bitbucket_basic_auth {
            if let Ok(mut url) = Url::parse(repo_url.as_str()) {
                let is_bitbucket = url
                    .host_str()
                    .map(|host| host.eq_ignore_ascii_case("bitbucket.org"))
                    .unwrap_or(false);
                // Embed credentials only on HTTPS bitbucket.org remotes. The
                // scoped credential helper is HTTPS-only for the same reason:
                // putting a token in a plaintext http:// URL would send it over
                // the wire in the clear.
                if url.scheme() == "https"
                    && is_bitbucket
                    && url.set_username(username).is_ok()
                    && url.set_password(Some(password)).is_ok()
                {
                    return url.into();
                }
            }
        }

        repo_url.as_str().to_string()
    }
}

impl Default for Git {
    /// Equivalent to `Git::new(false)`
    fn default() -> Self {
        Self::new(false)
    }
}

/// Represents how a repository is cloned.
#[derive(Debug, Clone, Copy)]
pub enum CloneMode {
    /// Equivalent to `git clone --bare`
    Bare,
    /// Equivalent to `git clone --mirror`
    Mirror,
    /// Standard clone with a working tree
    Checkout,
}

impl CloneMode {
    /// Return the CLI argument for this clone mode.
    pub fn arg(&self) -> Option<&str> {
        match self {
            Self::Bare => Some("--bare"),
            Self::Mirror => Some("--mirror"),
            Self::Checkout => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_git_new() {
        temp_env::with_vars(
            &[
                ("KF_GITHUB_TOKEN", None::<&str>),
                ("KF_BITBUCKET_OAUTH_TOKEN", None::<&str>),
                ("KF_BITBUCKET_ACCESS_TOKEN", None::<&str>),
                ("KF_BITBUCKET_USERNAME", None::<&str>),
                ("KF_BITBUCKET_APP_PASSWORD", None::<&str>),
            ],
            || {
                let git = Git::new(false);
                assert!(!git.ignore_certs);
                assert!(git.credentials.is_empty());
                assert!(git.bitbucket_access_token.is_none());
            },
        );

        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
        });
    }

    #[test]
    fn test_git_new_bitbucket_oauth() {
        temp_env::with_var("KF_BITBUCKET_OAUTH_TOKEN", Some("oauth"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
            assert!(git.credentials.iter().any(|value| value
                == &format!(
                    "credential.https://bitbucket.org.helper={BITBUCKET_CREDENTIAL_HELPER}"
                )));
            assert!(git.bitbucket_access_token.is_none());
        });
    }

    #[test]
    fn test_git_new_bitbucket_basic_auth() {
        temp_env::with_vars(
            &[
                ("KF_BITBUCKET_USERNAME", Some("user")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("password")),
            ],
            || {
                let git = Git::new(false);
                assert_eq!(git.credentials.len(), 4);
                assert!(git.credentials.iter().any(|value| value
                    == &format!(
                        "credential.https://bitbucket.org.helper={BITBUCKET_CREDENTIAL_HELPER}"
                    )));
                assert!(git.bitbucket_access_token.is_none());
            },
        );
    }

    #[test]
    fn test_repo_arg_for_clone_includes_bitbucket_app_password() {
        let url =
            GitUrl::try_from(url::Url::parse("https://bitbucket.org/workspace/demo.git").unwrap())
                .unwrap();

        temp_env::with_vars(
            &[
                ("KF_BITBUCKET_USERNAME", Some("user")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("secret")),
            ],
            || {
                let git = Git::new(false);
                assert_eq!(
                    git.repo_arg_for_clone(&url),
                    "https://user:secret@bitbucket.org/workspace/demo.git"
                );
            },
        );
    }

    #[test]
    fn test_repo_arg_for_clone_uses_token_auth_when_available() {
        let url =
            GitUrl::try_from(url::Url::parse("https://bitbucket.org/workspace/demo.git").unwrap())
                .unwrap();

        temp_env::with_vars(&[("KF_BITBUCKET_OAUTH_TOKEN", Some("token123"))], || {
            let git = Git::new(false);
            assert_eq!(
                git.repo_arg_for_clone(&url),
                "https://x-token-auth:token123@bitbucket.org/workspace/demo.git"
            );
        });
    }

    #[test]
    fn test_repo_arg_for_clone_uses_token_only_auth() {
        let url =
            GitUrl::try_from(url::Url::parse("https://bitbucket.org/workspace/demo.git").unwrap())
                .unwrap();

        temp_env::with_vars(&[("KF_BITBUCKET_TOKEN", Some("token123"))], || {
            let git = Git::new(false);
            assert_eq!(
                git.repo_arg_for_clone(&url),
                "https://x-token-auth:token123@bitbucket.org/workspace/demo.git"
            );
        });
    }

    #[test]
    fn test_repo_arg_for_clone_skips_plaintext_http_bitbucket() {
        // A plaintext http:// bitbucket.org remote must NOT receive embedded
        // credentials — that would leak the token over the wire and bypass the
        // HTTPS-only credential-helper scoping.
        let url =
            GitUrl::try_from(url::Url::parse("http://bitbucket.org/workspace/demo.git").unwrap())
                .unwrap();

        temp_env::with_vars(&[("KF_BITBUCKET_OAUTH_TOKEN", Some("token123"))], || {
            let git = Git::new(false);
            assert_eq!(git.repo_arg_for_clone(&url), url.as_str());
        });
    }

    #[test]
    fn test_repo_arg_for_clone_leaves_non_bitbucket_urls_untouched() {
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();

        temp_env::with_vars(
            &[
                ("KF_BITBUCKET_USERNAME", Some("user")),
                ("KF_BITBUCKET_APP_PASSWORD", Some("secret")),
            ],
            || {
                let git = Git::new(false);
                assert_eq!(git.repo_arg_for_clone(&url), url.as_str());
            },
        );
    }

    #[test]
    fn test_git_new_bitbucket_access_token() {
        let token = "AT1234567890_ACCESS_TOKEN_EXAMPLE_WITH_UNDERSCORE";
        temp_env::with_var("KF_BITBUCKET_TOKEN", Some(token), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
            assert!(git.credentials.iter().any(|value| value
                == &format!(
                    "credential.https://bitbucket.org.helper={BITBUCKET_CREDENTIAL_HELPER}"
                )));
            assert_eq!(git.bitbucket_access_token.as_deref(), Some(token));
        });
    }

    #[test]
    fn test_git_new_bitbucket_token_without_username() {
        temp_env::with_var("KF_BITBUCKET_TOKEN", Some("token123"), || {
            let git = Git::new(false);
            assert_eq!(git.credentials.len(), 4);
            assert!(git.credentials.iter().any(|value| value
                == &format!(
                    "credential.https://bitbucket.org.helper={BITBUCKET_CREDENTIAL_HELPER}"
                )));
            assert_eq!(git.bitbucket_access_token.as_deref(), None);
            assert_eq!(
                git.bitbucket_basic_auth,
                Some(("x-token-auth".to_string(), "token123".to_string()))
            );
        });
    }

    #[test]
    fn test_git_new_bitbucket_trims_whitespace() {
        let trimmed_token = "AT1234567890_ACCESS_TOKEN_EXAMPLE_WITH_UNDERSCORE";
        let token = format!("  {trimmed_token}  \n");

        temp_env::with_vars(
            &[("KF_BITBUCKET_USERNAME", Some("  user\n")), ("KF_BITBUCKET_TOKEN", Some(&token))],
            || {
                let git = Git::new(false);

                assert_eq!(
                    git.bitbucket_env,
                    vec![
                        ("KF_BITBUCKET_USERNAME".to_string(), "user".to_string()),
                        ("KF_BITBUCKET_TOKEN".to_string(), trimmed_token.to_string(),),
                    ],
                );
                assert_eq!(git.credentials.len(), 4);
                assert!(git.credentials.iter().any(|value| value
                    == &format!(
                        "credential.https://bitbucket.org.helper={BITBUCKET_CREDENTIAL_HELPER}"
                    )));
                assert_eq!(git.bitbucket_access_token.as_deref(), Some(trimmed_token));
            },
        );
    }

    #[test]
    fn test_clone_mode_arg() {
        assert_eq!(CloneMode::Bare.arg(), Some("--bare"));
        assert_eq!(CloneMode::Mirror.arg(), Some("--mirror"));
        assert_eq!(CloneMode::Checkout.arg(), None);
    }

    #[test]
    fn test_create_fresh_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        assert!(temp_dir.path().join("HEAD").exists());
        Ok(())
    }

    #[test]
    fn test_update_clone() -> Result<(), GitError> {
        let temp_dir = TempDir::new()?;
        let git = Git::default();
        let url = GitUrl::try_from(
            url::Url::parse("https://github.com/octocat/Hello-World.git").unwrap(),
        )
        .unwrap();
        git.create_fresh_clone(&url, temp_dir.path(), CloneMode::Bare)?;
        git.update_clone(&url, temp_dir.path())?;
        Ok(())
    }

    #[test]
    fn test_git_error() {
        let temp_dir = TempDir::new().unwrap();
        let git = Git::default();
        let invalid_url =
            GitUrl::try_from(url::Url::parse("https://invalid.git").unwrap()).unwrap();
        let err =
            git.create_fresh_clone(&invalid_url, temp_dir.path(), CloneMode::Bare).unwrap_err();
        assert!(matches!(err, GitError::GitError { .. }));
    }

    #[test]
    fn github_helper_is_scoped_to_provider_host_only() {
        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::new(false);

            // The only bare `credential.helper=` entry is the empty reset that
            // clears inherited helpers. The token-bearing helper must never be
            // installed unscoped — an unscoped helper is what leaked provider
            // tokens to any remote that issued an auth challenge.
            let unscoped: Vec<&String> = git
                .credentials
                .iter()
                .filter(|value| value.starts_with("credential.helper="))
                .collect();
            assert_eq!(unscoped, vec![&"credential.helper=".to_string()]);

            // The GitHub helper is bound to https://github.com.
            assert!(git.credentials.iter().any(|value| value
                == &format!("credential.https://github.com.helper={GITHUB_CREDENTIAL_HELPER}")));

            // No credential entry targets an unrelated/attacker host.
            assert!(!git.credentials.iter().any(|value| value.contains("127.0.0.1")));
        });
    }

    #[test]
    fn provider_helper_scoped_to_each_configured_host() {
        let hosts = ProviderHosts {
            github: vec!["github.com".to_string(), "ghe.corp.example.com".to_string()],
            ..ProviderHosts::default()
        };
        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::with_provider_hosts(false, &hosts);
            assert!(git.credentials.iter().any(|value| value
                == &format!("credential.https://github.com.helper={GITHUB_CREDENTIAL_HELPER}")));
            assert!(git.credentials.iter().any(|value| value
                == &format!(
                    "credential.https://ghe.corp.example.com.helper={GITHUB_CREDENTIAL_HELPER}"
                )));
        });
    }

    #[test]
    fn no_helper_installed_for_provider_without_trusted_host() {
        // An empty host list means the token has nowhere safe to go: no helper
        // is installed, so the token cannot leak even to its own SaaS host.
        let hosts = ProviderHosts { github: Vec::new(), ..ProviderHosts::default() };
        temp_env::with_var("KF_GITHUB_TOKEN", Some("test_token"), || {
            let git = Git::with_provider_hosts(false, &hosts);
            assert!(!git.credentials.iter().any(|value| value.contains("_ghcreds")));
        });
    }
}
