//! Native, non-interactive provider credentials for Git HTTP transports.
//!
//! Always install [`GitAuth::credentials`] on **every** clone/fetch connection, including when no
//! provider token is configured. Falling back to gix's configured credentials can execute local
//! `credential.helper` programs (including `git credential`) or an askpass program. Store/erase
//! notifications are deliberately ignored, and credentials must never be embedded in remote URLs.
//!
//! Repository opening must separately disable system, user/global, and Git-installation config.
//! `gix::open::Options::isolated()` additionally disables environment configuration and includes;
//! retaining those for compatibility requires explicit `open::Permissions` instead. Likewise, do
//! not retain the default `proxy_authenticate` callback from `Repository::transport_options`: it
//! can invoke configured helpers independently of this connection's credentials callback.
//!
//! This is intentionally HTTPS-only. SSH authentication would require a separate SSH transport
//! (gix normally executes an external SSH client), not conversion of KF tokens into SSH secrets.
//! External credential helpers and interactive prompting are intentionally not fallback mechanisms.

use std::fmt;

use gix::credentials::{
    helper::Action,
    protocol::{Context, Outcome},
};
use url::Url;

use crate::{bitbucket::is_bitbucket_access_token, git_binary::ProviderHosts};

/// A snapshot of KF credentials and the exact HTTPS authorities allowed to receive them.
///
/// No helper subprocesses, prompts, environment changes, disk writes, or secret-bearing logging
/// occur here. A custom redacted `Debug` implementation prevents accidentally logging the snapshot.
#[derive(Clone, Default)]
pub(crate) struct GitAuth {
    credentials: Vec<Credential>,
}

#[derive(Clone)]
struct Credential {
    authority: Authority,
    username: String,
    password: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Authority {
    host: String,
    port: u16,
}

impl Authority {
    fn from_url(raw: &str) -> Option<Self> {
        // Avoid URL-parser recovery and disagreement between Git URL parsing and the HTTP backend.
        if raw.bytes().any(|b| b.is_ascii_control() || b == b'\\')
            || raw.trim() != raw
            || !raw.get(..8)?.eq_ignore_ascii_case("https://")
            || raw.get(8..)?.starts_with('/')
        {
            return None;
        }
        let url = Url::parse(raw).ok()?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return None;
        }
        Some(Self {
            host: url.host_str()?.to_ascii_lowercase(),
            port: url.port_or_known_default()?,
        })
    }

    fn from_host(host: &str) -> Option<Self> {
        // Trusted configuration consists of a host and optional port, not URL patterns, suffixes,
        // paths, userinfo, or URL rewrite destinations. Reject all of those rather than widening
        // the destinations allowed to receive a provider's secret.
        if host.is_empty()
            || host.bytes().any(|b| {
                b.is_ascii_whitespace()
                    || b.is_ascii_control()
                    || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#' | b'*' | b'%')
            })
        {
            return None;
        }
        Self::from_url(&format!("https://{host}/"))
    }

    fn from_context(context: &Context) -> Option<Self> {
        let from_components = || {
            context.protocol.as_deref()?.eq_ignore_ascii_case("https").then_some(())?;
            Self::from_host(context.host.as_deref()?)
        };
        match &context.url {
            Some(raw) => {
                let authority = Self::from_url(std::str::from_utf8(raw.as_ref()).ok()?)?;
                // The transport normally supplies only `url`. If supplied independently, protocol
                // and host must agree with it; neither field may bless an untrusted other field.
                if context
                    .protocol
                    .as_deref()
                    .is_some_and(|protocol| !protocol.eq_ignore_ascii_case("https"))
                    || context
                        .host
                        .as_deref()
                        .is_some_and(|host| Self::from_host(host).as_ref() != Some(&authority))
                {
                    return None;
                }
                Some(authority)
            }
            None => from_components(),
        }
    }

    fn host_with_port(&self) -> String {
        if self.port == 443 { self.host.clone() } else { format!("{}:{}", self.host, self.port) }
    }
}

impl fmt::Debug for GitAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitAuth")
            .field("configured_authorities", &self.credentials.len())
            .finish_non_exhaustive()
    }
}

impl GitAuth {
    /// Read a stable snapshot of the process environment. GitHub and Bitbucket normalize outer
    /// whitespace as before; other providers preserve their existing raw-value behavior.
    pub(crate) fn from_env(hosts: &ProviderHosts) -> Self {
        Self::from_lookup(hosts, None, |name| std::env::var(name).ok())
    }

    /// Use an explicit GitHub App installation token instead of `KF_GITHUB_TOKEN`.
    ///
    /// `None` deliberately suppresses the environment's GitHub token; an explicit token is used
    /// verbatim. Other providers remain available according to their own environment variables.
    pub(crate) fn with_github_token(hosts: &ProviderHosts, github_token: Option<String>) -> Self {
        Self::from_lookup(hosts, Some(github_token), |name| std::env::var(name).ok())
    }

    fn from_lookup(
        hosts: &ProviderHosts,
        github_override: Option<Option<String>>,
        mut env: impl FnMut(&str) -> Option<String>,
    ) -> Self {
        fn nonempty(value: Option<String>) -> Option<String> {
            value.filter(|value| !value.is_empty())
        }
        fn normalized(value: Option<String>) -> Option<String> {
            nonempty(value.map(|value| value.trim().to_owned()))
        }
        fn username(value: Option<String>, default: &str) -> String {
            nonempty(value).unwrap_or_else(|| default.to_owned())
        }

        let mut auth = Self::default();
        let github_token = github_override.unwrap_or_else(|| normalized(env("KF_GITHUB_TOKEN")));
        // Provider order preserves the former helper cascade when multiple providers share an
        // explicitly trusted authority: the first complete identity wins, without merging secrets.
        auth.add(&hosts.github, github_token.map(|token| ("x-access-token".to_owned(), token)));
        auth.add(
            &hosts.gitlab,
            nonempty(env("KF_GITLAB_TOKEN")).map(|token| ("oauth2".to_owned(), token)),
        );
        let gitea_token = nonempty(env("KF_GITEA_TOKEN"));
        let gitea_username = username(env("KF_GITEA_USERNAME"), "gitea");
        auth.add(&hosts.gitea, gitea_token.map(|token| (gitea_username, token)));

        let bb_username = normalized(env("KF_BITBUCKET_USERNAME"));
        let bb_app_password = normalized(env("KF_BITBUCKET_APP_PASSWORD"));
        let bb_token = normalized(env("KF_BITBUCKET_TOKEN"));
        let bb_password = normalized(env("KF_BITBUCKET_PASSWORD"));
        let bb_oauth = normalized(env("KF_BITBUCKET_OAUTH_TOKEN"));
        let bb_access = bb_token.as_ref().filter(|token| is_bitbucket_access_token(token)).cloned();
        let bb_basic_password = bb_app_password.or_else(|| bb_token.clone()).or(bb_password);
        let bb_identity = bb_oauth
            .or(bb_access)
            .map(|token| ("x-token-auth".to_owned(), token))
            .or_else(|| bb_username.zip(bb_basic_password))
            .or_else(|| bb_token.map(|token| ("x-token-auth".to_owned(), token)));
        auth.add(&hosts.bitbucket, bb_identity);

        let azure_token = nonempty(env("KF_AZURE_TOKEN")).or_else(|| nonempty(env("KF_AZURE_PAT")));
        let azure_username = username(env("KF_AZURE_USERNAME"), "pat");
        auth.add(&hosts.azure, azure_token.map(|token| (azure_username, token)));
        let hf_token = nonempty(env("KF_HUGGINGFACE_TOKEN"));
        let hf_username = username(env("KF_HUGGINGFACE_USERNAME"), "hf_user");
        auth.add(&hosts.huggingface, hf_token.map(|token| (hf_username, token)));
        auth
    }

    fn add(&mut self, hosts: &[String], identity: Option<(String, String)>) {
        let Some((username, password)) = identity else { return };
        for host in hosts {
            if let Some(authority) = Authority::from_host(host.trim()) {
                self.credentials.push(Credential {
                    authority,
                    username: username.clone(),
                    password: password.clone(),
                });
            }
        }
    }

    /// Native gix callback. Return no identity for plaintext, wrong-host/port, or unsupported
    /// contexts; never consult a credential helper or terminal, even when no KF token is present.
    pub(crate) fn credentials(&self, action: Action) -> gix::Result<Option<Outcome>> {
        let Action::Get(context) = action else {
            // Approval and rejection are advisory, never persistence requests for KF tokens.
            return Ok(None);
        };
        let Some(authority) = Authority::from_context(&context) else { return Ok(None) };
        let Some(credential) =
            self.credentials.iter().find(|credential| credential.authority == authority)
        else {
            return Ok(None);
        };
        // Do not serialize input URL/path/userinfo or either identity secret into NextAction.
        // Store/Erase are ignored anyway, but a redacted handle also avoids secret-bearing payloads
        // escaping to callers or future persistence implementations.
        let next = Context {
            protocol: Some("https".to_owned()),
            host: Some(authority.host_with_port()),
            ..Context::default()
        }
        .into();
        Ok(Some(Outcome {
            identity: gix::sec::identity::Account {
                username: credential.username.clone(),
                password: credential.password.clone(),
                oauth_refresh_token: None,
            },
            next,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const ACCESS_TOKEN: &str = "AT0123456789012345678901234567890123456789_access";

    fn auth(hosts: &ProviderHosts, env: &[(&str, &str)]) -> GitAuth {
        GitAuth::from_lookup(hosts, None, lookup(env))
    }

    fn lookup<'a>(env: &'a [(&'a str, &'a str)]) -> impl FnMut(&str) -> Option<String> + 'a {
        let values: BTreeMap<_, _> = env.iter().copied().collect();
        move |name| values.get(name).map(|value| (*value).to_owned())
    }

    fn identity(auth: &GitAuth, url: &str) -> Option<(String, String)> {
        auth.credentials(Action::get_for_url(url))
            .expect("the native callback does not invoke fallible helpers")
            .map(|outcome| (outcome.identity.username, outcome.identity.password))
    }

    #[test]
    fn characterize_provider_usernames_and_secrets() {
        // These are the observable identities selected by the former provider helpers, rather
        // than assertions about shell snippets, command arguments, or configuration structure.
        for (url, env, expected) in [
            (
                "https://github.com/org/repo",
                vec![("KF_GITHUB_TOKEN", " gh-token ")],
                ("x-access-token", "gh-token"),
            ),
            (
                "https://gitlab.com/org/repo",
                vec![("KF_GITLAB_TOKEN", "gl-token")],
                ("oauth2", "gl-token"),
            ),
            (
                "https://gitea.com/org/repo",
                vec![("KF_GITEA_TOKEN", "gitea-token")],
                ("gitea", "gitea-token"),
            ),
            (
                "https://gitea.com/org/repo",
                vec![("KF_GITEA_TOKEN", "gitea-token"), ("KF_GITEA_USERNAME", "scanner")],
                ("scanner", "gitea-token"),
            ),
            (
                "https://dev.azure.com/org/repo",
                vec![("KF_AZURE_TOKEN", "azure-token")],
                ("pat", "azure-token"),
            ),
            (
                "https://dev.azure.com/org/repo",
                vec![("KF_AZURE_PAT", "azure-pat"), ("KF_AZURE_USERNAME", "scanner")],
                ("scanner", "azure-pat"),
            ),
            (
                "https://huggingface.co/org/repo",
                vec![("KF_HUGGINGFACE_TOKEN", "hf-token")],
                ("hf_user", "hf-token"),
            ),
            (
                "https://huggingface.co/org/repo",
                vec![("KF_HUGGINGFACE_TOKEN", "hf-token"), ("KF_HUGGINGFACE_USERNAME", "scanner")],
                ("scanner", "hf-token"),
            ),
        ] {
            assert_eq!(
                identity(&auth(&ProviderHosts::saas_defaults(), &env), url),
                Some((expected.0.to_owned(), expected.1.to_owned())),
                "{url}"
            );
        }
    }

    #[test]
    fn explicit_github_app_token_replaces_or_suppresses_environment_token() {
        let hosts = ProviderHosts::saas_defaults();
        let env = [("KF_GITHUB_TOKEN", "environment-token"), ("KF_GITLAB_TOKEN", "gitlab-token")];
        for (token, expected) in [
            (Some("fresh-installation-token"), Some("fresh-installation-token")),
            (Some("  explicit-is-verbatim  "), Some("  explicit-is-verbatim  ")),
            (Some(""), Some("")),
            (None, None),
        ] {
            let auth = GitAuth::from_lookup(&hosts, Some(token.map(str::to_owned)), lookup(&env));
            assert_eq!(
                identity(&auth, "https://github.com/org/repo"),
                expected.map(|secret| ("x-access-token".to_owned(), secret.to_owned()))
            );
            assert_eq!(
                identity(&auth, "https://gitlab.com/org/repo"),
                Some(("oauth2".to_owned(), "gitlab-token".to_owned()))
            );
        }
    }

    #[test]
    fn absent_and_empty_tokens_do_not_enable_credentials() {
        let hosts = ProviderHosts::saas_defaults();
        for env in [
            vec![],
            vec![
                ("KF_GITHUB_TOKEN", " \t "),
                ("KF_GITLAB_TOKEN", ""),
                ("KF_GITEA_TOKEN", ""),
                ("KF_BITBUCKET_TOKEN", " \t "),
                ("KF_AZURE_TOKEN", ""),
                ("KF_AZURE_PAT", ""),
                ("KF_HUGGINGFACE_TOKEN", ""),
            ],
            vec![
                ("KF_GITEA_USERNAME", "scanner"),
                ("KF_BITBUCKET_USERNAME", "scanner"),
                ("KF_AZURE_USERNAME", "scanner"),
                ("KF_HUGGINGFACE_USERNAME", "scanner"),
            ],
        ] {
            let auth = auth(&hosts, &env);
            for host in [
                "github.com",
                "gitlab.com",
                "gitea.com",
                "bitbucket.org",
                "dev.azure.com",
                "huggingface.co",
            ] {
                assert_eq!(identity(&auth, &format!("https://{host}/org/repo")), None);
            }
        }
    }

    #[test]
    fn provider_raw_whitespace_and_empty_username_fallbacks_are_preserved() {
        let hosts = ProviderHosts::saas_defaults();
        for (url, token_name, username_name, default) in [
            ("https://gitea.com/repo", "KF_GITEA_TOKEN", "KF_GITEA_USERNAME", "gitea"),
            ("https://dev.azure.com/repo", "KF_AZURE_TOKEN", "KF_AZURE_USERNAME", "pat"),
            (
                "https://huggingface.co/repo",
                "KF_HUGGINGFACE_TOKEN",
                "KF_HUGGINGFACE_USERNAME",
                "hf_user",
            ),
        ] {
            for user in [None, Some(""), Some("  custom user  "), Some(" ")] {
                let mut env = vec![(token_name, "  token  ")];
                if let Some(user) = user {
                    env.push((username_name, user));
                }
                let expected_user = user.filter(|user| !user.is_empty()).unwrap_or(default);
                assert_eq!(
                    identity(&auth(&hosts, &env), url),
                    Some((expected_user.to_owned(), "  token  ".to_owned()))
                );
            }
        }
        assert_eq!(
            identity(&auth(&hosts, &[("KF_GITLAB_TOKEN", "  token  ")]), "https://gitlab.com/repo"),
            Some(("oauth2".to_owned(), "  token  ".to_owned()))
        );
    }

    #[test]
    fn azure_primary_token_precedes_pat_but_empty_primary_falls_back() {
        let hosts = ProviderHosts::saas_defaults();
        for token in [None, Some(""), Some(" "), Some("token")] {
            for pat in [None, Some(""), Some(" "), Some("pat-token")] {
                let mut env = Vec::new();
                if let Some(token) = token {
                    env.push(("KF_AZURE_TOKEN", token));
                }
                if let Some(pat) = pat {
                    env.push(("KF_AZURE_PAT", pat));
                }
                let expected = token
                    .filter(|value| !value.is_empty())
                    .or(pat.filter(|value| !value.is_empty()));
                assert_eq!(
                    identity(&auth(&hosts, &env), "https://dev.azure.com/repo"),
                    expected.map(|token| ("pat".to_owned(), token.to_owned()))
                );
            }
        }
    }

    #[test]
    fn characterize_bitbucket_precedence() {
        // OAuth > detected workspace/access token > username+(app-password > token > password)
        // > token alone. The former clone URL construction selected this identity, even though
        // its challenge helper omitted the ordinary token-only fallback. Both native clone and
        // fetch must now use the same identity without persisting it in a URL.
        let cases = [
            (
                vec![
                    ("KF_BITBUCKET_OAUTH_TOKEN", "oauth"),
                    ("KF_BITBUCKET_TOKEN", ACCESS_TOKEN),
                    ("KF_BITBUCKET_USERNAME", "scanner"),
                    ("KF_BITBUCKET_APP_PASSWORD", "app"),
                    ("KF_BITBUCKET_PASSWORD", "password"),
                ],
                Some(("x-token-auth", "oauth")),
            ),
            (
                vec![
                    ("KF_BITBUCKET_TOKEN", ACCESS_TOKEN),
                    ("KF_BITBUCKET_USERNAME", "scanner"),
                    ("KF_BITBUCKET_APP_PASSWORD", "app"),
                    ("KF_BITBUCKET_PASSWORD", "password"),
                ],
                Some(("x-token-auth", ACCESS_TOKEN)),
            ),
            (
                vec![
                    ("KF_BITBUCKET_USERNAME", "scanner"),
                    ("KF_BITBUCKET_APP_PASSWORD", "app"),
                    ("KF_BITBUCKET_TOKEN", "token"),
                    ("KF_BITBUCKET_PASSWORD", "password"),
                ],
                Some(("scanner", "app")),
            ),
            (
                vec![
                    ("KF_BITBUCKET_USERNAME", "scanner"),
                    ("KF_BITBUCKET_TOKEN", "token"),
                    ("KF_BITBUCKET_PASSWORD", "password"),
                ],
                Some(("scanner", "token")),
            ),
            (
                vec![("KF_BITBUCKET_USERNAME", "scanner"), ("KF_BITBUCKET_PASSWORD", "password")],
                Some(("scanner", "password")),
            ),
            (vec![("KF_BITBUCKET_TOKEN", "token")], Some(("x-token-auth", "token"))),
            (
                vec![("KF_BITBUCKET_TOKEN", "token"), ("KF_BITBUCKET_APP_PASSWORD", "app")],
                Some(("x-token-auth", "token")),
            ),
            (vec![("KF_BITBUCKET_APP_PASSWORD", "app")], None),
            (vec![("KF_BITBUCKET_PASSWORD", "password")], None),
            (vec![("KF_BITBUCKET_USERNAME", "scanner")], None),
            (vec![], None),
        ];
        for (env, expected) in cases {
            assert_eq!(
                identity(
                    &auth(&ProviderHosts::saas_defaults(), &env),
                    "https://bitbucket.org/org/repo"
                ),
                expected.map(|(user, secret)| (user.to_owned(), secret.to_owned()))
            );
        }
    }

    #[test]
    fn bitbucket_all_combinations_choose_one_complete_identity() {
        let hosts = ProviderHosts::saas_defaults();
        for mask in 0u8..16 {
            for token in [None, Some("ordinary-token"), Some(ACCESS_TOKEN)] {
                let username = (mask & 1 != 0).then_some("scanner");
                let app = (mask & 2 != 0).then_some("app");
                let password = (mask & 4 != 0).then_some("password");
                let oauth = (mask & 8 != 0).then_some("oauth");
                let env: Vec<_> = [
                    ("KF_BITBUCKET_USERNAME", username),
                    ("KF_BITBUCKET_APP_PASSWORD", app),
                    ("KF_BITBUCKET_TOKEN", token),
                    ("KF_BITBUCKET_PASSWORD", password),
                    ("KF_BITBUCKET_OAUTH_TOKEN", oauth),
                ]
                .into_iter()
                .filter_map(|(name, value)| value.map(|value| (name, value)))
                .collect();
                let expected = if let Some(oauth) = oauth {
                    Some(("x-token-auth", oauth))
                } else if token == Some(ACCESS_TOKEN) {
                    Some(("x-token-auth", ACCESS_TOKEN))
                } else if let (Some(username), Some(password)) =
                    (username, app.or(token).or(password))
                {
                    Some((username, password))
                } else {
                    token.map(|token| ("x-token-auth", token))
                };
                assert_eq!(
                    identity(&auth(&hosts, &env), "https://bitbucket.org/repo"),
                    expected.map(|(username, password)| (username.to_owned(), password.to_owned())),
                    "combination {mask}, token kind {}",
                    if token == Some(ACCESS_TOKEN) { "access" } else { "ordinary/missing" }
                );
            }
        }
    }

    #[test]
    fn bitbucket_whitespace_normalization_precedes_selection() {
        let hosts = ProviderHosts::saas_defaults();
        let env = [
            ("KF_BITBUCKET_USERNAME", " scanner "),
            ("KF_BITBUCKET_APP_PASSWORD", " \t "),
            ("KF_BITBUCKET_TOKEN", " token "),
            ("KF_BITBUCKET_PASSWORD", " password "),
            ("KF_BITBUCKET_OAUTH_TOKEN", " \t "),
        ];
        assert_eq!(
            identity(&auth(&hosts, &env), "https://bitbucket.org/repo"),
            Some(("scanner".to_owned(), "token".to_owned()))
        );
        let env = [("KF_BITBUCKET_USERNAME", " \t "), ("KF_BITBUCKET_TOKEN", " token ")];
        assert_eq!(
            identity(&auth(&hosts, &env), "https://bitbucket.org/repo"),
            Some(("x-token-auth".to_owned(), "token".to_owned()))
        );
    }

    #[test]
    fn bitbucket_access_token_shape_boundary_is_unchanged() {
        let hosts = ProviderHosts::saas_defaults();
        for (token, recognized) in [
            (format!("AT_{}", "x".repeat(37)), false), // Exactly 40 bytes.
            (format!("AT_{}", "x".repeat(38)), true),
            (format!("AT{}", "x".repeat(50)), false),
            (format!("at_{}", "x".repeat(50)), false),
            (format!("BT_{}", "x".repeat(50)), false),
            (format!("AT{}_", "x".repeat(38)), true),
        ] {
            let env = [
                ("KF_BITBUCKET_TOKEN", token.as_str()),
                ("KF_BITBUCKET_USERNAME", "scanner"),
                ("KF_BITBUCKET_APP_PASSWORD", "app"),
            ];
            let expected =
                if recognized { ("x-token-auth", token.as_str()) } else { ("scanner", "app") };
            assert_eq!(
                identity(&auth(&hosts, &env), "https://bitbucket.org/repo"),
                Some((expected.0.to_owned(), expected.1.to_owned()))
            );
        }
    }

    fn all_tokens() -> Vec<(&'static str, &'static str)> {
        vec![
            ("KF_GITHUB_TOKEN", "gh-secret"),
            ("KF_GITLAB_TOKEN", "gl-secret"),
            ("KF_GITEA_TOKEN", "gitea-secret"),
            ("KF_BITBUCKET_TOKEN", "bb-secret"),
            ("KF_AZURE_TOKEN", "azure-secret"),
            ("KF_HUGGINGFACE_TOKEN", "hf-secret"),
        ]
    }

    #[test]
    fn every_provider_is_scoped_to_exact_https_host_and_effective_port() {
        let hosts = ProviderHosts::saas_defaults();
        let auth = auth(&hosts, &all_tokens());
        for (host, secret) in [
            ("github.com", "gh-secret"),
            ("gitlab.com", "gl-secret"),
            ("gitea.com", "gitea-secret"),
            ("bitbucket.org", "bb-secret"),
            ("dev.azure.com", "azure-secret"),
            ("huggingface.co", "hf-secret"),
        ] {
            for url in [
                format!("https://{host}/org/repo"),
                format!("https://{host}:443/org/repo"),
                format!("HTTPS://{}/org/repo", host.to_ascii_uppercase()),
            ] {
                assert_eq!(identity(&auth, &url).unwrap().1, secret);
            }
            for url in [
                format!("http://{host}/org/repo"),
                format!("http://{host}:443/org/repo"),
                format!("https://{host}:80/org/repo"),
                format!("https://{host}:444/org/repo"),
                format!("https://sub.{host}/org/repo"),
                format!("https://{host}.attacker.test/org/repo"),
                format!("https://{host}@attacker.test/org/repo"),
                format!("https://{host}./org/repo"),
            ] {
                assert_eq!(identity(&auth, &url), None, "credentials escaped to {url}");
            }
        }
    }

    #[test]
    fn enterprise_provider_hosts_do_not_cross_provider_or_port_boundaries() {
        let hosts = ProviderHosts {
            github: vec!["GH.CORP.EXAMPLE:8443".to_owned()],
            gitlab: vec!["gl.corp.example:8444".to_owned()],
            gitea: vec!["gitea.corp.example:8445".to_owned()],
            bitbucket: vec!["bb.corp.example:8446".to_owned()],
            azure: vec!["azure.corp.example:8447".to_owned()],
            huggingface: vec!["hf.corp.example:8448".to_owned()],
        };
        let auth = auth(&hosts, &all_tokens());
        for (host, port, secret) in [
            ("gh.corp.example", 8443, "gh-secret"),
            ("gl.corp.example", 8444, "gl-secret"),
            ("gitea.corp.example", 8445, "gitea-secret"),
            ("bb.corp.example", 8446, "bb-secret"),
            ("azure.corp.example", 8447, "azure-secret"),
            ("hf.corp.example", 8448, "hf-secret"),
        ] {
            assert_eq!(identity(&auth, &format!("https://{host}:{port}/repo")).unwrap().1, secret);
            assert_eq!(identity(&auth, &format!("https://{host}/repo")), None);
            assert_eq!(identity(&auth, &format!("https://{host}:{}/repo", port + 1)), None);
        }
        for host in [
            "github.com",
            "gitlab.com",
            "gitea.com",
            "bitbucket.org",
            "dev.azure.com",
            "huggingface.co",
        ] {
            assert_eq!(identity(&auth, &format!("https://{host}/repo")), None);
        }
    }

    #[test]
    fn empty_host_lists_never_offer_even_bitbucket_credentials() {
        let auth = auth(&ProviderHosts::default(), &all_tokens());
        for host in [
            "github.com",
            "gitlab.com",
            "gitea.com",
            "bitbucket.org",
            "dev.azure.com",
            "huggingface.co",
        ] {
            assert_eq!(identity(&auth, &format!("https://{host}/repo")), None);
        }
    }

    #[test]
    fn ipv4_ipv6_and_explicit_default_ports_are_exact_authorities() {
        let hosts = ProviderHosts {
            github: vec![
                "127.0.0.1:8443".to_owned(),
                "[::1]:8444".to_owned(),
                "default.example:443".to_owned(),
            ],
            ..ProviderHosts::default()
        };
        let auth = auth(&hosts, &[("KF_GITHUB_TOKEN", "secret")]);
        for url in [
            "https://127.0.0.1:8443/repo",
            "https://[::1]:8444/repo",
            "https://default.example/repo",
            "https://default.example:443/repo",
        ] {
            assert!(identity(&auth, url).is_some(), "{url}");
        }
        for url in [
            "https://127.0.0.1/repo",
            "https://127.0.0.2:8443/repo",
            "https://[::1]/repo",
            "https://[::2]:8444/repo",
            "https://default.example:8443/repo",
        ] {
            assert_eq!(identity(&auth, url), None, "{url}");
        }
    }

    #[test]
    fn malformed_trusted_hosts_never_become_url_patterns_or_userinfo() {
        for host in [
            "",
            "*",
            "*.github.com",
            "github.com/path",
            "github.com/",
            "github.com?x=y",
            "github.com#fragment",
            "evil@github.com",
            "github.com@evil",
            "github.com\\evil",
            "git\nhub.com",
            "github.com:65536",
            "https://github.com",
            "github%2ecom",
            "github.com:443@evil",
        ] {
            let hosts = ProviderHosts { github: vec![host.to_owned()], ..ProviderHosts::default() };
            let auth = auth(&hosts, &[("KF_GITHUB_TOKEN", "secret")]);
            assert!(auth.credentials.is_empty(), "accepted invalid trusted host");
            assert_eq!(identity(&auth, "https://github.com/repo"), None);
            assert_eq!(identity(&auth, "https://evil/repo"), None);
        }
    }

    #[test]
    fn malformed_remote_urls_and_unsupported_schemes_never_receive_tokens() {
        let auth = auth(&ProviderHosts::saas_defaults(), &all_tokens());
        for url in [
            "",
            "github.com/repo",
            "https:github.com/repo",
            "https:///github.com/repo",
            "file:///github.com/repo",
            "ssh://github.com/repo",
            "git://github.com/repo",
            "ftp://github.com/repo",
            "http://github.com/repo",
            "https://github.com:65536/repo",
            " https://github.com/repo",
            "https://github.com/repo\n",
            "https://github.com\u{0}/repo",
            "https://github.com\\@evil/repo",
            "https://username:password@github.com/repo",
        ] {
            assert_eq!(identity(&auth, url), None, "{url}");
        }
    }

    #[test]
    fn overlapping_provider_hosts_keep_cascade_order_without_mixing_accounts() {
        let hosts = ProviderHosts {
            github: vec!["shared.example".to_owned()],
            gitlab: vec!["shared.example".to_owned()],
            gitea: vec!["shared.example".to_owned()],
            bitbucket: vec!["shared.example".to_owned()],
            azure: vec!["shared.example".to_owned()],
            huggingface: vec!["shared.example".to_owned()],
        };
        let mut env = all_tokens();
        for (username, password) in [
            ("x-access-token", "gh-secret"),
            ("oauth2", "gl-secret"),
            ("gitea", "gitea-secret"),
            ("x-token-auth", "bb-secret"),
            ("pat", "azure-secret"),
            ("hf_user", "hf-secret"),
        ] {
            assert_eq!(
                identity(&auth(&hosts, &env), "https://shared.example/repo"),
                Some((username.to_owned(), password.to_owned()))
            );
            env.remove(0);
        }
    }

    #[test]
    fn callback_accepts_consistent_components_but_rejects_conflicting_destinations() {
        let auth = auth(&ProviderHosts::saas_defaults(), &[("KF_GITHUB_TOKEN", "secret")]);
        for url in [None, Some("https://github.com/repo")] {
            let context = Context {
                protocol: Some("https".to_owned()),
                host: Some("GITHUB.COM:443".to_owned()),
                username: Some("untrusted-caller".to_owned()),
                url: url.map(Into::into),
                ..Context::default()
            };
            let outcome = auth.credentials(Action::Get(context)).unwrap().unwrap();
            assert_eq!(outcome.identity.username, "x-access-token");
            assert_eq!(outcome.identity.password, "secret");
        }
        for (url, protocol, host) in [
            (Some("https://evil/repo"), Some("https"), Some("github.com")),
            (Some("https://github.com/repo"), Some("http"), Some("github.com")),
            (Some("https://github.com/repo"), Some("https"), Some("evil")),
            (Some("https://github.com/repo"), Some("https"), Some("github.com:8443")),
            (None, Some("https"), Some("github.com@evil")),
            (None, Some("https"), Some("github.com/repo")),
            (None, Some("https"), Some("github.com:8443")),
            (None, Some("http"), Some("github.com")),
            (None, None, Some("github.com")),
            (None, Some("https"), None),
        ] {
            let context = Context {
                url: url.map(Into::into),
                protocol: protocol.map(str::to_owned),
                host: host.map(str::to_owned),
                ..Context::default()
            };
            assert!(auth.credentials(Action::Get(context)).unwrap().is_none());
        }
        let mut invalid = Action::get_for_url("https://github.com/repo");
        invalid.context_mut().unwrap().url = Some(vec![0xff].into());
        assert!(auth.credentials(invalid).unwrap().is_none());
    }

    #[test]
    fn callback_never_persists_or_echoes_secrets_into_followup_payloads() {
        let auth = auth(&ProviderHosts::saas_defaults(), &[("KF_GITHUB_TOKEN", "provider-secret")]);
        let mut context = Context::from_url(
            "https://github.com/private-input-path?query=input-secret",
            Default::default(),
        );
        context.username = Some("caller-secret-user".to_owned());
        context.password = Some("caller-secret-password".to_owned());
        context.oauth_refresh_token = Some("caller-secret-refresh".to_owned());
        context.www_authenticate = vec!["Basic realm=challenge-secret".into()];
        let outcome = auth.credentials(Action::Get(context)).unwrap().unwrap();
        let store = outcome.next.clone().store();
        let erase = outcome.next.erase();
        for action in [store, erase] {
            let payload = std::str::from_utf8(action.payload().unwrap().as_ref()).unwrap();
            assert_eq!(payload, "protocol=https\nhost=github.com\n");
            assert!(auth.credentials(action).unwrap().is_none());
        }
        // Advisory actions from other callers are ignored without even parsing their payloads.
        for action in [
            Action::Store("password=provider-secret\nmalformed".into()),
            Action::Erase(vec![0xff, 0].into()),
        ] {
            assert!(auth.credentials(action).unwrap().is_none());
        }
        assert_eq!(identity(&auth, "https://github.com/repo").unwrap().1, "provider-secret");
    }

    #[test]
    fn debug_and_cloned_snapshots_are_safe_and_stable() {
        let auth = auth(&ProviderHosts::saas_defaults(), &all_tokens());
        let debug = format!("{auth:?}");
        for (_, secret) in all_tokens() {
            assert!(!debug.contains(secret));
        }
        assert!(!debug.contains("password"));
        let clone = auth.clone();
        assert_eq!(
            identity(&clone, "https://github.com/repo"),
            identity(&auth, "https://github.com/repo")
        );
        assert!(
            GitAuth::default()
                .credentials(Action::get_for_url("https://github.com/repo"))
                .unwrap()
                .is_none()
        );
    }
}
