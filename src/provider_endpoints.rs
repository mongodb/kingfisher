use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result, anyhow, bail};
use liquid::Object;
use liquid_core::{Value, ValueView};
use serde::Deserialize;
use url::Url;

use crate::cli::global::GlobalArgs;

const GITHUB_API_BASE_URL: &str = "GITHUB_API_BASE_URL";
const GITHUB_WEB_BASE_URL: &str = "GITHUB_WEB_BASE_URL";
const GITLAB_API_BASE_URL: &str = "GITLAB_API_BASE_URL";
const GITEA_API_BASE_URL: &str = "GITEA_API_BASE_URL";
const JIRA_BASE_URL: &str = "JIRA_BASE_URL";
const JIRA_CLOUD_BASE_URL: &str = "JIRA_CLOUD_BASE_URL";
const CONFLUENCE_BASE_URL: &str = "CONFLUENCE_BASE_URL";
const ARTIFACTORY_BASE_URL: &str = "ARTIFACTORY_BASE_URL";

#[derive(Debug, Clone, Default)]
pub struct ProviderEndpointOverrides {
    config: EndpointVars,
    cli: EndpointVars,
}

#[derive(Debug, Clone, Default)]
struct EndpointVars {
    values: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Default)]
struct EndpointConfigFile {
    #[serde(default)]
    endpoints: BTreeMap<String, String>,
    #[serde(default)]
    provider_endpoints: BTreeMap<String, String>,
    #[serde(default)]
    providers: BTreeMap<String, String>,
}

impl ProviderEndpointOverrides {
    pub fn from_global_args(global_args: &GlobalArgs) -> Result<Self> {
        let config = match &global_args.endpoint_config {
            Some(path) => EndpointVars::from_config_path(path)?,
            None => EndpointVars::default(),
        };
        let cli = EndpointVars::from_pairs(&global_args.endpoint)?;
        Ok(Self { config, cli })
    }

    pub fn apply_defaults(&self, globals: &mut Object) {
        self.config.apply(globals, false);
        apply_builtin_defaults(globals);
        self.cli.apply(globals, true);
    }

    pub fn apply_scan_overrides(&self, globals: &mut Object) {
        self.config.apply(globals, true);
        apply_builtin_defaults(globals);
        self.cli.apply(globals, true);
    }
}

impl EndpointVars {
    fn from_config_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("Failed to read endpoint config from {}", path.display()))?;
        let parsed: EndpointConfigFile = serde_yaml::from_str(&raw)
            .with_context(|| format!("Failed to parse endpoint config {}", path.display()))?;

        let mut merged = parsed.endpoints;
        merged.extend(parsed.provider_endpoints);
        merged.extend(parsed.providers);
        Self::from_map(merged)
    }

    fn from_pairs(pairs: &[String]) -> Result<Self> {
        let mut map = BTreeMap::new();
        for pair in pairs {
            let (provider, endpoint) = parse_assignment(pair)?;
            map.insert(provider, endpoint);
        }
        Self::from_map(map)
    }

    fn from_map(map: BTreeMap<String, String>) -> Result<Self> {
        let mut values = BTreeMap::new();
        for (provider, endpoint) in map {
            let normalized = normalize_endpoint_key(&provider);
            match normalized.as_str() {
                "github" => {
                    let github = normalize_github_endpoint(&endpoint)?;
                    values.insert(GITHUB_API_BASE_URL.to_string(), github.api_base_url);
                    values.insert(GITHUB_WEB_BASE_URL.to_string(), github.web_base_url);
                }
                "gitlab" => {
                    values.insert(
                        GITLAB_API_BASE_URL.to_string(),
                        normalize_api_base_url(&endpoint, "/api/v4")?,
                    );
                }
                "gitea" => {
                    values.insert(
                        GITEA_API_BASE_URL.to_string(),
                        normalize_api_base_url(&endpoint, "/api/v1")?,
                    );
                }
                "jira" | "jira-dc" => {
                    values.insert(JIRA_BASE_URL.to_string(), normalize_base_url(&endpoint)?);
                }
                "jira-cloud" => {
                    values.insert(JIRA_CLOUD_BASE_URL.to_string(), normalize_base_url(&endpoint)?);
                }
                "confluence" | "confluence-dc" => {
                    values.insert(CONFLUENCE_BASE_URL.to_string(), normalize_base_url(&endpoint)?);
                }
                "artifactory" | "jfrog" => {
                    values.insert(
                        ARTIFACTORY_BASE_URL.to_string(),
                        normalize_artifactory_base_url(&endpoint)?,
                    );
                }
                _ => bail!(
                    "Unsupported endpoint provider '{}'. Supported values: github, gitlab, gitea, jira (alias: jira-dc), jira-cloud, confluence (alias: confluence-dc), artifactory (alias: jfrog)",
                    provider
                ),
            }
        }
        Ok(Self { values })
    }

    fn apply(&self, globals: &mut Object, overwrite_existing: bool) {
        for (name, value) in &self.values {
            if overwrite_existing || !globals.contains_key(name.as_str()) {
                globals.insert(name.clone().into(), Value::scalar(value.clone()));
            }
        }
    }
}

#[derive(Debug)]
struct GitHubEndpoint {
    api_base_url: String,
    web_base_url: String,
}

pub fn hydrate_endpoint_globals_for_rule(rule_id: &str, globals: &mut Object) {
    hydrate_github_globals(globals);
    hydrate_artifactory_globals(globals);
    hydrate_confluence_globals(globals);
    hydrate_jira_dc_globals(globals);
    if rule_id == "kingfisher.jira.2" {
        hydrate_jira_cloud_globals(globals);
    }
}

pub fn endpoint_var_names() -> &'static [&'static str] {
    &[
        GITHUB_API_BASE_URL,
        GITHUB_WEB_BASE_URL,
        GITLAB_API_BASE_URL,
        GITEA_API_BASE_URL,
        JIRA_BASE_URL,
        JIRA_CLOUD_BASE_URL,
        CONFLUENCE_BASE_URL,
        ARTIFACTORY_BASE_URL,
    ]
}

fn hydrate_github_globals(globals: &mut Object) {
    match (string_var(globals, GITHUB_API_BASE_URL), string_var(globals, GITHUB_WEB_BASE_URL)) {
        (Some(api), None) => {
            if let Ok(normalized) = normalize_github_endpoint(&api) {
                globals.insert(GITHUB_API_BASE_URL.into(), Value::scalar(normalized.api_base_url));
                globals.insert(GITHUB_WEB_BASE_URL.into(), Value::scalar(normalized.web_base_url));
            }
        }
        (None, Some(web)) => {
            if let Ok(normalized) = normalize_github_endpoint(&web) {
                globals.insert(GITHUB_API_BASE_URL.into(), Value::scalar(normalized.api_base_url));
                globals.insert(GITHUB_WEB_BASE_URL.into(), Value::scalar(normalized.web_base_url));
            }
        }
        _ => {}
    }
}

fn hydrate_artifactory_globals(globals: &mut Object) {
    if globals.contains_key(ARTIFACTORY_BASE_URL) {
        return;
    }
    if let Some(jfrog_url) = string_var(globals, "JFROGURL")
        && let Ok(base_url) = normalize_artifactory_base_url(&jfrog_url)
    {
        globals.insert(ARTIFACTORY_BASE_URL.into(), Value::scalar(base_url));
    }
}

fn hydrate_confluence_globals(globals: &mut Object) {
    if globals.contains_key(CONFLUENCE_BASE_URL) {
        return;
    }
    if let Some(domain) = string_var(globals, "CONFLUENCEDCDOMAIN")
        && let Ok(base_url) = normalize_base_url(&domain)
    {
        globals.insert(CONFLUENCE_BASE_URL.into(), Value::scalar(base_url));
    }
}

fn hydrate_jira_dc_globals(globals: &mut Object) {
    if globals.contains_key(JIRA_BASE_URL) {
        return;
    }
    if let Some(domain) = string_var(globals, "JIRADCDOMAIN")
        && let Ok(base_url) = normalize_base_url(&domain)
    {
        globals.insert(JIRA_BASE_URL.into(), Value::scalar(base_url));
    }
}

fn hydrate_jira_cloud_globals(globals: &mut Object) {
    if globals.contains_key(JIRA_CLOUD_BASE_URL) {
        return;
    }
    if let Some(domain) = string_var(globals, "DOMAIN")
        && let Ok(base_url) = normalize_base_url(&domain)
    {
        globals.insert(JIRA_CLOUD_BASE_URL.into(), Value::scalar(base_url));
    }
}

fn string_var(globals: &Object, name: &str) -> Option<String> {
    globals.get(name).map(|value| value.to_kstr().to_string()).filter(|s| !s.is_empty())
}

fn apply_builtin_defaults(globals: &mut Object) {
    for (name, value) in [
        (GITHUB_API_BASE_URL, "https://api.github.com"),
        (GITHUB_WEB_BASE_URL, "https://github.com"),
        (GITLAB_API_BASE_URL, "https://gitlab.com/api/v4"),
        (GITEA_API_BASE_URL, "https://gitea.com/api/v1"),
    ] {
        if !globals.contains_key(name) {
            globals.insert(name.into(), Value::scalar(value.to_string()));
        }
    }
}

fn parse_assignment(raw: &str) -> Result<(String, String)> {
    let (provider, endpoint) = raw
        .split_once('=')
        .ok_or_else(|| anyhow!("Invalid endpoint '{}'. Expected PROVIDER=URL", raw))?;
    let provider = provider.trim();
    let endpoint = endpoint.trim();
    if provider.is_empty() {
        bail!("Invalid endpoint '{}'. Provider name cannot be empty", raw);
    }
    if endpoint.is_empty() {
        bail!("Invalid endpoint '{}'. URL cannot be empty", raw);
    }
    Ok((provider.to_string(), endpoint.to_string()))
}

fn normalize_endpoint_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace('_', "-")
}

fn normalize_base_url(raw: &str) -> Result<String> {
    let url = parse_url_or_assume_https(raw)?;
    Ok(url_with_path(&url, url.path().trim_end_matches('/')))
}

fn normalize_api_base_url(raw: &str, api_suffix: &str) -> Result<String> {
    let url = parse_url_or_assume_https(raw)?;
    let path = url.path().trim_end_matches('/');
    let full_path = if path.is_empty() {
        api_suffix.to_string()
    } else if path.ends_with(api_suffix) {
        path.to_string()
    } else {
        format!("{path}{api_suffix}")
    };
    Ok(url_with_path(&url, &full_path))
}

fn normalize_artifactory_base_url(raw: &str) -> Result<String> {
    let url = parse_url_or_assume_https(raw)?;
    let mut path = url.path().trim_end_matches('/').to_string();
    if let Some(prefix) = path.strip_suffix("/artifactory") {
        path = prefix.to_string();
    }
    Ok(url_with_path(&url, &path))
}

fn normalize_github_endpoint(raw: &str) -> Result<GitHubEndpoint> {
    let url = parse_url_or_assume_https(raw)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("Endpoint '{}' is missing a host", raw))?
        .to_ascii_lowercase();
    let path = url.path().trim_end_matches('/');

    if host == "api.github.com" {
        return Ok(GitHubEndpoint {
            api_base_url: "https://api.github.com".to_string(),
            web_base_url: "https://github.com".to_string(),
        });
    }
    if host == "github.com" && path.is_empty() {
        return Ok(GitHubEndpoint {
            api_base_url: "https://api.github.com".to_string(),
            web_base_url: "https://github.com".to_string(),
        });
    }

    let (web_path, api_path) = if path.is_empty() {
        ("".to_string(), "/api/v3".to_string())
    } else if let Some(prefix) = path.strip_suffix("/api/v3") {
        (prefix.to_string(), path.to_string())
    } else {
        (path.to_string(), format!("{path}/api/v3"))
    };

    Ok(GitHubEndpoint {
        api_base_url: url_with_path(&url, &api_path),
        web_base_url: url_with_path(&url, &web_path),
    })
}

fn parse_url_or_assume_https(raw: &str) -> Result<Url> {
    match Url::parse(raw.trim()) {
        Ok(url) => Ok(url),
        Err(url::ParseError::RelativeUrlWithoutBase) => {
            Url::parse(&format!("https://{}", raw.trim())).with_context(|| {
                format!("Invalid endpoint URL '{}'. Use a full URL or hostname", raw)
            })
        }
        Err(err) => Err(anyhow!("Invalid endpoint URL '{}': {}", raw, err)),
    }
}

fn url_with_path(url: &Url, path: &str) -> String {
    let mut out = url.clone();
    out.set_query(None);
    out.set_fragment(None);
    if path.is_empty() {
        out.set_path("");
    } else {
        out.set_path(path);
    }
    out.to_string().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_endpoint_normalizes_host_only() {
        let normalized = normalize_github_endpoint("ghe.corp.example.com").unwrap();
        assert_eq!(normalized.api_base_url, "https://ghe.corp.example.com/api/v3");
        assert_eq!(normalized.web_base_url, "https://ghe.corp.example.com");
    }

    #[test]
    fn github_endpoint_normalizes_api_path() {
        let normalized = normalize_github_endpoint("https://ghe.corp.example.com/api/v3").unwrap();
        assert_eq!(normalized.api_base_url, "https://ghe.corp.example.com/api/v3");
        assert_eq!(normalized.web_base_url, "https://ghe.corp.example.com");
    }

    #[test]
    fn gitlab_endpoint_appends_api_path() {
        assert_eq!(
            normalize_api_base_url("gitlab.example.com/gitlab", "/api/v4").unwrap(),
            "https://gitlab.example.com/gitlab/api/v4"
        );
    }

    #[test]
    fn artifactory_endpoint_strips_artifactory_suffix() {
        assert_eq!(
            normalize_artifactory_base_url("http://localhost:8071/artifactory").unwrap(),
            "http://localhost:8071"
        );
    }

    #[test]
    fn jira_cloud_hydrates_from_legacy_domain() {
        let mut globals = Object::new();
        globals.insert("DOMAIN".into(), Value::scalar("example.atlassian.net"));
        hydrate_endpoint_globals_for_rule("kingfisher.jira.2", &mut globals);
        assert_eq!(
            string_var(&globals, JIRA_CLOUD_BASE_URL).as_deref(),
            Some("https://example.atlassian.net")
        );
    }

    #[test]
    fn artifactory_hydrates_from_legacy_host() {
        let mut globals = Object::new();
        globals.insert("JFROGURL".into(), Value::scalar("repo.example.com"));
        hydrate_endpoint_globals_for_rule("kingfisher.artifactory.1", &mut globals);
        assert_eq!(
            string_var(&globals, ARTIFACTORY_BASE_URL).as_deref(),
            Some("https://repo.example.com")
        );
    }
}
