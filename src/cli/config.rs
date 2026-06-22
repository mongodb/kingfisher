//! `kingfisher.yaml` project configuration.
//!
//! The config file is **additive** for list/map values (lists are concatenated
//! onto CLI flags) and **default-only** for scalars: a scalar in YAML is
//! applied only when the user did not pass the matching `--flag` on the CLI.
//! Precedence end-to-end: **CLI > env > config > built-in default**.
//!
//! Detection of "was the CLI flag actually provided?" relies on
//! [`clap::parser::ValueSource`]; see `apply_config` in `main.rs`, which uses
//! the helper `config_wins(matches, "<arg_id>")` to gate every scalar
//! assignment.
//!
//! ```yaml
//! scan:
//!   confidence: medium
//!   redact: false
//! rules:
//!   enabled: ["all"]
//!   load_builtins: true
//!   cache: true
//!   cache_dir: ./.kingfisher-cache
//! validation:
//!   timeout: 10
//!   rps_per_rule:
//!     kingfisher.aws: 1.0
//! filters:
//!   max_file_size_mb: 256.0
//!   exclude: ["vendor/", "node_modules/"]
//!   skip_words: ["EXAMPLE", "TEST"]
//! output:
//!   format: json
//!   path: ./report.json
//! baseline:
//!   file: ./baseline.json
//! alerts:
//!   defaults:
//!     min_confidence: high
//!     include_secret: false
//!   webhooks:
//!     - url: https://hooks.slack.com/services/...
//!       format: slack
//! global:
//!   tls_mode: strict
//!   endpoints:
//!     - github=https://ghe.example.com/api/v3
//! git:
//!   clone_dir: ./clones
//!   keep_clones: false
//! ```
//!
//! This module is parsing-only. The CLI entry point (main.rs) is responsible
//! for resolving paths, reading file contents, and merging values into
//! `ScanArgs`/`GlobalArgs`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::alerts::{AlertDetail, AlertFormat, AlertOn};
use crate::cli::commands::output::ReportOutputFormat;
use crate::cli::commands::scan::ConfidenceLevel;
use crate::cli::global::TlsMode;

/// Conventional file name when users save a project-local config. The path
/// must still be passed explicitly via `--config`; nothing in the binary
/// auto-loads a file with this name.
pub const DEFAULT_CONFIG_NAME: &str = "kingfisher.yaml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KingfisherConfig {
    #[serde(default)]
    pub scan: ScanConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub validation: ValidationConfig,
    #[serde(default)]
    pub filters: FiltersConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
    #[serde(default)]
    pub alerts: AlertsConfig,
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub git: GitConfig,
}

// ----------------------------------------------------------------------------
// scan: behavioral knobs that map to top-level `scan` flags.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    pub confidence: Option<ConfigConfidence>,
    pub min_entropy: Option<f32>,
    pub no_validate: Option<bool>,
    pub only_valid: Option<bool>,
    pub redact: Option<bool>,
    pub no_dedup: Option<bool>,
    pub turbo: Option<bool>,
    pub no_base64: Option<bool>,
    pub access_map: Option<bool>,
    pub rule_stats: Option<bool>,
    pub jobs: Option<usize>,
    pub git_repo_timeout: Option<u64>,
}

// ----------------------------------------------------------------------------
// rules: rule selection / sources.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesConfig {
    /// Additive — merged with `--rule` selections.
    #[serde(default)]
    pub enabled: Vec<String>,
    /// Additive — merged with `--rules-path` paths.
    #[serde(default)]
    pub paths: Vec<PathBuf>,
    pub load_builtins: Option<bool>,
    pub cache: Option<bool>,
    pub cache_dir: Option<PathBuf>,
}

// ----------------------------------------------------------------------------
// validation: live validation tuning.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationConfig {
    pub timeout: Option<u64>,
    pub retries: Option<u32>,
    pub rps: Option<f64>,
    /// Additive map; serialized to `rule=rps` strings and concatenated with
    /// `--validation-rps-rule`.
    #[serde(default)]
    pub rps_per_rule: BTreeMap<String, f64>,
    pub full_response: Option<bool>,
    pub max_response_length: Option<usize>,
}

// ----------------------------------------------------------------------------
// filters: file-, path-, content-, and finding-level filters.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiltersConfig {
    // v1 fields — additive with CLI.
    #[serde(default)]
    pub skip_words: Vec<String>,
    #[serde(default)]
    pub skip_regex: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,

    // v2 additions.
    pub max_file_size_mb: Option<f64>,
    pub no_binary: Option<bool>,
    pub no_extract_archives: Option<bool>,
    pub extraction_depth: Option<u8>,
    pub no_inline_ignore: Option<bool>,
    pub no_ignore_if_contains: Option<bool>,
    /// Additive — merged with `--ignore-comment`.
    #[serde(default)]
    pub extra_ignore_comments: Vec<String>,
    /// Additive — merged with `--skip-aws-account`.
    #[serde(default)]
    pub skip_aws_accounts: Vec<String>,
    pub skip_aws_account_file: Option<PathBuf>,
}

// ----------------------------------------------------------------------------
// output: report destination and format.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub format: Option<ConfigReportFormat>,
    pub path: Option<PathBuf>,
}

// ----------------------------------------------------------------------------
// baseline: known-finding suppression.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    pub file: Option<PathBuf>,
    pub manage: Option<bool>,
}

// ----------------------------------------------------------------------------
// alerts: webhooks (existing) plus global defaults for the `--alert-*` flags.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsConfig {
    #[serde(default)]
    pub defaults: AlertsDefaultsConfig,
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertsDefaultsConfig {
    pub format: Option<AlertFormat>,
    #[serde(rename = "on")]
    pub on: Option<AlertOn>,
    pub min_confidence: Option<ConfigConfidence>,
    pub include_secret: Option<bool>,
    pub report_url: Option<String>,
    pub detail: Option<AlertDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub format: Option<AlertFormat>,
    #[serde(default, rename = "on")]
    pub on: Option<AlertOn>,
    #[serde(default)]
    pub min_confidence: Option<ConfigConfidence>,
    #[serde(default)]
    pub include_secret: Option<bool>,
    /// Per-webhook override of the global `--alert-report-url`. Useful when
    /// chat sinks should carry a pivot link but a SIEM-bound generic webhook
    /// shouldn't.
    #[serde(default)]
    pub report_url: Option<String>,
    /// Per-webhook override of the global `--alert-detail` mode.
    #[serde(default)]
    pub detail: Option<AlertDetail>,
}

// ----------------------------------------------------------------------------
// global: top-level GlobalArgs flags.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    pub tls_mode: Option<ConfigTlsMode>,
    pub allow_internal_ips: Option<bool>,
    pub no_update_check: Option<bool>,
    pub user_agent_suffix: Option<String>,
    /// Additive — merged with `--endpoint`. Each entry is `provider=url`.
    #[serde(default)]
    pub endpoints: Vec<String>,
    pub endpoint_config: Option<PathBuf>,
}

// ----------------------------------------------------------------------------
// git: clone behavior + provider API roots for git scans.
// ----------------------------------------------------------------------------
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitConfig {
    pub clone_dir: Option<PathBuf>,
    pub keep_clones: Option<bool>,
    pub repo_clone_limit: Option<usize>,
    pub include_contributors: Option<bool>,
    /// GitHub Enterprise / self-hosted GitHub API root used during enumeration
    /// and cloning. Equivalent to `--github-api-url` on the bare `scan` form
    /// or `--api-url` on `kingfisher scan github`. For *validation* of
    /// discovered tokens against the same instance, set
    /// `global.endpoints` (e.g. `github=https://ghe.example.com`).
    pub github_api_url: Option<String>,
    /// Self-hosted GitLab API root used during enumeration and cloning.
    /// Equivalent to `--gitlab-api-url`. Pair with a matching
    /// `global.endpoints` `gitlab=...` entry to also redirect token
    /// validation to the same instance.
    pub gitlab_api_url: Option<String>,
}

// ----------------------------------------------------------------------------
// Enum mirrors. We define separate YAML-only enums for types whose CLI variant
// uses kebab-case (clap) — this gives us snake_case_with_friendly_names in
// YAML without coupling to clap's value-enum parsing.
// ----------------------------------------------------------------------------
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigConfidence {
    Low,
    Medium,
    High,
}

impl From<ConfigConfidence> for ConfidenceLevel {
    fn from(c: ConfigConfidence) -> Self {
        match c {
            ConfigConfidence::Low => ConfidenceLevel::Low,
            ConfigConfidence::Medium => ConfidenceLevel::Medium,
            ConfigConfidence::High => ConfidenceLevel::High,
        }
    }
}

impl From<ConfidenceLevel> for ConfigConfidence {
    fn from(c: ConfidenceLevel) -> Self {
        match c {
            ConfidenceLevel::Low => ConfigConfidence::Low,
            ConfidenceLevel::Medium => ConfigConfidence::Medium,
            ConfidenceLevel::High => ConfigConfidence::High,
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigTlsMode {
    Strict,
    Lax,
    Off,
}

impl From<ConfigTlsMode> for TlsMode {
    fn from(m: ConfigTlsMode) -> Self {
        match m {
            ConfigTlsMode::Strict => TlsMode::Strict,
            ConfigTlsMode::Lax => TlsMode::Lax,
            ConfigTlsMode::Off => TlsMode::Off,
        }
    }
}

impl From<TlsMode> for ConfigTlsMode {
    fn from(m: TlsMode) -> Self {
        match m {
            TlsMode::Strict => ConfigTlsMode::Strict,
            TlsMode::Lax => ConfigTlsMode::Lax,
            TlsMode::Off => ConfigTlsMode::Off,
        }
    }
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfigReportFormat {
    Pretty,
    Json,
    Jsonl,
    Bson,
    Toon,
    Sarif,
    Html,
}

impl From<ConfigReportFormat> for ReportOutputFormat {
    fn from(f: ConfigReportFormat) -> Self {
        match f {
            ConfigReportFormat::Pretty => ReportOutputFormat::Pretty,
            ConfigReportFormat::Json => ReportOutputFormat::Json,
            ConfigReportFormat::Jsonl => ReportOutputFormat::Jsonl,
            ConfigReportFormat::Bson => ReportOutputFormat::Bson,
            ConfigReportFormat::Toon => ReportOutputFormat::Toon,
            ConfigReportFormat::Sarif => ReportOutputFormat::Sarif,
            ConfigReportFormat::Html => ReportOutputFormat::Html,
        }
    }
}

impl From<ReportOutputFormat> for ConfigReportFormat {
    fn from(f: ReportOutputFormat) -> Self {
        match f {
            ReportOutputFormat::Pretty => ConfigReportFormat::Pretty,
            ReportOutputFormat::Json => ConfigReportFormat::Json,
            ReportOutputFormat::Jsonl => ConfigReportFormat::Jsonl,
            ReportOutputFormat::Bson => ConfigReportFormat::Bson,
            ReportOutputFormat::Toon => ConfigReportFormat::Toon,
            ReportOutputFormat::Sarif => ConfigReportFormat::Sarif,
            ReportOutputFormat::Html => ConfigReportFormat::Html,
        }
    }
}

/// Parse YAML text into a config struct, validating webhook URLs, regex
/// patterns, range-bounded scalars, and endpoint formats so config errors
/// surface at the `--config` site rather than mid-scan.
pub fn parse_str(yaml: &str) -> Result<KingfisherConfig> {
    let cfg: KingfisherConfig =
        serde_yaml::from_str(yaml).context("failed to parse kingfisher.yaml")?;
    validate(&cfg)?;
    Ok(cfg)
}

fn validate(cfg: &KingfisherConfig) -> Result<()> {
    // alerts.webhooks
    for (idx, w) in cfg.alerts.webhooks.iter().enumerate() {
        crate::alerts::validate_webhook_url(&w.url)
            .with_context(|| format!("alerts.webhooks[{idx}].url"))?;
        if let Some(report_url) = &w.report_url {
            url::Url::parse(report_url)
                .with_context(|| format!("alerts.webhooks[{idx}].report_url is not a valid URL"))?;
        }
    }
    if let Some(report_url) = &cfg.alerts.defaults.report_url {
        url::Url::parse(report_url).context("alerts.defaults.report_url is not a valid URL")?;
    }

    // filters.skip_regex
    for (idx, pattern) in cfg.filters.skip_regex.iter().enumerate() {
        regex::Regex::new(pattern)
            .with_context(|| format!("filters.skip_regex[{idx}] is not a valid regex"))?;
    }

    // Range-bounded scalars (mirror the CLI value_parser ranges).
    if let Some(t) = cfg.validation.timeout
        && !(1..=60).contains(&t)
    {
        bail!("validation.timeout must be in 1..=60 (got {t})");
    }
    if let Some(r) = cfg.validation.retries
        && r > 5
    {
        bail!("validation.retries must be in 0..=5 (got {r})");
    }
    if let Some(d) = cfg.filters.extraction_depth
        && !(1..=25).contains(&d)
    {
        bail!("filters.extraction_depth must be in 1..=25 (got {d})");
    }
    if let Some(rps) = cfg.validation.rps
        && !(rps.is_finite() && rps > 0.0)
    {
        bail!("validation.rps must be a finite positive number (got {rps})");
    }
    for (rule, rps) in &cfg.validation.rps_per_rule {
        if rule.is_empty() {
            bail!("validation.rps_per_rule has an empty rule selector");
        }
        if !(rps.is_finite() && *rps > 0.0) {
            bail!("validation.rps_per_rule[{rule}] must be a finite positive number (got {rps})");
        }
    }

    // global.endpoints — must look like `provider=url`.
    for (idx, entry) in cfg.global.endpoints.iter().enumerate() {
        let (provider, url_str) = entry.split_once('=').with_context(|| {
            format!("global.endpoints[{idx}] must be `provider=url` (got {entry:?})")
        })?;
        if provider.is_empty() {
            bail!("global.endpoints[{idx}] has empty provider name");
        }
        url::Url::parse(url_str)
            .with_context(|| format!("global.endpoints[{idx}] URL is not valid"))?;
    }

    // git.github_api_url / git.gitlab_api_url — must parse as URLs.
    if let Some(u) = &cfg.git.github_api_url {
        url::Url::parse(u).context("git.github_api_url is not a valid URL")?;
    }
    if let Some(u) = &cfg.git.gitlab_api_url {
        url::Url::parse(u).context("git.gitlab_api_url is not a valid URL")?;
    }

    // alerts.defaults.report_url already checked above.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_alerts() {
        let yaml = r#"
alerts:
  webhooks:
    - url: https://example.com/hook
      format: slack
      on: findings
"#;
        let cfg = parse_str(yaml).unwrap();
        assert_eq!(cfg.alerts.webhooks.len(), 1);
        assert_eq!(cfg.alerts.webhooks[0].url, "https://example.com/hook");
        assert_eq!(cfg.alerts.webhooks[0].format, Some(AlertFormat::Slack));
        assert_eq!(cfg.alerts.webhooks[0].on, Some(AlertOn::Findings));
    }

    #[test]
    fn parse_filters_v1() {
        let yaml = r#"
filters:
  skip_words: ["EXAMPLE", "TEST"]
  exclude: ["vendor/", "**/node_modules/**"]
"#;
        let cfg = parse_str(yaml).unwrap();
        assert_eq!(cfg.filters.skip_words, vec!["EXAMPLE", "TEST"]);
        assert_eq!(cfg.filters.exclude.len(), 2);
    }

    #[test]
    fn parse_full_v2_schema() {
        let yaml = r#"
scan:
  confidence: high
  redact: true
  jobs: 8
  git_repo_timeout: 600
rules:
  enabled: ["all", "default"]
  paths: ["./custom-rules"]
  load_builtins: true
  cache: true
  cache_dir: "./.kingfisher-cache"
validation:
  timeout: 15
  retries: 2
  rps: 5.0
  rps_per_rule:
    kingfisher.aws: 1.0
    kingfisher.gcp: 0.5
  full_response: false
  max_response_length: 4096
filters:
  max_file_size_mb: 128.0
  no_binary: true
  extraction_depth: 5
  extra_ignore_comments: ["nosec"]
  skip_aws_accounts: ["111122223333"]
  exclude: ["vendor/"]
output:
  format: json
  path: "./report.json"
baseline:
  file: "./baseline.json"
  manage: false
alerts:
  defaults:
    min_confidence: high
    include_secret: false
    detail: summary
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA
      format: slack
global:
  tls_mode: lax
  allow_internal_ips: true
  endpoints:
    - github=https://ghe.example.com/api/v3
git:
  clone_dir: "./clones"
  keep_clones: true
  repo_clone_limit: 50
  github_api_url: https://ghe.example.com/api/v3/
  gitlab_api_url: https://gitlab.example.com/
"#;
        let cfg = parse_str(yaml).unwrap();
        assert!(matches!(cfg.scan.confidence, Some(ConfigConfidence::High)));
        assert_eq!(cfg.scan.redact, Some(true));
        assert_eq!(cfg.scan.jobs, Some(8));
        assert_eq!(cfg.rules.enabled, vec!["all", "default"]);
        assert_eq!(cfg.rules.paths.len(), 1);
        assert_eq!(cfg.rules.cache, Some(true));
        assert_eq!(
            cfg.rules.cache_dir.as_deref().map(|p| p.to_str().unwrap()),
            Some("./.kingfisher-cache")
        );
        assert_eq!(cfg.validation.timeout, Some(15));
        assert_eq!(cfg.validation.rps_per_rule.len(), 2);
        assert_eq!(cfg.filters.max_file_size_mb, Some(128.0));
        assert_eq!(cfg.filters.skip_aws_accounts, vec!["111122223333"]);
        assert!(matches!(cfg.output.format, Some(ConfigReportFormat::Json)));
        assert_eq!(
            cfg.baseline.file.as_deref().map(|p| p.to_str().unwrap()),
            Some("./baseline.json")
        );
        assert!(matches!(cfg.alerts.defaults.min_confidence, Some(ConfigConfidence::High)));
        assert!(matches!(cfg.alerts.defaults.detail, Some(AlertDetail::Summary)));
        assert!(matches!(cfg.global.tls_mode, Some(ConfigTlsMode::Lax)));
        assert_eq!(cfg.global.endpoints.len(), 1);
        assert_eq!(cfg.git.clone_dir.as_deref().map(|p| p.to_str().unwrap()), Some("./clones"));
        assert_eq!(cfg.git.keep_clones, Some(true));
        assert_eq!(cfg.git.github_api_url.as_deref(), Some("https://ghe.example.com/api/v3/"));
        assert_eq!(cfg.git.gitlab_api_url.as_deref(), Some("https://gitlab.example.com/"));
    }

    #[test]
    fn invalid_git_github_api_url_is_rejected() {
        let err = parse_str("git:\n  github_api_url: 'not_a_url'\n").unwrap_err();
        assert!(format!("{err:#}").contains("git.github_api_url"));
    }

    #[test]
    fn invalid_git_gitlab_api_url_is_rejected() {
        let err = parse_str("git:\n  gitlab_api_url: 'also not a url'\n").unwrap_err();
        assert!(format!("{err:#}").contains("git.gitlab_api_url"));
    }

    #[test]
    fn empty_yaml_yields_default() {
        // serde_yaml rejects an empty document, so feed it the canonical empty
        // mapping. This both pins the contract (top-level must be a mapping)
        // and exercises the "no fields set" path.
        let cfg = parse_str("{}").unwrap();
        assert!(cfg.alerts.webhooks.is_empty());
        assert!(cfg.filters.skip_words.is_empty());
        assert!(cfg.scan.confidence.is_none());
        assert!(cfg.rules.enabled.is_empty());
        assert!(cfg.global.endpoints.is_empty());
    }

    #[test]
    fn invalid_webhook_url_is_rejected() {
        let yaml = "alerts:\n  webhooks:\n    - url: not-a-url\n";
        let err = parse_str(yaml).unwrap_err();
        assert!(format!("{err:#}").contains("alerts.webhooks[0].url"));
    }

    #[test]
    fn invalid_skip_regex_is_rejected() {
        let yaml = "filters:\n  skip_regex: ['(unclosed']\n";
        let err = parse_str(yaml).unwrap_err();
        assert!(format!("{err:#}").contains("filters.skip_regex[0]"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let yaml = "alerts:\n  webhooks: []\nbogus: 42\n";
        assert!(parse_str(yaml).is_err());
    }

    #[test]
    fn unknown_nested_field_is_rejected() {
        let yaml = "scan:\n  confidence: high\n  bogus_field: true\n";
        assert!(parse_str(yaml).is_err());
    }

    #[test]
    fn invalid_validation_timeout_is_rejected() {
        let err = parse_str("validation:\n  timeout: 999\n").unwrap_err();
        assert!(format!("{err:#}").contains("validation.timeout"));
    }

    #[test]
    fn invalid_extraction_depth_is_rejected() {
        let err = parse_str("filters:\n  extraction_depth: 99\n").unwrap_err();
        assert!(format!("{err:#}").contains("filters.extraction_depth"));
    }

    #[test]
    fn invalid_endpoint_format_is_rejected() {
        let err = parse_str("global:\n  endpoints:\n    - 'notakvpair'\n").unwrap_err();
        assert!(format!("{err:#}").contains("global.endpoints[0]"));
    }

    #[test]
    fn invalid_endpoint_url_is_rejected() {
        let err = parse_str("global:\n  endpoints:\n    - 'github=not_a_url'\n").unwrap_err();
        assert!(format!("{err:#}").contains("global.endpoints[0]"));
    }

    #[test]
    fn invalid_rps_is_rejected() {
        let err = parse_str("validation:\n  rps: -1.0\n").unwrap_err();
        assert!(format!("{err:#}").contains("validation.rps"));
    }

    #[test]
    fn alerts_defaults_invalid_url_is_rejected() {
        let err = parse_str("alerts:\n  defaults:\n    report_url: 'not://a real url here'\n")
            .unwrap_err();
        assert!(format!("{err:#}").contains("alerts.defaults.report_url"));
    }

    #[test]
    fn empty_subsections_are_accepted() {
        // Each section must accept an empty mapping so users can stub out a
        // section without having to populate every field.
        let yaml = r#"
scan: {}
rules: {}
validation: {}
filters: {}
output: {}
baseline: {}
alerts:
  defaults: {}
  webhooks: []
global: {}
git: {}
"#;
        let cfg = parse_str(yaml).unwrap();
        assert!(cfg.scan.confidence.is_none());
        assert!(cfg.rules.enabled.is_empty());
        assert!(cfg.validation.timeout.is_none());
        assert!(cfg.filters.skip_words.is_empty());
        assert!(cfg.output.format.is_none());
        assert!(cfg.baseline.file.is_none());
        assert!(cfg.alerts.webhooks.is_empty());
        assert!(cfg.global.endpoints.is_empty());
        assert!(cfg.git.clone_dir.is_none());
    }

    #[test]
    fn validation_retries_above_max_is_rejected() {
        let err = parse_str("validation:\n  retries: 99\n").unwrap_err();
        assert!(format!("{err:#}").contains("validation.retries"));
    }

    #[test]
    fn validation_rps_per_rule_empty_selector_is_rejected() {
        let err = parse_str("validation:\n  rps_per_rule:\n    \"\": 1.0\n").unwrap_err();
        assert!(format!("{err:#}").contains("rps_per_rule"));
    }

    #[test]
    fn validation_rps_per_rule_negative_is_rejected() {
        let err =
            parse_str("validation:\n  rps_per_rule:\n    kingfisher.aws: -1.0\n").unwrap_err();
        assert!(format!("{err:#}").contains("rps_per_rule"));
    }

    #[test]
    fn endpoint_with_empty_provider_is_rejected() {
        let err = parse_str("global:\n  endpoints:\n    - '=https://example.com/'\n").unwrap_err();
        assert!(format!("{err:#}").contains("global.endpoints[0]"));
    }
}
