//! Generate project configuration from explicitly supplied CLI values.

use std::io::Write;

use anyhow::{Context, Result};
use kingfisher::cli::{self, GlobalArgs};
use tracing::info;

/// Run `kingfisher config <subcommand>`.
pub(crate) fn run_config_command(
    config_args: kingfisher::cli::commands::config_command::ConfigArgs,
    global_args: &GlobalArgs,
    top_matches: &clap::ArgMatches,
) -> Result<()> {
    use kingfisher::cli::commands::config_command::ConfigSubcommand;

    match config_args.command {
        ConfigSubcommand::Init(init_args) => {
            let init_matches = top_matches
                .subcommand_matches("config")
                .and_then(|m| m.subcommand_matches("init"))
                .ok_or_else(|| anyhow::anyhow!("internal: missing `config init` matches"))?;

            let yaml = build_config_yaml(&init_args.scan_args, global_args, init_matches)?;

            match init_args.out.as_deref() {
                Some(path) => {
                    if !init_args.force && path.exists() {
                        anyhow::bail!(
                            "{} already exists. Pass --force to overwrite.",
                            path.display()
                        );
                    }
                    std::fs::write(path, &yaml)
                        .with_context(|| format!("write {}", path.display()))?;
                    info!("wrote {}", path.display());
                }
                None => {
                    let mut stdout = std::io::stdout().lock();
                    stdout.write_all(yaml.as_bytes())?;
                }
            }
        }
    }
    Ok(())
}

/// Reverse of `apply_config`: walk the user-supplied flags from `ArgMatches`
/// and emit a [`kingfisher::cli::config::KingfisherConfig`] containing only the flags the user
/// actually passed (CLI defaults are left out so the YAML stays minimal).
pub(crate) fn build_config_yaml(
    scan_args: &cli::commands::scan::ScanArgs,
    global_args: &GlobalArgs,
    sub_matches: &clap::ArgMatches,
) -> Result<String> {
    use clap::parser::ValueSource;
    use kingfisher::cli::config::{
        AlertsConfig, AlertsDefaultsConfig, BaselineConfig, FiltersConfig, GitConfig, GlobalConfig,
        KingfisherConfig, OutputConfig, RulesConfig, ScanConfig, ValidationConfig, WebhookConfig,
    };
    use std::collections::BTreeMap;

    fn user_set(matches: &clap::ArgMatches, id: &str) -> bool {
        matches!(
            matches.value_source(id),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        )
    }

    let mut cfg = KingfisherConfig::default();

    // ---------- scan ----------------------------------------------------
    let mut scan = ScanConfig::default();
    if user_set(sub_matches, "confidence") {
        scan.confidence = Some(scan_args.confidence.into());
    }
    if user_set(sub_matches, "min_entropy")
        && let Some(e) = scan_args.min_entropy
    {
        scan.min_entropy = Some(e);
    }
    if user_set(sub_matches, "no_validate") {
        scan.no_validate = Some(scan_args.no_validate);
    }
    if user_set(sub_matches, "only_valid") {
        scan.only_valid = Some(scan_args.only_valid);
    }
    if user_set(sub_matches, "validation_filter") {
        scan.validation_filter = scan_args.validation_filter;
    }
    if user_set(sub_matches, "redact") {
        scan.redact = Some(scan_args.redact);
    }
    if user_set(sub_matches, "no_dedup") {
        scan.no_dedup = Some(scan_args.no_dedup);
    }
    if user_set(sub_matches, "turbo") {
        scan.turbo = Some(scan_args.turbo);
    }
    if user_set(sub_matches, "no_base64") {
        scan.no_base64 = Some(scan_args.no_base64);
    }
    if user_set(sub_matches, "access_map") {
        scan.access_map = Some(scan_args.access_map);
    }
    if user_set(sub_matches, "rule_stats") {
        scan.rule_stats = Some(scan_args.rule_stats);
    }
    if user_set(sub_matches, "num_jobs") {
        scan.jobs = Some(scan_args.num_jobs);
    }
    if user_set(sub_matches, "no_limits") {
        scan.no_limits = Some(scan_args.content_filtering_args.no_limits);
    }
    if user_set(sub_matches, "git_repo_timeout") {
        scan.git_repo_timeout = Some(scan_args.git_repo_timeout);
    }
    cfg.scan = scan;

    // ---------- rules ---------------------------------------------------
    let mut rules = RulesConfig::default();
    if user_set(sub_matches, "rule") {
        rules.enabled = scan_args.rules.rule.clone();
    }
    if user_set(sub_matches, "exclude_rule") {
        rules.disabled = scan_args.rules.exclude_rule.clone();
    }
    if !scan_args.rules.rules_path.is_empty() {
        rules.paths = scan_args.rules.rules_path.clone();
    }
    if user_set(sub_matches, "load_builtins") {
        rules.load_builtins = Some(scan_args.rules.load_builtins);
    }
    if user_set(sub_matches, "rule_cache") {
        rules.cache = Some(true);
    }
    if user_set(sub_matches, "no_rule_cache") {
        rules.cache = Some(false);
    }
    if user_set(sub_matches, "rule_cache_dir") {
        rules.cache_dir = scan_args.rule_cache.rule_cache_dir.clone();
    }
    cfg.rules = rules;

    // ---------- validation ---------------------------------------------
    let mut validation = ValidationConfig::default();
    if user_set(sub_matches, "validation_timeout") {
        validation.timeout = Some(scan_args.validation_timeout);
    }
    if user_set(sub_matches, "validation_retries") {
        validation.retries = Some(scan_args.validation_retries);
    }
    if user_set(sub_matches, "validation_rps")
        && let Some(rps) = scan_args.validation_rps
    {
        validation.rps = Some(rps);
    }
    if !scan_args.validation_rps_rule.is_empty() {
        let mut map = BTreeMap::new();
        for entry in &scan_args.validation_rps_rule {
            let (rule, rps) = entry
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("invalid --validation-rps-rule entry: {entry:?}"))?;
            let rps: f64 = rps.parse().with_context(|| format!("invalid RPS in {entry:?}"))?;
            map.insert(rule.trim().to_string(), rps);
        }
        validation.rps_per_rule = map;
    }
    if user_set(sub_matches, "full_validation_response") {
        validation.full_response = Some(scan_args.full_validation_response);
    }
    if user_set(sub_matches, "max_validation_response_length") {
        validation.max_response_length = Some(scan_args.max_validation_response_length);
    }
    cfg.validation = validation;

    // ---------- filters --------------------------------------------------
    let mut filters = FiltersConfig::default();
    if !scan_args.skip_word.is_empty() {
        filters.skip_words = scan_args.skip_word.clone();
    }
    if !scan_args.skip_regex.is_empty() {
        filters.skip_regex = scan_args.skip_regex.clone();
    }
    if !scan_args.content_filtering_args.exclude.is_empty() {
        filters.exclude = scan_args.content_filtering_args.exclude.clone();
    }
    if user_set(sub_matches, "max_file_size_mb") {
        filters.max_file_size_mb = Some(scan_args.content_filtering_args.max_file_size_mb);
    }
    if user_set(sub_matches, "no_binary") {
        filters.no_binary = Some(scan_args.content_filtering_args.no_binary);
    }
    if user_set(sub_matches, "no_extract_archives") {
        filters.no_extract_archives = Some(scan_args.content_filtering_args.no_extract_archives);
    }
    if user_set(sub_matches, "extraction_depth") {
        filters.extraction_depth = Some(scan_args.content_filtering_args.extraction_depth);
    }
    if user_set(sub_matches, "no_inline_ignore") {
        filters.no_inline_ignore = Some(scan_args.no_inline_ignore);
    }
    if user_set(sub_matches, "no_ignore_if_contains") {
        filters.no_ignore_if_contains = Some(scan_args.no_ignore_if_contains);
    }
    if !scan_args.extra_ignore_comments.is_empty() {
        filters.extra_ignore_comments = scan_args.extra_ignore_comments.clone();
    }
    if !scan_args.skip_aws_account.is_empty() {
        filters.skip_aws_accounts = scan_args.skip_aws_account.clone();
    }
    if user_set(sub_matches, "skip_aws_account_file")
        && let Some(p) = &scan_args.skip_aws_account_file
    {
        filters.skip_aws_account_file = Some(p.clone());
    }
    cfg.filters = filters;

    // ---------- output ---------------------------------------------------
    let mut output = OutputConfig::default();
    if user_set(sub_matches, "format") {
        output.format = Some(scan_args.output_args.format.into());
    }
    if user_set(sub_matches, "output")
        && let Some(p) = &scan_args.output_args.output
    {
        output.path = Some(p.clone());
    }
    cfg.output = output;

    // ---------- baseline ------------------------------------------------
    let mut baseline = BaselineConfig::default();
    if user_set(sub_matches, "baseline_file")
        && let Some(p) = &scan_args.baseline_file
    {
        baseline.file = Some(p.clone());
    }
    if user_set(sub_matches, "manage_baseline") {
        baseline.manage = Some(scan_args.manage_baseline);
    }
    cfg.baseline = baseline;

    // ---------- alerts (defaults + webhooks via --alert-webhook) -------
    let mut alerts = AlertsConfig::default();
    let mut defaults = AlertsDefaultsConfig::default();
    if user_set(sub_matches, "alert_format") {
        defaults.format = scan_args.alert_format;
    }
    if user_set(sub_matches, "alert_on") {
        defaults.on = Some(scan_args.alert_on);
    }
    if user_set(sub_matches, "alert_min_confidence") {
        defaults.min_confidence = Some(scan_args.alert_min_confidence.into());
    }
    if user_set(sub_matches, "alert_include_secret") {
        defaults.include_secret = Some(scan_args.alert_include_secret);
    }
    if user_set(sub_matches, "alert_report_url")
        && let Some(u) = &scan_args.alert_report_url
    {
        defaults.report_url = Some(u.clone());
    }
    if user_set(sub_matches, "alert_detail") {
        defaults.detail = Some(scan_args.alert_detail);
    }
    if user_set(sub_matches, "alert_finding_filter") {
        defaults.finding_filter = Some(scan_args.alert_finding_filter);
    }
    if user_set(sub_matches, "alert_prevent_empty") {
        defaults.prevent_empty = Some(scan_args.alert_prevent_empty);
    }
    alerts.defaults = defaults;
    // Each --alert-webhook URL becomes a webhook entry. Per-webhook overrides
    // (slack vs teams, on=always, etc.) cannot be expressed as positional CLI
    // flags, so the emitted entry just carries the URL — operators can edit
    // the file to add per-sink behavior afterward.
    for url in &scan_args.alert_webhook {
        alerts.webhooks.push(WebhookConfig {
            url: url.clone(),
            format: None,
            on: None,
            min_confidence: None,
            include_secret: None,
            report_url: None,
            detail: None,
            finding_filter: None,
            prevent_empty: None,
        });
    }
    cfg.alerts = alerts;

    // ---------- global --------------------------------------------------
    let mut g = GlobalConfig::default();
    if user_set(sub_matches, "tls_mode") {
        g.tls_mode = Some(global_args.tls_mode.into());
    }
    if user_set(sub_matches, "allow_internal_ips") {
        g.allow_internal_ips = Some(global_args.allow_internal_ips);
    }
    if user_set(sub_matches, "no_update_check") {
        g.no_update_check = Some(global_args.no_update_check);
    }
    if user_set(sub_matches, "user_agent_suffix")
        && let Some(s) = &global_args.user_agent_suffix
    {
        g.user_agent_suffix = Some(s.clone());
    }
    if !global_args.endpoint.is_empty() {
        g.endpoints = global_args.endpoint.clone();
    }
    if user_set(sub_matches, "endpoint_config")
        && let Some(p) = &global_args.endpoint_config
    {
        g.endpoint_config = Some(p.clone());
    }
    cfg.global = g;

    // ---------- git ----------------------------------------------------
    let mut git = GitConfig::default();
    if user_set(sub_matches, "git_clone_dir")
        && let Some(p) = &scan_args.input_specifier_args.git_clone_dir
    {
        git.clone_dir = Some(p.clone());
    }
    if user_set(sub_matches, "keep_clones") {
        git.keep_clones = Some(scan_args.input_specifier_args.keep_clones);
    }
    if user_set(sub_matches, "repo_clone_limit")
        && let Some(n) = scan_args.input_specifier_args.repo_clone_limit
    {
        git.repo_clone_limit = Some(n);
    }
    if user_set(sub_matches, "include_contributors") {
        git.include_contributors = Some(scan_args.input_specifier_args.include_contributors);
    }
    // Provider API roots are stored as `Url` on the runtime side; the YAML
    // schema is a `String` so the emitted file matches exactly what the
    // user typed. `Url::to_string()` adds a trailing `/` on bare-host URLs
    // (e.g. `https://gitlab.example.com` → `https://gitlab.example.com/`),
    // which would silently rewrite the user's input on every `config init`
    // round-trip. Pull the raw CLI/env string from `ArgMatches` instead so
    // the emitted YAML matches what the user actually passed.
    fn raw_arg_string(matches: &clap::ArgMatches, id: &str) -> Option<String> {
        matches.get_raw(id).and_then(|mut v| v.next()).and_then(|s| s.to_str()).map(str::to_owned)
    }
    if user_set(sub_matches, "github_api_url") {
        git.github_api_url = raw_arg_string(sub_matches, "github_api_url");
    }
    if user_set(sub_matches, "gitlab_api_url") {
        git.gitlab_api_url = raw_arg_string(sub_matches, "gitlab_api_url");
    }
    cfg.git = git;

    // Serialize, then prune null/empty mappings so the YAML is concise.
    let mut value =
        serde_yaml::to_value(&cfg).context("serialize KingfisherConfig to YAML value")?;
    prune_empty(&mut value);
    let mut yaml = serde_yaml::to_string(&value).context("emit YAML")?;

    if yaml.trim() == "{}" || yaml.trim().is_empty() {
        // Avoid emitting "{}" — a no-op YAML is more confusing than empty.
        yaml = String::from("# kingfisher.yaml — no flags supplied; nothing to emit.\n");
    } else {
        let header = "# kingfisher.yaml — generated by `kingfisher config init`.\n\
                      # Edit freely; CLI flags always override config values.\n";
        yaml = format!("{header}{yaml}");
    }
    Ok(yaml)
}

/// Recursively drop `null` values, empty sequences, and empty mappings from
/// a [`serde_yaml::Value`]. Used by `build_config_yaml` to keep the output
/// file as small as the user's actual flag set.
fn prune_empty(value: &mut serde_yaml::Value) {
    use serde_yaml::Value;
    match value {
        Value::Mapping(map) => {
            let keys: Vec<_> = map.keys().cloned().collect();
            for k in keys {
                if let Some(v) = map.get_mut(&k) {
                    prune_empty(v);
                    let drop = match v {
                        Value::Null => true,
                        Value::Sequence(s) => s.is_empty(),
                        Value::Mapping(m) => m.is_empty(),
                        _ => false,
                    };
                    if drop {
                        map.remove(&k);
                    }
                }
            }
        }
        Value::Sequence(s) => {
            for v in s.iter_mut() {
                prune_empty(v);
            }
        }
        _ => {}
    }
}
