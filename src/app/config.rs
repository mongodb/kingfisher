//! Explicit project configuration loading and CLI precedence.

use anyhow::{Context, Result};
use kingfisher::cli::{self, GlobalArgs};
use tracing::info;

/// Resolve and read a `kingfisher.yaml` project config.
///
/// The config file is loaded **only** when the user passes `--config <PATH>`
/// explicitly. There is intentionally no auto-discovery — relying on a
/// `kingfisher.yaml` that happens to sit in the cwd (or any ancestor
/// directory) makes scan results depend on where the binary was invoked
/// from, which is too easy to get wrong in CI. If the explicit path is
/// missing or fails to parse, that is a fatal error.
pub(crate) fn load_project_config(
    explicit: Option<&std::path::Path>,
) -> Result<Option<kingfisher::cli::config::KingfisherConfig>> {
    let Some(p) = explicit else { return Ok(None) };
    let bytes = std::fs::read(p).with_context(|| format!("read config {}", p.display()))?;
    let yaml =
        String::from_utf8(bytes).with_context(|| format!("config {} is not UTF-8", p.display()))?;
    let cfg = kingfisher::cli::config::parse_str(&yaml)
        .with_context(|| format!("parse config {}", p.display()))?;
    info!("loaded config from {}", p.display());
    Ok(Some(cfg))
}

/// Merge config-file values into clap-parsed args.
///
/// **Lists/maps**: additive with CLI values. Configured rules replace Clap's
/// synthetic `all` selection when `--rule` was not explicitly supplied.
///
/// **Scalars**: applied only when the user did not pass the matching CLI
/// flag, detected via [`clap::ArgMatches::value_source`]. A `Some(_)` config
/// value still loses to a CLI-supplied flag or an explicit env-var, but wins
/// over a clap `default_value_t`. This preserves precedence
/// **CLI > env > config > built-in default**.
pub(crate) fn apply_config(
    scan_args: &mut cli::commands::scan::ScanArgs,
    global_args: &mut GlobalArgs,
    cfg: &kingfisher::cli::config::KingfisherConfig,
    scan_matches: Option<&clap::ArgMatches>,
) {
    use clap::parser::ValueSource;

    /// True when the named arg was either absent or filled in with its clap
    /// default — i.e. the user did not pass `--<flag>` on the CLI and did
    /// not set its `env = ...`. In those cases the config value should win.
    fn config_wins(matches: Option<&clap::ArgMatches>, id: &str) -> bool {
        matches!(matches.and_then(|m| m.value_source(id)), None | Some(ValueSource::DefaultValue))
    }

    /// Like `config_wins`, but also inspects a nested provider subcommand's
    /// `--api-url` flag. The github/gitlab provider subcommands carry their
    /// own `api_url` arg (id `api_url`) that gets propagated to
    /// `scan_args.input_specifier_args.{github,gitlab}_api_url` in
    /// `into_operation()`. If that nested flag was user-supplied, the config
    /// must NOT clobber it.
    fn api_url_config_wins(
        matches: Option<&clap::ArgMatches>,
        outer_id: &str,
        subcommand: &str,
    ) -> bool {
        if !config_wins(matches, outer_id) {
            return false;
        }
        let sub = matches.and_then(|m| m.subcommand_matches(subcommand));
        config_wins(sub, "api_url")
    }

    // ---------- Filters: existing v1 list-typed merges ----------------------
    scan_args.skip_word.extend(cfg.filters.skip_words.iter().cloned());
    scan_args.skip_regex.extend(cfg.filters.skip_regex.iter().cloned());
    scan_args.content_filtering_args.exclude.extend(cfg.filters.exclude.iter().cloned());

    // ---------- scan: behavioral scalars ------------------------------------
    if let Some(c) = cfg.scan.confidence
        && config_wins(scan_matches, "confidence")
    {
        scan_args.confidence = c.into();
    }
    if let Some(e) = cfg.scan.min_entropy
        && config_wins(scan_matches, "min_entropy")
    {
        scan_args.min_entropy = Some(e);
    }
    if let Some(v) = cfg.scan.no_validate
        && config_wins(scan_matches, "no_validate")
    {
        scan_args.no_validate = v;
    }
    if let Some(v) = cfg.scan.only_valid
        && config_wins(scan_matches, "only_valid")
        && config_wins(scan_matches, "validation_filter")
    {
        scan_args.only_valid = v;
    }
    if let Some(v) = cfg.scan.validation_filter
        && config_wins(scan_matches, "validation_filter")
        && config_wins(scan_matches, "only_valid")
    {
        scan_args.validation_filter = Some(v);
    }
    if let Some(v) = cfg.scan.redact
        && config_wins(scan_matches, "redact")
    {
        scan_args.redact = v;
    }
    if let Some(v) = cfg.scan.no_dedup
        && config_wins(scan_matches, "no_dedup")
    {
        scan_args.no_dedup = v;
    }
    if let Some(v) = cfg.scan.turbo
        && config_wins(scan_matches, "turbo")
    {
        scan_args.turbo = v;
    }
    if let Some(v) = cfg.scan.no_base64
        && config_wins(scan_matches, "no_base64")
    {
        scan_args.no_base64 = v;
    }
    if let Some(v) = cfg.scan.access_map
        && config_wins(scan_matches, "access_map")
    {
        scan_args.access_map = v;
    }
    if let Some(v) = cfg.scan.rule_stats
        && config_wins(scan_matches, "rule_stats")
    {
        scan_args.rule_stats = v;
    }
    if let Some(j) = cfg.scan.jobs
        && config_wins(scan_matches, "num_jobs")
    {
        scan_args.num_jobs = j;
    }
    if let Some(value) = cfg.scan.no_limits
        && config_wins(scan_matches, "no_limits")
    {
        scan_args.content_filtering_args.no_limits = value;
    }
    if let Some(t) = cfg.scan.git_repo_timeout
        && config_wins(scan_matches, "git_repo_timeout")
    {
        scan_args.git_repo_timeout = t;
    }

    // ---------- rules ------------------------------------------------------
    // Explicit CLI rule selections and config selections are additive. Replace
    // Clap's synthetic `all` default so the config can narrow the selected rules.
    if !cfg.rules.enabled.is_empty() {
        if config_wins(scan_matches, "rule") {
            // Replace the synthetic clap default with the config selection.
            scan_args.rules.rule = cfg.rules.enabled.clone();
        } else {
            scan_args.rules.rule.extend(cfg.rules.enabled.iter().cloned());
        }
    }
    scan_args.rules.rules_path.extend(cfg.rules.paths.iter().cloned());
    scan_args.rules.exclude_rule.extend(cfg.rules.disabled.iter().cloned());
    if let Some(v) = cfg.rules.load_builtins
        && config_wins(scan_matches, "load_builtins")
    {
        scan_args.rules.load_builtins = v;
    }
    if let Some(v) = cfg.rules.cache
        && config_wins(scan_matches, "rule_cache")
        && config_wins(scan_matches, "no_rule_cache")
    {
        scan_args.rule_cache.rule_cache = v;
        scan_args.rule_cache.no_rule_cache = !v;
    }
    if let Some(path) = &cfg.rules.cache_dir
        && config_wins(scan_matches, "rule_cache_dir")
    {
        scan_args.rule_cache.rule_cache_dir = Some(path.clone());
    }

    // ---------- validation -------------------------------------------------
    if let Some(t) = cfg.validation.timeout
        && config_wins(scan_matches, "validation_timeout")
    {
        scan_args.validation_timeout = t;
    }
    if let Some(r) = cfg.validation.retries
        && config_wins(scan_matches, "validation_retries")
    {
        scan_args.validation_retries = r;
    }
    if let Some(rps) = cfg.validation.rps
        && config_wins(scan_matches, "validation_rps")
    {
        scan_args.validation_rps = Some(rps);
    }
    for (rule, rps) in &cfg.validation.rps_per_rule {
        scan_args.validation_rps_rule.push(format!("{rule}={rps}"));
    }
    if let Some(v) = cfg.validation.full_response
        && config_wins(scan_matches, "full_validation_response")
    {
        scan_args.full_validation_response = v;
    }
    if let Some(n) = cfg.validation.max_response_length
        && config_wins(scan_matches, "max_validation_response_length")
    {
        scan_args.max_validation_response_length = n;
    }

    // ---------- filters (v2 scalars + extra additive lists) ----------------
    if let Some(mb) = cfg.filters.max_file_size_mb
        && config_wins(scan_matches, "max_file_size_mb")
    {
        scan_args.content_filtering_args.max_file_size_mb = mb;
    }
    if let Some(v) = cfg.filters.no_binary
        && config_wins(scan_matches, "no_binary")
    {
        scan_args.content_filtering_args.no_binary = v;
    }
    if let Some(v) = cfg.filters.no_extract_archives
        && config_wins(scan_matches, "no_extract_archives")
    {
        scan_args.content_filtering_args.no_extract_archives = v;
    }
    if let Some(d) = cfg.filters.extraction_depth
        && config_wins(scan_matches, "extraction_depth")
    {
        scan_args.content_filtering_args.extraction_depth = d;
    }
    if let Some(v) = cfg.filters.no_inline_ignore
        && config_wins(scan_matches, "no_inline_ignore")
    {
        scan_args.no_inline_ignore = v;
    }
    if let Some(v) = cfg.filters.no_ignore_if_contains
        && config_wins(scan_matches, "no_ignore_if_contains")
    {
        scan_args.no_ignore_if_contains = v;
    }
    scan_args.extra_ignore_comments.extend(cfg.filters.extra_ignore_comments.iter().cloned());
    scan_args.skip_aws_account.extend(cfg.filters.skip_aws_accounts.iter().cloned());
    if let Some(p) = &cfg.filters.skip_aws_account_file
        && config_wins(scan_matches, "skip_aws_account_file")
    {
        scan_args.skip_aws_account_file = Some(p.clone());
    }

    // ---------- output -----------------------------------------------------
    if let Some(f) = cfg.output.format
        && config_wins(scan_matches, "format")
    {
        scan_args.output_args.format = f.into();
    }
    if let Some(p) = &cfg.output.path
        && config_wins(scan_matches, "output")
    {
        scan_args.output_args.output = Some(p.clone());
    }

    // ---------- baseline ---------------------------------------------------
    if let Some(p) = &cfg.baseline.file
        && config_wins(scan_matches, "baseline_file")
    {
        scan_args.baseline_file = Some(p.clone());
    }
    if let Some(v) = cfg.baseline.manage
        && config_wins(scan_matches, "manage_baseline")
    {
        scan_args.manage_baseline = v;
    }

    // ---------- alerts.defaults: feed the global --alert-* fields ----------
    if let Some(f) = cfg.alerts.defaults.format
        && config_wins(scan_matches, "alert_format")
    {
        scan_args.alert_format = Some(f);
    }
    if let Some(o) = cfg.alerts.defaults.on
        && config_wins(scan_matches, "alert_on")
    {
        scan_args.alert_on = o;
    }
    if let Some(c) = cfg.alerts.defaults.min_confidence
        && config_wins(scan_matches, "alert_min_confidence")
    {
        scan_args.alert_min_confidence = c.into();
    }
    if let Some(v) = cfg.alerts.defaults.include_secret
        && config_wins(scan_matches, "alert_include_secret")
    {
        scan_args.alert_include_secret = v;
    }
    if let Some(u) = &cfg.alerts.defaults.report_url
        && config_wins(scan_matches, "alert_report_url")
    {
        scan_args.alert_report_url = Some(u.clone());
    }
    if let Some(d) = cfg.alerts.defaults.detail
        && config_wins(scan_matches, "alert_detail")
    {
        scan_args.alert_detail = d;
    }
    if let Some(f) = cfg.alerts.defaults.finding_filter
        && config_wins(scan_matches, "alert_finding_filter")
    {
        scan_args.alert_finding_filter = f;
    }
    if let Some(v) = cfg.alerts.defaults.prevent_empty
        && config_wins(scan_matches, "alert_prevent_empty")
    {
        scan_args.alert_prevent_empty = v;
    }

    // ---------- alerts.webhooks: append URLs (existing v1 behavior) --------
    for w in &cfg.alerts.webhooks {
        scan_args.alert_webhook.push(w.url.clone());
        scan_args.config_webhook_overrides.push(
            kingfisher::cli::commands::scan::ConfigWebhookOverride {
                format: w.format,
                on: w.on,
                min_confidence: w.min_confidence.map(Into::into),
                include_secret: w.include_secret,
                report_url: w.report_url.clone(),
                detail: w.detail,
                finding_filter: w.finding_filter,
                prevent_empty: w.prevent_empty,
            },
        );
    }

    // ---------- global -----------------------------------------------------
    if let Some(m) = cfg.global.tls_mode
        && config_wins(scan_matches, "tls_mode")
    {
        global_args.tls_mode = m.into();
    }
    if let Some(v) = cfg.global.allow_internal_ips
        && config_wins(scan_matches, "allow_internal_ips")
    {
        global_args.allow_internal_ips = v;
    }
    if let Some(v) = cfg.global.no_update_check
        && config_wins(scan_matches, "no_update_check")
    {
        global_args.no_update_check = v;
    }
    if let Some(s) = &cfg.global.user_agent_suffix
        && config_wins(scan_matches, "user_agent_suffix")
    {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            global_args.user_agent_suffix = Some(trimmed.to_string());
        }
    }
    global_args.endpoint.extend(cfg.global.endpoints.iter().cloned());
    if let Some(p) = &cfg.global.endpoint_config
        && config_wins(scan_matches, "endpoint_config")
    {
        global_args.endpoint_config = Some(p.clone());
    }

    // ---------- git --------------------------------------------------------
    if let Some(p) = &cfg.git.clone_dir
        && config_wins(scan_matches, "git_clone_dir")
    {
        scan_args.input_specifier_args.git_clone_dir = Some(p.clone());
    }
    if let Some(v) = cfg.git.keep_clones
        && config_wins(scan_matches, "keep_clones")
    {
        scan_args.input_specifier_args.keep_clones = v;
    }
    if let Some(n) = cfg.git.repo_clone_limit
        && config_wins(scan_matches, "repo_clone_limit")
    {
        scan_args.input_specifier_args.repo_clone_limit = Some(n);
    }
    if let Some(v) = cfg.git.include_contributors
        && config_wins(scan_matches, "include_contributors")
    {
        scan_args.input_specifier_args.include_contributors = v;
    }
    // Provider API roots for enumeration / cloning. We accept the YAML value
    // as `String` (the schema serializer keeps it stable across `Url`'s
    // trailing-slash normalization), then parse to a `Url` for the runtime
    // field. parse_str() already validated this — `unwrap_or_default()`
    // would mask a real config bug, so we re-parse and *fail loud* if the
    // string somehow does not parse here.
    //
    // The provider subcommands (`scan github`, `scan gitlab`) expose their
    // own `--api-url` flag whose value is propagated into the same runtime
    // field by `into_operation()`. `api_url_config_wins` checks both the
    // outer hidden alias and the nested subcommand flag so an explicit
    // `kingfisher scan github --api-url ...` is never overridden by the
    // config file.
    if let Some(u) = &cfg.git.github_api_url
        && api_url_config_wins(scan_matches, "github_api_url", "github")
    {
        scan_args.input_specifier_args.github_api_url =
            url::Url::parse(u).expect("git.github_api_url validated in parse_str");
    }
    if let Some(u) = &cfg.git.gitlab_api_url
        && api_url_config_wins(scan_matches, "gitlab_api_url", "gitlab")
    {
        scan_args.input_specifier_args.gitlab_api_url =
            url::Url::parse(u).expect("git.gitlab_api_url validated in parse_str");
    }
}
