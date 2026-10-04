//! End-to-end precedence tests for `apply_config` — confirm that:
//!   * a user-supplied `--flag` always wins over a config-file value, and
//!   * a config-file value wins over the clap `default_value_t` when the
//!     user did not pass the flag.
//!
//! The test parses a real `ArgMatches` via clap so the same code path
//! `value_source` reads from is exercised.

use std::path::PathBuf;

use clap::{ArgMatches, CommandFactory, FromArgMatches};
use kingfisher::cli::CommandLineArgs;
use kingfisher::cli::commands::output::ReportOutputFormat;
use kingfisher::cli::commands::scan::{ConfidenceLevel, ScanOperation};
use kingfisher::cli::config::{KingfisherConfig, parse_str};
use kingfisher::cli::global::Command;

fn parse(argv: &[&str]) -> (CommandLineArgs, ArgMatches) {
    let matches = CommandLineArgs::command().try_get_matches_from(argv).expect("argv should parse");
    let args = CommandLineArgs::from_arg_matches(&matches).unwrap();
    (args, matches)
}

fn into_scan(args: CommandLineArgs) -> kingfisher::cli::commands::scan::ScanArgs {
    let cmd = match args.command {
        Command::Scan(c) => c,
        _ => panic!("expected scan subcommand"),
    };
    match cmd.into_operation().unwrap() {
        ScanOperation::Scan(s) => s,
        ScanOperation::ListRepositories(_) => panic!("expected scan op"),
    }
}

#[test]
fn non_interactive_git_url_does_not_stage_stdin() {
    let (args, _) = parse(&["kingfisher", "scan", "github.com/octocat/Hello-World"]);
    let scan_args = into_scan(args);

    assert!(scan_args.input_specifier_args.path_inputs.is_empty());
    assert!(!scan_args.input_specifier_args.git_url.is_empty());
    assert!(!super::should_stage_stdin(&scan_args.input_specifier_args, false));
}

#[test]
fn non_interactive_path_target_does_not_stage_stdin() {
    let (args, _) = parse(&["kingfisher", "scan", "."]);
    let scan_args = into_scan(args);

    assert!(!super::should_stage_stdin(&scan_args.input_specifier_args, false));
}

#[test]
fn dash_stages_stdin_only_when_stdin_is_redirected() {
    let (args, _) = parse(&["kingfisher", "scan", "-"]);
    let scan_args = into_scan(args);

    assert!(super::should_stage_stdin(&scan_args.input_specifier_args, false));
    assert!(!super::should_stage_stdin(&scan_args.input_specifier_args, true));
}

#[test]
fn github_event_user_file_cannot_alias_audit_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users.txt");
    let path = path.to_str().unwrap();
    let (args, _) = parse(&[
        "kingfisher",
        "scan",
        "github",
        "--public-events",
        "--user-file",
        path,
        "--audit-log",
        path,
    ]);

    let command = match args.command {
        Command::Scan(command) => command,
        _ => panic!("expected scan subcommand"),
    };
    assert!(command.into_operation().is_err());
}

#[test]
fn staging_stdin_keeps_sibling_paths_and_collapses_repeats() {
    let stdin_file = PathBuf::from("/tmp/kf/stdin_input");
    let mut path_inputs = vec![
        PathBuf::from("-"),
        PathBuf::from("./src"),
        PathBuf::from("-"),
        PathBuf::from("./tests"),
    ];

    super::replace_stdin_placeholders(&mut path_inputs, stdin_file.clone());

    assert_eq!(path_inputs, vec![stdin_file, PathBuf::from("./src"), PathBuf::from("./tests")]);
}

#[test]
fn no_limits_round_trips_and_overrides_individual_budgets() {
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        ".",
        "--no-limits",
        "--max-file-size=1",
        "--extraction-depth=1",
    ]);
    let global = args.global_args.clone();
    let scan = into_scan(args);
    let yaml =
        super::build_config_yaml(&scan, &global, matches.subcommand_matches("scan").unwrap())
            .unwrap();
    let config = parse_str(&yaml).unwrap();
    assert_eq!(config.scan.no_limits, Some(true));
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global = args.global_args.clone();
    let mut scan = into_scan(args);
    super::apply_config(&mut scan, &mut global, &config, matches.subcommand_matches("scan"));
    assert_eq!(scan.content_filtering_args.max_file_size_mb, 1.0);
    assert_eq!(scan.content_filtering_args.max_file_size_bytes(), None);
    assert_eq!(scan.content_filtering_args.archive_depth(), None);
}

#[test]
fn config_wins_when_cli_uses_default() {
    let yaml = r#"
scan:
  confidence: high
  redact: true
output:
  format: json
"#;
    let cfg: KingfisherConfig = parse_str(yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(scan_args.confidence, ConfidenceLevel::High);
    assert!(scan_args.redact);
    assert_eq!(scan_args.output_args.format, ReportOutputFormat::Json);
}

#[test]
fn config_output_path_colliding_with_audit_log_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let path_str = path.display().to_string();
    let yaml = format!(
        r#"
output:
  path: {path_str}
"#
    );
    let cfg: KingfisherConfig = parse_str(&yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "--audit-log", &path_str, "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);

    // CLI-only validation passes: the config has not been merged yet, so
    // `output_args.output` is still unset.
    assert!(scan_args.validate_audit_log_collisions(None, None).is_ok());

    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(scan_args.output_args.output.as_deref(), Some(path.as_path()));

    // After merging, the effective --output collides with --audit-log.
    assert!(scan_args.validate_audit_log_collisions(None, None).is_err());
}

#[test]
fn audit_log_colliding_with_baseline_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("baseline-file.yaml");
    let path_str = path.display().to_string();

    // An explicit --baseline-file aliasing --audit-log is rejected during
    // CLI validation, before any file is opened.
    let (args, _) =
        parse(&["kingfisher", "scan", "--audit-log", &path_str, "--baseline-file", &path_str, "."]);
    let cmd = match args.command {
        Command::Scan(c) => c,
        _ => panic!("expected scan subcommand"),
    };
    assert!(cmd.into_operation().is_err());

    // The managed-baseline default is protected too (resolved against the
    // working directory, so the collision is expressed relatively here).
    let (args, _) = parse(&[
        "kingfisher",
        "scan",
        "--audit-log",
        "baseline-file.yaml",
        "--manage-baseline",
        ".",
    ]);
    let cmd = match args.command {
        Command::Scan(c) => c,
        _ => panic!("expected scan subcommand"),
    };
    assert!(cmd.into_operation().is_err());

    // Without baseline operations the default path is not state.
    let (args, _) = parse(&["kingfisher", "scan", "--audit-log", &path_str, "."]);
    let scan_args = into_scan(args);
    assert!(scan_args.validate_audit_log_collisions(None, None).is_ok());
}

#[test]
fn audit_log_tilde_path_is_expanded_for_collision_checks() {
    // Shells do not expand `~` in the `--flag=~/...` form; the audit-log
    // path must still collide with the same file spelled the way
    // Kingfisher expands it. The output is computed with the product's
    // own tilde expansion so the test does not depend on which of
    // HOME/USERPROFILE the platform resolves first. The scan input stays
    // outside the working directory so only the tilde expansion can
    // produce the collision.
    let expanded =
        kingfisher::util::expand_tilde(std::path::Path::new("~/kf-audit-collision.jsonl"));
    let input = tempfile::tempdir().unwrap();
    let (args, _) = parse(&[
        "kingfisher",
        "scan",
        "--audit-log=~/kf-audit-collision.jsonl",
        "--output",
        expanded.to_str().unwrap(),
        input.path().to_str().unwrap(),
    ]);
    let cmd = match args.command {
        Command::Scan(c) => c,
        _ => panic!("expected scan subcommand"),
    };
    assert!(cmd.into_operation().is_err());
}

#[test]
fn audit_log_colliding_with_endpoint_config_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("endpoints.yaml");
    let path_str = path.display().to_string();
    let (args, _) = parse(&["kingfisher", "scan", "--audit-log", &path_str, "."]);
    let scan_args = into_scan(args);

    assert!(scan_args.validate_audit_log_collisions(None, None).is_ok());
    assert!(scan_args.validate_audit_log_collisions(Some(&path), None).is_err());
}

#[test]
fn audit_log_colliding_with_project_config_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kingfisher.yaml");
    let path_str = path.display().to_string();
    let (args, _) = parse(&["kingfisher", "scan", "--audit-log", &path_str, "."]);
    let scan_args = into_scan(args);

    assert!(scan_args.validate_audit_log_collisions(None, None).is_ok());
    assert!(scan_args.validate_audit_log_collisions(None, Some(&path)).is_err());
}

#[test]
fn cli_beats_config_for_scalars() {
    let yaml = r#"
scan:
  confidence: high
  redact: true
output:
  format: json
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) =
        parse(&["kingfisher", "scan", "--confidence", "low", "--format", "toon", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    // CLI wins
    assert_eq!(scan_args.confidence, ConfidenceLevel::Low);
    assert_eq!(scan_args.output_args.format, ReportOutputFormat::Toon);
    // Bool with no CLI flag still picks up config
    assert!(scan_args.redact);
}

#[test]
fn lists_are_concatenated_with_cli() {
    let yaml = r#"
filters:
  skip_words: ["FROM_CONFIG"]
  exclude: ["vendor/"]
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        "--skip-word",
        "FROM_CLI",
        "--exclude",
        "node_modules/",
        ".",
    ]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(scan_args.skip_word.contains(&"FROM_CLI".to_string()));
    assert!(scan_args.skip_word.contains(&"FROM_CONFIG".to_string()));
    assert!(scan_args.content_filtering_args.exclude.contains(&"vendor/".to_string()));
    assert!(scan_args.content_filtering_args.exclude.contains(&"node_modules/".to_string()));
}

#[test]
fn rules_enabled_replaces_default_but_appends_to_user_selection() {
    // Case A: user passes --rule, config appends.
    let yaml = r#"
rules:
  enabled: ["custom"]
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "--rule", "default", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(scan_args.rules.rule.contains(&"default".to_string()));
    assert!(scan_args.rules.rule.contains(&"custom".to_string()));

    // Case B: user did not pass --rule (CLI default `["all"]` in effect),
    // config replaces — otherwise users could never *narrow* the
    // selection from the config.
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(scan_args.rules.rule, vec!["custom".to_string()]);
}

#[test]
fn rules_disabled_is_concatenated_with_cli_exclusions() {
    let yaml = r#"
rules:
  disabled: ["betterleaks.github-pat"]
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) =
        parse(&["kingfisher", "scan", "--exclude-rule", "betterleaks.openai-api-key", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));

    assert_eq!(
        scan_args.rules.exclude_rule,
        vec!["betterleaks.openai-api-key".to_string(), "betterleaks.github-pat".to_string()]
    );
}

#[test]
fn cli_rule_and_exclude_rule_flags_are_repeated_and_preserved() {
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        "--rule",
        "betterleaks.github-pat",
        "--rule",
        "betterleaks.github-fine-grained-pat",
        "--exclude-rule",
        "betterleaks.openai-api-key",
        "--exclude-rule",
        "custom.openai.secondary",
        ".",
    ]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(
        &mut scan_args,
        &mut global_args,
        &kingfisher::cli::config::KingfisherConfig::default(),
        matches.subcommand_matches("scan"),
    );

    assert_eq!(
        scan_args.rules.rule,
        vec![
            "betterleaks.github-pat".to_string(),
            "betterleaks.github-fine-grained-pat".to_string(),
        ]
    );
    assert_eq!(
        scan_args.rules.exclude_rule,
        vec!["betterleaks.openai-api-key".to_string(), "custom.openai.secondary".to_string()]
    );
}

#[test]
fn rule_cache_config_and_cli_precedence_respects_opt_out() {
    let cfg = parse_str(
        r#"
rules:
  cache: false
"#,
    )
    .unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(!scan_args.rule_cache.enabled(), "config rules.cache=false should disable cache");

    let cfg = parse_str(
        r#"
rules:
  cache: true
"#,
    )
    .unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "--no-rule-cache", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(!scan_args.rule_cache.enabled(), "CLI --no-rule-cache should beat config");

    let cfg = parse_str(
        r#"
rules:
  cache: false
"#,
    )
    .unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "--rule-cache", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(scan_args.rule_cache.enabled(), "CLI --rule-cache should beat config");
}

#[test]
fn validation_rps_per_rule_appended_as_strings() {
    let yaml = r#"
validation:
  rps_per_rule:
    betterleaks.aws: 1.5
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) =
        parse(&["kingfisher", "scan", "--validation-rps-rule", "betterleaks.gcp=2.0", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert!(scan_args.validation_rps_rule.contains(&"betterleaks.gcp=2.0".to_string()));
    assert!(scan_args.validation_rps_rule.contains(&"betterleaks.aws=1.5".to_string()));
}

#[test]
fn alerts_defaults_set_alert_globals_when_cli_default() {
    let yaml = r#"
alerts:
  defaults:
    min_confidence: high
    include_secret: true
    detail: summary
    finding_filter: only-active
    prevent_empty: true
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(scan_args.alert_min_confidence, ConfidenceLevel::High);
    assert!(scan_args.alert_include_secret);
    assert_eq!(scan_args.alert_detail, kingfisher::alerts::AlertDetail::Summary);
    assert_eq!(scan_args.alert_finding_filter, kingfisher::alerts::AlertFindingFilter::OnlyActive);
    assert!(scan_args.alert_prevent_empty);
}

#[test]
fn cli_alert_flag_beats_config_default() {
    let yaml = r#"
alerts:
  defaults:
    min_confidence: high
    finding_filter: access-map-only
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        "--alert-min-confidence",
        "low",
        "--alert-finding-filter",
        "exclude-inactive",
        ".",
    ]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(scan_args.alert_min_confidence, ConfidenceLevel::Low);
    assert_eq!(
        scan_args.alert_finding_filter,
        kingfisher::alerts::AlertFindingFilter::ExcludeInactive
    );
}

#[test]
fn config_init_round_trips_supplied_flags_only() {
    // Take a CLI invocation, build a YAML config, parse it back, and
    // check that the resulting KingfisherConfig has *only* what we passed
    // (CLI defaults must not be reified into the config — that would
    // freeze an arbitrary moment in time as a "user choice").
    use kingfisher::cli::config::{ConfigConfidence, ConfigReportFormat, parse_str};

    let argv = &[
        "kingfisher",
        "config",
        "init",
        "--confidence",
        "high",
        "--redact",
        "--exclude",
        "vendor/",
        "--skip-word",
        "EXAMPLE",
        "--exclude-rule",
        "betterleaks.github-pat",
        "--format",
        "toon",
        "--alert-min-confidence",
        "high",
        "--alert-webhook",
        "https://hooks.slack.com/services/T0/B0/AAA",
        "--tls-mode",
        "lax",
    ];
    let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
    let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
    let global_args = parsed.global_args.clone();

    let init_matches =
        matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();

    // Recover the ScanArgs from the parsed `Config(Init(...))` branch.
    let scan_args = match parsed.command {
        Command::Config(c) => match c.command {
            kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                args.scan_args
            }
        },
        _ => panic!("expected config init"),
    };

    let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
    let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");

    // Exact set of keys that should be present.
    assert!(matches!(cfg.scan.confidence, Some(ConfigConfidence::High)));
    assert_eq!(cfg.scan.redact, Some(true));
    assert!(cfg.scan.no_dedup.is_none(), "should not emit unset bools");
    assert!(cfg.scan.jobs.is_none(), "should not emit clap-default scalars");

    assert_eq!(cfg.filters.exclude, vec!["vendor/".to_string()]);
    assert_eq!(cfg.filters.skip_words, vec!["EXAMPLE".to_string()]);
    assert!(cfg.filters.max_file_size_mb.is_none(), "should not emit unset filters");
    assert_eq!(cfg.rules.disabled, vec!["betterleaks.github-pat".to_string()]);

    assert!(matches!(cfg.output.format, Some(ConfigReportFormat::Toon)));
    assert!(cfg.output.path.is_none());

    assert!(matches!(cfg.alerts.defaults.min_confidence, Some(ConfigConfidence::High)));
    assert_eq!(cfg.alerts.webhooks.len(), 1);
    assert_eq!(cfg.alerts.webhooks[0].url, "https://hooks.slack.com/services/T0/B0/AAA");

    assert!(matches!(cfg.global.tls_mode, Some(kingfisher::cli::config::ConfigTlsMode::Lax)));
}

/// Regression: `config init --github-api-url ... --gitlab-api-url ...`
/// must round-trip the strings the user typed. `Url::to_string()` adds
/// a trailing `/` to bare-host URLs, so re-serializing the parsed `Url`
/// would silently rewrite `https://gitlab.example.com` →
/// `https://gitlab.example.com/` on every `config init` run.
#[test]
fn config_init_preserves_raw_api_url_strings() {
    use kingfisher::cli::config::parse_str;

    let argv = &[
        "kingfisher",
        "config",
        "init",
        // Bare host (no trailing slash) — `Url::to_string()` would add one.
        "--github-api-url",
        "https://ghe.corp.example.com/api/v3",
        "--gitlab-api-url",
        "https://gitlab.corp.example.com",
    ];
    let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
    let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
    let global_args = parsed.global_args.clone();
    let init_matches =
        matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();
    let scan_args = match parsed.command {
        Command::Config(c) => match c.command {
            kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                args.scan_args
            }
        },
        _ => panic!("expected config init"),
    };

    let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
    let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");

    assert_eq!(
        cfg.git.github_api_url.as_deref(),
        Some("https://ghe.corp.example.com/api/v3"),
        "github_api_url must preserve user input verbatim, no trailing-slash rewrite",
    );
    assert_eq!(
        cfg.git.gitlab_api_url.as_deref(),
        Some("https://gitlab.corp.example.com"),
        "gitlab_api_url must preserve user input verbatim, no trailing-slash rewrite",
    );

    // Sanity: when the user *does* pass a trailing slash, that's preserved too.
    let argv = &[
        "kingfisher",
        "config",
        "init",
        "--github-api-url",
        "https://ghe.corp.example.com/api/v3/",
    ];
    let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
    let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
    let global_args = parsed.global_args.clone();
    let init_matches =
        matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();
    let scan_args = match parsed.command {
        Command::Config(c) => match c.command {
            kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                args.scan_args
            }
        },
        _ => panic!("expected config init"),
    };
    let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
    let cfg = parse_str(&yaml).expect("emitted YAML must round-trip");
    assert_eq!(
        cfg.git.github_api_url.as_deref(),
        Some("https://ghe.corp.example.com/api/v3/"),
        "github_api_url must preserve a user-supplied trailing slash",
    );
}

#[test]
fn config_init_with_no_flags_emits_placeholder_comment() {
    // Edge case: user runs `kingfisher config init` with no flags. The
    // emitted file should still be valid YAML / a clear no-op rather
    // than a bare `{}`.
    let argv = &["kingfisher", "config", "init"];
    let matches = CommandLineArgs::command().try_get_matches_from(argv).unwrap();
    let parsed = CommandLineArgs::from_arg_matches(&matches).unwrap();
    let global_args = parsed.global_args.clone();

    let init_matches =
        matches.subcommand_matches("config").unwrap().subcommand_matches("init").unwrap();

    let scan_args = match parsed.command {
        Command::Config(c) => match c.command {
            kingfisher::cli::commands::config_command::ConfigSubcommand::Init(args) => {
                args.scan_args
            }
        },
        _ => panic!("expected config init"),
    };

    let yaml = super::build_config_yaml(&scan_args, &global_args, init_matches).unwrap();
    assert!(yaml.contains("no flags supplied"), "expected no-op header, got:\n{yaml}");
    assert!(!yaml.trim().ends_with("{}"));
}

#[test]
fn global_section_updates_global_args_when_cli_default() {
    let yaml = r#"
global:
  tls_mode: lax
  allow_internal_ips: true
  endpoints:
    - github=https://ghe.example.com/api/v3/
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "."]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(global_args.tls_mode, kingfisher::cli::global::TlsMode::Lax);
    assert!(global_args.allow_internal_ips);
    assert_eq!(global_args.endpoint.len(), 1);
}

/// Regression test: an explicit `--api-url` on the `scan github`
/// subcommand must beat `git.github_api_url` from the config file. The
/// flag lives on `GithubScanArgs` (id `api_url`), not on the outer scan
/// command — checking only the outer matches misses it and the config
/// silently overrode the CLI value.
#[test]
fn github_subcommand_api_url_beats_config() {
    let yaml = r#"
git:
  github_api_url: https://ghe-from-config.example.com/api/v3/
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        "github",
        "--organization",
        "my-org",
        "--api-url",
        "https://ghe-from-cli.example.com/api/v3/",
    ]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(
        scan_args.input_specifier_args.github_api_url.as_str(),
        "https://ghe-from-cli.example.com/api/v3/",
    );
}

/// And the inverse: when the user did NOT pass `--api-url` at all,
/// `git.github_api_url` from the config should still win over the
/// built-in default `https://api.github.com/`.
#[test]
fn github_config_wins_when_subcommand_api_url_default() {
    let yaml = r#"
git:
  github_api_url: https://ghe-from-config.example.com/api/v3/
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&["kingfisher", "scan", "github", "--organization", "my-org"]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(
        scan_args.input_specifier_args.github_api_url.as_str(),
        "https://ghe-from-config.example.com/api/v3/",
    );
}

/// Same precedence story for `scan gitlab --api-url`.
#[test]
fn gitlab_subcommand_api_url_beats_config() {
    let yaml = r#"
git:
  gitlab_api_url: https://gitlab-from-config.example.com/
"#;
    let cfg = parse_str(yaml).unwrap();
    let (args, matches) = parse(&[
        "kingfisher",
        "scan",
        "gitlab",
        "--group",
        "my-group",
        "--api-url",
        "https://gitlab-from-cli.example.com/",
    ]);
    let mut global_args = args.global_args.clone();
    let mut scan_args = into_scan(args);
    super::apply_config(&mut scan_args, &mut global_args, &cfg, matches.subcommand_matches("scan"));
    assert_eq!(
        scan_args.input_specifier_args.gitlab_api_url.as_str(),
        "https://gitlab-from-cli.example.com/",
    );
}

#[test]
fn conflicting_config_filters_report_the_config_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conflicting.yaml");
    std::fs::write(&path, "scan:\n  only_valid: true\n  validation_filter: actionable\n").unwrap();
    let error = super::load_project_config(Some(&path)).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains(&path.display().to_string()));
    assert!(message.contains("scan.only_valid and scan.validation_filter cannot both be set"));
}
