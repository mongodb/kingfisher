use std::{path::Path, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;

fn check_rule_file(path: &Path, extra_args: &[&str]) -> assert_cmd::assert::Assert {
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["rules", "check", "--no-update-check", "--load-builtins=false", "--rules-path"])
        .arg(path)
        .args(extra_args)
        .assert()
}

fn check_custom_rule(
    pattern: &str,
    options: &str,
    examples: &[&str],
    negative_examples: &[&str],
) -> assert_cmd::assert::Assert {
    check_custom_rule_with_args(pattern, options, examples, negative_examples, &[])
}

fn check_custom_rule_with_args(
    pattern: &str,
    options: &str,
    examples: &[&str],
    negative_examples: &[&str],
    extra_args: &[&str],
) -> assert_cmd::assert::Assert {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.yml");
    std::fs::write(
        &path,
        format!(
            "rules:\n  - id: custom.check\n    name: Check Examples\n    confidence: medium\n    pattern: {}\n    examples: {}\n    negative_examples: {}\n{}",
            serde_json::to_string(pattern).unwrap(),
            serde_json::to_string(examples).unwrap(),
            serde_json::to_string(negative_examples).unwrap(),
            options,
        ),
    )
    .unwrap();
    check_rule_file(&path, extra_args)
}

#[test]
fn check_rules() -> anyhow::Result<()> {
    // ── run kingfisher ────────────────────────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "rules",
            "check",
            "--no-update-check", // skip update check to avoid network calls
        ])
        .assert()
        .code(0) // no findings present
        .stdout(
            predicate::str::contains("All rules passed validation successfully")
                .or(predicate::str::contains("Errors: 0")),
        );

    Ok(())
}

#[test]
fn check_rules_rejects_matching_negative_examples_even_without_positive_examples() {
    check_custom_rule("token=([A-Za-z0-9]+)", "", &[], &["token=Q7m2V9r4T8p5N6c3"])
        .code(1)
        .stdout(predicate::str::contains("Negative example unexpectedly matched"))
        .stdout(predicate::str::contains("custom.check"))
        .stdout(predicate::str::contains("Processing negative example 1"))
        .stdout(predicate::str::contains("Errors: 1"));
}

#[test]
fn check_rules_rejects_positive_pattern_mismatches() {
    check_custom_rule("token=([A-Za-z0-9]+)", "", &["not a token"], &[])
        .code(1)
        .stdout(predicate::str::contains("Pattern mismatch detected for example"))
        .stdout(predicate::str::contains("Regex match: false"))
        .stdout(predicate::str::contains("Errors: 1"));
}

#[test]
fn check_rules_applies_content_filters_to_both_example_kinds() {
    let cases = [
        ("    min_entropy: 3.0\n", "token=AAAAAA"),
        // Entropy equal to the threshold is rejected, just as during scanning.
        ("    min_entropy: 1.0\n", "token=ABABABAB"),
        ("", "token=Ab123456789Zx7Qp"),
        ("    pattern_requirements:\n      min_digits: 1\n", "token=QmVrTpNc"),
        (
            "    betterleaks_filter:\n      kind: bool\n      value: true\n",
            "token=Q7m2V9r4T8p5N6c3",
        ),
    ];
    for (options, filtered) in cases {
        check_custom_rule("token=([A-Za-z0-9]+)", options, &[filtered], &[])
            .code(1)
            .stdout(predicate::str::contains("Example rejected by scan-time filters"))
            .stdout(predicate::str::contains("Errors: 1"));
        check_custom_rule("token=([A-Za-z0-9]+)", options, &[], &[filtered, "not a token"])
            .success()
            .stdout(predicate::str::contains("Errors: 0"));
    }
}

#[test]
fn check_rules_uses_scan_time_capture_selection_for_entropy() {
    // Neither a high-entropy prefix nor another capture can rescue a low-entropy secret.
    for (pattern, options, example) in [
        ("Q7m2V9r4T8p5N6c3=([A-Za-z0-9]+)", "    min_entropy: 3.0\n", "Q7m2V9r4T8p5N6c3=AAAAAA"),
        (
            "(?P<context>[A-Za-z0-9]+)=(?P<TOKEN>[A-Za-z0-9]+)",
            "    min_entropy: 3.0\n",
            "Q7m2V9r4T8p5N6c3=AAAAAA",
        ),
        (
            "([A-Za-z0-9]+)=([A-Za-z0-9]+)",
            "    min_entropy: 3.0\n    betterleaks_secret_group: 2\n",
            "Q7m2V9r4T8p5N6c3=AAAAAA",
        ),
    ] {
        check_custom_rule(pattern, options, &[example], &[])
            .code(1)
            .stdout(predicate::str::contains("Example rejected by scan-time filters"));
    }
}

#[test]
fn check_rules_considers_all_matches_in_each_example() {
    let mixed = "token=AAAAAA token=Q7m2V9r4T8p5N6c3 trailing context";
    check_custom_rule("token=([A-Za-z0-9]+)", "    min_entropy: 3.0\n", &[mixed], &[])
        .success()
        .stdout(predicate::str::contains("All rules passed validation successfully"));
    check_custom_rule("token=([A-Za-z0-9]+)", "    min_entropy: 3.0\n", &[], &[mixed])
        .code(1)
        .stdout(predicate::str::contains("Negative example unexpectedly matched"));
}

#[test]
fn check_rules_keeps_examples_isolated_and_checks_every_example() {
    check_custom_rule(
        "token=([A-Za-z0-9]+)",
        "    min_entropy: 3.0\n",
        &["token=Q7m2V9r4T8p5N6c3", "token=Q7m2V9r4T8p5N6c3", "token=AAAAAA"],
        &["not a token", "token=Q7m2V9r4T8p5N6c3"],
    )
    .code(1)
    .stdout(predicate::str::contains("Processing example 3"))
    .stdout(predicate::str::contains("Processing negative example 2"))
    .stdout(predicate::str::contains("Errors: 2"));
}

#[test]
fn check_rules_uses_full_match_requirements_for_named_captures() {
    // Scanning checks character requirements on the full match for named/multiple captures.
    check_custom_rule(
        "version1=(?P<secret>[A-Za-z]+)",
        "    pattern_requirements:\n      min_digits: 1\n",
        &["version1=QmVrTpNc"],
        &["not a token"],
    )
    .success();
}

#[test]
fn check_rules_applies_checksum_requirements() {
    let options = "    pattern_requirements:\n      checksum:\n        actual:\n          template: '{{ MATCH | luhn_valid }}'\n        expected: 'true'\n";
    check_custom_rule("card=([0-9]+)", options, &["card=79927398713"], &["card=79927398714"])
        .success();
    check_custom_rule("card=([0-9]+)", options, &["card=79927398714"], &[])
        .code(1)
        .stdout(predicate::str::contains("Checksum validation failed for example"))
        .stdout(predicate::str::contains("Actual checksum length: 5, Expected checksum length: 4"));
}

#[test]
fn check_rules_preserves_custom_kingfisher_yaml_file_and_directory_loading() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let nested = dir.path().join("nested");
    std::fs::create_dir(&nested)?;
    let yml = dir.path().join("team.yml");
    std::fs::write(
        &yml,
        r#"rules:
  - id: kingfisher.acme.v1
    name: Acme Token
    pattern: |
      (?x)
      acme=([A-Za-z0-9$%^]+)
    min_entropy: 3.0
    pattern_requirements:
      min_digits: 1
      min_uppercase: 1
      min_lowercase: 1
      min_special_chars: 2
      special_chars: '$%^'
    examples:
      - 'acme=Q7m2$%V9r4T8p5N6c3'
    negative_examples:
      - 'acme=Q7m2V9r4T8p5N6c3'
      - 'not an acme token'
  - id: acme.secondary.v1
    name: Secondary Token
    pattern: 'secondary=[A-Za-z0-9]+'
    examples:
      - secondary=Q7m2V9r4T8p5N6c3
    negative_examples:
      - not a secondary token
"#,
    )?;
    let yaml = nested.join("other.yaml");
    std::fs::write(
        &yaml,
        r#"rules:
  - id: acme.named.v1
    name: Named Token
    pattern: 'named=(?P<secret>[A-Za-z0-9]+)'
    examples:
      - named=Q7m2V9r4T8p5N6c3
    negative_examples:
      - not a named token
"#,
    )?;
    for path in [yml.as_path(), yaml.as_path(), dir.path()] {
        check_rule_file(path, &["--warnings-as-errors"])
            .success()
            .stdout(predicate::str::contains("All rules passed validation successfully"));
    }
    check_rule_file(dir.path(), &["--rule", "kingfisher.acme.v1", "--warnings-as-errors"])
        .success();
    Ok(())
}

#[test]
fn check_rules_preserves_named_capture_checksum_context_and_diagnostics() {
    let pattern = "(?x)ghp_(?P<body>[A-Za-z0-9]{30})(?P<checksum>[A-Za-z0-9]{6})";
    let options = r#"    pattern_requirements:
      checksum:
        actual:
          template: '{{ MATCH | suffix: 6 }}'
          requires_capture: checksum
        expected: '{{ BODY | crc32 | base62: 6 }}'
        skip_if_missing: false
"#;
    let valid = "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";
    let invalid = "ghp_NQLObn7M3OTKBL44TH6K9WxFY39LZM1sDc00";
    check_custom_rule(pattern, options, &[valid], &[invalid]).success();
    check_custom_rule(pattern, options, &[invalid], &[])
        .code(1)
        .stdout(predicate::str::contains("Checksum validation failed for example"))
        .stdout(predicate::str::contains("Actual checksum length: 6, Expected checksum length: 6"))
        .stdout(predicate::str::contains("Errors: 1"));
}

#[test]
fn check_rules_preserves_custom_character_requirement_diagnostics() {
    for (requirement, example) in [
        ("min_digits: 1", "token=QmVrTpNc"),
        ("min_uppercase: 1", "token=q7m2v9r4t8p5n6c3"),
        ("min_lowercase: 1", "token=Q7M2V9R4T8P5N6C3"),
        ("min_special_chars: 1", "token=Q7m2V9r4T8p5N6c3"),
    ] {
        check_custom_rule(
            "token=([A-Za-z0-9]+)",
            &format!("    pattern_requirements:\n      {requirement}\n"),
            &[example],
            &[],
        )
        .code(1)
        .stdout(predicate::str::contains("Pattern requirements not met for example"))
        .stdout(predicate::str::contains("Errors: 1"));
    }
}

#[test]
fn check_rules_preserves_ignored_substring_warnings() {
    for extra_args in [&[][..], &["--warnings-as-errors"][..]] {
        check_custom_rule_with_args(
            "token=([A-Za-z0-9]+)",
            "    pattern_requirements:\n      ignore_if_contains: [' q7m2 ']\n",
            &["token=Q7m2V9r4T8p5N6c3 token=Q7M2V9r4T8p5N6c3"],
            &["token=Q7m2V9r4T8p5N6c3", "not a token"],
            extra_args,
        )
        .code(if extra_args.is_empty() { 0 } else { 1 })
        .stdout(predicate::str::contains("Example would be ignored due to containing term: q7m2"))
        .stdout(predicate::str::contains("Errors: 0"))
        .stdout(predicate::str::contains("Warnings: 1"))
        .stdout(predicate::str::contains("Example rejected by scan-time filters").not());
    }
}

#[test]
fn check_rules_does_not_hide_other_rejections_behind_ignored_substrings() {
    check_custom_rule(
        "token=([A-Za-z0-9]+)",
        "    pattern_requirements:\n      min_digits: 1\n      ignore_if_contains: [Q7m2]\n",
        &["token=Q7m2V9r4T8p5N6c3 token=QmVrTpNc"],
        &[],
    )
    .code(1)
    .stdout(predicate::str::contains("Pattern requirements not met for example"))
    .stdout(predicate::str::contains("Errors: 1"));

    // An ignored first match does not invalidate a later surviving candidate.
    check_custom_rule(
        "token=([A-Za-z0-9]+)",
        "    pattern_requirements:\n      ignore_if_contains: [Q7m2]\n",
        &["token=Q7m2V9r4T8p5N6c3 token=Q8m3V9r4T8p5N6c3"],
        &[],
    )
    .success()
    .stdout(predicate::str::contains("All rules passed validation successfully"));
}

fn assert_ignored_substring_does_not_mask_rejection(pattern: &str, options: &str, example: &str) {
    for extra_args in [&[][..], &["--warnings-as-errors"][..]] {
        check_custom_rule_with_args(pattern, options, &[example], &[example], extra_args)
            .code(1)
            .stdout(predicate::str::contains("Example rejected by scan-time filters"))
            .stdout(predicate::str::contains("Errors: 1"))
            .stdout(predicate::str::contains("Warnings: 0"))
            .stdout(predicate::str::contains("Negative example unexpectedly matched").not());
    }
}

#[test]
fn check_rules_ignored_substring_does_not_mask_entropy() {
    assert_ignored_substring_does_not_mask_rejection(
        "token=([A-Za-z0-9]+)",
        "    min_entropy: 3.0\n    pattern_requirements:\n      ignore_if_contains: [AA]\n",
        "token=AAAAAA",
    );
}

#[test]
fn check_rules_ignored_substring_does_not_mask_safelist() {
    assert_ignored_substring_does_not_mask_rejection(
        "token=([A-Za-z0-9]+)",
        "    pattern_requirements:\n      ignore_if_contains: ['123456789']\n",
        "token=Ab123456789Zx7Qp",
    );
}

#[test]
fn check_rules_ignored_substring_does_not_mask_rule_filters() {
    assert_ignored_substring_does_not_mask_rejection(
        "token=([A-Za-z0-9]+)",
        "    betterleaks_filter:\n      kind: bool\n      value: true\n    pattern_requirements:\n      ignore_if_contains: [Q7m2]\n",
        "token=Q7m2V9r4T8p5N6c3",
    );
}

#[test]
fn check_rules_ignored_substring_does_not_mask_checksums() {
    let options = "    pattern_requirements:\n      ignore_if_contains: ['7992']\n      checksum:\n        actual:\n          template: '{{ MATCH | luhn_valid }}'\n        expected: 'true'\n";
    assert_ignored_substring_does_not_mask_rejection("card=([0-9]+)", options, "card=79927398714");
    // A valid checksum still permits the ignored-substring compatibility warning.
    for extra_args in [&[][..], &["--warnings-as-errors"][..]] {
        check_custom_rule_with_args(
            "card=([0-9]+)",
            options,
            &["card=79927398713"],
            &["card=79927398713"],
            extra_args,
        )
        .code(if extra_args.is_empty() { 0 } else { 1 })
        .stdout(predicate::str::contains("Errors: 0"))
        .stdout(predicate::str::contains("Warnings: 1"));
    }
}

#[test]
fn check_rules_accepts_patterns_containing_yaml_quotes() {
    check_custom_rule("token='([A-Za-z0-9]+)'", "", &["token='Q7m2V9r4T8p5N6c3'"], &[]).success();
}

#[test]
fn check_rules_preserves_authoring_warnings_and_warnings_as_errors() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("warnings.yml");
    std::fs::write(
        &path,
        r#"rules:
  - id: acme.short.v1
    name: X
    pattern: ab
    examples: [ab]
  - id: acme.no-examples.v1
    name: No Examples
    pattern: 'missing=([A-Za-z0-9]+)'
"#,
    )?;
    check_rule_file(&path, &[])
        .success()
        .stdout(predicate::str::contains("Errors: 0"))
        .stdout(predicate::str::contains("Warnings: 3"))
        .stderr(predicate::str::contains("very short name"))
        .stderr(predicate::str::contains("very short pattern"))
        .stderr(predicate::str::contains("has no examples"));
    check_rule_file(&path, &["--warnings-as-errors"])
        .code(1)
        .stdout(predicate::str::contains("Errors: 0"))
        .stdout(predicate::str::contains("Warnings: 3"));
    Ok(())
}

#[test]
fn check_rules_still_rejects_invalid_custom_regexes_and_validation_definitions() {
    check_custom_rule("(", "", &[], &[]).code(1).stderr(predicate::str::contains("custom.check"));
    check_custom_rule(
        "token=([A-Za-z0-9]+)",
        r#"    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://example.invalid/check
"#,
        &["token=Q7m2V9r4T8p5N6c3"],
        &[],
    )
    .code(1)
    .stderr(predicate::str::contains("custom.check"));
}

#[test]
fn check_rules_examples_do_not_require_source_paths_or_companion_findings() {
    check_custom_rule(
        "token=([A-Za-z0-9]+)",
        "    path: '^config/.*'\n    depends_on_rule:\n      - rule_id: custom.component\n        variable: COMPONENT\n        within: 1L\n    validation:\n      type: Raw\n      content: not-a-live-validator\n  - id: custom.component\n    name: Component\n    pattern: 'component=([A-Za-z0-9]+)'\n    confidence: medium\n    visible: false\n",
        &["token=Q7m2V9r4T8p5N6c3"],
        &["not a token"],
    )
    .success();
}

#[test]
fn normal_scan_does_not_check_rule_examples_at_startup() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let rules_path = dir.path().join("rules.yml");
    let input_path = dir.path().join("input.txt");
    let report_path = dir.path().join("report.json");
    std::fs::write(
        &rules_path,
        r#"rules:
  - id: custom.check
    name: Check Examples
    confidence: medium
    pattern: 'token=([A-Za-z0-9]+)'
    min_entropy: 3.0
    examples:
      - token=AAAAAA
    negative_examples:
      - token=Q7m2V9r4T8p5N6c3
"#,
    )?;
    std::fs::write(&input_path, "token=AAAAAA token=Q7m2V9r4T8p5N6c3")?;

    // Example failures belong to the explicit check command, not ordinary rule loading.
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["rules", "check", "--no-update-check", "--load-builtins=false", "--rules-path"])
        .arg(&rules_path)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Errors: 2"));

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input_path)
        .args([
            "--git-history",
            "none",
            "--no-validate",
            "--no-update-check",
            "--no-rule-cache",
            "--load-builtins=false",
            "--format",
            "json",
            "--rules-path",
        ])
        .arg(&rules_path)
        .arg("--output")
        .arg(&report_path)
        .assert()
        .code(200);
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(report_path)?)?;
    // Normal scan-time filters still apply to input content; only the real candidate survives.
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    Ok(())
}
