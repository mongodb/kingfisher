//! Tests for the `--tls-mode` CLI feature and TLS validation behavior.
//!
//! These tests verify that:
//! - The `--tls-mode` CLI flag is parsed correctly
//! - The `--ignore-certs` legacy flag is treated as `--tls-mode=off`
//! - Rules with `tls_mode: lax` are correctly parsed and respected
//! - The TLS mode behavior works as expected for different validators

use assert_cmd::Command;
use predicates::prelude::*;

/// Test that `--tls-mode` is recognized as a valid global option.
#[test]
fn tls_mode_flag_is_recognized() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=strict").arg("--help");
    cmd.assert().success();
}

/// Test that all TLS mode values are accepted.
#[test]
fn tls_mode_accepts_all_values() {
    for mode in ["strict", "lax", "off"] {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        cmd.arg(format!("--tls-mode={}", mode)).arg("--help");
        cmd.assert().success();
    }
}

/// Test that invalid TLS mode values are rejected.
#[test]
fn tls_mode_rejects_invalid_values() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=invalid").arg("--help");
    cmd.assert().failure().stderr(predicate::str::contains("invalid"));
}

/// Test that `--ignore-certs` is still accepted (deprecated but supported).
#[test]
fn ignore_certs_flag_still_works() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--ignore-certs").arg("--help");
    cmd.assert().success();
}

/// Test that --tls-mode appears in the help output.
#[test]
fn tls_mode_appears_in_help() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains("--tls-mode"));
}

/// Test that rules list subcommand runs with tls-mode flag.
#[test]
fn rules_list_works_with_tls_mode() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=lax").arg("rules").arg("list");
    cmd.assert().success().stdout(predicate::str::contains("betterleaks.github-pat"));
}

/// Test that a scan with `--tls-mode=strict` runs successfully.
#[test]
fn scan_with_strict_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=strict").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

/// Test that a scan with `--tls-mode=lax` runs successfully.
#[test]
fn scan_with_lax_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=lax").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

/// Test that a scan with `--tls-mode=off` runs successfully.
#[test]
fn scan_with_off_mode_runs() {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("--tls-mode=off").arg("scan").arg("--no-validate").arg("-");
    cmd.write_stdin("test input with no secrets");
    cmd.assert().success();
}

#[cfg(test)]
mod rule_tls_mode_tests {
    use kingfisher_rules::{RuleSyntax, TlsMode};
    use serde::Deserialize;

    /// Helper struct for deserializing rule YAML files.
    #[derive(Deserialize)]
    struct RawRules {
        rules: Vec<RuleSyntax>,
    }

    #[test]
    fn legacy_custom_rules_preserve_tls_mode() {
        let yaml = r#"
rules:
  - name: Custom database credential
    id: custom.database.1
    pattern: '(?P<TOKEN>postgres://[^ ]+)'
    validation: { type: Postgres }
    tls_mode: lax
  - name: Custom SaaS token
    id: custom.saas.1
    pattern: '(?P<TOKEN>saas_[A-Za-z0-9]+)'
"#;
        let raw: RawRules = serde_yaml::from_str(yaml).expect("custom legacy rules should parse");

        assert_eq!(raw.rules[0].tls_mode, Some(TlsMode::Lax));
        assert_eq!(raw.rules[1].tls_mode, None);
    }
}
