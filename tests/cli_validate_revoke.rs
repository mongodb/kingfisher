// tests/cli_validate_revoke.rs
//
// CLI tests for the `kingfisher validate` and `kingfisher revoke` commands.
// These tests validate CLI argument parsing, error messages, and basic functionality
// without requiring actual network connections or valid credentials.

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use serde_json::Value;
use std::fs;
use tempfile::TempDir;

// =============================================================================
// Validate Command Tests
// =============================================================================

mod validate {
    use super::*;

    #[test]
    fn validate_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--help"])
            .assert()
            .success()
            .stdout(
                contains("Directly validate a known secret")
                    .and(contains("--rule"))
                    .and(contains("SECRET")),
            );
    }

    #[test]
    fn validate_help_shows_all_options() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--help"])
            .assert()
            .success()
            .stdout(
                contains("--rule")
                    .and(contains("--arg"))
                    .and(contains("--var"))
                    .and(contains("--timeout"))
                    .and(contains("--retries"))
                    .and(contains("--rules-path"))
                    .and(contains("--no-builtins"))
                    .and(contains("--format")),
            );
    }

    #[test]
    fn validate_requires_rule_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "test-secret", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("--rule"));
    }

    #[test]
    fn validate_requires_secret() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--rule", "opsgenie", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("No secret provided"));
    }

    #[test]
    fn validate_rejects_empty_secret() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--rule", "opsgenie", "", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("Secret cannot be empty"));
    }

    #[test]
    fn validate_rejects_unknown_rule() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "nonexistent.rule.xyz",
                "test-secret",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("No rule found matching"));
    }

    #[test]
    fn validate_accepts_rule_prefix() {
        // Should find rules matching a prefix like "opsgenie"
        // The actual validation will fail but the rule should be found
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--rule", "opsgenie", "fake-api-key-12345", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| {
                // Exit 1 means validation failed (expected with fake key)
                // Exit 0 would mean valid (unexpected but possible)
                *code == 0 || *code == 1
            }))
            .stdout(contains("OpsGenie").or(contains("opsgenie")));
    }

    #[test]
    fn validate_accepts_full_rule_id() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "kingfisher.opsgenie.1",
                "fake-api-key-12345",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_json_output() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key-12345",
                "--format",
                "json",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(
                contains("rule_id")
                    .and(contains("rule_name"))
                    .and(contains("is_valid"))
                    .and(contains("message")),
            );
    }

    #[test]
    fn validate_toon_output() {
        let assert = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "kingfisher.opsgenie.1",
                "fake-api-key-12345",
                "--format",
                "toon",
                "--no-update-check",
            ])
            .assert();

        let output = assert.get_output();
        assert!(output.status.code().is_some_and(|code| code == 0 || code == 1));
        let toon = String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8");
        let decoded: Value = toon_format::decode_default(&toon).expect("toon should decode");
        assert!(decoded.get("rule_id").is_some());
        assert!(decoded.get("rule_name").is_some());
        assert!(decoded.get("message").is_some());
    }

    #[test]
    fn validate_text_output() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key-12345",
                "--format",
                "text",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Rule:").and(contains("Result:")));
    }

    /// HTTP infrastructure failures (DNS, SSRF preflight, connection
    /// refused, etc.) must surface as a structured DirectValidationResult
    /// rather than short-circuiting the validate command. Also verifies
    /// the secret is not leaked into stdout via the error message.
    #[test]
    fn validate_http_failure_emits_structured_result() {
        let secret = "ghp_redaction_test_secret_value_xyz";
        let assert = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "kingfisher.github.2",
                secret,
                "--format",
                "json",
                "--allow-internal-ips",
                "--endpoint",
                "github=http://127.0.0.1:1",
                "--timeout",
                "2",
                "--retries",
                "0",
                "--no-update-check",
            ])
            .assert();
        let output = assert.get_output();
        assert!(output.status.code().is_some_and(|code| code == 0 || code == 1));
        let stdout = String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8");
        let decoded: Value = serde_json::from_str(&stdout).expect("json should decode");
        assert_eq!(decoded.get("rule_id").and_then(|v| v.as_str()), Some("kingfisher.github.2"));
        assert_eq!(decoded.get("is_valid").and_then(|v| v.as_bool()), Some(false));
        let message = decoded.get("message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            message.contains("HTTP validation failed"),
            "message should explain the failure, got: {message}"
        );
        // The CLI must never echo the user's secret back to stdout, even
        // when the upstream validation fails. We emit a generic error
        // message and only log the underlying detail at debug level.
        assert!(!stdout.contains(secret), "secret must not appear in stdout output, got: {stdout}");
    }

    /// gRPC infrastructure failures must surface as a structured
    /// DirectValidationResult and must not leak the secret into stdout.
    /// Mirrors `validate_http_failure_emits_structured_result` for the
    /// gRPC code path.
    #[test]
    fn validate_grpc_failure_emits_structured_result() {
        let tmp = TempDir::new().unwrap();
        // Custom rule with gRPC validation pointing at an unreachable port
        // so we deterministically trigger a connection failure rather than
        // depending on any built-in provider's reachability.
        fs::write(
            tmp.path().join("custom_grpc_rule.yml"),
            r#"
rules:
  - name: Custom gRPC Rule
    id: test.custom.grpc
    pattern: "grpc_[a-z0-9]{8}"
    validation:
      type: Grpc
      content:
        request:
          url: http://127.0.0.1:1/example.Service/Method
          headers:
            content-type: application/grpc
            x-token: "{{ TOKEN }}"
          response_matcher:
            - report_response: true
            - type: HeaderMatch
              header: grpc-status
              expected:
                - "0"
"#,
        )
        .unwrap();

        let secret = "grpc_redaction_test_secret_xyz";
        let assert = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "test.custom.grpc",
                secret,
                "--rules-path",
                tmp.path().to_str().unwrap(),
                "--no-builtins",
                "--format",
                "json",
                "--allow-internal-ips",
                "--timeout",
                "2",
                "--retries",
                "0",
                "--no-update-check",
            ])
            .assert();
        let output = assert.get_output();
        assert!(output.status.code().is_some_and(|code| code == 0 || code == 1));
        let stdout = String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8");
        let decoded: Value = serde_json::from_str(&stdout).expect("json should decode");
        assert_eq!(decoded.get("rule_id").and_then(|v| v.as_str()), Some("test.custom.grpc"));
        assert_eq!(decoded.get("is_valid").and_then(|v| v.as_bool()), Some(false));
        let message = decoded.get("message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            message.contains("gRPC validation failed"),
            "message should explain the failure, got: {message}"
        );
        assert!(!stdout.contains(secret), "secret must not appear in stdout output, got: {stdout}");
    }

    #[test]
    fn validate_with_timeout() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--timeout",
                "5",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_rejects_invalid_timeout() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--timeout",
                "100",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("100").or(contains("invalid")).or(contains("range")));
    }

    #[test]
    fn validate_with_retries() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--retries",
                "3",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_rejects_invalid_retries() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--retries",
                "10",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("10").or(contains("invalid")).or(contains("range")));
    }

    #[test]
    fn validate_with_var_flag() {
        // AWS validation requires AKID variable
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "aws",
                "--var",
                "AKID=AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_with_arg_flag() {
        // AWS validation with --arg (auto-assigns to AKID)
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "aws",
                "--arg",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_rejects_invalid_var_format() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "aws",
                "--var",
                "INVALID_FORMAT_NO_EQUALS",
                "fake-secret",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("Invalid variable format").or(contains("NAME=VALUE")));
    }

    #[test]
    fn validate_rule_without_validation() {
        // Create a temporary rule without validation
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("no_validation.yml"),
            r#"
rules:
  - name: No Validation Rule
    id: test.no.validation
    pattern: "test_pattern_[a-z0-9]{4}"
"#,
        )
        .unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "test.no.validation",
                "test_pattern_abcd",
                "--rules-path",
                tmp.path().to_str().unwrap(),
                "--no-builtins",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("No rules with validation found"));
    }

    #[test]
    fn validate_no_builtins_with_custom_rule() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("custom_rule.yml"),
            r#"
rules:
  - name: Custom HTTP Rule
    id: test.custom.http
    pattern: "custom_[a-z0-9]{8}"
    validation:
      type: Http
      content:
        request:
          method: GET
          url: "https://httpbin.org/status/401"
          response_matcher:
            - status:
                - 200
              type: StatusMatch
"#,
        )
        .unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "test.custom.http",
                "custom_12345678",
                "--rules-path",
                tmp.path().to_str().unwrap(),
                "--no-builtins",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Custom HTTP Rule"));
    }

    #[test]
    fn validate_missing_required_variable() {
        // AWS validation requires AKID - should fail if not provided
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "aws",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("AKID").or(contains("variable")));
    }

    #[test]
    fn validate_too_many_args() {
        // OpsGenie only needs TOKEN, no additional variables
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "--arg",
                "extra1",
                "--arg",
                "extra2",
                "fake-api-key",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("Too many --arg"));
    }

    #[test]
    fn validate_mongodb_with_connection_uri() {
        // MongoDB validation expects a connection URI
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "mongodb",
                "mongodb://user:pass@localhost:27017/test",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_postgres_with_connection_url() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "postgres",
                "postgres://user:pass@localhost:5432/test",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_mysql_with_connection_url() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "mysql",
                "mysql://user:pass@localhost:3306/test",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_jdbc_with_connection_string() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "jdbc",
                "jdbc:postgresql://localhost:5432/test?user=admin&password=secret",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_jwt_token() {
        // A fake JWT token (will fail validation but tests the flow)
        let fake_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--rule", "jwt", fake_jwt, "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_format_invalid_value() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "opsgenie",
                "fake-key",
                "--format",
                "yaml",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("yaml").or(contains("invalid")));
    }
}

// =============================================================================
// Revoke Command Tests
// =============================================================================

mod revoke {
    use super::*;

    #[test]
    fn revoke_help() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--help"])
            .assert()
            .success()
            .stdout(
                contains("Directly revoke a known secret")
                    .and(contains("--rule"))
                    .and(contains("SECRET")),
            );
    }

    #[test]
    fn revoke_help_shows_all_options() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--help"])
            .assert()
            .success()
            .stdout(
                contains("--rule")
                    .and(contains("--arg"))
                    .and(contains("--var"))
                    .and(contains("--timeout"))
                    .and(contains("--retries"))
                    .and(contains("--rules-path"))
                    .and(contains("--no-builtins"))
                    .and(contains("--format")),
            );
    }

    #[test]
    fn revoke_requires_rule_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "test-secret", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("--rule"));
    }

    #[test]
    fn revoke_requires_secret() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--rule", "slack", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("No secret provided"));
    }

    #[test]
    fn revoke_rejects_empty_secret() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--rule", "slack", "", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("Secret cannot be empty"));
    }

    #[test]
    fn revoke_rejects_unknown_rule() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--rule", "nonexistent.rule.xyz", "test-secret", "--no-update-check"])
            .assert()
            .failure()
            .stderr(contains("No rule found matching"));
    }

    #[test]
    fn revoke_accepts_rule_prefix() {
        // Slack has revocation support
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--rule", "slack", "xoxb-fake-token-12345", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Slack").or(contains("slack")));
    }

    #[test]
    fn revoke_accepts_full_rule_id() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "kingfisher.slack.1",
                "xoxb-fake-token",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_json_output() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--format",
                "json",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(
                contains("rule_id")
                    .and(contains("rule_name"))
                    .and(contains("revoked"))
                    .and(contains("message")),
            );
    }

    #[test]
    fn revoke_toon_output() {
        let assert = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "kingfisher.slack.1",
                "xoxb-fake-token",
                "--format",
                "toon",
                "--no-update-check",
            ])
            .assert();

        let output = assert.get_output();
        assert!(output.status.code().is_some_and(|code| code == 0 || code == 1));
        let toon = String::from_utf8(output.stdout.clone()).expect("stdout should be UTF-8");
        let decoded: Value = toon_format::decode_default(&toon).expect("toon should decode");
        assert!(decoded.get("rule_id").is_some());
        assert!(decoded.get("rule_name").is_some());
        assert!(decoded.get("message").is_some());
    }

    #[test]
    fn revoke_text_output() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--format",
                "text",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Rule:").and(contains("Result:")));
    }

    #[test]
    fn revoke_with_timeout() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--timeout",
                "5",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_rejects_invalid_timeout() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--timeout",
                "100",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("100").or(contains("invalid")).or(contains("range")));
    }

    #[test]
    fn revoke_with_retries() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--retries",
                "3",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_rejects_invalid_retries() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--retries",
                "10",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("10").or(contains("invalid")).or(contains("range")));
    }

    #[test]
    fn revoke_with_var_flag() {
        // AWS revocation requires AKID variable
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "aws",
                "--var",
                "AKID=AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_with_arg_flag() {
        // AWS revocation with --arg (auto-assigns to AKID)
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "aws",
                "--arg",
                "AKIAIOSFODNN7EXAMPLE",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_rejects_invalid_var_format() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "aws",
                "--var",
                "INVALID_FORMAT_NO_EQUALS",
                "fake-secret",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("Invalid variable format").or(contains("NAME=VALUE")));
    }

    #[test]
    fn revoke_rule_without_revocation() {
        // Create a temporary rule without revocation
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("no_revocation.yml"),
            r#"
rules:
  - name: No Revocation Rule
    id: test.no.revocation
    pattern: "test_pattern_[a-z0-9]{4}"
"#,
        )
        .unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "test.no.revocation",
                "test_pattern_abcd",
                "--rules-path",
                tmp.path().to_str().unwrap(),
                "--no-builtins",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("No rules with revocation found"));
    }

    #[test]
    fn revoke_gcp_with_service_account_json() {
        // GCP revocation expects service account JSON
        let fake_sa_json =
            r#"{"type":"service_account","project_id":"test","private_key_id":"key123"}"#;
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--rule", "gcp", fake_sa_json, "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_github_token() {
        // GitHub has revocation support
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "github",
                "ghp_fake1234567890abcdefghijklmnopqrstuvw",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_gitlab_token() {
        // GitLab has revocation support
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "gitlab",
                "glpat-fake1234567890abcdefgh",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_missing_required_variable() {
        // AWS revocation requires AKID - should fail if not provided
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "aws",
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("AKID").or(contains("variable")));
    }

    #[test]
    fn revoke_format_invalid_value() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--format",
                "xml",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(contains("xml").or(contains("invalid")));
    }
}

// =============================================================================
// Shared/Cross-Command Tests
// =============================================================================

mod shared {
    use super::*;

    #[test]
    fn validate_and_revoke_exist_as_subcommands() {
        // Verify both commands show up in main help
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("--help")
            .assert()
            .success()
            .stdout(contains("validate").and(contains("revoke")));
    }

    #[test]
    fn validate_accepts_stdin_marker() {
        // Test that '-' is accepted as stdin marker (the actual read will fail in test)
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["validate", "--help"])
            .assert()
            .success()
            .stdout(contains("stdin").or(contains("-")));
    }

    #[test]
    fn revoke_accepts_stdin_marker() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["revoke", "--help"])
            .assert()
            .success()
            .stdout(contains("stdin").or(contains("-")));
    }

    #[test]
    fn validate_with_custom_rules_path() {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("custom.yml"),
            r#"
rules:
  - name: Custom Validate Rule
    id: custom.validate.test
    pattern: "customval_[a-z0-9]{4}"
    validation:
      type: Http
      content:
        request:
          method: GET
          url: "https://httpbin.org/status/200"
          response_matcher:
            - status:
                - 200
              type: StatusMatch
"#,
        )
        .unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "custom.validate.test",
                "customval_abcd",
                "--rules-path",
                tmp.path().to_str().unwrap(),
                "--no-builtins",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Custom Validate Rule"));
    }

    #[test]
    fn multiple_rules_path_flags() {
        let tmp1 = TempDir::new().unwrap();
        let tmp2 = TempDir::new().unwrap();

        fs::write(
            tmp1.path().join("rule1.yml"),
            r#"
rules:
  - name: Rule One
    id: multi.path.one
    pattern: "ruleone_[a-z]{4}"
    validation:
      type: Http
      content:
        request:
          method: GET
          url: "https://httpbin.org/status/200"
          response_matcher:
            - status:
                - 200
              type: StatusMatch
"#,
        )
        .unwrap();

        fs::write(
            tmp2.path().join("rule2.yml"),
            r#"
rules:
  - name: Rule Two
    id: multi.path.two
    pattern: "ruletwo_[a-z]{4}"
    validation:
      type: Http
      content:
        request:
          method: GET
          url: "https://httpbin.org/status/200"
          response_matcher:
            - status:
                - 200
              type: StatusMatch
"#,
        )
        .unwrap();

        // Should be able to find rules from both paths
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "multi.path.one",
                "ruleone_abcd",
                "--rules-path",
                tmp1.path().to_str().unwrap(),
                "--rules-path",
                tmp2.path().to_str().unwrap(),
                "--no-builtins",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1))
            .stdout(contains("Rule One"));
    }

    #[test]
    fn validate_with_verbose_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "--verbose",
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_with_verbose_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "--verbose",
                "revoke",
                "--rule",
                "slack",
                "xoxb-fake-token",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_with_quiet_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "--quiet",
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn revoke_with_quiet_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["--quiet", "revoke", "--rule", "slack", "xoxb-fake-token", "--no-update-check"])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }

    #[test]
    fn validate_with_tls_lax_flag() {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "--tls-mode",
                "lax",
                "validate",
                "--rule",
                "opsgenie",
                "fake-api-key",
                "--no-update-check",
            ])
            .assert()
            .code(predicates::function::function(|code: &i32| *code == 0 || *code == 1));
    }
}
