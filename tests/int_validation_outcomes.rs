use std::fs;

use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;
use wiremock::MockServer;

const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7a7kN8LymUu8Z
8D9r9K2m6N1ZaUT96UrFqjlL9nAqmZ+13D82H1CYLKy0NOAY3XBLzLk46HZd8na2
-----END PRIVATE KEY-----
"#;

const LEGACY_CUSTOM_RULES: &str = r#"
rules:
  - name: Custom Private Key
    id: custom.private-key
    pattern: '(?xims)(-----BEGIN[[:space:]]+(?:RSA[[:space:]]+)?PRIVATE[[:space:]]+KEY-----[a-z0-9 /+=\r\n]{32,}?-----END[[:space:]]+(?:RSA[[:space:]]+)?PRIVATE[[:space:]]+KEY-----)'
    min_entropy: 0.0
    validation:
      type: Assumed
  - name: Custom PEM Private Key
    id: custom.pem
    pattern: '(?xims)(-----BEGIN[[:space:]]+PRIVATE[[:space:]]+KEY-----[a-z0-9 /+=\r\n]{32,}?-----END[[:space:]]+PRIVATE[[:space:]]+KEY-----)'
    min_entropy: 0.0
    validation:
      type: Assumed
"#;

fn scan_private_key(rule: &str, filter_args: &[&str]) -> Result<Value> {
    let temp = tempdir()?;
    let input = temp.path().join("private-key.pem");
    let report = temp.path().join("report.json");
    let rules = temp.path().join("rules.yml");
    fs::write(&input, PRIVATE_KEY)?;
    fs::write(&rules, LEGACY_CUSTOM_RULES)?;

    let mut args = vec![
        "scan",
        input.to_str().unwrap(),
        "--rule",
        rule,
        "--rules-path",
        rules.to_str().unwrap(),
        "--load-builtins=false",
        "--format",
        "json",
        "--output",
        report.to_str().unwrap(),
        "--no-validate",
        "--no-update-check",
    ];
    args.extend_from_slice(filter_args);

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher")).args(args).assert().code(200);

    Ok(serde_json::from_str(&fs::read_to_string(report)?)?)
}

#[test]
fn actionable_filter_includes_assumed_private_keys() -> Result<()> {
    let report = scan_private_key("custom.private-key", &["--validation-filter", "actionable"])?;
    let findings = report["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "custom.private-key");
    assert_eq!(findings[0]["finding"]["validation"]["outcome"], "assumed");
    assert_eq!(
        findings[0]["finding"]["validation"]["status"],
        "Assumed Valid (Not Live-Validated)"
    );
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 1);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 0);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}

#[test]
fn only_valid_remains_strictly_verified_active() -> Result<()> {
    let report = scan_private_key("custom.private-key", &["--only-valid"])?;
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 0);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 1);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}

#[test]
fn actionable_filter_includes_assumed_pem_keys() -> Result<()> {
    let report = scan_private_key("custom.pem", &["--validation-filter", "actionable"])?;
    let findings = report["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "custom.pem");
    assert_eq!(findings[0]["finding"]["validation"]["outcome"], "assumed");
    assert_eq!(
        findings[0]["finding"]["validation"]["status"],
        "Assumed Valid (Not Live-Validated)"
    );
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 1);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 0);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}

#[test]
fn only_valid_conflicts_with_explicit_validation_filter() {
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            ".",
            "--only-valid",
            "--validation-filter",
            "actionable",
            "--no-update-check",
        ])
        .assert()
        .failure();
}

#[test]
fn assumed_findings_count_as_skipped_without_actionable_filter() -> Result<()> {
    let report = scan_private_key("custom.private-key", &[])?;

    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 0);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 1);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}

#[test]
fn unsupported_generic_credential_uri_scheme_remains_not_attempted() -> Result<()> {
    let temp = tempdir()?;
    let input = temp.path().join("service.env");
    let report_path = temp.path().join("report.json");
    fs::write(&input, "SERVICE_URL=ssh://svc_reader:hunter2x@service.internal/api")?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--rule",
            "betterleaks.generic-credential-uri",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--no-update-check",
        ])
        .assert()
        .code(200);

    let report: Value = serde_json::from_str(&fs::read_to_string(report_path)?)?;
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["finding"]["validation"]["outcome"], "not_attempted");
    assert_eq!(findings[0]["finding"]["validation"]["status"], "Not Attempted");
    Ok(())
}

#[tokio::test]
async fn generic_credential_uri_refuses_plaintext_basic_auth() -> Result<()> {
    let server = MockServer::start().await;

    let temp = tempdir()?;
    let input = temp.path().join("service.env");
    let report_path = temp.path().join("report.json");
    let uri = server.uri().replacen("http://", "http://alice:hunter2@", 1) + "/api";
    fs::write(&input, format!("SERVICE_URL={uri}"))?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--rule",
            "betterleaks.generic-credential-uri",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--allow-internal-ips",
            "--no-update-check",
        ])
        .assert()
        .code(200);

    let report: Value = serde_json::from_str(&fs::read_to_string(report_path)?)?;
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["finding"]["validation"]["outcome"], "unavailable");
    assert!(
        findings[0]["finding"]["validation"]["response"]
            .as_str()
            .unwrap()
            .contains("requires HTTPS")
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    Ok(())
}
