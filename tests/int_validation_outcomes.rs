use std::fs;

use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

const PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7a7kN8LymUu8Z
8D9r9K2m6N1ZaUT96UrFqjlL9nAqmZ+13D82H1CYLKy0NOAY3XBLzLk46HZd8na2
-----END PRIVATE KEY-----
"#;

fn scan_private_key(rule: &str, filter_args: &[&str]) -> Result<Value> {
    let temp = tempdir()?;
    let input = temp.path().join("private-key.pem");
    let report = temp.path().join("report.json");
    fs::write(&input, PRIVATE_KEY)?;

    let mut args = vec![
        "scan",
        input.to_str().unwrap(),
        "--rule",
        rule,
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
    let report = scan_private_key("kingfisher.privkey.2", &["--validation-filter", "actionable"])?;
    let findings = report["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "kingfisher.privkey.2");
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
    let report = scan_private_key("kingfisher.privkey.2", &["--only-valid"])?;
    assert!(report["findings"].as_array().unwrap().is_empty());
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 0);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 1);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}

#[test]
fn actionable_filter_includes_assumed_pem_keys() -> Result<()> {
    let report = scan_private_key("kingfisher.pem.1", &["--validation-filter", "actionable"])?;
    let findings = report["findings"].as_array().unwrap();

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "kingfisher.pem.1");
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
    let report = scan_private_key("kingfisher.privkey.2", &[])?;

    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 0);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 1);
    assert!(report["metadata"]["summary"].get("high_confidence_secrets").is_none());
    Ok(())
}
