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

/// Both CLI entry points must preserve the same explicit outcome as the embeddable API.
#[tokio::test]
async fn library_scan_and_direct_validation_agree_on_http_outcomes() -> Result<()> {
    use kingfisher_rules::{Confidence, Rules};
    use kingfisher_scanner::{RulesDatabase, Scanner, Validator};
    use std::sync::Arc;
    use wiremock::{
        Mock, ResponseTemplate,
        matchers::{header, method, path},
    };

    for (status, body, expected) in [
        (200, "authenticated", "verified_active"),
        (401, "rejected", "verified_inactive"),
        (429, "authenticated", "unavailable"),
        (503, "authenticated", "unavailable"),
        (200, "welcome", "unavailable"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/identity"))
            .and(header("authorization", "Bearer demo_abcd1234efgh5678"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(3)
            .mount(&server)
            .await;
        let temp = tempdir()?;
        let rules_path = temp.path().join("rules.yml");
        let input = temp.path().join("input.txt");
        let report_path = temp.path().join("report.json");
        fs::write(&input, "demo_abcd1234efgh5678")?;
        fs::write(
            &rules_path,
            format!(
                r#"
rules:
  - id: acme.parity
    name: Parity fixture
    pattern: '(demo_[a-z0-9]{{16}})'
    min_entropy: 0.0
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{}/identity'
          headers:
            Authorization: 'Bearer {{{{ TOKEN }}}}'
          response_matcher:
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: [authenticated]
"#,
                server.uri()
            ),
        )?;
        let database = RulesDatabase::from_rule_collection(Rules::from_paths(
            [&rules_path],
            Confidence::Low,
        )?)?;
        let findings = Scanner::new(Arc::new(database)).scan_file(&input)?;
        assert_eq!(findings.len(), 1);
        let library = Validator::builder()
            .allow_internal_ips(true)
            .build()?
            .validate_findings(findings)
            .await;
        assert_eq!(serde_json::to_value(library[0].outcome)?, expected);
        assert_eq!(library[0].http_status, Some(status));

        let direct = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "validate",
                "--rule",
                "acme.parity",
                "demo_abcd1234efgh5678",
                "--no-builtins",
                "--rules-path",
            ])
            .arg(&rules_path)
            .args([
                "--retries",
                "0",
                "--format",
                "json",
                "--allow-internal-ips",
                "--no-update-check",
            ])
            .output()?;
        assert_eq!(direct.status.code(), Some(if expected == "verified_active" { 0 } else { 1 }));
        let direct: Value = serde_json::from_slice(&direct.stdout)?;
        assert_eq!(direct["validation_outcome"], expected);
        assert_eq!(direct["status_code"], status);

        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(&input)
            .args(["--rule", "acme.parity", "--rules-path"])
            .arg(&rules_path)
            .args([
                "--load-builtins=false",
                "--validation-retries",
                "0",
                "--format",
                "json",
                "--output",
            ])
            .arg(&report_path)
            .args(["--allow-internal-ips", "--no-update-check"])
            .assert()
            .code(if expected == "verified_active" { 205 } else { 200 });
        let scan: Value = serde_json::from_slice(&fs::read(&report_path)?)?;
        assert_eq!(scan["findings"][0]["finding"]["validation"]["outcome"], expected);
        server.verify().await;
    }
    Ok(())
}
