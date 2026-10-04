use std::fs;

use assert_cmd::Command;
use predicates::{prelude::PredicateBooleanExt, str::contains};
use tempfile::TempDir;

/// 1. Path-does-not-exist ⇒ run_async_scan bails with “Invalid input”
#[test]
fn scan_fails_for_missing_path() {
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", "no/such/path/here", "--no-update-check"])
        .assert()
        .failure() // exit-code ≠ 0
        .stderr(contains("unrecognized scan target or path does not exist"));
}

/// 2. Malformed rule YAML ⇒ RuleLoader::load returns an error
#[test]
fn scan_fails_for_bad_rule_yaml() {
    let tmp = TempDir::new().unwrap();
    fs::write(tmp.path().join("broken.yml"), "this: is: : not yaml").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tmp.path().to_str().unwrap(), // dummy input dir (exists)
            "--rules-path",
            tmp.path().to_str().unwrap(), // point loader at bad YAML
            "--no-validate",              // keep the test fast
            "--no-update-check",          // skip update check to avoid network calls
        ])
        .assert()
        .failure()
        .stderr(contains("Failed to load rules")); // bubble-up from RuleLoader
}

/// 3. An invalid HTTP method makes validation inconclusive, not the credential inactive.
#[test]
fn scan_reports_inconclusive_validation_for_invalid_http_method() {
    let tmp = TempDir::new().unwrap();

    // Minimal rule with an invalid HTTP method containing whitespace.
    fs::write(
        tmp.path().join("bad_method.yml"),
        r#"
rules:
  - name: Bad HTTP verb
    id: demo.bad.http
    pattern: "dummy_[a-z0-9]{4}"
    validation:
      type: Http
      content:
        request:
          method: "BREW SPACE"
          url: "https://example.com/"
          response_matcher:
            - report_response: true
            - status:
                - 200
              type: StatusMatch
"#,
    )
    .unwrap();

    // Create a dummy input file that matches the rule
    fs::write(tmp.path().join("input.txt"), "dummy_dead").unwrap();

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tmp.path().join("input.txt").to_str().unwrap(),
            "--rules-path",
            tmp.path().to_str().unwrap(), // only the custom rule
            "--no-dedup",
            "--format",
            "pretty",
            "--load-builtins=false", // skip the builtin rules
            "--no-update-check",     // skip update check to avoid network calls
        ])
        .assert()
        .code(200)
        .stdout(
            contains("Validation InvalidConfiguration")
                .and(contains("Inconclusive Validation"))
                .and(contains("Inactive Credential").not()),
        );
}
