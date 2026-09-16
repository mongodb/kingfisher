//! Regressions for #500: resolve context before dedup and never guess endpoints.
use std::fs;

use serde_json::Value;
use tempfile::TempDir;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

async fn scan(
    files: &[String],
    within: Option<&str>,
    optional: bool,
    redact: bool,
) -> (Value, Vec<wiremock::Request>) {
    scan_with_extra_rules(files, within, optional, redact, "").await
}

async fn scan_with_extra_rules(
    files: &[String],
    within: Option<&str>,
    optional: bool,
    redact: bool,
    extra_rules: &str,
) -> (Value, Vec<wiremock::Request>) {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let temp = TempDir::new().unwrap();
    let inputs = temp.path().join("inputs");
    fs::create_dir(&inputs).unwrap();
    for (index, contents) in files.iter().enumerate() {
        fs::write(inputs.join(format!("{index}.py")), contents.replace("SERVER", &server.uri()))
            .unwrap();
    }
    let window = within.map(|value| format!("\n        within: '{value}'")).unwrap_or_default();
    let rules = temp.path().join("rules.yml");
    fs::write(
        &rules,
        format!(
            r#"
rules:
  - name: Test endpoint
    id: custom.issue500.endpoint
    pattern: '(http://127[.]0[.]0[.]1:[0-9]+/[ab])'
    min_entropy: 0
    confidence: high
    visible: false
  - name: Test token
    id: custom.issue500.token
    pattern: '(token_[a-z]{{16}})'
    min_entropy: 0
    confidence: high
    depends_on_rule:
      - rule_id: custom.issue500.endpoint
        variable: BASEURL
        optional: {optional}{window}
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{{{{ BASEURL }}}}'
          headers:
            Authorization: 'Bearer {{{{ TOKEN }}}}'
          response_matcher:
            - type: StatusMatch
              status: [200]
{extra_rules}
"#
        ),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .args(["--no-update-check", "--allow-internal-ips", "scan"])
        .arg(&inputs)
        .args(["--load-builtins=false", "--rules-path"])
        .arg(&rules)
        .args(["--format", "json", "--no-extract-archives"]);
    if redact {
        command.arg("--redact");
    }
    let output = command.output().await.unwrap();
    let report = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .next()
        .expect("JSON report")
        .unwrap_or_else(|error| {
            panic!(
                "{error}: {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
    (report, server.received_requests().await.unwrap())
}

const TOKEN: &str = "token_qmzrxwkvphtnsjby";

#[tokio::test]
async fn dedup_keeps_bare_and_paired_occurrences_in_either_order() {
    for reverse in [false, true] {
        let mut files = vec![
            TOKEN.to_string(),
            format!("{TOKEN}\nSERVER/a"),
            format!("# duplicate context\n{TOKEN}\nSERVER/a"),
        ];
        if reverse {
            files.reverse();
        }
        let (report, requests) = scan(&files, None, false, false).await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/a");
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 2, "{report}");
        assert!(
            findings.iter().any(|f| f["finding"]["validation"]["status"] == "Active Credential"),
            "{report}"
        );
        assert!(
            findings.iter().any(|f| f["finding"]["validation"]["response"]
                .as_str()
                .is_some_and(|s| s.contains("missing dependent"))),
            "{report}"
        );
    }
}

#[tokio::test]
async fn ambiguous_endpoints_are_skipped_even_with_a_nearer_comment() {
    for within in [None, Some("3L")] {
        let (report, requests) =
            scan(&[format!("SERVER/a\n# SERVER/b\n{TOKEN}")], within, false, false).await;
        assert!(requests.is_empty());
        let finding = &report["findings"][0]["finding"];
        assert_eq!(finding["ambiguous_dependencies"]["BASEURL"], 2, "{report}");
        assert!(
            finding["validation"]["response"].as_str().unwrap().contains("ambiguous dependency"),
            "{report}"
        );
        assert!(finding.get("validate_command").is_none());
        assert!(finding.get("dependent_captures").is_none());
    }
}

#[tokio::test]
async fn repeated_endpoint_values_are_not_ambiguous_and_redaction_hides_context() {
    for redact in [false, true] {
        let (report, requests) =
            scan(&[format!("SERVER/a\n{TOKEN}\nSERVER/a")], None, false, redact).await;
        assert_eq!(requests.len(), 1);
        let finding = &report["findings"][0]["finding"];
        assert!(finding.get("ambiguous_dependencies").is_none());
        assert_eq!(finding.get("dependent_captures").is_none(), redact, "{report}");
    }
}

#[tokio::test]
async fn window_resolves_one_endpoint_and_missing_required_window_drops_finding() {
    let (report, requests) =
        scan(&[format!("SERVER/b\n\nSERVER/a\n{TOKEN}")], Some("2L"), false, false).await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/a");
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    let (report, requests) =
        scan(&[format!("SERVER/a\n\n{TOKEN}")], Some("1L"), false, false).await;
    assert!(requests.is_empty());
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn distinct_windowed_pairs_in_one_blob_get_independent_results() {
    let (report, requests) =
        scan(&[format!("SERVER/a {TOKEN}\n\nSERVER/b {TOKEN}")], Some("1L"), false, false).await;
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().any(|request| request.url.path() == "/a"));
    assert!(requests.iter().any(|request| request.url.path() == "/b"));
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn optional_missing_window_does_not_borrow_another_occurrences_endpoint() {
    let (report, requests) =
        scan(&[format!("SERVER/a {TOKEN}\n\n{TOKEN}")], Some("1L"), true, false).await;
    assert_eq!(requests.len(), 1);
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .any(|finding| finding["finding"]["dependent_captures"]["BASEURL"].is_null()),
        "{report}"
    );
}

#[tokio::test]
async fn different_rules_cannot_share_an_unresolved_variable_by_name() {
    let extra_rules = r#"
  - name: Other endpoint
    id: custom.issue500.other-endpoint
    pattern: '(never_[a-z]{16})'
    visible: false
    min_entropy: 0
    confidence: high
  - name: Other token
    id: custom.issue500.other-token
    pattern: '(second_[a-z]{16})'
    min_entropy: 0
    confidence: high
    depends_on_rule:
      - rule_id: custom.issue500.other-endpoint
        variable: BASEURL
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{{ BASEURL }}'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [200]
"#;
    let (report, requests) = scan_with_extra_rules(
        &[format!("SERVER/a {TOKEN}\nsecond_qmzrxwkvphtnsjby")],
        None,
        false,
        false,
        extra_rules,
    )
    .await;
    assert_eq!(requests.len(), 1);
    let other = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["rule"]["id"] == "custom.issue500.other-token")
        .unwrap();
    assert!(other["finding"]["dependent_captures"]["BASEURL"].is_null(), "{report}");
    assert!(
        other["finding"]["validation"]["response"].as_str().unwrap().contains("missing dependent")
    );
}
