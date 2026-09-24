//! Candidate pairing is opt-in, bounded, and established only by authentication.
use serde_json::Value;
use std::{fs, time::Duration};
use tempfile::TempDir;
use wiremock::{Mock, MockServer, Request, ResponseTemplate, matchers::method};

const TOKEN: &str = "token_qmzrxwkvphtnsjby";
const GOOD: &str = "secret_qmzrxwkvphtnsjby";
const BAD: &str = "secret_jvptmrxhwnskqzby";

async fn scan(
    server: &MockServer,
    inputs: &[String],
    opt_in: bool,
    url: Option<&str>,
    extra_args: &[&str],
    second: bool,
) -> Value {
    let temp = TempDir::new().unwrap();
    let inputs_dir = temp.path().join("inputs");
    fs::create_dir(&inputs_dir).unwrap();
    for (i, input) in inputs.iter().enumerate() {
        fs::write(inputs_dir.join(format!("{i}.txt")), input).unwrap();
    }
    let rules = temp.path().join("rules.yml");
    let second_dependency = if second {
        "\n      - rule_id: custom.pair.other\n        variable: OTHER\n        verify_candidates: true\n        within: 5L"
    } else {
        ""
    };
    fs::write(
        &rules,
        format!(
            r#"
rules:
  - name: Secret component
    id: custom.pair.secret
    pattern: '(secret_[a-z0-9]{{16}})'
    min_entropy: 0
    confidence: high
    visible: false
  - name: Other component
    id: custom.pair.other
    pattern: '(other_[a-z0-9]{{16}})'
    min_entropy: 0
    confidence: high
    visible: false
  - name: Credential
    id: custom.pair.token
    pattern: '(token_[a-z]{{16}})'
    min_entropy: 0
    confidence: high
    depends_on_rule:
      - rule_id: custom.pair.secret
        variable: SECRET
        verify_candidates: {opt_in}
        within: 5L{second_dependency}
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{}'
          headers:
            Authorization: 'Bearer {{{{ TOKEN }}}}'
            X-Secret: '{{{{ SECRET }}}}'
            X-Endpoint: '{{{{ GITHUB_API_BASE_URL }}}}'
            X-Other: '{{{{ OTHER | default: "none" }}}}'
          response_matcher:
            - type: StatusMatch
              status: [200]
"#,
            url.unwrap_or(&server.uri())
        ),
    )
    .unwrap();
    let output = tokio::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["--no-update-check", "--allow-internal-ips", "scan"])
        .arg(inputs_dir)
        .args(["--load-builtins=false", "--rules-path"])
        .arg(rules)
        .args(["--format", "json", "--validation-retries", "0"])
        .args(extra_args)
        .output()
        .await
        .unwrap();
    serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .next()
        .expect("JSON report")
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)))
}

async fn server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|request: &Request| {
            ResponseTemplate::new(if request.headers.get("X-Secret").is_some_and(|v| v == GOOD) {
                200
            } else {
                401
            })
        })
        .mount(&server)
        .await;
    server
}

fn active(report: &Value) {
    let f = &report["findings"][0]["finding"];
    assert_eq!(f["validation"]["status"], "Active Credential", "{report}");
    assert!(f.get("ambiguous_dependencies").is_none(), "{report}");
    assert_eq!(f["dependent_captures"]["SECRET"], GOOD, "{report}");
    assert!(f.get("dependency_candidates").is_none());
}

#[tokio::test]
async fn matching_name_precedes_distance_and_falls_back_if_rejected() {
    for input in [
        format!(
            "prod_key={TOKEN} unrelated_secret={BAD} {} prod_secret={GOOD}",
            "padding ".repeat(80)
        ),
        format!("prod_key={TOKEN} prod_secret={BAD} unrelated_secret={GOOD}"),
    ] {
        let server = server().await;
        let report = scan(&server, std::slice::from_ref(&input), true, None, &[], false).await;
        active(&report);
        let requests = server.received_requests().await.unwrap();
        if input.contains("padding") {
            assert_eq!(requests.len(), 1);
        } else {
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0].headers["X-Secret"], BAD);
        }
        assert_eq!(requests.last().unwrap().headers["X-Secret"], GOOD);
    }
}

#[tokio::test]
async fn same_object_and_section_precede_distance() {
    for input in [
        format!(
            r#"{{"secret":"{GOOD}","padding":"{}","token":"{TOKEN}"}} {{"secret":"{BAD}"}}"#,
            "x".repeat(400)
        ),
        format!(
            "[other]\nsecret={BAD}\n[production]\nkey={TOKEN}\n{}\nsecret={GOOD}",
            "x".repeat(400)
        ),
    ] {
        let server = server().await;
        active(&scan(&server, &[input], true, None, &[], false).await);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers["X-Secret"], GOOD);
    }
}

#[tokio::test]
async fn no_opt_in_or_dynamic_destination_makes_no_requests() {
    for (opt_in, url, args) in [
        (false, None, vec![]),
        (true, Some("{{ SECRET }}"), vec![]),
        (true, None, vec!["--no-validate"]),
    ] {
        let server = server().await;
        let report =
            scan(&server, &[format!("{TOKEN} {GOOD} {BAD}")], opt_in, url, &args, false).await;
        assert!(server.received_requests().await.unwrap().is_empty());
        let f = &report["findings"][0]["finding"];
        assert_eq!(f["ambiguous_dependencies"]["SECRET"], 2, "{report}");
        assert!(f.get("dependent_captures").is_none());
        assert!(f.get("dependency_candidates").is_none());
        assert!(f.get("validate_command").is_none());
    }
}

#[tokio::test]
async fn opted_in_endpoints_do_not_start_candidate_searches() {
    for (variable, helper) in [
        ("BASEURL", "custom.location"),
        ("SERVICE_HOST", "custom.location"),
        ("GITHUB_API_BASE_URL", "custom.location"),
        ("LOCATION", "custom.service-endpoint.1"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let temp = TempDir::new().unwrap();
        let rules = temp.path().join("rules.yml");
        let input = temp.path().join("input.txt");
        let primary = serde_json::json!({
            "name": "Credential", "id": "custom.endpoint_pair", "pattern": "(token_[a-z]{16})", "min_entropy": 0,
            "depends_on_rule": [
                {"rule_id":"custom.secret", "variable":"SECRET", "within":"5L", "verify_candidates":true},
                {"rule_id":helper, "variable":variable, "within":"5L", "verify_candidates":true}
            ],
            "validation": {"type":"Http", "content":{"request":{
                "method":"GET", "url":server.uri(),
                "headers":{"Authorization":"Bearer {{ TOKEN }}", "X-Secret":"{{ SECRET }}"},
                "response_matcher":[{"type":"StatusMatch", "status":[200]}]
            }}}
        });
        let secret = serde_json::json!({"name":"Secret", "id":"custom.secret", "pattern":"(secret_[a-z]{16})", "min_entropy":0, "visible":false});
        let endpoint = serde_json::json!({"name":"Endpoint", "id":helper, "pattern":r"(https://[a-z]+\.invalid)", "min_entropy":0, "visible":false});
        fs::write(
            &rules,
            serde_yaml::to_string(&serde_json::json!({"rules":[primary,secret,endpoint]})).unwrap(),
        )
        .unwrap();
        // Both the credential and endpoint are ambiguous. The endpoint must block
        // the entire search even though the fixed validator would accept any pair.
        fs::write(
            &input,
            format!("{TOKEN} {BAD} {GOOD} https://first.invalid https://second.invalid"),
        )
        .unwrap();
        let output = tokio::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["--no-update-check", "--allow-internal-ips", "scan"])
            .arg(input)
            .args(["--load-builtins=false", "--rules-path"])
            .arg(rules)
            .args(["--format", "json", "--validation-retries", "0"])
            .output()
            .await
            .unwrap();
        let report = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter::<Value>()
            .next()
            .unwrap_or_else(|| panic!("{}", String::from_utf8_lossy(&output.stderr)))
            .unwrap();
        assert!(server.received_requests().await.unwrap().is_empty(), "{variable}");
        let finding = &report["findings"][0]["finding"];
        assert_eq!(finding["validation"]["status"], "Validation Skipped", "{report}");
        assert_eq!(finding["ambiguous_dependencies"][variable], 2, "{report}");
        assert!(finding.get("dependent_captures").is_none(), "{report}");
        assert!(finding.get("validate_command").is_none(), "{report}");
    }
}

#[tokio::test]
async fn combination_budget_exhaustion_is_unresolved() {
    let server = server().await;
    let input = format!(
        "{TOKEN} {}",
        (0..20).map(|i| format!("secret_{i:016}")).collect::<Vec<_>>().join(" ")
    );
    let report = scan(&server, &[input], true, None, &[], false).await;
    assert_eq!(server.received_requests().await.unwrap().len(), 16);
    let f = &report["findings"][0]["finding"];
    assert_eq!(f["validation"]["status"], "Validation Skipped", "{report}");
    assert!(f["validation"]["response"].as_str().unwrap().contains("combination budget exhausted"));
    assert!(f.get("dependent_captures").is_none());
}

#[tokio::test]
async fn throttling_timeout_and_redirects_do_not_select_or_forward_candidates() {
    for status in [429, 200, 302] {
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        let mut response =
            ResponseTemplate::new(status).insert_header("Location", destination.uri());
        if status == 200 {
            response = response.set_delay(Duration::from_secs(2));
        }
        Mock::given(method("GET"))
            .respond_with(move |request: &Request| {
                if status == 302 && request.headers.get("X-Secret").is_some_and(|v| v == GOOD) {
                    ResponseTemplate::new(200)
                } else {
                    response.clone()
                }
            })
            .mount(&server)
            .await;
        let report = scan(
            &server,
            &[format!("{TOKEN} {BAD} {GOOD}")],
            true,
            None,
            &["--validation-timeout", "1"],
            false,
        )
        .await;
        assert!(destination.received_requests().await.unwrap().is_empty());
        let f = &report["findings"][0]["finding"];
        assert_ne!(f["validation"]["status"], "Active Credential", "{report}");
        assert_ne!(f["validation"]["status"], "Inactive Credential", "{report}");
        assert!(f.get("dependent_captures").is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn opted_in_unambiguous_findings_also_disable_redirects() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", destination.uri()))
        .mount(&server)
        .await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&destination).await;
    let report = scan(&server, &[format!("{TOKEN} {GOOD}")], true, None, &[], false).await;
    assert!(!server.received_requests().await.unwrap().is_empty());
    assert!(destination.received_requests().await.unwrap().is_empty());
    assert_ne!(report["findings"][0]["finding"]["validation"]["status"], "Active Credential");
}

#[tokio::test]
async fn cache_reuses_exact_pairs_and_does_not_consume_a_secret_for_other_ids() {
    let server = server().await;
    let inputs = vec![
        format!("{TOKEN} {BAD} {GOOD}"),
        // Different candidate order prevents representative grouping from hiding cache hits.
        format!("prefix\n{TOKEN} {GOOD} {BAD}\n{TOKEN} {GOOD} {BAD}"),
        format!("token_vnpqjrxhmkwtzybs {BAD} {GOOD}"),
    ];
    let report = scan(
        &server,
        &inputs,
        true,
        None,
        &["--no-dedup", "--endpoint", "github=https://github.example.test"],
        false,
    )
    .await;
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 4, "{report}");
    assert!(
        findings.iter().all(|f| f["finding"]["validation"]["status"] == "Active Credential"),
        "{report}"
    );
    assert!(
        findings.iter().all(|f| f["finding"]["dependent_captures"]["SECRET"] == GOOD),
        "{report}"
    );
    for finding in findings {
        assert_eq!(
            finding["finding"]["dependent_captures"],
            findings[0]["finding"]["dependent_captures"]
        );
        assert_eq!(
            finding["finding"]["dependent_captures"]["GITHUB_API_BASE_URL"],
            "https://github.example.test/api/v3"
        );
        assert!(
            finding["finding"]["validate_command"]
                .as_str()
                .unwrap()
                .contains("https://github.example.test/api/v3")
        );
    }
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 4);
    assert!(
        requests.iter().all(|r| r.headers["X-Endpoint"] == "https://github.example.test/api/v3")
    );
}

#[tokio::test]
async fn multiple_dependencies_try_combinations_without_mixing_cached_results() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(|request: &Request| {
            ResponseTemplate::new(
                if request.headers.get("X-Secret").is_some_and(|v| v == GOOD)
                    && request.headers.get("X-Other").is_some_and(|v| v == "other_qmzrxwkvphtnsjby")
                {
                    200
                } else {
                    401
                },
            )
        })
        .mount(&server)
        .await;
    let report = scan(
        &server,
        &[format!("{TOKEN} {BAD} other_jvptmrxhwnskqzby {GOOD} other_qmzrxwkvphtnsjby")],
        true,
        None,
        &[],
        true,
    )
    .await;
    active(&report);
    assert_eq!(
        report["findings"][0]["finding"]["dependent_captures"]["OTHER"],
        "other_qmzrxwkvphtnsjby"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn redaction_hides_selected_and_unselected_candidates() {
    let server = server().await;
    let report =
        scan(&server, &[format!("{TOKEN} {BAD} {GOOD}")], true, None, &["--redact"], false).await;
    assert_eq!(report["findings"][0]["finding"]["validation"]["status"], "Active Credential");
    let serialized = report.to_string();
    for value in [TOKEN, GOOD, BAD] {
        assert!(!serialized.contains(value), "redacted report exposed a credential");
    }
    assert!(!serialized.contains("dependency_candidates"));
}

#[tokio::test]
async fn completely_rejected_combinations_do_not_mark_primary_inactive() {
    let server = server().await;
    let report =
        scan(&server, &[format!("{TOKEN} {BAD} secret_vnpqjrxhmkwtzybs")], true, None, &[], false)
            .await;
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
    let f = &report["findings"][0]["finding"];
    assert_eq!(f["validation"]["status"], "Validation Skipped", "{report}");
    assert!(
        f["validation"]["response"].as_str().unwrap().contains("no candidate combination verified")
    );
    assert!(f.get("dependent_captures").is_none());
}

/// Exercise the actual pinned provider expressions, changing only their destination
/// to a local mock and their detection patterns to synthetic fixture tokens.
#[tokio::test]
async fn builtin_http_expressions_try_rejected_then_valid_component() {
    let catalog = kingfisher_rules::defaults::get_builtin_rules(None).unwrap();
    let providers = [
        "browserstack-access-key.1",
        "clickhouse-cloud-api-secret-key",
        "mongodb-atlas-service-account-secret",
        "planetscale-api-token",
        "razorpay-key-secret.1",
        "wiz-client-secret.1",
    ];
    let cases = providers
        .into_iter()
        .map(|id| (id, 401))
        .chain([("browserstack-access-key.1", 429), ("browserstack-access-key.1", 302)]);
    for (id, rejected_status) in cases {
        let server = MockServer::start().await;
        use base64::Engine;
        let good_basic = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{GOOD}:{TOKEN}"))
        );
        Mock::given(wiremock::matchers::any())
            .respond_with(move |request: &Request| {
                let correct = request.headers.get("Authorization").is_some_and(|value| {
                    value == good_basic.as_str() || value == format!("{GOOD}:{TOKEN}").as_str()
                }) || String::from_utf8_lossy(&request.body)
                    .contains(&format!("client_id={GOOD}"));
                if correct {
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "automate_plan": "test", "id": "test", "name": "test",
                        "access_token": "synthetic", "type": "list", "items": []
                    }))
                } else {
                    ResponseTemplate::new(rejected_status).insert_header("Location", "/redirected")
                }
            })
            .mount(&server)
            .await;
        let temp = TempDir::new().unwrap();
        let mut primary =
            serde_json::to_value(&catalog.rules[&format!("betterleaks.{id}")]).unwrap();
        let variable = primary["depends_on_rule"][0]["variable"].as_str().unwrap().to_owned();
        primary["id"] = "custom.provider".into();
        primary["pattern"] = "(token_[a-z]{16})".into();
        primary["min_entropy"] = 0.into();
        primary["betterleaks_secret_group"] = 1.into();
        primary["betterleaks_filter"] = serde_json::Value::Null;
        primary["depends_on_rule"][0]["rule_id"] = "custom.component".into();
        // Component mappings still reference the original dependency variable.
        fn redirect_literals(value: &mut Value, destination: &str) {
            match value {
                Value::Object(map) => {
                    if map.get("kind").is_some_and(|kind| kind == "string")
                        && map
                            .get("value")
                            .and_then(Value::as_str)
                            .is_some_and(|v| v.starts_with("https://"))
                    {
                        map.insert("value".into(), destination.into());
                    } else {
                        for child in map.values_mut() {
                            redirect_literals(child, destination);
                        }
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        redirect_literals(child, destination);
                    }
                }
                _ => {}
            }
        }
        redirect_literals(&mut primary["validation"], &server.uri());
        let component = serde_json::json!({"name":"Component", "id":"custom.component",
            "pattern":"(secret_[a-z]{16})", "min_entropy":0, "visible":false});
        let rules = temp.path().join("rules.yml");
        fs::write(
            &rules,
            serde_yaml::to_string(&serde_json::json!({"rules":[primary, component]})).unwrap(),
        )
        .unwrap();
        let input = temp.path().join("input.txt");
        fs::write(&input, format!("prod_key={TOKEN} prod_secret={BAD} other_secret={GOOD}"))
            .unwrap();
        let output = tokio::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args(["--no-update-check", "--allow-internal-ips", "scan"])
            .arg(input)
            .args(["--load-builtins=false", "--rules-path"])
            .arg(rules)
            .args(["--format", "json", "--validation-retries", "0"])
            .output()
            .await
            .unwrap();
        let report = serde_json::Deserializer::from_slice(&output.stdout)
            .into_iter::<Value>()
            .next()
            .unwrap_or_else(|| panic!("{id}: {}", String::from_utf8_lossy(&output.stderr)))
            .unwrap();
        let finding = &report["findings"][0]["finding"];
        if rejected_status == 401 {
            assert_eq!(finding["validation"]["status"], "Active Credential", "{id}: {report}");
            assert_eq!(finding["dependent_captures"][&variable], GOOD, "{id}: {report}");
            assert_eq!(server.received_requests().await.unwrap().len(), 2, "{id}");
        } else {
            assert_ne!(finding["validation"]["status"], "Active Credential", "{id}: {report}");
            assert_eq!(finding["ambiguous_dependencies"][&variable], 2, "{id}: {report}");
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                1,
                "must stop on {rejected_status}"
            );
        }
    }
}
