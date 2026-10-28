//! Portable CLI coverage; synthetic credentials only and local mock HTTP services.
use std::{
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

fn validation(url: String) -> Value {
    json!({"type":"Http","content":{"request":{
        "method":"GET","url":url,"headers":{"Authorization":"Bearer {{ TOKEN }}"},
        "response_matcher":[{"type":"StatusMatch","status":[200]}]
    }}})
}

fn document(primary: String, fallback: String, reuse: bool) -> Value {
    let profile = if reuse {
        json!({"id":"secondary","reuse_primary_validation_logic":true,"url":fallback})
    } else {
        json!({"id":"secondary","validation":validation(fallback)})
    };
    json!({"rules":[{"id":"custom.cli-fallback","name":"CLI fixture","pattern":"(synthetic-secret)",
        "validation":validation(primary),"fallbacks":[profile]}]})
}

fn fallback_revoke_args() -> Vec<String> {
    vec!["--fallbacks".into(), "--allow-internal-ips".into()]
}

fn revocation(url: String) -> Value {
    json!({"type":"Http","content":{"request":{
        "method":"DELETE","url":url,"headers":{"Authorization":"Bearer {{ TOKEN }}"},
        "body":"{{ TOKEN }}","response_matcher":[{"type":"StatusMatch","status":[200]}]
    }}})
}

async fn run(document: Value, command: &str, extra: Vec<String>) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.yml");
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let command = command.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kingfisher"));
        child.args(["--no-update-check", &command, "--rules-path"]).arg(&path).args([
            "--no-builtins",
            "--rule",
            "custom.cli-fallback",
            "--format",
            "json",
        ]);
        if command == "validate" {
            child.args(["--allow-internal-ips", "--retries", "0"]);
        }
        let output = child.args(extra).arg("synthetic-secret").output().unwrap();
        drop(directory);
        output
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn legacy_primary_revocation_never_follows_credential_bearing_redirects() {
    use wiremock::matchers::{body_string, header};
    // Cover both historical POST-to-GET and method-preserving redirect statuses.
    for status in [302, 307] {
        let server = MockServer::start().await;
        let destination = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/revoke"))
            .and(header("Authorization", "Bearer synthetic-secret"))
            .and(body_string("synthetic-secret"))
            .respond_with(
                ResponseTemplate::new(status).insert_header("Location", destination.uri()),
            )
            .expect(1)
            .mount(&server)
            .await;
        let rule = json!({"rules":[{"id":"custom.cli-fallback","name":"Legacy primary",
            "pattern":"(synthetic-secret)",
            "revocation":revocation(format!("{}/revoke", server.uri()))}]});
        let output = run(rule, "revoke", vec![]).await;
        let result: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
        assert_eq!(result["revoked"], false);
        assert!(destination.received_requests().await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn primary_only_is_default_for_both_profile_forms_and_explicit_opt_in_works() {
    for reuse in [true, false] {
        let server = MockServer::start().await;
        Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
        Mock::given(path("/secondary"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let rule = document(
            format!("{}/primary", server.uri()),
            format!("{}/secondary", server.uri()),
            reuse,
        );
        let output = run(rule.clone(), "validate", vec![]).await;
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["validation_outcome"], "verified_inactive");
        assert!(value.get("fallback_id").is_none());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        let output = run(rule, "validate", vec!["--fallbacks".into()]).await;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["validation_outcome"], "verified_active");
        assert_eq!(value["fallback_id"], "secondary");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }
}

#[tokio::test]
async fn unused_fallback_inputs_do_not_block_primary_validation() {
    let server = MockServer::start().await;
    Mock::given(path("/primary")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let rule =
        document(format!("{}/primary", server.uri()), "{{ MISSING_ENDPOINT }}/me".into(), true);
    let output = run(rule, "validate", vec![]).await;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn enabling_fallbacks_does_not_reassign_primary_positional_arguments() {
    use wiremock::matchers::header;
    let server = MockServer::start().await;
    Mock::given(path("/primary"))
        .and(header("X-Project", "primary-project"))
        .respond_with(ResponseTemplate::new(200))
        .expect(4)
        .mount(&server)
        .await;
    for legacy in [false, true] {
        let mut rule = document(
            format!("{}/primary", server.uri()),
            format!("{}/secondary", server.uri()),
            false,
        );
        rule["rules"][0]["validation"]["content"]["request"]["headers"]["X-Project"] =
            json!("{{ Z_PRIMARY_PROJECT }}");
        rule["rules"][0]["fallbacks"][0]["validation"]["content"]["request"]["headers"]["X-Project"] =
            json!("{{ A_FALLBACK_PROJECT }}");
        if legacy {
            rule["rules"][0]["fallbacks"] = json!([]);
            rule["rules"][0]["validation"]["content"]["request"]["url"] =
                json!([format!("{}/primary", server.uri()), "{{ A_FALLBACK_PROJECT }}/identity",]);
        }
        for enabled in [false, true] {
            let mut args = vec![
                "--arg".into(),
                "primary-project".into(),
                "--var".into(),
                "A_FALLBACK_PROJECT=secondary-project".into(),
            ];
            if enabled {
                args.push("--fallbacks".into());
            }
            let output = run(rule.clone(), "validate", args).await;
            assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn long_legacy_url_lists_do_not_block_primary_validation_in_the_cli() {
    let server = MockServer::start().await;
    Mock::given(path("/primary"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;
    let mut rule =
        document(format!("{}/primary", server.uri()), format!("{}/secondary", server.uri()), true);
    rule["rules"][0]["fallbacks"] = json!([]);
    rule["rules"][0]["validation"]["content"]["request"]["url"] = json!([
        format!("{}/primary", server.uri()),
        format!("{}/secondary", server.uri()),
        format!("{}/third", server.uri()),
        format!("{}/fourth", server.uri()),
    ]);
    for args in [vec![], vec!["--fallbacks".into()]] {
        let output = run(rule.clone(), "validate", args).await;
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["validation_outcome"],
            "verified_active"
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn request_rate_limit_applies_between_fallback_attempts() {
    let server = MockServer::start().await;
    let times = Arc::new(Mutex::new(Vec::new()));
    let recorded = times.clone();
    Mock::given(method("GET"))
        .respond_with(move |request: &wiremock::Request| {
            recorded.lock().unwrap().push(Instant::now());
            ResponseTemplate::new(if request.url.path() == "/primary" { 401 } else { 200 })
        })
        .mount(&server)
        .await;
    let rule =
        document(format!("{}/primary", server.uri()), format!("{}/secondary", server.uri()), true);
    let output =
        run(rule, "validate", vec!["--fallbacks".into(), "--validation-rps".into(), "10".into()])
            .await;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let times = times.lock().unwrap();
    assert_eq!(times.len(), 2);
    assert!(times[1].duration_since(times[0]) >= Duration::from_millis(80));
}

#[tokio::test]
async fn fallback_revocation_does_not_follow_redirects_to_another_environment() {
    let accepted = MockServer::start().await;
    let other = MockServer::start().await;
    Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&accepted).await;
    Mock::given(path("/secondary")).respond_with(ResponseTemplate::new(200)).mount(&accepted).await;
    Mock::given(method("DELETE"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/unintended", other.uri())),
        )
        .mount(&accepted)
        .await;
    Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&other).await;
    let mut rule = document(
        format!("{}/primary", accepted.uri()),
        format!("{}/secondary", accepted.uri()),
        true,
    );
    rule["rules"][0]["fallbacks"][0]["revocation"] = json!({"type":"Http","content":{"request":{
        "method":"DELETE", "url":"{{ VALIDATION_ORIGIN }}/revoke", "body":"{{ TOKEN }}",
        "response_matcher":[{"type":"StatusMatch","status":[200]}]
    }}});
    let output = run(rule, "revoke", fallback_revoke_args()).await;
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["revoked"], false);
    assert_eq!(value["fallback_id"], "secondary");
    assert_eq!(accepted.received_requests().await.unwrap().len(), 3);
    assert!(other.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_propagates_opt_in_and_generates_environment_bound_custom_rule_commands() {
    for enabled in [false, true] {
        let server = MockServer::start().await;
        Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
        Mock::given(path("/secondary"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let mut rule = document(
            format!("{}/primary", server.uri()),
            format!("{}/secondary", server.uri()),
            true,
        );
        rule["rules"][0]["fallbacks"][0]["revocation"] = json!({"type":"Http","content":{"request":{
            "method":"DELETE", "url":"{{ VALIDATION_ORIGIN }}/revoke",
            "response_matcher":[{"type":"StatusMatch","status":[204]}]
        }}});
        let directory = tempfile::tempdir().unwrap();
        let rules = directory.path().join("rules.yml");
        let input = directory.path().join("input.txt");
        std::fs::write(&rules, serde_json::to_vec(&rule).unwrap()).unwrap();
        std::fs::write(&input, "synthetic-secret").unwrap();
        let output = tokio::task::spawn_blocking(move || {
            let mut command = Command::new(env!("CARGO_BIN_EXE_kingfisher"));
            command
                .args(["--no-update-check", "scan"])
                .arg(input)
                .arg("--rules-path")
                .arg(rules)
                .args([
                    "--load-builtins=false",
                    "--rule",
                    "custom.cli-fallback",
                    "--allow-internal-ips",
                    "--format",
                    "json",
                ]);
            if enabled {
                command.arg("--fallbacks");
            }
            let output = command.output().unwrap();
            drop(directory);
            output
        })
        .await
        .unwrap();
        let status = output.status;
        let report = String::from_utf8(output.stdout).unwrap();
        // Scan emits a report envelope followed by a separate JSON summary.
        let envelope = serde_json::Deserializer::from_str(&report)
            .into_iter::<Value>()
            .next()
            .expect("scan report envelope")
            .unwrap_or_else(|_| {
                panic!(
                    "status={status}; stdout={report}; stderr={}",
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        let finding = &envelope["findings"][0]["finding"];
        assert_eq!(server.received_requests().await.unwrap().len(), if enabled { 2 } else { 1 });
        assert_eq!(finding["validate_command"].as_str().unwrap().contains("--fallbacks"), enabled);
        assert_eq!(
            finding["validation"]["outcome"],
            if enabled { "verified_active" } else { "verified_inactive" }
        );
        assert!(finding["dependent_captures"].get("VALIDATION_FALLBACK_ID").is_none());
        if enabled {
            let command = finding["revoke_command"].as_str().unwrap();
            assert!(!command.contains("VALIDATION_"));
            assert!(command.contains("--fallbacks"));
            assert!(command.contains("--rules-path"));
        }
    }
}

#[tokio::test]
async fn revoke_fallbacks_validates_then_reuses_only_the_selected_action_and_preserves_legacy_default()
 {
    use wiremock::matchers::{body_string, header};
    let server = MockServer::start().await;
    Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
    Mock::given(path("/secondary")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    Mock::given(method("DELETE"))
        .and(path("/primary/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/secondary/revoke"))
        .and(header("Authorization", "Bearer synthetic-secret"))
        .and(body_string("synthetic-secret"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut rule =
        document(format!("{}/primary", server.uri()), format!("{}/secondary", server.uri()), true);
    rule["rules"][0]["revocation"] = json!({"type":"Http","content":{"request":{
        "method":"DELETE","url":format!("{}/primary/revoke",server.uri()),
        "headers":{"Authorization":"Bearer {{ TOKEN }}"},"body":"{{ TOKEN }}",
        "response_matcher":[{"type":"StatusMatch","status":[200]}]
    }}});
    rule["rules"][0]["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
    rule["rules"][0]["fallbacks"][0]["revocation_url"] =
        json!(format!("{}/secondary/revoke", server.uri()));
    let legacy = run(rule.clone(), "revoke", vec![]).await;
    assert_eq!(serde_json::from_slice::<Value>(&legacy.stdout).unwrap()["revoked"], true);
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].url.path(), "/primary/revoke");

    let revoked = run(rule, "revoke", fallback_revoke_args()).await;
    let value = serde_json::from_slice::<Value>(&revoked.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&revoked.stderr)));
    assert_eq!(value["revoked"], true);
    assert_eq!(value["fallback_id"], "secondary");
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[1].url.path(), "/primary");
    assert_eq!(calls[2].url.path(), "/secondary");
    assert_eq!(calls[3].url.path(), "/secondary/revoke");
}

#[tokio::test]
async fn fallback_revocation_fails_closed_before_any_mutation_or_other_environment_probing() {
    for (scenario, primary_status, secondary_status, expected_reads) in [
        ("inactive", 401, 401, 2),
        ("unavailable_primary", 503, 401, 2),
        ("unavailable_secondary", 401, 503, 2),
        ("missing_secondary_action", 401, 200, 2),
        ("missing_primary_action", 200, 200, 1),
        ("non_authoritative", 200, 200, 0),
        ("no_validator", 200, 200, 0),
        ("assumed", 200, 200, 0),
        ("forged_selection", 200, 200, 0),
        ("shadowed_token", 200, 200, 0),
        ("private_target", 200, 200, 0),
        ("ambiguous_rule", 200, 200, 0),
    ] {
        let server = MockServer::start().await;
        Mock::given(path("/primary"))
            .respond_with(ResponseTemplate::new(primary_status))
            .mount(&server)
            .await;
        Mock::given(path("/secondary"))
            .respond_with(ResponseTemplate::new(secondary_status))
            .mount(&server)
            .await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let mut rule = document(
            format!("{}/primary", server.uri()),
            format!("{}/secondary", server.uri()),
            true,
        );
        rule["rules"][0]["revocation"] = revocation(format!("{}/primary/revoke", server.uri()));
        if scenario != "missing_secondary_action" {
            rule["rules"][0]["fallbacks"][0]["revocation"] =
                revocation(format!("{}/secondary/revoke", server.uri()));
        }
        let mut args = fallback_revoke_args();
        match scenario {
            "missing_primary_action" => {
                rule["rules"][0].as_object_mut().unwrap().remove("revocation");
            }
            "non_authoritative" => rule["rules"][0]["authoritative"] = json!(false),
            "no_validator" | "assumed" => {
                rule["rules"][0]["fallbacks"] = json!([]);
                rule["rules"][0]["validation"] =
                    if scenario == "assumed" { json!({"type":"Assumed"}) } else { Value::Null };
            }
            "forged_selection" => {
                args.extend(["--var".into(), "VALIDATION_FALLBACK_ID=secondary".into()])
            }
            "shadowed_token" => args.extend(["--var".into(), "TOKEN=forged".into()]),
            "private_target" => args = vec!["--fallbacks".into()],
            "ambiguous_rule" => {
                let mut other = rule["rules"][0].clone();
                other["id"] = json!("custom.cli-fallback.other");
                rule["rules"].as_array_mut().unwrap().push(other);
            }
            _ => {}
        }
        let output = run(rule, "revoke", args).await;
        assert!(!output.status.success(), "{scenario}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("synthetic-secret"),
            "{scenario}"
        );
        let calls = server.received_requests().await.unwrap();
        assert_eq!(
            calls.len(),
            expected_reads,
            "{scenario}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(calls.iter().all(|request| request.method == "GET"), "{scenario}");
    }
}

#[tokio::test]
async fn failed_mutations_are_never_retried_at_the_same_or_another_environment() {
    for status in [429, 500] {
        let server = MockServer::start().await;
        Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
        Mock::given(path("/secondary"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(path("/secondary/revoke"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let mut rule = document(
            format!("{}/primary", server.uri()),
            format!("{}/secondary", server.uri()),
            true,
        );
        rule["rules"][0]["fallbacks"][0]["revocation"] =
            revocation(format!("{}/secondary/revoke", server.uri()));
        rule["rules"][0]["fallbacks"].as_array_mut().unwrap().push(json!({
            "id":"third","reuse_primary_validation_logic":true,"url":format!("{}/third",server.uri()),
            "revocation":revocation(format!("{}/third/revoke",server.uri()))
        }));
        let mut args = fallback_revoke_args();
        args.extend(["--retries".into(), "5".into()]);
        let output = run(rule, "revoke", args).await;
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["revoked"], false);
        assert_eq!(value["revocation_status"], "unknown");
        let calls = server.received_requests().await.unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[2].url.path(), "/secondary/revoke");
    }
}

#[tokio::test]
async fn fallback_selection_deadline_prevents_all_mutations() {
    let server = MockServer::start().await;
    Mock::given(path("/primary"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&server)
        .await;
    Mock::given(path("/secondary")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let mut rule =
        document(format!("{}/primary", server.uri()), format!("{}/secondary", server.uri()), true);
    rule["rules"][0]["revocation"] = revocation(format!("{}/primary/revoke", server.uri()));
    let mut args = fallback_revoke_args();
    args.extend(["--timeout".into(), "1".into()]);
    let output = run(rule, "revoke", args).await;
    assert!(!output.status.success());
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].method, "GET");
}

#[tokio::test]
async fn automatic_selection_preserves_reused_multi_step_inputs_and_response_extractors() {
    use wiremock::matchers::body_string;
    let server = MockServer::start().await;
    Mock::given(path("/primary")).respond_with(ResponseTemplate::new(401)).mount(&server).await;
    Mock::given(path("/secondary")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    Mock::given(path("/secondary/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id":"key-7"})))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/secondary/keys/key-7"))
        .and(body_string("extra-payload"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let mut rule =
        document(format!("{}/primary", server.uri()), format!("{}/secondary", server.uri()), true);
    rule["rules"][0]["revocation"] = json!({"type":"HttpMultiStep","content":{"steps":[
        {"request":{"method":"GET","url":format!("{}/primary/keys",server.uri())},
            "extract":{"KEY_ID":{"type":"JsonPath","path":"$.id"}}},
        {"request":{"method":"DELETE","url":format!("{}/primary/keys/{{{{ KEY_ID }}}}",server.uri()),
            "body":"{{ EXTRA }}","response_matcher":[{"type":"StatusMatch","status":[200]}]}}
    ]}});
    rule["rules"][0]["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
    rule["rules"][0]["fallbacks"][0]["revocation_urls"] = json!([
        "{{ VALIDATION_ORIGIN }}/secondary/keys",
        "{{ VALIDATION_ORIGIN }}/secondary/keys/{{ KEY_ID }}"
    ]);
    let mut args = fallback_revoke_args();
    args.extend(["--arg".into(), "extra-payload".into()]);
    let output = run(rule, "revoke", args).await;
    let value: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(value["revoked"], true);
    let calls = server.received_requests().await.unwrap();
    assert_eq!(calls.len(), 4);
    assert_eq!(calls[2].url.path(), "/secondary/keys");
    assert_eq!(calls[3].url.path(), "/secondary/keys/key-7");
}
