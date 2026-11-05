use std::{fs, process::Command};

use assert_cmd::prelude::*;

#[test]
fn rc7_mapbox_builtins_scan_bare_tokens_and_apply_payload_filters() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("mapbox.txt");
    let report = directory.path().join("report.json");
    let signature = "Ab3DeF9gHk2mNp6Qr8St0A";
    let mut lines = Vec::new();
    let mut expected = Vec::new();
    for (id, prefix) in [("mapbox-api-token", "pk"), ("mapbox-secret-token", "sk")] {
        for (index, username) in ["fixture", "fixture地图"].into_iter().enumerate() {
            let payload = format!(r#"{{"u":"{username}","a":"clAb3DeF9gHk2mNp6Qr8St0Vw1"}}"#);
            let token = format!("{prefix}.{}.{signature}", URL_SAFE_NO_PAD.encode(payload));
            lines.push(if index == 0 {
                token.clone()
            } else {
                format!("MAPBOX_TOKEN=\"{token}\"")
            });
            lines.push(format!("x{token}"));
            lines.push(format!("{token}_"));
            expected.push((format!("betterleaks.{id}"), token));
        }
        for payload in [
            r#"{"u":"fixture","b":"clAb3DeF9gHk2mNp6Qr8St0Vw1"}"#,
            r#"{"u":"fixture","a":"clAb3DeF9gHk2mNp6Qr8St0Vw1","extra":true}"#,
        ] {
            lines.push(format!("{prefix}.{}.{signature}", URL_SAFE_NO_PAD.encode(payload)));
        }
        let payload = format!(r#"{{"u":"{}","a":"{}"}}"#, "a".repeat(120), "a".repeat(20));
        lines.push(format!("{prefix}.{}.{}", URL_SAFE_NO_PAD.encode(payload), "A".repeat(22)));
    }
    fs::write(&input, lines.join("\n")).unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
        .args([
            "--rule",
            "betterleaks.mapbox-api-token",
            "--rule",
            "betterleaks.mapbox-secret-token",
            "--git-history=none",
            "--no-validate",
            "--no-update-check",
            "--no-rule-cache",
            "--format=json",
        ])
        .arg("--output")
        .arg(&report)
        .assert()
        .code(200);
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let mut actual: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            (
                record["rule"]["id"].as_str().unwrap().to_string(),
                record["finding"]["snippet"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn veles_precedence_preserves_heroku_tokens_outside_veles_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("heroku.txt");
    let report = directory.path().join("report.json");
    let body: String = "Ab3DeF9gHk2mNp6Qr8St0Vw1".chars().cycle().take(57).collect();
    let mut tokens = Vec::new();
    let mut expected = Vec::new();
    for (last, id) in [
        ("A", "veles.secrets/herokuplatformkey"),
        ("_", "veles.secrets/herokuplatformkey"),
        ("-", "betterleaks.heroku-api-key-v2"),
    ] {
        let token = format!("HRKU-AA{body}{last}");
        tokens.push(token.clone());
        expected.push((id.to_string(), token));
    }
    fs::write(&input, tokens.join("\n")).unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
        .args([
            "--rule",
            "betterleaks.heroku-api-key-v2",
            "--rule",
            "veles.secrets/herokuplatformkey",
            "--git-history=none",
            "--no-validate",
            "--no-update-check",
            "--no-rule-cache",
            "--format=json",
        ])
        .arg("--output")
        .arg(&report)
        .assert()
        .code(200);
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let mut actual: Vec<_> = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            (
                record["rule"]["id"].as_str().unwrap().to_string(),
                record["finding"]["snippet"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    actual.sort();
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn builtins_do_not_report_files_from_their_names_alone() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("private.p12");
    let report = directory.path().join("report.json");
    fs::write(&input, []).unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
        .args(["--git-history=none", "--no-validate", "--no-update-check", "--format=json"])
        .arg("--output")
        .arg(&report)
        .assert()
        .success();
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[test]
fn custom_v2_path_only_rules_detect_empty_files_without_provider_requests() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.toml");
    let input = directory.path().join("private.key");
    let report = directory.path().join("report.json");
    fs::write(
        &rules,
        r#"
minVersion = "2.0.0"
[[rules]]
id = "key-file"
description = "Key file"
path = '\.key$'
tags = ["inventory"]
"#,
    )
    .unwrap();
    fs::write(&input, []).unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
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
        .arg(&rules)
        .arg("--output")
        .arg(&report)
        .assert()
        .code(200);
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["rule"]["id"], "custom.key-file");
}

#[test]
fn custom_v2_specificity_filters_contained_findings() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.toml");
    let input = directory.path().join("input.txt");
    let report = directory.path().join("report.json");
    fs::write(
        &rules,
        r#"
[[rules]]
id = "service"
description = "Service token"
regex = '(svc_Q7m2V9r4)'
specificity = 10
validate = '{result: "unknown"}'
revoke = '{result: "unknown"}'
[[rules]]
id = "generic"
regex = '(Q7m2V9r4)'
"#,
    )
    .unwrap();
    fs::write(&input, "svc_Q7m2V9r4\nQ7m2V9r4").unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .arg("scan")
        .arg(&input)
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
        .arg(&rules)
        .arg("--output")
        .arg(&report)
        .assert()
        .code(200);
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|finding| finding["rule"]["id"] == "custom.service"));
    assert!(findings.iter().any(|finding| finding["rule"]["id"] == "custom.generic"));
}

#[test]
fn custom_specificity_helpers_preserve_ancestors_and_do_not_outlive_owners() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.toml");
    let input = directory.path().join("input.txt");
    let report = directory.path().join("report.json");
    for (primary, helper, extra, content, mut expected) in [
        ("svc_(Q7m2V9r4)", "(Q7m2V9r4)", "", "svc_Q7m2V9r4", vec!["custom.primary"]),
        (
            "(Q7m2V9r4)",
            "helper_(R8n3W0s5)",
            "[[rules]]\nid='specific'\nregex='(owner_Q7m2V9r4)'\nspecificity=5\n\
             [[rules]]\nid='generic'\nregex='(W0s5)'\n",
            "owner_Q7m2V9r4 helper_R8n3W0s5",
            vec!["custom.specific", "custom.generic"],
        ),
    ] {
        fs::write(
            &rules,
            format!(
                r#"
[[rules]]
id='primary'
regex='{primary}'
components=[{{id='helper',within='1L'}}]
[[rules]]
id='helper'
regex='{helper}'
specificity=10
skipReport=true
{extra}
"#
            ),
        )
        .unwrap();
        fs::write(&input, content).unwrap();
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(&input)
            .args([
                "--git-history=none",
                "--no-validate",
                "--no-update-check",
                "--no-rule-cache",
                "--load-builtins=false",
                "--format=json",
                "--rules-path",
            ])
            .arg(&rules)
            .arg("--output")
            .arg(&report)
            .assert()
            .code(200);
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        let mut actual: Vec<_> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["rule"]["id"].as_str().unwrap())
            .collect();
        actual.sort_unstable();
        expected.sort_unstable();
        assert_eq!(actual, expected);
    }
}

#[test]
fn custom_keywords_gate_raw_and_decoded_sources_in_both_rule_formats() {
    use base64::{Engine, engine::general_purpose::STANDARD};

    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.txt");
    let report = directory.path().join("report.json");
    let token = "svc_Q7m2V9r4xR4vN8kT";
    let decoded_without_keyword =
        format!("configuration: {token} # scanning fixture without provider context");
    let decoded_with_keyword =
        format!("provider-context: {token} # scanning fixture with provider context");
    for (extension, rules) in [
        (
            "toml",
            r#"[[rules]]
id = "keyword-token"
regex = '(svc_Q7m2V9r4xR4vN8kT)'
keywords = ["provider-context"]
"#,
        ),
        (
            "yml",
            r#"rules:
  - name: Keyword token
    id: private.keyword-token
    pattern: '(svc_Q7m2V9r4xR4vN8kT)'
    keywords: [provider-context]
"#,
        ),
    ] {
        let rule_path = directory.path().join(format!("rules.{extension}"));
        fs::write(&rule_path, rules).unwrap();
        for (payload, expected) in [
            (token.to_owned(), 0),
            (format!("PrOvIdEr-CoNtExT {} {token}", "x".repeat(6000)), 1),
            (STANDARD.encode(&decoded_with_keyword), 1),
            (format!("provider-context {}", STANDARD.encode(&decoded_without_keyword)), 0),
        ] {
            fs::write(&input, payload).unwrap();
            Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .arg("scan")
                .arg(&input)
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
                .arg(&rule_path)
                .arg("--output")
                .arg(&report)
                .assert()
                .code(if expected == 0 { 0 } else { 200 });
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
            assert_eq!(report["findings"].as_array().unwrap().len(), expected, "{extension}");
        }
    }
}

#[tokio::test]
async fn custom_v2_blast_radius_validates_once_and_reports_only_public_analysis() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    let server = MockServer::start().await;
    let token = "svc_Q7m2V9r4xR4vN8kT";
    Mock::given(method("GET"))
        .and(path("/identity"))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "owner":"fixture-user", "private":"private-validation-evidence"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/permissions"))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("private-analysis-evidence"))
        .expect(1)
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let rule_path = directory.path().join("analysis.toml");
    let report_path = directory.path().join("analysis.json");
    fs::write(&rule_path,r#"
[[rules]]
id = "analysis-token"
description = "Service analysis token"
regex = '(svc_[A-Za-z0-9]{16})'
validate = '''
let response = http.get(env.get("SERVICE_URL") + "/identity", {"Authorization":"Bearer " + finding.secret});
response.status == 200 ? {"result":"valid", "analysis":response.json} : {"result":"invalid"}
'''
analyze = '''
let response = http.get(env.get("SERVICE_URL") + "/permissions", {"Authorization":"Bearer " + finding.secret});
{
  "identity":{"username":validation.analysis.owner},
  "capabilities":analysis.capabilities({"read":response.status == 200}),
  "metadata":{"environment":env.get("ENVIRONMENT"), "credential_echo":finding.secret}
}
'''
"#).unwrap();
    let origin = server.uri();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "blast-radius",
                "--rule",
                "custom.analysis-token",
                token,
                "--no-builtins",
                "--no-update-check",
                "--allow-internal-ips",
                "--format",
                "json",
                "--rules-path",
            ])
            .arg(&rule_path)
            .arg("--output")
            .arg(&report_path)
            .arg("--var")
            .arg(format!("SERVICE_URL={origin}"))
            .args(["--var", "ENVIRONMENT=production"])
            .assert()
            .success();
        fs::read_to_string(report_path).unwrap()
    })
    .await
    .unwrap();
    let report: serde_json::Value = serde_json::from_str(&output).unwrap();
    let mapped = &report[0]["result"];
    assert_eq!(mapped["identity"]["id"], "fixture-user");
    let analysis = &mapped["provider_metadata"]["betterleaks_analysis"];
    assert_eq!(analysis["capabilities"], serde_json::json!(["read"]));
    assert_eq!(analysis["metadata"]["environment"], "production");
    assert_eq!(analysis["metadata"]["credential_echo"], "[REDACTED]");
    assert!(!output.contains("private-validation-evidence"));
    assert!(!output.contains("private-analysis-evidence"));
    assert!(!output.contains(token));
    server.verify().await;
}

#[test]
fn cli_redacts_allowlisted_identity_metadata_and_private_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("identity.yml");
    let input = directory.path().join("input.txt");
    let token = "svc_Q7m2V9r4xR4vN8kT";
    fs::write(&input, token).unwrap();
    fs::write(&rules, serde_json::json!({"rules":[{
        "id":"custom.identity", "name":"Identity fixture", "pattern":"(svc_[A-Za-z0-9]{16})",
        "validation":{"type":"Betterleaks", "content":{
            "expression":r#"{result:"valid", analysis:{id:"12345678", username:"fixture-user", private:"private-evidence"}}"#,
            "capabilities":{"access_map":{"handler":"github"}}
        }}
    }]}).to_string()).unwrap();
    for redact in [false, true] {
        let report = directory.path().join(format!("report-{redact}.json"));
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .arg("scan")
            .arg(&input)
            .args([
                "--git-history=none",
                "--load-builtins=false",
                "--no-rule-cache",
                "--no-update-check",
                "--rules-path",
            ])
            .arg(&rules)
            .args(["--format", "json", "--output"])
            .arg(&report);
        if redact {
            command.arg("--redact");
        }
        command.assert().code(205);
        let output = fs::read_to_string(&report).unwrap();
        assert!(!output.contains("private-evidence"));
        assert_eq!(output.contains("fixture-user"), !redact, "{output}");
        if redact {
            assert!(output.contains("[REDACTED:"));
            assert!(!output.contains(token));
        }
    }
}

#[tokio::test]
async fn custom_v2_revoke_preserves_unknown_outcomes_after_submitted_mutations() {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };
    let server = MockServer::start().await;
    let token = "svc_Q7m2V9r4xR4vN8kT";
    Mock::given(method("DELETE"))
        .and(path("/revoke"))
        .and(header("authorization", format!("Bearer {token}")))
        .respond_with(ResponseTemplate::new(200).set_body_string("private-revocation-evidence"))
        .expect(3)
        .mount(&server)
        .await;
    let directory = tempfile::tempdir().unwrap();
    let origin = server.uri();
    tokio::task::spawn_blocking(move || {
        let rule_path=directory.path().join("revoke.toml");
        for (program,status,code) in [
            (r#"{result:"unknown"}"#,"unknown",1),
            (r#"{result:"error"}"#,"failed",1),
            (r#"let r=http.delete(env.get("SERVICE_URL")+"/revoke", {"Authorization":"Bearer "+finding.secret}); fromJSON(r.body)"#,"unknown",1),
            (r#"let r=http.delete(env.get("SERVICE_URL")+"/revoke", {"Authorization":"Bearer "+finding.secret}); {result:"revoked", unexpected:true}"#,"unknown",1),
            (r#"let r=http.delete(env.get("SERVICE_URL")+"/revoke", {"Authorization":"Bearer "+finding.secret}); r.status==200 ? {result:"revoked"} : {result:"error"}"#,"succeeded",0),
        ] {
            fs::write(&rule_path,format!("[[rules]]\nid='revoke-token'\nregex='(svc_[A-Za-z0-9]{{16}})'\nrevoke='''\n{program}\n'''\n")).unwrap();
            let assertion=Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
                .args(["revoke","--rule","custom.revoke-token",token,"--no-builtins",
                    "--no-update-check","--format","json","--retries","5","--rules-path"])
                .arg(&rule_path).arg("--var").arg(format!("SERVICE_URL={origin}"))
                .assert().code(code);
            let result:serde_json::Value=serde_json::from_slice(&assertion.get_output().stdout).unwrap();
            assert_eq!(result["revocation_status"],status,"{program}");
            assert_eq!(result["revoked"],status=="succeeded");
        }
    }).await.unwrap();
    server.verify().await;
}
