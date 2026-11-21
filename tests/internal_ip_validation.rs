use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use anyhow::Result;
use serde_json::{Value, json};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

fn http_request(method: &str, url: String) -> Value {
    json!({
        "type": "Http",
        "content": {
            "request": {
                "method": method,
                "url": url,
                "headers": {"Authorization": "Bearer {{ TOKEN }}"},
                "response_matcher": [{"type": "StatusMatch", "status": [200]}]
            }
        }
    })
}

fn command(subcommand: &str, rules: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kingfisher"));
    command.args(["--no-update-check", subcommand, "--rules-path"]).arg(rules);
    command.env("NO_PROXY", "*");
    command
}

async fn run(mut command: Command) -> Result<Output> {
    Ok(tokio::task::spawn_blocking(move || command.output()).await??)
}

#[tokio::test]
async fn scan_limits_private_validation_to_approved_rules() -> Result<()> {
    let server = MockServer::start().await;
    let directory = tempfile::tempdir()?;
    let rules_path = directory.path().join("rules.yml");
    let input_path = directory.path().join("input.txt");
    let report_path = directory.path().join("report.json");
    let cases = [
        ("marked", Some(true)),
        ("vault-token", Some(false)),
        ("group/token", None),
        ("unrelated", None),
    ];
    let mut rules = Vec::new();
    let mut input = String::new();
    for (index, (suffix, allow_internal_ips)) in cases.iter().enumerate() {
        let token = format!("kf{index}_Q7m2V9r4xR4vN8kT");
        input.push_str(&token);
        input.push('\n');
        let mut rule = json!({
            "id": format!("custom.{suffix}"),
            "name": format!("Fixture {suffix}"),
            "pattern": format!("({token})"),
            "validation": http_request("GET", format!("{}/{suffix}", server.uri()))
        });
        if let Some(allowed) = allow_internal_ips {
            rule["allow_internal_ips"] = json!(allowed);
        }
        rules.push(rule);
    }
    fs::write(&input_path, input)?;
    fs::write(&rules_path, yaml_serde::to_string(&json!({"rules": rules}))?)?;
    fs::write(
        directory.path().join("kingfisher.yml"),
        "global:\n  enable_rule_internal_ips: true\n  enable_internal_ips_for: ['custom.vault-*']\n",
    )?;

    let scenarios: &[(&[&str], &[&str])] = &[
        (&[], &[]),
        (&["--enable-rule-internal-ips"], &["marked"]),
        (
            &[
                "--enable-rule-internal-ips",
                "--enable-internal-ips-for",
                "custom.vault-*",
                "--enable-internal-ips-for",
                "custom.group*",
                "--enable-internal-ips-for",
                "custom.Unrelated",
            ],
            &["group/token", "marked", "vault-token"],
        ),
        (
            &["--config", "kingfisher.yml", "--enable-internal-ips-for", "custom.group*"],
            &["group/token", "marked", "vault-token"],
        ),
        (&["--allow-internal-ips"], &["group/token", "marked", "unrelated", "vault-token"]),
    ];
    for (flags, expected) in scenarios {
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
        let mut scan = command("scan", &rules_path);
        scan.current_dir(directory.path())
            .arg(&input_path)
            .args([
                "--load-builtins=false",
                "--no-rule-cache",
                "--validation-retries=0",
                "--format=json",
                "--output",
            ])
            .arg(&report_path)
            .args(*flags);
        let output = run(scan).await?;
        assert_eq!(
            output.status.code(),
            Some(if expected.is_empty() { 200 } else { 205 }),
            "{flags:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let report: Value = serde_json::from_slice(&fs::read(&report_path)?)?;
        let findings = report["findings"].as_array().unwrap();
        assert_eq!(findings.len(), cases.len(), "{flags:?}");
        for (suffix, _) in cases {
            let id = format!("custom.{suffix}");
            let finding = findings.iter().find(|finding| finding["rule"]["id"] == id).unwrap();
            let outcome = if expected.contains(&suffix) { "verified_active" } else { "skipped" };
            assert_eq!(finding["finding"]["validation"]["outcome"], outcome, "{flags:?}: {id}");
        }

        let requests = server.received_requests().await.unwrap();
        let mut requested: Vec<_> =
            requests.iter().map(|request| request.url.path().strip_prefix('/').unwrap()).collect();
        requested.sort_unstable();
        assert_eq!(requested, *expected, "{flags:?}");
    }
    Ok(())
}

#[tokio::test]
async fn direct_validation_selects_betterleaks_rules_by_their_loaded_id() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let directory = tempfile::tempdir()?;
    let rules = directory.path().join("rules.toml");
    let token = "svc_Q7m2V9r4xR4vN8kT";
    fs::write(
        &rules,
        format!(
            r#"[[rules]]
id = "toml-token"
description = "TOML validation fixture"
regex = '({token})'
validate = '''
let r = http.get("{}/identity", {{"Authorization": "Bearer " + finding.secret}});
r.status == 200 ? {{"result": "valid"}} : validate.unknown(r)
'''
"#,
            server.uri()
        ),
    )?;
    for (pattern, expected) in [
        ("toml-token", "unavailable"),
        ("custom.toml", "unavailable"),
        ("custom.toml-token", "verified_active"),
    ] {
        let mut validate = command("validate", &rules);
        validate.args([
            "--no-builtins",
            "--rule",
            "custom.toml-token",
            "--format=json",
            "--enable-internal-ips-for",
            pattern,
            token,
        ]);
        let output = run(validate).await?;
        let result: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
        assert_eq!(result["validation_outcome"], expected, "{pattern}");
        assert_eq!(output.status.success(), expected == "verified_active", "{pattern}");
    }

    let mut invalid = command("validate", &rules);
    invalid.args([
        "--no-builtins",
        "--rule",
        "custom.toml-token",
        "--enable-internal-ips-for",
        "[",
        token,
    ]);
    let output = run(invalid).await?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--enable-internal-ips-for"));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/identity");
    Ok(())
}

#[tokio::test]
async fn revoke_fallbacks_requires_permission_for_private_prevalidation() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let directory = tempfile::tempdir()?;
    let rules = directory.path().join("rules.yml");
    let token = "svc_Q7m2V9r4xR4vN8kT";
    fs::write(
        &rules,
        yaml_serde::to_string(&json!({"rules": [{
            "id": "custom.marked",
            "name": "Fixture marked",
            "pattern": format!("({token})"),
            "allow_internal_ips": true,
            "validation": http_request("GET", format!("{}/identity", server.uri())),
            "revocation": http_request("DELETE", format!("{}/revoke", server.uri()))
        }]}))?,
    )?;

    let mut denied = command("revoke", &rules);
    denied.args(["--no-builtins", "--rule", "custom.marked", "--fallbacks", token]);
    let output = run(denied).await?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("TargetBlocked"));
    assert!(server.received_requests().await.unwrap().is_empty());

    let mut allowed = command("revoke", &rules);
    allowed.args([
        "--no-builtins",
        "--rule",
        "custom.marked",
        "--fallbacks",
        "--enable-rule-internal-ips",
        "--format=json",
        token,
    ]);
    let output = run(allowed).await?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let result: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(result["revoked"], true);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].url.path(), "/identity");
    assert_eq!(requests[1].method, "DELETE");
    assert_eq!(requests[1].url.path(), "/revoke");
    Ok(())
}

#[tokio::test]
async fn revoke_fallbacks_checks_the_mutation_target_after_public_prevalidation() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let directory = tempfile::tempdir()?;
    let rules = directory.path().join("rules.yml");
    let token = "svc_Q7m2V9r4xR4vN8kT";
    fs::write(
        &rules,
        yaml_serde::to_string(&json!({"rules": [{
            "id": "custom.checked",
            "name": "Fixture checked",
            "pattern": format!("({token})"),
            "validation": http_request("GET", "http://1.1.1.1/identity".into()),
            "revocation": http_request("DELETE", format!("{}/revoke", server.uri()))
        }]}))?,
    )?;

    let revoke = || {
        let mut command = command("revoke", &rules);
        // Simulate a public validation peer on a local proxy and keep all test traffic local.
        command
            .env_remove("http_proxy")
            .env_remove("no_proxy")
            .env("HTTP_PROXY", server.uri())
            .env("NO_PROXY", "127.0.0.1")
            .args(["--no-builtins", "--rule", "custom.checked", "--format=json", token]);
        command
    };
    let mut denied = revoke();
    denied.arg("--fallbacks");
    let output = run(denied).await?;
    assert!(!output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{}", String::from_utf8_lossy(&output.stderr)));
    assert_eq!(result["revoked"], false);
    assert!(result["message"].as_str().unwrap().contains("target_blocked"), "{result}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/identity");

    // A direct primary invocation still works with the same private endpoint.
    let output = run(revoke()).await?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].method, "DELETE");
    assert_eq!(requests[1].url.path(), "/revoke");
    Ok(())
}
