use std::{
    fs,
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};

use anyhow::Result;
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt, net::TcpListener, process::Command, time::timeout};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};

const TIMEOUT: Duration = Duration::from_secs(30);

fn scan(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kingfisher"));
    command.current_dir(root).kill_on_drop(true).env("NO_PROXY", "*").args([
        "scan",
        "--jobs",
        "2",
        "--load-builtins=false",
        "--rules-path",
        "rules.yml",
    ]);
    command
}

async fn run(mut command: Command) -> Result<Output> {
    Ok(timeout(TIMEOUT, command.output()).await??)
}

fn assert_success(output: &Output) -> String {
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn validation_rule(id: &str, token: &str, url: &str) -> Value {
    json!({
        "id": id,
        "name": "Preview fixture validator",
        "pattern": format!("({token})"),
        "min_entropy": 0,
        "confidence": "high",
        "validation": {
            "type": "Http",
            "content": {"request": {
                "method": "GET",
                "url": url,
                "headers": {"Authorization": "Bearer {{ TOKEN }}"},
                "response_matcher": [{"type": "StatusMatch", "status": [200]}]
            }}
        }
    })
}

fn write_simple_rules(root: &Path) -> Result<()> {
    fs::write(
        root.join("rules.yml"),
        "rules:\n  - id: preview.detector\n    name: Preview fixture\n    pattern: '(fixture_token)'\n    confidence: high\n",
    )?;
    Ok(())
}

#[tokio::test]
async fn preview_matches_scan_rule_selection_and_internal_ip_policy() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(any()).respond_with(ResponseTemplate::new(200)).mount(&server).await;
    let root = tempfile::tempdir()?;
    let directory = root.path();
    let source = directory.join("source/configs");
    fs::create_dir_all(source.join("generated"))?;

    let mut contents = String::from("helper_value\n");
    let mut rules = vec![json!({
        "id": "preview.helper", "name": "Preview fixture helper", "pattern": "(helper_value)",
        "min_entropy": 0, "confidence": "low", "visible": false
    })];
    for (index, suffix) in
        ["blocked", "cli-glob", "config-glob", "excluded", "marked", "low"].into_iter().enumerate()
    {
        let token = format!("preview{index}_Q7m2V9r4xR4vN8kT");
        contents.push_str(&token);
        contents.push('\n');
        let mut rule = validation_rule(
            &format!("preview.{suffix}"),
            &token,
            &format!("{}/validate/{suffix}", server.uri()),
        );
        match suffix {
            "marked" => {
                rule["allow_internal_ips"] = json!(true);
                rule["depends_on_rule"] =
                    json!([{"rule_id": "preview.helper", "variable": "HELPER"}]);
            }
            "config-glob" => rule["allow_internal_ips"] = json!(false),
            "low" => rule["confidence"] = json!("low"),
            _ => {}
        }
        rules.push(rule);
    }
    fs::write(source.join("key.env"), &contents)?;
    fs::write(source.join("settings.txt"), &contents)?;
    fs::write(source.join("generated/key.env"), &contents)?;
    fs::write(directory.join("rules.yml"), yaml_serde::to_string(&json!({"rules": rules}))?)?;
    fs::write(
        directory.join("kingfisher.yml"),
        yaml_serde::to_string(&json!({
            "scan": {"confidence": "low"},
            "rules": {"enabled": ["preview"], "cache_dir": "rule-cache"},
            "filters": {
                "skip_path_prefixes": ["configs/generated/"],
                "file_extensions": ["env"],
                "skip_words": ["sensitive-skip-word-fixture"],
                "skip_regex": ["sensitive-skip-regex-fixture"]
            },
            "global": {
                "enable_rule_internal_ips": true,
                "enable_internal_ips_for": ["preview.config-*"]
            },
            "output": {"format": "json", "path": "report.json"},
            "git": {"clone_dir": "clones"},
            "alerts": {"webhooks": [{
                "url": format!("{}/hook/sensitive-webhook-fixture", server.uri()),
                "format": "generic", "on": "always"
            }]}
        }))?,
    )?;

    let command = || {
        let mut command = scan(directory);
        command.args([
            "--no-update-check",
            "--config",
            "kingfisher.yml",
            "--confidence",
            "high",
            "--path-prefix",
            "configs/",
            "--exclude-rule",
            "preview.excluded",
            "--enable-internal-ips-for",
            "preview.cli-*",
            "--audit-log",
            "audit.jsonl",
            "--no-dedup",
            "source",
        ]);
        command
    };
    let mut preview = command();
    preview.arg("--preview");
    let text = assert_success(&run(preview).await?);
    for field in [
        "Local path",
        "source",
        "Include prefixes",
        "configs/",
        "Exclude prefixes",
        "configs/generated/",
        "Include extensions",
        "env",
        "Minimum confidence",
        "high",
        "Skip words",
        "Skip regexes",
        "Selected rules (5)",
    ] {
        assert!(text.contains(field), "missing {field:?} from preview:\n{text}");
    }
    let mut rule_rows =
        text.lines().filter_map(|line| line.trim().split_once(" | internal-IP access: "));
    assert_eq!(rule_rows.next(), Some(("preview.blocked", "blocked")), "{text}");
    assert_eq!(rule_rows.next(), Some(("preview.cli-glob", "allowed (rule ID glob)")), "{text}");
    assert_eq!(rule_rows.next(), Some(("preview.config-glob", "allowed (rule ID glob)")), "{text}");
    assert_eq!(
        rule_rows.next(),
        Some(("preview.helper [dependency helper]", "n/a (detection only)")),
        "{text}"
    );
    assert_eq!(rule_rows.next(), Some(("preview.marked", "allowed (YAML opt-in)")), "{text}");
    assert!(rule_rows.next().is_none(), "{text}");
    assert!(!text.contains("sensitive-"), "{text}");

    let mut allow_all = command();
    allow_all.args(["--preview", "--allow-internal-ips"]);
    let text = assert_success(&run(allow_all).await?);
    assert!(text.contains("preview.blocked | internal-IP access: allowed (--allow-internal-ips)"));

    assert!(server.received_requests().await.unwrap().is_empty());
    for artifact in ["rule-cache", "clones", "report.json", "audit.jsonl"] {
        assert!(!directory.join(artifact).exists(), "preview created {artifact}");
    }

    let output = run(command()).await?;
    assert_eq!(output.status.code(), Some(205), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&fs::read(directory.join("report.json"))?)?;
    let findings = report["findings"].as_array().unwrap();
    let mut outcomes: Vec<_> = findings
        .iter()
        .map(|finding| {
            assert!(finding["finding"]["path"].as_str().unwrap().ends_with("key.env"));
            (
                finding["rule"]["id"].as_str().unwrap(),
                finding["finding"]["validation"]["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    outcomes.sort_unstable();
    assert_eq!(
        outcomes,
        [
            ("preview.blocked", "skipped"),
            ("preview.cli-glob", "verified_active"),
            ("preview.config-glob", "verified_active"),
            ("preview.marked", "verified_active"),
        ]
    );
    let requests = server.received_requests().await.unwrap();
    let mut destinations: Vec<_> = requests.iter().map(|request| request.url.path()).collect();
    destinations.sort_unstable();
    assert_eq!(
        destinations,
        [
            "/hook/sensitive-webhook-fixture",
            "/validate/cli-glob",
            "/validate/config-glob",
            "/validate/marked",
        ]
    );
    Ok(())
}

#[tokio::test]
async fn preview_describes_remote_scope_without_network_requests() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(any()).respond_with(ResponseTemplate::new(404)).mount(&server).await;
    // Keep the preview's automatic update check enabled. A regression would open a
    // tunnel through this proxy, which rejects the request before any external connection.
    let proxy = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_url = format!("http://{}", proxy.local_addr()?);
    let proxy_probe = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await?;
        stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await
    });
    let root = tempfile::tempdir()?;
    write_simple_rules(root.path())?;
    let network_preview = || {
        let mut command = scan(root.path());
        command
            .env_remove("http_proxy")
            .env_remove("https_proxy")
            .env_remove("all_proxy")
            .env_remove("no_proxy")
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env_remove("KF_GITHUB_TOKEN")
            .arg("--preview");
        command
    };

    let endpoint = format!(
        "http://fixture-user:fixture-password@{}/scope?signature=fixture-query#fixture-fragment",
        server.address()
    );
    let mut github = network_preview();
    github.args([
        "github",
        "--org",
        "example-team",
        "--github-exclude",
        "example-team/archive*",
        "--api-url",
        &endpoint,
    ]);
    let text = assert_success(&run(github).await?);
    assert!(text.contains("GitHub") && text.contains("example-team"), "{text}");
    assert!(text.contains("example-team/archive*") && text.contains("/scope"), "{text}");
    for secret in ["fixture-user", "fixture-password", "fixture-query", "fixture-fragment"] {
        assert!(!text.contains(secret), "{text}");
    }

    let mut git = network_preview();
    let repository_url = format!("{}/example-team/repository.git", server.uri());
    git.args([&repository_url, "--git-history", "none", "--branch", "feature"])
        .arg("--no-validate");
    let text = assert_success(&run(git).await?);
    assert!(text.contains("Git repository") && text.contains(&repository_url), "{text}");
    assert!(text.contains("Git scope") && text.contains("feature"), "{text}");
    assert!(text.contains("Credential validation: disabled (--no-validate)"), "{text}");
    assert!(server.received_requests().await.unwrap().is_empty());
    assert!(!proxy_probe.is_finished(), "preview connected to the update proxy");
    proxy_probe.abort();
    Ok(())
}

#[tokio::test]
async fn preview_does_not_read_piped_stdin() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_simple_rules(root.path())?;
    let mut child = scan(root.path())
        .args(["--no-update-check", "--preview", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Take the handle so wait_with_output cannot close it and unblock a mistaken read.
    let stdin = child.stdin.take().unwrap();
    let output = timeout(TIMEOUT, child.wait_with_output()).await??;
    drop(stdin);
    let text = assert_success(&output);
    assert!(text.contains("Standard input (-)"), "{text}");
    Ok(())
}

#[tokio::test]
async fn preview_rejects_invalid_patterns_and_incompatible_operations() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_simple_rules(root.path())?;
    let server = MockServer::start().await;
    let cases: &[(&[&str], &str)] = &[
        (&[".", "--enable-internal-ips-for", "["], "--enable-internal-ips-for"),
        (&[".", "--rule", "preview.missing"], "preview.missing"),
        (&[".", "--since-hours", "1", "--git-history", "none"], "--since-hours"),
        (&[".", "--endpoint", "bogus"], "--endpoint"),
        (&[".", "--validation-rps-rule", "x"], "--validation-rps-rule"),
        (&["missing/input"], "path does not exist"),
        (&[".", "--self-update"], "--self-update"),
        (
            &["github", "--org", "example-team", "--api-url", &server.uri(), "--list-only"],
            "--list-only",
        ),
    ];
    for (flags, invalid_option) in cases {
        let mut command = scan(root.path());
        command.args(["--no-update-check", "--preview"]).args(*flags);
        let output = run(command).await?;
        assert!(!output.status.success(), "{flags:?}");
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(invalid_option), "{message}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn preview_describes_validators_with_provider_endpoints() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::write(
        root.path().join("rules.yml"),
        concat!(
            "rules:\n",
            "  - id: preview.aws\n    name: Preview AWS fixture\n    pattern: '(fixture_token)'\n",
            "    confidence: high\n    validation:\n      type: AWS\n",
            "  - id: preview.azure-storage\n    name: Preview Azure Storage fixture\n",
            "    pattern: '(azure_fixture_token)'\n    confidence: high\n",
            "    validation:\n      type: AzureStorage\n",
        ),
    )?;
    let mut command = scan(root.path());
    command.args([".", "--preview", "--no-update-check", "--enable-internal-ips-for", "preview.*"]);
    let stdout = assert_success(&run(command).await?);
    assert!(
        stdout.contains("preview.aws | internal-IP access: n/a (fixed provider endpoint)"),
        "{stdout}"
    );
    assert!(
        stdout.contains(
            "preview.azure-storage | internal-IP access: n/a (account-specific provider endpoint)"
        ),
        "{stdout}"
    );
    Ok(())
}
