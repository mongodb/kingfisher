use std::{
    io::{Cursor, Write},
    path::Path,
    process::Command,
};

use anyhow::Result;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

// kingfisher:ignore (synthetic test fixture, not a real token)
const SECRET: &str = "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";

fn scan(path: &Path) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.arg("scan").arg(path).args([
        "--no-update-check",
        "--no-validate",
        "--confidence=low",
        "--format=toon",
    ]);
    cmd
}

fn zip(name: &str, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        name,
        SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
    )?;
    zip.write_all(bytes)?;
    Ok(zip.finish()?.into_inner())
}

#[test]
fn unlimited_file_size_overrides_explicit_limit_and_config() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, format!("{}\ntoken={SECRET}\n", "padding ".repeat(100)))?;
    scan(&path)
        .arg("--max-file-size=0.0001")
        .assert()
        .success()
        .stdout(predicate::str::contains(SECRET).not());
    scan(&path)
        .args(["--max-file-size=0.0001", "--no-timeouts"])
        .assert()
        .success()
        .stdout(predicate::str::contains(SECRET).not());
    scan(&path)
        .args(["--max-file-size=0.0001", "--no-limits"])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET));
    scan(&path)
        .arg("--max-file-size=0")
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET));
    let config = dir.path().join("kingfisher.yaml");
    std::fs::write(&config, "scan:\n  no_limits: true\nfilters:\n  max_file_size_mb: 0.0001\n")?;
    scan(&path)
        .arg("--config")
        .arg(&config)
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_timeout_opt_out_preserves_late_validation_and_independent_body_limits()
-> Result<()> {
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    let server = MockServer::start().await;
    let body = "authenticated response with a complete-evidence-marker";
    Mock::given(method("GET"))
        .and(path("/identity"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(body).set_delay(Duration::from_millis(1500)),
        )
        .expect(6)
        .mount(&server)
        .await;
    for mode in ["bounded", "content", "timeouts", "both", "config", "zero"] {
        let dir = tempfile::tempdir()?;
        let input = dir.path().join("secret.env");
        let rules = dir.path().join("rules.yml");
        let config = dir.path().join("kingfisher.yml");
        let report = dir.path().join("report.json");
        std::fs::write(&input, "fixture-secret")?;
        std::fs::write(
            &config,
            "scan:\n  no_limits: true\n  no_timeouts: true\nvalidation:\n  timeout: 1\n",
        )?;
        std::fs::write(
            &rules,
            format!(
                r#"rules:
  - name: Late validation fixture
    id: custom.late.response
    pattern: '(fixture-secret)'
    min_entropy: 0
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{}/identity'
          response_matcher:
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: [authenticated]
"#,
                server.uri()
            ),
        )?;
        let report_output = report.clone();
        tokio::task::spawn_blocking(move || {
            let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
            command
                .timeout(Duration::from_secs(20))
                .arg("scan")
                .arg(input)
                .args(["--load-builtins=false", "--rules-path"])
                .arg(rules)
                .arg("--output")
                .arg(report_output)
                .args([
                    "--validation-retries=0",
                    "--max-validation-response-length=16",
                    "--allow-internal-ips",
                    "--no-update-check",
                    "--format=json",
                    "--jobs=2",
                ]);
            if mode != "config" {
                command.arg(if mode == "zero" {
                    "--validation-timeout=0"
                } else {
                    "--validation-timeout=1"
                });
            }
            match mode {
                "content" => {
                    command.arg("--no-limits");
                }
                "timeouts" => {
                    command.arg("--no-timeouts");
                }
                "both" => {
                    command.args(["--no-limits", "--no-timeouts"]);
                }
                "config" => {
                    command.arg("--config").arg(config);
                }
                "zero" => {
                    command.arg("--no-limits");
                }
                _ => {}
            }
            command.assert().code(if matches!(mode, "bounded" | "content") { 200 } else { 205 });
        })
        .await?;
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(report)?)?;
        let validation = &report["findings"][0]["finding"]["validation"];
        let timed_out = matches!(mode, "bounded" | "content");
        assert_eq!(
            validation["outcome"],
            if timed_out { "unavailable" } else { "verified_active" },
            "{mode}"
        );
        if !timed_out {
            let response = validation["response"].as_str().expect("validation evidence");
            assert_eq!(response.contains("complete-evidence-marker"), mode != "timeouts", "{mode}");
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn git_clone_and_update_deadlines_require_explicit_opt_out() -> Result<()> {
    use kingfisher::{findings_store::FindingsStore, git_url::GitUrl};
    use std::time::Duration;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    for update in [false, true] {
        for no_timeouts in [false, true] {
            let temp = tempfile::tempdir()?;
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/stalled.git/info/refs"))
                .respond_with(ResponseTemplate::new(404).set_delay(Duration::from_millis(1500)))
                .expect(if update { 2 } else { 1 })
                .mount(&server)
                .await;
            let url = format!("{}/stalled.git", server.uri());
            let clone_root = temp.path().join("clones");
            if update {
                let git_url =
                    GitUrl::try_from(url::Url::parse(&url)?).map_err(anyhow::Error::msg)?;
                let destination =
                    FindingsStore::new(clone_root.clone()).clone_destination(&git_url);
                let repo = git2::Repository::init_bare(destination)?;
                repo.remote("origin", &url)?;
                drop(repo);
            }
            let rules = temp.path().join("rules.yml");
            std::fs::write(
                &rules,
                "rules:\n  - name: Git deadline fixture\n    id: custom.git.deadline\n    pattern: '(fixture-secret)'\n    min_entropy: 0\n",
            )?;
            let output = tokio::task::spawn_blocking(move || {
                let mut command =
                    assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
                command
                    .timeout(Duration::from_secs(20))
                    .args([
                        "scan",
                        &url,
                        "--no-limits",
                        "--no-validate",
                        "--no-update-check",
                        "--load-builtins=false",
                        "--rules-path",
                    ])
                    .arg(rules)
                    .arg("--git-clone-dir")
                    .arg(clone_root)
                    .args(["--format=toon", "--jobs=2"])
                    .env("KF_GIT_CLONE_TIMEOUT_SECS", "1")
                    .env("KF_GIT_UPDATE_TIMEOUT_SECS", "1");
                if no_timeouts {
                    command.arg("--no-timeouts");
                }
                command.assert().get_output().clone()
            })
            .await?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                stdout.contains("git execution timed out after 1 seconds"),
                !no_timeouts,
                "{stdout}\n{stderr}"
            );
            assert_eq!(stderr.contains("exceeded 1s timeout"), !no_timeouts, "{stderr}");
            if update {
                assert!(stderr.contains("Updating clone of"), "{stderr}");
            }
            if no_timeouts {
                assert!(stderr.contains("not found") || stderr.contains("404"), "{stderr}");
            }
        }
    }
    Ok(())
}

#[test]
fn unlimited_archive_depth_reaches_deep_content_and_preserves_extraction_opt_out() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("outer.zip");
    let mut bytes = zip("secret.txt", format!("token={SECRET}").as_bytes())?;
    for _ in 0..5 {
        bytes = zip("inner.zip", &bytes)?;
    }
    std::fs::write(&path, bytes)?;
    scan(&path)
        .arg("--extraction-depth=1")
        .assert()
        .success()
        .stdout(predicate::str::contains(SECRET).not());
    scan(&path)
        .args(["--extraction-depth=1", "--no-limits"])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET));
    scan(&path)
        .arg("--extraction-depth=0")
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET));
    scan(&path)
        .args(["--no-limits", "--no-extract-archives"])
        .assert()
        .success()
        .stdout(predicate::str::contains(SECRET).not());
    Ok(())
}

#[test]
fn unlimited_git_history_extracts_nested_archive_with_explicitly_disabled_deadline() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("outer.zip");
    let mut bytes = zip("secret.txt", format!("token={SECRET}").as_bytes())?;
    for _ in 0..4 {
        bytes = zip("inner.zip", &bytes)?;
    }
    std::fs::write(&path, bytes)?;
    Command::new("git").arg("init").arg("--quiet").arg(dir.path()).assert().success();
    Command::new("git").arg("-C").arg(dir.path()).args(["add", "."]).assert().success();
    Command::new("git")
        .arg("-C")
        .arg(dir.path())
        .args([
            "-c",
            "user.name=Kingfisher Test",
            "-c",
            "user.email=kingfisher@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])
        .assert()
        .success();
    std::fs::remove_file(&path)?;
    scan(dir.path())
        .args(["--no-limits", "--git-repo-timeout=0"])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(SECRET))
        .stdout(predicate::str::contains("!inner.zip"));
    Ok(())
}

#[test]
fn max_file_size_applies_to_git_history_blobs() -> Result<()> {
    // kingfisher:ignore (synthetic test fixture, not a real token)
    const SMALL_SECRET: &str = "ghp_FZopZDMWeildfoFzyH0KnWyQ5Yy3vy0Y2SU6";
    let dir = tempfile::tempdir()?;
    let repo_path = dir.path().join("repo.git");
    {
        let repo = git2::Repository::init_bare(&repo_path)?;
        let mut small = format!("token={SMALL_SECRET}\n").into_bytes();
        small.resize(64, b' ');
        let small = repo.blob(&small)?;
        let large =
            repo.blob(format!("{}\ntoken={SECRET}\n", "padding ".repeat(100)).as_bytes())?;
        let mut tree = repo.treebuilder(None)?;
        tree.insert("small.txt", small, 0o100644)?;
        tree.insert("large.txt", large, 0o100644)?;
        let tree = repo.find_tree(tree.write()?)?;
        let signature = git2::Signature::now("Kingfisher Test", "kingfisher@example.invalid")?;
        repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])?;
    }
    let config = dir.path().join("kingfisher.yml");
    std::fs::write(&config, "scan:\n  no_limits: true\nfilters:\n  max_file_size_mb: 0.0001\n")?;

    // Exercise both loose objects and packed objects (which may use delta compression).
    for packed in [false, true] {
        if packed {
            Command::new("git")
                .arg("-C")
                .arg(&repo_path)
                .args(["repack", "-ad"])
                .assert()
                .success();
        }
        for metadata in ["--commit-metadata=true", "--commit-metadata=false"] {
            // This is exactly 64 bytes in MiB; the boundary itself must be included.
            let limit = "--max-file-size=0.00006103515625";
            // Cover the independent timeout override once, not across the whole matrix.
            let timeout_modes = if !packed && metadata == "--commit-metadata=true" {
                vec![None, Some("--no-timeouts")]
            } else {
                vec![None]
            };
            for extra in timeout_modes {
                let mut command = scan(&repo_path);
                command.args(["--git-history=full", metadata, limit]);
                if let Some(extra) = extra {
                    command.arg(extra);
                }
                command
                    .assert()
                    .code(200)
                    .stdout(predicate::str::contains(SMALL_SECRET))
                    .stdout(predicate::str::contains(SECRET).not());
            }
            if metadata == "--commit-metadata=true" {
                scan(&repo_path)
                    .args(["--git-history=full", metadata, "--max-file-size=0.00006"])
                    .assert()
                    .success()
                    .stdout(predicate::str::contains(SMALL_SECRET).not())
                    .stdout(predicate::str::contains(SECRET).not());
            }
            // These are option-resolution checks, not storage/metadata variants.
            if !packed && metadata == "--commit-metadata=true" {
                for unlimited in ["--no-limits", "--max-file-size=0", "--config"] {
                    let mut command = scan(&repo_path);
                    command.args(["--git-history=full", metadata]);
                    if unlimited != "--max-file-size=0" {
                        command.arg(limit);
                    }
                    command.arg(unlimited);
                    if unlimited == "--config" {
                        command.arg(&config);
                    }
                    command
                        .assert()
                        .code(200)
                        .stdout(predicate::str::contains(SMALL_SECRET))
                        .stdout(predicate::str::contains(SECRET));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn unlimited_base64_depth_preserves_explicit_opt_out() -> Result<()> {
    use base64::Engine;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("encoded.txt");
    let mut bytes = format!("token={SECRET}").into_bytes();
    for _ in 0..5 {
        bytes = base64::engine::general_purpose::STANDARD.encode(bytes).into_bytes();
    }
    std::fs::write(&path, bytes)?;
    scan(&path).assert().success().stdout(predicate::str::contains(SECRET).not());
    scan(&path).arg("--no-limits").assert().code(200).stdout(predicate::str::contains(SECRET));
    scan(&path)
        .args(["--no-limits", "--no-base64"])
        .assert()
        .success()
        .stdout(predicate::str::contains(SECRET).not());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlimited_policy_reaches_artifact_fetcher_thread() -> Result<()> {
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/rest/api/content/search"))
        .respond_with(|request: &wiremock::Request| {
            let limit: usize = request
                .url
                .query_pairs()
                .find(|(key, _)| key == "limit")
                .unwrap()
                .1
                .parse()
                .unwrap();
            let pages: Vec<_> = (0..limit.min(2)).map(|index| json!({
                "id": index.to_string(), "title": "fixture",
                "body": {"storage": {"value": if index == 0 { "no secret" } else { SECRET }}},
                "_links": {"webui": format!("/pages/{index}")}
            })).collect();
            ResponseTemplate::new(200).set_body_json(json!({"results": pages, "_links": {}}))
        })
        .expect(2)
        .mount(&server)
        .await;
    for unlimited in [false, true] {
        let dir = tempfile::tempdir()?;
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        cmd.args([
            "scan",
            "confluence",
            "--url",
            &server.uri(),
            "--cql",
            "label = secret",
            "--max-results=1",
            "--no-update-check",
            "--no-validate",
            "--format=toon",
            "--confidence=low",
        ])
        .current_dir(dir.path())
        .env("KF_CONFLUENCE_TOKEN", "test-token")
        .env_remove("KF_CONFLUENCE_USER");
        tokio::task::spawn_blocking(move || {
            let _dir = dir;
            if unlimited {
                cmd.arg("--no-limits");
                cmd.assert().code(200).stdout(predicate::str::contains(SECRET));
            } else {
                cmd.assert().success().stdout(predicate::str::contains(SECRET).not());
            }
        })
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlimited_scan_preserves_configured_validation_deadline() -> Result<()> {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    for mode in ["bounded", "flag", "config"] {
        let dir = tempfile::tempdir()?;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        // Accept the connection, then remain silent until the client closes it.
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut byte = [0];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), socket.read(&mut byte))
                    .await
                    .expect("the configured validation deadline must close the connection")
                    .unwrap(),
                0
            );
        });
        let input = dir.path().join("smtp.env");
        let rules = dir.path().join("rules.yml");
        let report = dir.path().join("report.json");
        let report_output = report.clone();
        let config = dir.path().join("kingfisher.yml");
        std::fs::write(&config, "scan:\n  no_limits: true\nvalidation:\n  timeout: 1\n")?;
        std::fs::write(&input, format!("smtp://user:fixture-password@{address}\n"))?;
        std::fs::write(
            &rules,
            "rules:\n  - name: Silent SMTP fixture\n    id: custom.timeout.smtp\n    pattern: '(smtp://[^\\s]+)'\n    min_entropy: 0\n    validation:\n      type: CredentialUri\n",
        )?;
        tokio::task::spawn_blocking(move || {
            let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
            command
                .timeout(Duration::from_secs(20))
                .arg("scan")
                .arg(input)
                .args(["--load-builtins=false", "--rules-path"])
                .arg(rules)
                .arg("--output")
                .arg(report_output)
                .args([
                    "--validation-retries=0",
                    "--allow-internal-ips",
                    "--no-update-check",
                    "--format=json",
                    "--jobs=2",
                ]);
            if mode == "config" {
                command.arg("--config").arg(config);
            } else {
                command.arg("--validation-timeout=1");
                if mode == "flag" {
                    command.arg("--no-limits");
                }
            }
            command.assert().code(200);
        })
        .await?;
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(report)?)?;
        let validation = &report["findings"][0]["finding"]["validation"];
        assert_eq!(validation["outcome"], "unavailable");
        tokio::time::timeout(Duration::from_secs(5), server).await??;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlimited_scan_preserves_git_clone_timeout() -> Result<()> {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    let temp = tempfile::tempdir()?;
    let rules = temp.path().join("rules.yml");
    std::fs::write(
        &rules,
        "rules:\n  - name: Clone timeout fixture\n    id: custom.clone.timeout\n    pattern: '(fixture-secret)'\n    min_entropy: 0\n",
    )?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}/stalled.git", listener.local_addr()?);
    let server = tokio::spawn(async move {
        let (mut socket, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("Git must connect to the stalled server")
            .unwrap();
        let mut request = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_secs(10), socket.read_to_end(&mut request))
                .await
                .expect("the Git clone timeout must close the stalled connection");
        // Killing Git may close the socket gracefully or reset it, particularly
        // on Windows. Both prove that the stalled connection was terminated.
        if let Err(error) = closed {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset, "{error}");
        }
        // Under load, Git can connect but be killed before writing any request
        // bytes. Socket termination, not a nonempty request, proves cleanup.
    });
    tokio::task::spawn_blocking(move || {
        assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .timeout(Duration::from_secs(20))
            .args([
                "scan",
                &url,
                "--no-limits",
                "--no-validate",
                "--no-update-check",
                "--load-builtins=false",
                "--rules-path",
            ])
            .arg(rules)
            .args(["--format=toon", "--jobs=2"])
            .env("KF_GIT_CLONE_TIMEOUT_SECS", "3")
            .assert()
            .stdout(predicate::str::contains("git execution timed out after 3 seconds"))
            .stderr(predicate::str::contains("exceeded 3s timeout"));
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(5), server).await??;
    Ok(())
}
