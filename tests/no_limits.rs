use std::{
    io::{Cursor, Write},
    path::Path,
    process::Command,
};

use anyhow::Result;
use assert_cmd::prelude::*;
use predicates::prelude::*;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

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
fn unlimited_git_history_extracts_nested_archive_with_no_deadline() -> Result<()> {
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
