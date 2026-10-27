use std::{fs::File, io::Write, path::Path, process::Command, time::Duration};

use assert_cmd::prelude::*;
use flate2::{Compression, write::GzEncoder};
use predicates::prelude::*;
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

fn append_bytes(tar: &mut tar::Builder<impl Write>, path: &str, data: &[u8]) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, data)?;
    Ok(())
}

fn build_docker_archive(path: &Path, github_pat: &str) -> anyhow::Result<()> {
    let mut layer = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = tar::Builder::new(&mut layer);
        append_bytes(&mut tar, "app/secret.txt", format!("token={github_pat}\n").as_bytes())?;
        tar.finish()?;
    }
    let layer = layer.finish()?;

    let mut tar = tar::Builder::new(File::create(path)?);
    append_bytes(&mut tar, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    append_bytes(
        &mut tar,
        "manifest.json",
        br#"[{"Config":"blobs/sha256/config","Layers":["blobs/sha256/layer"]}]"#,
    )?;
    append_bytes(&mut tar, "blobs/sha256/config", br#"{}"#)?;
    append_bytes(&mut tar, "blobs/sha256/layer", &layer)?;
    tar.finish()?;
    Ok(())
}

#[tokio::test]
async fn smoke_scan_docker_image() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join("image.tar");
    // kingfisher:ignore (synthetic Docker fixture, not a real token)
    let secret = "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";
    build_docker_archive(&archive, secret)?;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/version$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ApiVersion":"1.40"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/images/local-smoke.invalid/fixture:latest/json$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"Id":"sha256:fixture"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/images/local-smoke.invalid/fixture:latest/get$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(std::fs::read(&archive)?))
        .expect(1)
        .mount(&server)
        .await;
    let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .timeout(Duration::from_secs(30))
        .args([
            "scan",
            "--docker-image",
            "local-smoke.invalid/fixture:latest",
            "--format",
            "json",
            "--rule",
            "betterleaks.github-pat",
            "--no-validate",
            "--no-update-check",
        ])
        .env("DOCKER_HOST", server.uri())
        .env("DOCKER_CONFIG", dir.path().join("docker config"))
        .env("PATH", dir.path().join("empty bin"));
    for name in [
        "DOCKER_CONTEXT",
        "DOCKER_API_VERSION",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "KF_DOCKER_TOKEN",
    ] {
        command.env_remove(name);
    }
    // Keep the mock API responsive while the real CLI subprocess runs.
    let output = tokio::task::spawn_blocking(move || command.output()).await??;
    assert_eq!(output.status.code(), Some(200), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains(secret));
    let summary = serde_json::Deserializer::from_slice(&output.stdout)
        .into_iter::<Value>()
        .filter_map(Result::ok)
        .find_map(|value| value.pointer("/metadata/summary").cloned())
        .expect("scan output must contain a JSON summary");
    assert!(summary["blobs_scanned"].as_u64().unwrap_or_default() > 0);
    server.verify().await;
    Ok(())
}

// Keep the real registry probe available explicitly. It downloads/scans a large,
// mutable third-party image and is unsuitable for deterministic PR regression CI.
#[test]
#[ignore = "manual live registry smoke test; downloads/scans a large third-party image"]
fn smoke_scan_live_wrongsecrets_image() -> anyhow::Result<()> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    let output = cmd
        .args([
            "scan",
            "--docker-image",
            "ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .output()?;

    // Finding secrets is a completed scan with exit code 200, so still verify
    // coverage instead of silently skipping the report assertions.
    if !output.status.success() && output.status.code() != Some(200) {
        eprintln!("Skipping test: {}", String::from_utf8_lossy(&output.stderr));
        return Ok(());
    }

    let summary = output
        .stdout
        .split(|&byte| byte == b'\n')
        .filter(|line| !line.is_empty())
        .find_map(|line| {
            let value: Value = serde_json::from_slice(line).ok()?;
            value.pointer("/metadata/summary").cloned()
        })
        .expect("scan output must contain a JSON summary");
    assert!(summary["blobs_scanned"].as_u64().unwrap_or_default() > 0);
    Ok(())
}

#[test]
fn smoke_scan_docker_archive() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join("image.tar");
    // kingfisher:ignore (synthetic Docker fixture, not a real token)
    let github_pat = "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";
    build_docker_archive(&archive, github_pat)?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            "docker",
            "--archive",
            archive.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--rule",
            "betterleaks.github-pat",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            predicate::str::contains(github_pat).and(
                predicate::str::contains("app/secret.txt")
                    .or(predicate::str::contains("app\\\\secret.txt")),
            ),
        );

    Ok(())
}

#[test]
fn docker_archive_without_findings_emits_complete_coverage() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join("image.tar");
    let report = dir.path().join("report.json");
    build_docker_archive(&archive, "not-a-credential")?;
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            "docker",
            "--archive",
            archive.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            report.to_str().unwrap(),
            "--rule",
            "betterleaks.github-pat",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .success();
    let report: Value = serde_json::from_reader(File::open(report)?)?;
    assert!(report["audit"]["completed_at"].is_string());
    assert_eq!(report["audit"]["summary"]["discovered"], 1);
    assert_eq!(report["audit"]["summary"]["scan_succeeded"], 1);
    for field in ["fetch_failed", "scan_failed", "scan_partial", "pending"] {
        assert_eq!(report["audit"]["summary"][field], 0, "{field}");
    }
    assert!(report["audit"]["repositories"][0].get("git").is_none());
    Ok(())
}
