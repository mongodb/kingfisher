use std::{fs::File, io::Write, path::Path, process::Command};

use assert_cmd::prelude::*;
use flate2::{Compression, write::GzEncoder};
use predicates::prelude::*;

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

#[test]
fn smoke_scan_docker_image() -> anyhow::Result<()> {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    let output = cmd
        .args([
            "scan",
            "--docker-image",
            "ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master",
            "--format",
            "json",
            "--no-update-check",
        ])
        .output()?;

    if !output.status.success() {
        eprintln!("Skipping test: {}", String::from_utf8_lossy(&output.stderr));
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Not Attempted"));
    Ok(())
}

#[test]
fn smoke_scan_docker_archive() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join("image.tar");
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
            "kingfisher.github.2",
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
