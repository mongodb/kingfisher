use std::{fs, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::tempdir;

const GITHUB_PAT: &str = "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";

#[test]
fn smoke_scan_filesystem_text_and_binary() -> anyhow::Result<()> {
    // ── temp workspace ────────────────────────────────────────────────
    let dir = tempdir()?;
    let txt_path = dir.path().join("leak.txt");
    let bin_path = dir.path().join("image.png");

    fs::write(&txt_path, format!("token = \"{GITHUB_PAT}\"\n"))?;
    fs::write(&bin_path, [0x89, 0x50, 0x4E, 0x47])?; // tiny PNG header

    // ── run kingfisher ────────────────────────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary", // PNG should be skipped
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check", // skip update check to avoid network calls
        ])
        .assert()
        .code(200) // findings present
        .stdout(
            predicate::str::contains("leak.txt")
                .and(predicate::str::contains(GITHUB_PAT))
                .and(predicate::str::contains("image.png").not()),
        );

    dir.close()?;
    Ok(())
}

#[cfg(any(windows, unix))]
#[test]
fn scan_file_symlink_respects_input_scope() -> anyhow::Result<()> {
    let source_dir = tempdir()?;
    let target_dir = tempdir()?;
    let link = source_dir.path().join("link.txt");
    let target = target_dir.path().join("target.txt");
    fs::write(&target, format!("token = \"{GITHUB_PAT}\"\n"))?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link)?;
    #[cfg(windows)]
    {
        use anyhow::Context as _;

        std::os::windows::fs::symlink_file(&target, &link).context(
            "Could not create the test file symlink. Enable Windows Developer Mode or grant symlink creation privileges",
        )?;
    }

    let scan = |path: &std::path::Path| {
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(path)
            .args([
                "--rule=github",
                "--no-validate",
                "--redact",
                "--format=toon",
                "--no-update-check",
            ])
            .assert()
    };
    scan(source_dir.path()).success().stdout(predicate::str::contains("findings[0|]"));
    #[cfg(windows)]
    scan(&link).code(200).stdout(predicate::str::contains("link.txt"));
    Ok(())
}
