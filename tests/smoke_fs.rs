// tests/smoke_fs.rs
use std::{fs, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::tempdir;

const GITHUB_PAT: &str = "ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa";

#[test]
fn smoke_scan_filesystem_text_and_binary() -> anyhow::Result<()> {
    // ── temp workspace ────────────────────────────────────────────────
    let dir = tempdir()?;
    let txt_path = dir.path().join("leak.txt");
    let bin_path = dir.path().join("image.png");

    fs::write(&txt_path, format!("token = \"{GITHUB_PAT}\"\n"))?;
    fs::write(&bin_path, [0x89, 0x50, 0x4E, 0x47])?; // tiny PNG header

    // ── run kingfisher ────────────────────────────────────────────────
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary", // PNG should be skipped
            "--confidence=low",
            "--format",
            "json",
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
