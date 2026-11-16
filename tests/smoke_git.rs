#[path = "../src/git_test_fixture.rs"]
mod fixture;

use std::{fs, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn smoke_scan_git_history() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = gix::init(&repo_dir)?;
    let sig = fixture::signature("tester", "tester@exmple.com");

    // commit v1
    let file_path = repo_dir.join("config.yml");
    fs::write(&file_path, b"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")?;
    let mut idx = fixture::index(&repo)?;
    fixture::stage(&repo, &mut idx, std::path::Path::new("config.yml"))?;
    let oid1 = fixture::write_tree(&repo, &idx)?;
    let tree1 = oid1;
    fixture::commit(&repo, Some("HEAD"), &sig, &sig, "init", &tree1, &[])?;

    // commit v2 (same leak, will test dedup)
    fs::write(&file_path, b"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 # unchanged")?;
    fixture::stage(&repo, &mut idx, std::path::Path::new("config.yml"))?;
    let oid2 = fixture::write_tree(&repo, &idx)?;
    let tree2 = oid2;
    let head = repo.head_id()?.detach();
    fixture::commit(&repo, Some("HEAD"), &sig, &sig, "update", &tree2, &[&head])?;

    // ── run kingfisher with git-history mode FULL ─────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--git-history",
            "full",
            "--confidence=low", // pick up even low-confidence rules
            "--format",
            "json",
            "--no-update-check", // skip update check to avoid network calls
            "--no-validate",
        ])
        .env("KF_GIT_BINARY", dir.path().join("missing git.exe"))
        .env("PATH", dir.path().join("missing executables"))
        .assert()
        .code(200) // ← kingfisher’s “findings present” status
        .stdout(predicate::str::contains("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"));

    dir.close()?;
    Ok(())
}
