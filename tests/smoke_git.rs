// tests/smoke_git.rs
use std::{fs, process::Command};

use assert_cmd::prelude::*;
use git2::{Repository, Signature};
use predicates::prelude::*;
use tempfile::tempdir;

#[test]
fn smoke_scan_git_history() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let repo_dir = dir.path().join("repo");
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@example.com")?;

    // commit v1
    let file_path = repo_dir.join("config.yml");
    fs::write(&file_path, b"ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa")?;
    let mut idx = repo.index()?;
    idx.add_path(std::path::Path::new("config.yml"))?;
    let oid1 = idx.write_tree()?;
    let tree1 = repo.find_tree(oid1)?;
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree1, &[])?;

    // commit v2 (same leak, will test dedup)
    fs::write(&file_path, b"ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa # unchanged")?;
    idx.add_path(std::path::Path::new("config.yml"))?;
    let oid2 = idx.write_tree()?;
    let tree2 = repo.find_tree(oid2)?;
    let head = repo.head()?.peel_to_commit()?;
    repo.commit(Some("HEAD"), &sig, &sig, "update", &tree2, &[&head])?;

    // ── run kingfisher with git-history mode FULL ─────────────────────
    Command::cargo_bin("kingfisher")?
        .args([
            "scan",
            repo_dir.to_str().unwrap(),
            "--git-history",
            "full",
            "--confidence=low", // pick up even low-confidence rules
            "--format",
            "json",
            // add "--no-validate" if the CLI supports it to avoid network I/O
        ])
        .assert()
        .code(200) // ← kingfisher’s “findings present” status
        .stdout(predicate::str::contains("ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa"));

    dir.close()?;
    Ok(())
}
