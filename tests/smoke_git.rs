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
    let sig = Signature::now("tester", "tester@exmple.com")?;

    // commit v1
    let file_path = repo_dir.join("config.yml");
    fs::write(&file_path, b"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")?;
    let mut idx = repo.index()?;
    idx.add_path(std::path::Path::new("config.yml"))?;
    let oid1 = idx.write_tree()?;
    let tree1 = repo.find_tree(oid1)?;
    repo.commit(Some("HEAD"), &sig, &sig, "init", &tree1, &[])?;

    // commit v2 (same leak, will test dedup)
    fs::write(&file_path, b"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 # unchanged")?;
    idx.add_path(std::path::Path::new("config.yml"))?;
    let oid2 = idx.write_tree()?;
    let tree2 = repo.find_tree(oid2)?;
    let head = repo.head()?.peel_to_commit()?;
    repo.commit(Some("HEAD"), &sig, &sig, "update", &tree2, &[&head])?;

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
        ])
        .assert()
        .code(200) // ← kingfisher’s “findings present” status
        .stdout(predicate::str::contains("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"));

    dir.close()?;
    Ok(())
}
