use std::{fs, path::Path, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

fn compile_cache_command(rules_path: &Path, cache_dir: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .args([
            "rules",
            "compile-cache",
            "--no-update-check",
            "--load-builtins=false",
            "--rules-path",
        ])
        .arg(rules_path)
        .arg("--rule-cache-dir")
        .arg(cache_dir);
    command
}

fn write_test_rules(path: &Path) -> anyhow::Result<()> {
    fs::write(
        path,
        "rules:\n  - id: test.secret\n    name: Test secret\n    pattern: 'demo_[0-9]{4}'\n    confidence: high\n",
    )?;
    Ok(())
}

#[test]
fn compile_cache_reports_ready_only_after_persistence() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let rules_path = temporary.path().join("rules.yml");
    let cache_dir = temporary.path().join("cache");
    write_test_rules(&rules_path)?;

    compile_cache_command(&rules_path, &cache_dir)
        .assert()
        .success()
        .stdout(predicate::str::contains("Rule cache ready: 1 rules"));
    let entry = fs::read_dir(&cache_dir)?.next().expect("persisted cache entry")?.path();
    assert_eq!(entry.extension().and_then(|extension| extension.to_str()), Some("vscdb"));

    // Existing valid entries can satisfy image prewarming without rewriting them.
    compile_cache_command(&rules_path, &cache_dir).assert().success();
    Ok(())
}

#[test]
fn compile_cache_fails_when_the_configured_location_is_unavailable() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let rules_path = temporary.path().join("rules.yml");
    let cache_dir = temporary.path().join("not-a-directory");
    write_test_rules(&rules_path)?;
    fs::write(&cache_dir, b"an ordinary file prevents cache creation")?;

    compile_cache_command(&rules_path, &cache_dir)
        .assert()
        .failure()
        .stdout(predicate::str::contains("Rule cache ready").not())
        .stderr(predicate::str::contains("cache could not be persisted"));
    assert_eq!(fs::read(&cache_dir)?, b"an ordinary file prevents cache creation");
    Ok(())
}
