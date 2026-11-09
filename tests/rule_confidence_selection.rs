use std::{fs, path::Path, process::Command};

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

fn scan_command(input: &Path, cache: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .arg("scan")
        .arg(input)
        .args(["--no-update-check", "--no-validate", "--no-base64", "--format=toon"])
        .arg("--rule-cache-dir")
        .arg(cache);
    command
}

#[test]
fn explicit_low_rule_reports_the_required_confidence_before_compilation() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let input = temporary.path().join("input.txt");
    let cache = temporary.path().join("cache");
    fs::write(&input, "ordinary text without credentials\n")?;

    for selectors in [
        vec!["betterleaks.generic-api-key"],
        vec!["betterleaks.aws-access-token", "betterleaks.generic-api-key"],
        vec!["all", "betterleaks.generic-api-key"],
    ] {
        let mut command = scan_command(&input, &cache);
        for selector in selectors {
            command.arg("--rule").arg(selector);
        }
        command
            .assert()
            .failure()
            .stderr(predicate::str::contains("generic-api-key"))
            .stderr(predicate::str::contains("below medium confidence"))
            .stderr(predicate::str::contains("--confidence low"))
            .stderr(predicate::str::contains("No rules to compile").not());
        assert!(!cache.exists(), "selection errors must precede native compilation");
    }
    Ok(())
}

#[test]
fn explicitly_excluded_low_rule_does_not_reject_the_remaining_selection() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let input = temporary.path().join("input.txt");
    let cache = temporary.path().join("cache");
    fs::write(&input, "ordinary text without credentials\n")?;

    scan_command(&input, &cache)
        .args([
            "--rule=betterleaks.aws-access-token",
            "--rule=betterleaks.generic-api-key",
            "--exclude-rule=betterleaks.generic-api-key",
        ])
        .assert()
        .success();
    Ok(())
}

#[test]
fn rule_inspection_includes_low_by_default_and_accepts_the_suggested_flag() -> anyhow::Result<()> {
    for subcommand in ["list", "check"] {
        for confidence in [None, Some("low")] {
            let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
            command.args([
                "rules",
                subcommand,
                "--rule=betterleaks.generic-api-key",
                "--no-update-check",
            ]);
            if let Some(confidence) = confidence {
                command.arg("--confidence").arg(confidence);
            }
            command.assert().success();
        }
        Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .args([
                "rules",
                subcommand,
                "--rule=betterleaks.generic-api-key",
                "--confidence=medium",
                "--no-update-check",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--confidence low"));
    }
    Ok(())
}

#[test]
fn explicit_low_rule_can_be_enabled_with_the_suggested_flag() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let input = temporary.path().join("input.txt");
    let cache = temporary.path().join("cache");
    fs::write(&input, "ordinary text without credentials\n")?;

    scan_command(&input, &cache)
        .args(["--rule=betterleaks.generic-api-key", "--confidence=low"])
        .assert()
        .success();
    Ok(())
}
