// tests/smoke_check_rules.rs
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

#[test]
fn check_rules() -> anyhow::Result<()> {
    // ── run kingfisher ────────────────────────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "rules",
            "check",
            "--no-update-check", // skip update check to avoid network calls
        ])
        .assert()
        .code(0) // no findings present
        .stdout(
            predicate::str::contains("All rules passed validation successfully")
                .or(predicate::str::contains("Errors: 0")),
        );

    Ok(())
}
