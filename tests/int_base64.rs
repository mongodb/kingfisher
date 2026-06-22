use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{fs, process::Command};
use tempfile::tempdir;

// Ensure base64 encoded secrets are decoded and detected
#[test]
fn detects_base64_encoded_secret() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.txt");
    // Base64 for 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
    let encoded = "Z2hwX0Vab3BaRE1XZWlsZGZvRnp5SDBLbld5UTVZeTN2eTBZMlNVNg==";
    fs::write(&file_path, encoded)?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            predicate::str::contains("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")
                .and(predicate::str::contains("\"encoding\":\"base64\"")),
        );

    dir.close()?;
    Ok(())
}

// Ensure disabling Base64 decoding suppresses encoded secrets
#[test]
fn skips_base64_when_disabled() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.txt");
    let encoded = "Z2hwX0Vab3BaRE1XZWlsZGZvRnp5SDBLbld5UTVZeTN2eTBZMlNVNg==";
    fs::write(&file_path, encoded)?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--no-base64",
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("\"findings\":0"));

    dir.close()?;
    Ok(())
}

// Ensure disabling Base64 decoding does not trigger context verifier errors on empty files
#[test]
fn no_base64_skips_empty_files() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("empty.py");
    fs::write(&file_path, "")?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--no-base64",
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Source code is empty").not());

    dir.close()?;
    Ok(())
}

// Ensure parser-based context extraction still surfaces base64-looking code assignments
#[test]
fn detects_base64_in_code_with_context_verifier() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("secret.py");
    // Base64 for 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
    let encoded = "Z2hwX0Vab3BaRE1XZWlsZGZvRnp5SDBLbld5UTVZeTN2eTBZMlNVNg==";
    fs::write(&file_path, format!("token = \"{}\"\n", encoded))?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(
            predicate::str::contains("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")
                .and(predicate::str::contains("\"encoding\":\"base64\"")),
        );

    dir.close()?;
    Ok(())
}
