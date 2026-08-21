use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::tempdir;

fn write_legacy_uri_rules(dir: &Path) -> anyhow::Result<PathBuf> {
    let path = dir.join("uri-rules.yml");
    fs::write(
        &path,
        r#"
rules:
  - name: Custom MongoDB URI
    id: custom.mongodb-uri
    pattern: '(?x) (mongodb(?:\+srv)?://[^\s]+)'
    confidence: low
    validation:
      type: MongoDB
  - name: Custom PostgreSQL URI
    id: custom.postgres-uri
    pattern: '(?x) (postgres(?:ql)?://[^\s]+)'
    confidence: low
    validation:
      type: Postgres
  - name: Custom MySQL URI
    id: custom.mysql-uri
    pattern: '(?x) (mysql://[^\s]+)'
    confidence: low
    validation:
      type: MySQL
"#,
    )?;
    Ok(path)
}

#[test]
fn filters_invalid_mongodb_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("mongo.txt");
    // Avoid placeholder-like passwords filtered by ignore_if_contains (e.g. :pass@).
    let valid = "mongodb://usr:p4ssw0rd123@exmple.com:27017/db";
    let invalid = "mongodb://usr:p4ssw0rd123@exmple.com:abc/db";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;
    let rules_path = write_legacy_uri_rules(dir.path())?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", dir.path().to_str().unwrap()])
        .arg("--rules-path")
        .arg(&rules_path)
        .args([
            "--load-builtins=false",
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}

#[test]
fn filters_invalid_postgres_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("postgres.txt");
    let valid = "postgres://postgres:secret@exmple.com:5432";
    let invalid = "postgres://postgres:secret@exmple.com:70000";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;
    let rules_path = write_legacy_uri_rules(dir.path())?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", dir.path().to_str().unwrap()])
        .arg("--rules-path")
        .arg(&rules_path)
        .args([
            "--load-builtins=false",
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}

#[test]
fn filters_invalid_mysql_uri_even_without_validation() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("mysql.txt");
    let valid = "mysql://user:secret@exmple.com:3306/app";
    let invalid = "mysql://user:secret@exmple.com:70000/app";
    fs::write(&file_path, format!("{valid}\n{invalid}\n"))?;
    let rules_path = write_legacy_uri_rules(dir.path())?;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(["scan", dir.path().to_str().unwrap()])
        .arg("--rules-path")
        .arg(&rules_path)
        .args([
            "--load-builtins=false",
            "--no-binary",
            "--confidence=low",
            "--format",
            "json",
            "--no-validate",
            "--no-update-check",
        ])
        .assert()
        .code(200)
        .stdout(predicate::str::contains(valid))
        .stdout(predicate::str::contains(invalid).not());

    dir.close()?;
    Ok(())
}
