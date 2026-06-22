use std::fs;
use std::path::Path;
use std::process::Command;

fn toml_escape_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\")
}

#[cfg(not(windows))]
#[test]
fn library_crates_work_from_external_project() -> anyhow::Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_path = toml_escape_path(&repo_root.join("crates/kingfisher-core"));
    let rules_path = toml_escape_path(&repo_root.join("crates/kingfisher-rules"));
    let scanner_path = toml_escape_path(&repo_root.join("crates/kingfisher-scanner"));
    let vectorscan_rs_path =
        toml_escape_path(&repo_root.join("vendor/vectorscan-rs/vectorscan-rs"));
    let vectorscan_rs_sys_path =
        toml_escape_path(&repo_root.join("vendor/vectorscan-rs/vectorscan-rs-sys"));

    let temp = tempfile::tempdir()?;
    let project_dir = temp.path().join("external-kingfisher-consumer");
    fs::create_dir_all(project_dir.join("src"))?;
    fs::copy(repo_root.join("Cargo.lock"), project_dir.join("Cargo.lock"))?;

    fs::write(
        project_dir.join("Cargo.toml"),
        format!(
            r#"[package]
name = "external-kingfisher-consumer"
version = "0.1.0"
edition = "2021"

[dependencies]
kingfisher-core = {{ path = "{core_path}" }}
kingfisher-rules = {{ path = "{rules_path}" }}

[target.'cfg(not(windows))'.dependencies]
kingfisher-scanner = {{ path = "{scanner_path}" }}

[patch.crates-io]
vectorscan-rs = {{ path = "{vectorscan_rs_path}" }}
vectorscan-rs-sys = {{ path = "{vectorscan_rs_sys_path}" }}
"#
        ),
    )?;

    fs::write(
        project_dir.join("src/main.rs"),
        r#"use std::sync::Arc;
use kingfisher_core::Blob;
use kingfisher_rules::{get_builtin_rules, Rule, RulesDatabase};
#[cfg(not(windows))]
use kingfisher_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rules = get_builtin_rules(None)?;
    println!("rules={}", rules.num_rules());

    let rule_vec: Vec<Rule> = rules
        .iter_rules()
        .map(|syntax| Rule::new(syntax.clone()))
        .collect();
    let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);

    #[cfg(not(windows))]
    {
        let scanner = Scanner::new(rules_db);
        let blob =
            Blob::from_bytes(b"token = \"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\"".to_vec());
        let findings = scanner.scan_blob(&blob)?;
        println!("findings={}", findings.len());
    }

    #[cfg(windows)]
    {
        let _ = Blob::from_bytes(Vec::new());
        let _ = rules_db;
    }

    Ok(())
}
"#,
    )?;

    let lock_output = Command::new("cargo")
        .arg("generate-lockfile")
        .arg("--offline")
        .current_dir(&project_dir)
        .output()?;
    let lock_stdout = String::from_utf8_lossy(&lock_output.stdout);
    let lock_stderr = String::from_utf8_lossy(&lock_output.stderr);
    assert!(
        lock_output.status.success(),
        "external project lockfile generation failed\nstdout:\n{lock_stdout}\nstderr:\n{lock_stderr}"
    );

    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--frozen")
        .current_dir(&project_dir)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "external project failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let rules_count = stdout
        .lines()
        .find_map(|line| line.strip_prefix("rules="))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(rules_count > 0, "expected builtin rules to load\nstdout:\n{stdout}");

    Ok(())
}
