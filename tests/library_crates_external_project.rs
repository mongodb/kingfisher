use std::fs;
use std::path::Path;
use std::process::Command;

fn toml_escape_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
}

#[test]
fn library_crates_work_from_external_project() -> anyhow::Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let core_path = toml_escape_path(&repo_root.join("crates/kingfisher-core"));
    let rules_path = toml_escape_path(&repo_root.join("crates/kingfisher-rules"));
    let scanner_path = toml_escape_path(&repo_root.join("crates/kingfisher-scanner"));
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

kingfisher-scanner = {{ path = "{scanner_path}" }}

"#
        ),
    )?;

    fs::write(
        project_dir.join("src/main.rs"),
        r#"use std::sync::Arc;
use kingfisher_core::Blob;
use kingfisher_rules::{get_builtin_rules, RulesDatabase};
use kingfisher_scanner::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rules = get_builtin_rules(None)?;
    println!("rules={}", rules.num_rules());

    let rules_db = Arc::new(RulesDatabase::from_rule_collection(rules)?);

    {
        let scanner = Scanner::new(rules_db);
        let blob =
            Blob::from_bytes(b"token = \"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\"".to_vec());
        let findings = scanner.scan_blob(&blob)?;
        assert!(findings.iter().any(|finding| {
            finding.rule_id == "betterleaks.github-pat"
                && finding.secret == "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"
        }), "expected the GitHub PAT rule to report the exact token");
        println!("findings={}", findings.len());
    }

    Ok(())
}
"#,
    )?;

    let lock_output = Command::new("cargo")
        // Add the consumer without upgrading the native dependencies whose
        // verified archives are reused below.
        .args(["update", "--workspace"])
        .arg("--offline")
        .current_dir(&project_dir)
        .output()?;
    let lock_stdout = String::from_utf8_lossy(&lock_output.stdout);
    let lock_stderr = String::from_utf8_lossy(&lock_output.stderr);
    assert!(
        lock_output.status.success(),
        "external project lockfile generation failed\nstdout:\n{lock_stdout}\nstderr:\n{lock_stderr}"
    );

    // Keep dependency artifacts across test runs and inside the CI Rust cache.
    // Use a separate target directory because this consumer has its own feature graph.
    let target_root = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| repo_root.join("target"));
    let target_dir = repo_root.join(target_root).join("external-consumer");

    let mut run = Command::new("cargo");
    // MSYS2 CI invokes the parent tests with --target; Cargo does not inherit
    // that flag in subprocesses. Avoid falling back to the unsupported MSVC host.
    #[cfg(all(windows, target_arch = "x86_64"))]
    run.args(["run", "--target", "x86_64-pc-windows-gnu"]);
    #[cfg(all(windows, target_arch = "aarch64"))]
    run.args(["run", "--target", "aarch64-pc-windows-gnullvm"]);
    #[cfg(not(windows))]
    run.arg("run");

    // Reuse the native archives already verified by the parent build. The
    // consumer has a separate target directory, but should not need a second
    // GitHub release download just to exercise the library API.
    if std::env::var_os("VECTORSCAN_PREBUILT_DIR").is_none() {
        let archive_dir = temp.path().join("vectorscan-prebuilt");
        let profile_dir = std::env::current_exe()?
            .parent()
            .and_then(Path::parent)
            .expect("test executable is in the profile deps directory")
            .to_path_buf();
        if let Ok(builds) = fs::read_dir(profile_dir.join("build")) {
            for build in builds {
                let build = build?;
                if !build.file_name().to_string_lossy().starts_with("kingfisher-vectorscan-sys-") {
                    continue;
                }
                let Ok(outputs) = fs::read_dir(build.path().join("out")) else { continue };
                for output in outputs {
                    let output = output?;
                    let name = output.file_name();
                    let text = name.to_string_lossy();
                    if text.starts_with("vectorscan-") && text.ends_with(".tar.gz") {
                        fs::create_dir_all(&archive_dir)?;
                        fs::copy(output.path(), archive_dir.join(name))?;
                    }
                }
            }
        }
        if archive_dir.is_dir() {
            run.env("VECTORSCAN_PREBUILT_DIR", archive_dir);
        }
    }

    let output = run
        .arg("--quiet")
        // The external dependency graph can include packages that the workspace build did not
        // download. Keep its generated lockfile fixed without requiring a warm Cargo cache.
        .arg("--locked")
        .env("CARGO_TARGET_DIR", &target_dir)
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

    let findings_count = stdout
        .lines()
        .find_map(|line| line.strip_prefix("findings="))
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(
        findings_count > 0,
        "expected embedded Betterleaks rules to find the token\nstdout:\n{stdout}"
    );

    Ok(())
}
