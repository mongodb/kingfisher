use std::{fs, path::Path};

use anyhow::Result;
use git2::{Repository, Signature};

const KEPT: &str = "acme_A1b2C3d4E5f6G7h8";
const SKIPPED: &str = "acme_J1k2L3m4N5o6P7q8";

fn rules(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("rules.yml");
    fs::write(
        &path,
        "rules:\n  - id: acme.path-selection\n    name: Path selection fixture\n    pattern: '(acme_[A-Za-z0-9]{16})'\n    min_entropy: 0\n    confidence: high\n",
    )?;
    Ok(path)
}

fn scan(path: &Path, rules: &Path, git: bool) -> Result<Vec<serde_json::Value>> {
    scan_from(path, rules, git, None)
}

fn scan_from(
    path: &Path,
    rules: &Path,
    git: bool,
    cwd: Option<&Path>,
) -> Result<Vec<serde_json::Value>> {
    let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command.arg("scan").arg(path).arg("--rules-path").arg(rules).args([
        "--load-builtins=false",
        "--no-validate",
        "--no-update-check",
        "--format",
        "json",
        "--path-prefix",
        "configs/",
        "--skip-path-prefix",
        "configs/generated/",
        "--file-extension",
        "env",
        "--file-extension",
        "yaml",
        "--skip-file-extension",
        "yaml",
        "--git-history",
        if git { "full" } else { "none" },
        "--commit-metadata=false",
    ]);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let output = command.assert().code(200).get_output().stdout.clone();
    // JSON stdout includes report envelopes and a separate numeric scan summary.
    let mut findings = Vec::new();
    for report in serde_json::Deserializer::from_slice(&output).into_iter::<serde_json::Value>() {
        let report = report?;
        if let Some(records) = report["findings"].as_array() {
            findings.extend(records.iter().cloned());
        } else {
            assert!(report["findings"].is_u64() && report["blobs_scanned"].is_u64());
        }
    }
    assert_eq!(findings.len(), 1, "only the selected file must contribute findings");
    assert_eq!(findings[0]["finding"]["snippet"], KEPT);
    Ok(findings)
}

#[test]
fn explicit_file_input_preserves_its_cwd_relative_directories() -> Result<()> {
    let root = tempfile::tempdir()?;
    let cwd = root.path().canonicalize()?;
    fs::create_dir_all(cwd.join("configs"))?;
    fs::write(cwd.join("configs/key.env"), KEPT)?;
    let rules = rules(&cwd)?;
    scan_from(Path::new("configs/key.env"), &rules, false, Some(&cwd))?;
    scan_from(&cwd.join("configs/key.env"), &rules, false, Some(&cwd))?;
    Ok(())
}

#[test]
fn ordinary_files_with_bangs_are_not_mistaken_for_archive_members() -> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source");
    fs::create_dir_all(source.join("configs"))?;
    fs::write(source.join("configs/key!literal.env"), KEPT)?;
    fs::create_dir_all(source.join("outside!configs"))?;
    fs::write(source.join("outside!configs/key.env"), SKIPPED)?;
    scan(&source, &rules(root.path())?, false)?;
    Ok(())
}

#[test]
fn filesystem_paths_are_relative_to_the_selected_root() -> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("source");
    fs::create_dir_all(source.join("configs/generated"))?;
    fs::write(source.join("configs/key.env"), KEPT)?;
    fs::write(source.join("configs/generated/key.env"), SKIPPED)?;
    fs::write(source.join("configs/settings.yaml"), SKIPPED)?;
    fs::write(source.join("outside.env"), SKIPPED)?;
    scan(&source, &rules(root.path())?, false)?;
    Ok(())
}

#[test]
fn archive_members_use_logical_paths_for_selection() -> Result<()> {
    use std::io::Write;
    let root = tempfile::tempdir()?;
    let archive = root.path().join("source!literal.zip");
    let file = fs::File::create(&archive)?;
    let mut zip = zip::ZipWriter::new(file);
    for (name, content) in [
        ("configs/key!literal.env", KEPT),
        ("outside!configs/key.env", SKIPPED),
        ("configs/generated/key.env", SKIPPED),
        ("outside.env", SKIPPED),
    ] {
        zip.start_file(name, zip::write::SimpleFileOptions::default())?;
        zip.write_all(content.as_bytes())?;
    }
    drop(zip.finish()?);
    scan(&archive, &rules(root.path())?, false)?;
    Ok(())
}

#[test]
fn repository_selection_filters_shared_blob_appearances_for_azure_and_other_git_sources()
-> Result<()> {
    let root = tempfile::tempdir()?;
    let source = root.path().join("repository.git");
    let repo = Repository::init_bare(&source)?;
    repo.remote("origin", "https://dev.azure.com/example/project/_git/repository")?;
    let kept = repo.blob(KEPT.as_bytes())?;
    let skipped = repo.blob(SKIPPED.as_bytes())?;
    let generated = {
        let mut tree = repo.treebuilder(None)?;
        tree.insert("key.env", skipped, 0o100644)?;
        tree.write()?
    };
    let configs = {
        let mut tree = repo.treebuilder(None)?;
        tree.insert("key!literal.env", kept, 0o100644)?;
        tree.insert("settings.yaml", skipped, 0o100644)?;
        tree.insert("generated", generated, 0o040000)?;
        tree.write()?
    };
    let mut tree = repo.treebuilder(None)?;
    tree.insert("configs", configs, 0o040000)?;
    tree.insert("outside.env", kept, 0o100644)?;
    let tree = repo.find_tree(tree.write()?)?;
    let signature = Signature::now("Scanner test", "scanner@example.com")?;
    let commit = repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])?;
    let findings = scan(&source, &rules(root.path())?, true)?;
    let finding = &findings[0]["finding"];
    assert_eq!(finding["path"], "configs/key!literal.env");
    let git = &finding["git_metadata"];
    assert_eq!(
        git["repository_url"], "https://dev.azure.com/example/project/_git/repository",
        "repository identity must survive --commit-metadata=false"
    );
    assert_eq!(git["file"]["path"], "configs/key!literal.env");
    assert_eq!(git["commit"]["id"], commit.to_string());
    assert!(git["commit"]["url"].as_str().is_some_and(|url| !url.is_empty()));
    for field in ["date", "author", "committer"] {
        assert!(
            git["commit"].get(field).is_none(),
            "internal commit {field} must respect --commit-metadata=false"
        );
    }
    Ok(())
}
