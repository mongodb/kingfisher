use std::{fs, io::Write, path::Path};

use anyhow::Result;
use assert_cmd::Command;
use git2::{Repository, Signature};

fn pdf() -> Vec<u8> {
    let text: String =
        include_str!("../crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex")
            .split_whitespace()
            .collect();
    hex::decode(text).unwrap()
}

fn overlapping_pdf() -> Vec<u8> {
    let mut bytes = pdf();
    // Keep xref offsets and /Length intact while making page 1's token visible
    // in both raw bytes and extracted text. Page 2 remains extraction-only.
    let start = bytes.windows(7).position(|word| word == b"stream\n").unwrap() + 7;
    let end = start + bytes[start..].windows(9).position(|word| word == b"endstream").unwrap();
    bytes[start..end].fill(b' ');
    let content = b"BT /F1 12 Tf (demo_abcd1234efgh5678) Tj ET\n";
    bytes[start..start + content.len()].copy_from_slice(content);
    bytes[end - 1] = b'\n';
    bytes.extend_from_slice(b"\n% metadata-only demo_deadbeef12345678\n");
    bytes
}

fn rules(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("rules.yml");
    fs::write(
        &path,
        "rules:\n  - id: acme.pdf-test\n    name: PDF test token\n    pattern: '(demo_[a-z0-9]{16})'\n    min_entropy: 0\n    confidence: high\n",
    )?;
    Ok(path)
}

fn scan(path: &Path, rules: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command.arg("scan").arg(path).arg("--rules-path").arg(rules).args([
        "--load-builtins=false",
        "--no-validate",
        "--no-update-check",
        "--no-base64",
        "--format=json",
    ]);
    command
}

fn findings(command: &mut Command) -> Vec<serde_json::Value> {
    let bytes = command.assert().code(200).get_output().stdout.clone();
    serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<serde_json::Value>()
        .flat_map(|report| report.unwrap()["findings"].as_array().cloned().unwrap_or_default())
        .collect()
}

#[test]
fn pdf_files_extract_page_text_and_honor_disable_and_selection_flags() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let bytes = pdf();
    for name in ["document.PDF", "extensionless"] {
        let path = root.path().join(name);
        fs::write(&path, &bytes)?;
        let records = findings(scan(&path, &rules).arg("--no-binary"));
        assert_eq!(records.len(), 2);
        let output = serde_json::to_string(&records)?;
        assert!(output.contains("!page-1.txt") && output.contains("!page-2.txt"));
        assert!(output.contains("demo_abcd1234efgh5678"));
        assert!(output.contains("demo_1234abcd5678efgh"));
        scan(&path, &rules).arg("--no-extract-archives").assert().success();
        assert_eq!(fs::read(&path)?, bytes, "PDF extraction must not modify inputs");
    }
    assert_eq!(
        findings(scan(&root.path().join("document.PDF"), &rules).args(["--file-extension=pdf"]))
            .len(),
        2
    );
    Ok(())
}

#[test]
fn pdf_archive_members_extract_at_the_archive_depth_boundary() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let archive = root.path().join("backup.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive)?);
    zip.start_file("configs/document.pdf", zip::write::SimpleFileOptions::default())?;
    zip.write_all(&pdf())?;
    drop(zip.finish()?);
    let records = findings(scan(&archive, &rules).args([
        "--extraction-depth=1",
        "--path-prefix=configs/",
        "--file-extension=pdf",
    ]));
    assert_eq!(records.len(), 2);
    assert!(serde_json::to_string(&records)?.contains("!configs/document.pdf!page-1.txt"));
    Ok(())
}

#[test]
fn pdf_git_history_keeps_extracted_findings_and_commit_provenance() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let path = root.path().join("repository.git");
    let repo = Repository::init_bare(&path)?;
    repo.remote("origin", "https://github.com/example/pdf-fixture")?;
    let blob = repo.blob(&pdf())?;
    let mut builder = repo.treebuilder(None)?;
    builder.insert("document.pdf", blob, 0o100644)?;
    let tree = repo.find_tree(builder.write()?)?;
    let signature = Signature::now("PDF Test", "pdf@example.invalid")?;
    let commit = repo.commit(Some("HEAD"), &signature, &signature, "PDF fixture", &tree, &[])?;
    let records =
        findings(scan(&path, &rules).args(["--git-history=full", "--file-extension=pdf"]));
    assert_eq!(records.len(), 2);
    let output = serde_json::to_string(&records)?;
    assert!(output.contains("document.pdf!page-1.txt"));
    assert!(output.contains(&commit.to_string()));
    scan(&path, &rules).args(["--git-history=full", "--no-extract-archives"]).assert().success();
    Ok(())
}

#[test]
fn malformed_pdf_falls_back_to_raw_scanning() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let path = root.path().join("broken.pdf");
    fs::write(&path, b"%PDF-1.4\ndemo_abcd1234efgh5678")?;
    assert_eq!(findings(&mut scan(&path, &rules)).len(), 1);
    Ok(())
}

#[test]
fn pdf_raw_bytes_are_scanned_alongside_extracted_pages() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let mut bytes = pdf();
    bytes.extend_from_slice(b"\n% appended metadata demo_deadbeef12345678\n");
    let path = root.path().join("document.pdf");
    fs::write(&path, &bytes)?;
    let records = findings(&mut scan(&path, &rules));
    assert_eq!(records.len(), 3);
    assert!(serde_json::to_string(&records)?.contains("demo_deadbeef12345678"));

    let archive = root.path().join("backup.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive)?);
    zip.start_file("document.pdf", zip::write::SimpleFileOptions::default())?;
    zip.write_all(&bytes)?;
    drop(zip.finish()?);
    assert_eq!(findings(&mut scan(&archive, &rules)).len(), 3);

    // Container magic takes precedence over a misleading .pdf extension.
    let renamed = root.path().join("archive.pdf");
    fs::copy(&archive, &renamed)?;
    assert_eq!(findings(&mut scan(&renamed, &rules)).len(), 3);

    let repository = root.path().join("repository.git");
    let repo = Repository::init_bare(&repository)?;
    let blob = repo.blob(&bytes)?;
    let mut builder = repo.treebuilder(None)?;
    builder.insert("document.pdf", blob, 0o100644)?;
    let tree = repo.find_tree(builder.write()?)?;
    let signature = Signature::now("PDF Test", "pdf@example.invalid")?;
    repo.commit(Some("HEAD"), &signature, &signature, "PDF raw fixture", &tree, &[])?;
    assert_eq!(findings(scan(&repository, &rules).arg("--git-history=full")).len(), 3);
    Ok(())
}

#[test]
fn pdf_raw_and_page_overlap_has_one_stable_location_even_without_dedup() -> Result<()> {
    let root = tempfile::tempdir()?;
    let rules = rules(root.path())?;
    let bytes = overlapping_pdf();
    let file = root.path().join("document.pdf");
    fs::write(&file, &bytes)?;
    let archive = root.path().join("backup.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&archive)?);
    zip.start_file("document.pdf", zip::write::SimpleFileOptions::default())?;
    zip.write_all(&bytes)?;
    drop(zip.finish()?);
    let repository = root.path().join("repository.git");
    let repo = Repository::init_bare(&repository)?;
    let mut builder = repo.treebuilder(None)?;
    builder.insert("document.pdf", repo.blob(&bytes)?, 0o100644)?;
    let tree = repo.find_tree(builder.write()?)?;
    let signature = Signature::now("PDF Test", "pdf@example.invalid")?;
    repo.commit(Some("HEAD"), &signature, &signature, "PDF overlap", &tree, &[])?;

    for path in [&file, &archive, &repository] {
        let mut previous = None;
        for (jobs, no_dedup) in [(1, false), (4, false), (4, true), (2, false)] {
            let mut command = scan(path, &rules);
            command.args(["--git-history=full", &format!("--jobs={jobs}")]);
            if no_dedup {
                command.arg("--no-dedup");
            }
            let records = findings(&mut command);
            assert_eq!(records.len(), 3, "{}: {records:?}", path.display());
            let raw = records
                .iter()
                .find(|record| record["finding"]["snippet"] == "demo_abcd1234efgh5678")
                .unwrap();
            assert!(!raw["finding"]["path"].as_str().unwrap().contains("!page-1.txt"));
            assert!(records.iter().any(|record| {
                record["finding"]["path"].as_str().unwrap().ends_with("!page-2.txt")
            }));
            let mut locations: Vec<_> = records
                .iter()
                .map(|record| {
                    let finding = &record["finding"];
                    serde_json::json!([
                        finding["snippet"],
                        finding["path"],
                        finding["line"],
                        finding["fingerprint"]
                    ])
                })
                .collect();
            locations.sort_by_key(serde_json::Value::to_string);
            if let Some(previous) = &previous {
                assert_eq!(&locations, previous, "{}", path.display());
            }
            previous = Some(locations);
        }
    }

    let baseline = root.path().join("baseline.yml");
    findings(scan(&file, &rules).arg("--manage-baseline").arg("--baseline-file").arg(&baseline));
    let saved = fs::read(&baseline)?;
    for jobs in [1, 4] {
        scan(&file, &rules)
            .arg("--baseline-file")
            .arg(&baseline)
            .arg(format!("--jobs={jobs}"))
            .assert()
            .success();
        assert_eq!(fs::read(&baseline)?, saved);
    }
    Ok(())
}
