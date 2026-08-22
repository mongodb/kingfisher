// tests/smoke_archive.rs
use assert_cmd::prelude::*;
use predicates::prelude::*;
#[test]
fn smoke_scan_tar_gz_archive() -> anyhow::Result<()> {
    use std::process::Command;

    let dir = tempfile::tempdir()?;
    let tar_gz = dir.path().join("payload.tar.gz");
    let github_pat = "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";

    // --- build a payload.tar.gz -------------------------------------------------
    {
        use std::fs::File;

        use flate2::{Compression, write::GzEncoder};
        use tar::Builder;

        let f = File::create(&tar_gz)?;
        let gz = GzEncoder::new(f, Compression::default());
        let mut t = Builder::new(gz);

        let data = format!("token={github_pat}\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        t.append_data(&mut header, "secret.txt", data.as_bytes())?;
        t.into_inner()?.finish()?;
    }

    // Expected exit-code differs by OS
    let findings_code = 200;

    // ── 1) extraction ENABLED -- secret should be found ─────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tar_gz.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(findings_code)
        .stdout(predicates::str::contains(github_pat));

    // ── 2) extraction DISABLED -- secret *not* found ────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            tar_gz.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-extract-archives",
            "--no-update-check", // skip update check to avoid network calls
        ])
        .assert()
        .success() // always 0
        .stdout(predicates::str::contains(github_pat).not());

    dir.close()?;
    Ok(())
}

#[test]
fn smoke_scan_zip_inside_zip_archive() -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::Command;

    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    let dir = tempfile::tempdir()?;
    let outer_zip = dir.path().join("outer.zip");
    let github_pat = "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";
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    let mut inner = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut inner);
        zip.start_file("secret.txt", options)?;
        zip.write_all(format!("token={github_pat}\n").as_bytes())?;
        zip.finish()?;
    }

    {
        let file = std::fs::File::create(&outer_zip)?;
        let mut zip = ZipWriter::new(file);
        zip.start_file("inner.zip", options)?;
        zip.write_all(inner.get_ref())?;
        zip.finish()?;
    }

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            outer_zip.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
            "--no-validate",
        ])
        .assert()
        .code(200)
        .stdout(predicates::str::contains(github_pat))
        .stdout(predicates::str::contains("!inner.zip!secret.txt"));

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            outer_zip.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--extraction-depth=1",
            "--no-update-check",
            "--no-validate",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(github_pat).not());

    Ok(())
}
