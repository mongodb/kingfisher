// tests/smoke_tfplan.rs
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

// A Terraform plan file is a ZIP archive under a name with no recognized
// archive extension (`terraform plan -out=tfplan` yields a ZIP named `tfplan`;
// `tf.plan` downloads use the generic `.plan` extension). Kingfisher must still
// extract and scan the entries inside it rather than treat it as opaque bytes.
#[test]
fn smoke_scan_tfplan_zip_without_archive_extension() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let plan = dir.path().join("tf.plan");
    let github_pat = "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";

    // Build a ZIP (named like a Terraform plan) with the token inside a state
    // entry and a `.tf` config entry.
    {
        use std::io::Write;

        use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

        let f = std::fs::File::create(&plan)?;
        let mut zip = ZipWriter::new(f);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("tfstate", opts)?;
        zip.write_all(format!("token={github_pat}\n").as_bytes())?;
        zip.start_file("tfconfig/main.tf", opts)?;
        zip.write_all(b"variable \"region\" { default = \"us-east-1\" }\n")?;
        zip.finish()?;
    }

    let findings_code = 200;

    // ── extraction ENABLED (default) -- secret should be found ──────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            plan.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-update-check",
        ])
        .assert()
        .code(findings_code)
        .stdout(predicates::str::contains(github_pat));

    // ── extraction DISABLED -- secret *not* found ───────────────────────────────
    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            plan.to_str().unwrap(),
            "--confidence=low",
            "--format",
            "json",
            "--no-extract-archives",
            "--no-update-check",
        ])
        .assert()
        .success()
        .stdout(predicates::str::contains(github_pat).not());

    dir.close()?;
    Ok(())
}
