use anyhow::Result;
use assert_cmd::Command;
use tempfile::tempdir;

#[test]
fn scan_local_path_finishes_without_repo_inputs() -> Result<()> {
    let dir = tempdir()?;
    let file_path = dir.path().join("sample.txt");
    std::fs::write(&file_path, "hello world")?;

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    cmd.args([
        "scan",
        file_path.to_str().expect("temp path is valid UTF-8"),
        "--no-update-check",
        "--format",
        "json",
        "--only-valid",
    ]);

    let output = cmd.output()?;
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
    assert!(output.status.success());

    Ok(())
}
