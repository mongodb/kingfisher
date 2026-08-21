use std::{
    ffi::{OsStr, OsString},
    fs,
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use serde_json::{Deserializer, Value};

fn scan_inputs_without_parser_fixtures() -> Result<Vec<OsString>> {
    let mut inputs = fs::read_dir("testdata")
        .context("read testdata directory")?
        .map(|entry| {
            let entry = entry.context("read testdata entry")?;
            let path = entry.path();
            Ok((entry.file_name(), path))
        })
        .collect::<Result<Vec<_>>>()?;

    inputs.sort_by(|left, right| left.0.cmp(&right.0));

    Ok(inputs
        .into_iter()
        .filter_map(|(name, path)| (name != OsStr::new("parsers")).then_some(path.into_os_string()))
        .collect())
}

#[test]
fn default_scan_uses_betterleaks_builtin_catalog() -> Result<()> {
    let mut args = vec![OsString::from("scan")];
    args.extend(scan_inputs_without_parser_fixtures()?);
    args.extend([
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("--no-validate"),
        OsString::from("--no-update-check"),
        OsString::from("--no-dedup"),
    ]);

    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args(&args)
        .output()
        .context("run kingfisher scan against testdata inputs without parser fixtures")?;

    let code = output.status.code().unwrap_or_default();
    assert!(
        matches!(code, 0 | 200),
        "expected exit code 0 or 200, got {code}. stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).context("scan stdout is not valid utf-8")?;
    let mut stream = Deserializer::from_str(&stdout).into_iter::<Value>();
    let value = stream
        .next()
        .transpose()
        .context("parse scan json output")?
        .context("scan output did not contain a json object")?;

    let findings = value
        .get("findings")
        .and_then(Value::as_array)
        .context("scan output missing findings array")?;

    assert!(!findings.is_empty(), "expected the test corpus to produce findings");
    for finding in findings {
        let rule_id = finding
            .get("rule")
            .and_then(|rule| rule.get("id"))
            .and_then(Value::as_str)
            .context("finding is missing its rule id")?;
        assert!(
            rule_id.starts_with("betterleaks.") || rule_id.starts_with("veles."),
            "default scan used an unexpected rule catalog: {rule_id}"
        );
    }
    Ok(())
}

#[test]
fn scan_inputs_exclude_parser_fixture_directory() -> Result<()> {
    let inputs = scan_inputs_without_parser_fixtures()?;

    assert!(inputs.iter().all(|path| Path::new(path) != Path::new("testdata/parsers")));
    assert!(
        inputs.iter().any(|path| Path::new(path) == Path::new("testdata/python_vulnerable.py"))
    );

    Ok(())
}
