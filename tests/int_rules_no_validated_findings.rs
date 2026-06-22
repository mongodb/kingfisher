use anyhow::Result;
use assert_cmd::Command;
use serde_json::Value;

/// Ensure that none of the example secrets embedded in the built-in rule YAML
/// files validate as active credentials.
///
/// Kingfisher writes two JSON documents to stdout when `--format json` is used:
///   1. A summary object (`{"findings": N, "successful_validations": M, ...}`)
///      emitted by the scanner runner for every scan.
///   2. The full report envelope (`{"findings": [ ... ], "metadata": ...}`)
///      emitted by the JSON reporter when there is at least one finding to
///      report. With `--only-valid`, this envelope is omitted when no findings
///      validated successfully.
///
/// Kingfisher's exit code contract (see `determine_exit_code` in `src/main.rs`):
///   * 0   — no visible findings
///   * 200 — visible findings present, but none validated as active
///   * 205 — at least one validated (active) finding
///
/// This test passes as long as `successful_validations` is zero and no entry
/// in the optional findings envelope has validation status "active credential".
/// It is deliberately tolerant of exit code 200, of failed HTTP validations
/// (e.g. network unreachable in CI), and of the summary-only / envelope-only
/// stdout shapes.
#[test]
fn scan_rules_has_no_validated_findings() -> Result<()> {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            "crates/kingfisher-rules/data/rules",
            "--format",
            "json",
            "--no-update-check",
            "--only-valid",
        ])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Scan stdout for top-level JSON values. The stream contains the summary
    // object followed optionally by the report envelope (both top-level
    // objects or arrays, no wrapping). Walk through, parse each, and collect
    // whichever shapes we find.
    let mut summary: Option<Value> = None;
    let mut envelope: Option<Value> = None;

    let bytes = stdout.as_bytes();
    let mut idx = 0;
    while idx < bytes.len() {
        // Skip whitespace / stray non-JSON noise between documents.
        while idx < bytes.len() && !matches!(bytes[idx], b'{' | b'[') {
            idx += 1;
        }
        if idx >= bytes.len() {
            break;
        }
        let mut de = serde_json::Deserializer::from_slice(&bytes[idx..]).into_iter::<Value>();
        match de.next() {
            Some(Ok(value)) => {
                let consumed = de.byte_offset();
                // Heuristic: the summary has a numeric "findings" field; the
                // envelope has an array "findings" field.
                if let Some(findings) = value.get("findings") {
                    if findings.is_array() && envelope.is_none() {
                        envelope = Some(value);
                    } else if findings.is_number() && summary.is_none() {
                        summary = Some(value);
                    }
                }
                idx += consumed.max(1);
            }
            Some(Err(_)) | None => break,
        }
    }

    // Primary signal: the scanner summary's `successful_validations` counter.
    let successful_validations = summary
        .as_ref()
        .and_then(|s| s.get("successful_validations"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Secondary signal: any finding in the report envelope whose validation
    // status indicates an active credential. This catches the case where the
    // envelope is present (because something validated) and tells us which
    // rule's example triggered it.
    let mut validated_rule_ids: Vec<String> = Vec::new();
    if let Some(env) = &envelope
        && let Some(findings) = env.get("findings").and_then(|v| v.as_array())
    {
        for finding in findings {
            let status = finding
                .pointer("/finding/validation/status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if status.contains("active") && !status.contains("inactive") {
                let id = finding
                    .pointer("/rule/id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                validated_rule_ids.push(id);
            }
        }
    }

    assert!(
        successful_validations == 0 && validated_rule_ids.is_empty(),
        "Validated findings detected in rules.\n  successful_validations: {}\n  active rule ids: {}\nstdout:\n{}\nstderr:\n{}",
        successful_validations,
        validated_rule_ids.join(", "),
        stdout,
        stderr,
    );

    // Accept exit codes 0 (no findings) and 200 (findings but none validated).
    // Anything else — in particular 205 (active validated findings) or a
    // crash-style exit — is a real failure.
    match output.status.code() {
        Some(0) | Some(200) => Ok(()),
        Some(code) => {
            panic!(
                "kingfisher scan exited with unexpected code {code}.\nstdout:\n{stdout}\nstderr:\n{stderr}",
            );
        }
        None => {
            panic!(
                "kingfisher scan terminated without an exit code.\nstdout:\n{stdout}\nstderr:\n{stderr}",
            );
        }
    }
}
