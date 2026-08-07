use std::fs;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

const ANVIL_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
const ANVIL_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

#[test]
fn ethereum_rules_derive_addresses_without_claiming_live_activity() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("fixture.txt");
    let report_path = temp.path().join("report.json");
    fs::write(
        &input,
        format!(
            "ETHEREUM_PRIVATE_KEY={ANVIL_PRIVATE_KEY}\n\
             ETHEREUM_MNEMONIC=\"{ANVIL_MNEMONIC}\"\n"
        ),
    )
    .unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.ethereum.1",
            "--rule",
            "kingfisher.ethereum.2",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--no-update-check",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(200), "{}", String::from_utf8_lossy(&output.stderr));
    let report_text = fs::read_to_string(report_path).unwrap();

    let report: Value = serde_json::from_str(&report_text).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    for finding in findings {
        assert_eq!(finding["finding"]["validation"]["outcome"], "locally_derived");
        assert_eq!(finding["finding"]["validation"]["status"], "Locally Derived");
        let response = finding["finding"]["validation"]["response"].as_str().unwrap();
        assert!(!response.contains(ANVIL_PRIVATE_KEY));
        assert!(!response.contains(ANVIL_MNEMONIC));
        let evidence: Value = serde_json::from_str(response).unwrap();
        assert_eq!(evidence["derived_address"], ANVIL_ADDRESS);
    }
    assert_eq!(report["metadata"]["summary"]["locally_derived_findings"], 2);
    assert_eq!(report["metadata"]["summary"]["active_findings"], 0);
    assert_eq!(report["metadata"]["summary"]["successful_validations"], 0);
    assert_eq!(report["metadata"]["summary"]["skipped_validations"], 2);
}

#[test]
fn direct_validation_exposes_local_outcome_and_sanitized_evidence() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "validate",
            "--rule",
            "kingfisher.ethereum.1",
            "--format",
            "json",
            "--no-update-check",
            ANVIL_PRIVATE_KEY,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(ANVIL_PRIVATE_KEY));
    let result: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["validation_outcome"], "locally_derived");
    let evidence: Value = serde_json::from_str(result["message"].as_str().unwrap()).unwrap();
    assert_eq!(evidence["derived_address"], ANVIL_ADDRESS);
}

#[test]
fn generic_bip39_detection_is_checksum_gated_and_chain_neutral() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("fixture.txt");
    let report_path = temp.path().join("report.json");
    fs::write(
        &input,
        "seed_phrase=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n\
         mnemonic=abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon\n",
    )
    .unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.bip39.1",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--no-update-check",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(200), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"][0]["rule"]["id"], "kingfisher.bip39.1");
}

#[test]
fn invalid_curve_material_has_its_own_non_actionable_outcome() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("fixture.txt");
    let report_path = temp.path().join("report.json");
    // secp256k1's group order is not a valid private scalar.
    let invalid_private_key = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    fs::write(&input, format!("ETHEREUM_PRIVATE_KEY={invalid_private_key}\n")).unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.ethereum.1",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--no-update-check",
        ])
        .output()
        .unwrap();

    assert!(matches!(output.status.code(), Some(0 | 200)));
    let report: Value = serde_json::from_slice(&fs::read(report_path).unwrap()).unwrap();
    assert_eq!(report["findings"][0]["finding"]["validation"]["outcome"], "invalid_material");
    assert_eq!(report["metadata"]["summary"]["invalid_material_findings"], 1);
    assert_eq!(report["metadata"]["summary"]["failed_validations"], 1);
}
