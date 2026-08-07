use std::{collections::BTreeSet, fs};

use assert_cmd::Command;
use serde_json::Value;
use tempfile::tempdir;

struct ScanResult {
    exit_code: i32,
    findings: Vec<Value>,
    metadata: Value,
}

fn scan_fixture(contents: &str, rule_ids: &[&str], validate: bool) -> ScanResult {
    let temp = tempdir().expect("tempdir should be created");
    let input = temp.path().join("fixture.txt");
    let output = temp.path().join("report.json");
    fs::write(&input, contents).expect("fixture should be written");

    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command.args([
        "scan",
        input.to_str().expect("input path should be UTF-8"),
        "--format",
        "json",
        "--output",
        output.to_str().expect("output path should be UTF-8"),
        "--no-update-check",
        "--no-dedup",
        "--include-hidden-findings",
    ]);
    if !validate {
        command.arg("--no-validate");
    }
    for rule_id in rule_ids {
        command.args(["--rule", rule_id]);
    }
    let output_result = command.output().expect("scan should run");
    let exit_code = output_result.status.code().expect("scan should exit normally");
    assert!(
        matches!(exit_code, 0 | 200 | 205),
        "unexpected scan exit {exit_code}: {}",
        String::from_utf8_lossy(&output_result.stderr)
    );

    let report: Value =
        serde_json::from_slice(&fs::read(output).expect("report should be readable"))
            .expect("report should be valid JSON");
    ScanResult {
        exit_code,
        findings: report["findings"].as_array().expect("findings should be an array").clone(),
        metadata: report["metadata"].clone(),
    }
}

fn snippets_for_rule<'a>(findings: &'a [Value], rule_id: &str) -> Vec<&'a str> {
    findings
        .iter()
        .filter(|finding| finding.pointer("/rule/id").and_then(Value::as_str) == Some(rule_id))
        .filter_map(|finding| finding.pointer("/finding/snippet").and_then(Value::as_str))
        .collect()
}

fn finding_for_rule<'a>(findings: &'a [Value], rule_id: &str) -> &'a Value {
    findings
        .iter()
        .find(|finding| finding.pointer("/rule/id").and_then(Value::as_str) == Some(rule_id))
        .unwrap_or_else(|| panic!("missing finding for {rule_id}"))
}

#[test]
fn ethereum_private_and_public_key_patterns_are_contextual_and_same_line() {
    const COMPRESSED_PUBLIC_KEY: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const UNCOMPRESSED_PUBLIC_KEY: &str = concat!(
        "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
    const RAW_PUBLIC_KEY: &str = concat!(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
    const RAW_PUBLIC_KEY_PREFIX_COLLISION: &str = concat!(
        "049370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b459637",
        "58f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a"
    );
    // Small integer scalars are unmistakably synthetic and must never be used as credentials.
    const KEY_A: &str = "0x0000000000000000000000000000000000000000000000000000000000000002";
    const KEY_B: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const KEY_C: &str = "0x0000000000000000000000000000000000000000000000000000000000000004";
    const SCALAR_ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const UNRELATED_HEX: &str =
        "0x0000000000000000000000000000000000000000000000000000000000000000";

    let result = scan_fixture(
        &format!(
            "ETHEREUM_PUBLIC_KEY={COMPRESSED_PUBLIC_KEY}\n\
             EVM_PUBLIC_KEY = {UNCOMPRESSED_PUBLIC_KEY}\n\
             ETH_PUBLIC_KEY: {RAW_PUBLIC_KEY}\n\
             ETH_PUBLIC_KEY={RAW_PUBLIC_KEY_PREFIX_COLLISION}\n\
             EVM_APP_PRIVATE_KEY={KEY_A}\n\
             MY_ETHEREUM_DEPLOYER_PRIVATE_KEY: {KEY_B}\n\
             EVM_PRIVATE_KEY={SCALAR_ONE}\n\
             ethPrivateKey: Hex = {KEY_C}\n\
             privateKeyToAccount(\"{KEY_A}\")\n\
             PRIVATE_KEY={KEY_B}\n\
             SOLANA_PRIVATE_KEY={KEY_B}\n\
             SOLANA WALLET_PRIVATE_KEY={KEY_B}\n\
             BITCOIN: WALLET_PRIVATE_KEY={KEY_B}\n\
             WALLET_PRIVATE_KEY={KEY_B}\n\
             SOLANA_WALLET_PRIVATE_KEY={KEY_B}\n\
             BITCOIN_WALLET_PRIVATE_KEY={KEY_B}\n\
             SOLANA-WALLET_PRIVATE_KEY={KEY_B}\n\
             BITCOIN-WALLET-PRIVATE-KEY={KEY_B}\n\
             solana.wallet_private_key={KEY_B}\n\
             private_key = null\n\
             hash={UNRELATED_HEX}\n\
             publicKey={COMPRESSED_PUBLIC_KEY}\n"
        ),
        &["kingfisher.ethereum.public_key", "kingfisher.ethereum.private_key"],
        false,
    );

    let public = snippets_for_rule(&result.findings, "kingfisher.ethereum.public_key");
    assert_eq!(
        public,
        [
            COMPRESSED_PUBLIC_KEY,
            UNCOMPRESSED_PUBLIC_KEY,
            RAW_PUBLIC_KEY,
            RAW_PUBLIC_KEY_PREFIX_COLLISION,
        ]
    );

    let private = snippets_for_rule(&result.findings, "kingfisher.ethereum.private_key");
    for expected in [KEY_A, KEY_B, SCALAR_ONE, KEY_C] {
        assert!(private.contains(&expected), "missing contextual key fixture");
    }
    assert_eq!(private.len(), 5, "only the four assignments and direct API call should match");
    assert!(!private.contains(&UNRELATED_HEX));
}

#[test]
fn ethernet_identifiers_are_not_ethereum_context() {
    const PRIVATE_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let result = scan_fixture(
        &format!(
            "ethernetPrivateKey={PRIVATE_KEY}\n\
             ethernetPublicKey={PUBLIC_KEY}\n\
             ethernetMnemonic=\"{MNEMONIC}\"\n"
        ),
        &[
            "kingfisher.ethereum.private_key",
            "kingfisher.ethereum.public_key",
            "kingfisher.ethereum.mnemonic",
        ],
        true,
    );

    assert!(result.findings.is_empty(), "Ethernet identifiers must not imply Ethereum context");
}

#[test]
fn generic_bip39_is_chain_neutral_and_phrase_lengths_are_not_truncated() {
    const VALID_12: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const VALID_24: &str = concat!(
        "abandon abandon abandon abandon abandon abandon abandon abandon ",
        "abandon abandon abandon abandon abandon abandon abandon abandon ",
        "abandon abandon abandon abandon abandon abandon abandon art"
    );
    const INVALID_13: &str = concat!(
        "abandon abandon abandon abandon abandon abandon abandon abandon ",
        "abandon abandon abandon about extra"
    );
    const INVALID_MULTILINE_13: &str = concat!(
        "abandon abandon abandon\nabandon abandon abandon\nabandon abandon abandon\n",
        "abandon abandon about extra"
    );
    const MULTILINE_12: &str = "abandon abandon abandon\nabandon abandon abandon\nabandon abandon abandon\nabandon abandon about";
    const MID_FILE_GENERIC: &str =
        "legal winner thank year wave sausage worth useful legal winner thank yellow";
    const MID_FILE_ETHEREUM: &str =
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";

    let result = scan_fixture(
        &format!(
            "\"mnemonic\": \"{VALID_12}\"\n\
             ETHEREUM_MNEMONIC=\"{VALID_24}\"\n\
             ethSeedPhrase=\"{MULTILINE_12}\"\n\
             ETHEREUM_MNEMONIC=\"{INVALID_13}\"\n\
             ETH_MNEMONIC=\"{INVALID_MULTILINE_13}\"\n\
             SOLANA_MNEMONIC=\"{VALID_12}\"\n\
             mnemonic={MID_FILE_GENERIC}\n\
             NEXT=value\n\
             ETHEREUM_MNEMONIC={MID_FILE_ETHEREUM} # local development wallet\n\
             NEXT_AGAIN=value\n"
        ),
        &["kingfisher.bip39.mnemonic", "kingfisher.ethereum.mnemonic"],
        false,
    );

    assert_eq!(
        snippets_for_rule(&result.findings, "kingfisher.bip39.mnemonic"),
        [VALID_12, MID_FILE_GENERIC]
    );
    let ethereum = snippets_for_rule(&result.findings, "kingfisher.ethereum.mnemonic");
    assert_eq!(ethereum, [VALID_24, MULTILINE_12, MID_FILE_ETHEREUM]);
    assert!(!ethereum.iter().any(|snippet| snippet.contains("extra")));
}

#[test]
fn valid_key_material_is_locally_derived_but_never_active() {
    // Publicly documented Anvil defaults: https://getfoundry.sh/anvil/index.html
    const ANVIL_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const PUBLIC_KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ANVIL_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const SCALAR_ONE_ADDRESS: &str = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf";

    let result = scan_fixture(
        &format!(
            "ethereum_private_key={ANVIL_PRIVATE_KEY}\n\
             ETHEREUM_MNEMONIC=\"{ANVIL_MNEMONIC}\"\n\
             ETHEREUM_PUBLIC_KEY={PUBLIC_KEY}\n"
        ),
        &[
            "kingfisher.ethereum.private_key",
            "kingfisher.ethereum.mnemonic",
            "kingfisher.ethereum.public_key",
        ],
        true,
    );

    assert_eq!(result.exit_code, 200, "local derivation must not use the active-credential exit");
    for (rule_id, expected_address) in [
        ("kingfisher.ethereum.private_key", ANVIL_ADDRESS),
        ("kingfisher.ethereum.mnemonic", ANVIL_ADDRESS),
        ("kingfisher.ethereum.public_key", SCALAR_ONE_ADDRESS),
    ] {
        let finding = finding_for_rule(&result.findings, rule_id);
        assert_eq!(
            finding.pointer("/finding/validation/status").and_then(Value::as_str),
            Some("Locally Derived")
        );
        let response: Value = serde_json::from_str(
            finding
                .pointer("/finding/validation/response")
                .and_then(Value::as_str)
                .expect("safe validation response should be present"),
        )
        .expect("response should be JSON");
        assert_eq!(response["derived_address"], expected_address);
        assert_eq!(response["derivation"], "local");
    }

    let mnemonic_response: Value = serde_json::from_str(
        finding_for_rule(&result.findings, "kingfisher.ethereum.mnemonic")
            .pointer("/finding/validation/response")
            .and_then(Value::as_str)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(mnemonic_response["derivation_path"], "m/44'/60'/0'/0/0");
    assert_eq!(mnemonic_response["bip39_passphrase_assumption"], "empty");
    assert_eq!(mnemonic_response["derived_address_status"], "candidate");
    assert_eq!(result.metadata.pointer("/summary/successful_validations"), Some(&Value::from(0)));
    assert_eq!(result.metadata.pointer("/summary/failed_validations"), Some(&Value::from(0)));
    assert_eq!(result.metadata.pointer("/summary/locally_derived_findings"), Some(&Value::from(3)));
    assert_eq!(
        result.metadata.pointer("/summary/invalid_key_material_findings"),
        Some(&Value::from(0))
    );
}

#[test]
fn no_validate_is_not_mislabeled_as_locally_derived() {
    // Publicly documented Anvil default: https://getfoundry.sh/anvil/index.html
    const KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let result = scan_fixture(
        &format!("ETHEREUM_PRIVATE_KEY={KEY}\n"),
        &["kingfisher.ethereum.private_key"],
        false,
    );
    assert_eq!(
        finding_for_rule(&result.findings, "kingfisher.ethereum.private_key")
            .pointer("/finding/validation/status")
            .and_then(Value::as_str),
        Some("Not Attempted")
    );
}

#[test]
fn invalid_curve_material_is_detected_but_not_locally_derived() {
    let invalid_public_key = format!("02{}", "f".repeat(64));
    let result = scan_fixture(
        &format!("ETHEREUM_PUBLIC_KEY={invalid_public_key}\n"),
        &["kingfisher.ethereum.public_key"],
        true,
    );
    let finding = finding_for_rule(&result.findings, "kingfisher.ethereum.public_key");
    assert_eq!(
        finding.pointer("/finding/validation/status").and_then(Value::as_str),
        Some("Invalid Key Material")
    );
    assert_eq!(
        result.exit_code, 0,
        "a hidden public-identifier finding must not change the process exit code"
    );
    assert_eq!(result.metadata.pointer("/summary/successful_validations"), Some(&Value::from(0)));
    assert_eq!(result.metadata.pointer("/summary/failed_validations"), Some(&Value::from(1)));
    assert_eq!(
        result.metadata.pointer("/summary/invalid_key_material_findings"),
        Some(&Value::from(1))
    );
}

#[test]
fn local_derivations_are_excluded_by_only_valid_and_rendered_in_html() {
    // Publicly documented Anvil default: https://getfoundry.sh/anvil/index.html
    const PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const DERIVED_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    let invalid_public_key = format!("02{}", "f".repeat(64));
    let temp = tempdir().unwrap();
    let input = temp.path().join("fixture.txt");
    let html_path = temp.path().join("report.html");
    fs::write(
        &input,
        format!("ETHEREUM_PRIVATE_KEY={PRIVATE_KEY}\nETHEREUM_PUBLIC_KEY={invalid_public_key}\n"),
    )
    .unwrap();

    let html_output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.ethereum.private_key",
            "--rule",
            "kingfisher.ethereum.public_key",
            "--format",
            "html",
            "--include-hidden-findings",
            "--output",
            html_path.to_str().unwrap(),
            "--no-update-check",
        ])
        .output()
        .unwrap();
    assert_eq!(html_output.status.code(), Some(200));
    let html = fs::read_to_string(html_path).unwrap();
    assert!(html.contains("Locally Derived"));
    assert!(html.contains("status-local"));
    assert!(html.contains(DERIVED_ADDRESS));
    assert!(html.contains("Invalid Key Material"));
    assert!(html.contains("status-invalid"));
    assert!(html.contains("Validation Response"));
    assert!(!html.contains(PRIVATE_KEY));

    let only_valid = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.ethereum.private_key",
            "--format",
            "json",
            "--only-valid",
            "--no-update-check",
        ])
        .output()
        .unwrap();
    assert_eq!(only_valid.status.code(), Some(200));
    assert!(!String::from_utf8_lossy(&only_valid.stdout).contains("Locally Derived"));
}

#[test]
fn distinct_private_keys_keep_distinct_safe_derivation_results() {
    // Publicly documented Anvil defaults: https://getfoundry.sh/anvil/index.html
    const FIRST_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const FIRST_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const SECOND_PRIVATE_KEY: &str =
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const SECOND_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    let result = scan_fixture(
        &format!(
            "ETHEREUM_PRIVATE_KEY={FIRST_PRIVATE_KEY}\nETH_PRIVATE_KEY={SECOND_PRIVATE_KEY}\n"
        ),
        &["kingfisher.ethereum.private_key"],
        true,
    );
    let addresses = result
        .findings
        .iter()
        .filter(|finding| {
            finding.pointer("/rule/id").and_then(Value::as_str)
                == Some("kingfisher.ethereum.private_key")
        })
        .map(|finding| {
            let response = finding
                .pointer("/finding/validation/response")
                .and_then(Value::as_str)
                .expect("validation response should be present");
            serde_json::from_str::<Value>(response).unwrap()["derived_address"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        addresses,
        [FIRST_ADDRESS.to_string(), SECOND_ADDRESS.to_string()].into_iter().collect()
    );
}

#[test]
fn ethereum_key_material_never_appears_in_verbose_logs_or_validation_responses() {
    // Publicly documented Anvil defaults: https://getfoundry.sh/anvil/index.html
    const PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const MNEMONIC: &str = "test test test test test test test test test test test junk";
    let temp = tempdir().expect("tempdir should be created");
    let input = temp.path().join("fixture.txt");
    let report_path = temp.path().join("report.json");
    fs::write(
        &input,
        format!("ETHEREUM_PRIVATE_KEY={PRIVATE_KEY}\nETHEREUM_MNEMONIC=\"{MNEMONIC}\"\n"),
    )
    .unwrap();

    let output = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "-vvv",
            "scan",
            input.to_str().unwrap(),
            "--git-history",
            "none",
            "--rule",
            "kingfisher.ethereum.private_key",
            "--rule",
            "kingfisher.ethereum.mnemonic",
            "--format",
            "json",
            "--output",
            report_path.to_str().unwrap(),
            "--redact",
            "--no-update-check",
        ])
        .output()
        .expect("scan should run");

    assert_eq!(output.status.code(), Some(200));
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains(PRIVATE_KEY));
    assert!(!combined.contains(MNEMONIC));

    let report = fs::read_to_string(report_path).unwrap();
    assert!(!report.contains(PRIVATE_KEY));
    assert!(!report.contains(MNEMONIC));
    assert!(report.contains("Locally Derived"));
    assert!(report.contains("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"));
}
