//! Network-free validation and address derivation for Ethereum key material.

use alloy_primitives::Address;
use bip32::{
    DerivationPath, XPrv,
    secp256k1::ecdsa::{SigningKey, VerifyingKey},
};
use bip39::{Language, Mnemonic};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use super::{ValidationDisposition, local::LocalValidationOutcome};

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
// Covers 24 eight-letter words with every detector-accepted 16-byte separator.
const MAX_MNEMONIC_BYTES: usize = 640;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedAddressEvidence {
    validation: String,
    derived_address: String,
    derivation: String,
    key_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    bip39_passphrase_assumption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derivation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_address_status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InvalidMaterialEvidence {
    validation: String,
}

/// Whether a raw validation name is implemented by this module.
pub(super) fn handles(kind: &str) -> bool {
    matches!(kind, "ethereum_mnemonic" | "ethereum_private_key" | "ethereum_public_key")
}

/// Parse key material and derive its EVM address without making a network request.
pub(super) fn validate(kind: &str, token: &str) -> LocalValidationOutcome {
    match kind {
        "ethereum_mnemonic" => validate_mnemonic(token),
        "ethereum_private_key" => validate_private_key(token),
        "ethereum_public_key" => validate_public_key(token),
        _ => invalid_key_material(),
    }
}

/// Reconstruct an allowlisted, secret-free response for reports.
pub(super) fn sanitized_report_body(
    kind: &str,
    disposition: ValidationDisposition,
    body: &str,
) -> Option<String> {
    match disposition {
        ValidationDisposition::LocallyDerived => {
            let evidence: DerivedAddressEvidence = serde_json::from_str(body).ok()?;
            let expected_key_type = match kind {
                "ethereum_private_key" => "secp256k1_private_key",
                "ethereum_public_key" => "secp256k1_public_key",
                "ethereum_mnemonic" => "bip39_mnemonic",
                _ => return None,
            };
            if evidence.validation != "cryptographically_valid_key_material"
                || evidence.derivation != "local"
                || evidence.key_type != expected_key_type
                || Address::parse_checksummed(&evidence.derived_address, None).is_err()
            {
                return None;
            }
            let mnemonic_metadata_is_valid = if kind == "ethereum_mnemonic" {
                evidence.bip39_passphrase_assumption.as_deref() == Some("empty")
                    && evidence.derivation_path.as_deref() == Some(DEFAULT_DERIVATION_PATH)
                    && evidence.derived_address_status.as_deref() == Some("candidate")
            } else {
                evidence.bip39_passphrase_assumption.is_none()
                    && evidence.derivation_path.is_none()
                    && evidence.derived_address_status.is_none()
            };
            mnemonic_metadata_is_valid.then(|| serde_json::to_string(&evidence).ok()).flatten()
        }
        ValidationDisposition::InvalidMaterial => {
            let evidence: InvalidMaterialEvidence = serde_json::from_str(body).ok()?;
            (handles(kind) && evidence.validation == "invalid_key_material")
                .then(|| serde_json::to_string(&evidence).ok())
                .flatten()
        }
        _ => None,
    }
}

fn validate_private_key(token: &str) -> LocalValidationOutcome {
    parse_private_key(token).map_or_else(invalid_key_material, |key| {
        valid_outcome(address_from_public_key(key.verifying_key()), "secp256k1_private_key", false)
    })
}

fn validate_public_key(token: &str) -> LocalValidationOutcome {
    parse_public_key(token).map_or_else(invalid_key_material, |key| {
        valid_outcome(address_from_public_key(&key), "secp256k1_public_key", false)
    })
}

fn validate_mnemonic(token: &str) -> LocalValidationOutcome {
    if token.len() > MAX_MNEMONIC_BYTES {
        return invalid_key_material();
    }
    let normalized = Zeroizing::new(token.split_whitespace().collect::<Vec<_>>().join(" "));
    let Some(mnemonic) = Mnemonic::parse_in_normalized(Language::English, &normalized).ok() else {
        return invalid_key_material();
    };

    let mut seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let derived = DEFAULT_DERIVATION_PATH
        .parse::<DerivationPath>()
        .ok()
        .and_then(|path| XPrv::derive_from_path(seed.as_slice(), &path).ok());
    seed.as_mut().zeroize();

    derived.map_or_else(invalid_key_material, |key| {
        valid_outcome(
            address_from_public_key(key.private_key().verifying_key()),
            "bip39_mnemonic",
            true,
        )
    })
}

fn parse_private_key(token: &str) -> Option<SigningKey> {
    let encoded = strip_hex_prefix(token.trim());
    if encoded.len() != 64 {
        return None;
    }
    let mut bytes = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(encoded, bytes.as_mut()).ok()?;
    SigningKey::from_slice(bytes.as_ref()).ok()
}

fn parse_public_key(token: &str) -> Option<VerifyingKey> {
    let encoded = strip_hex_prefix(token.trim());
    match encoded.len() {
        // Length takes precedence over prefix: a raw x-coordinate can begin
        // with any byte, including the SEC1 marker values 02, 03, or 04.
        128 => {
            let mut bytes = [0_u8; 65];
            bytes[0] = 0x04;
            hex::decode_to_slice(encoded, &mut bytes[1..]).ok()?;
            VerifyingKey::from_sec1_bytes(&bytes).ok()
        }
        66 if matches!(encoded.get(..2), Some("02" | "03")) => {
            let bytes = hex::decode(encoded).ok()?;
            VerifyingKey::from_sec1_bytes(&bytes).ok()
        }
        130 if encoded.starts_with("04") => {
            let bytes = hex::decode(encoded).ok()?;
            VerifyingKey::from_sec1_bytes(&bytes).ok()
        }
        _ => None,
    }
}

fn strip_hex_prefix(value: &str) -> &str {
    value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value)
}

fn address_from_public_key(key: &VerifyingKey) -> String {
    Address::from_public_key(key).to_checksum(None)
}

fn valid_outcome(
    derived_address: String,
    key_type: &str,
    is_mnemonic: bool,
) -> LocalValidationOutcome {
    let evidence = DerivedAddressEvidence {
        validation: "cryptographically_valid_key_material".to_string(),
        derived_address,
        derivation: "local".to_string(),
        key_type: key_type.to_string(),
        bip39_passphrase_assumption: is_mnemonic.then(|| "empty".to_string()),
        derivation_path: is_mnemonic.then(|| DEFAULT_DERIVATION_PATH.to_string()),
        derived_address_status: is_mnemonic.then(|| "candidate".to_string()),
    };
    LocalValidationOutcome {
        disposition: ValidationDisposition::LocallyDerived,
        body: serde_json::to_string(&evidence).expect("fixed local evidence must serialize"),
    }
}

fn invalid_key_material() -> LocalValidationOutcome {
    LocalValidationOutcome {
        disposition: ValidationDisposition::InvalidMaterial,
        body: serde_json::to_string(&InvalidMaterialEvidence {
            validation: "invalid_key_material".to_string(),
        })
        .expect("fixed local evidence must serialize"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Publicly documented Anvil defaults: https://getfoundry.sh/anvil/index.html
    const ANVIL_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ANVIL_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn private_key_derives_expected_address_without_echoing_secret() {
        let outcome = validate("ethereum_private_key", ANVIL_PRIVATE_KEY);
        assert_valid_address(&outcome, ANVIL_ADDRESS);
        assert!(!outcome.body.contains(ANVIL_PRIVATE_KEY));
    }

    #[test]
    fn scalar_one_is_valid() {
        let scalar_one = format!("{:064x}", 1);
        let outcome = validate("ethereum_private_key", &scalar_one);
        assert_valid_address(&outcome, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
    }

    #[test]
    fn largest_valid_scalar_is_accepted() {
        let order_minus_one = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";
        assert_eq!(
            validate("ethereum_private_key", order_minus_one).disposition,
            ValidationDisposition::LocallyDerived
        );
        assert_eq!(
            validate(
                "ethereum_private_key",
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            )
            .disposition,
            ValidationDisposition::InvalidMaterial
        );
    }

    #[test]
    fn public_keys_are_validated_and_derive_the_same_address() {
        for key in [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ] {
            let outcome = validate("ethereum_public_key", key);
            assert_valid_address(&outcome, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
        }

        // Scalar 45 has a raw x-coordinate beginning with 0x04. Raw-key
        // parsing must use total length before interpreting SEC1 prefixes.
        let raw_prefix_collision = "049370a4b5f43412ea25f514e8ecdad05266115e4a7ecb1387231808f8b45963758f3f41afd6ed428b3081b0512fd62a54c3f3afbb5b6764b653052a12949c9a";
        assert_valid_address(
            &validate("ethereum_public_key", raw_prefix_collision),
            "0x6C23faCE014F20B3ebb65aE96D0D7FF32aB94c17",
        );
    }

    #[test]
    fn invalid_scalars_and_curve_points_are_rejected_without_echoing_input() {
        for (kind, invalid) in [
            ("ethereum_private_key", "0".repeat(64)),
            ("ethereum_private_key", "f".repeat(64)),
            ("ethereum_public_key", format!("02{}", "f".repeat(64))),
            ("ethereum_public_key", format!("04{}", "0".repeat(128))),
        ] {
            let outcome = validate(kind, &invalid);
            assert_eq!(outcome.disposition, ValidationDisposition::InvalidMaterial);
            assert!(!outcome.body.contains(&invalid));
        }
    }

    #[test]
    fn mnemonic_derivation_qualifies_path_and_passphrase_assumptions() {
        let outcome = validate("ethereum_mnemonic", ANVIL_MNEMONIC);
        assert_valid_address(&outcome, ANVIL_ADDRESS);
        let body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        assert_eq!(body["derivation_path"], DEFAULT_DERIVATION_PATH);
        assert_eq!(body["bip39_passphrase_assumption"], "empty");
        assert_eq!(body["derived_address_status"], "candidate");
        assert!(!outcome.body.contains(ANVIL_MNEMONIC));
    }

    #[test]
    fn mnemonic_accepts_standard_word_counts_and_normalizes_whitespace() {
        for phrase in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "  test\ttest  test\ntest test   test test test test test test junk  ",
        ] {
            let outcome = validate("ethereum_mnemonic", phrase);
            assert_eq!(
                outcome.disposition,
                ValidationDisposition::LocallyDerived,
                "rejected a valid BIP-39 phrase"
            );
            assert!(!outcome.body.contains(phrase));
        }
    }

    #[test]
    fn mnemonic_rejects_invalid_material_without_echoing_input() {
        for invalid in [
            "",
            "test test test test test test test test test test test test",
            "test test test test test test test test test test test unknown",
            "test test test",
        ] {
            let outcome = validate("ethereum_mnemonic", invalid);
            assert_eq!(outcome.disposition, ValidationDisposition::InvalidMaterial);
            assert!(invalid.is_empty() || !outcome.body.contains(invalid));
        }
    }

    #[test]
    fn local_derivation_response_is_strictly_sanitized() {
        let outcome = validate("ethereum_private_key", ANVIL_PRIVATE_KEY);
        assert_eq!(
            sanitized_report_body(
                "ethereum_private_key",
                ValidationDisposition::LocallyDerived,
                &outcome.body,
            ),
            Some(outcome.body.clone())
        );
        let mut unsafe_body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        unsafe_body["private_key"] = serde_json::Value::String(ANVIL_PRIVATE_KEY.to_string());
        assert!(
            sanitized_report_body(
                "ethereum_private_key",
                ValidationDisposition::LocallyDerived,
                &unsafe_body.to_string(),
            )
            .is_none()
        );
        assert_eq!(
            sanitized_report_body(
                "ethereum_private_key",
                ValidationDisposition::InvalidMaterial,
                &invalid_key_material().body
            ),
            Some(invalid_key_material().body)
        );
    }

    #[test]
    fn oversized_mnemonic_is_rejected_before_normalization() {
        let oversized = "a".repeat(MAX_MNEMONIC_BYTES + 1);
        assert_eq!(
            validate("ethereum_mnemonic", &oversized).disposition,
            ValidationDisposition::InvalidMaterial
        );
    }

    fn assert_valid_address(outcome: &LocalValidationOutcome, expected: &str) {
        assert_eq!(outcome.disposition, ValidationDisposition::LocallyDerived);
        let body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        assert_eq!(body["derived_address"], expected);
    }
}
