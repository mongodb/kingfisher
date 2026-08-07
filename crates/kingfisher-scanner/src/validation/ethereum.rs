//! Deterministic, network-free validation of Ethereum key material.

use bip32::{
    DerivationPath, XPrv,
    secp256k1::ecdsa::{SigningKey, VerifyingKey},
};
use bip39::{Language, Mnemonic};
use kingfisher_core::ValidationOutcome;
use kingfisher_rules::EthereumValidation;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
const MAX_MNEMONIC_BYTES: usize = 640;

/// Secret-free result from local Ethereum validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EthereumValidationOutcome {
    pub outcome: ValidationOutcome,
    pub body: String,
}

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

/// Parse key material and derive its EIP-55 address without network access.
pub fn validate(kind: EthereumValidation, token: &str) -> EthereumValidationOutcome {
    match kind {
        EthereumValidation::PrivateKey => validate_private_key(token),
        EthereumValidation::PublicKey => validate_public_key(token),
        EthereumValidation::Mnemonic => validate_mnemonic(token),
    }
}

/// Reconstruct an allowlisted, secret-free response for reports.
pub fn sanitized_report_body(
    kind: EthereumValidation,
    outcome: ValidationOutcome,
    body: &str,
) -> Option<String> {
    match outcome {
        ValidationOutcome::LocallyDerived => {
            let evidence: DerivedAddressEvidence = serde_json::from_str(body).ok()?;
            let expected_key_type = match kind {
                EthereumValidation::PrivateKey => "secp256k1_private_key",
                EthereumValidation::PublicKey => "secp256k1_public_key",
                EthereumValidation::Mnemonic => "bip39_mnemonic",
            };
            if evidence.validation != "cryptographically_valid_key_material"
                || evidence.derivation != "local"
                || evidence.key_type != expected_key_type
                || !is_checksummed_address(&evidence.derived_address)
            {
                return None;
            }

            let metadata_is_valid = match kind {
                EthereumValidation::Mnemonic => {
                    evidence.bip39_passphrase_assumption.as_deref() == Some("empty")
                        && evidence.derivation_path.as_deref() == Some(DEFAULT_DERIVATION_PATH)
                        && evidence.derived_address_status.as_deref() == Some("candidate")
                }
                EthereumValidation::PrivateKey | EthereumValidation::PublicKey => {
                    evidence.bip39_passphrase_assumption.is_none()
                        && evidence.derivation_path.is_none()
                        && evidence.derived_address_status.is_none()
                }
            };
            metadata_is_valid.then(|| serde_json::to_string(&evidence).ok()).flatten()
        }
        ValidationOutcome::InvalidMaterial => {
            let evidence: InvalidMaterialEvidence = serde_json::from_str(body).ok()?;
            (evidence.validation == "invalid_key_material")
                .then(|| serde_json::to_string(&evidence).ok())
                .flatten()
        }
        _ => None,
    }
}

fn validate_private_key(token: &str) -> EthereumValidationOutcome {
    parse_private_key(token).map_or_else(invalid_key_material, |key| {
        valid_outcome(address_from_public_key(key.verifying_key()), "secp256k1_private_key", false)
    })
}

fn validate_public_key(token: &str) -> EthereumValidationOutcome {
    parse_public_key(token).map_or_else(invalid_key_material, |key| {
        valid_outcome(address_from_public_key(&key), "secp256k1_public_key", false)
    })
}

fn validate_mnemonic(token: &str) -> EthereumValidationOutcome {
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
    let encoded = key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    checksum_address(&digest[12..])
}

fn checksum_address(address: &[u8]) -> String {
    debug_assert_eq!(address.len(), 20);
    let lower = hex::encode(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (index, byte) in lower.bytes().enumerate() {
        let nibble = if index % 2 == 0 { hash[index / 2] >> 4 } else { hash[index / 2] & 0x0f };
        if byte.is_ascii_alphabetic() && nibble >= 8 {
            result.push((byte as char).to_ascii_uppercase());
        } else {
            result.push(byte as char);
        }
    }
    result
}

fn is_checksummed_address(value: &str) -> bool {
    let Some(encoded) = value.strip_prefix("0x") else {
        return false;
    };
    if encoded.len() != 40 {
        return false;
    }
    let Ok(bytes) = hex::decode(encoded) else {
        return false;
    };
    checksum_address(&bytes) == value
}

fn valid_outcome(
    derived_address: String,
    key_type: &str,
    is_mnemonic: bool,
) -> EthereumValidationOutcome {
    let evidence = DerivedAddressEvidence {
        validation: "cryptographically_valid_key_material".to_string(),
        derived_address,
        derivation: "local".to_string(),
        key_type: key_type.to_string(),
        bip39_passphrase_assumption: is_mnemonic.then(|| "empty".to_string()),
        derivation_path: is_mnemonic.then(|| DEFAULT_DERIVATION_PATH.to_string()),
        derived_address_status: is_mnemonic.then(|| "candidate".to_string()),
    };
    EthereumValidationOutcome {
        outcome: ValidationOutcome::LocallyDerived,
        body: serde_json::to_string(&evidence).expect("fixed local evidence must serialize"),
    }
}

fn invalid_key_material() -> EthereumValidationOutcome {
    EthereumValidationOutcome {
        outcome: ValidationOutcome::InvalidMaterial,
        body: serde_json::to_string(&InvalidMaterialEvidence {
            validation: "invalid_key_material".to_string(),
        })
        .expect("fixed local evidence must serialize"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANVIL_PRIVATE_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_MNEMONIC: &str = "test test test test test test test test test test test junk";
    const ANVIL_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn private_key_derives_expected_address_without_echoing_secret() {
        let outcome = validate(EthereumValidation::PrivateKey, ANVIL_PRIVATE_KEY);
        assert_valid_address(&outcome, ANVIL_ADDRESS);
        assert!(!outcome.body.contains(ANVIL_PRIVATE_KEY));
    }

    #[test]
    fn public_key_encodings_derive_the_expected_address() {
        for key in [
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ] {
            assert_valid_address(
                &validate(EthereumValidation::PublicKey, key),
                "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
            );
        }
    }

    #[test]
    fn invalid_scalars_and_curve_points_are_rejected() {
        for (kind, invalid) in [
            (EthereumValidation::PrivateKey, "0".repeat(64)),
            (EthereumValidation::PrivateKey, "f".repeat(64)),
            (EthereumValidation::PublicKey, format!("02{}", "f".repeat(64))),
            (EthereumValidation::PublicKey, format!("04{}", "0".repeat(128))),
        ] {
            let outcome = validate(kind, &invalid);
            assert_eq!(outcome.outcome, ValidationOutcome::InvalidMaterial);
            assert!(!outcome.body.contains(&invalid));
        }
    }

    #[test]
    fn mnemonic_derivation_records_its_assumptions() {
        let outcome = validate(EthereumValidation::Mnemonic, ANVIL_MNEMONIC);
        assert_valid_address(&outcome, ANVIL_ADDRESS);
        let body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        assert_eq!(body["derivation_path"], DEFAULT_DERIVATION_PATH);
        assert_eq!(body["bip39_passphrase_assumption"], "empty");
        assert_eq!(body["derived_address_status"], "candidate");
        assert!(!outcome.body.contains(ANVIL_MNEMONIC));
    }

    #[test]
    fn report_evidence_is_strictly_allowlisted() {
        let outcome = validate(EthereumValidation::PrivateKey, ANVIL_PRIVATE_KEY);
        assert_eq!(
            sanitized_report_body(
                EthereumValidation::PrivateKey,
                ValidationOutcome::LocallyDerived,
                &outcome.body,
            ),
            Some(outcome.body.clone())
        );
        let mut unsafe_body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        unsafe_body["private_key"] = serde_json::Value::String(ANVIL_PRIVATE_KEY.to_string());
        assert!(
            sanitized_report_body(
                EthereumValidation::PrivateKey,
                ValidationOutcome::LocallyDerived,
                &unsafe_body.to_string(),
            )
            .is_none()
        );
    }

    fn assert_valid_address(outcome: &EthereumValidationOutcome, expected: &str) {
        assert_eq!(outcome.outcome, ValidationOutcome::LocallyDerived);
        let body: serde_json::Value = serde_json::from_str(&outcome.body).unwrap();
        assert_eq!(body["derived_address"], expected);
    }
}
