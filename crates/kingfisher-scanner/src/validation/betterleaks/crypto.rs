//! Strict, binary-safe adapters for Kingfisher's opt-in cryptographic expression helpers.
//!
//! Legacy Betterleaks helpers retain their existing coercions and return encodings in
//! the parent module. Never interpolate argument values into errors here.

use anyhow::{Context, Result, anyhow, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use kingfisher_rules::{
    BetterleaksExpr,
    crypto::{self as primitives, InvalidCryptoInput, WorkBudget, WorkBudgetExceeded},
};
use sha2::{Digest, Sha384, Sha512};

use super::{Value, static_name};

#[derive(Debug, thiserror::Error)]
#[error("invalid cryptographic configuration")]
pub(super) struct InvalidCryptoConfiguration;

pub(super) fn configuration_failure(error: &anyhow::Error) -> bool {
    error.is::<InvalidCryptoConfiguration>() || error.is::<WorkBudgetExceeded>()
}

pub(super) fn classify_input_error(
    error: anyhow::Error,
    arguments: &[BetterleaksExpr],
) -> anyhow::Error {
    let literal_at = |index| arguments.get(index).is_some_and(is_literal);
    let from_literals = match error.downcast_ref::<InvalidCryptoInput>() {
        Some(InvalidCryptoInput::Argument(index)) => literal_at(*index),
        Some(InvalidCryptoInput::Arguments(indices)) => indices.iter().copied().all(literal_at),
        Some(InvalidCryptoInput::Combined) => arguments.iter().all(is_literal),
        None => false,
    };
    if from_literals { error.context(InvalidCryptoConfiguration) } else { error }
}

fn is_literal(expression: &BetterleaksExpr) -> bool {
    use BetterleaksExpr as Expr;
    match expression {
        Expr::Nil
        | Expr::Bool { .. }
        | Expr::Integer { .. }
        | Expr::Float { .. }
        | Expr::String { .. } => true,
        Expr::Unary { operator, node } if matches!(operator.as_str(), "+" | "-") => {
            is_literal(node)
        }
        Expr::Call { callee, arguments } => {
            // These builtins derive bytes or text entirely from their arguments.
            static_name(callee).is_some_and(|name| {
                matches!(
                    name.as_str(),
                    "bytes" | "repeat" | "hex.decode" | "base64.decode" | "base64url.decode"
                )
            }) && arguments.iter().all(is_literal)
        }
        _ => false,
    }
}

pub(super) fn call(name: &str, args: &[Value], budget: &mut WorkBudget) -> Result<Value> {
    // The helpers with caller-specified output lengths check their bounds before charging.
    if !matches!(name, "crypto.hkdfSha256" | "crypto.pbkdf2Sha256" | "crypto.randomBytes") {
        budget.charge(data_length(args), extra_work(name, args))?;
    }
    match name {
        "crypto.sha384" | "crypto.sha512" => {
            arity(args, 1, 1)?;
            let input = bytes(args, 0)?;
            Ok(Value::String(if name == "crypto.sha384" {
                hex::encode(Sha384::digest(input))
            } else {
                hex::encode(Sha512::digest(input))
            }))
        }
        "crypto.hmacSha384" | "crypto.hmacSha512" => {
            arity(args, 2, 2)?;
            let key = bytes(args, 0)?;
            let message = bytes(args, 1)?;
            let digest = if name == "crypto.hmacSha384" {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            } else {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| anyhow::anyhow!("invalid HMAC key"))?;
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            };
            Ok(Value::bytes(digest))
        }
        "crypto.ecPublicKey" => {
            arity(args, 2, 2)?;
            Ok(Value::bytes(primitives::ec_public_key(text(args, 0)?, bytes(args, 1)?)?))
        }
        "crypto.ecdh" => {
            arity(args, 3, 3)?;
            Ok(Value::bytes(primitives::ecdh(text(args, 0)?, bytes(args, 1)?, bytes(args, 2)?)?))
        }
        "crypto.ecdsaSign" => {
            arity(args, 3, 4)?;
            Ok(Value::bytes(primitives::ecdsa_sign(
                text(args, 0)?,
                bytes(args, 1)?,
                bytes(args, 2)?,
                if args.len() == 4 { text(args, 3)? } else { "p1363" },
            )?))
        }
        "crypto.ecdsaVerify" => {
            arity(args, 4, 5)?;
            Ok(Value::Bool(primitives::ecdsa_verify(
                text(args, 0)?,
                bytes(args, 1)?,
                bytes(args, 2)?,
                bytes(args, 3)?,
                if args.len() == 5 { text(args, 4)? } else { "p1363" },
            )?))
        }
        "crypto.aesGcmEncrypt" | "crypto.aesGcmDecrypt" => {
            arity(args, 3, 4)?;
            let key = bytes(args, 0)?;
            let nonce = bytes(args, 1)?;
            let input = bytes(args, 2)?;
            let aad = if args.len() == 4 { bytes(args, 3)? } else { &[] };
            Ok(Value::bytes(if name == "crypto.aesGcmEncrypt" {
                primitives::aes_gcm_encrypt(key, nonce, input, aad)?
            } else {
                primitives::aes_gcm_decrypt(key, nonce, input, aad)?
            }))
        }
        "crypto.hkdfSha256" => {
            arity(args, 4, 4)?;
            Ok(Value::bytes(primitives::hkdf_sha256_with_budget(
                bytes(args, 0)?,
                bytes(args, 1)?,
                bytes(args, 2)?,
                positive_integer(args, 3)?,
                budget,
            )?))
        }
        "crypto.pbkdf2Sha256" => {
            arity(args, 4, 4)?;
            let iterations = u32::try_from(positive_integer(args, 2)?)
                .map_err(|_| anyhow!("invalid PBKDF2 iteration count"))
                .context(InvalidCryptoInput::Argument(2))?;
            Ok(Value::bytes(primitives::pbkdf2_sha256_with_budget(
                bytes(args, 0)?,
                bytes(args, 1)?,
                iterations,
                positive_integer(args, 3)?,
                budget,
            )?))
        }
        "crypto.ed25519PublicKey" => {
            arity(args, 1, 1)?;
            Ok(Value::bytes(primitives::ed25519_public_key(bytes(args, 0)?)?))
        }
        "crypto.ed25519Sign" => {
            arity(args, 2, 2)?;
            Ok(Value::bytes(primitives::ed25519_sign(bytes(args, 0)?, bytes(args, 1)?)?))
        }
        "crypto.ed25519Verify" => {
            arity(args, 3, 3)?;
            Ok(Value::Bool(primitives::ed25519_verify(
                bytes(args, 0)?,
                bytes(args, 1)?,
                bytes(args, 2)?,
            )?))
        }
        "crypto.randomBytes" => {
            arity(args, 1, 1)?;
            Ok(Value::bytes(primitives::random_bytes_with_budget(
                positive_integer(args, 0)?,
                budget,
            )?))
        }
        "crypto.constantTimeEqual" => {
            arity(args, 2, 2)?;
            Ok(Value::Bool(primitives::constant_time_eq(bytes(args, 0)?, bytes(args, 1)?)))
        }
        "hex.decode" => {
            arity(args, 1, 1)?;
            Ok(Value::bytes(
                hex::decode(encoded_text(args, 0)?)
                    .map_err(|_| anyhow!("hex.decode: invalid hexadecimal input"))
                    .context(InvalidCryptoInput::Argument(0))?,
            ))
        }
        "base64url.encode" => {
            arity(args, 1, 1)?;
            Ok(Value::String(URL_SAFE_NO_PAD.encode(bytes(args, 0)?)))
        }
        "base64url.decode" => {
            arity(args, 1, 1)?;
            let input = encoded_text(args, 0)?;
            Ok(Value::bytes(
                URL_SAFE_NO_PAD
                    .decode(input)
                    .or_else(|_| URL_SAFE.decode(input))
                    .map_err(|_| anyhow!("base64url.decode: invalid Base64url input"))
                    .context(InvalidCryptoInput::Argument(0))?,
            ))
        }
        _ => {
            Err(anyhow!("unsupported cryptographic operation").context(InvalidCryptoConfiguration))
        }
    }
}

fn arity(args: &[Value], min: usize, max: usize) -> Result<()> {
    ensure!(
        (min..=max).contains(&args.len()),
        anyhow!("incorrect cryptographic argument count").context(InvalidCryptoConfiguration)
    );
    Ok(())
}

fn bytes(args: &[Value], index: usize) -> Result<&[u8]> {
    match args.get(index) {
        Some(Value::Bytes(bytes)) => Ok(bytes),
        Some(Value::String(text)) => Ok(text.as_bytes()),
        _ => Err(anyhow!("expected bytes or a UTF-8 string for cryptographic argument")
            .context(InvalidCryptoInput::Argument(index))),
    }
}

fn text(args: &[Value], index: usize) -> Result<&str> {
    match args.get(index) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(anyhow!("expected a string for cryptographic argument")
            .context(InvalidCryptoInput::Argument(index))),
    }
}

/// Encoded text for decoders. Like `base64.decode`, accept bytes as well as strings, but
/// require them to be valid UTF-8 instead of lossily replacing invalid sequences.
fn encoded_text(args: &[Value], index: usize) -> Result<&str> {
    match args.get(index) {
        Some(Value::String(text)) => Ok(text),
        Some(Value::Bytes(bytes)) => std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("expected UTF-8 encoded text for decoding"))
            .context(InvalidCryptoInput::Argument(index)),
        _ => Err(anyhow!("expected a string or bytes for decoding")
            .context(InvalidCryptoInput::Argument(index))),
    }
}

/// Input bytes processed by operations that charge in the adapter.
fn data_length(args: &[Value]) -> usize {
    args.iter()
        .map(|value| match value {
            Value::Bytes(bytes) => bytes.len(),
            Value::String(text) => text.len(),
            _ => 0,
        })
        .fold(0usize, usize::saturating_add)
}

fn extra_work(name: &str, args: &[Value]) -> u64 {
    match name {
        "crypto.ecPublicKey" | "crypto.ecdh" | "crypto.ecdsaSign" | "crypto.ecdsaVerify" => {
            text(args, 0).map(primitives::ec_extra_work).unwrap_or_default()
        }
        "crypto.ed25519PublicKey" | "crypto.ed25519Sign" | "crypto.ed25519Verify" => {
            primitives::ED25519_EXTRA_WORK
        }
        _ => 0,
    }
}

fn positive_integer(args: &[Value], index: usize) -> Result<usize> {
    match args.get(index) {
        Some(Value::Integer(value)) if *value > 0 => usize::try_from(*value)
            .map_err(|_| anyhow!("cryptographic length or count is out of range"))
            .context(InvalidCryptoInput::Argument(index)),
        _ => Err(anyhow!("expected a positive integer for cryptographic length or count")
            .context(InvalidCryptoInput::Argument(index))),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::Router;
    use base64::engine::general_purpose::STANDARD;
    use kingfisher_core::ValidationOutcome;
    use kingfisher_rules::{BetterleaksValidation, Confidence, Rule, Rules};
    use liquid::{Object, model::Value as LiquidValue};
    use reqwest::{Client, StatusCode};
    use serde_json::Value as JsonValue;

    use super::*;
    use crate::validation::{ValidationEngine, betterleaks::validate};

    fn program(source: &str) -> BetterleaksValidation {
        serde_json::from_value(serde_json::json!({"expression": source})).unwrap()
    }

    #[tokio::test]
    async fn crypto_expression_known_answers_preserve_binary_and_legacy_encodings() {
        let config = program(
            r#"
            let alice = hex.decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            let bob = hex.decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
            let shared = crypto.ecdh("X25519", alice, bob);
            let key = hex.decode("00000000000000000000000000000000");
            let nonce = hex.decode("000000000000000000000000");
            let plain = hex.decode("00000000000000000000000000000000");
            let sealed = crypto.aesGcmEncrypt(key, nonce, plain);
            let seed = hex.decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            let sig = crypto.ed25519Sign(seed, bytes(""));
            hex.encode(shared) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" &&
            hex.encode(sealed) == "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf" &&
            crypto.constantTimeEqual(crypto.aesGcmDecrypt(key, nonce, sealed), plain) &&
            hex.encode(crypto.hkdfSha256(hex.decode(repeat("0b", 22)), hex.decode("000102030405060708090a0b0c"), hex.decode("f0f1f2f3f4f5f6f7f8f9"), 42)) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" &&
            hex.encode(crypto.pbkdf2Sha256("password", "salt", 1, 32)) == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b" &&
            hex.encode(crypto.ed25519PublicKey(seed)) == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a" &&
            hex.encode(sig) == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" &&
            crypto.ed25519Verify(crypto.ed25519PublicKey(seed), bytes(""), sig) &&
            !crypto.ed25519Verify(crypto.ed25519PublicKey(seed), "tampered", sig) &&
            crypto.sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" &&
            crypto.sha384("abc") == "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" &&
            crypto.sha512("abc") == "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" &&
            hex.encode(crypto.hmacSha384(hex.decode(repeat("0b", 20)), "Hi There")) == "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" &&
            hex.encode(crypto.hmacSha512(hex.decode(repeat("0b", 20)), "Hi There")) == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" &&
            base64url.encode(hex.decode("ff00fe")) == "_wD-" &&
            crypto.constantTimeEqual(base64url.decode("_wD-"), hex.decode("ff00fe")) &&
            crypto.constantTimeEqual(base64url.decode("_wA="), hex.decode("ff00")) &&
            crypto.constantTimeEqual(hex.decode(bytes("ff00")), base64url.decode(bytes("_wA"))) &&
            len(crypto.randomBytes(32)) == 32
                ? {"result": "valid"} : {"result": "invalid"}
        "#,
        );
        let result = validate(&config, &[], &Object::new(), &Client::new(), true).await;
        assert!(result.valid, "{}", result.body);
    }

    #[test]
    fn crypto_expression_kdf_adapters_reject_repeated_input_undercharge() {
        for (name, args) in [
            (
                "crypto.pbkdf2Sha256",
                vec![
                    Value::String("p".into()),
                    Value::bytes(vec![0; 40 * 1024]),
                    Value::Integer(1),
                    Value::Integer(65_536),
                ],
            ),
            (
                "crypto.hkdfSha256",
                vec![
                    Value::bytes(b"ikm".to_vec()),
                    Value::String("salt".into()),
                    Value::bytes(vec![0; 384 * 1024]),
                    Value::Integer(8160),
                ],
            ),
        ] {
            let error = call(name, &args, &mut WorkBudget::default()).unwrap_err().to_string();
            assert_eq!(error, "cryptographic work budget exceeded", "{name}");
        }
    }

    #[test]
    fn crypto_expression_output_sized_helpers_share_the_program_budget() {
        for (name, args) in [
            (
                "crypto.pbkdf2Sha256",
                vec![
                    Value::String("password".into()),
                    Value::String("salt".into()),
                    Value::Integer(1),
                    Value::Integer(32),
                ],
            ),
            (
                "crypto.hkdfSha256",
                vec![
                    Value::String("ikm".into()),
                    Value::String("salt".into()),
                    Value::String("info".into()),
                    Value::Integer(32),
                ],
            ),
            ("crypto.randomBytes", vec![Value::Integer(32)]),
        ] {
            let mut budget = WorkBudget::default();
            budget.charge(0, primitives::MAX_PROGRAM_WORK - 2_500).unwrap();
            assert_eq!(call(name, &args, &mut budget).unwrap().as_bytes().len(), 32);
            assert!(call(name, &args, &mut budget).unwrap_err().is::<WorkBudgetExceeded>());
        }
    }

    #[tokio::test]
    async fn crypto_expression_ecdsa_supports_both_curves_and_signature_formats() {
        for (curve, length) in [("P-256", 32), ("P-384", 48)] {
            for format in ["p1363", "der"] {
                let config = program(&format!(
                    r#"
                    let private = hex.decode("{}01");
                    let public = crypto.ecPublicKey("{curve}", private);
                    let message = hex.decode("ff0080fe");
                    let signature = crypto.ecdsaSign("{curve}", private, message, "{format}");
                    crypto.ecdsaVerify("{curve}", public, message, signature, "{format}") &&
                    !crypto.ecdsaVerify("{curve}", public, bytes("tampered"), signature, "{format}") &&
                    crypto.ecdsaVerify("{curve}", public, message, crypto.ecdsaSign("{curve}", private, message))
                        ? {{"result": "valid"}} : {{"result": "invalid"}}
                "#,
                    "00".repeat(length - 1)
                ));
                let result = validate(&config, &[], &Object::new(), &Client::new(), true).await;
                assert!(result.valid, "{curve} {format}: {}", result.body);
            }
        }
    }

    #[tokio::test]
    async fn crypto_expression_literal_errors_are_configuration_failures_without_leaking_values() {
        for source in [
            "crypto.aesGcmDecrypt(hex.decode(repeat(\"00\", 16)), hex.decode(repeat(\"00\", 12)), hex.decode(repeat(\"00\", 16)))",
            "crypto.aesGcmEncrypt(bytes(\"sensitive-private-value\"), bytes(\"nonce\"), bytes(\"message\"))",
            "crypto.ecdh(\"P-256\", bytes(\"sensitive-private-value\"), bytes(\"public\"))",
            "crypto.ed25519Sign(bytes(\"sensitive-private-value\"), bytes(\"message\"))",
            "crypto.randomBytes(-1)",
            "crypto.randomBytes(0)",
            "crypto.randomBytes(65537)",
            "crypto.randomBytes(1.5)",
            "crypto.randomBytes(\"12\")",
            "crypto.hkdfSha256(\"ikm\", \"salt\", \"info\", 8161)",
            "crypto.pbkdf2Sha256(\"password\", \"salt\", 0, 32)",
            "crypto.pbkdf2Sha256(finding.secret, \"salt\", 0, 32)",
            "crypto.pbkdf2Sha256(finding.secret, \"salt\", 1000000, 160)",
            "crypto.pbkdf2Sha256(\"password\", \"salt\", 1000001, 32)",
            "crypto.pbkdf2Sha256(\"password\", \"salt\", 1000000, 65536)",
            "crypto.constantTimeEqual(nil, bytes(\"\"))",
            "hex.decode(\"sensitive-private-value\")",
            "base64url.decode(\"sensitive-private-value!\")",
            "hex.decode(hex.decode(\"ff\"))",
            "crypto.randomBytes(12, 1)",
        ] {
            let result =
                validate(&program(source), &[], &Object::new(), &Client::new(), true).await;
            assert_eq!(result.outcome, ValidationOutcome::Unavailable, "{source}");
            assert_eq!(
                result.reason,
                Some(crate::ValidationReason::InvalidConfiguration),
                "{source}"
            );
            assert!(!result.valid);
            assert!(!result.body.contains("sensitive-private-value"));
        }
    }

    #[tokio::test]
    async fn crypto_expression_bad_provider_data_is_a_request_failure() {
        use axum::routing::get;

        let app = Router::new().route(
            "/challenge",
            get(|| async {
                r#"{"challenge":"sensitive-provider-input","length":9223372036854775807}"#
            }),
        );
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let endpoint = format!("http://{}/challenge", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = Client::builder().no_proxy().build().unwrap();
        for (operation, reason) in [
            ("hex.decode(response.body)", crate::ValidationReason::RequestFailed),
            ("crypto.randomBytes(response.json.length)", crate::ValidationReason::RequestFailed),
            (
                "crypto.aesGcmDecrypt(\"0123456789abcdef\", \"short\", response.body)",
                crate::ValidationReason::InvalidConfiguration,
            ),
            (
                "crypto.aesGcmDecrypt(\"0123456789abcdef\", \"0123456789ab\", response.body)",
                crate::ValidationReason::RequestFailed,
            ),
        ] {
            let source = format!("let response = http.get(\"{endpoint}\"); {operation}");
            let result = validate(&program(&source), &[], &Object::new(), &client, true).await;
            assert_eq!(result.outcome, ValidationOutcome::Unavailable, "{operation}");
            assert_eq!(result.reason, Some(reason), "{operation}");
            assert!(!result.valid);
            assert!(!result.body.contains("sensitive-provider-input"));
        }
        server.abort();
    }

    #[tokio::test]
    async fn crypto_expression_budget_exhaustion_matches_yaml_configuration_failure() {
        for source in [
            "len(map(split(repeat(\"a,\", 6000), \",\"), crypto.sha384(\"x\")))",
            "len(map(split(repeat(\"a,\", 6000), \",\"), hex.decode(\"78\")))",
            "len(map(split(repeat(\"a,\", 6000), \",\"), base64url.encode(\"x\")))",
            "len(map(split(repeat(\"a,\", 6000), \",\"), base64url.decode(\"eA\")))",
        ] {
            let result =
                validate(&program(source), &[], &Object::new(), &Client::new(), true).await;
            assert_eq!(result.outcome, ValidationOutcome::Unavailable, "{source}");
            assert_eq!(
                result.reason,
                Some(crate::ValidationReason::InvalidConfiguration),
                "{source}"
            );
            assert!(!result.valid);
            assert!(result.body.contains("cryptographic work budget exceeded"));
        }
    }

    // The server decrypts with RFC 7748 Bob's PUBLIC test private key and verifies
    // with RFC 6979 A.2.5's public key, never a key supplied by the request.
    fn verify_documented_envelope(body: &str) -> bool {
        let verify = || -> Result<()> {
            let json: JsonValue = serde_json::from_str(body)?;
            let field = |name: &str| -> Result<&str> {
                json[name].as_str().ok_or_else(|| anyhow::anyhow!("missing envelope field"))
            };
            ensure!(field("client_id")? == "tenant-fixture-7f51", "wrong client");
            let public_b64 = field("ephemeral_public_key_b64")?;
            let aad = format!("kingfisher-crypto-v1|tenant-fixture-7f51|{public_b64}");
            let signing_text = format!(
                "{aad}|{}|{}|{}",
                field("salt_b64")?,
                field("nonce_b64")?,
                field("sealed_b64")?
            );
            let signing_private =
                STANDARD.decode("ya+p2EW6dRZrXCFXZ7HWk05Qw9s26JsSe4piKxIPZyE=")?;
            let signing_public = primitives::ec_public_key("P-256", &signing_private)?;
            ensure!(
                primitives::ecdsa_verify(
                    "P-256",
                    &signing_public,
                    signing_text.as_bytes(),
                    &STANDARD.decode(field("signature_b64")?)?,
                    "p1363"
                )?,
                "invalid signature"
            );
            let peer_private =
                hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")?;
            let shared = primitives::ecdh("X25519", &peer_private, &STANDARD.decode(public_b64)?)?;
            let salt = STANDARD.decode(field("salt_b64")?)?;
            ensure!(salt.len() == 16, "wrong salt length");
            let key = primitives::hkdf_sha256(&shared, &salt, b"kingfisher-crypto-v1", 32)?;
            let plaintext = primitives::aes_gcm_decrypt(
                &key,
                &STANDARD.decode(field("nonce_b64")?)?,
                &STANDARD.decode(field("sealed_b64")?)?,
                aad.as_bytes(),
            )?;
            ensure!(plaintext.as_slice() == b"{\"operation\":\"identity\"}", "wrong plaintext");
            Ok(())
        };
        verify().is_ok()
    }

    #[test]
    fn documented_crypto_detection_examples_use_native_matching_on_lf_and_crlf() {
        let source = include_str!("../../../examples/rules/cryptographic-auth.yml");
        let rules = Rules::from_paths_and_contents(
            [(Path::new("cryptographic-auth.yml"), source.as_bytes())],
            Confidence::Low,
        )
        .unwrap();
        let database = crate::RulesDatabase::from_rule_collection(rules.clone()).unwrap();
        let scanner = crate::Scanner::new(Arc::new(database));
        for (id, rule) in &rules.rules {
            for example in &rule.examples {
                for ending in ["\n", "\r\n"] {
                    // Native scanning enforces the required nearby client-ID component.
                    let context = if rule.depends_on_rule.is_empty() {
                        String::new()
                    } else {
                        format!("KFC_CLIENT_ID=tenant-fixture-7f51{ending}")
                    };
                    let input = format!("{context}{example}{ending}");
                    let findings = scanner.scan_bytes(input.as_bytes()).unwrap();
                    assert!(findings.iter().any(|finding| finding.rule_id == *id), "{id}");
                }
            }
            for example in &rule.negative_examples {
                for ending in ["\n", "\r\n"] {
                    let context = if rule.depends_on_rule.is_empty() {
                        String::new()
                    } else {
                        format!("KFC_CLIENT_ID=tenant-fixture-7f51{ending}")
                    };
                    let input = format!("{context}{example}{ending}");
                    assert!(
                        scanner
                            .scan_bytes(input.as_bytes())
                            .unwrap()
                            .iter()
                            .all(|finding| finding.rule_id != *id),
                        "{id}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn documented_crypto_rules_authenticate_against_a_local_provider_only() {
        const EXAMPLE: &str = include_str!("../../../examples/rules/cryptographic-auth.yml");
        const ACTIVE: &str = r#"{"credential_status":"active","signature_verified":true}"#;
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let mut globals = Object::new();
        globals.insert(
            "TOKEN".into(),
            LiquidValue::scalar("ya+p2EW6dRZrXCFXZ7HWk05Qw9s26JsSe4piKxIPZyE="),
        );
        globals.insert("CLIENT_ID".into(), LiquidValue::scalar("tenant-fixture-7f51"));
        for (status, response_body, expected_valid) in [
            (StatusCode::OK, ACTIVE, true),
            (StatusCode::UNAUTHORIZED, ACTIVE, false),
            (
                StatusCode::OK,
                r#"{"credential_status":"inactive","signature_verified":true}"#,
                false,
            ),
            (StatusCode::OK, r#"{"credential_status":"active","signature_verified":false}"#, false),
            (StatusCode::OK, r#"{"error":"unrecognized credential"}"#, false),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let verified = calls.clone();
            let app = Router::new().fallback(move |body: String| {
                assert!(
                    verify_documented_envelope(&body),
                    "documented request did not authenticate"
                );
                verified.fetch_add(1, Ordering::SeqCst);
                async move { (status, [("content-type", "application/json")], response_body) }
            });
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let endpoint = format!("http://{}/v1/verify", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let source = EXAMPLE.replace("https://crypto.example.invalid/v1/verify", &endpoint);
            let rules = Rules::from_paths_and_contents(
                [(Path::new("cryptographic-auth.yml"), source.as_bytes())],
                Confidence::Low,
            )
            .unwrap();
            for id in ["custom.crypto-demo.liquid-p256", "custom.crypto-demo.expr-p256"] {
                let syntax = rules.rules[id].clone();
                assert!(syntax.revocation.is_none());
                assert!(syntax.fallbacks.is_empty());
                let rule = Rule::new(syntax);
                let result = ValidationEngine::new(&client, &parser)
                    .allow_internal_ips(true)
                    .validate(&rule, &globals)
                    .await;
                assert_eq!(
                    result.outcome == ValidationOutcome::VerifiedActive,
                    expected_valid,
                    "{id}: {result:?}"
                );
            }
            server.abort();
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
}
