use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Result, anyhow};
use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::{Client, StatusCode, Url};
use rsa::pkcs8::{
    AlgorithmIdentifierRef, ObjectIdentifier, PrivateKeyInfoRef, SecretDocument,
    der::{Decode, asn1::OctetStringRef},
};
use sha1::{Digest, Sha1};

use super::http_validation as httpvalidation;
use super::{
    Cache, CachedResponse, VALIDATION_CACHE_SECONDS, ValidationResponseBody, validation_body,
};

pub fn generate_coinbase_cache_key(cred_name: &str, private_key: &str) -> String {
    let mut h = Sha1::new();
    h.update(cred_name.as_bytes());
    h.update(b"\0");
    h.update(private_key.as_bytes());
    format!("COINBASE:{}", hex::encode(h.finalize()))
}

pub async fn validate_cdp_api_key(
    cred_name: &str,
    private_key_pem: &str,
    client: &Client,
    parser: &liquid::Parser,
    cache: &Cache,
) -> Result<(bool, ValidationResponseBody)> {
    let cache_key = generate_coinbase_cache_key(cred_name, private_key_pem);
    if let Some(entry) = cache.get(&cache_key) {
        let c = entry.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            return Ok((c.is_valid, c.body.clone()));
        }
    }

    let jwt = build_jwt("GET", "api.coinbase.com", "/v2/user", cred_name, private_key_pem)?;

    let url = Url::parse("https://api.coinbase.com/v2/user")?;
    let headers = BTreeMap::from([("Authorization".to_string(), format!("Bearer {}", jwt))]);
    let rb = httpvalidation::build_request_builder(
        client,
        "GET",
        &url,
        &headers,
        &None,
        Duration::from_secs(10),
        parser,
        &liquid::Object::new(),
    )
    .map_err(|e| anyhow!(e))?;
    let resp =
        httpvalidation::retry_request(rb, 1, Duration::from_millis(500), Duration::from_secs(2))
            .await?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let ok = status == StatusCode::OK;
    let msg = validation_body::from_string(body);

    cache.insert(cache_key.clone(), CachedResponse::new(msg.clone(), status, ok));

    Ok((ok, msg))
}

const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

fn p256_key_from_private_key_info(key: &PrivateKeyInfoRef<'_>) -> Option<EcdsaKeyPair> {
    // Keep key validation/signing in AWS-LC and zeroize the temporary private DER.
    let normalized = SecretDocument::encode_msg(key).ok()?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, normalized.as_bytes()).ok()
}

fn p256_key_from_sec1(der: &[u8]) -> Option<EcdsaKeyPair> {
    // The generic AWS-LC DER importer auto-detects PKCS#8 too. Put only the supplied
    // SEC1 bytes inside a strict PKCS#8 wrapper so a mislabeled container is rejected.
    let algorithm =
        AlgorithmIdentifierRef { oid: EC_PUBLIC_KEY, parameters: Some((&PRIME256V1).into()) };
    let key = PrivateKeyInfoRef::new(algorithm, OctetStringRef::new(der).ok()?);
    p256_key_from_private_key_info(&key)
}

fn p256_key_from_pkcs8(der: &[u8]) -> Option<EcdsaKeyPair> {
    let mut key = PrivateKeyInfoRef::from_der(der).ok()?;
    key.algorithm.assert_oids(EC_PUBLIC_KEY, PRIME256V1).ok()?;
    // The previous RustCrypto importer accepted PKCS#8 v1/v2 and used the inner
    // SEC1 key, ignoring the optional outer public key. AWS-LC's EC importer only
    // accepts v1, so normalize the validated wrapper with the retained DER codec.
    key.public_key = None;
    p256_key_from_private_key_info(&key)
}

fn build_jwt(
    method: &str,
    host: &str,
    endpoint: &str,
    key_name: &str,
    pem: &str,
) -> Result<String> {
    let pem =
        pem.replace("\r\n", "\n").replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r", "\n");

    let nonce: [u8; 16] = rand::random();

    // Reuse the workspace's existing crypto provider for both supported key
    // families. Keep SEC1/PKCS8 PEM labels and the P-256 curve restriction.
    let ecdsa_key = pem::parse(&pem).ok().and_then(|pem| match pem.tag() {
        "EC PRIVATE KEY" => p256_key_from_sec1(pem.contents()),
        "PRIVATE KEY" => p256_key_from_pkcs8(pem.contents()),
        _ => None,
    });
    match ecdsa_key {
        Some(signing_key) => {
            let header = serde_json::json!({
                "typ": "JWT",
                "alg": "ES256",
                "kid": key_name,
                "nonce": hex::encode(nonce),
            });
            let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

            let now = Utc::now().timestamp();
            let claims = serde_json::json!({
                "sub": key_name,
                "iss": "cdp",
                "nbf": now,
                "exp": now + 120,
                "uri": format!("{} {}{}", method, host, endpoint),
            });
            let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());

            let signing_input = format!("{header_b64}.{claims_b64}");
            let sig = signing_key
                .sign(&SystemRandom::new(), signing_input.as_bytes())
                .map_err(|_| anyhow!("failed to sign Coinbase JWT"))?;
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

            Ok(format!("{signing_input}.{sig_b64}"))
        }
        _ => {
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(pem.as_bytes())
                .map_err(|e| anyhow!("invalid base64 key: {e}"))?;
            let signing_key = match key_bytes.len() {
                32 => Ed25519KeyPair::from_seed_unchecked(&key_bytes),
                // Coinbase's 64-byte form is seed || public key. Do not silently
                // ignore a corrupted or mismatched public half.
                64 => Ed25519KeyPair::from_seed_and_public_key(&key_bytes[..32], &key_bytes[32..]),
                _ => return Err(anyhow!("invalid Ed25519 key length")),
            }
            .map_err(|e| anyhow!("invalid Ed25519 key: {e}"))?;

            let header = serde_json::json!({
                "typ": "JWT",
                "alg": "EdDSA",
                "kid": key_name,
                "nonce": hex::encode(nonce),
            });
            let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string());

            let now = Utc::now().timestamp();
            let claims = serde_json::json!({
                "sub": key_name,
                "iss": "cdp",
                "nbf": now,
                "exp": now + 120,
                "uri": format!("{} {}{}", method, host, endpoint),
            });
            let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string());

            let signing_input = format!("{header_b64}.{claims_b64}");
            let sig = signing_key.sign(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());
            Ok(format!("{signing_input}.{sig_b64}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::{
        encoding::AsDer,
        signature::{
            self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair,
            Ed25519KeyPair, KeyPair, UnparsedPublicKey,
        },
    };
    use rsa::pkcs8::{
        Version,
        der::{
            Encode,
            asn1::{AnyRef, BitStringRef},
        },
    };

    use super::*;

    const KEY_NAME: &str = "organizations/test/apiKeys/fixture";

    fn assert_jwt_contract(token: &str, algorithm: &str) -> (String, Vec<u8>) {
        let parts: Vec<_> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["alg"], algorithm);
        assert_eq!(header["kid"], KEY_NAME);
        let nonce = header["nonce"].as_str().unwrap();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["sub"], KEY_NAME);
        assert_eq!(claims["iss"], "cdp");
        assert_eq!(claims["uri"], "GET api.coinbase.com/v2/user");
        let nbf = claims["nbf"].as_i64().unwrap();
        assert_eq!(claims["exp"].as_i64().unwrap() - nbf, 120);
        assert!((Utc::now().timestamp() - nbf).abs() <= 10);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert_eq!(signature.len(), 64, "JWT signatures must use fixed-width r||s/Ed25519");
        (format!("{}.{}", parts[0], parts[1]), signature)
    }

    fn p256_fixture() -> EcdsaKeyPair {
        // Public NIST P-256 generator and scalar one; test material only.
        let mut private = [0u8; 32];
        private[31] = 1;
        let public = hex::decode(concat!(
            "04",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
        ))
        .unwrap();
        EcdsaKeyPair::from_private_key_and_public_key(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &private,
            &public,
        )
        .unwrap()
    }

    fn pkcs8_v2_fixture(key: &EcdsaKeyPair, outer_public_key: &[u8]) -> Vec<u8> {
        let pkcs8 = key.to_pkcs8v1().unwrap();
        let mut wrapper = PrivateKeyInfoRef::from_der(pkcs8.as_ref()).unwrap();
        wrapper.public_key = Some(BitStringRef::from_bytes(outer_public_key).unwrap());
        let encoded = wrapper.to_der().unwrap();
        assert_eq!(PrivateKeyInfoRef::from_der(&encoded).unwrap().version(), Version::V2);
        encoded
    }

    #[test]
    fn coinbase_es256_preserves_sec1_pkcs8_and_newline_formats() {
        let key = p256_fixture();
        let sec1 = key.private_key().as_der().unwrap();
        let pkcs8 = key.to_pkcs8v1().unwrap();
        let pkcs8_v2 = pkcs8_v2_fixture(&key, key.public_key().as_ref());
        for pem in [
            pem::encode(&pem::Pem::new("EC PRIVATE KEY", sec1.as_ref())),
            pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref())),
            pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_v2)),
        ] {
            for value in [
                pem.clone(),
                pem.replace("\r\n", "\n"),
                pem.replace("\r\n", "\\n"),
                pem.replace("\r\n", "\\r\\n"),
                pem.replace("\r\n", "\r"),
            ] {
                let token =
                    build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &value).unwrap();
                let (message, signature) = assert_jwt_contract(&token, "ES256");
                let verifier =
                    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref());
                verifier.verify(message.as_bytes(), &signature).unwrap();
                assert!(verifier.verify(b"changed message", &signature).is_err());
            }
        }
    }

    #[test]
    fn coinbase_pkcs8_v2_preserves_ignored_outer_public_key() {
        let key = p256_fixture();
        let other = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        // Legacy p256 used only the inner SEC1 key, not the redundant outer bit
        // string: even a mismatched point or a non-point byte string was ignored.
        for outer_public in [other.public_key().as_ref(), &[0u8]] {
            let encoded = pkcs8_v2_fixture(&key, outer_public);
            let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", encoded));
            let token = build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &pem).unwrap();
            let (message, signature) = assert_jwt_contract(&token, "ES256");
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key.public_key().as_ref())
                .verify(message.as_bytes(), &signature)
                .unwrap();
            assert!(
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, other.public_key().as_ref())
                    .verify(message.as_bytes(), &signature)
                    .is_err()
            );
        }
    }

    #[test]
    fn coinbase_pkcs8_versions_reject_wrong_key_family_and_invalid_inner_key() {
        const P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
        let key = p256_fixture();
        let pkcs8_v1 = key.to_pkcs8v1().unwrap();
        let pkcs8_v2 = pkcs8_v2_fixture(&key, key.public_key().as_ref());
        for encoded in [pkcs8_v1.as_ref(), pkcs8_v2.as_slice()] {
            let valid = PrivateKeyInfoRef::from_der(encoded).unwrap();
            let mut wrong_algorithm = valid.clone();
            wrong_algorithm.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
            let mut wrong_curve = valid.clone();
            wrong_curve.algorithm.parameters = Some((&P384).into());
            let mut missing_curve = valid.clone();
            missing_curve.algorithm.parameters = None;
            let mut null_curve = valid.clone();
            null_curve.algorithm.parameters = Some(AnyRef::NULL);
            let mut invalid_inner = valid.clone();
            invalid_inner.private_key = OctetStringRef::new(b"not an ECPrivateKey").unwrap();
            let mut nested_pkcs8 = valid;
            nested_pkcs8.private_key = OctetStringRef::new(pkcs8_v1.as_ref()).unwrap();
            for (case, wrapper) in [
                ("wrong algorithm", wrong_algorithm),
                ("wrong curve", wrong_curve),
                ("missing curve", missing_curve),
                ("null curve", null_curve),
                ("invalid inner key", invalid_inner),
                ("nested PKCS#8 instead of SEC1", nested_pkcs8),
            ] {
                let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", wrapper.to_der().unwrap()));
                assert!(
                    build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &pem).is_err(),
                    "accepted {case}"
                );
            }
        }
        let p384 = EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let encoded = pkcs8_v2_fixture(&p384, p384.public_key().as_ref());
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", encoded));
        assert!(build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &pem).is_err());
    }

    #[test]
    fn coinbase_pkcs8_rejects_malformed_versions_public_key_and_der() {
        let key = p256_fixture();
        let pkcs8_v1 = key.to_pkcs8v1().unwrap();
        let pkcs8_v2 = pkcs8_v2_fixture(&key, key.public_key().as_ref());
        let v1_version = pkcs8_v1.as_ref().windows(3).position(|b| b == [2, 1, 0]).unwrap();
        let v2_version = pkcs8_v2.windows(3).position(|b| b == [2, 1, 1]).unwrap();
        let mut v2_without_public = pkcs8_v1.as_ref().to_vec();
        v2_without_public[v1_version + 2] = 1;
        let mut v1_with_public = pkcs8_v2.clone();
        v1_with_public[v2_version + 2] = 0;
        let mut unsupported_version = pkcs8_v2.clone();
        unsupported_version[v2_version + 2] = 2;
        let mut invalid_bit_string = pkcs8_v2.clone();
        let unused_bits = invalid_bit_string.len() - key.public_key().as_ref().len() - 1;
        assert_eq!(invalid_bit_string[unused_bits], 0);
        invalid_bit_string[unused_bits] = 8;
        let mut trailing_data = pkcs8_v2.clone();
        trailing_data.push(0);
        for (case, encoded) in [
            ("v2 without public key", v2_without_public),
            ("v1 with public key", v1_with_public),
            ("unsupported version", unsupported_version),
            ("invalid public BIT STRING", invalid_bit_string),
            ("truncated public key", pkcs8_v2[..pkcs8_v2.len() - 1].to_vec()),
            ("trailing DER data", trailing_data),
        ] {
            let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", encoded));
            assert!(
                build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &pem).is_err(),
                "accepted {case}"
            );
        }
    }

    #[test]
    fn coinbase_eddsa_preserves_seed_and_verified_keypair_formats() {
        // RFC 8032 section 7.1 first test vector (public test key).
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let key = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let mut keypair = seed.clone();
        keypair.extend_from_slice(key.public_key().as_ref());
        for bytes in [&seed, &keypair] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            let token =
                build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &encoded).unwrap();
            let (message, signature) = assert_jwt_contract(&token, "EdDSA");
            let verifier = UnparsedPublicKey::new(&signature::ED25519, key.public_key().as_ref());
            verifier.verify(message.as_bytes(), &signature).unwrap();
            assert!(verifier.verify(b"changed message", &signature).is_err());
        }
        keypair[63] ^= 1;
        let inconsistent = base64::engine::general_purpose::STANDARD.encode(keypair);
        assert!(build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &inconsistent).is_err());
    }

    #[test]
    fn coinbase_rejects_invalid_lengths_wrong_curve_and_mislabeled_pem() {
        for length in [0, 31, 33, 63, 65] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(vec![1u8; length]);
            assert!(build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &encoded).is_err());
        }
        let key = EcdsaKeyPair::generate(&signature::ECDSA_P384_SHA384_FIXED_SIGNING).unwrap();
        let key = key.to_pkcs8v1().unwrap();
        let wrong_curve = pem::encode(&pem::Pem::new("PRIVATE KEY", key.as_ref()));
        let key = p256_fixture();
        let pkcs8_v1 = key.to_pkcs8v1().unwrap();
        let wrong_label = pem::encode(&pem::Pem::new("PUBLIC KEY", pkcs8_v1.as_ref()));
        for value in [wrong_curve.as_str(), wrong_label.as_str(), "not base64!"] {
            assert!(build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, value).is_err());
        }
        let pkcs8_v2 = pkcs8_v2_fixture(&key, key.public_key().as_ref());
        let sec1 = key.private_key().as_der().unwrap();
        for (case, label, der) in [
            ("PKCS#8 v1", "EC PRIVATE KEY", pkcs8_v1.as_ref()),
            ("PKCS#8 v2", "EC PRIVATE KEY", pkcs8_v2.as_slice()),
            ("SEC1", "PRIVATE KEY", sec1.as_ref()),
        ] {
            let pem = pem::encode(&pem::Pem::new(label, der));
            assert!(
                build_jwt("GET", "api.coinbase.com", "/v2/user", KEY_NAME, &pem).is_err(),
                "accepted {case} with incorrect {label} label"
            );
        }
    }
}
