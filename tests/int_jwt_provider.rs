use std::sync::LazyLock;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, errors::ErrorKind};
use kingfisher_scanner::validation::jwt::{
    ValidateOptions, ensure_crypto_provider, validate_jwt_with,
};
use rsa::{
    PrivateKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{EncodePublicKey, LineEnding},
    sha2::{Sha256, Sha384, Sha512},
    signature::{RandomizedSigner, SignatureEncoding},
    traits::PublicKeyParts,
};
use serde_json::{Value, json};

const RSA_ALGORITHMS: [Algorithm; 6] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];
const LEGACY_1024_ALGORITHMS: [Algorithm; 5] =
    [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512, Algorithm::PS256, Algorithm::PS384];
static STRONG_KEY: LazyLock<PrivateKey> = LazyLock::new(|| generate_key(2048));
static LEGACY_KEY: LazyLock<PrivateKey> = LazyLock::new(|| generate_key(1024));
static WRONG_KEY: LazyLock<PrivateKey> = LazyLock::new(|| generate_key(1024));

/// Regression for the CryptoProvider panic (#385), expanded to all six RSA algorithms.
/// Keys and tokens are generated from readable claims; no opaque fixtures are committed.
#[tokio::test]
async fn validate_jwt_with_fallback_key_handles_rs256_without_panicking() {
    assert_fallback_rsa_verification(&STRONG_KEY, &RSA_ALGORITHMS, true).await;
}

/// Existing weak credentials must remain verifiable, not suitable for new signing.
#[tokio::test]
async fn validate_jwt_with_fallback_key_preserves_legacy_rsa_verification() {
    assert_fallback_rsa_verification(&LEGACY_KEY, &LEGACY_1024_ALGORITHMS, false).await;
    // SHA-512 PSS requires 64-byte salt + 64-byte hash + padding, so 1024 bits
    // cannot encode a valid JWT signature. Test PS512's legacy range separately.
    assert!(LEGACY_KEY.pss_sign::<Sha512>(b"too short for PS512").is_err());
}

#[tokio::test]
async fn validate_jwt_preserves_legacy_ps512_verification() {
    assert_fallback_rsa_verification(&generate_key(1536), &[Algorithm::PS512], false).await;
}

#[tokio::test]
async fn validate_jwt_preserves_512_bit_rs256_verification() {
    // Explicit test-only size relaxation; never used for production signing.
    let private_key =
        PrivateKey::new_unchecked(&mut rand::rng(), 512).expect("generate legacy key");
    assert_fallback_rsa_verification(&private_key, &[Algorithm::RS256], false).await;
}

fn initialize_provider() {
    // Deliberately initialize the ordinary AWS provider BEFORE the scanner.
    // Local compatibility must work even if GitHub/GCS/embedding code got here first.
    let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
    ensure_crypto_provider();
}

async fn assert_fallback_rsa_verification(
    private_key: &PrivateKey,
    algorithms: &[Algorithm],
    normal_provider_accepts: bool,
) {
    initialize_provider();
    let claims = valid_claims();
    let wrong_key = decoding_keys(&WRONG_KEY)[0].clone();
    for &algorithm in algorithms {
        let token = sign_rsa(private_key, algorithm, &claims);
        // PEM, raw PKCS#1 DER and JWK modulus/exponent representations.
        for decoding_key in decoding_keys(private_key) {
            assert_eq!(
                decode::<Value>(&token, &decoding_key, &Validation::new(algorithm)).is_ok(),
                normal_provider_accepts,
                "unexpected AWS verification policy for {algorithm:?}"
            );
            let opts = options(decoding_key);
            let (ok, message) = validate_jwt_with(&token, &opts, false, false)
                .await
                .expect("RSA validation should not panic or error");
            assert!(ok, "expected {algorithm:?} verification to succeed: {message}");
            assert!(message.contains("JWT valid via fallback key"), "{message}");

            let mut tampered = claims.clone();
            tampered["sub"] = json!("tampered-subject");
            assert_rejected(&replace_payload(&token, &tampered), &opts).await;
            let (message, signature) = token.rsplit_once('.').expect("JWT signature");
            let mut signature = URL_SAFE_NO_PAD.decode(signature).expect("decode signature");
            signature[0] ^= 1;
            assert_rejected(&format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)), &opts)
                .await;
            assert_rejected(&format!("{message}.!invalid-base64"), &opts).await;
            assert_rejected(&format!("{token}.extra-segment"), &opts).await;
            assert_rejected(message, &opts).await;

            let (_, body) = token.split_once('.').expect("JWT body");
            let different_algorithm =
                if algorithm == Algorithm::RS256 { Algorithm::RS384 } else { Algorithm::RS256 };
            let header = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Header::new(different_algorithm)).expect("serialize header"),
            );
            assert_rejected(&format!("{header}.{body}"), &opts).await;

            let missing_exp = sign_rsa(private_key, algorithm, &json!({ "sub": "mock-subject" }));
            assert_rejected(&missing_exp, &opts).await;
            let empty_aud =
                sign_rsa(private_key, algorithm, &json!({ "exp": 4_102_444_800_i64, "aud": [] }));
            assert_rejected(&empty_aud, &opts).await;
        }
        let public_key = private_key.to_public_key();
        let mut padded_modulus = vec![0; 8];
        padded_modulus.extend_from_slice(&public_key.n().to_be_bytes());
        let mut padded_exponent = vec![0; 16];
        padded_exponent.extend_from_slice(&public_key.e().to_be_bytes());
        let padded_key = DecodingKey::from_rsa_raw_components(&padded_modulus, &padded_exponent);
        assert!(
            validate_jwt_with(&token, &options(padded_key), false, false)
                .await
                .expect("equivalent zero-padded RSA components must validate")
                .0
        );
        assert_rejected(&token, &options(wrong_key.clone())).await;
        assert_rejected(
            &token,
            &options(DecodingKey::from_secret(b"not an RSA key").expect("nonempty HMAC key")),
        )
        .await;
        assert_rejected(&token, &options(DecodingKey::from_rsa_der(b"not DER"))).await;
        assert_rejected(&token, &options(DecodingKey::from_rsa_raw_components(&[0], &[3]))).await;
    }
}

/// The compatibility path must preserve the ordinary provider's exact claims
/// policy, including ignored optional malformed sub and required/empty claims.
#[tokio::test]
async fn legacy_and_strong_rsa_have_identical_claims_policy() {
    initialize_provider();
    let valid = valid_claims();
    let mut cases = vec![("valid", valid.clone())];
    for (name, claim, value) in [
        ("null exp", "exp", Value::Null),
        ("negative exp", "exp", json!(-1)),
        ("zero exp", "exp", json!(0)),
        ("string exp", "exp", json!("4102444800")),
        ("float exp", "exp", json!(4_102_444_800.5_f64)),
        ("huge exp", "exp", json!(u64::MAX)),
        ("empty aud array", "aud", json!([])),
        ("empty aud string", "aud", json!("")),
        ("string aud", "aud", json!("scanner")),
        ("array aud", "aud", json!(["scanner", "another"])),
        ("null aud", "aud", Value::Null),
        ("number aud", "aud", json!(7)),
        ("mixed aud", "aud", json!(["scanner", 7])),
        ("object aud", "aud", json!({})),
        ("null iss", "iss", Value::Null),
        ("empty iss", "iss", json!("")),
        ("whitespace iss", "iss", json!(" ")),
        ("malformed iss", "iss", json!(7)),
        ("null sub", "sub", Value::Null),
        ("number sub", "sub", json!(7)),
        ("boolean sub", "sub", json!(true)),
        ("empty array sub", "sub", json!([])),
        ("array sub", "sub", json!(["unexpected"])),
        ("empty object sub", "sub", json!({})),
        ("object sub", "sub", json!({ "ignored": true })),
        ("null nbf", "nbf", Value::Null),
        ("negative nbf", "nbf", json!(-1)),
        ("future nbf", "nbf", json!(4_102_444_800_i64)),
        ("malformed nbf", "nbf", json!("not a timestamp")),
    ] {
        let mut claims = valid.clone();
        claims[claim] = value;
        cases.push((name, claims));
    }
    for (name, claim) in [("missing exp", "exp"), ("missing nbf", "nbf"), ("missing sub", "sub")] {
        let mut claims = valid.clone();
        claims.as_object_mut().expect("claims object").remove(claim);
        cases.push((name, claims));
    }
    cases.extend([
        ("empty positional claims", json!([])),
        ("positional claims", json!([4_102_444_800_i64, 0, null, null])),
        ("positional empty audience", json!([4_102_444_800_i64, 0, null, []])),
        ("positional string audience", json!([4_102_444_800_i64, 0, null, "scanner"])),
        ("positional array audience", json!([4_102_444_800_i64, 0, "", ["scanner"]])),
        ("non-object claims", json!("not claims")),
    ]);
    for (name, claims) in cases {
        assert_same_claims_outcome(name, &claims).await;
    }
    // Compare immediately around the scanner's no-leeway expiration boundary.
    // A clock tick BETWEEN the two calls is retried, not mistaken for a policy difference.
    for offset in [-1, 0, 1] {
        let mut stable = false;
        for _ in 0..10 {
            let now = chrono::Utc::now().timestamp();
            let claims = json!({ "exp": now + offset });
            let outcomes = claims_outcomes(&claims).await;
            if chrono::Utc::now().timestamp() == now {
                assert_eq!(outcomes.0, outcomes.1, "expiration boundary {offset}");
                stable = true;
                break;
            }
        }
        assert!(stable, "could not compare expiration policy within one clock second");
    }
}

/// jsonwebtoken 12 rejects malformed audiences rather than treating them as absent.
/// The scanner's entry parser and legacy verifier must not turn that into acceptance.
#[tokio::test]
async fn malformed_audiences_are_rejected_for_strong_and_legacy_rsa() {
    initialize_provider();
    for (name, audience) in [
        ("number", json!(7)),
        ("boolean", json!(true)),
        ("mixed array", json!(["scanner", 7])),
        ("object", json!({ "aud": "scanner" })),
        ("nested array", json!([["scanner"]])),
        ("null array member", json!(["scanner", null])),
    ] {
        let mut claims = valid_claims();
        claims["aud"] = audience;
        let token = sign_rsa(&STRONG_KEY, Algorithm::RS256, &claims);
        let error = decode::<Value>(
            &token,
            &decoding_keys(&STRONG_KEY)[0],
            &Validation::new(Algorithm::RS256),
        )
        .expect_err("the ordinary provider must reject malformed audiences");
        assert_eq!(error.kind(), &ErrorKind::InvalidClaimFormat("aud".into()), "{name}");
        let (strong, legacy) = claims_outcomes(&claims).await;
        assert_eq!(strong, legacy, "malformed audience policy differs: {name}");
        for outcome in strong.iter().chain(&legacy) {
            assert!(!matches!(outcome, Ok((true, _))), "{name} accepted: {outcome:?}");
        }
    }
}

/// decode_header is intentionally unchecked; normal decode must reject unsupported
/// critical headers before an RSA signature failure can enter local compatibility.
#[tokio::test]
async fn legacy_and_strong_rsa_have_identical_critical_header_policy() {
    initialize_provider();
    for (name, fields, accepted) in [
        ("ordinary header", json!({}), true),
        ("base64 enabled", json!({ "b64": true }), true),
        ("critical base64 enabled", json!({ "b64": true, "crit": ["b64"] }), true),
        ("unknown noncritical extension", json!({ "unknown": true }), true),
        ("unknown critical extension", json!({ "unknown": true, "crit": ["unknown"] }), false),
        ("missing critical extension", json!({ "crit": ["unknown"] }), false),
        ("empty critical list", json!({ "crit": [] }), false),
        ("duplicate critical extension", json!({ "b64": true, "crit": ["b64", "b64"] }), false),
        ("malformed critical list", json!({ "b64": true, "crit": "b64" }), false),
        ("malformed critical member", json!({ "b64": true, "crit": [7] }), false),
        ("critical base64 missing", json!({ "crit": ["b64"] }), false),
        ("base64 disabled", json!({ "b64": false }), false),
        ("critical base64 disabled", json!({ "b64": false, "crit": ["b64"] }), false),
        ("malformed base64", json!({ "b64": "true" }), false),
        ("null base64", json!({ "b64": null }), false),
    ] {
        let mut header = serde_json::to_value(Header::new(Algorithm::RS256)).expect("RSA header");
        header
            .as_object_mut()
            .expect("header object")
            .extend(fields.as_object().expect("extra header fields").clone());
        let mut outcomes = Vec::new();
        for (private_key, is_strong) in [(&*STRONG_KEY, true), (&*LEGACY_KEY, false)] {
            let token =
                sign_rsa_with_header(private_key, Algorithm::RS256, &valid_claims(), &header);
            let mut representations = Vec::new();
            for decoding_key in decoding_keys(private_key) {
                if is_strong {
                    assert_eq!(
                        decode::<Value>(&token, &decoding_key, &Validation::new(Algorithm::RS256))
                            .is_ok(),
                        accepted,
                        "unexpected ordinary header policy: {name}",
                    );
                }
                let outcome = validate_jwt_with(&token, &options(decoding_key), false, false)
                    .await
                    .map_err(|error| error.to_string());
                assert_eq!(
                    matches!(&outcome, Ok((true, _))),
                    accepted,
                    "unexpected scanner header policy: {name}: {outcome:?}",
                );
                representations.push(outcome);
            }
            outcomes.push(representations);
        }
        assert_eq!(outcomes[0], outcomes[1], "critical header policy differs: {name}");
    }
}

#[tokio::test]
async fn legacy_pss_still_requires_digest_length_salt() {
    initialize_provider();
    let valid_token = sign_rsa(&LEGACY_KEY, Algorithm::PS256, &valid_claims());
    let (message, _) = valid_token.rsplit_once('.').expect("JWT signature");
    let signing_key = rsa::pss::SigningKey::<Sha256>::new_with_salt_len(LEGACY_KEY.clone(), 0);
    let signature = signing_key.sign_with_rng(&mut rand::rng(), message.as_bytes());
    let token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_vec()));
    for key in decoding_keys(&LEGACY_KEY) {
        assert_rejected(&token, &options(key)).await;
    }
}

async fn assert_same_claims_outcome(name: &str, claims: &Value) {
    let outcomes = claims_outcomes(claims).await;
    assert_eq!(outcomes.0, outcomes.1, "claims policy differs: {name}: {claims}");
}

type Outcome = Result<(bool, String), String>;

async fn claims_outcomes(claims: &Value) -> (Vec<Outcome>, Vec<Outcome>) {
    let mut outcomes = Vec::new();
    for key in [&*STRONG_KEY, &*LEGACY_KEY] {
        let token = sign_rsa(key, Algorithm::RS256, claims);
        let mut representations = Vec::new();
        for decoding_key in decoding_keys(key) {
            representations.push(
                validate_jwt_with(&token, &options(decoding_key), false, false)
                    .await
                    .map_err(|error| error.to_string()),
            );
        }
        outcomes.push(representations);
    }
    (outcomes.remove(0), outcomes.remove(0))
}

async fn assert_rejected(token: &str, opts: &ValidateOptions) {
    if let Ok((valid, message)) = validate_jwt_with(token, opts, false, false).await {
        assert!(!valid, "invalid token accepted: {message}");
    }
}

fn valid_claims() -> Value {
    // Omitting iss selects the fallback-key path; year 2100 keeps valid fixtures stable.
    json!({ "sub": "mock-subject", "nbf": 0, "exp": 4_102_444_800_i64 })
}

fn generate_key(bits: usize) -> PrivateKey {
    PrivateKey::new(&mut rand::rng(), bits).expect("generate ephemeral RSA key")
}

fn options(key: DecodingKey) -> ValidateOptions {
    ValidateOptions { allow_alg_none: false, fallback_decoding_key: Some(key) }
}

fn decoding_keys(private_key: &PrivateKey) -> [DecodingKey; 3] {
    let public_key = private_key.to_public_key();
    let pem = public_key.to_public_key_pem(LineEnding::LF).expect("encode public key");
    let der = public_key.to_pkcs1_der().expect("encode PKCS#1 public key");
    let exponent = public_key.e().to_be_bytes();
    let exponent = exponent.iter().copied().skip_while(|byte| *byte == 0).collect::<Vec<_>>();
    [
        DecodingKey::from_rsa_pem(pem.as_bytes()).expect("valid RSA key"),
        DecodingKey::from_rsa_der(der.as_bytes()),
        DecodingKey::from_rsa_raw_components(&public_key.n().to_be_bytes(), &exponent),
    ]
}

fn replace_payload(token: &str, claims: &Value) -> String {
    let (header, _) = token.split_once('.').expect("JWT header");
    let (_, signature) = token.rsplit_once('.').expect("JWT signature");
    format!(
        "{header}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize claims"))
    )
}

fn sign_rsa(private_key: &PrivateKey, algorithm: Algorithm, claims: &Value) -> String {
    let header = serde_json::to_value(Header::new(algorithm)).expect("serialize RSA header");
    sign_rsa_with_header(private_key, algorithm, claims, &header)
}

fn sign_rsa_with_header(
    private_key: &PrivateKey,
    algorithm: Algorithm,
    claims: &Value,
    header: &Value,
) -> String {
    // AWS-LC cannot generate weak signatures; use current RSA with explicit RNG.
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).expect("serialize RSA header"));
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("serialize claims"));
    let message = format!("{header}.{payload}");
    let mut rng = rand::rng();
    let signature = match algorithm {
        Algorithm::RS256 => {
            private_key.pkcs1v15_sign_with_rng::<Sha256, _>(&mut rng, message.as_bytes())
        }
        Algorithm::RS384 => {
            private_key.pkcs1v15_sign_with_rng::<Sha384, _>(&mut rng, message.as_bytes())
        }
        Algorithm::RS512 => {
            private_key.pkcs1v15_sign_with_rng::<Sha512, _>(&mut rng, message.as_bytes())
        }
        Algorithm::PS256 => {
            private_key.pss_sign_with_rng::<Sha256, _>(&mut rng, message.as_bytes())
        }
        Algorithm::PS384 => {
            private_key.pss_sign_with_rng::<Sha384, _>(&mut rng, message.as_bytes())
        }
        Algorithm::PS512 => {
            private_key.pss_sign_with_rng::<Sha512, _>(&mut rng, message.as_bytes())
        }
        _ => panic!("not an RSA algorithm"),
    }
    .expect("sign RSA token");
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
}
