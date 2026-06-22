use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use kingfisher_scanner::validation::jwt::{
    ValidateOptions, ensure_crypto_provider, validate_jwt_with,
};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::pkcs8::EncodePublicKey;
use rsa::rand_core::OsRng;

/// Regression test for the `jsonwebtoken` CryptoProvider panic (see issue #385).
///
/// It exercises the asymmetric (RS256) verification path through `validate_jwt_with`
/// via the fallback decoding key. A throwaway RSA keypair is generated at runtime and
/// the token is signed from readable claims, so no opaque token blobs or key material
/// are committed to the repository.
#[tokio::test]
async fn validate_jwt_with_fallback_key_handles_rs256_without_panicking() {
    ensure_crypto_provider();

    // Generate an ephemeral RSA keypair for this test run only.
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).expect("encode private key");
    let public_pem =
        private_key.to_public_key().to_public_key_pem(LineEnding::LF).expect("encode public key");

    // Omitting `iss` routes validation through the fallback-key path (the one that panicked).
    let claims = serde_json::json!({
        "sub": "mock-subject",
        "nbf": 0,
        "exp": 4_102_444_800_i64, // year 2100, so the token never expires during CI
    });
    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("valid encoding key"),
    )
    .expect("sign RS256 token");

    let opts = ValidateOptions {
        allow_alg_none: false,
        fallback_decoding_key: Some(
            DecodingKey::from_rsa_pem(public_pem.as_bytes()).expect("valid RSA key"),
        ),
    };

    let (ok, message) = validate_jwt_with(&token, &opts, false, false)
        .await
        .expect("RS256 validation should not panic or error");

    assert!(ok, "expected JWT signature verification to succeed: {message}");
    assert!(
        message.contains("JWT valid via fallback key"),
        "expected the fallback-key verification path: {message}"
    );
}
