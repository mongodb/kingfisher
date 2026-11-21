//! Shared, byte-oriented cryptographic primitives for rule expressions and Liquid filters.
//!
//! P-256/P-384 private keys are fixed-width big-endian scalars (32/48 bytes), and public
//! keys are SEC1 uncompressed points (65/97 bytes). Unencrypted RFC5915 `EC PRIVATE KEY`
//! and PKCS#8 `PRIVATE KEY` PEM private keys, and SPKI `PUBLIC KEY` PEM public keys, are
//! also accepted for these curves. X25519 uses only raw 32-byte keys. Ed25519 private
//! inputs are raw 32-byte seeds. No function includes input data or backend errors in
//! diagnostics. This module is an internal integration surface, not a stable crypto API.

use std::{borrow::Cow, num::NonZeroU32};

use anyhow::{Context, Result, anyhow, bail, ensure};
use aws_lc_rs::{
    aead, agreement, constant_time, hkdf, pbkdf2,
    rand::{SecureRandom, SystemRandom},
    signature::{self, KeyPair},
};
use zeroize::Zeroizing;

const MAX_OUTPUT_LENGTH: usize = 65_536;
const MAX_HKDF_LENGTH: usize = 255 * 32;
const MAX_PBKDF2_ITERATIONS: u32 = 1_000_000;
const MAX_PBKDF2_WORK: u64 = 4_000_000;
/// Fixed charge for any budgeted operation, so loops of cheap calls are also bounded.
const OPERATION_WORK: u64 = 1_000;
/// Total work for one expression program or one Liquid request attempt: one maximal
/// PBKDF2 derivation plus roughly a thousand inexpensive operations.
pub const MAX_PROGRAM_WORK: u64 = MAX_PBKDF2_WORK + 1_000 * OPERATION_WORK;
/// Extra units for the Ed25519 helpers, including the cost of signature verification.
pub const ED25519_EXTRA_WORK: u64 = 9_000;

/// The cumulative work limit was reached before running a cryptographic operation.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("cryptographic work budget exceeded")]
pub struct WorkBudgetExceeded;

/// Identifies the inputs responsible for a failed check, without retaining their values.
/// Positions follow the shared primitive and expression argument order.
#[doc(hidden)]
#[derive(Debug, thiserror::Error)]
#[error("invalid cryptographic input")]
pub enum InvalidCryptoInput {
    Argument(usize),
    Arguments(&'static [usize]),
    Combined,
}

/// Extra units for elliptic-curve operations. P-384's scalar arithmetic is more
/// expensive than the other curves and must be weighted accordingly.
pub fn ec_extra_work(curve: &str) -> u64 {
    match curve {
        "P-256" => 9_000,
        "P-384" => 24_000,
        "X25519" => 4_000,
        _ => 0,
    }
}

/// Cumulative CPU budget for cryptographic helpers within one program or request.
///
/// Per-call limits alone do not bound work: expression `map`/`filter` and Liquid `for`
/// loops can repeat an expensive call arbitrarily often on a validation worker.
#[derive(Debug, Default)]
pub struct WorkBudget {
    used: u64,
}

impl WorkBudget {
    /// Charge one operation over `data_len` input/output bytes plus `extra` work units
    /// (including curve arithmetic, KDF blocks and repeated-input work). Fails closed once
    /// the budget is exhausted.
    pub fn charge(&mut self, data_len: usize, extra: u64) -> Result<()> {
        let units = OPERATION_WORK.saturating_add(data_len as u64 / 16).saturating_add(extra);
        let used = self.used.saturating_add(units);
        ensure!(used <= MAX_PROGRAM_WORK, WorkBudgetExceeded);
        self.used = used;
        Ok(())
    }
}

/// PBKDF2 work units (`iterations * ceil(length / 32)`), saturating for out-of-range input.
pub fn pbkdf2_work(iterations: u64, length: u64) -> u64 {
    iterations.saturating_mul(length.div_ceil(32))
}

/// Additional byte-processing work when an input is hashed once per SHA-256 output block.
/// The caller already charges the first copy in `WorkBudget::charge`'s input byte count.
fn repeated_input_work(input_length: u64, length: u64) -> u64 {
    input_length.saturating_mul(length.div_ceil(32).saturating_sub(1)).div_ceil(16)
}

/// Extra HKDF work beyond charging input/output bytes once. HKDF expansion hashes the
/// complete `info` for every output block; a long info string must not hide that multiplier.
pub fn hkdf_extra_work(info_length: u64, length: u64) -> u64 {
    repeated_input_work(info_length, length)
}

/// Extra PBKDF2 work beyond charging input/output bytes once. The complete salt is hashed
/// for each output block (not each iteration); normal short salts retain the supported
/// `iterations * ceil(length / 32) <= 4,000,000` range.
pub fn pbkdf2_extra_work(salt_length: u64, iterations: u64, length: u64) -> u64 {
    pbkdf2_work(iterations, length).saturating_add(repeated_input_work(salt_length, length))
}

#[derive(Clone, Copy)]
enum Curve {
    P256,
    P384,
    X25519,
}

impl Curve {
    fn parse(curve: &str) -> Result<Self> {
        match curve {
            "P-256" => Ok(Self::P256),
            "P-384" => Ok(Self::P384),
            "X25519" => Ok(Self::X25519),
            _ => bail!("unsupported elliptic curve"),
        }
    }

    fn agreement_algorithm(self) -> &'static agreement::Algorithm {
        match self {
            Self::P256 => &agreement::ECDH_P256,
            Self::P384 => &agreement::ECDH_P384,
            Self::X25519 => &agreement::X25519,
        }
    }

    fn private_length(self) -> usize {
        match self {
            Self::P256 | Self::X25519 => 32,
            Self::P384 => 48,
        }
    }

    fn public_length(self) -> usize {
        match self {
            Self::P256 => 65,
            Self::P384 => 97,
            Self::X25519 => 32,
        }
    }

    fn is_nist(self) -> bool {
        !matches!(self, Self::X25519)
    }
}

fn parse_key_pem(key: &[u8], markers: &[&[u8]], error: &'static str) -> Result<pem::Pem> {
    // Select the first relevant block before decoding. For example, OpenSSL can
    // emit EC PARAMETERS before EC PRIVATE KEY. Unrelated blocks need no DER buffer.
    let start = markers
        .iter()
        .filter_map(|marker| key.windows(marker.len()).position(|window| window == *marker))
        .min()
        .ok_or_else(|| anyhow!(error))?;
    pem::parse(&key[start..]).map_err(|_| anyhow!(error))
}

fn private_pem_der(key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let pem = parse_key_pem(
        key,
        &[b"-----BEGIN EC PRIVATE KEY-----", b"-----BEGIN PRIVATE KEY-----"],
        "invalid EC private key",
    )?;
    let valid_tag = matches!(pem.tag(), "EC PRIVATE KEY" | "PRIVATE KEY");
    let der = Zeroizing::new(pem.into_contents());
    ensure!(valid_tag, "invalid EC private key");
    Ok(der)
}

fn agreement_private_key(curve: Curve, key: &[u8]) -> Result<agreement::PrivateKey> {
    let algorithm = curve.agreement_algorithm();
    if key.len() == curve.private_length() {
        agreement::PrivateKey::from_private_key(algorithm, key)
    } else if curve.is_nist() {
        agreement::PrivateKey::from_private_key_der(algorithm, &private_pem_der(key)?)
    } else {
        bail!("invalid X25519 private key");
    }
    .map_err(|_| anyhow!("invalid EC private key"))
}

fn public_key_bytes(curve: Curve, key: &[u8]) -> Result<Cow<'_, [u8]>> {
    if key.len() == curve.public_length() {
        ensure!(!curve.is_nist() || key[0] == 4, "invalid EC public key");
        return Ok(Cow::Borrowed(key));
    }
    ensure!(curve.is_nist(), "invalid X25519 public key");
    let pem = parse_key_pem(key, &[b"-----BEGIN PUBLIC KEY-----"], "invalid EC public key")?;
    ensure!(pem.tag() == "PUBLIC KEY", "invalid EC public key");
    Ok(Cow::Owned(pem.into_contents()))
}

/// Derive a SEC1 uncompressed EC public key, or a raw X25519 public key.
pub fn ec_public_key(curve: &str, private_key: &[u8]) -> Result<Vec<u8>> {
    agreement_private_key(
        Curve::parse(curve).context(InvalidCryptoInput::Argument(0))?,
        private_key,
    )
    .context(InvalidCryptoInput::Arguments(&[0, 1]))?
    .compute_public_key()
    .map(|key| key.as_ref().to_vec())
    .map_err(|_| anyhow!("EC public key derivation failed"))
}

/// Compute the raw ECDH shared secret. Apply an appropriate KDF before using it as a key.
pub fn ecdh(curve: &str, private_key: &[u8], peer_public_key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let curve = Curve::parse(curve).context(InvalidCryptoInput::Argument(0))?;
    let private_key = agreement_private_key(curve, private_key)
        .context(InvalidCryptoInput::Arguments(&[0, 1]))?;
    let peer =
        public_key_bytes(curve, peer_public_key).context(InvalidCryptoInput::Arguments(&[0, 2]))?;
    let peer = agreement::UnparsedPublicKey::new(curve.agreement_algorithm(), peer.as_ref());
    agreement::agree(&private_key, peer, anyhow!("ECDH key agreement failed"), |secret| {
        Ok(Zeroizing::new(secret.to_vec()))
    })
    .context(InvalidCryptoInput::Combined)
}

fn ecdsa_algorithms(
    curve: &str,
    format: &str,
    format_argument: usize,
) -> Result<(
    &'static signature::EcdsaSigningAlgorithm,
    &'static signature::EcdsaVerificationAlgorithm,
)> {
    match (Curve::parse(curve).context(InvalidCryptoInput::Argument(0))?, format) {
        (Curve::P256, "p1363") => {
            Ok((&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &signature::ECDSA_P256_SHA256_FIXED))
        }
        (Curve::P256, "der") => {
            Ok((&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &signature::ECDSA_P256_SHA256_ASN1))
        }
        (Curve::P384, "p1363") => {
            Ok((&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &signature::ECDSA_P384_SHA384_FIXED))
        }
        (Curve::P384, "der") => {
            Ok((&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &signature::ECDSA_P384_SHA384_ASN1))
        }
        (Curve::X25519, _) => {
            Err(anyhow!("X25519 does not support ECDSA").context(InvalidCryptoInput::Argument(0)))
        }
        _ => Err(anyhow!("unsupported ECDSA signature format")
            .context(InvalidCryptoInput::Argument(format_argument))),
    }
}

/// Sign a message using ECDSA with SHA-256 (P-256) or SHA-384 (P-384).
/// `format` is `p1363` (fixed-width r || s) or `der` (ASN.1).
pub fn ecdsa_sign(
    curve: &str,
    private_key: &[u8],
    message: &[u8],
    format: &str,
) -> Result<Vec<u8>> {
    let (algorithm, _) = ecdsa_algorithms(curve, format, 3)?;
    let curve_id = Curve::parse(curve)?;
    let key = if private_key.len() == curve_id.private_length() {
        let public_key = ec_public_key(curve, private_key)?;
        signature::EcdsaKeyPair::from_private_key_and_public_key(
            algorithm,
            private_key,
            &public_key,
        )
    } else {
        let der = private_pem_der(private_key).context(InvalidCryptoInput::Arguments(&[0, 1]))?;
        signature::EcdsaKeyPair::from_private_key_der(algorithm, &der)
    }
    .map_err(|_| {
        anyhow!("invalid ECDSA private key").context(InvalidCryptoInput::Arguments(&[0, 1]))
    })?;
    key.sign(&SystemRandom::new(), message)
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|_| anyhow!("ECDSA signing failed"))
}

/// Verify an ECDSA signature. Invalid signatures return `false`; invalid keys/options error.
pub fn ecdsa_verify(
    curve: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    format: &str,
) -> Result<bool> {
    let (_, algorithm) = ecdsa_algorithms(curve, format, 4)?;
    let key = public_key_bytes(Curve::parse(curve)?, public_key)
        .context(InvalidCryptoInput::Arguments(&[0, 1]))?;
    let key = signature::ParsedPublicKey::new(algorithm, key.as_ref()).map_err(|_| {
        anyhow!("invalid ECDSA public key").context(InvalidCryptoInput::Arguments(&[0, 1]))
    })?;
    Ok(key.verify_sig(message, signature).is_ok())
}

fn aes_gcm_key(key: &[u8]) -> Result<aead::LessSafeKey> {
    let algorithm = match key.len() {
        16 => &aead::AES_128_GCM,
        32 => &aead::AES_256_GCM,
        _ => bail!("AES-GCM requires a 16- or 32-byte key"),
    };
    aead::UnboundKey::new(algorithm, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| anyhow!("invalid AES-GCM key"))
}

fn aes_gcm_nonce(nonce: &[u8]) -> Result<aead::Nonce> {
    aead::Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| anyhow!("AES-GCM requires a 12-byte nonce"))
}

/// Encrypt using AES-128/256-GCM, returning ciphertext followed by the 16-byte tag.
/// The caller must never reuse a nonce with the same key.
pub fn aes_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = aes_gcm_key(key).context(InvalidCryptoInput::Argument(0))?;
    let nonce = aes_gcm_nonce(nonce).context(InvalidCryptoInput::Argument(1))?;
    let capacity =
        plaintext.len().checked_add(16).ok_or_else(|| anyhow!("AES-GCM input too large"))?;
    let mut sealed = Zeroizing::new(Vec::new());
    sealed.try_reserve_exact(capacity).map_err(|_| anyhow!("AES-GCM input too large"))?;
    sealed.extend_from_slice(plaintext);
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut *sealed)
        .map_err(|_| anyhow!("AES-GCM encryption failed"))?;
    Ok(sealed)
}

/// Authenticate and decrypt ciphertext followed by a 16-byte tag.
/// Authentication failure returns an error and never returns any plaintext.
pub fn aes_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = aes_gcm_key(key).context(InvalidCryptoInput::Argument(0))?;
    let nonce = aes_gcm_nonce(nonce).context(InvalidCryptoInput::Argument(1))?;
    ensure!(
        ciphertext_and_tag.len() >= 16,
        anyhow!("invalid AES-GCM ciphertext").context(InvalidCryptoInput::Argument(2))
    );
    // The backend may overwrite this buffer before detecting a bad tag. Wipe it on failure.
    let mut plaintext = Zeroizing::new(ciphertext_and_tag.to_vec());
    let length = key
        .open_in_place(nonce, aead::Aad::from(aad), &mut plaintext)
        .map_err(|_| {
            anyhow!("AES-GCM authentication failed").context(InvalidCryptoInput::Combined)
        })?
        .len();
    plaintext.truncate(length);
    Ok(plaintext)
}

struct HkdfLength(usize);

impl hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}

/// RFC5869 HKDF-SHA256 extract-and-expand, with 1..=8,160 output bytes.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    hkdf_sha256_with_budget(ikm, salt, info, length, &mut WorkBudget::default())
}

#[doc(hidden)]
pub fn hkdf_sha256_with_budget(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    budget: &mut WorkBudget,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        (1..=MAX_HKDF_LENGTH).contains(&length),
        anyhow!("HKDF output length exceeds limits").context(InvalidCryptoInput::Argument(3))
    );
    budget.charge(
        ikm.len().saturating_add(salt.len()).saturating_add(info.len()).saturating_add(length),
        hkdf_extra_work(info.len() as u64, length as u64),
    )?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let info = [info];
    let okm =
        prk.expand(&info, HkdfLength(length)).map_err(|_| anyhow!("HKDF derivation failed"))?;
    let mut output = Zeroizing::new(vec![0; length]);
    okm.fill(&mut output).map_err(|_| anyhow!("HKDF derivation failed"))?;
    Ok(output)
}

/// PBKDF2-HMAC-SHA256, with 1..=1,000,000 iterations and 1..=65,536 output bytes.
/// Total work (`iterations * ceil(length / 32)`) must not exceed 4,000,000.
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    pbkdf2_sha256_with_budget(password, salt, iterations, length, &mut WorkBudget::default())
}

#[doc(hidden)]
pub fn pbkdf2_sha256_with_budget(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
    budget: &mut WorkBudget,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        (1..=MAX_PBKDF2_ITERATIONS).contains(&iterations),
        anyhow!("PBKDF2 iterations exceed limits").context(InvalidCryptoInput::Argument(2))
    );
    ensure!(
        (1..=MAX_OUTPUT_LENGTH).contains(&length),
        anyhow!("PBKDF2 output length exceeds limits").context(InvalidCryptoInput::Argument(3))
    );
    ensure!(
        pbkdf2_work(u64::from(iterations), length as u64) <= MAX_PBKDF2_WORK,
        anyhow!("PBKDF2 work exceeds limit").context(InvalidCryptoInput::Arguments(&[2, 3]))
    );
    budget.charge(
        password.len().saturating_add(salt.len()).saturating_add(length),
        pbkdf2_extra_work(salt.len() as u64, u64::from(iterations), length as u64),
    )?;
    let mut output = Zeroizing::new(vec![0; length]);
    // The checked iteration/output bounds satisfy the backend's nonzero and size requirements.
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(iterations).ok_or_else(|| anyhow!("invalid PBKDF2 iterations"))?,
        salt,
        password,
        &mut output,
    );
    Ok(output)
}

fn ed25519_key(seed: &[u8]) -> Result<signature::Ed25519KeyPair> {
    ensure!(
        seed.len() == 32,
        anyhow!("Ed25519 requires a 32-byte seed").context(InvalidCryptoInput::Argument(0))
    );
    signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| anyhow!("invalid Ed25519 seed"))
}

/// Derive a raw 32-byte Ed25519 public key from a 32-byte seed.
pub fn ed25519_public_key(seed: &[u8]) -> Result<Vec<u8>> {
    Ok(ed25519_key(seed)?.public_key().as_ref().to_vec())
}

/// Sign a message with Ed25519, returning a raw 64-byte signature.
pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    ed25519_key(seed)?
        .try_sign(message)
        .map(|signature| signature.as_ref().to_vec())
        .map_err(|_| anyhow!("Ed25519 signing failed"))
}

/// Verify an Ed25519 signature. Invalid signatures return `false`; invalid key lengths error.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
    ensure!(
        public_key.len() == 32,
        anyhow!("Ed25519 requires a 32-byte public key").context(InvalidCryptoInput::Argument(0))
    );
    let key = signature::ParsedPublicKey::new(&signature::ED25519, public_key)
        .map_err(|_| anyhow!("invalid Ed25519 public key"))?;
    Ok(signature.len() == 64 && key.verify_sig(message, signature).is_ok())
}

/// Generate 1..=65,536 cryptographically secure random bytes.
pub fn random_bytes(length: usize) -> Result<Zeroizing<Vec<u8>>> {
    random_bytes_with_budget(length, &mut WorkBudget::default())
}

#[doc(hidden)]
pub fn random_bytes_with_budget(
    length: usize,
    budget: &mut WorkBudget,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        (1..=MAX_OUTPUT_LENGTH).contains(&length),
        anyhow!("random output length exceeds limits").context(InvalidCryptoInput::Argument(0))
    );
    budget.charge(length, 0)?;
    let mut output = Zeroizing::new(vec![0; length]);
    SystemRandom::new().fill(&mut output).map_err(|_| anyhow!("random byte generation failed"))?;
    Ok(output)
}

/// Compare byte slices in constant time with respect to their contents, but not their lengths.
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(left, right).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn nist_aes_gcm_known_answers() {
        for (key_length, plaintext, expected) in [
            (16, Vec::new(), "58e2fccefa7e3061367f1d57a4e7455a"),
            (16, vec![0; 16], "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
            (32, Vec::new(), "530f8afbc74536b9a963b4f1c4cb738b"),
            (32, vec![0; 16], "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
        ] {
            let key = vec![0; key_length];
            let sealed = aes_gcm_encrypt(&key, &[0; 12], &plaintext, b"").unwrap();
            assert_eq!(sealed.as_slice(), bytes(expected));
            assert_eq!(
                aes_gcm_decrypt(&key, &[0; 12], &sealed, b"").unwrap().as_slice(),
                plaintext
            );
        }
    }

    #[test]
    fn aes_gcm_rejects_tampering_wrong_key_nonce_and_aad() {
        let key = [0x11; 32];
        let nonce = [0x22; 12];
        let message = b"\0\xffsecret plaintext\x80";
        let sealed = aes_gcm_encrypt(&key, &nonce, message, b"metadata").unwrap();
        assert_eq!(
            aes_gcm_decrypt(&key, &nonce, &sealed, b"metadata").unwrap().as_slice(),
            message
        );
        for offset in [0, sealed.len() - 1] {
            let mut changed = sealed.clone();
            changed[offset] ^= 1;
            assert!(aes_gcm_decrypt(&key, &nonce, &changed, b"metadata").is_err());
        }
        for result in [
            aes_gcm_decrypt(&[0x12; 32], &nonce, &sealed, b"metadata"),
            aes_gcm_decrypt(&key, &[0x23; 12], &sealed, b"metadata"),
            aes_gcm_decrypt(&key, &nonce, &sealed, b"changed"),
            aes_gcm_decrypt(&key, &nonce, &sealed[..15], b"metadata"),
            aes_gcm_decrypt(&key, &[0; 11], &sealed, b"metadata"),
            aes_gcm_encrypt(&[0; 24], &nonce, message, b""),
            aes_gcm_encrypt(&key, &[0; 13], message, b""),
        ] {
            let error = result.unwrap_err().to_string();
            assert!(!error.contains("secret plaintext"));
            assert!(!error.contains("metadata"));
        }
    }

    #[test]
    fn rfc5869_hkdf_sha256_known_answers() {
        assert_eq!(
            hkdf_sha256(
                &[0x0b; 22],
                &bytes("000102030405060708090a0b0c"),
                &bytes("f0f1f2f3f4f5f6f7f8f9"),
                42,
            )
            .unwrap()
            .as_slice(),
            bytes(concat!(
                "3cb25f25faacd57a90434f64d0362f2a",
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            ))
        );
        assert_eq!(
            hkdf_sha256(&[0x0b; 22], b"", b"", 42).unwrap().as_slice(),
            bytes(concat!(
                "8da4e775a563c18f715f802a063c5a31",
                "b8a11f5c5ee1879ec3454e5f3c738d2d",
                "9d201395faa4b61a96c8"
            ))
        );
    }

    #[test]
    fn pbkdf2_sha256_known_answers() {
        for (iterations, expected) in [
            (1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
            (2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
            (4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
        ] {
            assert_eq!(
                pbkdf2_sha256(b"password", b"salt", iterations, 32).unwrap().as_slice(),
                bytes(expected)
            );
        }
        assert_eq!(
            pbkdf2_sha256(b"pass\0word", b"sa\0lt", 4096, 16).unwrap().as_slice(),
            bytes("89b69d0516f829893c696226650a8687")
        );
    }

    #[test]
    fn rfc7748_x25519_known_answer() {
        let alice_private =
            bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public =
            bytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_private = bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public = bytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = bytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(ec_public_key("X25519", &alice_private).unwrap(), alice_public);
        assert_eq!(ec_public_key("X25519", &bob_private).unwrap(), bob_public);
        assert_eq!(ecdh("X25519", &alice_private, &bob_public).unwrap().as_slice(), shared);
        assert_eq!(ecdh("X25519", &bob_private, &alice_public).unwrap().as_slice(), shared);
        assert!(ecdh("X25519", &alice_private, &[0; 32]).is_err());
    }

    #[test]
    fn rfc8032_ed25519_known_answers() {
        for (seed, public, message, signature) in [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                concat!(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
                    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                ),
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                concat!(
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da",
                    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
                ),
            ),
        ] {
            let seed = bytes(seed);
            let public = bytes(public);
            let message = bytes(message);
            let signature = bytes(signature);
            assert_eq!(ed25519_public_key(&seed).unwrap(), public);
            assert_eq!(ed25519_sign(&seed, &message).unwrap(), signature);
            assert!(ed25519_verify(&public, &message, &signature).unwrap());
            assert!(!ed25519_verify(&public, b"changed", &signature).unwrap());
            let mut tampered = signature.clone();
            tampered[0] ^= 1;
            assert!(!ed25519_verify(&public, &message, &tampered).unwrap());
            assert!(!ed25519_verify(&public, &message, &signature[..63]).unwrap());
        }
    }

    #[test]
    fn nist_curve_public_keys_ecdh_and_signature_formats() {
        for (curve, length, generator) in [
            (
                "P-256",
                32,
                concat!(
                    "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
                ),
            ),
            (
                "P-384",
                48,
                concat!(
                    "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385",
                    "502f25dbf55296c3a545e3872760ab7",
                    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00",
                    "a60b1ce1d7e819d7a431d7c90ea0e5f"
                ),
            ),
        ] {
            let mut private = vec![0; length];
            private[length - 1] = 1;
            let public = ec_public_key(curve, &private).unwrap();
            assert_eq!(public, bytes(generator));
            let mut other_private = private.clone();
            other_private[length - 1] = 2;
            let other_public = ec_public_key(curve, &other_private).unwrap();
            assert_eq!(
                ecdh(curve, &private, &other_public).unwrap(),
                ecdh(curve, &other_private, &public).unwrap()
            );
            for format in ["p1363", "der"] {
                let signature =
                    ecdsa_sign(curve, &private, b"\0binary\xffmessage", format).unwrap();
                if format == "p1363" {
                    assert_eq!(signature.len(), length * 2);
                } else {
                    assert_eq!(signature[0], 0x30);
                }
                assert!(
                    ecdsa_verify(curve, &public, b"\0binary\xffmessage", &signature, format)
                        .unwrap()
                );
                assert!(!ecdsa_verify(curve, &public, b"changed", &signature, format).unwrap());
                assert!(
                    !ecdsa_verify(curve, &other_public, b"\0binary\xffmessage", &signature, format)
                        .unwrap()
                );
                assert!(
                    !ecdsa_verify(curve, &public, b"\0binary\xffmessage", b"bad", format).unwrap()
                );
            }
        }
    }

    #[test]
    fn rfc6979_external_ecdsa_verification_vectors() {
        // Published SHA-256/P-256 and SHA-384/P-384 "sample" vectors, not self-signed fixtures.
        // https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.5
        // https://www.rfc-editor.org/rfc/rfc6979.html#appendix-A.2.6
        for (curve, private, public, r, s, der_prefix, integer_prefix) in [
            (
                "P-256",
                "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
                concat!(
                    "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
                    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
                ),
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                "3046",
                "022100",
            ),
            (
                "P-384",
                concat!(
                    "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8",
                    "96d5724e4c70a825f872c9ea60d2edf5"
                ),
                concat!(
                    "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64",
                    "def8f0ea9055866064a254515480bc13",
                    "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1",
                    "288b231c3ae0d4fe7344fd2533264720"
                ),
                concat!(
                    "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c",
                    "81a648152e44acf96e36dd1e80fabe46"
                ),
                concat!(
                    "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f",
                    "a329c145786e679e7b82c71a38628ac8"
                ),
                "3066",
                "023100",
            ),
        ] {
            let public = bytes(public);
            assert_eq!(ec_public_key(curve, &bytes(private)).unwrap(), public);
            let fixed = bytes(&format!("{r}{s}"));
            let der = bytes(&format!("{der_prefix}{integer_prefix}{r}{integer_prefix}{s}"));
            for (format, signature) in [("p1363", fixed), ("der", der)] {
                assert!(ecdsa_verify(curve, &public, b"sample", &signature, format).unwrap());
                assert!(
                    !ecdsa_verify(curve, &public, b"wrong message", &signature, format).unwrap()
                );
            }
        }
    }

    #[test]
    fn ec_pem_keys_match_raw_keys_and_reject_wrong_curves() {
        use aws_lc_rs::encoding::{AsDer, EcPrivateKeyRfc5915Der, PublicKeyX509Der};

        for (curve_name, curve) in [("P-256", Curve::P256), ("P-384", Curve::P384)] {
            let mut raw = vec![0; curve.private_length()];
            raw[0] = 1;
            let key = agreement_private_key(curve, &raw).unwrap();
            let rfc5915: EcPrivateKeyRfc5915Der = key.as_der().unwrap();
            let rfc5915 = pem::encode(&pem::Pem::new("EC PRIVATE KEY", rfc5915.as_ref()));
            let public = key.compute_public_key().unwrap();
            let spki: PublicKeyX509Der = public.as_der().unwrap();
            let public_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki.as_ref()));
            let (algorithm, _) = ecdsa_algorithms(curve_name, "p1363", 3).unwrap();
            let signing_key = signature::EcdsaKeyPair::from_private_key_and_public_key(
                algorithm,
                &raw,
                public.as_ref(),
            )
            .unwrap();
            let pkcs8 = signing_key.to_pkcs8v1().unwrap();
            let pkcs8 = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8.as_ref()));
            let parameters = match curve {
                Curve::P256 => "06082a8648ce3d030107",
                Curve::P384 => "06052b81040022",
                Curve::X25519 => unreachable!(),
            };
            let ec_parameters = pem::encode(&pem::Pem::new("EC PARAMETERS", bytes(parameters)));
            let private_bundle = format!("{ec_parameters}{rfc5915}");
            let public_bundle = format!("{ec_parameters}{public_pem}");
            for pem in [rfc5915, pkcs8, private_bundle] {
                assert_eq!(ec_public_key(curve_name, pem.as_bytes()).unwrap(), public.as_ref());
                assert_eq!(
                    ecdh(curve_name, pem.as_bytes(), public_bundle.as_bytes()).unwrap(),
                    ecdh(curve_name, &raw, public.as_ref()).unwrap()
                );
                let signed = ecdsa_sign(curve_name, pem.as_bytes(), b"message", "der").unwrap();
                assert!(
                    ecdsa_verify(curve_name, public_bundle.as_bytes(), b"message", &signed, "der")
                        .unwrap()
                );
                let other_curve = if curve_name == "P-256" { "P-384" } else { "P-256" };
                assert!(ec_public_key(other_curve, pem.as_bytes()).is_err());
                assert!(ecdsa_sign(other_curve, pem.as_bytes(), b"message", "der").is_err());
                let mut other_private =
                    vec![0; Curve::parse(other_curve).unwrap().private_length()];
                *other_private.last_mut().unwrap() = 1;
                assert!(ecdh(other_curve, &other_private, public_pem.as_bytes()).is_err());
                assert!(
                    ecdsa_verify(other_curve, public_pem.as_bytes(), b"message", &signed, "der")
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn invalid_keys_curves_and_formats_fail_without_echoing_inputs() {
        let marker = b"sensitive-key-marker-not-a-valid-key";
        for curve in ["P-256", "P-384", "X25519", "unsupported-sensitive-curve"] {
            for result in [
                ec_public_key(curve, marker).unwrap_err(),
                ecdh(curve, marker, marker).unwrap_err(),
                ecdsa_sign(curve, marker, b"sensitive-message-marker", "p1363").unwrap_err(),
            ] {
                let error = result.to_string();
                assert!(!error.contains("sensitive"));
                assert!(!error.contains("KeyRejected"));
            }
            assert!(ecdsa_verify(curve, marker, b"message", marker, "der").is_err());
        }
        for curve in ["P-256", "P-384"] {
            let length = Curve::parse(curve).unwrap().private_length();
            assert!(ec_public_key(curve, &vec![0; length]).is_err());
            assert!(ec_public_key(curve, &vec![0xff; length]).is_err());
            let mut private = vec![0; length];
            private[length - 1] = 1;
            assert!(ecdsa_sign(curve, &private, b"message", "unknown").is_err());
            assert!(ecdh(curve, &private, &vec![0; length * 2 + 1]).is_err());
            assert!(ecdsa_verify(curve, &vec![0; length * 2 + 1], b"message", b"", "der").is_err());
        }
        assert!(ed25519_public_key(b"").is_err());
        assert!(ed25519_public_key(&[0; 31]).is_err());
        assert!(ed25519_sign(b"", b"message").is_err());
        assert!(ed25519_sign(&[0; 64], b"message").is_err());
        assert!(ed25519_verify(&[0; 31], b"message", &[0; 64]).is_err());
    }

    #[test]
    fn output_and_iteration_limits_are_checked() {
        assert!(hkdf_sha256(b"ikm", b"", b"", 8160).is_ok());
        assert!(hkdf_sha256(b"ikm", b"", b"", 8161).is_err());
        assert!(hkdf_sha256(b"ikm", b"", b"", usize::MAX).is_err());
        assert!(hkdf_sha256(b"ikm", b"", b"", 0).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 1, 65_536).is_ok());
        assert!(pbkdf2_sha256(b"password", b"salt", 1, 65_537).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 1, usize::MAX).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 0, 32).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 1_000_001, 32).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", u32::MAX, 32).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 1_000_000, 1).is_ok());
        assert!(pbkdf2_sha256(b"password", b"salt", 1_000_000, 129).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 2_000, 65_536).is_err());
        assert!(pbkdf2_sha256(b"password", b"salt", 1, 0).is_err());
        assert!(random_bytes(0).is_err());
        assert_eq!(random_bytes(65_536).unwrap().len(), 65_536);
        assert!(random_bytes(65_537).is_err());
        assert!(random_bytes(usize::MAX).is_err());
    }

    #[test]
    fn work_budget_admits_one_maximal_pbkdf2_and_bounds_repetition() {
        let mut budget = WorkBudget::default();
        budget.charge(168, pbkdf2_extra_work(32, 1_000_000, 128)).unwrap();
        assert!(budget.charge(168, pbkdf2_extra_work(32, 1_000_000, 128)).is_err());
        let headroom = (0..10_000).take_while(|_| budget.charge(32, 0).is_ok()).count();
        assert!((900..1_000).contains(&headroom), "{headroom}");
        let mut budget = WorkBudget::default();
        let admitted = (0..10_000).take_while(|_| budget.charge(32, 0).is_ok()).count();
        assert!((1_000..10_000).contains(&admitted), "{admitted}");
        assert!(WorkBudget::default().charge(0, u64::MAX).is_err());
    }

    #[test]
    fn work_budget_caps_expensive_curve_operations() {
        for (extra, cap) in [
            (ec_extra_work("P-256"), 500),
            (ec_extra_work("P-384"), 200),
            (ec_extra_work("X25519"), 1000),
            (ED25519_EXTRA_WORK, 500),
        ] {
            let mut budget = WorkBudget::default();
            for _ in 0..cap {
                budget.charge(0, extra).unwrap();
            }
            assert!(budget.charge(0, extra).is_err());
        }
    }

    #[test]
    fn kdf_work_charges_repeated_salt_and_info_without_running_derivations() {
        // The historical 16 MiB salt reproducer would hash 32 GiB. Use only its lengths.
        let input_length = 16 * 1024 * 1024usize;
        assert!(
            WorkBudget::default().charge(input_length + 1 + 65_536, pbkdf2_work(1, 65_536)).is_ok()
        );
        assert!(
            WorkBudget::default()
                .charge(
                    input_length + 1 + 65_536,
                    pbkdf2_extra_work(input_length as u64, 1, 65_536)
                )
                .is_err()
        );
        assert!(WorkBudget::default().charge(input_length + 1 + 8160, 0).is_ok());
        assert!(
            WorkBudget::default()
                .charge(input_length + 1 + 8160, hkdf_extra_work(input_length as u64, 8160))
                .is_err()
        );

        assert_eq!(hkdf_extra_work(17, 32), 0);
        assert_eq!(hkdf_extra_work(17, 33), 2);
        assert_eq!(pbkdf2_extra_work(17, 3, 32), 3);
        assert_eq!(pbkdf2_extra_work(17, 3, 33), 8);
        assert_eq!(pbkdf2_extra_work(u64::MAX, u64::MAX, u64::MAX), u64::MAX);
        assert!(WorkBudget::default().charge(0, hkdf_extra_work(u64::MAX, u64::MAX)).is_err());
    }

    #[test]
    fn kdf_work_preserves_normal_maximum_profiles() {
        // Check costs, not millions of HMAC calls. All previously documented maximum
        // iteration/output-work profiles remain available with ordinary 32-byte salts.
        for (iterations, length) in [(1_000_000, 128), (1953, 65_536), (1, 65_536)] {
            assert!(pbkdf2_work(iterations, length) <= MAX_PBKDF2_WORK);
            WorkBudget::default()
                .charge(8 + 32 + length as usize, pbkdf2_extra_work(32, iterations, length))
                .unwrap();
        }
        WorkBudget::default().charge(32 + 32 + 32 + 8160, hkdf_extra_work(32, 8160)).unwrap();
    }

    #[test]
    fn kdf_primitives_reject_excessive_repeated_inputs_before_backend_work() {
        // Small allocations suffice to exceed the budget once repeated across output
        // blocks. Neither test executes the historical 32 GiB derivation.
        let salt = vec![0; 40 * 1024];
        let info = vec![0; 384 * 1024];
        let error = pbkdf2_sha256(b"p", &salt, 1, 65_536).unwrap_err().to_string();
        assert_eq!(error, "cryptographic work budget exceeded");
        let error = hkdf_sha256(b"ikm", b"salt", &info, 8160).unwrap_err().to_string();
        assert_eq!(error, "cryptographic work budget exceeded");
    }

    #[test]
    fn randomness_and_constant_time_equality() {
        let first = random_bytes(32).unwrap();
        let second = random_bytes(32).unwrap();
        assert_ne!(first, second);
        assert!(constant_time_eq(&first, &first));
        assert!(!constant_time_eq(&first, &second));
        assert!(!constant_time_eq(&first, &first[..31]));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\0\xff\x80", b"\0\xff\x80"));
        assert!(!constant_time_eq(b"\0\xff\x80", b"\0\xff\x81"));
    }
}
