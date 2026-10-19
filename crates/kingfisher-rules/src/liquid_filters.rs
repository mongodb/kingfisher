//! Collection of small Liquid filters that make HTTP validations & API-signing templates easy

use base64::{Engine, engine::general_purpose};
use bip39::{Language, Mnemonic};
use crc32fast::Hasher;
use hmac::{Hmac, KeyInit, Mac};
use liquid_core::{
    Display_filter, Error as LiquidError, Expression, Filter, FilterParameters, FilterReflection,
    FromFilterParameters, ParseFilter, Result, Runtime, Value, ValueView,
};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use rand::{RngExt, distr::Alphanumeric};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use time::{
    OffsetDateTime,
    format_description::well_known::{Iso8601, Rfc2822},
};
use uuid::Uuid;
use zeroize::Zeroizing;

// -----------------------------------------------------------------------------
// Declare Liquid filters with reflection and evaluation implementations.
// -----------------------------------------------------------------------------
macro_rules! static_filter {
    // Stateless filter.
    (
        $(#[$outer:meta])*
        $name:ident, $display:literal, $body:expr_2021
    ) => {
        $(#[$outer])*
        #[derive(Debug, Clone, FilterReflection, ParseFilter, Default)]
        #[filter(name = $display, description = $display, parsed($name))]
        pub struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $display)
            }
        }
        impl Filter for $name {
            fn evaluate(
                &self,
                input: &dyn ValueView,
                _runtime: &dyn Runtime,
            ) -> Result<Value, LiquidError> {
                Ok(Value::scalar($body(input)))
            }
        }
    };

    // Filter with stored fields.
(
    $(#[$outer:meta])*
    $name:ident { $( $(#[$f_meta:meta])* $field:ident : $ty:ty ),+ $(,)? },
    $display:literal,
    $body:expr_2021
) => {
    $(#[$outer])*
    #[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]
    #[filter(name = $display, description = $display, parsed($name))]
    pub struct $name { $( $(#[$f_meta])* pub $field : $ty ),+ }

    impl std::fmt::Display for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, $display)
        }
    }
    impl Filter for $name {
        fn evaluate(
            &self,
            input: &dyn ValueView,
            _runtime: &dyn Runtime,
        ) -> Result<Value, LiquidError> {
            Ok(Value::scalar($body(self, input)))
        }
    }
};
}

#[derive(Debug, FilterParameters)]
struct ReplaceArgs {
    #[parameter(description = "The substring to search for.", arg_type = "str")]
    from: Expression,
    #[parameter(description = "The string to replace it with.", arg_type = "str")]
    to: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "replace",
    description = "Replaces every occurrence of a substring with another.",
    parameters(ReplaceArgs),
    parsed(ReplaceFilter)
)]
pub struct Replace;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "replace"]
struct ReplaceFilter {
    #[parameters]
    args: ReplaceArgs,
}

impl Filter for ReplaceFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let from = args.from.to_kstr();
        let to = args.to.to_kstr();
        let input_str = input.to_kstr();
        Ok(Value::scalar(input_str.replace(from.as_str(), to.as_str())))
    }
}

#[derive(Debug, FilterParameters)]
struct LstripCharsArgs {
    #[parameter(
        description = "Characters to remove from the start of the input.",
        arg_type = "str"
    )]
    chars: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "lstrip_chars",
    description = "Removes the provided characters from the beginning of the string.",
    parameters(LstripCharsArgs),
    parsed(LstripCharsFilter)
)]
pub struct LstripChars;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "lstrip_chars"]
struct LstripCharsFilter {
    #[parameters]
    args: LstripCharsArgs,
}

impl Filter for LstripCharsFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let chars = args.chars.to_string();
        let input_str = input.to_kstr();
        let trimmed = input_str.trim_start_matches(|c| chars.contains(c)).to_string();
        Ok(Value::scalar(trimmed))
    }
}

// ── HMAC args ─────────────────────────────────────
#[derive(Debug, FilterParameters)]
struct HmacArgs {
    #[parameter(description = "HMAC key", arg_type = "str")]
    key: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "hmac_sha256",
    description = "HMAC-SHA256 – returns Base64.",
    parameters(HmacArgs),
    parsed(HmacSha256Filter)
)]
pub struct HmacSha256;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "hmac_sha256"]
struct HmacSha256Filter {
    #[parameters]
    args: HmacArgs,
}

impl Filter for HmacSha256Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        // Evaluate the arguments first…
        let args = self.args.evaluate(runtime)?;
        let key = args.key.to_kstr(); // evaluated to literal/variable value

        // …then do the cryptography.
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(input.to_kstr().as_bytes());
        Ok(Value::scalar(
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()),
        ))
    }
}

// ── HMAC-SHA256 with base64-encoded key ──────────────────────────────────
#[derive(Debug, FilterParameters)]
struct HmacB64KeyArgs {
    #[parameter(description = "Base64-encoded HMAC key", arg_type = "str")]
    key: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "hmac_sha256_b64key",
    description = "HMAC-SHA256 with a base64-encoded key – decodes the key to raw bytes before signing. Returns Base64.",
    parameters(HmacB64KeyArgs),
    parsed(HmacSha256B64KeyFilter)
)]
pub struct HmacSha256B64Key;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "hmac_sha256_b64key"]
struct HmacSha256B64KeyFilter {
    #[parameters]
    args: HmacB64KeyArgs,
}

impl Filter for HmacSha256B64KeyFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let key_b64 = args.key.to_kstr();

        let key_bytes = general_purpose::STANDARD.decode(key_b64.as_bytes()).map_err(|e| {
            LiquidError::with_msg(format!("hmac_sha256_b64key: invalid base64 key: {e}"))
        })?;

        let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
            .map_err(|e| LiquidError::with_msg(format!("hmac_sha256_b64key: {e}")))?;
        mac.update(input.to_kstr().as_bytes());
        Ok(Value::scalar(general_purpose::STANDARD.encode(mac.finalize().into_bytes())))
    }
}

// ── HMAC-SHA1 ─────────────────────────────────────────────
#[derive(Debug, FilterParameters)]
struct HmacSha1Args {
    #[parameter(description = "HMAC key", arg_type = "str")]
    key: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "hmac_sha1",
    description = "HMAC-SHA1 – returns Base64.",
    parameters(HmacSha1Args),
    parsed(HmacSha1Filter)
)]
pub struct HmacSha1;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "hmac_sha1"]
struct HmacSha1Filter {
    #[parameters]
    args: HmacSha1Args,
}

impl Filter for HmacSha1Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        // Evaluate the arguments first…
        let args = self.args.evaluate(runtime)?;
        let key = args.key.to_kstr();

        // …then do the cryptography.
        let mut mac = Hmac::<Sha1>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(input.to_kstr().as_bytes());
        Ok(Value::scalar(
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()),
        ))
    }
}

// ── HMAC-SHA384 ─────────────────────────────────────────────
#[derive(Debug, FilterParameters)]
struct Hmac384Args {
    #[parameter(description = "HMAC key", arg_type = "str")]
    key: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "hmac_sha384",
    description = "HMAC-SHA384 – returns Base64.",
    parameters(Hmac384Args),
    parsed(HmacSha384Filter)
)]
pub struct HmacSha384;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "hmac_sha384"]
struct HmacSha384Filter {
    #[parameters]
    args: Hmac384Args,
}

impl Filter for HmacSha384Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        // Evaluate the arguments first…
        let args = self.args.evaluate(runtime)?;
        let key = args.key.to_kstr(); // evaluated to literal/variable value

        // …then do the cryptography.
        let mut mac = Hmac::<Sha384>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(input.to_kstr().as_bytes());
        Ok(Value::scalar(
            base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()),
        ))
    }
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "hmac_sha384_hex",
    description = "HMAC-SHA384 - returns lowercase hex.",
    parameters(Hmac384Args),
    parsed(HmacSha384HexFilter)
)]
pub struct HmacSha384Hex;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "hmac_sha384_hex"]
struct HmacSha384HexFilter {
    #[parameters]
    args: Hmac384Args,
}

impl Filter for HmacSha384HexFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        use std::fmt::Write as _;

        let args = self.args.evaluate(runtime)?;
        let key = args.key.to_kstr();

        let mut mac = Hmac::<Sha384>::new_from_slice(key.as_bytes()).unwrap();
        mac.update(input.to_kstr().as_bytes());

        let bytes = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(&mut hex, "{byte:02x}");
        }

        Ok(Value::scalar(hex))
    }
}

// ── random_string ────────────────────────────────
#[derive(Debug, FilterParameters)]
struct RandomStringArgs {
    #[parameter(description = "Desired output length", arg_type = "integer")]
    len: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "random_string",
    description = "Random alphanumeric string (default 32 chars).",
    parameters(RandomStringArgs),
    parsed(RandomString)
)]
pub struct RandomStringFilter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "random_string"]
struct RandomString {
    #[parameters]
    args: RandomStringArgs,
}

impl Filter for RandomString {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let n = args
            .len
            .and_then(|value| {
                let scalar = Value::scalar(value);
                value_to_usize(&scalar)
            })
            .or_else(|| input.to_kstr().parse().ok())
            .unwrap_or(32);

        let value: String =
            rand::rng().sample_iter(&Alphanumeric).take(n).map(char::from).collect();

        Ok(Value::scalar(value))
    }
}

#[derive(Debug, FilterParameters)]
struct SuffixArgs {
    #[parameter(description = "Number of trailing characters to keep", arg_type = "integer")]
    len: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "suffix",
    description = "Return the suffix (last N characters) of the provided string.",
    parameters(SuffixArgs),
    parsed(Suffix)
)]
pub struct SuffixFilter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "suffix"]
struct Suffix {
    #[parameters]
    args: SuffixArgs,
}

impl Filter for Suffix {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let text = input.to_kstr();
        let requested = args
            .len
            .and_then(|value| {
                let scalar = Value::scalar(value);
                value_to_usize(&scalar)
            })
            .unwrap_or_else(|| text.len());
        if requested == 0 {
            return Ok(Value::scalar(String::new()));
        }

        let mut chars: Vec<char> = text.chars().collect();
        let keep = requested.min(chars.len());
        chars.drain(0..chars.len().saturating_sub(keep));
        Ok(Value::scalar(chars.into_iter().collect::<String>()))
    }
}

#[derive(Debug, FilterParameters)]
struct PrefixArgs {
    #[parameter(description = "Number of leading characters to keep", arg_type = "integer")]
    len: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "prefix",
    description = "Return the prefix (first N characters) of the provided string.",
    parameters(PrefixArgs),
    parsed(Prefix)
)]
pub struct PrefixFilter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "prefix"]
struct Prefix {
    #[parameters]
    args: PrefixArgs,
}

impl Filter for Prefix {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let text = input.to_kstr();
        let requested = args
            .len
            .and_then(|value| {
                let scalar = Value::scalar(value);
                value_to_usize(&scalar)
            })
            .unwrap_or_else(|| text.len());
        if requested == 0 {
            return Ok(Value::scalar(String::new()));
        }

        let mut chars: Vec<char> = text.chars().collect();
        chars.truncate(requested.min(chars.len()));
        Ok(Value::scalar(chars.into_iter().collect::<String>()))
    }
}

#[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]
#[filter(
    name = "b64enc",
    description = "Encodes the input string using Base64 encoding",
    parsed(B64EncFilter)
)]
pub struct B64EncFilter;

impl std::fmt::Display for B64EncFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "b64enc")
    }
}

impl Filter for B64EncFilter {
    fn evaluate(
        &self,
        input: &dyn ValueView,
        _runtime: &dyn Runtime,
    ) -> Result<Value, LiquidError> {
        let input_str = input.to_kstr().into_owned();
        let encoded = general_purpose::STANDARD.encode(input_str.as_bytes());
        Ok(Value::scalar(encoded))
    }
}

#[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]
#[filter(name = "b64dec", description = "Decodes a Base64 string", parsed(B64DecFilter))]
pub struct B64DecFilter;

impl std::fmt::Display for B64DecFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "b64dec")
    }
}

impl Filter for B64DecFilter {
    fn evaluate(
        &self,
        input: &dyn ValueView,
        _runtime: &dyn Runtime,
    ) -> Result<Value, LiquidError> {
        let input_str = input.to_kstr();
        match general_purpose::STANDARD.decode(input_str.as_bytes()) {
            Ok(bytes) => Ok(Value::scalar(String::from_utf8_lossy(&bytes).to_string())),
            Err(e) => Err(LiquidError::with_msg(e.to_string())),
        }
    }
}

// {{ "any" | newline }} → "\n"  (appends nothing, just returns a newline character)
static_filter!(
    /// Returns a single newline character. Useful inside YAML block scalars where
    /// a literal newline in the template would break indentation.
    NewlineFilter, "newline",
    |_input: &dyn ValueView| -> String { "\n".to_string() }
);

// {{ TOKEN | bip39_valid }}
static_filter!(
    /// Return whether the input is a checksum-valid English BIP-39 mnemonic.
    Bip39ValidFilter, "bip39_valid",
    |input: &dyn ValueView| -> bool {
        const MAX_MNEMONIC_BYTES: usize = 640;
        let input = input.to_kstr();
        if input.len() > MAX_MNEMONIC_BYTES {
            return false;
        }

        // This contains the full mnemonic. Keep `Zeroizing`: the crypto-inventory Semgrep rule
        // flags the crate generically, but wiping this temporary is intentional memory hygiene.
        let normalized = Zeroizing::new(input.split_whitespace().collect::<Vec<_>>().join(" "));
        Mnemonic::parse_in_normalized(Language::English, &normalized).is_ok()
    }
);

static_filter!(
    /// Check the Luhn checksum of at least two ASCII digits, ignoring spaces and hyphens.
    LuhnValidFilter, "luhn_valid",
    |input: &dyn ValueView| -> bool {
        let input = input.to_kstr();
        let mut count = 0usize;
        let mut sum = 0u32;
        for byte in input.bytes().rev() {
            if matches!(byte, b' ' | b'-') {
                continue;
            }
            if !byte.is_ascii_digit() {
                return false;
            }
            let mut digit = u32::from(byte - b'0');
            if count % 2 == 1 {
                digit *= 2;
                if digit > 9 {
                    digit -= 9;
                }
            }
            sum = (sum + digit) % 10;
            count += 1;
        }
        count >= 2 && sum == 0
    }
);

static_filter!(
    /// Check generic IBAN structure and MOD-97 checksum, ignoring ASCII spaces and case.
    /// Country registration, country-specific lengths, and account existence are not checked.
    IbanValidFilter, "iban_valid",
    |input: &dyn ValueView| -> bool {
        // Normalize into a bounded stack buffer, without building a large decimal integer.
        let input = input.to_kstr();
        let mut normalized = [0u8; 34];
        let mut len = 0;
        for byte in input.bytes().filter(|&byte| byte != b' ') {
            if len == normalized.len() || !byte.is_ascii_alphanumeric() {
                return false;
            }
            normalized[len] = byte.to_ascii_uppercase();
            len += 1;
        }
        if len < 5
            || !normalized[..2].iter().all(u8::is_ascii_uppercase)
            || !normalized[2..4].iter().all(u8::is_ascii_digit)
        {
            return false;
        }
        let check_digits = (normalized[2] - b'0') * 10 + normalized[3] - b'0';
        if !(2..=98).contains(&check_digits) {
            return false;
        }
        let mut remainder = 0u32;
        for &byte in normalized[4..len].iter().chain(&normalized[..4]) {
            remainder = if byte.is_ascii_digit() {
                (remainder * 10 + u32::from(byte - b'0')) % 97
            } else {
                (remainder * 100 + u32::from(byte - b'A' + 10)) % 97
            };
        }
        remainder == 1
    }
);

// -----------------------------------------------------------------------------
// Authentication & Security
// -----------------------------------------------------------------------------

// {{ value | sha256 }} -- hex digest
static_filter!(
    /// SHA-256 hex digest.
    Sha256Filter, "sha256",
    |input: &dyn ValueView| -> String {
        let mut h = Sha256::new();
        h.update(input.to_kstr().as_bytes());
        hex::encode(h.finalize())
    }
);

// {{ value | sha256_b32 }} -- base32-encoded SHA-256 digest, optional length
#[derive(Debug, FilterParameters)]
struct Sha256B32Args {
    #[parameter(
        description = "Exact output length: truncates the Base32 text if longer, pads with '=' if shorter (output may not be valid RFC 4648 Base32)",
        arg_type = "integer"
    )]
    len: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "sha256_b32",
    description = "SHA-256 digest encoded as RFC 4648 Base32 by default; with `len`, returns a Base32-alphabet checksum substring of the requested length (truncated or '='-padded), which may not be valid RFC 4648 Base32.",
    parameters(Sha256B32Args),
    parsed(Sha256B32)
)]
pub struct Sha256B32Filter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "sha256_b32"]
struct Sha256B32 {
    #[parameters]
    args: Sha256B32Args,
}

impl Filter for Sha256B32 {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let mut h = Sha256::new();
        h.update(input.to_kstr().as_bytes());
        let mut encoded =
            base32::encode(base32::Alphabet::Rfc4648 { padding: true }, &h.finalize()[..]);
        if let Some(len) = args.len.and_then(|value| {
            let scalar = Value::scalar(value);
            value_to_usize(&scalar)
        }) {
            match encoded.len().cmp(&len) {
                std::cmp::Ordering::Greater => encoded.truncate(len),
                std::cmp::Ordering::Less => {
                    for _ in 0..(len - encoded.len()) {
                        encoded.push('=');
                    }
                }
                std::cmp::Ordering::Equal => {}
            }
        }
        Ok(Value::scalar(encoded))
    }
}

static_filter!(
    /// Compute the CRC32 of the input and return it as a decimal number.
    Crc32Filter,
    "crc32",
    |input: &dyn ValueView| -> i64 {
        let mut hasher = Hasher::new();
        hasher.update(input.to_kstr().as_bytes());
        i64::from(hasher.finalize())
    }
);

#[derive(Debug, FilterParameters)]
struct Crc32DecArgs {
    #[parameter(
        description = "Number of trailing decimal digits to return (zero padded)",
        arg_type = "integer"
    )]
    digits: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "crc32_dec",
    description = "Compute the CRC32 and optionally return the last N decimal digits.",
    parameters(Crc32DecArgs),
    parsed(Crc32Dec)
)]
pub struct Crc32DecFilter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "crc32_dec"]
struct Crc32Dec {
    #[parameters]
    args: Crc32DecArgs,
}

impl Filter for Crc32Dec {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let mut hasher = Hasher::new();
        hasher.update(input.to_kstr().as_bytes());
        let checksum = u128::from(hasher.finalize());

        let digits = args
            .digits
            .and_then(|value| {
                let scalar = Value::scalar(value);
                value_to_usize(&scalar)
            })
            .unwrap_or(0);

        if digits == 0 {
            return Ok(Value::scalar(checksum.to_string()));
        }

        let clamped_digits = digits.min(38); // 10^38 fits within u128
        let modulus = 10u128.pow(clamped_digits as u32);
        let truncated = checksum % modulus;
        let mut value = truncated.to_string();
        if clamped_digits > value.len() {
            let mut padded = String::with_capacity(clamped_digits);
            for _ in 0..(clamped_digits - value.len()) {
                padded.push('0');
            }
            padded.push_str(&value);
            value = padded;
        }

        Ok(Value::scalar(value))
    }
}

#[derive(Debug, FilterParameters)]
struct Crc32HexArgs {
    #[parameter(
        description = "Number of trailing hexadecimal digits to return (zero padded)",
        arg_type = "integer"
    )]
    digits: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "crc32_hex",
    description = "Compute the CRC32 and optionally return the last N hexadecimal digits.",
    parameters(Crc32HexArgs),
    parsed(Crc32Hex)
)]
pub struct Crc32HexFilter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "crc32_hex"]
struct Crc32Hex {
    #[parameters]
    args: Crc32HexArgs,
}

impl Filter for Crc32Hex {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let mut hasher = Hasher::new();
        hasher.update(input.to_kstr().as_bytes());
        let checksum = hasher.finalize();
        let mut hex = format!("{checksum:08x}");

        let digits = args
            .digits
            .and_then(|value| {
                let scalar = Value::scalar(value);
                value_to_usize(&scalar)
            })
            .unwrap_or(0);

        if digits == 0 {
            return Ok(Value::scalar(hex));
        }

        let clamped = digits.min(32);
        if clamped > hex.len() {
            let mut padded = String::with_capacity(clamped);
            for _ in 0..(clamped - hex.len()) {
                padded.push('0');
            }
            padded.push_str(&hex);
            hex = padded;
        } else {
            let start = hex.len() - clamped;
            hex = hex[start..].to_string();
        }

        Ok(Value::scalar(hex))
    }
}

#[derive(Debug, FilterParameters)]
struct Crc32LeB64Args {
    #[parameter(
        description = "Number of leading characters from the Base64 string to keep",
        arg_type = "integer"
    )]
    len: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "crc32_le_b64",
    description = "Compute the CRC32, encode little-endian bytes as Base64, optionally truncating.",
    parameters(Crc32LeB64Args),
    parsed(Crc32LeB64)
)]
pub struct Crc32LeB64Filter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "crc32_le_b64"]
struct Crc32LeB64 {
    #[parameters]
    args: Crc32LeB64Args,
}

impl Filter for Crc32LeB64 {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let mut hasher = Hasher::new();
        hasher.update(input.to_kstr().as_bytes());
        let checksum = hasher.finalize();
        let encoded = general_purpose::STANDARD.encode(checksum.to_le_bytes());

        let output = if let Some(len) = args.len.and_then(|value| {
            let scalar = Value::scalar(value);
            value_to_usize(&scalar)
        }) {
            encoded.chars().take(len).collect::<String>()
        } else {
            encoded
        };

        Ok(Value::scalar(output))
    }
}

#[derive(Debug, FilterParameters)]
struct Base62Args {
    #[parameter(
        description = "Pad the encoded value to at least this width",
        arg_type = "integer"
    )]
    width: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "base62",
    description = "Encode the provided integer value using Base62.",
    parameters(Base62Args),
    parsed(Base62)
)]
pub struct Base62Filter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "base62"]
struct Base62 {
    #[parameters]
    args: Base62Args,
}

impl Filter for Base62 {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let value = input
            .as_scalar()
            .and_then(|scalar| {
                if let Some(int) = scalar.to_integer() {
                    Some(if int < 0 { 0 } else { int as u64 })
                } else if let Some(float) = scalar.to_float() {
                    Some(if float.is_sign_negative() { 0 } else { float.floor() as u64 })
                } else if let Some(boolean) = scalar.to_bool() {
                    Some(u64::from(boolean))
                } else {
                    scalar.to_kstr().to_string().parse::<u64>().ok()
                }
            })
            .or_else(|| input.to_kstr().to_string().parse::<u64>().ok())
            .unwrap_or(0);

        let mut encoded = encode_base62(value);
        if let Some(width) = args.width.and_then(|value| {
            let scalar = Value::scalar(value);
            value_to_usize(&scalar)
        }) && encoded.len() < width
        {
            let mut padded = String::with_capacity(width);
            for _ in 0..(width - encoded.len()) {
                padded.push('0');
            }
            padded.push_str(&encoded);
            encoded = padded;
        }

        Ok(Value::scalar(encoded))
    }
}

fn encode_base62(mut value: u64) -> String {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let mut buf = Vec::new();
    while value > 0 {
        let rem = (value % 62) as usize;
        buf.push(ALPHABET[rem] as char);
        value /= 62;
    }
    buf.iter().rev().collect()
}

fn value_to_usize(value: &Value) -> Option<usize> {
    let view = value.as_view();
    view.as_scalar()
        .and_then(|scalar| {
            if let Some(int) = scalar.to_integer() {
                Some(if int < 0 { 0 } else { int as usize })
            } else if let Some(float) = scalar.to_float() {
                Some(if float.is_sign_negative() { 0 } else { float.floor() as usize })
            } else if let Some(boolean) = scalar.to_bool() {
                Some(if boolean { 1 } else { 0 })
            } else {
                scalar.to_kstr().parse::<usize>().ok()
            }
        })
        .or_else(|| view.to_kstr().parse::<usize>().ok())
}

#[derive(Debug, FilterParameters)]
struct Base36Args {
    #[parameter(
        description = "Pad the encoded value to at least this width",
        arg_type = "integer"
    )]
    width: Option<Expression>,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "base36",
    description = "Encode the provided integer value using Base36.",
    parameters(Base36Args),
    parsed(Base36)
)]
pub struct Base36Filter;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "base36"]
struct Base36 {
    #[parameters]
    args: Base36Args,
}

impl Filter for Base36 {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let args = self.args.evaluate(runtime)?;
        let value = input
            .as_scalar()
            .and_then(|scalar| {
                if let Some(int) = scalar.to_integer() {
                    Some(if int < 0 { 0 } else { int as u64 })
                } else if let Some(float) = scalar.to_float() {
                    Some(if float.is_sign_negative() { 0 } else { float.floor() as u64 })
                } else if let Some(boolean) = scalar.to_bool() {
                    Some(u64::from(boolean))
                } else {
                    scalar.to_kstr().to_string().parse::<u64>().ok()
                }
            })
            .or_else(|| input.to_kstr().to_string().parse::<u64>().ok())
            .unwrap_or(0);

        let mut encoded = encode_base36(value);
        if let Some(width) = args.width.and_then(|value| {
            let scalar = Value::scalar(value);
            value_to_usize(&scalar)
        }) && encoded.len() < width
        {
            let mut padded = String::with_capacity(width);
            for _ in 0..(width - encoded.len()) {
                padded.push('0');
            }
            padded.push_str(&encoded);
            encoded = padded;
        }

        Ok(Value::scalar(encoded))
    }
}

fn encode_base36(mut value: u64) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if value == 0 {
        return "0".to_string();
    }
    let mut buf = Vec::new();
    while value > 0 {
        let rem = (value % 36) as usize;
        buf.push(ALPHABET[rem] as char);
        value /= 36;
    }
    buf.iter().rev().collect()
}

// {{ value | b64url_enc }} – URL-safe base64 w/o padding
static_filter!(
    /// Base64 URL-safe (no ‘=’ padding).
    B64UrlEncFilter, "b64url_enc",
    |input: &dyn ValueView| -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(input.to_kstr().as_bytes())
    }
);

// {{ value | b64url_dec }} – URL-safe base64 decode (with or without padding)
#[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]
#[filter(
    name = "b64url_dec",
    description = "Decodes a URL-safe Base64 string (with or without padding)",
    parsed(B64UrlDecFilter)
)]
pub struct B64UrlDecFilter;

impl std::fmt::Display for B64UrlDecFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "b64url_dec")
    }
}

impl Filter for B64UrlDecFilter {
    fn evaluate(
        &self,
        input: &dyn ValueView,
        _runtime: &dyn Runtime,
    ) -> Result<Value, LiquidError> {
        let input_str = input.to_kstr();
        general_purpose::URL_SAFE_NO_PAD
            .decode(input_str.as_bytes())
            .or_else(|_| general_purpose::URL_SAFE.decode(input_str.as_bytes()))
            .map(|bytes| Value::scalar(String::from_utf8_lossy(&bytes).to_string()))
            .map_err(|e| LiquidError::with_msg(format!("b64url_dec: {e}")))
    }
}

// {{ algo | jwt_header }} – e.g. “HS256” -- Base64URL-encoded header
static_filter!(
    /// Generate a minimal JWT header for the given alg.
    JwtHeaderFilter, "jwt_header",
    |input: &dyn ValueView| -> String {
        let alg = input.to_kstr();
        let json = serde_json::json!({ "typ": "JWT", "alg": alg });
        general_purpose::URL_SAFE_NO_PAD.encode(json.to_string())
    }
);

#[derive(Debug, FilterParameters)]
struct RsaSha256Args {
    #[parameter(
        description = "Unencrypted PKCS#1 or PKCS#8 RSA private key PEM",
        arg_type = "str"
    )]
    key: Expression,
}

#[derive(Clone, ParseFilter, FilterReflection, Default)]
#[filter(
    name = "rsa_sha256",
    description = "RSA PKCS#1 v1.5 with SHA-256 (RS256) – returns unpadded Base64URL.",
    parameters(RsaSha256Args),
    parsed(RsaSha256Filter)
)]
pub struct RsaSha256;

#[derive(Debug, FromFilterParameters, Display_filter)]
#[name = "rsa_sha256"]
struct RsaSha256Filter {
    #[parameters]
    args: RsaSha256Args,
}

impl Filter for RsaSha256Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        use aws_lc_rs::{rand::SystemRandom, signature, signature::KeyPair};

        let args = self.args.evaluate(runtime)?;
        // Never include parser errors or key material in template diagnostics.
        let pem = pem::parse(args.key.as_bytes())
            .map_err(|_| LiquidError::with_msg("rsa_sha256: invalid private key PEM"))?;
        let pkcs8 = match pem.tag() {
            "PRIVATE KEY" => true,
            "RSA PRIVATE KEY" => false,
            _ => {
                return Err(LiquidError::with_msg(
                    "rsa_sha256: expected an unencrypted PKCS#1 or PKCS#8 RSA private key",
                ));
            }
        };
        let der = Zeroizing::new(pem.into_contents());
        let key = if pkcs8 {
            signature::RsaKeyPair::from_pkcs8(&der)
        } else {
            signature::RsaKeyPair::from_der(&der)
        }
        .map_err(|_| LiquidError::with_msg("rsa_sha256: invalid RSA private key"))?;
        let mut signature = vec![0; key.public_key().modulus_len()];
        key.sign(
            &signature::RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.to_kstr().as_bytes(),
            &mut signature,
        )
        .map_err(|_| LiquidError::with_msg("rsa_sha256: signing failed"))?;
        Ok(Value::scalar(general_purpose::URL_SAFE_NO_PAD.encode(signature)))
    }
}

// -----------------------------------------------------------------------------
// Data Formatting
// -----------------------------------------------------------------------------

// {{ value | url_encode }}
static_filter!(
    /// Percent-encode for a URL.
    UrlEncodeFilter, "url_encode",
    |input: &dyn ValueView| -> String {
        utf8_percent_encode(&input.to_kstr(), NON_ALPHANUMERIC).to_string()
    }
);

// {{ value | json_escape }}
static_filter!(
    /// Escape string for JSON contexts.
    JsonEscapeFilter, "json_escape",
    |input: &dyn ValueView| -> String {
        serde_json::to_string(&input.to_kstr().to_string()).unwrap_or_default()
    }
);

// {{ "" | unix_timestamp }}
static_filter!(
    /// Current Unix epoch seconds.
    UnixTimestampFilter, "unix_timestamp",
    |_input: &dyn ValueView| -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }
);

// {{ "" | unix_timestamp_ms }}
static_filter!(
    /// Current Unix epoch milliseconds.
    UnixTimestampMsFilter, "unix_timestamp_ms",
    |_input: &dyn ValueView| -> i64 {
        (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
    }
);

// {{ "" | iso_timestamp_no_frac }}
static_filter!(
    /// Current ISO-8601 timestamp (UTC) with no fractional seconds.
    IsoTimestampNoFracFilter, "iso_timestamp_no_frac",
    |_input: &dyn ValueView| -> String {
        let full = OffsetDateTime::now_utc()
            .format(&Iso8601::DEFAULT)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());

        // If there’s a fractional-second part, remove it but keep the trailing ‘Z’.
        match full.split_once('.') {
            Some((prefix, _)) => {
                format!("{prefix}Z")
            }
            None => full,
        }
    }
);

// {{ "" | iso_timestamp }}
static_filter!(
    /// Current ISO-8601 timestamp (UTC).
    IsoTimestampFilter, "iso_timestamp",
    |_input: &dyn ValueView| -> String {
        OffsetDateTime::now_utc()
            .format(&Iso8601::DEFAULT)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
    }
);

// {{ "" | rfc1123_date }}
static_filter!(
    /// Current RFC-1123 timestamp in GMT.
    Rfc1123DateFilter, "rfc1123_date",
    |_input: &dyn ValueView| -> String {
        let rendered = OffsetDateTime::now_utc()
            .format(&Rfc2822)
            .unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".into());
        rendered
            .strip_suffix(" +0000")
            .map(|prefix| format!("{prefix} GMT"))
            .unwrap_or(rendered)
    }
);

// -----------------------------------------------------------------------------
// Request Uniqueness
// -----------------------------------------------------------------------------

// {{ "" | uuid }}
static_filter!(
    /// Generate random UUID-v4.
    UuidFilter, "uuid",
    |_input: &dyn ValueView| -> String { Uuid::new_v4().to_string() }
);

pub fn register_all(builder: liquid::ParserBuilder) -> liquid::ParserBuilder {
    builder
        // zero-arg helpers
        .filter(Replace)
        .filter(B64UrlEncFilter)
        .filter(B64UrlDecFilter)
        .filter(Sha256Filter)
        .filter(Sha256B32Filter)
        .filter(UrlEncodeFilter)
        .filter(JsonEscapeFilter)
        .filter(UnixTimestampFilter)
        .filter(UnixTimestampMsFilter)
        .filter(IsoTimestampFilter)
        .filter(IsoTimestampNoFracFilter)
        .filter(Rfc1123DateFilter)
        .filter(UuidFilter)
        .filter(Bip39ValidFilter)
        .filter(LuhnValidFilter)
        .filter(IbanValidFilter)
        .filter(JwtHeaderFilter)
        .filter(RsaSha256)
        .filter(B64EncFilter)
        .filter(B64DecFilter)
        .filter(NewlineFilter)
        .filter(RandomStringFilter)
        .filter(SuffixFilter)
        .filter(PrefixFilter)
        .filter(LstripChars)
        .filter(Crc32Filter)
        .filter(Crc32DecFilter)
        .filter(Crc32HexFilter)
        .filter(Crc32LeB64Filter)
        .filter(Base62Filter)
        .filter(Base36Filter)
        .filter(HmacSha256)
        .filter(HmacSha256B64Key)
        .filter(HmacSha1)
        .filter(HmacSha384)
        .filter(HmacSha384Hex)
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use hmac::{Hmac, KeyInit, Mac};
    use liquid::{ParserBuilder, object};
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    use regex::Regex;
    use sha1::Sha1;
    use sha2::{Digest, Sha256, Sha384};
    use time::OffsetDateTime;

    use super::*;

    fn parser() -> liquid::Parser {
        // Build a Liquid parser with stdlib + all custom filters
        register_all(ParserBuilder::with_stdlib()).build().unwrap()
    }

    fn render(src: &str) -> String {
        parser().parse(src).unwrap().render(&object!({})).unwrap()
    }

    #[test]
    fn luhn_valid_checks_digits_and_separator_handling() {
        for input in ["4111111111111111", "4111 1111-1111 1111", "79927398713", "18"] {
            assert_eq!(render(&format!("{{{{ {input:?} | luhn_valid }}}}")), "true");
        }
        for input in [
            "",
            " - ",
            "0",
            "4111111111111112",
            "79927398714",
            "4a11111111111111",
            "４１１１１１１１１１１１１１１１",
            "4111\t111111111111",
        ] {
            // Pass control characters as globals rather than interpolating string literals.
            let template = parser().parse("{{ input | luhn_valid }}").unwrap();
            assert_eq!(template.render(&object!({"input": input})).unwrap(), "false");
        }
        assert_eq!(
            render(
                r#"{% assign valid = "4111111111111112" | luhn_valid %}{% if valid %}yes{% else %}no{% endif %}"#
            ),
            "no"
        );
    }

    #[test]
    fn iban_valid_checks_structure_case_spaces_and_mod97() {
        for input in [
            "GB82WEST12345698765432",
            "gb82 west 1234 5698 7654 32",
            "DE89370400440532013000",
            "NO9386011117947",
            "FR1420041010050500013M02606",
        ] {
            assert_eq!(render(&format!("{{{{ {input:?} | iban_valid }}}}")), "true");
        }
        for input in [
            "",
            "GB82",
            "GB82WEST12345698765433",
            "G182WEST12345698765432",
            "GBXXWEST12345698765432",
            "GB82-WEST12345698765432",
            "GB82WÉST12345698765432",
            "GB82\tWEST12345698765432",
            "GB82WEST12345698765432000000000000000",
        ] {
            let template = parser().parse("{{ input | iban_valid }}").unwrap();
            assert_eq!(template.render(&object!({"input": input})).unwrap(), "false");
        }
        // The filter checks generic structure/checksum, without a country registry.
        assert_eq!(
            render(
                r#"{% assign valid = "GB82WEST12345698765432" | iban_valid %}{% if valid %}yes{% else %}no{% endif %}"#
            ),
            "yes"
        );
    }

    // -------------------------------------------------------------------------
    // Simple one-liner helpers
    // -------------------------------------------------------------------------
    #[test]
    fn b64enc_filter() {
        assert_eq!(render(r#"{{ "hello" | b64enc }}"#), "aGVsbG8=");
    }

    #[test]
    fn b64dec_filter() {
        assert_eq!(render(r#"{{ "aGVsbG8=" | b64dec }}"#), "hello");
    }

    #[test]
    fn sha256_filter() {
        let expect = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(render(r#"{{ "hello" | sha256 }}"#), expect);
    }

    #[test]
    fn sha256_b32_filter() {
        let expect = "FTZE3OS7WCRQ4JXIHMVMLOPCTYNRMHS4D6TUEXTTAQZWFE4LTASA====";
        assert_eq!(render(r#"{{ "hello" | sha256_b32 }}"#), expect);
        // truncate
        assert_eq!(render(r#"{{ "hello" | sha256_b32: 4 }}"#), &expect[..4]);
        // pad
        let padded = render(r#"{{ "hello" | sha256_b32: 60 }}"#);
        assert!(padded.ends_with("===="));
        assert_eq!(padded.len(), 60);
    }

    #[test]
    fn suffix_filter() {
        assert_eq!(render(r#"{{ "abcdef" | suffix: 3 }}"#), "def");
        assert_eq!(render(r#"{{ "short" | suffix: 10 }}"#), "short");
        assert_eq!(render(r#"{{ "value" | suffix: 0 }}"#), "");
    }

    #[test]
    fn prefix_filter() {
        assert_eq!(render(r#"{{ "abcdef" | prefix: 3 }}"#), "abc");
        assert_eq!(render(r#"{{ "short" | prefix: 10 }}"#), "short");
        assert_eq!(render(r#"{{ "value" | prefix: 0 }}"#), "");
    }

    #[test]
    fn crc32_and_base62_filters() {
        assert_eq!(render(r#"{{ "hello" | crc32 }}"#), "907060870");
        assert_eq!(render(r#"{{ "hello" | crc32 | base62 }}"#), "zNvy2");
        assert_eq!(render(r#"{{ "hello" | crc32 | base62: 6 }}"#), "0zNvy2");
    }

    #[test]
    fn base36_filter() {
        assert_eq!(render(r#"{{ 123456 | base36 }}"#), "2n9c");
        assert_eq!(render(r#"{{ 123456 | base36: 6 }}"#), "002n9c");
    }

    #[test]
    fn crc32_dec_filter() {
        assert_eq!(render(r#"{{ "hello" | crc32_dec }}"#), "907060870");
        assert_eq!(render(r#"{{ "hello" | crc32_dec: 6 }}"#), "060870");
    }

    #[test]
    fn crc32_hex_filter() {
        assert_eq!(render(r#"{{ "hello" | crc32_hex }}"#), "3610a686");
        assert_eq!(render(r#"{{ "hello" | crc32_hex: 4 }}"#), "a686");
        assert_eq!(render(r#"{{ "hello" | crc32_hex: 10 }}"#), "003610a686");
    }

    #[test]
    fn crc32_le_b64_filter() {
        assert_eq!(render(r#"{{ "hello" | crc32_le_b64 }}"#), "hqYQNg==");
        assert_eq!(render(r#"{{ "hello" | crc32_le_b64: 6 }}"#), "hqYQNg");
    }

    #[test]
    fn hmac_sha1_filter() {
        let key = b"key1";
        let data = b"data";
        let mut mac = Hmac::<Sha1>::new_from_slice(key).unwrap();
        mac.update(data);
        let expect = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        assert_eq!(render(r#"{{ "data" | hmac_sha1: "key1" }}"#), expect);
    }

    #[test]
    fn b64url_enc_filter() {
        assert_eq!(
            render(r#"{{ "++??" | b64url_enc }}"#),
            general_purpose::URL_SAFE_NO_PAD.encode("++??")
        );
    }

    #[test]
    fn b64url_dec_filter() {
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode("++??");
        assert_eq!(render(&format!("{{{{ \"{encoded}\" | b64url_dec }}}}")), "++??");
        // Also works with padding
        let padded = general_purpose::URL_SAFE.encode("hello");
        assert_eq!(render(&format!("{{{{ \"{padded}\" | b64url_dec }}}}")), "hello");
    }

    #[test]
    fn url_encode_filter() {
        assert_eq!(
            render(r#"{{ "hello world!" | url_encode }}"#),
            utf8_percent_encode("hello world!", NON_ALPHANUMERIC).to_string()
        );
    }

    #[test]
    fn json_escape_filter() {
        assert_eq!(render(r#"{{ '"hi"' | json_escape }}"#), r#""\"hi\"""#);
    }

    // -------------------------------------------------------------------------
    // JWT header
    // -------------------------------------------------------------------------
    #[test]
    fn jwt_header_filter() {
        let result = render(r#"{{ "HS256" | jwt_header }}"#);
        let decoded = general_purpose::URL_SAFE_NO_PAD.decode(&result).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(json["typ"], "JWT");
        assert_eq!(json["alg"], "HS256");
    }

    fn rsa_test_key() -> &'static rsa::RsaPrivateKey {
        static KEY: std::sync::OnceLock<rsa::RsaPrivateKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap())
    }

    #[test]
    fn rsa_sha256_signs_rs256_jwt_with_pkcs1_and_pkcs8_pem() {
        use rsa::{
            pkcs1::{EncodeRsaPrivateKey, LineEnding},
            pkcs8::EncodePrivateKey,
            signature::Verifier,
        };

        let key = rsa_test_key();
        let verifier = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(key.to_public_key());
        let template = parser()
            .parse(
                r#"{%- assign now = "" | unix_timestamp -%}
                {%- assign iat = now | minus: 60 -%}
                {%- assign exp = now | plus: 540 -%}
                {%- capture payload -%}{"iss":{{ APP_ID | json_escape }},"iat":{{ iat }},"exp":{{ exp }}}{%- endcapture -%}
                {%- assign header = "RS256" | jwt_header -%}
                {%- assign payload = payload | b64url_enc -%}
                {%- assign signing_input = header | append: "." | append: payload -%}
                Bearer {{ signing_input }}.{{ signing_input | rsa_sha256: TOKEN }}"#,
            )
            .unwrap();

        for line_ending in [LineEnding::LF, LineEnding::CRLF] {
            for pem in
                [key.to_pkcs1_pem(line_ending).unwrap(), key.to_pkcs8_pem(line_ending).unwrap()]
            {
                let globals = object!({ "TOKEN": pem.as_str(), "APP_ID": "12345" });
                let before = OffsetDateTime::now_utc().unix_timestamp();
                let rendered = template.render(&globals).unwrap();
                let token = rendered.strip_prefix("Bearer ").unwrap();
                let (message, signature) = token.rsplit_once('.').unwrap();
                assert!(signature.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)));
                let signature = general_purpose::URL_SAFE_NO_PAD.decode(signature).unwrap();
                assert_eq!(signature.len(), 256);
                let signature = rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap();
                // Verify with a separate crypto implementation and reject changed claims.
                verifier.verify(message.as_bytes(), &signature).unwrap();
                assert!(verifier.verify(b"changed.payload", &signature).is_err());

                let (header, payload) = message.split_once('.').unwrap();
                let decode = |value: &str| -> serde_json::Value {
                    serde_json::from_slice(&general_purpose::URL_SAFE_NO_PAD.decode(value).unwrap())
                        .unwrap()
                };
                assert_eq!(decode(header), serde_json::json!({"typ": "JWT", "alg": "RS256"}));
                let claims = decode(payload);
                assert_eq!(claims["iss"], "12345");
                let iat = claims["iat"].as_i64().unwrap();
                assert!(iat >= before - 60);
                assert!(iat <= OffsetDateTime::now_utc().unix_timestamp() - 60);
                assert_eq!(claims["exp"].as_i64().unwrap() - iat, 600);
            }
        }
    }

    #[test]
    fn rsa_sha256_rejects_invalid_keys_without_disclosing_key_material() {
        let template = parser().parse(r#"{{ "header.payload" | rsa_sha256: TOKEN }}"#).unwrap();
        let marker = "sensitive-key-marker";
        for key in [
            String::new(),
            marker.to_string(),
            format!("-----BEGIN PRIVATE KEY-----\n{marker}\n-----END PRIVATE KEY-----"),
            pem::encode(&pem::Pem::new("PRIVATE KEY", marker)),
            pem::encode(&pem::Pem::new("RSA PRIVATE KEY", marker)),
            pem::encode(&pem::Pem::new("ENCRYPTED PRIVATE KEY", marker)),
            pem::encode(&pem::Pem::new("PUBLIC KEY", marker)),
        ] {
            let error = template.render(&object!({ "TOKEN": key })).unwrap_err().to_string();
            assert!(error.contains("rsa_sha256:"));
            assert!(!error.contains(marker));
            assert!(!error.contains(&general_purpose::STANDARD.encode(marker)));
        }

        // A well-formed non-RSA PKCS#8 key is also rejected.
        use aws_lc_rs::signature::Ed25519KeyPair;
        let ed25519 =
            Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        let pem = pem::encode(&pem::Pem::new("PRIVATE KEY", ed25519.as_ref()));
        let error = template.render(&object!({ "TOKEN": pem })).unwrap_err().to_string();
        assert!(error.contains("rsa_sha256: invalid RSA private key"));
    }

    // -------------------------------------------------------------------------
    // HMAC helpers
    // -------------------------------------------------------------------------
    #[test]
    fn hmac_sha256_filter() {
        let key = b"secret";
        let data = b"hi!";
        // expected value
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(data);
        let expect = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        assert_eq!(render(r#"{{ "hi!" | hmac_sha256: "secret" }}"#), expect);
    }

    #[test]
    fn hmac_sha256_b64key_filter() {
        // Key is base64-encoded; the filter must decode it to raw bytes before HMAC.
        let raw_key: &[u8] = &[0x00, 0x80, 0xFF, 0x42, 0xDE, 0xAD, 0xBE, 0xEF];
        let b64_key = general_purpose::STANDARD.encode(raw_key);

        let data = b"hello azure";
        let mut mac = Hmac::<Sha256>::new_from_slice(raw_key).unwrap();
        mac.update(data);
        let expect = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        let template = format!(r#"{{{{ "hello azure" | hmac_sha256_b64key: "{b64_key}" }}}}"#);
        assert_eq!(render(&template), expect);
    }

    #[test]
    fn hmac_sha384_filter() {
        let key = b"topsecret";
        let data = b"payload";
        let mut mac = Hmac::<Sha384>::new_from_slice(key).unwrap();
        mac.update(data);
        let expect = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        assert_eq!(render(r#"{{ "payload" | hmac_sha384: "topsecret" }}"#), expect);
    }

    #[test]
    fn hmac_sha384_hex_filter() {
        use std::fmt::Write as _;

        let key = b"topsecret";
        let data = b"payload";
        let mut mac = Hmac::<Sha384>::new_from_slice(key).unwrap();
        mac.update(data);

        let bytes = mac.finalize().into_bytes();
        let mut expect = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(&mut expect, "{byte:02x}");
        }

        assert_eq!(render(r#"{{ "payload" | hmac_sha384_hex: "topsecret" }}"#), expect);
    }

    // -------------------------------------------------------------------------
    // Random string
    // -------------------------------------------------------------------------
    #[test]
    fn random_string_filter_default_len() {
        let out = render(r#"{{ "" | random_string }}"#);
        assert_eq!(out.len(), 32);
        assert!(out.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_string_filter_custom_len() {
        let out = render(r#"{{ 10 | random_string }}"#);
        assert_eq!(out.len(), 10);
    }

    // -------------------------------------------------------------------------
    // Time helpers
    // -------------------------------------------------------------------------
    #[test]
    fn unix_timestamp_filter_is_nowish() {
        let tmpl_val: i64 = render(r#"{{ "" | unix_timestamp }}"#).parse().unwrap();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        assert!((now - tmpl_val).abs() < 5, "timestamp differs by >5 s");
    }

    #[test]
    fn unix_timestamp_ms_filter_is_nowish() {
        let tmpl_val: i64 = render(r#"{{ "" | unix_timestamp_ms }}"#).parse().unwrap();
        let now = (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64;
        assert!((now - tmpl_val).abs() < 5_000, "timestamp differs by >5 s");
    }

    #[test]
    fn iso_timestamp_filter_parses() {
        let out = render(r#"{{ "" | iso_timestamp }}"#);
        // Parse to make sure it’s valid ISO-8601
        assert!(OffsetDateTime::parse(&out, &Iso8601::DEFAULT).is_ok());
    }

    // -------------------------------------------------------------------------
    // UUID
    // -------------------------------------------------------------------------
    #[test]
    fn uuid_filter_format() {
        let uuid_re =
            Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
                .unwrap();
        let v = render(r#"{{ "" | uuid }}"#);
        assert!(uuid_re.is_match(&v));
    }

    #[test]
    fn bip39_valid_filter_accepts_standard_lengths_and_whitespace() {
        for phrase in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon address",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon admit",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        ] {
            assert_eq!(render(&format!(r#"{{{{ {phrase:?} | bip39_valid }}}}"#)), "true");
        }

        let spaced = "abandon  abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(render(&format!(r#"{{{{ "{spaced}" | bip39_valid }}}}"#)), "true");
    }

    #[test]
    fn bip39_valid_filter_rejects_bad_checksum_and_oversized_input() {
        assert_eq!(
            render(
                r#"{{ "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon" | bip39_valid }}"#
            ),
            "false"
        );
        let oversized = "abandon ".repeat(81);
        assert_eq!(render(&format!(r#"{{{{ {oversized:?} | bip39_valid }}}}"#)), "false");
    }

    #[test]
    fn bip39_valid_filter_is_boolean_in_conditionals() {
        assert_eq!(
            render(
                r#"{% assign valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | bip39_valid %}{% if valid %}valid{% else %}invalid{% endif %}"#
            ),
            "valid"
        );
        assert_eq!(
            render(
                r#"{% assign valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon" | bip39_valid %}{% if valid %}valid{% else %}invalid{% endif %}"#
            ),
            "invalid"
        );
    }

    #[test]
    fn rfc1123_date_filter_format() {
        let out = render(r#"{{ "" | rfc1123_date }}"#);
        assert!(out.ends_with(" GMT"), "unexpected RFC-1123 date: {out}");
        let normalized = out.replace(" GMT", " +0000");
        assert!(OffsetDateTime::parse(&normalized, &Rfc2822).is_ok());
    }
    // -------------------------------------------------------------------------
    // Replace filter
    // -------------------------------------------------------------------------
    #[test]
    fn replace_filter() {
        assert_eq!(render(r#"{{ "hello world" | replace: "world", "mars" }}"#), "hello mars");
    }

    #[test]
    fn lstrip_chars_single() {
        assert_eq!(render(r#"{{ "000abc" | lstrip_chars: "0" }}"#), "abc");
    }

    #[test]
    fn lstrip_chars_multiple_chars() {
        assert_eq!(render(r#"{{ "-=--token" | lstrip_chars: "-=" }}"#), "token");
    }

    // -------------------------------------------------------------------------
    // iso_timestamp_no_frac filter
    // -------------------------------------------------------------------------
    #[test]
    fn iso_timestamp_no_frac_filter() {
        let ts = render(r#"{{ "" | iso_timestamp_no_frac }}"#);
        assert!(!ts.contains('.'), "timestamp should not include fractional seconds: {ts}");
        // Verify it’s still valid ISO-8601
        assert!(OffsetDateTime::parse(&ts, &Iso8601::DEFAULT).is_ok());
    }
}
