//! Collection of small Liquid filters that make HTTP validations & API-signing templates easy

use base64::{engine::general_purpose, Engine};
use hmac::{Hmac, Mac};
use liquid_core::{
    Display_filter, Error as LiquidError, Expression, Filter, FilterParameters, FilterReflection,
    FromFilterParameters, ParseFilter, Result, Runtime, Value, ValueView,
};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use rand::{distr::Alphanumeric, Rng};
use sha2::{Digest, Sha256, Sha384};
use time::{format_description::well_known::Iso8601, OffsetDateTime};
use uuid::Uuid;

// -----------------------------------------------------------------------------
// Helper macro – keeps most filters <10 lines long
// -----------------------------------------------------------------------------
// -- filters.rs (or wherever the macro lives) -------------------------------
macro_rules! static_filter {
    // ── original, zero-arg variant ────────────────────────────────
    (
        $(#[$outer:meta])*
        $name:ident, $display:literal, $body:expr
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

    // -- NEW, second arm of the macro (add Default) ----------------------------
(
    $(#[$outer:meta])*
    $name:ident { $( $(#[$f_meta:meta])* $field:ident : $ty:ty ),+ $(,)? },
    $display:literal,
    $body:expr
) => {
    $(#[$outer])*
    #[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]   // ← added Default
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

// ── random_string ────────────────────────────────
static_filter!(
    /// Random alphanumeric string (default 32 chars).
    RandomStringFilter { len: Option<usize> },
    "random_string",
    |s: &RandomStringFilter, input: &dyn ValueView| -> String {
        let n = s.len                                   // explicit argument?
            .or_else(|| input.to_kstr().parse().ok())   // else parse input
            .unwrap_or(32);                             // else default

        rand::rng()
            .sample_iter(&Alphanumeric)
            .take(n)
            .map(char::from)
            .collect()
    }
);

#[derive(Debug, Clone, Default, FilterReflection, ParseFilter)]
#[filter(
    name = "b64enc",
    description = "Encodes the input string using Base64 encoding",
    parsed(B64EncFilter)
)]
// pub struct B64EncFilterParser;

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
        format!("{:x}", h.finalize())
    }
);

// {{ value | b64url_enc }} – URL-safe base64 w/o padding
static_filter!(
    /// Base64 URL-safe (no ‘=’ padding).
    B64UrlEncFilter, "b64url_enc",
    |input: &dyn ValueView| -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(input.to_kstr().as_bytes())
    }
);

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
        .filter(B64UrlEncFilter::default())
        .filter(Sha256Filter::default())
        .filter(UrlEncodeFilter::default())
        .filter(JsonEscapeFilter::default())
        .filter(UnixTimestampFilter::default())
        .filter(IsoTimestampFilter::default())
        .filter(UuidFilter::default())
        .filter(JwtHeaderFilter::default())
        .filter(B64EncFilter::default())
        .filter(RandomStringFilter::default())
        .filter(HmacSha256::default())
        .filter(HmacSha384::default())
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine as _};
    use hmac::{Hmac, Mac};
    use liquid::{object, ParserBuilder};
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    use regex::Regex;
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

    // -------------------------------------------------------------------------
    // Simple one-liner helpers
    // -------------------------------------------------------------------------
    #[test]
    fn b64enc_filter() {
        assert_eq!(render(r#"{{ "hello" | b64enc }}"#), "aGVsbG8=");
    }

    #[test]
    fn sha256_filter() {
        let expect = format!("{:x}", Sha256::digest(b"hello"));
        assert_eq!(render(r#"{{ "hello" | sha256 }}"#), expect);
    }

    #[test]
    fn b64url_enc_filter() {
        assert_eq!(
            render(r#"{{ "++??" | b64url_enc }}"#),
            general_purpose::URL_SAFE_NO_PAD.encode("++??")
        );
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
        let expect = general_purpose::URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"HS256"}"#);
        assert_eq!(render(r#"{{ "HS256" | jwt_header }}"#), expect);
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
    fn hmac_sha384_filter() {
        let key = b"topsecret";
        let data = b"payload";
        let mut mac = Hmac::<Sha384>::new_from_slice(key).unwrap();
        mac.update(data);
        let expect = general_purpose::STANDARD.encode(mac.finalize().into_bytes());

        assert_eq!(render(r#"{{ "payload" | hmac_sha384: "topsecret" }}"#), expect);
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
}
