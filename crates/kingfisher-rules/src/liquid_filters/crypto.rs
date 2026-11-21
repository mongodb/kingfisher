//! Binary-safe crypto adapters. Every binary argument/result is standard padded Base64;
//! no adapter passes binary data through the lossy, text-oriented `b64dec` filter.
//! EC private/public key arguments may also be PEM text, passed through unchanged.
//! All adapters share one cumulative work budget across a request's template renders.

use std::cell::RefCell;
use std::sync::{
    Arc, LazyLock, RwLock,
    atomic::{AtomicBool, Ordering},
};

use rustc_hash::FxHashMap;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use liquid_core::{
    Error, Expression, Filter, FilterParameters, FilterReflection, ParseFilter, Result, Runtime,
    Value, ValueView,
};
use sha2::{Digest, Sha384, Sha512};
use zeroize::Zeroizing;

use crate::crypto;

// Deliberately omit argument expressions from Display: Liquid adds this to error traces,
// and a literal expression may contain a private key or other sensitive input.
macro_rules! crypto_filter {
    ($name:ident, $parsed:ident, $args:ident, $display:literal) => {
        #[derive(Clone, FilterReflection, Default)]
        #[filter(name = $display, description = $display, parameters($args), parsed($parsed))]
        pub(super) struct $name;

        #[derive(Debug)]
        struct $parsed {
            args: $args,
        }

        // Implement this directly: liquid-derive's ParseFilter spans its generated `args`
        // identifier differently when parameters are supplied through a declarative macro.
        impl ParseFilter for $name {
            fn parse(
                &self,
                args: liquid_core::parser::FilterArguments<'_>,
            ) -> Result<Box<dyn Filter>> {
                Ok(Box::new($parsed { args: $args::from_args(args)? }))
            }

            fn reflection(&self) -> &dyn FilterReflection {
                self
            }
        }

        impl std::fmt::Display for $parsed {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($display)
            }
        }
    };
    ($name:ident, $display:literal) => {
        #[derive(Debug, Clone, ParseFilter, FilterReflection, Default)]
        #[filter(name = $display, description = $display, parsed($name))]
        pub(super) struct $name;

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($display)
            }
        }
    };
}

fn error(filter: &str, reason: &str) -> Error {
    Error::with_msg(format!("{filter}: {reason}"))
}

fn argument_error(filter: &str) -> Error {
    error(filter, "invalid arguments")
}

fn decode(value: &str, filter: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Own the destination before decoding, so even a partially decoded invalid key is wiped.
    let mut decoded = Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(value, &mut decoded)
        .map_err(|_| error(filter, "expected standard padded Base64"))?;
    Ok(decoded)
}

/// EC key input: pass PEM text through for the primitive to select the first matching
/// block, including when the bundle has an OpenSSL metadata preamble.
fn key(value: &str, filter: &str) -> Result<Zeroizing<Vec<u8>>> {
    if value.lines().any(|line| line.trim_start().starts_with("-----BEGIN ")) {
        Ok(Zeroizing::new(value.as_bytes().to_vec()))
    } else {
        decode(value, filter)
    }
}

thread_local! {
    static REQUEST_BUDGET: RefCell<Option<crypto::WorkBudget>> = const { RefCell::new(None) };
}

/// Share one crypto budget across the Liquid fields of a request attempt.
#[doc(hidden)]
#[derive(Default)]
pub struct TemplateWorkBudget(crypto::WorkBudget);

impl TemplateWorkBudget {
    /// Render one field, charging this request's remaining budget.
    pub fn render(
        &mut self,
        template: &liquid::Template,
        globals: &liquid::Object,
    ) -> Result<String> {
        // Liquid owns each render's runtime and registers. Install the request budget only
        // for this synchronous render so it never crosses an await or leaks to another render.
        struct Restore<'a> {
            current: &'a mut crypto::WorkBudget,
            previous: Option<crypto::WorkBudget>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                *self.current =
                    REQUEST_BUDGET.with(|budget| budget.replace(self.previous.take()).unwrap());
            }
        }
        let previous =
            REQUEST_BUDGET.with(|budget| budget.replace(Some(std::mem::take(&mut self.0))));
        let _restore = Restore { current: &mut self.0, previous };
        template.render(globals)
    }
}

fn charge(runtime: &dyn Runtime, filter: &str, data_len: usize, extra: u64) -> Result<()> {
    REQUEST_BUDGET
        .with(|budget| {
            if let Some(budget) = budget.borrow_mut().as_mut() {
                budget.charge(data_len, extra)
            } else {
                // Standalone renders still share a budget across all calls, including loops.
                runtime.registers().get_mut::<crypto::WorkBudget>().charge(data_len, extra)
            }
        })
        .map_err(|_| error(filter, "cryptographic work budget exceeded"))
}

fn length(value: i64, filter: &str) -> Result<usize> {
    let value = usize::try_from(value).map_err(|_| argument_error(filter))?;
    if value == 0 {
        return Err(argument_error(filter));
    }
    Ok(value)
}

fn binary_result(result: anyhow::Result<impl AsRef<[u8]>>, filter: &str) -> Result<Value> {
    let bytes = result.map_err(|_| error(filter, "cryptographic operation failed"))?;
    Ok(Value::scalar(STANDARD.encode(bytes)))
}

fn bool_result(result: anyhow::Result<bool>, filter: &str) -> Result<Value> {
    result.map(Value::scalar).map_err(|_| error(filter, "cryptographic operation failed"))
}

#[derive(Debug, FilterParameters)]
struct CurveArgs {
    #[parameter(description = "Curve: P-256, P-384, or X25519", arg_type = "str")]
    curve: Expression,
}

crypto_filter!(EcPublicKey, EcPublicKeyFilter, CurveArgs, "ec_public_key");

impl Filter for EcPublicKeyFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ec_public_key";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let private = key(&input.to_kstr(), filter)?;
        charge(runtime, filter, private.len(), crypto::ec_extra_work(&args.curve))?;
        binary_result(crypto::ec_public_key(&args.curve, &private), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct EcdhArgs {
    #[parameter(description = "Base64 private key", arg_type = "str")]
    private_key: Expression,
    #[parameter(description = "Curve: P-256, P-384, or X25519", arg_type = "str")]
    curve: Expression,
}

crypto_filter!(Ecdh, EcdhFilter, EcdhArgs, "ecdh");

impl Filter for EcdhFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ecdh";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let public = key(&input.to_kstr(), filter)?;
        let private = key(&args.private_key, filter)?;
        charge(runtime, filter, public.len() + private.len(), crypto::ec_extra_work(&args.curve))?;
        binary_result(crypto::ecdh(&args.curve, &private, &public), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct EcdsaSignArgs {
    #[parameter(description = "Base64 private key", arg_type = "str")]
    private_key: Expression,
    #[parameter(description = "Curve: P-256 or P-384", arg_type = "str")]
    curve: Expression,
    #[parameter(description = "Signature format: p1363 (default) or der", arg_type = "str")]
    format: Option<Expression>,
}

crypto_filter!(EcdsaSign, EcdsaSignFilter, EcdsaSignArgs, "ecdsa_sign");

impl Filter for EcdsaSignFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ecdsa_sign";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let message = decode(&input.to_kstr(), filter)?;
        let private = key(&args.private_key, filter)?;
        charge(runtime, filter, message.len() + private.len(), crypto::ec_extra_work(&args.curve))?;
        binary_result(
            crypto::ecdsa_sign(
                &args.curve,
                &private,
                &message,
                args.format.as_deref().unwrap_or("p1363"),
            ),
            filter,
        )
    }
}

#[derive(Debug, FilterParameters)]
struct EcdsaVerifyArgs {
    #[parameter(description = "Base64 public key", arg_type = "str")]
    public_key: Expression,
    #[parameter(description = "Base64 signature", arg_type = "str")]
    signature: Expression,
    #[parameter(description = "Curve: P-256 or P-384", arg_type = "str")]
    curve: Expression,
    #[parameter(description = "Signature format: p1363 (default) or der", arg_type = "str")]
    format: Option<Expression>,
}

crypto_filter!(EcdsaVerify, EcdsaVerifyFilter, EcdsaVerifyArgs, "ecdsa_verify");

impl Filter for EcdsaVerifyFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ecdsa_verify";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let message = decode(&input.to_kstr(), filter)?;
        let public = key(&args.public_key, filter)?;
        let signature = decode(&args.signature, filter)?;
        charge(
            runtime,
            filter,
            message.len() + public.len() + signature.len(),
            crypto::ec_extra_work(&args.curve),
        )?;
        bool_result(
            crypto::ecdsa_verify(
                &args.curve,
                &public,
                &message,
                &signature,
                args.format.as_deref().unwrap_or("p1363"),
            ),
            filter,
        )
    }
}

#[derive(Debug, FilterParameters)]
struct AesGcmArgs {
    #[parameter(description = "Base64 AES key (16 or 32 bytes)", arg_type = "str")]
    key: Expression,
    #[parameter(description = "Base64 nonce (12 bytes)", arg_type = "str")]
    nonce: Expression,
    #[parameter(description = "Base64 associated data (default empty)", arg_type = "str")]
    aad: Option<Expression>,
}

crypto_filter!(AesGcmEncrypt, AesGcmEncryptFilter, AesGcmArgs, "aes_gcm_encrypt");
crypto_filter!(AesGcmDecrypt, AesGcmDecryptFilter, AesGcmArgs, "aes_gcm_decrypt");

impl Filter for AesGcmEncryptFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "aes_gcm_encrypt";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let plaintext = decode(&input.to_kstr(), filter)?;
        let key = decode(&args.key, filter)?;
        let nonce = decode(&args.nonce, filter)?;
        let aad = decode(args.aad.as_deref().unwrap_or(""), filter)?;
        charge(runtime, filter, plaintext.len() + aad.len(), 0)?;
        binary_result(crypto::aes_gcm_encrypt(&key, &nonce, &plaintext, &aad), filter)
    }
}

impl Filter for AesGcmDecryptFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "aes_gcm_decrypt";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let ciphertext = decode(&input.to_kstr(), filter)?;
        let key = decode(&args.key, filter)?;
        let nonce = decode(&args.nonce, filter)?;
        let aad = decode(args.aad.as_deref().unwrap_or(""), filter)?;
        charge(runtime, filter, ciphertext.len() + aad.len(), 0)?;
        binary_result(crypto::aes_gcm_decrypt(&key, &nonce, &ciphertext, &aad), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct HkdfArgs {
    #[parameter(description = "Base64 salt", arg_type = "str")]
    salt: Expression,
    #[parameter(description = "Base64 info", arg_type = "str")]
    info: Expression,
    #[parameter(description = "Output length in bytes (1..8160)", arg_type = "integer")]
    length: Expression,
}

crypto_filter!(HkdfSha256, HkdfSha256Filter, HkdfArgs, "hkdf_sha256");

impl Filter for HkdfSha256Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "hkdf_sha256";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let ikm = decode(&input.to_kstr(), filter)?;
        let salt = decode(&args.salt, filter)?;
        let info = decode(&args.info, filter)?;
        let output = length(args.length, filter)?;
        charge(
            runtime,
            filter,
            ikm.len().saturating_add(salt.len()).saturating_add(info.len()).saturating_add(output),
            crypto::hkdf_extra_work(info.len() as u64, output as u64),
        )?;
        binary_result(crypto::hkdf_sha256(&ikm, &salt, &info, output), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct Pbkdf2Args {
    #[parameter(description = "Base64 salt", arg_type = "str")]
    salt: Expression,
    #[parameter(description = "Iteration count (1..1000000)", arg_type = "integer")]
    iterations: Expression,
    #[parameter(description = "Output length in bytes (1..65536)", arg_type = "integer")]
    length: Expression,
}

crypto_filter!(Pbkdf2Sha256, Pbkdf2Sha256Filter, Pbkdf2Args, "pbkdf2_sha256");

impl Filter for Pbkdf2Sha256Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "pbkdf2_sha256";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let password = decode(&input.to_kstr(), filter)?;
        let salt = decode(&args.salt, filter)?;
        let iterations = u32::try_from(args.iterations).map_err(|_| argument_error(filter))?;
        let output = length(args.length, filter)?;
        let work =
            crypto::pbkdf2_extra_work(salt.len() as u64, u64::from(iterations), output as u64);
        charge(
            runtime,
            filter,
            password.len().saturating_add(salt.len()).saturating_add(output),
            work,
        )?;
        binary_result(crypto::pbkdf2_sha256(&password, &salt, iterations, output), filter)
    }
}

crypto_filter!(Ed25519PublicKey, "ed25519_public_key");

impl Filter for Ed25519PublicKey {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ed25519_public_key";
        let seed = decode(&input.to_kstr(), filter)?;
        charge(runtime, filter, seed.len(), crypto::ED25519_EXTRA_WORK)?;
        binary_result(crypto::ed25519_public_key(&seed), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct Ed25519SignArgs {
    #[parameter(description = "Base64 Ed25519 seed (32 bytes)", arg_type = "str")]
    seed: Expression,
}

crypto_filter!(Ed25519Sign, Ed25519SignFilter, Ed25519SignArgs, "ed25519_sign");

impl Filter for Ed25519SignFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ed25519_sign";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let message = decode(&input.to_kstr(), filter)?;
        let seed = decode(&args.seed, filter)?;
        charge(runtime, filter, message.len() + seed.len(), crypto::ED25519_EXTRA_WORK)?;
        binary_result(crypto::ed25519_sign(&seed, &message), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct Ed25519VerifyArgs {
    #[parameter(description = "Base64 Ed25519 public key (32 bytes)", arg_type = "str")]
    public_key: Expression,
    #[parameter(description = "Base64 Ed25519 signature (64 bytes)", arg_type = "str")]
    signature: Expression,
}

crypto_filter!(Ed25519Verify, Ed25519VerifyFilter, Ed25519VerifyArgs, "ed25519_verify");

impl Filter for Ed25519VerifyFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "ed25519_verify";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let message = decode(&input.to_kstr(), filter)?;
        let public = decode(&args.public_key, filter)?;
        let signature = decode(&args.signature, filter)?;
        charge(
            runtime,
            filter,
            message.len() + public.len() + signature.len(),
            crypto::ED25519_EXTRA_WORK,
        )?;
        bool_result(crypto::ed25519_verify(&public, &message, &signature), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct RandomBytesArgs {
    #[parameter(description = "Output length in bytes (1..65536)", arg_type = "integer")]
    length: Expression,
}

crypto_filter!(RandomBytes, RandomBytesFilter, RandomBytesArgs, "random_bytes");

impl Filter for RandomBytesFilter {
    fn evaluate(&self, _input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "random_bytes";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let output = length(args.length, filter)?;
        charge(runtime, filter, output, 0)?;
        binary_result(crypto::random_bytes(output), filter)
    }
}

#[derive(Debug, FilterParameters)]
struct ConstantTimeEqArgs {
    #[parameter(description = "Base64 value to compare", arg_type = "str")]
    other: Expression,
}

crypto_filter!(ConstantTimeEq, ConstantTimeEqFilter, ConstantTimeEqArgs, "constant_time_eq");

impl Filter for ConstantTimeEqFilter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "constant_time_eq";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let left = decode(&input.to_kstr(), filter)?;
        let right = decode(&args.other, filter)?;
        charge(runtime, filter, left.len() + right.len(), 0)?;
        Ok(Value::scalar(crypto::constant_time_eq(&left, &right)))
    }
}

crypto_filter!(Sha384Hex, "sha384");
crypto_filter!(Sha512Hex, "sha512");

impl Filter for Sha384Hex {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let input = input.to_kstr();
        charge(runtime, "sha384", input.len(), 0)?;
        Ok(Value::scalar(hex::encode(Sha384::digest(input.as_bytes()))))
    }
}

impl Filter for Sha512Hex {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let input = input.to_kstr();
        charge(runtime, "sha512", input.len(), 0)?;
        Ok(Value::scalar(hex::encode(Sha512::digest(input.as_bytes()))))
    }
}

#[derive(Debug, FilterParameters)]
struct HmacSha512Args {
    #[parameter(description = "HMAC text key", arg_type = "str")]
    key: Expression,
}

crypto_filter!(HmacSha512, HmacSha512Filter, HmacSha512Args, "hmac_sha512");

impl Filter for HmacSha512Filter {
    fn evaluate(&self, input: &dyn ValueView, runtime: &dyn Runtime) -> Result<Value> {
        let filter = "hmac_sha512";
        let args = self.args.evaluate(runtime).map_err(|_| argument_error(filter))?;
        let input = input.to_kstr();
        charge(runtime, filter, args.key.len() + input.len(), 0)?;
        let mut mac = Hmac::<Sha512>::new_from_slice(args.key.as_bytes())
            .map_err(|_| argument_error(filter))?;
        mac.update(input.as_bytes());
        Ok(Value::scalar(STANDARD.encode(mac.finalize().into_bytes())))
    }
}

/// Names of the filters that use the cumulative budget and require strict rendering.
const FILTER_NAMES: &[&str] = &[
    "ecdh",
    "ec_public_key",
    "ecdsa_sign",
    "ecdsa_verify",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "hkdf_sha256",
    "pbkdf2_sha256",
    "ed25519_public_key",
    "ed25519_sign",
    "ed25519_verify",
    "random_bytes",
    "constant_time_eq",
    "sha384",
    "sha512",
    "hmac_sha512",
];

/// Whether executable Liquid syntax applies one of the newly introduced crypto filters.
/// Plain text, raw/comment blocks, and string literals do not opt legacy rules into crypto
/// handling. Classification does not validate arity or render anything: malformed crypto
/// applications must still let callers fail parsing closed.
pub fn template_uses_crypto_filters(template: &str) -> bool {
    if !template.contains('|') {
        return false;
    }
    // Validation asks this for every header of every request, but the answer depends only on
    // the rule-defined template. Memoize so the classifier parser is built once per template.
    // Templates come from loaded rules, so the set is small; stop caching if it ever is not.
    const MAX_CACHED_TEMPLATES: usize = 4_096;
    static CACHE: LazyLock<RwLock<FxHashMap<String, bool>>> = LazyLock::new(Default::default);
    if let Some(&found) = CACHE.read().unwrap_or_else(|e| e.into_inner()).get(template) {
        return found;
    }
    let found = classify_crypto_filters(template);
    let mut cache = CACHE.write().unwrap_or_else(|e| e.into_inner());
    if cache.len() < MAX_CACHED_TEMPLATES {
        cache.insert(template.to_owned(), found);
    }
    found
}

fn classify_crypto_filters(template: &str) -> bool {
    let found = Arc::new(AtomicBool::new(false));
    // Liquid's standalone lexer is private. A non-rendered custom block exposes its public
    // TagBlock/BlockElement tokenizer, including whitespace control and multiline syntax.
    // Neither wrapper delimiter may occur in the original source (even inside comments).
    let mut start_tag = "__kingfisher_crypto_classifier".to_owned();
    while template.contains(&start_tag) {
        start_tag.push('_');
    }
    let end_tag = format!("end{start_tag}");
    let source = format!("{{% {start_tag} %}}{template}{{% {end_tag} %}}");
    let classifier = CryptoFilterClassifier { start_tag, end_tag, found: Arc::clone(&found) };
    let parser = liquid::ParserBuilder::with_stdlib().block(classifier).build().unwrap();
    // Parsing errors do not erase crypto applications already recognized. In particular,
    // classification never invokes a filter parser that could reject missing arguments.
    let _ = parser.parse(&source);
    found.load(Ordering::Relaxed)
}

#[derive(Clone)]
struct CryptoFilterClassifier {
    start_tag: String,
    end_tag: String,
    found: Arc<AtomicBool>,
}

impl liquid_core::parser::BlockReflection for CryptoFilterClassifier {
    fn start_tag(&self) -> &str {
        &self.start_tag
    }

    fn end_tag(&self) -> &str {
        &self.end_tag
    }

    fn description(&self) -> &str {
        "Non-rendered cryptographic filter classifier"
    }
}

impl liquid_core::parser::ParseBlock for CryptoFilterClassifier {
    fn parse(
        &self,
        mut arguments: liquid_core::parser::TagTokenIter<'_>,
        mut block: liquid_core::parser::TagBlock<'_, '_>,
        options: &liquid_core::parser::Language,
    ) -> Result<Box<dyn liquid_core::Renderable>> {
        use liquid_core::parser::BlockElement;

        arguments.expect_nothing()?;
        let mut malformed = String::new();
        while let Some(element) = block.next()? {
            match element {
                BlockElement::Invalid(invalid) => malformed.push_str(invalid.as_str()),
                BlockElement::Raw(raw) => {
                    if !malformed.is_empty() {
                        malformed.push_str(raw.as_str());
                    }
                }
                element => {
                    if filter_application_in(&malformed) {
                        self.found.store(true, Ordering::Relaxed);
                    }
                    malformed.clear();
                    match element {
                        BlockElement::Expression(expression) => {
                            if filter_application_in(expression.as_str()) {
                                self.found.store(true, Ordering::Relaxed);
                            }
                        }
                        BlockElement::Tag(tag) if matches!(tag.name(), "raw" | "comment") => {
                            // Delegate ignored-block semantics (including nested comments and
                            // raw blocks inside comments) to Liquid, not a parallel hand grammar.
                            tag.parse(&mut block, options)?;
                        }
                        BlockElement::Tag(tag) => {
                            if filter_application_in(tag.as_str()) {
                                self.found.store(true, Ordering::Relaxed);
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        if filter_application_in(&malformed) {
            self.found.store(true, Ordering::Relaxed);
        }
        block.assert_empty();
        Ok(Box::new(liquid_core::runtime::Template::new(Vec::new())))
    }

    fn reflection(&self) -> &dyn liquid_core::parser::BlockReflection {
        self
    }
}

/// Recognize filter-name tokens only inside an output/tag element supplied by Liquid.
/// Its string-literal grammar has no backslash escapes, so matching quotes end literals.
/// Stop at the element's closing delimiter when inspecting a malformed lexer fragment.
fn filter_application_in(element: &str) -> bool {
    let element = element.trim_start();
    let closing = if element.starts_with("{{") {
        "}}"
    } else if element.starts_with("{%") {
        "%}"
    } else {
        return false;
    };
    let mut quote = None;
    for (index, ch) in element.char_indices() {
        if let Some(expected) = quote {
            if ch == expected {
                quote = None;
            }
            continue;
        }
        if element[index..].starts_with(closing) {
            break;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch == '|' {
            let after = element[index + 1..].trim_start();
            let end = after
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-')))
                .unwrap_or(after.len());
            let name = &after[..end];
            if FILTER_NAMES.contains(&name) {
                return true;
            }
        }
    }
    false
}

pub(super) fn register_all(builder: liquid::ParserBuilder) -> liquid::ParserBuilder {
    builder
        .filter(Ecdh)
        .filter(EcPublicKey)
        .filter(EcdsaSign)
        .filter(EcdsaVerify)
        .filter(AesGcmEncrypt)
        .filter(AesGcmDecrypt)
        .filter(HkdfSha256)
        .filter(Pbkdf2Sha256)
        .filter(Ed25519PublicKey)
        .filter(Ed25519Sign)
        .filter(Ed25519Verify)
        .filter(RandomBytes)
        .filter(ConstantTimeEq)
}

#[cfg(test)]
mod tests {
    use liquid::object;

    use super::*;

    fn render(source: &str, globals: &liquid::Object) -> Result<String> {
        crate::liquid_filters::register_all(liquid::ParserBuilder::with_stdlib())
            .build()
            .unwrap()
            .parse(source)
            .unwrap()
            .render(globals)
    }

    fn b64hex(value: &str) -> String {
        STANDARD.encode(hex::decode(value).unwrap())
    }

    #[test]
    fn registered_ec_public_key_and_ecdh_match_rfc7748() {
        let private = b64hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let public = b64hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let peer = b64hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared = b64hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        let globals = object!({"PRIVATE": private, "PEER": peer});
        assert_eq!(render("{{ PRIVATE | ec_public_key: 'X25519' }}", &globals).unwrap(), public);
        assert_eq!(render("{{ PEER | ecdh: PRIVATE, 'X25519' }}", &globals).unwrap(), shared);
    }

    #[test]
    fn ecdsa_filter_defaults_and_explicit_formats_are_binary_safe() {
        let message = STANDARD.encode(b"\0\xff\x80binary message");
        for (curve, length) in [("P-256", 32), ("P-384", 48)] {
            let mut private = vec![0; length];
            private[length - 1] = 1;
            let public = crypto::ec_public_key(curve, &private).unwrap();
            let mut globals = object!({
                "MESSAGE": message,
                "PRIVATE": STANDARD.encode(&private),
                "PUBLIC": STANDARD.encode(public),
                "CURVE": curve,
            });
            for format_arg in ["", ", 'p1363'", ", 'der'"] {
                let signature = render(
                    &format!("{{{{ MESSAGE | ecdsa_sign: PRIVATE, CURVE{format_arg} }}}}"),
                    &globals,
                )
                .unwrap();
                let bytes = STANDARD.decode(&signature).unwrap();
                if format_arg.contains("der") {
                    assert_eq!(bytes[0], 0x30);
                } else {
                    assert_eq!(bytes.len(), length * 2);
                }
                globals.insert("SIGNATURE".into(), Value::scalar(signature));
                let verify = format!(
                    "{{{{ MESSAGE | ecdsa_verify: PUBLIC, SIGNATURE, CURVE{format_arg} }}}}"
                );
                assert_eq!(render(&verify, &globals).unwrap(), "true");
                globals.insert("MESSAGE".into(), Value::scalar(STANDARD.encode(b"changed")));
                assert_eq!(render(&verify, &globals).unwrap(), "false");
                globals.insert("MESSAGE".into(), Value::scalar(message.clone()));
            }
        }
    }

    #[test]
    fn aes_gcm_filters_match_nist_and_preserve_non_utf8_plaintext() {
        let globals = object!({"PLAINTEXT": STANDARD.encode([0; 16]), "KEY": STANDARD.encode([0; 16]), "NONCE": STANDARD.encode([0; 12])});
        let expected = b64hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
        assert_eq!(
            render("{{ PLAINTEXT | aes_gcm_encrypt: KEY, NONCE }}", &globals).unwrap(),
            expected
        );
        assert_eq!(
            render("{{ PLAINTEXT | aes_gcm_encrypt: KEY, NONCE, '' }}", &globals).unwrap(),
            expected
        );
        let binary = STANDARD.encode(b"\0\xff\x80\xc0\xfe\0");
        let globals = object!({"PLAINTEXT": binary, "KEY": STANDARD.encode([0x11; 32]), "NONCE": STANDARD.encode([0x22; 12]), "AAD": STANDARD.encode(b"\xff\0metadata")});
        let pipeline =
            "{{ PLAINTEXT | aes_gcm_encrypt: KEY, NONCE, AAD | aes_gcm_decrypt: KEY, NONCE, AAD }}";
        assert_eq!(render(pipeline, &globals).unwrap(), binary);
        let bad_aad =
            "{{ PLAINTEXT | aes_gcm_encrypt: KEY, NONCE, AAD | aes_gcm_decrypt: KEY, NONCE, '' }}";
        assert!(render(bad_aad, &globals).is_err());
    }

    #[test]
    fn kdf_filters_match_known_answers() {
        let globals = object!({
            "IKM": STANDARD.encode([0x0b; 22]),
            "SALT": b64hex("000102030405060708090a0b0c"),
            "INFO": b64hex("f0f1f2f3f4f5f6f7f8f9"),
        });
        assert_eq!(
            render("{{ IKM | hkdf_sha256: SALT, INFO, 42 }}", &globals).unwrap(),
            b64hex(concat!(
                "3cb25f25faacd57a90434f64d0362f2a",
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf",
                "34007208d5b887185865"
            ))
        );
        let globals =
            object!({"PASSWORD": STANDARD.encode(b"password"), "SALT": STANDARD.encode(b"salt")});
        assert_eq!(
            render("{{ PASSWORD | pbkdf2_sha256: SALT, 2, 32 }}", &globals).unwrap(),
            b64hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    fn ed25519_filters_match_rfc8032() {
        let seed = b64hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let public = b64hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = b64hex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ));
        let globals = object!({"SEED": seed, "PUBLIC": public, "SIGNATURE": signature});
        assert_eq!(render("{{ SEED | ed25519_public_key }}", &globals).unwrap(), public);
        assert_eq!(render("{{ '' | ed25519_sign: SEED }}", &globals).unwrap(), signature);
        assert_eq!(
            render("{{ '' | ed25519_verify: PUBLIC, SIGNATURE }}", &globals).unwrap(),
            "true"
        );
        assert_eq!(
            render("{{ 'AA==' | ed25519_verify: PUBLIC, SIGNATURE }}", &globals).unwrap(),
            "false"
        );
    }

    #[test]
    fn random_and_comparison_filters_are_registered_and_binary_safe() {
        let globals = object!({"LEFT": STANDARD.encode(b"\0\xff\x80"), "RIGHT": STANDARD.encode(b"\0\xff\x81")});
        assert_eq!(render("{{ LEFT | constant_time_eq: LEFT }}", &globals).unwrap(), "true");
        assert_eq!(render("{{ LEFT | constant_time_eq: RIGHT }}", &globals).unwrap(), "false");
        assert_eq!(render("{{ LEFT | constant_time_eq: '' }}", &globals).unwrap(), "false");
        assert_eq!(render("{{ '' | constant_time_eq: '' }}", &globals).unwrap(), "true");
        let random = render("{{ '' | random_bytes: 32 }}", &globals).unwrap();
        assert_eq!(STANDARD.decode(&random).unwrap().len(), 32);
        assert!(random.ends_with('='));
    }

    #[test]
    fn binary_filters_reject_nonstandard_or_unpadded_base64() {
        for invalid in ["Zg", "_w==", "/x==", "AA=", "AA==\n", "!!private-marker!!"] {
            let globals = object!({"INVALID": invalid, "VALID": STANDARD.encode([1; 32]), "NONCE": STANDARD.encode([2; 12])});
            for source in [
                "{{ INVALID | ec_public_key: 'P-256' }}",
                "{{ VALID | ecdh: INVALID, 'X25519' }}",
                "{{ '' | ecdsa_sign: INVALID, 'P-256' }}",
                "{{ INVALID | ecdsa_verify: VALID, '', 'P-256' }}",
                "{{ '' | ecdsa_verify: INVALID, '', 'P-256' }}",
                "{{ '' | ecdsa_verify: VALID, INVALID, 'P-256' }}",
                "{{ INVALID | aes_gcm_encrypt: VALID, NONCE }}",
                "{{ '' | aes_gcm_encrypt: INVALID, NONCE }}",
                "{{ '' | aes_gcm_encrypt: VALID, INVALID }}",
                "{{ '' | aes_gcm_encrypt: VALID, NONCE, INVALID }}",
                "{{ INVALID | aes_gcm_decrypt: VALID, NONCE }}",
                "{{ INVALID | hkdf_sha256: '', '', 32 }}",
                "{{ '' | hkdf_sha256: INVALID, '', 32 }}",
                "{{ '' | hkdf_sha256: '', INVALID, 32 }}",
                "{{ INVALID | pbkdf2_sha256: '', 1, 32 }}",
                "{{ '' | pbkdf2_sha256: INVALID, 1, 32 }}",
                "{{ INVALID | ed25519_public_key }}",
                "{{ INVALID | ed25519_sign: VALID }}",
                "{{ '' | ed25519_sign: INVALID }}",
                "{{ '' | ed25519_verify: INVALID, '' }}",
                "{{ '' | ed25519_verify: VALID, INVALID }}",
                "{{ INVALID | constant_time_eq: '' }}",
                "{{ '' | constant_time_eq: INVALID }}",
            ] {
                let error = render(source, &globals).unwrap_err().to_string();
                assert!(error.contains("expected standard padded Base64"), "{source}: {error}");
                // FilterChain itself adds the input to its error; Kingfisher's render
                // boundaries sanitize that outer context. Direct filter errors are tested below.
            }
        }
    }

    #[test]
    fn bounds_invalid_options_and_crypto_errors_fail_closed() {
        let marker = "sensitive-value-marker";
        let globals = object!({
            "VALUE": STANDARD.encode(marker), "RAW": marker,
            "KEY": STANDARD.encode([1; 32]), "NONCE": STANDARD.encode([2; 12]),
        });
        for source in [
            "{{ KEY | ec_public_key: RAW }}",
            "{{ VALUE | ec_public_key: 'P-256' }}",
            "{{ VALUE | ecdh: KEY, 'X25519' }}",
            "{{ VALUE | ecdsa_sign: KEY, 'P-256', RAW }}",
            "{{ VALUE | aes_gcm_decrypt: KEY, NONCE }}",
            "{{ VALUE | aes_gcm_encrypt: VALUE, NONCE }}",
            "{{ VALUE | aes_gcm_encrypt: KEY, VALUE }}",
            "{{ VALUE | ed25519_public_key }}",
            "{{ VALUE | ed25519_sign: VALUE }}",
            "{{ VALUE | ed25519_verify: VALUE, VALUE }}",
            "{{ '' | random_bytes: RAW }}",
        ] {
            let error = render(source, &globals).unwrap_err().to_string();
            assert!(!error.contains("KeyRejected"), "{source}: {error}");
        }
        for source in [
            "{{ '' | random_bytes: -1 }}",
            "{{ '' | random_bytes: 0 }}",
            "{{ '' | random_bytes: 65537 }}",
            "{{ '' | hkdf_sha256: '', '', 0 }}",
            "{{ '' | hkdf_sha256: '', '', -1 }}",
            "{{ '' | hkdf_sha256: '', '', 8161 }}",
            "{{ '' | pbkdf2_sha256: '', 0, 32 }}",
            "{{ '' | pbkdf2_sha256: '', -1, 32 }}",
            "{{ '' | pbkdf2_sha256: '', 1000001, 32 }}",
            "{{ '' | pbkdf2_sha256: '', 4294967296, 32 }}",
            "{{ '' | pbkdf2_sha256: '', 1, 0 }}",
            "{{ '' | pbkdf2_sha256: '', 1, -1 }}",
            "{{ '' | pbkdf2_sha256: '', 1, 65537 }}",
            "{{ '' | pbkdf2_sha256: '', 1000000, 129 }}",
        ] {
            assert!(render(source, &globals).is_err(), "{source}");
        }
    }

    #[test]
    fn direct_filter_errors_do_not_disclose_inputs_or_arguments() {
        // Test adapter errors before Liquid's FilterChain adds its own input context.
        // Kingfisher sanitizes that additional context at each application render boundary.
        let marker = "sensitive-value-marker";
        let encoded = STANDARD.encode(marker);
        let key = STANDARD.encode([1; 32]);
        let nonce = STANDARD.encode([2; 12]);
        let text = |value: &str| Expression::with_literal(value.to_owned());
        let cases: Vec<Box<dyn Filter>> = vec![
            Box::new(EcPublicKeyFilter { args: CurveArgs { curve: text("P-256") } }),
            Box::new(EcdhFilter {
                args: EcdhArgs { private_key: text(key.as_str()), curve: text("X25519") },
            }),
            Box::new(EcdsaSignFilter {
                args: EcdsaSignArgs {
                    private_key: text(encoded.as_str()),
                    curve: text("P-256"),
                    format: None,
                },
            }),
            Box::new(EcdsaVerifyFilter {
                args: EcdsaVerifyArgs {
                    public_key: text(encoded.as_str()),
                    signature: text(""),
                    curve: text("P-256"),
                    format: None,
                },
            }),
            Box::new(AesGcmEncryptFilter {
                args: AesGcmArgs {
                    key: text(encoded.as_str()),
                    nonce: text(nonce.as_str()),
                    aad: None,
                },
            }),
            Box::new(AesGcmDecryptFilter {
                args: AesGcmArgs {
                    key: text(key.as_str()),
                    nonce: text(nonce.as_str()),
                    aad: None,
                },
            }),
            Box::new(HkdfSha256Filter {
                args: HkdfArgs {
                    salt: text(""),
                    info: text(""),
                    length: Expression::with_literal(0),
                },
            }),
            Box::new(Pbkdf2Sha256Filter {
                args: Pbkdf2Args {
                    salt: text(""),
                    iterations: Expression::with_literal(0),
                    length: Expression::with_literal(32),
                },
            }),
            Box::new(Ed25519PublicKey),
            Box::new(Ed25519SignFilter { args: Ed25519SignArgs { seed: text(encoded.as_str()) } }),
            Box::new(Ed25519VerifyFilter {
                args: Ed25519VerifyArgs { public_key: text(encoded.as_str()), signature: text("") },
            }),
            Box::new(RandomBytesFilter { args: RandomBytesArgs { length: text(marker) } }),
            Box::new(ConstantTimeEqFilter { args: ConstantTimeEqArgs { other: text(marker) } }),
        ];
        let runtime = liquid_core::runtime::RuntimeBuilder::new().build();
        for filter in cases {
            let error =
                filter.evaluate(&Value::scalar(encoded.clone()), &runtime).unwrap_err().to_string();
            assert!(!error.contains(marker), "{filter}: {error}");
            assert!(!error.contains(&encoded), "{filter}: {error}");
            assert!(!error.contains("KeyRejected"), "{filter}: {error}");
            let error = filter.evaluate(&Value::scalar(marker), &runtime).unwrap_err().to_string();
            assert!(!error.contains(marker), "{filter}: {error}");
            assert!(!error.contains(&encoded), "{filter}: {error}");
        }
    }

    #[test]
    fn literal_secret_arguments_are_not_in_crypto_error_traces() {
        let private = "literal-private-key-marker";
        let encoded = STANDARD.encode(private);
        let nonce = STANDARD.encode([2; 12]);
        for secret in [private, encoded.as_str()] {
            for source in [
                format!("{{{{ '' | ed25519_sign: '{secret}' }}}}"),
                format!("{{{{ '' | ecdsa_sign: '{secret}', 'P-256' }}}}"),
                format!("{{{{ '' | aes_gcm_encrypt: '{secret}', '{nonce}' }}}}"),
            ] {
                let error = render(&source, &object!({})).unwrap_err().to_string();
                assert!(!error.contains(private), "{error}");
                assert!(!error.contains(&encoded), "{error}");
            }
        }
    }

    #[test]
    fn crypto_filter_detection_matches_registered_names() {
        for name in FILTER_NAMES {
            assert!(template_uses_crypto_filters(&format!("{{{{ x |{name}: 'a' }}}}")), "{name}");
        }
        assert!(template_uses_crypto_filters("{{ A | b64enc | ecdsa_sign: K, 'P-256' }}"));
        assert!(!template_uses_crypto_filters("{{ TOKEN | sha256 | b64enc }}"));
        assert!(!template_uses_crypto_filters("{{ TOKEN | hmac_sha384: KEY }}"));
        assert!(!template_uses_crypto_filters("Bearer {{ TOKEN }}"));
        let checksum =
            crate::liquid_filters::register_checksum_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        for source in [
            "{{ TOKEN | ed25519_public_key }}",
            "{{ TOKEN | random_bytes: 16 }}",
            "{{ TOKEN | pbkdf2_sha256: '', 1, 32 }}",
        ] {
            assert!(checksum.parse(source).is_err(), "{source}");
        }
    }

    #[test]
    fn crypto_filter_detection_ignores_non_executable_and_legacy_pipes() {
        for source in [
            "literal | sha512 and | ecdsa_sign",
            "Bearer {{ TOKEN }} | sha512",
            "{{ '| sha512' }}",
            "{{ \"| ec_public_key\" | sha256 }}",
            "{{ TOKEN | append: '| ed25519_sign' }}",
            "{{ TABLE['| sha512'] }}",
            "{% assign text = '| ecdsa_sign' %}{{ text }}",
            "{% capture text %}| sha512{% endcapture %}{{ text }}",
            "{% raw %}{{ TOKEN | sha512 }}{% assign x = TOKEN | ecdsa_sign %}{% endraw %}",
            "{%- raw -%}{{ TOKEN | ed25519_sign: }}{%- endraw -%}",
            "{% comment %}{{ TOKEN | sha512 }}{% comment %}| sha384{% endcomment %}{% endcomment %}",
            "{% comment %}{% raw %}{% endcomment %}{{ TOKEN | sha512 }}{% endraw %}{% endcomment %}",
            "{{ TOKEN | sha512_other }}",
            "{{ TOKEN | sha512-other }}",
            "{{ TOKEN | unknown: '| sha512' }}",
            "{{ TOKEN | unknown: }} plain | sha512",
        ] {
            assert!(!template_uses_crypto_filters(source), "{source}");
        }
        for name in
            ["sha1", "sha256", "hmac_sha1", "hmac_sha256", "hmac_sha384", "rsa_sha256", "jwt_sign"]
        {
            for source in [
                format!("{{{{ TOKEN | {name} }}}}"),
                format!("{{% assign value = TOKEN | {name} %}}"),
            ] {
                assert!(!template_uses_crypto_filters(&source), "{source}");
            }
        }
    }

    #[test]
    fn crypto_filter_detection_recognizes_output_tags_and_malformed_applications() {
        for source in [
            "{{ TOKEN | ecdsa_sign: KEY }}", // Missing required curve.
            "{% assign sig = TOKEN | ecdsa_sign: KEY %}",
            "{{ TOKEN | ed25519_sign }}", // Missing required seed.
            "{%- assign key = TOKEN\n | ec_public_key -%}",
            "{{- TOKEN\n | hkdf_sha256: SALT, INFO, 32 -}}",
            "{% if FLAG %}{{ TOKEN | sha512 }}{% endif %}",
            "{% capture digest %}{{ TOKEN | sha512 }}{% endcapture %}",
            "{{ '| sha512' | append: '| ecdsa_sign' | sha384 }}",
            "{{ TOKEN | ecdsa_sign: }}", // Invalid lexer fragment, not just invalid arity.
            "{% assign sig = TOKEN | ecdsa_sign: %}",
            "{% raw %}ignored{% endraw %}{{ TOKEN | sha512 }}",
            "{{ TOKEN | sha512 }}\0",
            "{% comment %}__kingfisher_crypto_classifier{% endcomment %}{{ TOKEN | sha512 }}",
        ] {
            assert!(template_uses_crypto_filters(source), "{source}");
        }
    }

    #[test]
    fn liquid_kdf_adapters_reject_repeated_input_undercharge() {
        let globals = object!({
            "PASSWORD": STANDARD.encode(b"p"),
            "SALT": STANDARD.encode(vec![0; 40 * 1024]),
            "INFO": STANDARD.encode(vec![0; 384 * 1024]),
        });
        for source in [
            "{{ PASSWORD | pbkdf2_sha256: SALT, 1, 65536 }}",
            "{{ PASSWORD | hkdf_sha256: '', INFO, 8160 }}",
        ] {
            let error = render(source, &globals).unwrap_err().to_string();
            assert!(error.contains("cryptographic work budget exceeded"), "{source}: {error}");
        }
    }

    #[test]
    fn render_wide_budget_bounds_liquid_loops() {
        let loop_of = |count: usize| {
            format!("{{% for i in (1..{count}) %}}{{{{ 'x' | sha384 | size }}}}{{% endfor %}}")
        };
        assert!(render(&loop_of(100), &object!({})).is_ok());
        let error = render(&loop_of(6_000), &object!({})).unwrap_err().to_string();
        assert!(error.contains("cryptographic work budget exceeded"), "{error}");
        // Each render starts with a fresh budget.
        assert!(render(&loop_of(100), &object!({})).is_ok());
    }

    #[test]
    fn request_budget_accumulates_across_template_renders() {
        let parser = crate::liquid_filters::register_all(liquid::ParserBuilder::with_stdlib())
            .build()
            .unwrap();
        let template = parser.parse("{{ 'abc' | sha384 }}").unwrap();
        let globals = object!({});
        let mut budget = TemplateWorkBudget::default();
        budget.0.charge(0, crypto::MAX_PROGRAM_WORK - 2000).unwrap();
        assert!(budget.render(&template, &globals).is_ok());
        assert!(budget.render(&template, &globals).is_err());
        assert!(template.render(&globals).is_ok());
    }

    #[test]
    fn ec_key_arguments_accept_pem_text() {
        use aws_lc_rs::agreement;
        use aws_lc_rs::encoding::{AsDer, EcPrivateKeyRfc5915Der, PublicKeyX509Der};

        let mut raw = [0u8; 32];
        raw[31] = 7;
        let private = agreement::PrivateKey::from_private_key(&agreement::ECDH_P256, &raw).unwrap();
        let der: EcPrivateKeyRfc5915Der = private.as_der().unwrap();
        let private_pem = format!(
            "Bag Attributes\n    friendlyName: example\n{}",
            pem::encode(&pem::Pem::new("EC PRIVATE KEY", der.as_ref()))
        );
        let public = private.compute_public_key().unwrap();
        let spki: PublicKeyX509Der = public.as_der().unwrap();
        let public_pem = pem::encode(&pem::Pem::new("PUBLIC KEY", spki.as_ref()));
        let globals = object!({
            "PEM": private_pem, "RAW": STANDARD.encode(raw), "PUBLIC_PEM": public_pem,
            "MESSAGE": STANDARD.encode(b"message"),
        });
        assert_eq!(
            render("{{ PEM | ec_public_key: 'P-256' }}", &globals).unwrap(),
            render("{{ RAW | ec_public_key: 'P-256' }}", &globals).unwrap()
        );
        let mut globals = globals;
        let signature = render("{{ MESSAGE | ecdsa_sign: PEM, 'P-256' }}", &globals).unwrap();
        globals.insert("SIGNATURE".into(), Value::scalar(signature));
        assert_eq!(
            render("{{ MESSAGE | ecdsa_verify: PUBLIC_PEM, SIGNATURE, 'P-256' }}", &globals)
                .unwrap(),
            "true"
        );
        assert_eq!(
            render("{{ PUBLIC_PEM | ecdh: PEM, 'P-256' }}", &globals).unwrap(),
            render("{{ PUBLIC_PEM | ecdh: RAW, 'P-256' }}", &globals).unwrap()
        );
    }

    #[test]
    fn additional_text_hashes_and_hmac_match_known_answers() {
        let globals = object!({});
        assert_eq!(
            render("{{ 'abc' | sha384 }}", &globals).unwrap(),
            concat!(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163",
                "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
            )
        );
        assert_eq!(
            render("{{ 'abc' | sha512 }}", &globals).unwrap(),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        // RFC4231, HMAC-SHA512 test case 2 (text key and message).
        assert_eq!(
            render("{{ 'what do ya want for nothing?' | hmac_sha512: 'Jefe' }}", &globals).unwrap(),
            b64hex(concat!(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
                "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            ))
        );
    }
}
