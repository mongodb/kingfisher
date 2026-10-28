//! Bounded, offline structure checks, not cryptographic or live key validation.
//!
//! Reject only demonstrably malformed complete containers. Unknown labels/algorithms,
//! encrypted payloads, and candidates beyond our work budget remain findings. Never
//! log parser errors: both the original text and decoded bytes can contain secrets.

use std::{borrow::Cow, sync::LazyLock};

use base64::{Engine, engine::general_purpose::STANDARD};
use der::{
    Decode, Reader, SliceReader, Tag, TagNumber, Tagged,
    asn1::{AnyRef, BitStringRef, IntRef, ObjectIdentifier, OctetStringRef, UintRef},
};
use regex::Regex;
use zeroize::Zeroizing;

const MAX_CANDIDATE_BYTES: usize = 1024 * 1024;

static ENVELOPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?is)-----BEGIN (?P<label>[A-Z0-9 _-]*PRIVATE KEY(?: BLOCK)?)-----",
        r"(?P<body>.*?)-----END (?P<end>[A-Z0-9 _-]*PRIVATE KEY(?: BLOCK)?)-----"
    ))
    .unwrap()
});

// Remove only adjacent/concatenated string-literal boundaries, never arbitrary
// punctuation. Runtime references are checked separately, without evaluating them.
static STRING_JOIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""\s*(?:\+\s*)?"|'\s*(?:\+\s*)?'"#).unwrap());

// Match the entire body, not a substring that could precede real key material
// in an unfamiliar source representation. These delimiters cannot be PEM data.
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A\s*(?:PRIVATE_KEY|\$\{PRIVATE_KEY(?:_[A-Z0-9_.\x{2026}]+)?\}|<YOUR_PRIVATE_KEY[A-Z0-9_.\x{2026}]*>)\s*\z",
    )
    .unwrap()
});

pub(crate) fn is_malformed(candidate: &str) -> bool {
    is_malformed_inner(candidate, true)
}

fn is_malformed_inner(candidate: &str, repair_partial_diff: bool) -> bool {
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return false;
    }
    // The detector can span adjacent envelopes. Reject only when every complete
    // container is malformed and nothing but whitespace separates them. A real
    // key, partial leak, or unknown source representation keeps the candidate.
    let mut end = 0;
    let mut found = false;
    for parts in ENVELOPE.captures_iter(candidate) {
        let container = parts.get(0).expect("matched envelope");
        if !candidate[end..container.start()].trim().is_empty() || !malformed_container(&parts) {
            return false;
        }
        if repair_partial_diff && partial_diff_keeps_material(&parts) {
            return false;
        }
        end = container.end();
        found = true;
    }
    found && candidate[end..].trim().is_empty()
}

fn partial_diff_keeps_material(parts: &regex::Captures<'_>) -> bool {
    let body = normalize(&parts["body"]);
    // '+' is also a source-code concatenation operator. Only repair an armor
    // payload; never reinterpret an already-recognized runtime-reference stub.
    if armor_body(&body, &parts["label"].to_ascii_uppercase()).is_none() {
        return false;
    }
    let lines: Vec<_> = body.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    if !lines.iter().any(|line| line.starts_with('+'))
        || !lines.iter().any(|line| !line.starts_with('+'))
    {
        return false;
    }
    let mut repaired = Zeroizing::new(format!("-----BEGIN {}-----\n", &parts["label"]));
    for line in lines {
        repaired.push_str(line.strip_prefix('+').unwrap_or(line));
        repaired.push('\n');
    }
    repaired.push_str(&format!("-----END {}-----", &parts["end"]));
    // At most one repair attempt: a literal '+' can itself be Base64 material.
    // Never strip repeatedly or turn this source repair into unbounded recursion.
    !is_malformed_inner(&repaired, false)
}

fn malformed_container(parts: &regex::Captures<'_>) -> bool {
    if parts["body"]
        .as_bytes()
        .windows(b"-----BEGIN ".len())
        .any(|window| window.eq_ignore_ascii_case(b"-----BEGIN "))
    {
        // A stub or outer source wrapper must not consume a later real key's
        // END marker and make its different label look like malformed material.
        return false;
    }
    let label = parts["label"].to_ascii_uppercase();
    if !label.eq_ignore_ascii_case(&parts["end"]) {
        return true;
    }
    let body = normalize(&parts["body"]);
    let Some((encoded, encrypted, checksum)) = armor_body(&body, &label) else {
        // Unknown source representations may contain real serialized keys. Reject
        // only a placeholder or literal PEM markers around runtime references with
        // no literal key material, e.g. "BEGIN..." + privateKeyEncoded + "...END".
        return PLACEHOLDER.is_match(&body) || concatenated_references_only(&body);
    };
    let Ok(decoded) = STANDARD.decode(encoded.as_bytes()).map(Zeroizing::new) else {
        return false;
    };
    if decoded.is_empty() || checksum.is_some_and(|checksum| crc24(&decoded) != checksum) {
        return true;
    }
    if encrypted {
        // Traditional PEM encryption has no inspectable DER until decrypted.
        return false;
    }
    if matches!(
        label.as_str(),
        "PRIVATE KEY"
            | "ENCRYPTED PRIVATE KEY"
            | "RSA PRIVATE KEY"
            | "EC PRIVATE KEY"
            | "DSA PRIVATE KEY"
    ) {
        // PKCS#8 permits BER, and common key consumers accept its indefinite
        // and non-minimal definite lengths. DER-only decoders cannot establish
        // that those keys are malformed. Retain bounded, complete BER framing
        // rather than attempting to normalize or cryptographically validate it.
        if decoded.first() == Some(&0x30) && non_der_ber(&decoded) {
            return false;
        }
        match der_structure(&decoded, 0) {
            // Excessive nesting is a work-limit outcome, not proof of invalidity.
            None => return false,
            Some(false) => return true,
            Some(true) => {}
        }
    }
    let valid = match label.as_str() {
        // A misleading PEM label does not make otherwise valid key material
        // harmless. Some tools label PKCS#8 keys as RSA/EC/DSA private keys.
        "PRIVATE KEY"
        | "ENCRYPTED PRIVATE KEY"
        | "RSA PRIVATE KEY"
        | "EC PRIVATE KEY"
        | "DSA PRIVATE KEY" => {
            pkcs8_key(&decoded)
                || encrypted_pkcs8(&decoded)
                || rsa_key(&decoded)
                || ec_key(&decoded)
                || dsa_key(&decoded)
        }
        "OPENSSH PRIVATE KEY" => openssh_key(&decoded),
        "PGP PRIVATE KEY BLOCK" => pgp_key(&decoded),
        _ => true,
    };
    !valid
}

fn concatenated_references_only(body: &str) -> bool {
    let body = body.trim();
    let Some(quote @ ('"' | '\'')) = body.chars().next() else {
        return false;
    };
    let Some(expression) = body.strip_prefix(quote).and_then(|body| body.strip_suffix(quote))
    else {
        return false;
    };
    let Some(references) = expression
        .trim()
        .strip_prefix('+')
        .and_then(|expression| expression.trim().strip_suffix('+'))
    else {
        return false;
    };
    // Whitespace-only string literals can disappear during STRING_JOIN normalization,
    // leaving adjacent `+` separators. Still require at least one runtime reference.
    let mut references =
        references.split('+').map(str::trim).filter(|part| !part.is_empty()).peekable();
    // Quotes, calls, operators, comments, and any literal payload keep the finding.
    references.peek().is_some()
        && references.all(|reference| {
            reference.split('.').all(|part| {
                let mut bytes = part.trim().bytes();
                bytes
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
                    && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
            })
        })
}

fn normalize(body: &str) -> Zeroizing<String> {
    // Handle JSON/source escaped newlines (including an extra serialization layer)
    // without evaluating source or indiscriminately removing backslashes.
    let mut body = Zeroizing::new(body.to_string());
    for _ in 0..2 {
        if !body.contains('\\') {
            break;
        }
        for (escaped, literal) in
            [("\\\\", "\\"), ("\\r", "\r"), ("\\n", "\n"), ("\\t", "\t"), ("\\/", "/")]
        {
            if body.contains(escaped) {
                body = Zeroizing::new(body.replace(escaped, literal));
            }
        }
    }
    if (body.contains('"') || body.contains('\''))
        && let Cow::Owned(joined) = STRING_JOIN.replace_all(&body, "")
    {
        body = Zeroizing::new(joined);
    }
    // The match begins at BEGIN, after any line prefix, and ends before the
    // END line's suffix. Strip only a prefix shared by every nonempty body
    // line, including the prefix left immediately before END.
    for prefix in ["//", "#", "*", ">", "+", ";"] {
        let mut lines = body.lines().map(str::trim).filter(|line| !line.is_empty()).peekable();
        if lines.peek().is_some() && lines.clone().all(|line| line.starts_with(prefix)) {
            body = Zeroizing::new(
                lines.map(|line| &line[prefix.len()..]).collect::<Vec<_>>().join("\n"),
            );
            break;
        }
    }
    body
}

type ArmorBody = (Zeroizing<String>, bool, Option<u32>);

fn armor_body(body: &str, label: &str) -> Option<ArmorBody> {
    let pgp = label == "PGP PRIVATE KEY BLOCK";
    let traditional = matches!(label, "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "DSA PRIVATE KEY");
    let opaque = !matches!(
        label,
        "PRIVATE KEY"
            | "ENCRYPTED PRIVATE KEY"
            | "RSA PRIVATE KEY"
            | "EC PRIVATE KEY"
            | "DSA PRIVATE KEY"
            | "OPENSSH PRIVATE KEY"
            | "PGP PRIVATE KEY BLOCK"
    );
    let mut encoded = Zeroizing::new(String::new());
    let mut proc_type = false;
    let mut dek_info = false;
    let mut checksum = None;
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if encoded.is_empty() && line.contains(':') {
            let (name, value) = line.split_once(':')?;
            if pgp || opaque {
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
                    return None;
                }
            } else if traditional && name == "Proc-Type" && !proc_type {
                if value.trim() != "4,ENCRYPTED" {
                    return None;
                }
                proc_type = true;
            } else if traditional && name == "DEK-Info" && !dek_info {
                let (cipher, iv) = value.trim().split_once(',')?;
                if cipher.is_empty()
                    || iv.is_empty()
                    || iv.len() % 2 != 0
                    || !iv.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return None;
                }
                dek_info = true;
            } else {
                // Unknown armor metadata does not change the decoded key. Keep
                // accepting well-formed headers from non-OpenSSL tooling, but
                // do not let duplicate encryption headers bypass their checks.
                if matches!(name, "Proc-Type" | "DEK-Info")
                    || name.is_empty()
                    || !name.bytes().all(|b| b.is_ascii_graphic())
                {
                    return None;
                }
            }
        } else if pgp && line.starts_with('=') {
            if checksum.is_some() || encoded.is_empty() {
                return None;
            }
            let bytes = STANDARD.decode(&line[1..]).ok()?;
            let [a, b, c] = bytes.as_slice() else { return None };
            checksum = Some(u32::from_be_bytes([0, *a, *b, *c]));
        } else {
            if checksum.is_some() {
                return None;
            }
            for byte in line.bytes().filter(|b| !b.is_ascii_whitespace()) {
                if !byte.is_ascii_alphanumeric() && !matches!(byte, b'+' | b'/' | b'=') {
                    return None;
                }
                encoded.push(char::from(byte));
            }
        }
    }
    if proc_type != dek_info {
        return None;
    }
    Some((encoded, proc_type, checksum))
}

fn rsa_key(bytes: &[u8]) -> bool {
    // Syntax only: no primality tests, big-integer arithmetic, or minimum key size.
    pkcs1::RsaPrivateKey::from_der(bytes).is_ok()
}

fn non_der_ber(bytes: &[u8]) -> bool {
    // Algorithm-specific PKCS#8 material can be an INTEGER (DSA) or OCTET
    // STRING (RFC 8410), not just an RSA/EC SEQUENCE. Constructed OCTET STRINGs
    // are BER-only even when their lengths use the shortest definite form.
    if !matches!(bytes.first(), Some(0x02 | 0x04 | 0x24 | 0x30)) {
        return false;
    }
    let mut non_der = false;
    let mut work_limit = false;
    let length = ber_value_length(bytes, 0, &mut non_der, &mut work_limit);
    work_limit || non_der && length == Some(bytes.len())
}

// Framing only, linear in the bounded candidate size, with the same depth cap
// as the DER walk. Primitive indefinite lengths and misplaced EOC markers are
// invalid; a depth-limit outcome is unknown, never grounds for suppression.
fn ber_value_length(
    bytes: &[u8],
    depth: usize,
    non_der: &mut bool,
    work_limit: &mut bool,
) -> Option<usize> {
    if depth > 24 {
        *work_limit = true;
        return None;
    }
    let tag = *bytes.first()?;
    if tag == 0 {
        return None;
    }
    if tag == 0x24 {
        *non_der = true;
    }
    let mut offset = 1usize;
    if tag & 0x1f == 0x1f {
        loop {
            let byte = *bytes.get(offset)?;
            offset += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let length = *bytes.get(offset)?;
    offset += 1;
    if length == 0x80 {
        if tag & 0x20 == 0 {
            return None;
        }
        *non_der = true;
        loop {
            if bytes.get(offset..offset.checked_add(2)?) == Some(&[0, 0]) {
                return offset.checked_add(2);
            }
            offset = offset.checked_add(ber_value_length(
                bytes.get(offset..)?,
                depth + 1,
                non_der,
                work_limit,
            )?)?;
        }
    }
    let length = if length & 0x80 == 0 {
        usize::from(length)
    } else {
        let count = usize::from(length & 0x7f);
        if count > std::mem::size_of::<usize>() {
            return None;
        }
        let length_bytes = bytes.get(offset..offset.checked_add(count)?)?;
        let length = length_bytes.iter().try_fold(0usize, |length, byte| {
            length.checked_mul(256)?.checked_add(usize::from(*byte))
        })?;
        if length < 128 || length_bytes.first() == Some(&0) {
            *non_der = true;
        }
        offset += count;
        length
    };
    let end = offset.checked_add(length)?;
    bytes.get(..end)?;
    if tag & 0x20 != 0 {
        while offset < end {
            offset = offset.checked_add(ber_value_length(
                &bytes[offset..end],
                depth + 1,
                non_der,
                work_limit,
            )?)?;
        }
    }
    Some(end)
}

fn der_structure(bytes: &[u8], depth: usize) -> Option<bool> {
    let Ok(value) = AnyRef::from_der(bytes) else { return Some(false) };
    der_value(value, depth)
}

fn der_value(value: AnyRef<'_>, depth: usize) -> Option<bool> {
    if depth > 24 {
        return None;
    }
    if value.tag().is_constructed() {
        let Ok(mut reader) = SliceReader::new(value.value()) else { return Some(false) };
        while !reader.is_finished() {
            let Ok(child) = reader.decode::<AnyRef<'_>>() else { return Some(false) };
            if !der_value(child, depth + 1)? {
                return Some(false);
            }
        }
        return Some(true);
    }
    Some(match value.tag() {
        Tag::Integer => value.decode_as::<IntRef<'_>>().is_ok(),
        Tag::BitString => value.decode_as::<BitStringRef<'_>>().is_ok(),
        Tag::ObjectIdentifier => value.decode_as::<ObjectIdentifier>().is_ok(),
        Tag::Boolean => value.decode_as::<bool>().is_ok(),
        Tag::Null => value.value().is_empty(),
        _ => true,
    })
}

fn pkcs8_key(bytes: &[u8]) -> bool {
    let Ok(key) = pkcs8::PrivateKeyInfo::from_der(bytes) else { return false };
    if key.private_key.is_empty() {
        return false;
    }
    if non_der_ber(key.private_key) {
        return true;
    }
    // Parsing the outer OCTET STRING alone would accept arbitrary text as a key.
    // Inspect known algorithms' inner encodings, but preserve future algorithms.
    match key.algorithm.oid {
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            || oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7")
            || oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10") =>
        {
            rsa_key(key.private_key)
        }
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
            key.algorithm.parameters.is_none_or(|value| ec_parameters(value).is_ok())
                && ec_key(key.private_key)
        }
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10040.4.1") => {
            key.algorithm.parameters.is_none_or(|value| {
                value
                    .sequence(|reader| {
                        for _ in 0..3 {
                            reader.decode::<UintRef<'_>>()?;
                        }
                        Ok(())
                    })
                    .is_ok()
            }) && UintRef::from_der(key.private_key).is_ok()
        }
        oid if oid == ObjectIdentifier::new_unwrap("1.3.101.110")
            || oid == ObjectIdentifier::new_unwrap("1.3.101.111")
            || oid == ObjectIdentifier::new_unwrap("1.3.101.112")
            || oid == ObjectIdentifier::new_unwrap("1.3.101.113") =>
        {
            let size = match oid.to_string().as_str() {
                "1.3.101.111" => 56, // X448
                "1.3.101.113" => 57, // Ed448
                _ => 32,             // X25519 / Ed25519
            };
            OctetStringRef::from_der(key.private_key).is_ok_and(|key| key.as_bytes().len() == size)
        }
        _ => true,
    }
}

fn encrypted_pkcs8(bytes: &[u8]) -> bool {
    // Generic AlgorithmIdentifier rather than a cipher allowlist: unsupported
    // PBES/KDF schemes are still secrets. Never decrypt or run a password KDF.
    AnyRef::from_der(bytes)
        .and_then(|value| {
            value.sequence(|reader| {
                let algorithm = reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?;
                if algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13") {
                    // PBES2 contains two AlgorithmIdentifiers, not arbitrary DER.
                    algorithm.parameters.ok_or_else(|| Tag::Sequence.value_error())?.sequence(
                        |reader| {
                            let kdf = reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?;
                            kdf_parameters(kdf)?;
                            reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?;
                            Ok(())
                        },
                    )?;
                }
                let ciphertext = reader.decode::<OctetStringRef<'_>>()?;
                if ciphertext.as_bytes().is_empty() {
                    return Err(Tag::OctetString.value_error());
                }
                Ok(())
            })
        })
        .is_ok()
}

fn kdf_parameters(algorithm: pkcs8::AlgorithmIdentifierRef<'_>) -> der::Result<()> {
    let pbkdf2 = algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12");
    let scrypt = algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11591.4.11");
    if !pbkdf2 && !scrypt {
        return Ok(());
    }
    algorithm.parameters.ok_or_else(|| Tag::Sequence.value_error())?.sequence(|reader| {
        if pbkdf2 && reader.peek_tag()? == Tag::Sequence {
            reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?; // otherSource salt
        } else {
            reader.decode::<OctetStringRef<'_>>()?; // specified salt
        }
        // Decode counts only: no work is proportional to attacker-supplied values.
        for _ in 0..if scrypt { 3 } else { 1 } {
            reader.decode::<UintRef<'_>>()?;
        }
        if !reader.is_finished() && reader.peek_tag()? == Tag::Integer {
            reader.decode::<UintRef<'_>>()?; // optional key length
        }
        if pbkdf2 && !reader.is_finished() {
            reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?; // optional PRF
        }
        Ok(())
    })
}

fn ec_key(bytes: &[u8]) -> bool {
    // Read SEC1 without a curve allowlist, including explicit EC parameters.
    match der_structure(bytes, 0) {
        None => return true,
        Some(false) => return false,
        Some(true) => {}
    }
    AnyRef::from_der(bytes)
        .and_then(|value| {
            value.sequence(|reader| {
                if reader.decode::<u8>()? != 1
                    || reader.decode::<OctetStringRef<'_>>()?.as_bytes().is_empty()
                {
                    return Err(Tag::Sequence.value_error());
                }
                if !reader.is_finished()
                    && reader.peek_tag()?
                        == (Tag::ContextSpecific { constructed: true, number: TagNumber::N0 })
                {
                    let parameters = reader.decode::<AnyRef<'_>>()?;
                    let value = AnyRef::from_der(parameters.value())?;
                    ec_parameters(value)?;
                }
                if !reader.is_finished() {
                    let public = reader.decode::<AnyRef<'_>>()?;
                    public.tag().assert_eq(Tag::ContextSpecific {
                        constructed: true,
                        number: TagNumber::N1,
                    })?;
                    BitStringRef::from_der(public.value())?;
                }
                Ok(())
            })
        })
        .is_ok()
}

fn ec_parameters(value: AnyRef<'_>) -> der::Result<()> {
    match value.tag() {
        Tag::ObjectIdentifier => {
            value.decode_as::<ObjectIdentifier>()?;
            Ok(())
        }
        Tag::Null if value.value().is_empty() => Ok(()),
        Tag::Sequence => explicit_ec_parameters(value),
        _ => Err(Tag::Sequence.value_error()),
    }
}

fn explicit_ec_parameters(value: AnyRef<'_>) -> der::Result<()> {
    value.sequence(|reader| {
        if !matches!(reader.decode::<u8>()?, 1..=3) {
            return Err(Tag::Integer.value_error());
        }
        // FieldID: an OID plus its parameters. Unknown finite-field types remain
        // opaque; prime fields must at least contain a DER unsigned integer.
        let field = reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?;
        let parameters = field.parameters.ok_or_else(|| Tag::Sequence.value_error())?;
        if field.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.1.1") {
            parameters.decode_as::<UintRef<'_>>()?;
        }
        reader.decode::<AnyRef<'_>>()?.sequence(|reader| {
            reader.decode::<OctetStringRef<'_>>()?; // curve coefficient a
            reader.decode::<OctetStringRef<'_>>()?; // curve coefficient b
            if !reader.is_finished() {
                reader.decode::<BitStringRef<'_>>()?;
            } // optional seed
            Ok(())
        })?;
        if reader.decode::<OctetStringRef<'_>>()?.as_bytes().is_empty() {
            // base point
            return Err(Tag::OctetString.value_error());
        }
        reader.decode::<UintRef<'_>>()?; // order
        if !reader.is_finished() && reader.peek_tag()? == Tag::Integer {
            reader.decode::<UintRef<'_>>()?; // optional cofactor
        }
        if !reader.is_finished() {
            reader.decode::<pkcs8::AlgorithmIdentifierRef<'_>>()?; // optional hash
        }
        Ok(())
    })
}

fn dsa_key(bytes: &[u8]) -> bool {
    AnyRef::from_der(bytes)
        .and_then(|value| {
            value.sequence(|reader| {
                if reader.decode::<u8>()? != 0 {
                    return Err(Tag::Integer.value_error());
                }
                for _ in 0..5 {
                    reader.decode::<UintRef<'_>>()?;
                } // p, q, g, y, x
                Ok(())
            })
        })
        .is_ok()
}

/// Length-prefixed SSH fields. All reads are checked, including attacker-chosen sizes.
struct SshReader<'a>(&'a [u8]);

impl<'a> SshReader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (value, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(value)
    }

    fn uint(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.uint()?).ok()?;
        self.take(len)
    }
}

fn openssh_key(bytes: &[u8]) -> bool {
    openssh_fields(bytes).is_some()
}

fn openssh_fields(bytes: &[u8]) -> Option<()> {
    let mut reader = SshReader(bytes.strip_prefix(b"openssh-key-v1\0")?);
    let cipher = reader.string()?;
    let kdf = reader.string()?;
    let options = reader.string()?;
    if cipher.is_empty() || kdf.is_empty() {
        return None;
    }
    let count = usize::try_from(reader.uint()?).ok()?;
    if count == 0 || count > reader.0.len() / 4 {
        return None;
    }
    let mut algorithms = Vec::new();
    for _ in 0..count {
        let public = reader.string()?;
        let mut public = SshReader(public);
        let algorithm = public.string()?;
        if algorithm.is_empty() || public.0.is_empty() {
            return None;
        }
        let fields = match algorithm {
            b"ssh-rsa" => Some(2),
            b"ssh-dss" => Some(4),
            b"ssh-ed25519" => Some(1),
            name if name.starts_with(b"ecdsa-sha2-") => Some(2),
            _ => None,
        };
        if let Some(fields) = fields {
            for _ in 0..fields {
                let value = public.string()?;
                if value.is_empty() || (algorithm == b"ssh-ed25519" && value.len() != 32) {
                    return None;
                }
            }
            if !public.0.is_empty() {
                return None;
            }
        }
        algorithms.push(algorithm);
    }
    let private = reader.string()?;
    if private.is_empty() {
        return None;
    }
    if cipher != b"none" {
        // Encrypted SSH records cannot be inspected without the passphrase. KDF
        // and cipher names are deliberately not restricted to today's algorithms.
        if kdf == b"none" || options.is_empty() {
            return None;
        }
        if kdf == b"bcrypt" {
            let mut options = SshReader(options);
            if options.string()?.is_empty() || options.uint()? == 0 || !options.0.is_empty() {
                return None;
            }
        }
        // AEAD authentication tags follow the ciphertext string, outside it.
        let tag_len = match cipher {
            b"aes128-gcm@openssh.com"
            | b"aes256-gcm@openssh.com"
            | b"chacha20-poly1305@openssh.com" => Some(16),
            b"aes128-ctr" | b"aes192-ctr" | b"aes256-ctr" | b"aes128-cbc" | b"aes192-cbc"
            | b"aes256-cbc" | b"3des-cbc" => Some(0),
            _ => None,
        };
        return tag_len.is_none_or(|len| reader.0.len() == len).then_some(());
    }
    if kdf != b"none" || !options.is_empty() || !reader.0.is_empty() || private.len() % 8 != 0 {
        return None;
    }
    let mut private = SshReader(private);
    if private.uint()? != private.uint()? {
        return None;
    }
    for public_algorithm in algorithms {
        let algorithm = private.string()?;
        if algorithm != public_algorithm {
            return None;
        }
        let fields = match algorithm {
            b"ssh-rsa" => 6, // n, e, d, iqmp, p, q
            b"ssh-dss" => 5, // p, q, g, y, x
            b"ssh-ed25519" => 2,
            name if name.starts_with(b"ecdsa-sha2-") => 3, // curve, point, scalar
            // Hardware-backed and future formats are opaque, not invalid.
            _ => return (!algorithm.is_empty() && !private.0.is_empty()).then_some(()),
        };
        for field in 0..fields {
            let value = private.string()?;
            if value.is_empty()
                || (algorithm == b"ssh-ed25519" && value.len() != if field == 0 { 32 } else { 64 })
            {
                return None;
            }
        }
        private.string()?; // comment, allowed to be empty
    }
    // PuTTYgen permits up to 16 padding bytes even for unencrypted OpenSSH keys.
    if private.0.len() > 16 || !private.0.iter().enumerate().all(|(i, b)| usize::from(*b) == i + 1)
    {
        return None;
    }
    Some(())
}

fn crc24(bytes: &[u8]) -> u32 {
    let mut crc = 0xb704ce;
    for byte in bytes {
        crc ^= u32::from(*byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864cfb;
            }
        }
    }
    crc & 0xffffff
}

fn pgp_key(bytes: &[u8]) -> bool {
    pgp_packets(bytes).is_some()
}

fn pgp_packets(mut bytes: &[u8]) -> Option<()> {
    let mut secret = false;
    while !bytes.is_empty() {
        let header = *bytes.first()?;
        bytes = &bytes[1..];
        if header & 0x80 == 0 {
            return None;
        }
        let tag = if header & 0x40 != 0 { header & 0x3f } else { (header >> 2) & 0xf };
        let mut packet = Zeroizing::new(Vec::new());
        if header & 0x40 != 0 {
            loop {
                let length = *bytes.first()?;
                bytes = &bytes[1..];
                let (len, partial) = match length {
                    0..=191 => (usize::from(length), false),
                    192..=223 => {
                        let next = *bytes.first()?;
                        bytes = &bytes[1..];
                        (((usize::from(length) - 192) << 8) + usize::from(next) + 192, false)
                    }
                    224..=254 => (1_usize.checked_shl(u32::from(length & 0x1f))?, true),
                    255 => {
                        let mut reader = SshReader(bytes);
                        let len = usize::try_from(reader.uint()?).ok()?;
                        bytes = reader.0;
                        (len, false)
                    }
                };
                let (chunk, rest) = bytes.split_at_checked(len)?;
                packet.extend_from_slice(chunk);
                bytes = rest;
                if !partial {
                    break;
                }
            }
        } else {
            let size = match header & 3 {
                0 => 1,
                1 => 2,
                2 => 4,
                _ => 0,
            };
            let len = if size == 0 {
                bytes.len()
            } else {
                let (length, rest) = bytes.split_at_checked(size)?;
                bytes = rest;
                length
                    .iter()
                    .try_fold(0_usize, |n, b| n.checked_mul(256)?.checked_add(usize::from(*b)))?
            };
            let (chunk, rest) = bytes.split_at_checked(len)?;
            packet.extend_from_slice(chunk);
            bytes = rest;
        }
        if matches!(tag, 5 | 7) {
            if !pgp_secret_packet(&packet) {
                return None;
            }
            secret = true;
        }
    }
    secret.then_some(())
}

fn pgp_secret_packet(packet: &[u8]) -> bool {
    pgp_secret_fields(packet).is_some()
}

fn pgp_secret_fields(packet: &[u8]) -> Option<()> {
    let mut reader = SshReader(packet);
    let version = *reader.take(1)?.first()?;
    reader.take(4)?; // creation timestamp
    if matches!(version, 2 | 3) {
        reader.take(2)?;
    } // legacy validity period
    let algorithm = *reader.take(1)?.first()?;
    if !matches!(version, 2..=4) {
        // Newer versions carry different public/secret-field length encodings.
        return (!reader.0.is_empty()).then_some(());
    }
    let (public_mpis, secret_mpis) = match algorithm {
        1..=3 => (2, 4),   // RSA
        16 | 20 => (3, 1), // ElGamal
        17 => (4, 1),      // DSA
        18 | 19 | 22 => {
            // ECDH, ECDSA, legacy EdDSA
            let size = usize::from(*reader.take(1)?.first()?);
            if size == 0 {
                return None;
            }
            reader.take(size)?; // curve OID (not restricted to supported curves)
            (1, 1)
        }
        _ => return (!reader.0.is_empty()).then_some(()),
    };
    for _ in 0..public_mpis {
        pgp_mpi(&mut reader)?;
    }
    if algorithm == 18 {
        let size = usize::from(*reader.take(1)?.first()?);
        if size == 0 {
            return None;
        }
        reader.take(size)?; // ECDH KDF parameters
    }
    let usage = *reader.take(1)?.first()?;
    if usage != 0 {
        // S2K/cipher fields and ciphertext: do not decrypt or run any KDF.
        return (!reader.0.is_empty()).then_some(());
    }
    let secret_bytes = reader.0;
    for _ in 0..secret_mpis {
        pgp_mpi(&mut reader)?;
    }
    let consumed = secret_bytes.len() - reader.0.len();
    let checksum = u16::from_be_bytes(reader.take(2)?.try_into().ok()?);
    let expected =
        secret_bytes[..consumed].iter().fold(0_u16, |sum, b| sum.wrapping_add(u16::from(*b)));
    (reader.0.is_empty() && checksum == expected).then_some(())
}

fn pgp_mpi(reader: &mut SshReader<'_>) -> Option<()> {
    let bits = u16::from_be_bytes(reader.take(2)?.try_into().ok()?);
    // Keep the declared octet boundary, but do not require a canonical leading
    // bit count. Readers can accept the same key integers despite that padding.
    // Packet framing and the unencrypted secret checksum are still checked.
    reader.take(usize::from(bits).div_ceil(8))?;
    Some(())
}

#[cfg(test)]
mod tests {
    use der::Encode;
    use proptest::prelude::*;

    use super::*;

    // Deliberately synthetic containers, not usable private keys. These tests
    // establish encoding/structure, not mathematical validity or active access.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        if value.len() < 128 {
            bytes.push(value.len() as u8);
        } else if value.len() <= 255 {
            bytes.extend_from_slice(&[0x81, value.len() as u8]);
        } else {
            bytes.extend_from_slice(&[0x82, (value.len() >> 8) as u8, value.len() as u8]);
        }
        bytes.extend_from_slice(value);
        bytes
    }

    fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
        tlv(0x30, &fields.concat())
    }

    fn integer(value: u8) -> Vec<u8> {
        tlv(2, &[value])
    }

    fn rsa(multi: bool) -> Vec<u8> {
        let mut fields = vec![integer(u8::from(multi))];
        fields.extend((1..=8).map(integer));
        if multi {
            fields.push(sequence(&[sequence(&[integer(9), integer(10), integer(11)])]));
        }
        sequence(&fields)
    }

    fn ec(parameters: Option<Vec<u8>>, public: bool) -> Vec<u8> {
        let mut fields = vec![integer(1), tlv(4, &[0x35; 32])];
        if let Some(parameters) = parameters {
            fields.push(tlv(0xa0, &parameters));
        }
        if public {
            fields.push(tlv(0xa1, &tlv(3, &[0, 4, 1, 2, 3])));
        }
        sequence(&fields)
    }

    fn pkcs8(oid: &str, inner: &[u8]) -> Vec<u8> {
        pkcs8::PrivateKeyInfo::new(
            pkcs8::AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap(oid),
                parameters: None,
            },
            inner,
        )
        .to_der()
        .unwrap()
    }

    fn pem(label: &str, bytes: &[u8]) -> String {
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----", STANDARD.encode(bytes))
    }

    #[test]
    fn preserves_opaque_source_code_but_rejects_decoded_garbage_and_placeholders() {
        let java = r#"-----BEGIN PRIVATE KEY-----", "begin key marker"),
            Pair.of(expectedKeyString, "private key pem"),
            Pair.of("-----END PRIVATE KEY-----"#;
        // Unrecognized source syntax may also contain a real serialized key.
        // Failure to parse armor alone must not suppress a candidate.
        assert!(!is_malformed(java));
        for label in [
            "PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        ] {
            assert!(is_malformed(&pem(label, &[b'x'; 200])), "{label}");
            assert!(is_malformed(&pem(label, &[])), "{label}");
        }
        assert!(is_malformed(
            "-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n-----END PRIVATE KEY-----"
        ));
        assert!(!is_malformed("-----BEGIN PRIVATE KEY-----\nYWJjZA=\n-----END PRIVATE KEY-----"));
        assert!(is_malformed(
            "-----BEGIN RSA PRIVATE KEY-----\nYWJjZA==\n-----END EC PRIVATE KEY-----"
        ));
    }

    #[test]
    fn pem_wrappers_around_runtime_references_are_not_embedded_keys() {
        for body in [
            r#"\n" + privateKeyEncoded + "\n"#,
            r#"\\n"
                + privateKeyEncoded
                + "\\n"
                + ""#,
            r#"\n" + credentials.privateKeyEncoded + "\n"#,
            r#"\n" + firstPart + secondPart + "\n"#,
            r"\n' + private_key_encoded + '\n",
            r#"\n" + $privateKey + "\n"#,
        ] {
            let candidate = format!("-----BEGIN PRIVATE KEY-----{body}-----END PRIVATE KEY-----");
            assert!(is_malformed(&candidate), "{candidate}");
            assert!(is_malformed(&candidate.replace('\n', "\r\n")));
        }

        let encoded = STANDARD.encode(pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
        for body in [
            format!(r#"\n{encoded}" + suffix + "\n"#),
            format!(r#"\n" + prefix + "{encoded}\n"#),
            format!(r#"\n" + prefix + "{encoded}" + suffix + "\n"#),
            format!(r#"\n" + "{encoded}" + "\n"#),
            r#"\n" + loadKey() + "\n"#.to_owned(),
            r#"\n" + /* unknown source representation */ key + "\n"#.to_owned(),
            r#"\n" + key + "\n'"#.to_owned(),
        ] {
            let candidate = format!("-----BEGIN PRIVATE KEY-----{body}-----END PRIVATE KEY-----");
            assert!(!is_malformed(&candidate), "{candidate}");
        }
    }

    #[test]
    fn placeholder_filter_requires_a_complete_placeholder_only_body() {
        for body in [
            "${PRIVATE_KEY}",
            "${PRIVATE_KEY_CONTENTS}",
            "${PRIVATE_KEY_…}",
            "<YOUR_PRIVATE_KEY_HERE>",
            "<YOUR_PRIVATE_KEY_HERE...>",
            "<YOUR_PRIVATE_KEY_HERE…>",
        ] {
            for newline in ["\n", "\r\n", "\\n"] {
                let candidate = format!(
                    "-----BEGIN PRIVATE KEY-----{newline}{body}{newline}-----END PRIVATE KEY-----"
                );
                assert!(is_malformed(&candidate), "{body}");
            }
            // Unknown wrappers can still contain a real serialized key. Never
            // discard one just because a placeholder also appears in the body.
            let encoded = STANDARD.encode(pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
            for mixed in [format!("{body}\n{encoded}"), format!("{encoded}\n{body}")] {
                assert!(!is_malformed(&format!(
                    "-----BEGIN PRIVATE KEY-----\n{mixed}\n-----END PRIVATE KEY-----"
                )));
            }
        }
    }

    #[test]
    fn checks_pkcs1_including_multiprime_and_pkcs8_inner_keys() {
        for multi in [false, true] {
            let key = rsa(multi);
            assert!(!is_malformed(&pem("RSA PRIVATE KEY", &key)));
            for oid in ["1.2.840.113549.1.1.1", "1.2.840.113549.1.1.7", "1.2.840.113549.1.1.10"] {
                assert!(!is_malformed(&pem("PRIVATE KEY", &pkcs8(oid, &key))));
                assert!(is_malformed(&pem("PRIVATE KEY", &pkcs8(oid, b"not an RSA key"))));
            }
            let mut trailing = key.clone();
            trailing.push(0);
            assert!(is_malformed(&pem("RSA PRIVATE KEY", &trailing)));
            assert!(is_malformed(&pem("RSA PRIVATE KEY", &key[..key.len() - 1])));
        }
        assert!(is_malformed(&pem("RSA PRIVATE KEY", &sequence(&[integer(0), integer(1)]))));
    }

    #[test]
    fn ber_encoded_keys_are_not_rejected_by_der_only_checks() {
        for (label, key) in [
            ("RSA PRIVATE KEY", rsa(false)),
            ("PRIVATE KEY", pkcs8("1.3.101.112", &tlv(4, &[0x35; 32]))),
        ] {
            let body = AnyRef::from_der(&key).unwrap().value().to_vec();
            assert!(body.len() < 128);
            let indefinite = [vec![0x30, 0x80], body.clone(), vec![0, 0]].concat();
            let long_length = [vec![0x30, 0x82, 0, body.len() as u8], body].concat();
            for ber in [indefinite, long_length] {
                assert!(non_der_ber(&ber));
                assert!(!is_malformed(&pem(label, &ber)), "{label}");
                if label == "RSA PRIVATE KEY" {
                    assert!(!is_malformed(&pem(
                        "PRIVATE KEY",
                        &pkcs8("1.2.840.113549.1.1.1", &ber)
                    )));
                }
                assert!(is_malformed(&pem(label, &ber[..ber.len() - 1])));
            }
        }
        let algorithm = [
            vec![0x30, 0x80],
            ObjectIdentifier::new_unwrap("1.3.101.112").to_der().unwrap(),
            vec![0, 0],
        ]
        .concat();
        let nested = sequence(&[integer(0), algorithm, tlv(4, &tlv(4, &[0x35; 32]))]);
        assert!(!is_malformed(&pem("PRIVATE KEY", &nested)));
        // An indefinite-length primitive is not valid BER framing.
        assert!(!non_der_ber(&[0x30, 0x80, 4, 0x80, 0, 0, 0, 0]));
    }

    #[test]
    fn rfc8410_private_octets_accept_ber_lengths_and_constructed_strings() {
        for (oid, len) in
            [("1.3.101.110", 32), ("1.3.101.111", 56), ("1.3.101.112", 32), ("1.3.101.113", 57)]
        {
            let scalar = vec![0x35; len];
            let chunks = [tlv(4, &scalar[..16]), tlv(4, &scalar[16..])].concat();
            for inner in [
                [vec![4, 0x81, len as u8], scalar.clone()].concat(),
                tlv(0x24, &chunks),
                [vec![0x24, 0x80], chunks, vec![0, 0]].concat(),
            ] {
                assert!(non_der_ber(&inner), "{oid}");
                let key = pkcs8(oid, &inner);
                assert!(!is_malformed(&pem("PRIVATE KEY", &key)), "{oid}");
                assert!(!is_malformed(&pem("RSA PRIVATE KEY", &key)), "{oid}");
                assert!(is_malformed(&pem("PRIVATE KEY", &pkcs8(oid, &inner[..inner.len() - 1]))));
            }
        }
    }

    #[test]
    fn checks_sec1_and_dsa_without_a_curve_allowlist() {
        let curve = ObjectIdentifier::new_unwrap("1.3.132.0.10").to_der().unwrap();
        let explicit = sequence(&[
            integer(1),
            sequence(&[
                ObjectIdentifier::new_unwrap("1.2.840.10045.1.1").to_der().unwrap(),
                integer(23),
            ]),
            sequence(&[tlv(4, &[1]), tlv(4, &[2])]),
            tlv(4, &[4, 3, 5]),
            integer(7),
            integer(1),
        ]);
        for parameters in [None, Some(curve), Some(explicit), Some(vec![5, 0])] {
            for public in [false, true] {
                let key = ec(parameters.clone(), public);
                assert!(!is_malformed(&pem("EC PRIVATE KEY", &key)));
                assert!(!is_malformed(&pem("PRIVATE KEY", &pkcs8("1.2.840.10045.2.1", &key))));
            }
        }
        let dsa =
            sequence(&[integer(0), integer(1), integer(2), integer(3), integer(4), integer(5)]);
        assert!(!is_malformed(&pem("DSA PRIVATE KEY", &dsa)));
        assert!(!is_malformed(&pem("PRIVATE KEY", &pkcs8("1.2.840.10040.4.1", &integer(5)))));
        for (label, bytes) in [
            ("EC PRIVATE KEY", sequence(&[integer(0), tlv(4, &[1; 32])])),
            ("EC PRIVATE KEY", sequence(&[integer(1), tlv(4, &[])])),
            ("EC PRIVATE KEY", sequence(&[integer(1), tlv(4, &[1; 32]), tlv(0xa1, &integer(0))])),
            ("EC PRIVATE KEY", ec(Some(sequence(&[integer(1), integer(2)])), false)),
            ("DSA PRIVATE KEY", sequence(&[integer(0), integer(1)])),
        ] {
            assert!(is_malformed(&pem(label, &bytes)), "{label}");
        }
    }

    #[test]
    fn checks_rfc8410_nested_octets_and_preserves_unknown_algorithms() {
        for (oid, len) in
            [("1.3.101.110", 32), ("1.3.101.111", 56), ("1.3.101.112", 32), ("1.3.101.113", 57)]
        {
            assert!(!is_malformed(&pem("PRIVATE KEY", &pkcs8(oid, &tlv(4, &vec![0x35; len])))));
            for inner in [
                vec![0x35; len],
                tlv(4, &vec![0x35; len - 1]),
                tlv(4, &vec![0x35; len + 1]),
                tlv(4, &[]),
            ] {
                assert!(is_malformed(&pem("PRIVATE KEY", &pkcs8(oid, &inner))), "{oid}");
            }
        }
        assert!(!is_malformed(&pem("PRIVATE KEY", &pkcs8("1.3.6.1.4.1.55555.1", &[0x35; 48]))));
        assert!(is_malformed(&pem("PRIVATE KEY", &pkcs8("1.3.6.1.4.1.55555.1", &[]))));
        assert!(!is_malformed(&pem("FUTURE PRIVATE KEY", b"opaque future key encoding")));
    }

    #[test]
    fn checks_der_lengths_tags_versions_and_nested_parameters() {
        let oid = ObjectIdentifier::new_unwrap("1.3.101.112").to_der().unwrap();
        let inner = tlv(4, &tlv(4, &[0x35; 32]));
        for fields in [
            vec![integer(2), sequence(std::slice::from_ref(&oid)), inner.clone()],
            vec![integer(0), integer(1), inner.clone()],
            vec![integer(0), sequence(&[oid.clone(), vec![5, 1, 0]]), inner.clone()],
            vec![integer(0), sequence(&[oid.clone(), vec![0x30, 2, 4, 5]]), inner.clone()],
            vec![integer(0), sequence(std::slice::from_ref(&oid)), tlv(3, &[0, 1, 2, 3])],
        ] {
            assert!(is_malformed(&pem("PRIVATE KEY", &sequence(&fields))));
        }
        // RFC5958 OneAsymmetricKey with an optional public key and attributes.
        let public = tlv(0x81, &[vec![0], vec![0x47; 32]].concat());
        let key = sequence(&[
            integer(1),
            sequence(std::slice::from_ref(&oid)),
            inner.clone(),
            tlv(0xa0, &[]),
            public,
        ]);
        assert!(!is_malformed(&pem("PRIVATE KEY", &key)));
        let wrong_version = sequence(&[integer(1), sequence(&[oid]), inner]);
        assert!(is_malformed(&pem("PRIVATE KEY", &wrong_version)));
        // Well-formed but deeply nested future parameters hit the work budget.
        let mut nested = integer(0);
        for _ in 0..30 {
            nested = sequence(&[nested]);
        }
        let algorithm = sequence(&[
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1").to_der().unwrap(),
            nested,
        ]);
        assert!(!is_malformed(&pem(
            "PRIVATE KEY",
            &sequence(&[integer(0), algorithm, tlv(4, &[1])])
        )));
    }

    #[test]
    fn retains_encrypted_pkcs8_and_traditional_pem_without_decryption() {
        let kdf = sequence(&[
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.12").to_der().unwrap(),
            sequence(&[tlv(4, &[0x35; 16]), integer(10)]),
        ]);
        let cipher = sequence(&[
            ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42").to_der().unwrap(),
            tlv(4, &[0x47; 16]),
        ]);
        let algorithm = sequence(&[
            ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13").to_der().unwrap(),
            sequence(&[kdf.clone(), cipher.clone()]),
        ]);
        assert!(!is_malformed(&pem(
            "ENCRYPTED PRIVATE KEY",
            &sequence(&[algorithm.clone(), tlv(4, &[0x35; 64])])
        )));
        assert!(is_malformed(&pem(
            "ENCRYPTED PRIVATE KEY",
            &sequence(&[algorithm.clone(), tlv(4, &[])])
        )));
        assert!(is_malformed(&pem("ENCRYPTED PRIVATE KEY", &sequence(&[algorithm]))));
        for parameters in
            [sequence(&[integer(1)]), sequence(&[kdf]), sequence(&[integer(1), cipher])]
        {
            let algorithm = sequence(&[
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.5.13").to_der().unwrap(),
                parameters,
            ]);
            assert!(is_malformed(&pem(
                "ENCRYPTED PRIVATE KEY",
                &sequence(&[algorithm, tlv(4, &[0x35; 64])])
            )));
        }
        // Unsupported encryption/KDF schemes are not evidence of invalidity.
        let unknown = sequence(&[
            ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1").to_der().unwrap(),
            integer(1),
        ]);
        assert!(!is_malformed(&pem(
            "ENCRYPTED PRIVATE KEY",
            &sequence(&[unknown, tlv(4, &[0x35; 64])])
        )));
        for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"] {
            let encrypted = pem(label, &[0x35; 64]).replacen(
                '\n',
                "\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF\n\n",
                1,
            );
            assert!(!is_malformed(&encrypted));
            assert!(!is_malformed(&encrypted.replace("Proc-Type: 4,ENCRYPTED\n", "")));
            assert!(!is_malformed(&encrypted.replace("0123456789ABCDEF", "not an IV")));
        }
    }

    #[test]
    fn unknown_armor_metadata_does_not_invalidate_der_keys() {
        let encryption = sequence(&[
            sequence(&[ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1").to_der().unwrap()]),
            tlv(4, &[0x35; 64]),
        ]);
        for (label, bytes) in [
            ("PRIVATE KEY", pkcs8("1.2.840.113549.1.1.1", &rsa(false))),
            ("ENCRYPTED PRIVATE KEY", encryption),
            ("RSA PRIVATE KEY", rsa(false)),
            ("EC PRIVATE KEY", ec(None, false)),
            ("DSA PRIVATE KEY", sequence(&(0..=5).map(integer).collect::<Vec<_>>())),
        ] {
            let key = pem(label, &bytes);
            assert!(!is_malformed(&key), "{label}");
            let with_comment = key.replacen('\n', "\nComment: generated by another tool\n\n", 1);
            assert!(!is_malformed(&with_comment), "{label}");
        }
    }

    #[test]
    fn checks_common_kdf_parameter_schemas_without_executing_them() {
        for (oid, parameters) in [
            ("1.2.840.113549.1.5.12", sequence(&[tlv(4, &[0x35; 8]), integer(10)])),
            (
                "1.2.840.113549.1.5.12",
                sequence(&[
                    tlv(4, &[0x35; 8]),
                    integer(10),
                    integer(32),
                    sequence(&[
                        ObjectIdentifier::new_unwrap("1.2.840.113549.2.9").to_der().unwrap(),
                        vec![5, 0],
                    ]),
                ]),
            ),
            (
                "1.3.6.1.4.1.11591.4.11",
                sequence(&[tlv(4, &[0x35; 8]), integer(16), integer(8), integer(1), integer(32)]),
            ),
        ] {
            let algorithm = pkcs8::AlgorithmIdentifierRef {
                oid: ObjectIdentifier::new_unwrap(oid),
                parameters: Some(AnyRef::from_der(&parameters).unwrap()),
            };
            assert!(kdf_parameters(algorithm).is_ok());
            let bad = sequence(&[tlv(4, &[0x35; 8])]);
            assert!(
                kdf_parameters(pkcs8::AlgorithmIdentifierRef {
                    parameters: Some(AnyRef::from_der(&bad).unwrap()),
                    ..algorithm
                })
                .is_err()
            );
        }
    }

    #[test]
    fn source_representations_and_line_wrapping_do_not_lose_keys() {
        let key = pem("PRIVATE KEY", &pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
        let lowercase_labels = key
            .replace("BEGIN PRIVATE KEY", "begin private key")
            .replace("END PRIVATE KEY", "end private key");
        for representation in [
            key.clone(),
            key.replace('\n', "\r\n"),
            key.replace('\n', "\\n"),
            key.replace('\n', "\\r\\n"),
            key.replace('\n', "\\\\n"),
            key.replace('\n', "\\n\" +\n    \""),
            key.replace('\n', "\\n\"\n    \""),
            key.replace('\n', "\\n' +\n    '"),
            key.replace('\n', "\n# "),
            key.replace('\n', "\n// "),
            key.replace('\n', "\n * "),
            key.replace('\n', "\n> "),
            key.replace('\n', "\n+"),
            key.replace('\n', "\n; "),
            key.replace('\n', "\",\n\""),
            key.replace('\n', "&#xA;"),
            key.replace('\n', "\\n\" + b\""),
            lowercase_labels,
        ] {
            assert!(!is_malformed(&representation));
        }
        let encoded = STANDARD.encode(pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
        let wrapped = encoded
            .as_bytes()
            .chunks(8)
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect::<Vec<_>>()
            .join(" \t\r\n");
        assert!(!is_malformed(&format!(
            "-----BEGIN PRIVATE KEY-----\n{wrapped}\n-----END PRIVATE KEY-----"
        )));
        assert!(!is_malformed("-----BEGIN PRIVATE KEY-----\npartial leak"));
        assert!(!is_malformed(&format!(
            "-----BEGIN PRIVATE KEY-----{}-----END PRIVATE KEY-----",
            "x".repeat(MAX_CANDIDATE_BYTES)
        )));
    }

    #[test]
    fn stub_markers_and_partial_diff_prefixes_do_not_hide_keys() {
        let key = pem("PRIVATE KEY", &pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
        for label in ["RSA PRIVATE KEY", "EC PRIVATE KEY"] {
            assert!(!is_malformed(&format!("-----BEGIN {label}-----\n{key}")));
        }
        let encoded = STANDARD.encode(pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])));
        let lines: Vec<_> =
            encoded.as_bytes().chunks(8).map(|line| std::str::from_utf8(line).unwrap()).collect();
        for changed in [vec![0], vec![0, 1, 2, 3], vec![0, 2, 4, 6], vec![4, 5, 6, 7]] {
            let body =
                lines
                    .iter()
                    .enumerate()
                    .map(|(index, line)| {
                        if changed.contains(&index) { format!("+{line}") } else { line.to_string() }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
            let candidate =
                format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----");
            if changed.len() == 4 {
                // Four added '+' characters still form valid Base64, but its
                // decoded container fails. This must exercise the repair path.
                assert!(malformed_container(&ENVELOPE.captures(&candidate).unwrap()));
            }
            assert!(!is_malformed(&candidate));
        }
    }

    #[test]
    fn der_key_material_survives_misleading_pem_labels() {
        for bytes in [
            rsa(false),
            pkcs8("1.2.840.113549.1.1.1", &rsa(false)),
            ec(None, false),
            sequence(&(0..=5).map(integer).collect::<Vec<_>>()),
        ] {
            for label in [
                "PRIVATE KEY",
                "ENCRYPTED PRIVATE KEY",
                "RSA PRIVATE KEY",
                "EC PRIVATE KEY",
                "DSA PRIVATE KEY",
            ] {
                assert!(!is_malformed(&pem(label, &bytes)), "{label}");
            }
        }
    }

    #[test]
    fn adjacent_placeholders_are_filtered_without_hiding_any_real_or_partial_key() {
        let placeholder = "-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n-----END PRIVATE KEY-----";
        assert!(is_malformed(&format!("{placeholder}\n{placeholder}")));
        let key = pem("RSA PRIVATE KEY", &rsa(false));
        assert!(!is_malformed(&format!("{placeholder}\n{key}")));
        assert!(!is_malformed(&format!("{key}\n{placeholder}")));
        assert!(!is_malformed(&format!("{placeholder}\n-----BEGIN PRIVATE KEY-----\npartial")));
    }

    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        [&(bytes.len() as u32).to_be_bytes()[..], bytes].concat()
    }

    fn ssh_container(
        cipher: &[u8],
        kdf: &[u8],
        options: &[u8],
        public: &[u8],
        private: &[u8],
    ) -> Vec<u8> {
        [
            b"openssh-key-v1\0".to_vec(),
            ssh_string(cipher),
            ssh_string(kdf),
            ssh_string(options),
            1_u32.to_be_bytes().to_vec(),
            ssh_string(public),
            ssh_string(private),
        ]
        .concat()
    }

    fn ssh_public(algorithm: &[u8], fields: &[Vec<u8>]) -> Vec<u8> {
        [ssh_string(algorithm), fields.iter().flat_map(|f| ssh_string(f)).collect()].concat()
    }

    fn ssh_private(algorithm: &[u8], fields: &[Vec<u8>]) -> Vec<u8> {
        let mut private = [
            0x12345678_u32.to_be_bytes().repeat(2),
            ssh_public(algorithm, fields),
            ssh_string(b"synthetic"),
        ]
        .concat();
        let padding = (8 - private.len() % 8) % 8;
        private.extend((1..=padding).map(|n| n as u8));
        private
    }

    #[test]
    fn checks_openssh_records_checkints_field_sizes_padding_and_aead() {
        for (algorithm, public_fields, private_fields) in [
            (&b"ssh-ed25519"[..], vec![vec![0x35; 32]], vec![vec![0x35; 32], vec![0x47; 64]]),
            (
                b"ssh-rsa",
                vec![vec![3], vec![5]],
                vec![vec![5], vec![3], vec![7], vec![11], vec![13], vec![17]],
            ),
            (b"ssh-dss", vec![vec![3]; 4], vec![vec![3]; 5]),
            (
                b"ecdsa-sha2-nistp256",
                vec![b"nistp256".to_vec(), vec![4; 65]],
                vec![b"nistp256".to_vec(), vec![4; 65], vec![0x35; 32]],
            ),
        ] {
            let public = ssh_public(algorithm, &public_fields);
            let private = ssh_private(algorithm, &private_fields);
            let container = ssh_container(b"none", b"none", b"", &public, &private);
            assert!(!is_malformed(&pem("OPENSSH PRIVATE KEY", &container)));
            let mut bad = private.clone();
            bad[0] ^= 1;
            assert!(is_malformed(&pem(
                "OPENSSH PRIVATE KEY",
                &ssh_container(b"none", b"none", b"", &public, &bad)
            )));
            let mut bad = private.clone();
            bad.extend([0; 8]);
            assert!(is_malformed(&pem(
                "OPENSSH PRIVATE KEY",
                &ssh_container(b"none", b"none", b"", &public, &bad)
            )));
            assert!(is_malformed(&pem("OPENSSH PRIVATE KEY", &container[..container.len() - 1])));
            let options = [ssh_string(&[0x35; 16]), 16_u32.to_be_bytes().to_vec()].concat();
            assert!(!is_malformed(&pem(
                "OPENSSH PRIVATE KEY",
                &ssh_container(b"aes256-ctr", b"bcrypt", &options, &public, &[0x35; 64])
            )));
            let mut aead =
                ssh_container(b"aes256-gcm@openssh.com", b"bcrypt", &options, &public, &[0x35; 64]);
            assert!(is_malformed(&pem("OPENSSH PRIVATE KEY", &aead)));
            aead.extend([0x47; 16]);
            assert!(!is_malformed(&pem("OPENSSH PRIVATE KEY", &aead)));
        }
        let public = ssh_public(b"ssh-ed25519", &[vec![0x35; 32]]);
        let private = ssh_private(b"ssh-ed25519", &[vec![0x35; 32], vec![0x47; 63]]);
        assert!(is_malformed(&pem(
            "OPENSSH PRIVATE KEY",
            &ssh_container(b"none", b"none", b"", &public, &private)
        )));
        let public = ssh_public(b"sk-future@openssh.com", &[vec![0x35; 32]]);
        let private = ssh_private(b"sk-future@openssh.com", &[vec![0x47; 64]]);
        assert!(!is_malformed(&pem(
            "OPENSSH PRIVATE KEY",
            &ssh_container(b"none", b"none", b"", &public, &private)
        )));
    }

    fn pgp_secret() -> Vec<u8> {
        let mut packet = vec![4, 0, 0, 0, 0, 1]; // v4 RSA
        packet.extend([0, 2, 3].repeat(2)); // public MPIs
        packet.push(0); // unencrypted
        let secret = [0, 2, 3].repeat(4);
        let checksum = secret.iter().map(|b| u16::from(*b)).sum::<u16>();
        packet.extend(secret);
        packet.extend(checksum.to_be_bytes());
        packet
    }

    #[test]
    fn checks_openpgp_packet_framing_secret_material_and_armor_checksum() {
        let packet = pgp_secret();
        let new = [&[0xc5, packet.len() as u8][..], &packet].concat();
        let old = [&[0x94, packet.len() as u8][..], &packet].concat();
        let partial =
            [&[0xc5, 0xe4][..], &packet[..16], &[(packet.len() - 16) as u8], &packet[16..]]
                .concat();
        for bytes in [new.clone(), old, partial] {
            let armored = pem("PGP PRIVATE KEY BLOCK", &bytes);
            assert!(!is_malformed(&armored));
            let checksum = crc24(&bytes).to_be_bytes();
            let checksummed = armored.replace(
                "\n-----END",
                &format!("\n={}\n-----END", STANDARD.encode(&checksum[1..])),
            );
            assert!(!is_malformed(&checksummed));
            assert!(is_malformed(&checksummed.replace(&STANDARD.encode(&checksum[1..]), "AAAA")));
            let header = armored.replacen(
                '\n',
                "\nVersion: synthetic fixture\nComment: not a real key\n\n",
                1,
            );
            assert!(!is_malformed(&header));
        }
        let mut bad_secret = new.clone();
        *bad_secret.last_mut().unwrap() ^= 1;
        for bytes in [
            new[..new.len() - 1].to_vec(),
            vec![0xc5, 0xff, 0xff, 0xff, 0xff, 0xff],
            bad_secret,
            [&[0xc6, packet.len() as u8][..], &packet].concat(),
            vec![0xc5, 8, 4, 0, 0, 0, 0, 1, 0, 8],
        ] {
            assert!(is_malformed(&pem("PGP PRIVATE KEY BLOCK", &bytes)));
        }
        assert!(!is_malformed(&pem("PGP PRIVATE KEY BLOCK", &[0xc5, 8, 6, 0, 0, 0, 0, 99, 1, 2])));
        assert_eq!(crc24(b"123456789"), 0x21cf02);
    }

    #[test]
    fn pgp_mpi_bit_padding_is_not_proof_that_key_material_is_invalid() {
        for bits in [1, 8] {
            let mut packet = pgp_secret();
            for offset in [7, 10, 14, 17, 20, 23] {
                packet[offset] = bits;
            }
            let checksum: u16 = packet[13..25].iter().map(|byte| u16::from(*byte)).sum();
            packet[25..].copy_from_slice(&checksum.to_be_bytes());
            let bytes = [vec![0xc5, packet.len() as u8], packet].concat();
            assert!(!is_malformed(&pem("PGP PRIVATE KEY BLOCK", &bytes)));
        }
        let mut truncated = pgp_secret();
        truncated[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(is_malformed(&pem(
            "PGP PRIVATE KEY BLOCK",
            &[vec![0xc5, truncated.len() as u8], truncated,].concat()
        )));
    }

    #[test]
    fn retains_legacy_and_encrypted_pgp_algorithms_and_secret_subkeys() {
        for algorithm in [1, 2, 3, 16, 17, 18, 19, 20, 22] {
            let public_mpis = match algorithm {
                1..=3 => 2,
                16 | 20 => 3,
                17 => 4,
                _ => 1,
            };
            let mut packet = vec![4, 0, 0, 0, 0, algorithm];
            if matches!(algorithm, 18 | 19 | 22) {
                packet.extend([3, 0x2b, 6, 1]);
            } // synthetic curve OID
            packet.extend([0, 2, 3].repeat(public_mpis));
            if algorithm == 18 {
                packet.extend([3, 1, 8, 9]);
            } // ECDH KDF
            packet.extend([254, 9, 3, 8]); // opaque encrypted secret fields
            for tag in [5, 7] {
                let bytes = [&[0xc0 | tag, packet.len() as u8][..], &packet].concat();
                assert!(!is_malformed(&pem("PGP PRIVATE KEY BLOCK", &bytes)));
            }
        }
        for version in [2, 3] {
            let mut packet = pgp_secret();
            packet[0] = version;
            packet.splice(5..5, [0, 0]); // v2/v3 validity period
            assert!(!is_malformed(&pem(
                "PGP PRIVATE KEY BLOCK",
                &[vec![0x94, packet.len() as u8], packet].concat()
            )));
        }
    }

    #[test]
    #[ignore = "manual candidate-only microbenchmark; run with --release --ignored --nocapture"]
    fn structural_filter_microbenchmark() {
        use std::{hint::black_box, time::Instant};

        let mut rsa_fields = vec![integer(0)];
        rsa_fields.extend((0..8).map(|_| tlv(2, &[0x35; 256])));
        let cases = [
            ("Ed25519 PKCS8", pem("PRIVATE KEY", &pkcs8("1.3.101.112", &tlv(4, &[0x35; 32])))),
            ("RSA-shaped 2 KiB DER", pem("RSA PRIVATE KEY", &sequence(&rsa_fields))),
            ("Java placeholder", "-----BEGIN PRIVATE KEY-----\", \"begin key marker\"), Pair.of(expectedKeyString, \"private key pem\"), Pair.of(\"-----END PRIVATE KEY-----".to_string()),
        ];
        for (name, candidate) in cases {
            black_box(is_malformed(&candidate)); // warm the shared regexes
            let start = Instant::now();
            for _ in 0..20_000 {
                black_box(is_malformed(black_box(&candidate)));
            }
            eprintln!(
                "{name}: {:.2} microseconds/candidate",
                start.elapsed().as_secs_f64() * 1_000_000.0 / 20_000.0
            );
        }
    }

    proptest! {
        #[test]
        fn arbitrary_decoded_data_does_not_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
            for label in ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "PGP PRIVATE KEY BLOCK"] {
                let _ = is_malformed(&pem(label, &bytes));
            }
        }
    }
}
