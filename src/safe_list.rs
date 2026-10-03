//! Safe-match filters: identify *benign* placeholder/example/redacted strings
//! so they don't get treated as real secrets. When a rule matches, we log
//! which rule/explanation fired at `debug!` level.
//
// Usage:
//   if is_safe_match(bytes) { /* skip finding */ }
//
// If you also want the specific reason:
//   if let Some(reason) = is_safe_match_reason(bytes) {
//       // reason contains the rule description
//   }

use regex::bytes::Regex;
use std::sync::{LazyLock, Mutex};
use tracing::debug;

/// A rule that describes *why* a match is considered safe/benign.
#[derive(Debug)]
struct SafeRule {
    /// Human-friendly reason that will be logged when this rule fires.
    description: &'static str,
    /// Compiled regex to detect the benign pattern.
    regex: Regex,
}

/// Compile a bytes regex and panic on failure (at init time).
fn compile(pattern: &'static str) -> Regex {
    Regex::new(pattern).unwrap_or_else(|e| {
        // These embedded patterns are compiled on first use; invalid patterns are programmer errors.
        // We still emit a debug line to aid troubleshooting in non-panic logs.
        debug!("Failed to compile safe-list regex: {pattern}\nError: {e}");
        panic!("invalid safe-list regex: {pattern}: {e}");
    })
}

/// Case-insensitive patterns that indicate a *benign* match (placeholders, examples, redactions, etc.).
/// `is_safe_match()` returns true if any of these are present and logs which rule fired.
/// `is_safe_match_reason()` returns the matching rule's description instead of logging.
static SAFE_LIST_FILTER_RULES: LazyLock<Vec<SafeRule>> = LazyLock::new(|| {
    vec![
        SafeRule {
            description: "Assignment ending with EXAMPLEKEY (placeholder)",
            regex: compile(r"(?i)[:=][^:=]{0,64}EXAMPLEKEY"),
        },
        SafeRule {
            description: "AWS AKIA key explicitly marked as example/fake/test/sample",
            regex: compile(r"(?i)\b(AKIA(?:.*?EXAMPLE|.*?FAKE|TEST|.*?SAMPLE))\b"),
        },
        SafeRule {
            description: "Secret-like key followed by redaction marker (&&, ||, or ***** run)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\s(&&|\|\||\*{5,50})",
            ),
        },
        SafeRule {
            description: "Secret-like key + short value followed by another short assignment on same line (example-y)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b\w{4,12}\s{0,6}=\s{0,6}\D{0,3}\w{1,12}",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned from a shell variable reference (e.g., $FOO), not a literal",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\$\w{4,30}",
            ),
        },
        SafeRule {
            description: "Secret-like key set via randomness generator command (openssl rand ...), not a literal",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,16}[=:?][^=:?]{0,8}\bopenssl\s{0,4}rand\b",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned a value containing 'encrypted' (metadata/marker)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}encrypted",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned boolean literal (true/false)",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(?:false|true)\b",
            ),
        },
        SafeRule {
            description: "Secret-like key assigned to null-ish or self-referential placeholders",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(null|nil|none|password|pass|pwd|passwd|secret|cred|key|auth|authorization).{1,6}$",
            ),
        },
        SafeRule {
            description: "Classic xkcd fake password 'hunter2'",
            regex: compile(
                r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}hunter2",
            ),
        },
        SafeRule {
            description: "Obvious placeholder sequences (123456789 or abcdefghij)",
            regex: compile(r"(?i)123456789|abcdefghij"),
        },
        SafeRule {
            description: "Literal placeholder tag '<secretmanager>'",
            regex: compile(r"(?i)<secretmanager>"),
        },
        SafeRule {
            description: "OpenAPI schema references near assignment/query (not a secret)",
            regex: compile(r"(?i)[=:?][^=:?]{0,8}#/components/schemas/"),
        },
        SafeRule {
            description: "Example MongoDB URI with placeholder user/pass like user:pass or foo:bar",
            regex: compile(
                r"(?i)\b(mongodb(?:\+srv)?://(?:user|foo)[^:@]+:(?:pass|bar)[^@]+@[-\w.%+/:]{3,64}(?:/\w+)?)",
            ),
        },
        SafeRule {
            description: "Classpath URI (configuration reference, not a secret)",
            regex: compile(r"(?i)\b(classpath://)"),
        },
        SafeRule {
            description: "Assignment using property placeholder like ${ENV_VAR}",
            regex: compile(r"(?i)(\b[^\s\t]{0,16}[=:][^$]*\$\{[a-z_-]{5,30}\})"),
        },
        SafeRule {
            description: "URL with basic auth to host ending in example/test (placeholder)",
            regex: compile(
                r"(?i)\b((?:https?:)?//[^:@]{3,50}:[^:@]{3,50}@[\w.]{0,16}(?:example|test))",
            ),
        },
        SafeRule {
            description: "Assignment ending with SECRETMANAGER (explicit placeholder)",
            regex: compile(r"(?i)[:=][^:=]{0,32}\bSECRETMANAGER"),
        },
    ]
});

// User-supplied allow-list patterns (regexes) and skipwords. These are empty by
// default and populated via CLI flags at runtime.
static USER_SAFE_REGEXES: LazyLock<Mutex<Vec<Regex>>> = LazyLock::new(|| Mutex::new(Vec::new()));
static USER_SAFE_SKIPWORDS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Register an additional allow-list regex provided by the user.
/// If the pattern fails to compile, the error is returned so the caller can
/// surface it.
pub fn add_user_regex(pattern: &str) -> std::result::Result<(), regex::Error> {
    let re = Regex::new(pattern)?;
    USER_SAFE_REGEXES.lock().unwrap().push(re);
    Ok(())
}

/// Register an allow-list skipword provided by the user. Comparisons are
/// case-insensitive.
pub fn add_user_skipword(word: &str) {
    USER_SAFE_SKIPWORDS.lock().unwrap().push(word.to_lowercase());
}

/// Returns `true` if the given input matches any user-supplied allow-list
/// patterns (regexes or skipwords).
///
/// `secret` is the primary capture group (typically just the secret value)
/// while `full_match` includes the entire match, allowing regexes to target
/// surrounding context such as variable names.
pub fn is_user_match(secret: &[u8], full_match: &[u8]) -> bool {
    {
        let regexes = USER_SAFE_REGEXES.lock().unwrap();
        if regexes.iter().any(|re| re.is_match(secret) || re.is_match(full_match)) {
            debug!("Safe match: user skip-regex");
            return true;
        }
    }

    let skipwords = USER_SAFE_SKIPWORDS.lock().unwrap();
    if skipwords.is_empty() {
        return false;
    }

    // Check skipwords against both the secret and full match (case-insensitive)
    let contains_skipword = |bytes: &[u8]| -> bool {
        if let Ok(s) = std::str::from_utf8(bytes) {
            let lower = s.to_lowercase();
            return skipwords.iter().any(|w| lower.contains(w));
        }
        false
    };

    if contains_skipword(secret) || contains_skipword(full_match) {
        debug!("Safe match: user skip-word");
        return true;
    }

    false
}

/// Returns `Some(&'static str)` with the rule description if the input likely
/// contains *benign* placeholder/test strings; otherwise `None`.
pub fn is_safe_match_reason(input: &[u8]) -> Option<&'static str> {
    SAFE_LIST_FILTER_RULES
        .iter()
        .find(|rule| rule.regex.is_match(input))
        .map(|rule| rule.description)
}

/// Test helper: clear all user-provided allow-list configuration.
#[doc(hidden)]
pub fn clear_user_filters_for_tests() {
    USER_SAFE_REGEXES.lock().unwrap().clear();
    USER_SAFE_SKIPWORDS.lock().unwrap().clear();
}

/// Returns true if the input likely contains *benign* placeholder/test strings,
/// and logs which rule triggered at `debug!` level.
pub fn is_safe_match(input: &[u8]) -> bool {
    if let Some(reason) = is_safe_match_reason(input) {
        debug!("Safe match: {reason}");
        true
    } else {
        false
    }
}
