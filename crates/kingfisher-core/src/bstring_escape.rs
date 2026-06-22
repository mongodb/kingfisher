//! Safe string escaping utilities.
//!
//! This module provides utilities for safely displaying byte strings that may
//! contain non-UTF8 data, ANSI escape codes, or control characters.

use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

use console::strip_ansi_codes;

/// Escapes non-printing characters in a string while preserving whitespace.
///
/// Returns borrowed data if no escaping was needed, avoiding allocations.
fn escape_nonprinting(s: &str) -> Cow<'_, str> {
    // Fast path - return original if no control chars (except whitespace)
    if s.chars().all(|ch| !ch.is_control() || ch.is_whitespace()) {
        return Cow::Borrowed(s);
    }

    // Allocate with extra capacity for possible escape sequences
    let mut escaped = String::with_capacity(s.len() * 2);
    for ch in s.chars() {
        match ch {
            // Handle ANSI escape sequences
            '\x1B' => continue,
            // Escape non-whitespace control characters
            ch if ch.is_control() && !ch.is_whitespace() => {
                use std::fmt::Write;
                write!(escaped, "{}", ch.escape_unicode()).expect("string writing must succeed");
            }
            // Pass through all other characters unchanged
            ch => escaped.push(ch),
        }
    }

    Cow::Owned(escaped)
}

/// A wrapper around `&[u8]` that provides safe string formatting.
///
/// When displayed, `Escaped` will:
/// 1. Convert from UTF-8 with replacement of invalid sequences
/// 2. Remove ANSI control sequences
/// 3. Escape remaining control characters (except whitespace)
///
/// # Examples
///
/// ```
/// use kingfisher_core::Escaped;
///
/// let bytes = b"Hello\x00World";
/// let escaped = Escaped(bytes);
/// assert_eq!(escaped.to_string(), "Hello\\u{0}World");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Escaped<'a>(pub &'a [u8]);

impl Display for Escaped<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // First handle UTF-8 decoding with replacement characters
        let decoded = String::from_utf8_lossy(self.0);
        // Then strip ANSI sequences and escape control chars
        let stripped = strip_ansi_codes(&decoded);
        let escaped = escape_nonprinting(&stripped);
        f.write_str(&escaped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_normal_text() {
        let input = "Hello, World!";
        let result = escape_nonprinting(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "Hello, World!");
    }

    #[test]
    fn test_escape_with_whitespace() {
        let input = "Hello\n\t World!";
        let result = escape_nonprinting(input);
        assert!(matches!(result, Cow::Borrowed(_)));
        assert_eq!(result, "Hello\n\t World!");
    }

    #[test]
    fn test_escape_control_chars() {
        let input = "Hello\x00World\x01";
        let result = escape_nonprinting(input);
        assert!(matches!(result, Cow::Owned(_)));
        assert_eq!(result, "Hello\\u{0}World\\u{1}");
    }

    #[test]
    fn test_escaped_struct_simple() {
        let bytes = b"Hello World";
        let escaped = Escaped(bytes);
        assert_eq!(escaped.to_string(), "Hello World");
    }

    #[test]
    fn test_escaped_struct_ansi_codes() {
        let bytes = b"\x1b[31mRed\x1b[0m \x1b[32mGreen\x1b[0m";
        let escaped = Escaped(bytes);
        assert_eq!(escaped.to_string(), "Red Green");
    }

    #[test]
    fn test_escaped_struct_invalid_utf8() {
        let bytes = b"Hello\xFF\xFEWorld";
        let escaped = Escaped(bytes);
        assert_eq!(escaped.to_string(), "Hello\u{FFFD}\u{FFFD}World");
    }

    #[test]
    fn test_escaped_struct_empty() {
        let bytes = b"";
        let escaped = Escaped(bytes);
        assert_eq!(escaped.to_string(), "");
    }
}
