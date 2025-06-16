use std::{
    fs::File,
    io::{stdin, stdout, BufReader, BufWriter},
    path::Path,
};

use blake3::Hasher;
use dashmap::DashSet;
use once_cell::sync::Lazy;
use path_dedot::ParseDot;
use ring::rand::{SecureRandom, SystemRandom};
// Generate a random salt once and use it for the entire application runtime
static APP_SALT: Lazy<String> = Lazy::new(|| generate_salt());

/// Interns a string once and returns a `'static` reference to it.
pub fn intern(s: &str) -> &'static str {
    static INTERN: Lazy<DashSet<&'static str>> = Lazy::new(|| DashSet::with_capacity(512));

    // Fast path: string already interned?
    if let Some(existing) = INTERN.get(s) {
        return *existing;
    }

    // Slow path: allocate one new copy for eternity.
    let static_str: &'static str = Box::leak(s.to_owned().into_boxed_str());
    INTERN.insert(static_str);
    static_str
}

pub fn is_safe_path(path: &Path) -> std::io::Result<bool> {
    Ok(path
        .parse_dot()
        .map(|p| !p.components().any(|c| matches!(c, std::path::Component::ParentDir)))
        .unwrap_or(false))
}

pub fn redact_value(value: &str) -> String {
    let mut hasher = Hasher::new();
    hasher.update(APP_SALT.as_bytes());
    hasher.update(value.as_bytes());
    let hash = hasher.finalize();
    format!("[REDACTED:{}]", hash_to_short_id(&hash))
}
// Generate a random salt (16-character alphanumeric string)
fn generate_salt() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).unwrap();
    hex::encode(bytes)
}
// Convert full hash to shorter identifier
fn hash_to_short_id(hash: &blake3::Hash) -> String {
    hash.to_hex().chars().take(8).collect()
}
/// Represents a countable item with properly pluralized log messages.
pub enum Counted<'a> {
    Regular { singular: &'a str, count: usize },
    Explicit { singular: &'a str, count: usize, plural: &'a str },
}
impl<'a> Counted<'a> {
    /// Creates a `Counted` with explicit singular and plural forms.
    pub fn new(count: usize, singular: &'a str, plural: &'a str) -> Self {
        Counted::Explicit { singular, plural, count }
    }

    /// Creates a `Counted` with a singular form, automatically pluralizing by
    /// adding "s".
    pub fn regular(count: usize, singular: &'a str) -> Self {
        Counted::Regular { singular, count }
    }
}
impl<'a> std::fmt::Display for Counted<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Counted::Explicit { singular, plural, count } => {
                write!(f, "{} {}", count, if *count == 1 { singular } else { plural })
            }
            Counted::Regular { singular, count } => {
                write!(f, "{} {}{}", count, singular, if *count == 1 { "" } else { "s" })
            }
        }
    }
}
/// Returns a buffered writer for a specified file path or stdout if none is
/// provided.
pub fn get_writer_for_file_or_stdout<P: AsRef<Path>>(
    path: Option<P>,
) -> std::io::Result<Box<dyn std::io::Write>> {
    match path {
        None => Ok(Box::new(BufWriter::new(stdout()))),
        Some(p) => Ok(Box::new(BufWriter::new(File::create(p)?))),
    }
}
/// Returns a buffered reader for a specified file path or stdin if none is
/// provided.
pub fn get_reader_for_file_or_stdin<P: AsRef<Path>>(
    path: Option<P>,
) -> std::io::Result<Box<dyn std::io::Read>> {
    match path {
        None => Ok(Box::new(BufReader::new(stdin()))),
        Some(p) => Ok(Box::new(BufReader::new(File::open(p)?))),
    }
}
/// Determines whether the input string is valid Base64.
pub fn is_base64(input: &str) -> bool {
    input.len() % 4 == 0
        && input
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='))
}
#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read, Write},
        path::PathBuf,
    };

    use super::*;
    #[test]
    fn test_counted_display_regular() {
        let single = Counted::regular(1, "rule");
        let multiple = Counted::regular(3, "rule");
        assert_eq!(format!("{}", single), "1 rule");
        assert_eq!(format!("{}", multiple), "3 rules");
    }
    #[test]
    fn test_counted_display_explicit() {
        let single = Counted::new(1, "person", "people");
        let multiple = Counted::new(5, "person", "people");
        assert_eq!(format!("{}", single), "1 person");
        assert_eq!(format!("{}", multiple), "5 people");
    }
    #[test]
    fn test_get_writer_for_file_or_stdout_stdout() {
        use std::io::Write;
        // Test writing to stdout
        let mut writer = get_writer_for_file_or_stdout::<PathBuf>(None).unwrap();
        // Write a test string to ensure it's writing to stdout without errors
        let result = writer.write(b"Test output to stdout\n");
        assert!(result.is_ok(), "Failed to write to stdout");
    }
    #[test]
    fn test_get_writer_for_file_or_stdout_file() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        // Test writing to a file
        let mut writer = get_writer_for_file_or_stdout(Some(&path)).unwrap();
        writer.write_all(b"Test content").unwrap();
        writer.flush().unwrap();
        // Verify file content
        let mut file_content = String::new();
        std::fs::File::open(&path).unwrap().read_to_string(&mut file_content).unwrap();
        assert_eq!(file_content, "Test content");
    }
    #[test]
    fn test_get_reader_for_file_or_stdin_stdin() {
        // Test reading from stdin (mocked)
        let input = b"stdin test content";
        let mut stdin_mock = Cursor::new(input);
        let mut reader = BufReader::new(&mut stdin_mock);
        let mut buffer = String::new();
        reader.read_to_string(&mut buffer).unwrap();
        assert_eq!(buffer, "stdin test content");
    }
    #[test]
    fn test_get_reader_for_file_or_stdin_file() {
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        std::fs::write(&path, "File test content").unwrap();
        // Test reading from a file
        let mut reader = get_reader_for_file_or_stdin(Some(&path)).unwrap();
        let mut buffer = String::new();
        reader.read_to_string(&mut buffer).unwrap();
        assert_eq!(buffer, "File test content");
    }
    #[test]
    fn test_is_base64_valid() {
        let valid_base64 = "SGVsbG8gV29ybGQh"; // "Hello World!" in Base64
        let valid_base64_with_padding = "SGVsbG8gdGhpcyB3b3JsZAo=";
        let valid_empty = "";
        assert!(is_base64(valid_base64));
        assert!(is_base64(valid_base64_with_padding));
        assert!(is_base64(valid_empty));
    }
    #[test]
    fn test_is_base64_invalid() {
        let invalid_base64 = "Hello World!";
        let invalid_length = "SGVsbG8"; // Not divisible by 4
        let invalid_characters = "SGVsbG8$V29ybGQh";
        assert!(!is_base64(invalid_base64));
        assert!(!is_base64(invalid_length));
        assert!(!is_base64(invalid_characters));
    }
}
