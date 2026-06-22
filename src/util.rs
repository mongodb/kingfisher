use std::{
    borrow::Cow,
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter, stdin, stdout},
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use std::sync::LazyLock;

use blake3::Hasher;
use dashmap::DashSet;
use path_dedot::ParseDot;
use rand::RngExt;
// Generate a random salt once and use it for the entire application runtime
static APP_SALT: LazyLock<String> = LazyLock::new(generate_salt);
static REDACTION_ENABLED: AtomicBool = AtomicBool::new(false);

const MIN_TOKIO_BLOCKING_THREADS: usize = 32;
const TOKIO_BLOCKING_THREADS_PER_JOB: usize = 8;
const MAX_TOKIO_BLOCKING_THREADS: usize = 256;

/// Per-runtime cap for Tokio's blocking thread pool.
///
/// Tokio defaults to 512 blocking threads per runtime. Kingfisher can run the
/// main and artifact-fetcher runtimes at the same time, so keeping each runtime
/// below that default avoids runaway thread growth during validation-heavy scans.
pub fn tokio_blocking_threads_limit(num_jobs: usize) -> usize {
    num_jobs
        .saturating_mul(TOKIO_BLOCKING_THREADS_PER_JOB)
        .clamp(MIN_TOKIO_BLOCKING_THREADS, MAX_TOKIO_BLOCKING_THREADS)
}

/// Interns a string once and returns a `'static` reference to it.
pub fn intern(s: &str) -> &'static str {
    static INTERN: LazyLock<DashSet<&'static str>> = LazyLock::new(|| DashSet::with_capacity(512));

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

/// Enables or disables global output redaction.
pub fn set_redaction_enabled(enabled: bool) {
    REDACTION_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Returns true if redaction is enabled for user-facing output.
pub fn redaction_enabled() -> bool {
    REDACTION_ENABLED.load(Ordering::Relaxed)
}

/// Returns either the original value or a redacted placeholder depending on
/// the current redaction setting.
pub fn display_value(value: &'static str) -> Cow<'static, str> {
    if redaction_enabled() { Cow::Owned(redact_value(value)) } else { Cow::Borrowed(value) }
}
// Generate a random salt (16-character alphanumeric string)
fn generate_salt() -> String {
    let bytes: [u8; 16] = rand::rng().random();
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
        Some(p) => Ok(Box::new(BufWriter::new(create_no_follow(p.as_ref())?))),
    }
}

/// Create (truncating) a file for writing, refusing to follow a symlink at the
/// final path component.
///
/// A scanned repository can contain a symlink at the report output path (e.g.
/// `report.json` in the workspace). Plain `File::create` follows it and
/// truncates whatever the link targets, letting a malicious repo clobber files
/// outside the workspace as the scanner user. `O_NOFOLLOW` makes the open fail
/// atomically when the final component is a symlink, closing the TOCTOU window.
fn create_no_follow(path: &Path) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    // Without O_NOFOLLOW, fall back to a pre-open symlink check. This is racy
    // (TOCTOU) but still rejects the common case of a committed symlink sitting
    // at the report path.
    #[cfg(not(unix))]
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("refusing to write output through symlink: {}", path.display()),
        ));
    }

    match opts.open(path) {
        Ok(file) => Ok(file),
        // O_NOFOLLOW surfaces a symlinked final component as ELOOP; report it as
        // a clear refusal rather than the opaque OS message.
        #[cfg(unix)]
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("refusing to write output through symlink: {}", path.display()),
        )),
        Err(e) => Err(e),
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
    input.len().is_multiple_of(4)
        && input
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='))
}

/// Heuristic check whether a path points to test files or directories.
///
/// Looks for common substrings like "test", "tests", "spec", "fixture", or
/// "example" in any path component. Case-insensitive.
pub fn is_test_like_path(path: &Path) -> bool {
    path.components().any(|c| {
        if let std::path::Component::Normal(os) = c
            && let Some(name) = os.to_str()
        {
            let name = name.to_ascii_lowercase();
            return name.contains("test")
                || name.contains("spec")
                || name.contains("fixture")
                || name.contains("example")
                || name.contains("sample");
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read, Write},
        path::PathBuf,
    };

    use super::{is_test_like_path, *};

    #[test]
    fn tokio_blocking_threads_limit_scales_and_caps() {
        assert_eq!(tokio_blocking_threads_limit(0), 32);
        assert_eq!(tokio_blocking_threads_limit(1), 32);
        assert_eq!(tokio_blocking_threads_limit(4), 32);
        assert_eq!(tokio_blocking_threads_limit(8), 64);
        assert_eq!(tokio_blocking_threads_limit(32), 256);
        assert_eq!(tokio_blocking_threads_limit(usize::MAX), 256);
    }

    /// Paths that **should** be classified as test-like.
    #[test]
    fn test_is_test_like_path_positive() {
        let positives = [
            "src/tests/helpers.rs",
            "/project/spec/controllers/user_spec.rb",
            "C:\\repo\\fixtures\\config.json",
            "examples/hello_world/main.go",
            "/home/user/scripts/local-testCert.pem",
            "samples/data/sample_input.txt",
        ];

        for p in positives {
            assert!(
                is_test_like_path(Path::new(p)),
                "Path {p:?} was expected to be test-like but was not"
            );
        }
    }

    /// Paths that **should not** be classified as test-like.
    #[test]
    fn test_is_test_like_path_negative() {
        let negatives = [
            "src/main.rs",
            "/opt/service/config/production.yml",
            "C:\\Program Files\\app\\README.md",
            "docs/architecture/overview.md",
            "assets/images/logo.png",
        ];

        for p in negatives {
            assert!(
                !is_test_like_path(Path::new(p)),
                "Path {p:?} was incorrectly classified as test-like"
            );
        }
    }

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
    #[cfg(unix)]
    #[test]
    fn test_get_writer_for_file_refuses_symlink() {
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"ORIGINAL_CONTENT").unwrap();

        // Simulate a malicious symlink planted at the report output path.
        let link = dir.path().join("report.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = get_writer_for_file_or_stdout(Some(&link)).err();
        assert!(err.is_some(), "writer must refuse a symlinked output path");

        // The symlink target must be left untouched (not truncated).
        assert_eq!(std::fs::read(&target).unwrap(), b"ORIGINAL_CONTENT");

        // A regular (non-symlink) path still works and truncates as before.
        let regular = dir.path().join("plain.json");
        std::fs::write(&regular, b"stale").unwrap();
        let mut writer = get_writer_for_file_or_stdout(Some(&regular)).unwrap();
        writer.write_all(b"fresh").unwrap();
        writer.flush().unwrap();
        drop(writer);
        assert_eq!(std::fs::read(&regular).unwrap(), b"fresh");
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
