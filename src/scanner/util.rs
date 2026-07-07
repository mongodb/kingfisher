use std::path::Path;

use crate::decompress::{ZIP_BASED_FORMATS, looks_like_zip};

pub fn is_compressed_file(path: &Path) -> bool {
    // Get the full filename
    let filename = match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name.to_lowercase(),
        None => return false,
    };
    // Check for compound extensions first
    if filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.gzip")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.bzip2")
        || filename.ends_with(".tar.xz")
    {
        return true;
    }
    // Then check single extensions
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        ext_lower == "gz"
            || ext_lower == "gzip"
            || ext_lower == "tgz"
            || ext_lower == "bz2"
            || ext_lower == "bzip2"
            || ext_lower == "xz"
            || ext_lower == "tar"
            || ext_lower == "zlib"
            || ext_lower == "asar"
            || ext_lower == "hwp"
            || ext_lower == "egg"
            || ZIP_BASED_FORMATS.iter().any(|z| *z == ext_lower)
    } else {
        false
    }
}

/// Like [`is_compressed_file`], but also recognizes ZIP containers by their
/// leading magic bytes when the filename carries no known archive extension
/// (e.g. a Terraform `tfplan`/`tf.plan`). The extension check short-circuits
/// first, so recognized archives pay nothing extra and non-ZIP files are
/// unaffected — [`looks_like_zip`] inspects at most the first four bytes.
pub fn is_compressed_content(path: &Path, data: &[u8]) -> bool {
    is_compressed_file(path) || looks_like_zip(data)
}

const SQLITE_EXTENSIONS: &[&str] = &["db", "sqlite", "sqlite3", "db3", "s3db", "sl3"];
/// SQLite file header magic bytes. Useful for detecting extensionless SQLite
/// files (e.g. Chrome `Cookies`, `History`, `Web Data`).
#[allow(dead_code)]
pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

pub fn is_pyc_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        ext_lower == "pyc" || ext_lower == "pyo"
    } else {
        false
    }
}

pub fn is_sqlite_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        let ext_lower = ext.to_lowercase();
        if SQLITE_EXTENSIONS.iter().any(|e| *e == ext_lower) {
            return true;
        }
    }
    false
}

/// Check the first 16 bytes of `data` for the SQLite magic header.
#[allow(dead_code)]
pub fn has_sqlite_magic(data: &[u8]) -> bool {
    data.len() >= SQLITE_MAGIC.len() && data[..SQLITE_MAGIC.len()] == *SQLITE_MAGIC
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{is_compressed_content, is_compressed_file};

    /// Minimal but valid local-file-header ZIP signature.
    const ZIP_MAGIC: &[u8] = b"PK\x03\x04";

    #[test]
    fn recognizes_tar_wrapped_long_compression_extensions() {
        assert!(is_compressed_file(Path::new("archive.tar.gzip")));
        assert!(is_compressed_file(Path::new("archive.tar.bzip2")));
    }

    #[test]
    fn recognizes_long_single_compression_extensions() {
        assert!(is_compressed_file(Path::new("payload.gzip")));
        assert!(is_compressed_file(Path::new("payload.bzip2")));
    }

    #[test]
    fn content_sniffing_detects_zip_without_known_extension() {
        // Terraform plan artifacts: a ZIP body under a non-archive name.
        assert!(is_compressed_content(Path::new("tf.plan"), ZIP_MAGIC));
        assert!(is_compressed_content(Path::new("tfplan"), ZIP_MAGIC));
        assert!(is_compressed_content(Path::new("no_extension_at_all"), ZIP_MAGIC));
    }

    #[test]
    fn content_sniffing_ignores_non_zip_files() {
        // A file named like a plan but whose bytes are plain text must not be
        // promoted to an archive: no drawbacks for non-ZIP content.
        assert!(!is_compressed_content(Path::new("notes.plan"), b"just some text\n"));
        assert!(!is_compressed_content(Path::new("empty.plan"), b""));
        assert!(!is_compressed_content(Path::new("short.plan"), b"PK"));
    }

    #[test]
    fn content_sniffing_still_honors_known_extensions() {
        // Extension detection short-circuits before byte inspection, so a
        // recognized archive is detected even with non-ZIP (or empty) bytes.
        assert!(is_compressed_content(Path::new("archive.zip"), b""));
        assert!(is_compressed_content(Path::new("archive.tar.gz"), b"not really gz"));
    }
}
