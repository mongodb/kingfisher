use std::path::Path;

use crate::decompress::ZIP_BASED_FORMATS;

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

    use super::is_compressed_file;

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
}
