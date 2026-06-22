use std::{cmp::Reverse, path::Path, sync::LazyLock};
use tokei::LanguageType;

// Precompute all (shebang_prefix_bytes, language) pairs once.
// Sort longest-first so more specific shebangs win.
static SHEBANG_PREFIXES: LazyLock<Vec<(&'static [u8], LanguageType)>> = LazyLock::new(|| {
    let mut v = Vec::new();
    for &(lang, shebangs) in LanguageType::list() {
        for &sb in shebangs {
            v.push((sb.as_bytes(), lang));
        }
    }
    // Longest prefix first to prefer e.g. "#!/usr/bin/env python3" over "#!/usr/bin/env python"
    v.sort_by_key(|(prefix, _)| Reverse(prefix.len()));
    v
});

/// The type of content detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Unprintable or control-heavy data.
    BINARY,
    /// Mostly printable text.
    TEXT,
}

/// Heuristic thresholds for text vs. binary detection.
pub struct ContentInspector {
    max_null_bytes: usize,
    max_control_ratio: f64,
}

impl Default for ContentInspector {
    fn default() -> Self {
        Self { max_null_bytes: 4, max_control_ratio: 0.3 }
    }
}

impl ContentInspector {
    /// Maximum bytes inspected for content-based language hints.
    const LANGUAGE_SAMPLE_BYTES: usize = 4096;
    /// Create a new inspector with default thresholds.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Classify `bytes` as TEXT or BINARY:
    ///
    /// 1. If null-byte count > `max_null_bytes` -- `BINARY`.
    /// 2. Else if (control chars excluding `\n`, `\r`, `\t`) / total > `max_control_ratio` →
    ///    `BINARY`.
    /// 3. Otherwise,  `TEXT`.
    #[inline]
    #[must_use]
    pub fn inspect(&self, bytes: &[u8]) -> ContentType {
        let nulls = bytes.iter().filter(|&&b| b == 0).count();
        if nulls > self.max_null_bytes {
            return ContentType::BINARY;
        }
        let controls =
            bytes.iter().filter(|&&b| b < 32 && !matches!(b, b'\n' | b'\r' | b'\t')).count();
        let ratio = if bytes.is_empty() { 0.0 } else { controls as f64 / bytes.len() as f64 };
        if ratio > self.max_control_ratio { ContentType::BINARY } else { ContentType::TEXT }
    }

    /// Guess MIME type from `path` extension.
    ///
    /// Returns:
    /// - `Some(mime)` if the extension is one of the known text or image types.
    /// - `None` if there is no extension or it’s unrecognized.
    #[inline]
    #[must_use]
    pub fn guess_mime_type(&self, path: &Path) -> Option<String> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        let mime = match ext.as_str() {
            "txt" | "md" | "rst" => "text/plain",
            "html" | "htm" => "text/html",
            "css" => "text/css",
            "js" => "application/javascript",
            "json" => "application/json",
            "xml" => "application/xml",
            "pdf" => "application/pdf",
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            "gif" => "image/gif",
            _ => return None,
        };
        Some(mime.to_string())
    }

    /// Detect UTF-8 encoding by attempting a lossless conversion.
    #[inline]
    #[must_use]
    pub fn guess_charset(&self, bytes: &[u8]) -> Option<String> {
        std::str::from_utf8(bytes).ok().map(|_| "UTF-8".to_string())
    }
    /// Guess programming language with broad coverage using `tokei`.
    ///
    /// Strategy (no disk I/O):
    /// 1) Try extension via `LanguageType::from_file_extension`.
    /// 2) Handle common extensionless filenames (e.g., Makefile, Dockerfile, CMakeLists.txt).
    /// 3) Parse an in-memory shebang (first line) against `LanguageType::shebangs`.
    /// 4) Minimal content markers as a last resort.
    ///
    /// Returns the canonical `tokei` language name (e.g., `Rust`, `Bash`, `Python`).
    #[inline]
    #[must_use]
    pub fn guess_language(&self, path: &Path, content: &[u8]) -> Option<String> {
        // 1) Extension mapping (turbo, no I/O).
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && let Some(lang) = LanguageType::from_file_extension(&ext.to_ascii_lowercase())
        {
            return Some(lang.name().to_string());
        }

        // 2) Well-known filenames with no/odd extensions (avoid from_path to keep this pure).
        if let Some(file) = path.file_name().and_then(|f| f.to_str()) {
            match file {
                "Makefile" | "makefile" => {
                    return Some(LanguageType::Makefile.name().to_string());
                }
                "Dockerfile" | "dockerfile" => {
                    return Some(LanguageType::Dockerfile.name().to_string());
                }
                "CMakeLists.txt" => {
                    return Some(LanguageType::CMake.name().to_string());
                }
                "Rakefile" | "rakefile" => {
                    return Some(LanguageType::Rakefile.name().to_string());
                }
                // Common ecosystem files; map to their primary language where sensible.
                "Gemfile" | "gemfile" => {
                    return Some(LanguageType::Ruby.name().to_string());
                }
                _ => {}
            }
        }

        // Limit expensive content probing to a small prefix. This keeps language
        // detection cheap for large files while preserving extension-based accuracy.
        let sample = &content[..content.len().min(Self::LANGUAGE_SAMPLE_BYTES)];

        // 3) Shebang detection (in-memory): match by longest prefix, byte-wise (no UTF-8 needed).
        if let Some(first_line) = sample.split(|&b| b == b'\n').next()
            && first_line.starts_with(b"#!")
        {
            for (prefix, lang) in SHEBANG_PREFIXES.iter() {
                if first_line.starts_with(prefix) {
                    return Some(lang.name().to_string());
                }
            }
        }

        // 4) Lightweight content markers to catch a few ubiquitous cases without I/O.
        let s = String::from_utf8_lossy(sample);
        if s.contains("<?php") {
            return Some(LanguageType::Php.name().to_string());
        }
        if s.contains("package main") {
            return Some(LanguageType::Go.name().to_string());
        }
        if s.contains("public class") {
            return Some(LanguageType::Java.name().to_string());
        }
        if s.contains("#!/usr/bin/env bash") || s.contains("#!/bin/bash") {
            return Some(LanguageType::Bash.name().to_string());
        }
        if s.contains("#!/usr/bin/env python") {
            return Some(LanguageType::Python.name().to_string());
        }

        None
    }
}

/// Shorthand: inspect with default thresholds.
#[inline]
#[must_use]
pub fn inspect(bytes: &[u8]) -> ContentType {
    ContentInspector::default().inspect(bytes)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn binary_vs_text() {
        let ins = ContentInspector::default();
        let bin = vec![0, 1, 2, 0, 0, 0, 5];
        assert_eq!(ins.inspect(&bin), ContentType::BINARY);
        let txt = b"Hello\nWorld";
        assert_eq!(ins.inspect(txt), ContentType::TEXT);
    }

    #[test]
    fn mime_guess() {
        let ins = ContentInspector::default();
        assert_eq!(ins.guess_mime_type(&PathBuf::from("a.md")), Some("text/plain".into()));
        assert_eq!(ins.guess_mime_type(&PathBuf::from("img.png")), Some("image/png".into()));
        assert_eq!(ins.guess_mime_type(&PathBuf::from("x.xyz")), None);
    }

    #[test]
    fn charset_guess() {
        let ins = ContentInspector::default();
        assert_eq!(ins.guess_charset("ok".as_bytes()), Some("UTF-8".into()));
        assert_eq!(ins.guess_charset(&[0xFF, 0xFE, 0xFD]), None);
    }

    #[test]
    fn language_guess() {
        let ins = ContentInspector::default();

        // Compare case-insensitively by lowercasing both sides.
        let rust =
            ins.guess_language(&PathBuf::from("main.rs"), b"").map(|s| s.to_ascii_lowercase());
        assert_eq!(rust, Some("rust".into()));

        let php = ins
            .guess_language(&PathBuf::from("x"), b"<?php echo; ?>")
            .map(|s| s.to_ascii_lowercase());
        assert_eq!(php, Some("php".into()));

        let bash = ins
            .guess_language(&PathBuf::from("run"), b"#!/bin/bash\necho hi")
            .map(|s| s.to_ascii_lowercase());
        assert_eq!(bash, Some("bash".into()));
    }
}
