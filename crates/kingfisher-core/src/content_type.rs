use std::path::Path;

#[path = "language.rs"]
mod language;

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
    /// Guess a programming language using the embedded extension/name catalog.
    ///
    /// Tries the final extension first, then well-known filenames, then lightweight
    /// content markers (including Bash/Python shebangs). Performs no disk I/O.
    /// The names and extension precedence preserve the original tokei 14 catalog.
    #[inline]
    #[must_use]
    pub fn guess_language(&self, path: &Path, content: &[u8]) -> Option<String> {
        // 1) Extension mapping (turbo, no I/O).
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && let Ok(index) = language::EXTENSIONS
                .binary_search_by_key(&ext.to_ascii_lowercase().as_str(), |&(extension, _)| {
                    extension
                })
        {
            return Some(language::EXTENSIONS[index].1.to_string());
        }

        // 2) Well-known filenames with no/odd extensions (avoid from_path to keep this pure).
        if let Some(file) = path.file_name().and_then(|f| f.to_str()) {
            let language = match file {
                "Makefile" | "makefile" => Some("Makefile"),
                "Dockerfile" | "dockerfile" => Some("Dockerfile"),
                "CMakeLists.txt" => Some("CMake"),
                "Rakefile" | "rakefile" => Some("Rakefile"),
                "Gemfile" | "gemfile" => Some("Ruby"),
                _ => None,
            };
            if let Some(language) = language {
                return Some(language.to_string());
            }
        }

        // Limit expensive content probing to a small prefix. This keeps language
        // detection cheap for large files while preserving extension-based accuracy.
        let sample = &content[..content.len().min(Self::LANGUAGE_SAMPLE_BYTES)];

        // The former first-line loop used LanguageType::list() (extensions), not
        // shebangs, so it could never match a line beginning "#!". Preserve the
        // actual content-marker behavior and its precedence without that dead loop.
        // 3) Lightweight content markers to catch a few ubiquitous cases without I/O.
        let s = String::from_utf8_lossy(sample);
        if s.contains("<?php") {
            return Some("PHP".to_string());
        }
        if s.contains("package main") {
            return Some("Go".to_string());
        }
        if s.contains("public class") {
            return Some("Java".to_string());
        }
        if s.contains("#!/usr/bin/env bash") || s.contains("#!/bin/bash") {
            return Some("BASH".to_string());
        }
        if s.contains("#!/usr/bin/env python") {
            return Some("Python".to_string());
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

    /// Pins the extension table that was checked against tokei 14.0.0's
    /// `languages.json`, so accidental edits or reordering are caught. Update the
    /// count and digest only after re-checking the table against tokei.
    #[test]
    fn language_extension_table_matches_the_verified_tokei_snapshot() {
        let mut digest: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 64
        for &(extension, language) in language::EXTENSIONS {
            for byte in extension.bytes().chain(*b"\t").chain(language.bytes()).chain(*b"\n") {
                digest ^= u64::from(byte);
                digest = digest.wrapping_mul(0x0100_0000_01b3);
            }
        }
        assert_eq!(language::EXTENSIONS.len(), 517);
        assert_eq!(digest, 0xddb5_6e21_f437_4857);
    }

    /// Every table entry is reachable through the public inspector, in either case.
    #[test]
    fn legacy_language_catalog_preserves_all_extensions() {
        let ins = ContentInspector::default();
        assert!(language::EXTENSIONS.len() > 500);
        for &(extension, expected) in language::EXTENSIONS {
            // The public inspector has always considered only Path::extension(),
            // not a whole multipart suffix such as "cs.st".
            if extension.contains('.') {
                continue;
            }
            for extension in [extension.to_string(), extension.to_ascii_uppercase()] {
                let path = PathBuf::from(format!("sample.{extension}"));
                assert_eq!(ins.guess_language(&path, b""), Some(expected.to_string()), "{path:?}");
            }
        }
    }

    #[test]
    fn legacy_language_priority_and_sample_bounds() {
        let ins = ContentInspector::default();
        for (filename, expected) in [
            ("Makefile", "Makefile"),
            ("makefile", "Makefile"),
            ("Dockerfile", "Dockerfile"),
            ("dockerfile", "Dockerfile"),
            ("CMakeLists.txt", "Plain Text"),
            ("Rakefile", "Rakefile"),
            ("rakefile", "Rakefile"),
            ("Gemfile", "Ruby"),
            ("gemfile", "Ruby"),
        ] {
            assert_eq!(ins.guess_language(Path::new(filename), b""), Some(expected.to_string()));
        }
        assert_eq!(ins.guess_language(Path::new("main.RS"), b"#!/bin/bash\n"), Some("Rust".into()));
        assert_eq!(
            ins.guess_language(Path::new("script"), b"#!/bin/bash\r\necho hi"),
            Some("BASH".into())
        );
        assert_eq!(
            ins.guess_language(Path::new("script"), b"#!/usr/bin/env python3\n"),
            Some("Python".into())
        );
        assert_eq!(ins.guess_language(Path::new("unknown"), &[0xff]), None);
        let mut beyond_sample = vec![b' '; ContentInspector::LANGUAGE_SAMPLE_BYTES];
        beyond_sample.extend_from_slice(b"<?php");
        assert_eq!(ins.guess_language(Path::new("unknown"), &beyond_sample), None);
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
