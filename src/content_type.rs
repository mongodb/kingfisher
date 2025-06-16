use std::path::Path;

/// The type of content detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Unprintable or control‑heavy data.
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
    /// Create a new inspector with default thresholds.
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }

    /// Classify `bytes` as TEXT or BINARY:
    ///
    /// 1. If null‑byte count > `max_null_bytes` -- `BINARY`.
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
        if ratio > self.max_control_ratio {
            ContentType::BINARY
        } else {
            ContentType::TEXT
        }
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

    /// Detect UTF‑8 encoding by attempting a lossless conversion.
    #[inline]
    #[must_use]
    pub fn guess_charset(&self, bytes: &[u8]) -> Option<String> {
        String::from_utf8(bytes.to_vec()).ok().map(|_| "UTF-8".to_string())
    }

    /// Guess programming language by extension, else simple content markers.
    ///
    /// Extension mapping covers common languages (Rust, Python, JS, etc.).  
    /// Fallback checks for `<?php`, `package main`, `public class`, or shebangs.
    #[inline]
    #[must_use]
    pub fn guess_language(&self, path: &Path, content: &[u8]) -> Option<String> {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let name = match ext.to_ascii_lowercase().as_str() {
                "rs" => "Rust",
                "py" => "Python",
                "js" => "JavaScript",
                "ts" => "TypeScript",
                "java" => "Java",
                "c" => "C",
                "cpp" | "cc" | "cxx" => "C++",
                "go" => "Go",
                "rb" => "Ruby",
                "php" => "PHP",
                "cs" => "C#",
                "kt" | "kts" => "Kotlin",
                "scala" => "Scala",
                "swift" => "Swift",
                "sh" => "Shell",
                "pl" => "Perl",
                "lua" => "Lua",
                "hs" => "Haskell",
                "r" => "R",
                _ => "",
            };
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }

        let s = String::from_utf8_lossy(content);
        if s.contains("<?php") {
            Some("PHP".to_string())
        } else if s.contains("package main") {
            Some("Go".to_string())
        } else if s.contains("public class") {
            Some("Java".to_string())
        } else if s.contains("#!/usr/bin/env bash") || s.contains("#!/bin/bash") {
            Some("Shell".to_string())
        } else if s.contains("#!/usr/bin/env python") {
            Some("Python".to_string())
        } else {
            None
        }
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
        assert_eq!(ins.guess_language(&PathBuf::from("main.rs"), b""), Some("Rust".into()));
        assert_eq!(ins.guess_language(&PathBuf::from("x"), b"<?php echo; ?>"), Some("PHP".into()));
        assert_eq!(
            ins.guess_language(&PathBuf::from("run"), b"#!/bin/bash\necho hi"),
            Some("Shell".into())
        );
    }
}
