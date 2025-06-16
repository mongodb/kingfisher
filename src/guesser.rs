// Fixed guesser.rs
use std::path::Path;

use anyhow::Result;

use crate::content_type::ContentInspector;

pub enum Input<'a> {
    Bytes(&'a [u8]),
    PathAndBytes(&'a Path, &'a [u8]),
}
impl<'a> Input<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self::Bytes(bytes)
    }

    pub fn from_path_and_bytes(path: &'a Path, bytes: &'a [u8]) -> Self {
        Self::PathAndBytes(path, bytes)
    }
}
/// Result from content guessing
#[derive(Debug, Default)]
pub struct Guess {
    mime_type: Option<String>,
    mime_params: Vec<(String, String)>,
    content_guess: Option<String>,
}
impl Guess {
    pub fn path_guess(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    pub fn content_guess(&self) -> Option<&str> {
        self.content_guess.as_deref()
    }

    pub fn essence_str(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    pub fn get_param(&self, param: &str) -> Option<String> {
        self.mime_params.iter().find(|(p, _)| p == param).map(|(_, v)| v.clone())
    }
}
/// Content guesser with configurable inspector
pub struct Guesser {
    inspector: ContentInspector,
}

impl Guesser {
    pub fn new() -> Result<Self> {
        Ok(Self { inspector: ContentInspector::default() })
    }

    pub fn guess(&self, input: Input<'_>) -> Guess {
        let mut guess = Guess { mime_type: None, mime_params: Vec::new(), content_guess: None };
        match input {
            Input::Bytes(bytes) => {
                guess.mime_type = Some("text/plain".to_string());
                if let Some(charset) = self.inspector.guess_charset(bytes) {
                    guess.mime_params.push(("charset".to_string(), charset));
                }
            }
            Input::PathAndBytes(path, bytes) => {
                // Try to get MIME type from extension
                match self.inspector.guess_mime_type(path) {
                    Some(mime) => guess.mime_type = Some(mime),
                    None => guess.mime_type = Some("application/octet-stream".into()),
                }

                // Charset (if textual)
                if let Some(charset) = self.inspector.guess_charset(bytes) {
                    guess.mime_params.push(("charset".into(), charset));
                }
                // Try to guess language
                guess.content_guess = self.inspector.guess_language(path, bytes);
            }
        }
        guess
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_guesser() -> Result<()> {
        let guesser = Guesser::new()?;
        // Test bytes only
        let bytes = b"Hello World";
        let guess = guesser.guess(Input::from_bytes(bytes));
        assert_eq!(
            guess.path_guess(),
            Some("text/plain"),
            "expected: {:?}, got: {:?}",
            Some("text/plain"),
            guess.path_guess()
        );
        assert_eq!(
            guess.content_guess(),
            None,
            "expected: {:?}, got: {:?}",
            None::<String>,
            guess.content_guess()
        );

        // Test path and bytes
        let path = PathBuf::from("test.rs");
        let guess = guesser.guess(Input::from_path_and_bytes(&path, bytes));
        assert_eq!(
            guess.path_guess(),
            Some("application/octet-stream"),
            "expected: {:?}, got: {:?}",
            Some("application/octet-stream"),
            guess.path_guess()
        );
        assert_eq!(
            guess.content_guess(),
            Some("Rust"),
            "expected: {:?}, got: {:?}",
            Some("Rust"),
            guess.content_guess()
        );
        Ok(())
    }
}
