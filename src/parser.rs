use std::str::FromStr;

use anyhow::Result;
use regex::bytes::Regex;
use serde::Deserialize;

mod css;
mod html;
mod lexer;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Bash,
    C,
    CSharp,
    Cpp,
    Css,
    Go,
    Html,
    Java,
    JavaScript,
    Php,
    Python,
    Ruby,
    Rust,
    Toml,
    TypeScript,
    Yaml,
}

impl Language {
    pub fn name(&self) -> &'static str {
        match self {
            Language::Bash => "bash",
            Language::C => "c",
            Language::CSharp => "c_sharp",
            Language::Cpp => "cpp",
            Language::Css => "css",
            Language::Go => "go",
            Language::Html => "html",
            Language::Java => "java",
            Language::JavaScript => "javascript",
            Language::Php => "php",
            Language::Python => "python",
            Language::Ruby => "ruby",
            Language::Rust => "rust",
            Language::Toml => "toml",
            Language::TypeScript => "typescript",
            Language::Yaml => "yaml",
        }
    }

    pub fn from_hint(hint: &str) -> Option<Self> {
        match hint.to_lowercase().as_str() {
            "bash" | "shell" => Some(Language::Bash),
            "c" => Some(Language::C),
            "c#" | "csharp" => Some(Language::CSharp),
            "c++" | "cpp" => Some(Language::Cpp),
            "css" => Some(Language::Css),
            "go" => Some(Language::Go),
            "html" => Some(Language::Html),
            "java" => Some(Language::Java),
            "javascript" | "js" => Some(Language::JavaScript),
            "php" => Some(Language::Php),
            "python" | "py" | "starlark" => Some(Language::Python),
            "ruby" => Some(Language::Ruby),
            "rust" | "rs" => Some(Language::Rust),
            "toml" => Some(Language::Toml),
            "typescript" | "ts" => Some(Language::TypeScript),
            "yaml" | "yml" => Some(Language::Yaml),
            _ => None,
        }
    }
}

impl FromStr for Language {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_hint(s).ok_or_else(|| format!("Unknown language: {s}"))
    }
}

pub fn stream_context_candidates<F>(source: &[u8], language: &Language, mut sink: F) -> Result<()>
where
    F: FnMut(&str) -> bool,
{
    match language {
        Language::Css => css::stream_context_candidates(source, &mut sink),
        Language::Html => html::stream_context_candidates(source, &mut sink),
        _ => lexer::stream_context_candidates(source, language, &mut sink),
    }
}

pub fn verify_match_in_context(
    source: &[u8],
    language: &Language,
    re: &Regex,
    expected_secret: &[u8],
) -> Result<bool> {
    let mut verified = false;
    stream_context_candidates(source, language, |text| {
        verified = verify_match_in_context_text(re, expected_secret, text.as_bytes());
        !verified
    })?;
    Ok(verified)
}

fn verify_match_in_context_text(re: &Regex, expected_secret: &[u8], text: &[u8]) -> bool {
    use kingfisher_scanner::primitives::find_secret_capture;

    re.captures_iter(text)
        .any(|captures| find_secret_capture(re, &captures).as_bytes() == expected_secret)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
    };

    use super::*;

    fn fixture_cases() -> Vec<(Language, &'static str)> {
        vec![
            (Language::Bash, "testdata/shell_vulnerable.sh"),
            (Language::C, "testdata/c_vulnerable.c"),
            (Language::CSharp, "testdata/csharp_vulnerable.cs"),
            (Language::Cpp, "testdata/cpp_vulnerable.cpp"),
            (Language::Css, "testdata/css_vulnerable.css"),
            (Language::Go, "testdata/go_vulnerable.go"),
            (Language::Html, "testdata/html_embedded_vulnerable.html"),
            (Language::Html, "testdata/html_vulnerable.html"),
            (Language::Java, "testdata/java_vulnerable.java"),
            (Language::JavaScript, "testdata/javascript_vulnerable.js"),
            (Language::Php, "testdata/php_vulnerable.php"),
            (Language::Python, "testdata/parsers/comment_only_context.py"),
            (Language::Python, "testdata/python_vulnerable.py"),
            (Language::Ruby, "testdata/ruby_vulnerable.rb"),
            (Language::Rust, "testdata/rust_vulnerable.rs"),
            (Language::Toml, "testdata/toml_vulnerable.toml"),
            (Language::TypeScript, "testdata/typescript_vulnerable.ts"),
            (Language::Yaml, "testdata/yaml_vulnerable.yaml"),
        ]
    }

    fn current_capture_texts(
        root: &Path,
        cases: &[(Language, &'static str)],
    ) -> BTreeMap<String, Vec<String>> {
        let mut current = BTreeMap::new();
        for (language, rel_path) in cases {
            let file_path = root.join(rel_path);
            let source = fs::read(&file_path)
                .unwrap_or_else(|e| panic!("failed to read fixture {}: {e}", file_path.display()));
            let mut texts = Vec::new();
            stream_context_candidates(&source, language, |text| {
                texts.push(text.to_string());
                true
            })
            .unwrap_or_else(|e| panic!("context verifier failed for {}: {e}", rel_path));
            current.insert(format!("{}:{}", language.name(), rel_path), texts);
        }
        current
    }

    /// The golden file records the minimum set of candidates each fixture must
    /// produce.  The current output must be a **superset** of the golden set
    /// (every golden candidate must still appear), but new candidates are
    /// allowed — this lets us improve extraction without regenerating the
    /// golden file every time.
    #[test]
    fn context_verifier_outputs_are_superset_of_golden() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let baseline_path = root.join("testdata/parsers/context_verifier_golden.json");
        let cases = fixture_cases();
        let current = current_capture_texts(&root, &cases);

        if std::env::var("UPDATE_CONTEXT_VERIFIER_GOLDEN").as_deref() == Ok("1") {
            let payload = serde_json::to_string_pretty(&current)
                .unwrap_or_else(|e| panic!("failed to serialize golden output: {e}"));
            fs::write(&baseline_path, format!("{payload}\n")).unwrap_or_else(|e| {
                panic!("failed to write golden output {}: {e}", baseline_path.display())
            });
            return;
        }

        let baseline_raw = fs::read_to_string(&baseline_path).unwrap_or_else(|e| {
            panic!(
                "failed to read golden output {}: {e}. Run with UPDATE_CONTEXT_VERIFIER_GOLDEN=1",
                baseline_path.display()
            )
        });
        let baseline: BTreeMap<String, Vec<String>> = serde_json::from_str(&baseline_raw)
            .unwrap_or_else(|e| panic!("invalid golden JSON {}: {e}", baseline_path.display()));

        let mut regressions = Vec::new();
        for (key, expected_texts) in &baseline {
            let actual_texts = current.get(key).unwrap_or_else(|| {
                panic!("missing fixture key {key}. Run with UPDATE_CONTEXT_VERIFIER_GOLDEN=1")
            });
            for expected in expected_texts {
                if !actual_texts.contains(expected) {
                    regressions.push(format!("  {key}: missing candidate: {expected:?}"));
                }
            }
        }

        assert!(
            regressions.is_empty(),
            "context verifier regression(s) — golden candidates no longer emitted:\n{}",
            regressions.join("\n")
        );
    }

    #[test]
    fn html_embedded_context_extracts_script_and_style_candidates() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = fs::read(root.join("testdata/html_embedded_vulnerable.html")).unwrap();
        let mut texts = Vec::new();
        stream_context_candidates(&source, &Language::Html, |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();

        assert!(
            texts.iter().any(|text| text.contains("auth0_client_secret =")),
            "expected script extraction to emit auth0_client_secret candidate"
        );
        assert!(
            texts.iter().any(|text| text.contains("content =")),
            "expected style extraction to emit CSS content candidate"
        );
    }

    #[test]
    fn html_embedded_context_extracts_uppercase_script_and_style_candidates() {
        let source = br#"
            <HTML>
              <BODY>
                <SCRIPT>const auth0_client_secret = "secret-value";</SCRIPT>
                <STYLE>.banner::before { content: "hello"; }</STYLE>
              </BODY>
            </HTML>
        "#;
        let mut texts = Vec::new();
        stream_context_candidates(source, &Language::Html, |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();

        assert!(
            texts.iter().any(|text| text.contains("auth0_client_secret = secret-value")),
            "expected uppercase script tag to be handled like lowercase script"
        );
        assert!(
            texts.iter().any(|text| text.contains("content =")),
            "expected uppercase style tag to emit CSS declaration candidates"
        );
    }

    #[test]
    fn html_comment_only_script_context_is_ignored() {
        let source = br#"
            <html>
              <body>
                <script>// AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM</script>
                <div>visible text</div>
              </body>
            </html>
        "#;
        let mut texts = Vec::new();
        stream_context_candidates(source, &Language::Html, |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();

        assert!(
            !texts.iter().any(|text| text.contains("AIzaSyBUPHAjZl3n8Eza66ka6B78iVyPteC5MgM")),
            "expected commented-out script secrets to stay ignored"
        );
        assert!(
            texts.iter().any(|text| text.contains("div = visible text")),
            "expected visible non-script HTML text to remain available for verification"
        );
    }

    #[test]
    fn html_multiline_script_assignment_extracts_context() {
        let source = br#"
            <html>
              <body>
                <script>
                  const auth0_client_secret =
                    "abcd1234abcd1234abcd1234abcd1234";
                </script>
              </body>
            </html>
        "#;
        let mut texts = Vec::new();
        stream_context_candidates(source, &Language::Html, |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();

        assert!(
            texts
                .iter()
                .any(|text| text == "auth0_client_secret = abcd1234abcd1234abcd1234abcd1234"),
            "expected multiline script assignment candidate, got {texts:?}"
        );
    }

    #[test]
    fn comment_only_python_context_is_ignored() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let source = fs::read(root.join("testdata/parsers/comment_only_context.py")).unwrap();
        let mut texts = Vec::new();
        stream_context_candidates(&source, &Language::Python, |text| {
            texts.push(text.to_string());
            true
        })
        .unwrap();
        assert!(texts.is_empty());
    }
}
