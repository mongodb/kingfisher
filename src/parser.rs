use std::{cell::RefCell, error::Error as StdError, ops::Range, str, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use rustc_hash::FxHashMap;
use serde::Deserialize;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser as TreeSitterParser, Query, QueryCursor};
use tree_sitter_bash;
use tree_sitter_c;
use tree_sitter_c_sharp;
use tree_sitter_cpp;
use tree_sitter_css;
use tree_sitter_go;
use tree_sitter_html;
use tree_sitter_java;
use tree_sitter_javascript;
use tree_sitter_php;
use tree_sitter_python;
use tree_sitter_regex;
use tree_sitter_ruby;
use tree_sitter_rust;
use tree_sitter_toml_ng;
use tree_sitter_typescript;
use tree_sitter_yaml;

// use tree_sitter_php;
use crate::util::is_base64;
//
pub mod queries;
// pub(crate) type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Box<dyn StdError>>;
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
    Regex,
    Ruby,
    Rust,
    Toml,
    TypeScript,
    Yaml,
}
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub range: Range<usize>,
    pub text: String,
    pub is_base64_decoded: bool,
    pub original_base64: Option<String>, // Store original base64 if decoded
}
impl Language {
    fn name(&self) -> &'static str {
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
            Language::Regex => "regex",
            Language::Ruby => "ruby",
            Language::Rust => "rust",
            Language::Toml => "toml",
            Language::TypeScript => "typescript",
            Language::Yaml => "yaml",
        }
    }

    pub fn get_ts_language(&self) -> Result<tree_sitter::Language> {
        match self {
            Language::Bash => Ok(tree_sitter_bash::LANGUAGE.into()),
            Language::C => Ok(tree_sitter_c::LANGUAGE.into()),
            Language::CSharp => Ok(tree_sitter_c_sharp::LANGUAGE.into()),
            Language::Cpp => Ok(tree_sitter_cpp::LANGUAGE.into()),
            Language::Css => Ok(tree_sitter_css::LANGUAGE.into()),
            Language::Go => Ok(tree_sitter_go::LANGUAGE.into()),
            Language::Html => Ok(tree_sitter_html::LANGUAGE.into()),
            Language::Java => Ok(tree_sitter_java::LANGUAGE.into()),
            Language::JavaScript => Ok(tree_sitter_javascript::LANGUAGE.into()),
            Language::Php => Ok(tree_sitter_php::LANGUAGE_PHP.into()),
            Language::Python => Ok(tree_sitter_python::LANGUAGE.into()),
            Language::Regex => Ok(tree_sitter_regex::LANGUAGE.into()),
            Language::Ruby => Ok(tree_sitter_ruby::LANGUAGE.into()),
            Language::Rust => Ok(tree_sitter_rust::LANGUAGE.into()),
            Language::Toml => Ok(tree_sitter_toml_ng::LANGUAGE.into()),
            Language::TypeScript => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
            Language::Yaml => Ok(tree_sitter_yaml::language()),
        }
    }
}
impl FromStr for Language {
    // type Err = Box<dyn Error>;
    type Err = Box<dyn StdError + Send + Sync>;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bash" => Ok(Language::Bash),
            "c" => Ok(Language::C),
            "csharp" | "c_sharp" => Ok(Language::CSharp),
            "cpp" => Ok(Language::Cpp),
            "css" => Ok(Language::Css),
            "go" => Ok(Language::Go),
            "html" => Ok(Language::Html),
            "java" => Ok(Language::Java),
            "javascript" | "js" => Ok(Language::JavaScript),
            "php" => Ok(Language::Php),
            "python" | "py" => Ok(Language::Python),
            "ruby" => Ok(Language::Ruby),
            "rust" | "rs" => Ok(Language::Rust),
            "toml" => Ok(Language::Toml),
            "typescript" | "ts" => Ok(Language::TypeScript),
            "yaml" | "yml" => Ok(Language::Yaml),
            _ => Err(format!("Unknown language: {}", s).into()),
        }
    }
}
thread_local! {
    static PARSER_CACHE: RefCell<Option<TreeSitterParser>> = RefCell::new(None);
}
#[derive(Debug, Deserialize)]
pub struct Checker {
    pub language: Language,
    pub rules: FxHashMap<String, String>,
}
impl Checker {
    pub fn modify_regex(&self, source: &[u8]) -> Result<String> {
        if source.is_empty() {
            return Err("Source code is empty".into());
        }
        let tree_sitter_language = self.language.get_ts_language()?;
        PARSER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.is_none() {
                *cache = Some(TreeSitterParser::new());
            }
            let parser = cache.as_mut().unwrap();
            parser
                .set_language(&tree_sitter_language)
                .map_err(|e| format!("Failed to set language '{}': {}", self.language.name(), e))?;
            let tree = parser.parse(source, None).ok_or_else(|| {
                format!("Failed to parse source for language '{}'", self.language.name())
            })?;
            let mut modified_regex = String::from_utf8_lossy(source).to_string();
            for (_name, rule) in &self.rules {
                let query = Query::new(&tree_sitter_language, rule)
                    .map_err(|e| format!("Failed to create query: {}", e))?;
                // Store matches in a Vec so we can process them in reverse order
                let mut matches = Vec::new();
                let mut query_cursor = QueryCursor::new();
                let mut cursor = query_cursor.matches(&query, tree.root_node(), source);
                // Collect matches, converting them into owned data structures
                while cursor.next().is_some() {
                    if let Some(m) = cursor.get() {
                        let captures: Vec<_> = m
                            .captures
                            .iter()
                            .map(|capture| {
                                let range = capture.node.byte_range();
                                let text = source[range.clone()].to_vec();
                                (capture.index, range, text)
                            })
                            .collect();
                        matches.push(captures);
                    }
                }
                // Process matches in reverse order to maintain correct byte offsets
                for captures in matches.iter().rev() {
                    let mut boundary_text = None;
                    let mut boundary_range = None;
                    let mut key_text = None;
                    let mut key_range = None;
                    for (index, range, _) in captures {
                        let capture_name = query.capture_names()[*index as usize];
                        let captured_text = &source[range.clone()];
                        if capture_name == "key" {
                            key_text = Some(String::from_utf8_lossy(captured_text).to_string());
                            key_range = Some(range.clone());
                        } else if capture_name == "boundary" {
                            boundary_text =
                                Some(String::from_utf8_lossy(captured_text).to_string());
                            boundary_range = Some(range.clone());
                        }
                    }
                    if let Some(key_str) = key_text {
                        // Include the boundary text if available
                        let new_pattern = if let Some(boundary_str) = boundary_text {
                            format!(
                                r#"(?:
                                        {}
                                        {}
                                    )
                                    |
                                    (?:
                                        [A-Za-z0-9+/]{{16,64}}={{0,3}}
                                    )"#,
                                key_str, boundary_str
                            )
                        } else {
                            format!(
                                r#"(?:
                                        {}
                                    )
                                    |
                                    (?:
                                        [A-Za-z0-9+/]{{16,64}}={{0,3}}
                                    )"#,
                                key_str
                            )
                        };
                        // Remove the `boundary` part if it exists
                        if let Some(range) = boundary_range {
                            modified_regex.replace_range(range, "");
                        }
                        // Replace the captured part with the new pattern
                        if let Some(range) = key_range {
                            modified_regex.replace_range(range, &new_pattern);
                        }
                    }
                }
            }
            Ok(modified_regex)
        })
    }

    pub fn check(&self, source: &[u8]) -> Result<Vec<MatchResult>> {
        if source.is_empty() {
            return Err("Source code is empty".into());
        }
        let tree_sitter_language = self.language.get_ts_language()?;
        PARSER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.is_none() {
                *cache = Some(TreeSitterParser::new());
            }
            let parser = cache.as_mut().unwrap();
            parser
                .set_language(&tree_sitter_language)
                .map_err(|e| format!("Failed to set language '{}': {}", self.language.name(), e))?;
            let tree = parser.parse(source, None).ok_or_else(|| {
                format!("Failed to parse source for language '{}'", self.language.name())
            })?;
            let mut all_matches = Vec::new();
            for (_name, rule) in &self.rules {
                let query = Query::new(&tree_sitter_language, rule)
                    .map_err(|e| format!("Failed to create query: {}", e))?;
                let mut rule_matches = Vec::new();
                QueryCursor::new().matches(&query, tree.root_node(), source).for_each(|m| {
                    let captures: Vec<_> = m.captures.iter().collect();
                    if captures.len() >= 2 {
                        let first_range = captures[0].node.range();
                        let second_range = captures[1].node.range();
                        let first_text = String::from_utf8_lossy(
                            &source[first_range.start_byte..first_range.end_byte],
                        );
                        let second_text = String::from_utf8_lossy(
                            &source[second_range.start_byte..second_range.end_byte],
                        );
                        let second_trimmed = second_text.trim();
                        let mut is_base64_decoded = is_base64(second_trimmed);
                        let (final_text, original_base64) = if is_base64_decoded {
                            if let Some(decoded) =
                                STANDARD.decode(second_trimmed).ok().and_then(|decoded| {
                                    if decoded.is_ascii() && std::str::from_utf8(&decoded).is_ok() {
                                        Some(String::from_utf8_lossy(&decoded).to_string())
                                    } else {
                                        is_base64_decoded = false;
                                        None
                                    }
                                })
                            {
                                (
                                    format!("{} = {}", first_text.trim(), decoded),
                                    Some(second_trimmed.to_string()),
                                )
                            } else {
                                (format!("{} = {}", first_text.trim(), second_trimmed), None)
                            }
                        } else {
                            (format!("{} = {}", first_text.trim(), second_trimmed), None)
                        };
                        rule_matches.push(MatchResult {
                            range: first_range.start_byte..second_range.end_byte,
                            text: final_text,
                            is_base64_decoded,
                            original_base64,
                        });
                    }
                });
                all_matches.extend(rule_matches);
            }
            Ok(all_matches)
        })
    }
}
