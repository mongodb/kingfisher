use std::str::FromStr;

use anyhow::Result;
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
    #[cfg(feature = "__cli-internals")]
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
