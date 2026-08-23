//! Rule collection and loading utilities.

use anyhow::{Context, Result, bail};
use ignore::{WalkBuilder, types::TypesBuilder};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, debug_span, error};

use std::{collections::BTreeMap, fs::File, io::BufReader, path::Path};

pub use crate::rule::{BetterleaksExpr, Confidence, Revocation, RuleSyntax, Validation};
use serde::de::DeserializeOwned;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("Failed to parse YAML file at path: {0}")]
    YamlParseError(String),

    #[error("Invalid input: {0} is neither a file nor a directory")]
    InvalidInputError(String),

    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    #[error("Error building YAML types: {0}")]
    YamlTypesBuildError(String),

    #[error("Invalid ResponseMatcher variant in file: {0}, at line: {1}, column: {2}")]
    InvalidResponseMatcherVariant(String, usize, usize),

    #[error("HTTP validation for rule `{rule_id}` in file {path} missing response_matcher")]
    MissingResponseMatcher { path: String, rule_id: String },

    #[error("HTTP revocation for rule `{rule_id}` in file {path} missing response_matcher")]
    MissingRevocationMatcher { path: String, rule_id: String },
}

#[derive(Clone, Default)]
pub struct Rules {
    pub rules: BTreeMap<String, RuleSyntax>,
    pub betterleaks_prefilter: Option<BetterleaksExpr>,
}

#[derive(Deserialize)]
struct RawRules {
    #[serde(default)]
    betterleaks_prefilter: Option<BetterleaksExpr>,
    rules: Vec<RuleSyntax>,
}

impl Rules {
    pub fn new() -> Self {
        Self { rules: BTreeMap::new(), betterleaks_prefilter: None }
    }

    pub fn update(&mut self, other: Rules) {
        if self.betterleaks_prefilter.is_none() {
            self.betterleaks_prefilter = other.betterleaks_prefilter;
        }
        self.rules.extend(other.rules);
    }

    pub fn from_paths_and_contents<'a, I: IntoIterator<Item = (&'a Path, &'a [u8])>>(
        iterable: I,
        confidence: Confidence,
    ) -> Result<Self> {
        let mut rules = Self::new();
        for (path, contents) in iterable {
            match serde_yaml::from_slice::<RawRules>(contents) {
                Ok(rs) => {
                    if rules.betterleaks_prefilter.is_none() {
                        rules.betterleaks_prefilter = rs.betterleaks_prefilter;
                    }
                    for rule_syntax in rs.rules {
                        if !rule_syntax.confidence.is_at_least(&confidence) {
                            continue;
                        }
                        if let Some(Validation::Http(http_val)) = &rule_syntax.validation
                            && http_val
                                .request
                                .response_matcher
                                .as_ref()
                                .is_none_or(|m| m.is_empty())
                        {
                            bail!(RulesError::MissingResponseMatcher {
                                path: path.display().to_string(),
                                rule_id: rule_syntax.id.clone(),
                            });
                        }
                        if let Some(Revocation::Http(http_revocation)) = &rule_syntax.revocation
                            && http_revocation
                                .request
                                .response_matcher
                                .as_ref()
                                .is_none_or(|m| m.is_empty())
                        {
                            bail!(RulesError::MissingRevocationMatcher {
                                path: path.display().to_string(),
                                rule_id: rule_syntax.id.clone(),
                            });
                        }
                        rules.rules.insert(rule_syntax.id.clone(), rule_syntax);
                    }
                }
                Err(e) => {
                    if let Some(location) = e.location() {
                        error!(
                            "Failed to parse rules YAML from {}: {}, at line: {}, column: {}",
                            path.display(),
                            e,
                            location.line(),
                            location.column()
                        );
                        bail!(RulesError::InvalidResponseMatcherVariant(
                            path.display().to_string(),
                            location.line(),
                            location.column(),
                        ));
                    } else {
                        error!("Failed to parse rules YAML from {}: {}", path.display(), e);
                        bail!(RulesError::YamlParseError(format!(
                            "Failed to load rules YAML from {}: {}",
                            path.display(),
                            e
                        )));
                    }
                }
            }
        }
        Ok(rules)
    }

    pub fn from_paths<P: AsRef<Path>, I: IntoIterator<Item = P>>(
        paths: I,
        confidence: Confidence,
    ) -> Result<Self> {
        let mut num_paths = 0;
        let mut rules = Rules::new();
        for input in paths {
            num_paths += 1;
            let input = input.as_ref();
            if input.is_file() {
                rules.update(Rules::from_file(input, confidence)?);
            } else if input.is_dir() {
                rules.update(Rules::from_directory(input, confidence)?);
            } else {
                error!("Invalid input type: {} is neither a file nor a directory", input.display());
                bail!(RulesError::InvalidInputError(input.display().to_string()));
            }
        }
        debug!("Loaded {} rules from {} paths", rules.num_rules(), num_paths);
        Ok(rules)
    }

    pub fn from_yaml_file<P: AsRef<Path>>(path: P, confidence: Confidence) -> Result<Self> {
        let path = path.as_ref();
        let _span = debug_span!("Rules::from_yaml_file", "{}", path.display()).entered();
        match load_yaml_file::<RawRules, _>(path) {
            Ok(rs) => {
                let mut rules = Rules::new();
                rules.betterleaks_prefilter = rs.betterleaks_prefilter;
                for rule_syntax in rs.rules {
                    if !rule_syntax.confidence.is_at_least(&confidence) {
                        continue;
                    }
                    if let Some(Validation::Http(http_val)) = &rule_syntax.validation
                        && http_val.request.response_matcher.as_ref().is_none_or(|m| m.is_empty())
                    {
                        bail!(RulesError::MissingResponseMatcher {
                            path: path.display().to_string(),
                            rule_id: rule_syntax.id.clone(),
                        });
                    }
                    if let Some(Revocation::Http(http_revocation)) = &rule_syntax.revocation
                        && http_revocation
                            .request
                            .response_matcher
                            .as_ref()
                            .is_none_or(|m| m.is_empty())
                    {
                        bail!(RulesError::MissingRevocationMatcher {
                            path: path.display().to_string(),
                            rule_id: rule_syntax.id.clone(),
                        });
                    }
                    rules.rules.insert(rule_syntax.id.clone(), rule_syntax);
                }
                debug!("Loaded {} rules from {}", rules.num_rules(), path.display());
                Ok(rules)
            }
            Err(e) => {
                error!("Failed to load rules YAML from {}: {}", path.display(), e);
                bail!(RulesError::YamlParseError(format!(
                    "Failed to load rules YAML from {}: {}",
                    path.display(),
                    e
                )))
            }
        }
    }

    pub fn from_toml_file<P: AsRef<Path>>(path: P, confidence: Confidence) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to open Betterleaks TOML file: {}", path.display()))?;
        let yaml = crate::betterleaks::import_custom_config(&contents, &path.display().to_string())
            .with_context(|| {
                format!("Failed to import Betterleaks TOML from {}", path.display())
            })?;
        Self::from_paths_and_contents([(path, yaml.as_bytes())], confidence)
    }

    fn from_file<P: AsRef<Path>>(path: P, confidence: Confidence) -> Result<Self> {
        let path = path.as_ref();
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("toml") => Self::from_toml_file(path, confidence),
            _ => Self::from_yaml_file(path, confidence),
        }
    }

    pub fn from_yaml_files<P: AsRef<Path>, I: IntoIterator<Item = P>>(
        paths: I,
        confidence: Confidence,
    ) -> Result<Self> {
        let mut num_paths = 0;
        let mut rules = Rules::new();
        for path in paths {
            num_paths += 1;
            rules.update(Rules::from_yaml_file(path.as_ref(), confidence)?);
        }
        debug!("Loaded {} rules from {} YAML files", rules.num_rules(), num_paths);
        Ok(rules)
    }

    pub fn from_directory<P: AsRef<Path>>(path: P, confidence: Confidence) -> Result<Self> {
        let path = path.as_ref();
        let _span = debug_span!("Rules::from_directory", "{}", path.display()).entered();
        let mut file_types = TypesBuilder::new();
        file_types.add_defaults();
        file_types.add("kingfishertoml", "*.toml").map_err(|e| {
            error!("Failed to build rule file types: {}", e);
            RulesError::YamlTypesBuildError(e.to_string())
        })?;
        file_types.select("yaml");
        file_types.select("kingfishertoml");
        let file_types = file_types.build().map_err(|e| {
            error!("Failed to build rule file types: {}", e);
            RulesError::YamlTypesBuildError(e.to_string())
        })?;
        let walker = WalkBuilder::new(path)
            .types(file_types)
            .follow_links(true)
            .standard_filters(false)
            .build();
        let mut rule_files = Vec::new();
        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_some_and(|t| !t.is_dir()) {
                        let path = entry.into_path();
                        if path.extension().and_then(|extension| extension.to_str()) != Some("toml")
                            || is_betterleaks_toml_document(&path)
                        {
                            rule_files.push(path);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to read directory entry: {}", e);
                }
            }
        }
        rule_files.sort();
        debug!("Found {} rule files in {}", rule_files.len(), path.display());
        let mut rules = Self::new();
        for rule_file in rule_files {
            rules.update(Self::from_file(rule_file, confidence)?);
        }
        Ok(rules)
    }

    #[inline]
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[inline]
    pub fn iter_rules(&self) -> std::collections::btree_map::Values<'_, String, RuleSyntax> {
        self.rules.values()
    }
}

fn is_betterleaks_toml_document(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|contents| toml::from_str::<toml::Value>(&contents).ok())
        .and_then(|document| document.get("rules").cloned())
        .is_some_and(|rules| rules.is_array())
}

impl IntoIterator for Rules {
    type Item = RuleSyntax;
    type IntoIter = std::collections::btree_map::IntoValues<String, RuleSyntax>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.into_values()
    }
}

pub fn load_yaml_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("Failed to open YAML file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let data = serde_yaml::from_reader(reader)
        .with_context(|| format!("Failed to parse YAML from file: {}", path.display()))?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_betterleaks_toml_as_namespaced_custom_rules() {
        let path =
            std::env::temp_dir().join(format!("kingfisher-custom-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(
            &path,
            r#"
[[rules]]
id = "component"
description = "Component"
regex = '''(component_[a-z]+)'''
confidence = "medium"

[[rules]]
id = "token"
description = "Token"
regex = '''(token=)(demo_[A-Za-z0-9]{16})'''
secretGroup = 2
confidence = "high"
validate = '''{"result": "valid"}'''
components = [{ id = "component", optional = true }]
"#,
        )
        .unwrap();

        let rules = Rules::from_paths([path.as_path()], Confidence::Low).unwrap();
        std::fs::remove_file(path).ok();

        assert!(rules.rules.contains_key("custom.component"));
        let token = rules.rules.get("custom.token").unwrap();
        assert!(token.as_regex().unwrap().is_match(b"token=demo_AbCdEfGhIjKlMnOp"));
        assert!(token.validation.is_some());
        assert_eq!(token.depends_on_rule[0].as_ref().unwrap().rule_id, "custom.component");
    }

    #[test]
    fn directory_loading_ignores_unrelated_toml_files() {
        let directory =
            std::env::temp_dir().join(format!("kingfisher-rules-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(
            directory.join("rules.yml"),
            r#"
rules:
  - id: private.directory-rule
    name: Directory YAML rule
    pattern: '(directory_[A-Za-z0-9]+)'
"#,
        )
        .unwrap();
        std::fs::write(
            directory.join("Cargo.toml"),
            "[package]\nname = \"not-a-rule\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("pyproject.toml"),
            "[project]\nname = \"not-a-rule\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("custom.toml"),
            r#"
[[rules]]
id = "directory-toml"
description = "Directory TOML rule"
regex = '''(toml_[A-Za-z0-9]+)'''
"#,
        )
        .unwrap();

        let rules = Rules::from_directory(&directory, Confidence::Low).unwrap();
        std::fs::remove_dir_all(directory).ok();

        assert_eq!(rules.rules.len(), 2);
        assert!(rules.rules.contains_key("private.directory-rule"));
        assert!(rules.rules.contains_key("custom.directory-toml"));
    }
}
