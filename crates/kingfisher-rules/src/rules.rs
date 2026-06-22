//! Rule collection and loading utilities.

use anyhow::{Context, Result, bail};
use ignore::{WalkBuilder, types::TypesBuilder};
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, debug_span, error};

use std::{collections::BTreeMap, fs::File, io::BufReader, path::Path};

pub use crate::rule::{Confidence, Revocation, RuleSyntax, Validation};
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
}

#[derive(Deserialize)]
struct RawRules {
    rules: Vec<RuleSyntax>,
}

impl Rules {
    pub fn new() -> Self {
        Self { rules: BTreeMap::new() }
    }

    pub fn update(&mut self, other: Rules) {
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
                rules.update(Rules::from_yaml_file(input, confidence)?);
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
        let yaml_types =
            TypesBuilder::new().add_defaults().select("yaml").build().map_err(|e| {
                error!("Failed to build YAML types: {}", e);
                RulesError::YamlTypesBuildError(e.to_string())
            })?;
        let walker = WalkBuilder::new(path)
            .types(yaml_types)
            .follow_links(true)
            .standard_filters(false)
            .build();
        let mut yaml_files = Vec::new();
        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_some_and(|t| !t.is_dir()) {
                        yaml_files.push(entry.into_path());
                    }
                }
                Err(e) => {
                    debug!("Failed to read directory entry: {}", e);
                }
            }
        }
        yaml_files.sort();
        debug!("Found {} YAML files in {}", yaml_files.len(), path.display());
        Self::from_yaml_files(&yaml_files, confidence)
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
