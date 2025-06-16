use anyhow::{bail, Result};
use ignore::{types::TypesBuilder, WalkBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, debug_span, error};

pub mod rule;
use std::{fs::File, io::BufReader, path::Path};

use anyhow::Context;
use rule::{Confidence, RuleSyntax};
use serde::de::DeserializeOwned;

/// Custom error type for more granular rules loading errors.
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
}

/// Represents a collection of rule syntaxes.
#[derive(Serialize, Deserialize, Clone)]
pub struct Rules {
    pub rules: Vec<RuleSyntax>,
}

impl Rules {
    /// Creates a new empty set of rules.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Updates the current set with the rules from another set.
    pub fn update(&mut self, other: Rules) {
        self.rules.extend(other.rules);
    }

    /// Loads rules from an iterator over (path, contents) pairs.
    /// Only rules with a confidence level at least as high as `confidence` are retained.
    pub fn from_paths_and_contents<'a, I: IntoIterator<Item = (&'a Path, &'a [u8])>>(
        iterable: I,
        confidence: Confidence,
    ) -> Result<Self> {
        let mut rules = Self::new();
        for (path, contents) in iterable.into_iter() {
            match serde_yaml::from_reader::<_, Rules>(contents) {
                Ok(mut rs) => {
                    rs.rules.retain(|rule| rule.confidence.is_at_least(&confidence));
                    rules.update(rs);
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
                            location.column()
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

    /// Loads rules from the given paths.
    /// Each path may be a file or a directory.
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

    /// Loads rules from a YAML file.
    pub fn from_yaml_file<P: AsRef<Path>>(path: P, confidence: Confidence) -> Result<Self> {
        let path = path.as_ref();
        let _span = debug_span!("Rules::from_yaml_file", "{}", path.display()).entered();
        match load_yaml_file::<Rules, _>(path) {
            Ok(mut rules) => {
                rules.rules.retain(|rule| rule.confidence.is_at_least(&confidence));
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

    /// Loads rules from multiple YAML files.
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

    /// Loads rules from all YAML files in a directory.
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
                    if entry.file_type().map_or(false, |t| !t.is_dir()) {
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

    /// Returns the number of rules.
    #[inline]
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    /// Returns true if no rules are present.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns an iterator over the rules.
    #[inline]
    pub fn iter_rules(&self) -> std::slice::Iter<'_, RuleSyntax> {
        self.rules.iter()
    }
}

impl Default for Rules {
    fn default() -> Self {
        Self::new()
    }
}

/// Loads and deserializes a YAML file into a value of type `T`.
pub fn load_yaml_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let path = path.as_ref();
    let file = File::open(path)
        .with_context(|| format!("Failed to open YAML file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let data = serde_yaml::from_reader(reader)
        .with_context(|| format!("Failed to parse YAML from file: {}", path.display()))?;
    Ok(data)
}
