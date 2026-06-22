//! Builtin rules embedded in the kingfisher-rules crate.

use std::path::Path;

use anyhow::Result;
use include_dir::{Dir, DirEntry, include_dir};

use crate::rule::Confidence;
use crate::rules::Rules;

/// The embedded rules directory.
pub static DEFAULT_RULES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data");

fn load_yaml_files<'a>(dir: &'a Dir<'a>) -> Vec<(&'a Path, &'a [u8])> {
    let mut files = Vec::new();
    collect_yaml_files(dir, &mut files);
    files
}

fn collect_yaml_files<'a>(dir: &'a Dir<'a>, files: &mut Vec<(&'a Path, &'a [u8])>) {
    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(subdir) => collect_yaml_files(subdir, files),
            DirEntry::File(file) => {
                if file.path().extension().is_some_and(|ext| ext == "yml" || ext == "yaml") {
                    files.push((file.path(), file.contents()));
                }
            }
        }
    }
}

/// Load the default YAML rule files, returning their pathnames and contents.
fn get_default_rule_files() -> Vec<(&'static Path, &'static [u8])> {
    let mut yaml_files = load_yaml_files(&DEFAULT_RULES_DIR);
    yaml_files.sort_by_key(|t| t.0);
    yaml_files
}

/// Load the builtin rules from the embedded YAML files.
///
/// This loads all rules that meet or exceed the given confidence level.
/// If no confidence is specified, defaults to `Confidence::Medium`.
pub fn get_builtin_rules(confidence: Option<Confidence>) -> Result<Rules> {
    let confidence = confidence.unwrap_or(Confidence::Medium);
    Rules::from_paths_and_contents(get_default_rule_files(), confidence)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_default_rules() {
        assert!(get_builtin_rules(None).unwrap().num_rules() >= 100);
    }
}
