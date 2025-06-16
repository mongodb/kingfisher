use std::path::Path;

use anyhow::Result;
use include_dir::{include_dir, Dir};

use crate::rules::{rule::Confidence, Rules};

pub static DEFAULT_RULES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/data");

fn load_yaml_files<'a>(dir: &Dir<'a>) -> Vec<(&'a Path, &'a [u8])> {
    dir.find("**/*.yml")
        .expect("Constant glob should compile")
        .filter_map(|e| e.as_file())
        .map(|f| (f.path(), f.contents()))
        .collect()
}
/// Load the default YAML rule files, returning their pathnames and contents.
fn get_default_rule_files() -> Vec<(&'static Path, &'static [u8])> {
    let mut yaml_files = load_yaml_files(&DEFAULT_RULES_DIR);
    yaml_files.sort_by_key(|t| t.0);
    yaml_files
}
/// Load the default rules and rulesets.
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
