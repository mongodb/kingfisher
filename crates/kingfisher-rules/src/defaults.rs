//! Builtin rules embedded in the kingfisher-rules crate.

use std::{io::Read, path::PathBuf, sync::OnceLock};

use anyhow::{Context, Result, anyhow, bail};
use flate2::read::GzDecoder;

use crate::rule::Confidence;
use crate::rules::Rules;

const BUNDLE_MAGIC: &[u8] = b"KFRULES\x01";
const DEFAULT_RULE_BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/builtin-rules.gz"));
type BuiltinRuleFiles = Vec<(PathBuf, Vec<u8>)>;
type CachedBuiltinRuleFiles = Result<BuiltinRuleFiles, String>;

static BUILTIN_RULE_FILES: OnceLock<CachedBuiltinRuleFiles> = OnceLock::new();

/// Return the paths and contents of the embedded builtin YAML rule files.
///
/// The returned paths are relative to the bundled rules directory.
pub fn get_builtin_rule_files() -> Result<Vec<(PathBuf, Vec<u8>)>> {
    Ok(builtin_rule_files()?.to_vec())
}

fn builtin_rule_files() -> Result<&'static [(PathBuf, Vec<u8>)]> {
    BUILTIN_RULE_FILES
        .get_or_init(|| load_builtin_rule_files().map_err(|err| format!("{err:#}")))
        .as_deref()
        .map_err(|err| anyhow!("failed to load embedded builtin rules: {err}"))
}

fn load_builtin_rule_files() -> Result<BuiltinRuleFiles> {
    let mut decoded = Vec::new();
    GzDecoder::new(DEFAULT_RULE_BUNDLE)
        .read_to_end(&mut decoded)
        .context("failed to decompress embedded rule bundle")?;

    let mut cursor = BundleCursor::new(&decoded);
    if cursor.take(BUNDLE_MAGIC.len())? != BUNDLE_MAGIC {
        bail!("embedded rule bundle has an invalid header");
    }

    let mut files = Vec::new();
    loop {
        let path_len = usize::try_from(cursor.u32()?)
            .map_err(|_| anyhow!("embedded rule path length exceeds platform limits"))?;
        if path_len == 0 {
            break;
        }
        let contents_len = usize::try_from(cursor.u64()?)
            .map_err(|_| anyhow!("embedded rule contents length exceeds platform limits"))?;
        let path = std::str::from_utf8(cursor.take(path_len)?)
            .context("embedded rule bundle contains a non-UTF-8 path")?;
        files.push((PathBuf::from(path), cursor.take(contents_len)?.to_vec()));
    }
    if !cursor.is_empty() {
        bail!("embedded rule bundle has trailing data");
    }
    Ok(files)
}

/// Load the builtin rules from the embedded YAML files.
///
/// This loads all rules that meet or exceed the given confidence level.
/// If no confidence is specified, defaults to `Confidence::Medium`.
pub fn get_builtin_rules(confidence: Option<Confidence>) -> Result<Rules> {
    let confidence = confidence.unwrap_or(Confidence::Medium);
    let files = builtin_rule_files()?;
    Rules::from_paths_and_contents(
        files.iter().map(|(path, contents)| (path.as_path(), contents.as_slice())),
        confidence,
    )
}

struct BundleCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> BundleCursor<'a> {
    fn new(contents: &'a [u8]) -> Self {
        Self { remaining: contents }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        if self.remaining.len() < length {
            bail!("embedded rule bundle is truncated");
        }
        let (result, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(result)
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.take(4)?.try_into().expect("slice length is checked");
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.take(8)?.try_into().expect("slice length is checked");
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_default_rules() {
        assert!(get_builtin_rules(None).unwrap().num_rules() >= 100);
    }

    #[test]
    fn bundled_rule_files_are_sorted_and_complete() {
        let files = get_builtin_rule_files().unwrap();
        assert!(files.len() >= 100);
        assert!(files.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    }

    #[test]
    fn builtin_rule_files_are_cached() {
        assert!(std::ptr::eq(builtin_rule_files().unwrap(), builtin_rule_files().unwrap()));
    }

    #[test]
    fn builtin_rules_capture_full_secrets() -> Result<()> {
        let rules = get_builtin_rules(Some(Confidence::Low))?;
        for (rule_id, input, expected_secret) in [
            (
                "kingfisher.slack.8",
                "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c",
                "xoxa-2-511111111-31111111111-3111111111111-e039d02840a0b9379c",
            ),
            (
                "kingfisher.html.1",
                "<input type=\"password\" value=\"Jasper@Admin2024!\" />",
                "Jasper@Admin2024!",
            ),
            (
                "kingfisher.html.2",
                "<input value=\"jasper_secret_XYZ!\" type=\"password\" />",
                "jasper_secret_XYZ!",
            ),
        ] {
            let rule = rules.rules.get(rule_id).expect("builtin rule should exist");
            let regex = rule.as_regex()?;
            let captures = regex
                .captures(input.as_bytes())
                .unwrap_or_else(|| panic!("{rule_id} should match its example"));
            let capture = captures
                .get(1)
                .unwrap_or_else(|| panic!("{rule_id} should capture its example secret"));
            assert_eq!(capture.as_bytes(), expected_secret.as_bytes(), "{rule_id}");
        }
        Ok(())
    }
}
