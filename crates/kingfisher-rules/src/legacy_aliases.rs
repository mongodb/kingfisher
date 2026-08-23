//! Kingfisher 1.x → 2.x rule-selector aliases.
//!
//! Kingfisher 2.0 replaced the hand-maintained `kingfisher.*` catalog with rules
//! imported from Betterleaks and Veles, which renamed essentially every rule ID.
//! Existing `--rule` flags, `rules.disabled` config entries, and CI pipelines all
//! reference the old IDs.
//!
//! This module maps a legacy rule-ID *family* to the 2.x selectors covering the
//! same provider, so those references keep working (with a deprecation warning)
//! instead of hard-failing.
//!
//! The table doubles as Kingfisher's **coverage drift guard**: every alias target
//! must resolve against the built-in catalog, and a test enforces that. If an
//! upstream release drops a provider Kingfisher used to cover, the test fails
//! rather than the regression landing silently.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Raw alias table, embedded at compile time.
const LEGACY_ALIASES_YAML: &str = include_str!("../data/legacy-rule-aliases.yml");

/// Prefix used by every Kingfisher 1.x rule ID.
pub const LEGACY_RULE_PREFIX: &str = "kingfisher.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAliasFile {
    version: u32,
    #[serde(default)]
    aliases: BTreeMap<String, Vec<String>>,
}

fn parse() -> Result<BTreeMap<String, Vec<String>>> {
    let parsed: LegacyAliasFile =
        serde_yaml::from_str(LEGACY_ALIASES_YAML).context("invalid legacy rule alias table")?;
    if parsed.version != 1 {
        bail!("unsupported legacy rule alias table version {}", parsed.version);
    }
    Ok(parsed.aliases)
}

/// The full legacy-family → 2.x-selector table.
pub fn legacy_aliases() -> &'static BTreeMap<String, Vec<String>> {
    static ALIASES: std::sync::OnceLock<BTreeMap<String, Vec<String>>> = std::sync::OnceLock::new();
    ALIASES.get_or_init(|| parse().expect("embedded legacy rule alias table must parse"))
}

/// Extract the family from a Kingfisher 1.x rule ID or selector.
///
/// `kingfisher.aws.1` → `aws`, `kingfisher.azure.devops.2` → `azure.devops`,
/// `kingfisher.slack` → `slack`. Returns `None` for non-legacy selectors.
///
/// The trailing numeric component is dropped because 1.x rule IDs were
/// `kingfisher.<family>.<ordinal>` and the ordinal has no 2.x equivalent.
pub fn legacy_family(selector: &str) -> Option<&str> {
    let rest = selector.strip_prefix(LEGACY_RULE_PREFIX)?;
    if rest.is_empty() {
        return None;
    }
    match rest.rsplit_once('.') {
        Some((head, tail)) if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
            Some(head)
        }
        _ => Some(rest),
    }
}

/// 2.x selectors replacing a legacy `kingfisher.*` selector, if any are known.
pub fn replacements_for(selector: &str) -> Option<&'static [String]> {
    let family = legacy_family(selector)?;
    legacy_aliases().get(family).map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_table_parses_and_is_non_trivial() {
        assert!(legacy_aliases().len() >= 200, "alias table shrank unexpectedly");
    }

    #[test]
    fn extracts_family_from_legacy_ids() {
        assert_eq!(legacy_family("kingfisher.aws.1"), Some("aws"));
        assert_eq!(legacy_family("kingfisher.azure.devops.2"), Some("azure.devops"));
        assert_eq!(legacy_family("kingfisher.slack"), Some("slack"));
        assert_eq!(legacy_family("kingfisher.gitlab.14"), Some("gitlab"));
        // Non-numeric trailing components are part of the family.
        assert_eq!(legacy_family("kingfisher.aws.bedrock"), Some("aws.bedrock"));
        assert_eq!(legacy_family("betterleaks.aws-access-token"), None);
        assert_eq!(legacy_family("aws"), None);
        assert_eq!(legacy_family("kingfisher."), None);
    }

    #[test]
    fn maps_well_known_legacy_selectors() {
        assert_eq!(
            replacements_for("kingfisher.aws.1"),
            Some(["betterleaks.aws".to_string()].as_slice())
        );
        assert!(
            replacements_for("kingfisher.slack.6")
                .unwrap()
                .contains(&"betterleaks.slack".to_string())
        );
        assert!(replacements_for("kingfisher.alibabacloud.2").is_some());
        assert_eq!(
            replacements_for("kingfisher.abuseipdb.1"),
            Some(["betterleaks.abuseipdb-api-key".to_string()].as_slice())
        );
        assert!(replacements_for("kingfisher.no-such-provider.1").is_none());
    }

    #[test]
    fn alias_targets_are_namespaced_2x_selectors() {
        for (family, selectors) in legacy_aliases() {
            assert!(!selectors.is_empty(), "{family} has no replacement selectors");
            for selector in selectors {
                assert!(
                    selector.starts_with("betterleaks.") || selector.starts_with("veles."),
                    "{family} -> {selector} is not a 2.x selector"
                );
            }
        }
    }
}
