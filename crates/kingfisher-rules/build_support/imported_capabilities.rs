use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedCapabilities {
    version: u32,
    #[serde(default, deserialize_with = "unique_rules")]
    betterleaks: BTreeMap<String, serde_yaml::Value>,
    #[serde(default, deserialize_with = "unique_rules")]
    veles: BTreeMap<String, serde_yaml::Value>,
}

fn unique_rules<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, serde_yaml::Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct UniqueRules;

    impl<'de> serde::de::Visitor<'de> for UniqueRules {
        type Value = BTreeMap<String, serde_yaml::Value>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a mapping of unique rule capability IDs")
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut rules = BTreeMap::new();
            while let Some((id, capabilities)) = map.next_entry::<String, serde_yaml::Value>()? {
                if rules.insert(id.clone(), capabilities).is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate rule capability ID {id:?}"
                    )));
                }
            }
            Ok(rules)
        }
    }

    deserializer.deserialize_map(UniqueRules)
}

#[derive(Serialize)]
struct SourceCapabilities {
    version: u32,
    rules: BTreeMap<String, serde_yaml::Value>,
}

pub fn split_config(contents: &str) -> Result<(String, String)> {
    let config: ImportedCapabilities =
        serde_yaml::from_str(contents).context("invalid imported-rule capability overlay")?;
    if config.version != 1 {
        bail!("unsupported imported-rule capability overlay version {}", config.version);
    }

    Ok((
        serde_yaml::to_string(&SourceCapabilities {
            version: config.version,
            rules: config.betterleaks,
        })?,
        serde_yaml::to_string(&SourceCapabilities {
            version: config.version,
            rules: config.veles,
        })?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_source_namespaces() {
        let (betterleaks, veles) = split_config(
            r#"
version: 1
betterleaks:
  github-pat:
    revocation: { type: Http }
veles:
  secrets/cloudflareapitoken:
    revocation: { type: HttpMultiStep }
"#,
        )
        .unwrap();

        assert!(betterleaks.contains("github-pat"));
        assert!(!betterleaks.contains("cloudflareapitoken"));
        assert!(veles.contains("secrets/cloudflareapitoken"));
        assert!(!veles.contains("github-pat"));
    }

    #[test]
    fn rejects_duplicate_rule_ids_in_each_source() {
        for source in ["betterleaks", "veles"] {
            let error = split_config(&format!(
                "version: 1\n{source}:\n  token:\n    filter_override: 'true'\n  token:\n    revocation: {{ type: Http }}\n"
            ))
            .unwrap_err();
            assert!(format!("{error:#}").contains("duplicate rule capability ID \"token\""));
        }
    }

    #[test]
    fn preserves_filters_and_revocation_for_combined_entries() {
        let (betterleaks, _) =
            split_config(include_str!("../data/imported-rules-capabilities.yml")).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&betterleaks).unwrap();
        for id in ["heroku-api-key-v2", "slack-app-token"] {
            assert!(value["rules"][id]["filter_override"].is_string(), "{id}");
            assert!(value["rules"][id]["revocation"].is_mapping(), "{id}");
        }
    }

    #[test]
    fn rejects_unknown_source_namespaces() {
        let error = split_config("version: 1\nbetterleek: {}\n").unwrap_err();
        assert!(error.to_string().contains("invalid imported-rule capability overlay"));
    }
}
