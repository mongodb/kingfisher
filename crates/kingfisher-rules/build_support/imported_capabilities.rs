use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedCapabilities {
    version: u32,
    #[serde(default)]
    betterleaks: BTreeMap<String, serde_yaml::Value>,
    #[serde(default)]
    veles: BTreeMap<String, serde_yaml::Value>,
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
    fn rejects_unknown_source_namespaces() {
        let error = split_config("version: 1\nbetterleek: {}\n").unwrap_err();
        assert!(error.to_string().contains("invalid imported-rule capability overlay"));
    }
}
