//! Maintainer-only rule generation. Normal crate builds never execute this tool.

#[allow(dead_code)]
#[path = "../../../crates/kingfisher-rules/build_support/betterleaks.rs"]
mod betterleaks;
#[path = "../../../crates/kingfisher-rules/build_support/builtin_docs.rs"]
mod builtin_docs;
#[path = "../../../crates/kingfisher-rules/build_support/imported_capabilities.rs"]
mod imported_capabilities;
#[path = "../../../crates/kingfisher-rules/build_support/veles.rs"]
mod veles;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// Betterleaks v2.0.0-rc.5 adds Labelbox, NuGet, and Tailscale content detectors.
const BETTERLEAKS_REVISION: &str = "b1aa878bc41b06583f6ce83bf0ffcc5e6ed8f4f3";
const BETTERLEAKS_SHA256: &str = "107da222fc897daa2647027248d86ece9dde29e993d5fc9e138826c71f951127";
const BETTERLEAKS_WORDS_SHA256: &str =
    "d4dd5530d98f4ff343864ed71cfc0064abeae34e4f078edc0b46590c2da8fb47";
const RULES: &str = "crates/kingfisher-rules";
const GENERATED: &str = "crates/kingfisher-rules/generated";
const DOCS: &str = "docs-site/docs/rules/builtin-rules.md";
const FIRST_PARTY_RULES: &str = "crates/kingfisher-rules/data/kingfisher-rules.yml";
// A null entry records an upstream NOTICE that was absent (HTTP 404) at the pinned revision.
type Sources = BTreeMap<String, Option<String>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.is_empty() || args == ["--check"] || args == ["--refresh"],
        "usage: cargo run -p kingfisher-rule-bundle -- [--check | --refresh]\n\
         No option: regenerate from archived inputs. --check: verify without writing.\n\
         --refresh: fetch pinned upstream inputs and regenerate."
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    generate(root, args.first().map(String::as_str))
}

fn generate(root: &Path, mode: Option<&str>) -> Result<()> {
    ensure!(
        BETTERLEAKS_REVISION.len() == 40
            && BETTERLEAKS_REVISION.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Betterleaks revision must be a full 40-character commit hash"
    );
    let refresh = mode == Some("--refresh");
    let check = mode == Some("--check");
    let archive_path = format!("{GENERATED}/upstream-sources.json.gz");
    let mut sources: Sources = if refresh {
        BTreeMap::new()
    } else {
        let bytes =
            fs::read(root.join(&archive_path)).context("run with --refresh to fetch inputs")?;
        serde_json::from_reader(GzDecoder::new(bytes.as_slice()))?
    };
    let mut used = BTreeSet::new();
    let mut source = |url: &str, optional: bool| -> Result<Option<String>> {
        used.insert(url.to_string());
        if !sources.contains_key(url) {
            ensure!(refresh, "missing archived input {url}; run with --refresh");
            sources.insert(url.to_string(), download(url, optional)?);
        }
        let contents = sources[url].clone();
        ensure!(optional || contents.is_some(), "missing required source {url}");
        Ok(contents)
    };

    let betterleaks_base =
        format!("https://raw.githubusercontent.com/betterleaks/betterleaks/{BETTERLEAKS_REVISION}");
    let betterleaks_url = format!("{betterleaks_base}/config/betterleaks.toml");
    let contents = source(&betterleaks_url, false)?.unwrap();
    ensure!(digest(contents.as_bytes()) == BETTERLEAKS_SHA256, "Betterleaks digest mismatch");
    let words_url = format!("{betterleaks_base}/internal/words/words.txt.gz");
    let words = source(&words_url, false)?.unwrap();
    let words = decode_archived_source(&words_url, &words)?;
    ensure!(digest(&words) == BETTERLEAKS_WORDS_SHA256, "Betterleaks wordlist digest mismatch");
    let capabilities =
        fs::read_to_string(root.join(format!("{RULES}/data/imported-rules-capabilities.yml")))?;
    let (betterleaks_capabilities, veles_capabilities) =
        imported_capabilities::split_config(&capabilities)?;
    let yaml = betterleaks::import_config(&contents, &betterleaks_url, &betterleaks_capabilities)?;
    let veles_config = fs::read_to_string(root.join(format!("{RULES}/data/veles-rules.yml")))?;
    let veles_yaml = veles::import_config(&veles_config, &veles_capabilities, |url| {
        Ok(source(url, false)?.unwrap())
    })?;
    let first_party_source = fs::read_to_string(root.join(FIRST_PARTY_RULES))?;
    let (kingfisher_yaml, first_party_provenance) =
        first_party_rules(&first_party_source, &[&yaml, &veles_yaml])?;
    let config: serde_yaml::Value = serde_yaml::from_str(&veles_config)?;
    let revision = config["revision"].as_str().context("missing Veles revision")?;
    let veles_base = format!("https://raw.githubusercontent.com/google/osv-scalibr/{revision}");
    let mut notices = String::from(
        "Kingfisher built-in rule attribution\n\n\
         Rules are converted and modified by Kingfisher's importers and operational overlays.\n\
         The provenance manifest records source revisions, hashes, and generated rule IDs.\n\
         Exact source files, including their original headers, accompany this bundle in\n\
         upstream-sources.json.gz. Binary sources use a base64: prefix.\n\
         Compression does not change the applicable licenses.\n",
    );
    for (name, base) in [
        ("Betterleaks (MIT)", &betterleaks_base),
        ("Veles / OSV-SCALIBR (Apache-2.0)", &veles_base),
    ] {
        notices.push_str(&format!("\n===== {name} =====\n"));
        for filename in ["LICENSE", "NOTICE"] {
            let url = format!("{base}/{filename}");
            if let Some(text) = source(&url, filename == "NOTICE")? {
                notices.push_str(&format!("\n{url}\n\n{text}\n"));
            }
        }
    }
    let wordfreq_notice_url = "https://raw.githubusercontent.com/rspeer/wordfreq/912caf64b657478d1dff1138efdc078947d54bb1/NOTICE.md";
    let wordfreq_license_url = "https://creativecommons.org/licenses/by-sa/4.0/legalcode.txt";
    let wordfreq_notice = source(wordfreq_notice_url, false)?.unwrap();
    let wordfreq_license = source(wordfreq_license_url, false)?.unwrap();
    ensure!(
        digest(wordfreq_notice.as_bytes())
            == "d9b104dafe63886af55e7cea7484824e32e12d4e1f57f319923dd643b36d6b15",
        "wordfreq attribution digest mismatch"
    );
    ensure!(
        digest(wordfreq_license.as_bytes())
            == "28a9529c7d0bb4dc51f4bf5c116a3d16ef247a052f7591466768ddf563fd1cf5",
        "wordfreq data license digest mismatch"
    );
    notices.push_str(&format!("\n===== Betterleaks wordfreq-derived wordlist data (CC-BY-SA-4.0) =====\n\n{wordfreq_notice_url}\n\n{wordfreq_notice}\n{wordfreq_license_url}\n\n{wordfreq_license}\n"));
    let license = fs::read_to_string(root.join("LICENSE"))?;
    notices.push_str(&format!(
        "\n===== Kingfisher first-party detector exceptions (Apache-2.0) =====\n\n\
         Source: {FIRST_PARTY_RULES}\n\
         Per-rule exception reasons and upstream migration conditions are recorded in provenance.json.\n\n\
         {license}\n"
    ));
    // Preserve distinct Go copyright/license headers in readable binary notices as well.
    let headers: BTreeSet<_> = sources
        .iter()
        .filter_map(|(url, contents)| {
            if !url.ends_with(".go") {
                return None;
            }
            contents.as_ref()?.split_once("\npackage ").map(|(header, _)| header.to_string())
        })
        .collect();
    for header in headers {
        notices.push_str(&format!("\n===== Upstream source header =====\n{header}\n"));
    }
    ensure!(
        sources.keys().all(|url| used.contains(url)),
        "archive contains unused inputs; run --refresh"
    );

    let bundle = rule_bundle(&[
        ("betterleaks.yml", &yaml),
        ("kingfisher.yml", &kingfisher_yaml),
        ("veles.yml", &veles_yaml),
    ])?;
    let docs = builtin_docs::generate_builtin_rules_page(&[&yaml, &veles_yaml, &kingfisher_yaml])?;
    let mut artifacts = BTreeMap::from([
        (format!("{RULES}/data/betterleaks-words.txt.gz"), words),
        (format!("{RULES}/data/wordfreq-NOTICE.md"), wordfreq_notice.into_bytes()),
        (format!("{RULES}/data/wordfreq-LICENSE.txt"), wordfreq_license.into_bytes()),
        (format!("{GENERATED}/builtin-rules.gz"), bundle),
        (archive_path, gzip(&serde_json::to_vec_pretty(&sources)?)?),
        (format!("{GENERATED}/NOTICES.txt"), notices.into_bytes()),
        (DOCS.to_string(), docs.into_bytes()),
    ]);
    let mut provenance = rule_provenance(&yaml, &veles_yaml, &betterleaks_url, &contents, &config)?;
    for (id, record) in first_party_provenance {
        ensure!(provenance.insert(id.clone(), record).is_none(), "duplicate generated ID {id}");
    }
    for (provider, contents) in
        [("betterleaks", &yaml), ("veles", &veles_yaml), ("kingfisher", &kingfisher_yaml)]
    {
        let path = format!("rules/{provider}.yml");
        let header = if provider == "kingfisher" {
            "# SPDX-License-Identifier: Apache-2.0\n\
             # Generated from reviewed Kingfisher first-party detector exceptions.\n\
             # See ../provenance.json for source hashes, exception reasons, and upstream migration\n\
             # conditions, and ../NOTICES.txt for attribution and license terms.\n"
        } else {
            "# Converted and modified by Kingfisher importers and operational overlays.\n\
                      # See ../provenance.json for per-rule origins, pinned revisions, and hashes,\n\
                      # ../NOTICES.txt for attribution/licenses, and ../upstream-sources.json.gz\n\
                      # for exact upstream sources. Kingfisher-authored helpers are identified in provenance.\n"
        };
        artifacts.insert(format!("{GENERATED}/{path}"), format!("{header}{contents}").into_bytes());
        for (id, record) in &mut provenance {
            if id.starts_with(&format!("{provider}.")) {
                record["generated_file"] = Value::String(path.clone());
            }
        }
    }
    for name in ["core", "rules", "scanner"] {
        artifacts
            .insert(format!("crates/kingfisher-{name}/LICENSE"), fs::read(root.join("LICENSE"))?);
    }

    let inputs = [
        "LICENSE",
        "Cargo.toml",
        "Cargo.lock",
        "tools/rule-bundle/Cargo.toml",
        "tools/rule-bundle/src/main.rs",
        "crates/kingfisher-rules/Cargo.toml",
        "crates/kingfisher-rules/build_support/betterleaks.rs",
        "crates/kingfisher-rules/build_support/builtin_docs.rs",
        "crates/kingfisher-rules/build_support/imported_capabilities.rs",
        "crates/kingfisher-rules/build_support/veles.rs",
        "crates/kingfisher-rules/data/imported-rules-capabilities.yml",
        "crates/kingfisher-rules/data/veles-rules.yml",
        FIRST_PARTY_RULES,
        "crates/kingfisher-rules/data/kingfisher-rules.md",
        "crates/kingfisher-rules/data/betterleaks-words.md",
    ]
    .into_iter()
    .map(|path| Ok((path, digest(&fs::read(root.join(path))?))))
    .collect::<Result<BTreeMap<_, _>>>()?;
    let source_hashes: BTreeMap<_, _> = sources
        .iter()
        .map(|(url, contents)| {
            Ok((
                url,
                contents
                    .as_ref()
                    .map(|text| decode_archived_source(url, text).map(|bytes| digest(&bytes)))
                    .transpose()?,
            ))
        })
        .collect::<Result<_>>()?;
    let output_hashes: BTreeMap<_, _> =
        artifacts.iter().map(|(path, bytes)| (path, digest(bytes))).collect();
    let mut manifest = json!({
        "schema_version": 1,
        "bundle_format": "gzip / KFRULES v1 / generated YAML",
        "transformation": "Kingfisher imports upstream rules, applies operational overlays, and includes reviewed first-party exceptions; imported rules are modified derivatives, not verbatim upstream files.",
        "betterleaks": {"repository": "https://github.com/betterleaks/betterleaks", "revision": BETTERLEAKS_REVISION, "license": "MIT"},
        "veles": {"repository": "https://github.com/google/osv-scalibr", "revision": revision, "license": "Apache-2.0"},
        "kingfisher": {"source": FIRST_PARTY_RULES, "license": "Apache-2.0", "policy": "Rare first-party exceptions require a specific reason and an upstream Betterleaks migration condition."},
        "source_sha256": source_hashes,
        "generator_input_sha256": inputs,
        "artifact_sha256": output_hashes,
        "rules": provenance,
    });
    // Workspace dependencies may enable serde_json's preserve_order feature.
    // Keep canonical key ordering in both standalone and workspace builds.
    manifest.sort_all_objects();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    artifacts.insert(format!("{GENERATED}/provenance.json"), manifest_bytes);
    // Compare everything before writing anything; --check never mutates the checkout.
    let stale: Vec<_> = artifacts
        .iter()
        .filter(|(path, expected)| {
            fs::read(root.join(path)).map_or(true, |actual| actual != **expected)
        })
        .map(|(path, _)| path.as_str())
        .collect();
    let mut obsolete = Vec::new();
    find_obsolete_rule_files(
        root,
        &root.join(format!("{GENERATED}/rules")),
        &artifacts,
        &mut obsolete,
    )?;
    if check {
        ensure!(obsolete.is_empty(), "obsolete generated rule files: {obsolete:?}");
        ensure!(
            stale.is_empty(),
            "stale generated artifacts:\n{}\nrun cargo run -p kingfisher-rule-bundle",
            stale.join("\n")
        );
        println!("Rule bundle, archived inputs, provenance, notices, and docs verified offline.");
    } else {
        for path in obsolete {
            fs::remove_file(&path)?;
            println!("Removed {}", path.display());
        }
        for path in &stale {
            let output = root.join(path);
            fs::create_dir_all(output.parent().unwrap())?;
            fs::write(&output, &artifacts[*path])?;
            println!("Updated {path}");
        }
    }
    Ok(())
}

// This directory is generator-owned. Reject stale files in check mode and remove them
// on regeneration so old layouts cannot leave duplicate rules behind.
fn find_obsolete_rule_files(
    root: &Path,
    directory: &Path,
    artifacts: &BTreeMap<String, Vec<u8>>,
    obsolete: &mut Vec<std::path::PathBuf>,
) -> Result<()> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            find_obsolete_rule_files(root, &path, artifacts, obsolete)?;
        } else {
            let relative = path.strip_prefix(root)?.to_string_lossy().replace('\\', "/");
            if !artifacts.contains_key(&relative) {
                obsolete.push(path);
            }
        }
    }
    obsolete.sort();
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstPartySource {
    rules: Vec<serde_yaml::Value>,
    exceptions: Vec<FirstPartyException>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FirstPartyException {
    rule_ids: Vec<String>,
    reason: String,
    upstream: String,
    tracking: String,
    removal_condition: String,
}

// This single reviewed source is part of the existing bundle, not a directory of extra catalogs.
// New generally useful detectors belong upstream; retaining one here requires an explicit exception.
fn first_party_rules(source: &str, imported: &[&str]) -> Result<(String, BTreeMap<String, Value>)> {
    let source: FirstPartySource =
        serde_yaml::from_str(source).context("invalid first-party detector source")?;
    let mut imported_ids = BTreeSet::new();
    for yaml in imported {
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        for rule in parsed["rules"].as_sequence().context("missing imported rules")? {
            let id = rule["id"].as_str().context("missing imported rule ID")?;
            ensure!(imported_ids.insert(id.to_string()), "duplicate imported rule ID {id}");
        }
    }
    let mut rules = BTreeMap::new();
    for rule in source.rules {
        let id = rule["id"].as_str().context("missing first-party rule ID")?;
        ensure!(
            id.starts_with("kingfisher.")
                && id.split('.').all(|segment| {
                    !segment.is_empty()
                        && segment.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                }),
            "first-party rule ID must use the kingfisher namespace: {id}"
        );
        ensure!(!imported_ids.contains(id), "first-party rule overlaps imported rule {id}");
        ensure!(
            rule["pattern"].as_str().is_some_and(|pattern| !pattern.trim().is_empty()),
            "first-party rule {id} must detect content"
        );
        ensure!(
            rule["examples"].as_sequence().is_some_and(|examples| !examples.is_empty())
                && rule["negative_examples"]
                    .as_sequence()
                    .is_some_and(|examples| !examples.is_empty()),
            "first-party rule {id} requires positive and negative examples"
        );
        let id = id.to_string();
        ensure!(rules.insert(id.clone(), rule).is_none(), "duplicate first-party rule ID {id}");
    }
    let mut provenance = BTreeMap::new();
    for exception in source.exceptions {
        ensure!(!exception.rule_ids.is_empty(), "first-party exception requires rule IDs");
        for (name, value) in [
            ("reason", &exception.reason),
            ("tracking", &exception.tracking),
            ("removal_condition", &exception.removal_condition),
        ] {
            ensure!(!value.trim().is_empty(), "first-party exception requires a nonempty {name}");
        }
        ensure!(
            exception.upstream == "https://github.com/betterleaks/betterleaks",
            "first-party exception upstream must be Betterleaks"
        );
        ensure!(
            ["betterleaks/betterleaks", "mongodb/kingfisher"].iter().any(|repository| {
                ["issues", "pull"].iter().any(|kind| {
                    exception
                        .tracking
                        .strip_prefix(&format!("https://github.com/{repository}/{kind}/"))
                        .is_some_and(|number| {
                            !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                        })
                })
            }),
            "first-party exception tracking must identify an upstream or Kingfisher issue or pull request"
        );
        for id in exception.rule_ids {
            ensure!(rules.contains_key(&id), "exception references unknown first-party rule {id}");
            let record = json!({
                "provider": "kingfisher",
                "role": "first-party-detector-exception",
                "sources": [FIRST_PARTY_RULES],
                "license": "Apache-2.0",
                "reason": exception.reason,
                "upstream": exception.upstream,
                "tracking": exception.tracking,
                "removal_condition": exception.removal_condition,
            });
            ensure!(
                provenance.insert(id.clone(), record).is_none(),
                "duplicate first-party exception for {id}"
            );
        }
    }
    for id in rules.keys() {
        ensure!(provenance.contains_key(id), "first-party rule {id} requires a reviewed exception");
    }
    // Emit only runtime rule data; exception metadata stays in the per-rule provenance manifest.
    let yaml = serde_yaml::to_string(&BTreeMap::from([(
        "rules",
        rules.into_values().collect::<Vec<_>>(),
    )]))?;
    Ok((yaml, provenance))
}

fn rule_provenance(
    betterleaks: &str,
    veles: &str,
    betterleaks_url: &str,
    upstream_toml: &str,
    veles_config: &serde_yaml::Value,
) -> Result<BTreeMap<String, Value>> {
    let upstream: toml::Value = toml::from_str(upstream_toml)?;
    let upstream_ids: BTreeSet<_> = upstream["rules"]
        .as_array()
        .context("missing upstream rules")?
        .iter()
        .filter_map(|rule| rule["id"].as_str())
        .collect();
    let plugin_ids = veles_config["rules"].as_sequence().context("missing Veles selections")?;
    let mut result = BTreeMap::new();
    for (provider, yaml) in [("betterleaks", betterleaks), ("veles", veles)] {
        let parsed: serde_yaml::Value = serde_yaml::from_str(yaml)?;
        for rule in parsed["rules"].as_sequence().context("missing generated rules")? {
            let id = rule["id"].as_str().context("missing generated rule ID")?;
            let record = if provider == "betterleaks" {
                let upstream_id =
                    id.strip_prefix("betterleaks.").context("invalid Betterleaks ID")?;
                if upstream_ids.contains(upstream_id) {
                    json!({"provider": provider, "upstream_rule_id": upstream_id, "sources": [betterleaks_url]})
                } else {
                    // This operational helper is authored by Kingfisher, not the upstream catalog.
                    ensure!(upstream_id == "aws-session-token", "unmapped generated rule {id}");
                    json!({"provider": "kingfisher", "upstream_rule_id": null,
                        "sources": ["crates/kingfisher-rules/build_support/betterleaks.rs"],
                        "role": "AWS STS session-token operational helper"})
                }
            } else {
                let unqualified = id.strip_prefix("veles.").context("invalid Veles ID")?;
                let plugin = plugin_ids
                    .iter()
                    .filter_map(serde_yaml::Value::as_str)
                    .filter(|plugin| {
                        unqualified == *plugin || unqualified.starts_with(&format!("{plugin}-"))
                    })
                    .max_by_key(|plugin| plugin.len())
                    .context("unmapped Veles rule")?;
                json!({"provider": provider, "upstream_plugin_id": plugin,
                    "generated_helper": unqualified != plugin,
                    "sources": serde_json::to_value(&rule["references"])?})
            };
            ensure!(result.insert(id.to_string(), record).is_none(), "duplicate generated ID {id}");
        }
    }
    Ok(result)
}

fn download(url: &str, optional: bool) -> Result<Option<String>> {
    eprintln!("Fetching {url}");
    let agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::NativeTls).build(),
        )
        .build()
        .new_agent();
    match agent.get(url).header("User-Agent", "kingfisher-rule-bundle").call() {
        Ok(mut response) => {
            let mut bytes = Vec::new();
            response.body_mut().as_reader().read_to_end(&mut bytes)?;
            if url.ends_with(".gz") {
                return Ok(Some(format!("base64:{}", BASE64.encode(bytes))));
            }
            Ok(Some(String::from_utf8(bytes).with_context(|| format!("non-UTF-8 source {url}"))?))
        }
        Err(ureq::Error::StatusCode(404)) if optional => Ok(None),
        Err(error) => bail!("failed to fetch {url}: {error}"),
    }
}

fn decode_archived_source(url: &str, contents: &str) -> Result<Vec<u8>> {
    if url.ends_with(".gz") {
        BASE64
            .decode(
                contents.strip_prefix("base64:").context("binary source lacks base64 encoding")?,
            )
            .context("invalid base64-encoded source archive")
    } else {
        Ok(contents.as_bytes().to_vec())
    }
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    // GzEncoder uses mtime=0 and no filename, making the archive reproducible.
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

fn rule_bundle(files: &[(&str, &str)]) -> Result<Vec<u8>> {
    let mut bytes = b"KFRULES\x01".to_vec();
    for (name, contents) in files {
        bytes.extend(u32::try_from(name.len())?.to_le_bytes());
        bytes.extend(u64::try_from(contents.len())?.to_le_bytes());
        bytes.extend(name.as_bytes());
        bytes.extend(contents.as_bytes());
    }
    bytes.extend(0_u32.to_le_bytes());
    gzip(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_PARTY_FIXTURE: &str = r#"
rules:
  - id: kingfisher.connection-string.password.test
    name: Connection string password
    pattern: 'Host=[^;]+;Password=([^;]+);'
    examples: ['Host=db.example.com;Password=swordfish;']
    negative_examples: ['Password=swordfish;']
exceptions:
  - rule_ids: [kingfisher.connection-string.password.test]
    reason: Restore focused compatibility coverage unavailable in the pinned upstream.
    upstream: https://github.com/betterleaks/betterleaks
    tracking: https://github.com/mongodb/kingfisher/issues/558
    removal_condition: Replace when a reviewed immutable Betterleaks pin includes the focused detector.
"#;

    #[test]
    fn first_party_metadata_is_recorded_without_expanding_runtime_yaml() {
        let (yaml, provenance) = first_party_rules(FIRST_PARTY_FIXTURE, &[]).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.as_mapping().unwrap().len(), 1);
        assert_eq!(parsed["rules"].as_sequence().unwrap().len(), 1);
        let record = &provenance["kingfisher.connection-string.password.test"];
        assert_eq!(record["provider"], "kingfisher");
        assert_eq!(record["role"], "first-party-detector-exception");
        assert_eq!(record["sources"], json!([FIRST_PARTY_RULES]));
        assert_eq!(record["license"], "Apache-2.0");
        assert!(record["reason"].as_str().unwrap().contains("focused compatibility"));
        assert!(record["removal_condition"].as_str().unwrap().contains("Betterleaks"));
    }

    #[test]
    fn first_party_exceptions_fail_closed_on_incomplete_metadata() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(FIRST_PARTY_FIXTURE).unwrap();
        for field in ["reason", "tracking", "removal_condition"] {
            let mut source = baseline.clone();
            source["exceptions"][0][field] = serde_yaml::Value::String("  ".into());
            let error =
                first_party_rules(&serde_yaml::to_string(&source).unwrap(), &[]).unwrap_err();
            assert!(error.to_string().contains(field), "{field}: {error:#}");
        }
        for (field, value) in [
            ("upstream", "https://example.com/catalog"),
            ("tracking", "https://github.com/mongodb/kingfisher/issues/"),
        ] {
            let mut source = baseline.clone();
            source["exceptions"][0][field] = serde_yaml::Value::String(value.into());
            assert!(first_party_rules(&serde_yaml::to_string(&source).unwrap(), &[]).is_err());
        }
        let mut missing = baseline.clone();
        missing["exceptions"][0].as_mapping_mut().unwrap().remove("reason");
        assert!(first_party_rules(&serde_yaml::to_string(&missing).unwrap(), &[]).is_err());
        let mut unreviewed = baseline;
        unreviewed["exceptions"] = serde_yaml::Value::Sequence(Vec::new());
        let error =
            first_party_rules(&serde_yaml::to_string(&unreviewed).unwrap(), &[]).unwrap_err();
        assert!(error.to_string().contains("requires a reviewed exception"));
    }

    #[test]
    fn first_party_ids_and_exception_ownership_are_unique() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(FIRST_PARTY_FIXTURE).unwrap();
        for (field, expected) in [
            ("rules", "duplicate first-party rule ID"),
            ("exceptions", "duplicate first-party exception"),
        ] {
            let mut source = baseline.clone();
            let first = source[field][0].clone();
            source[field].as_sequence_mut().unwrap().push(first);
            let error =
                first_party_rules(&serde_yaml::to_string(&source).unwrap(), &[]).unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
        let mut unknown = baseline;
        unknown["exceptions"][0]["rule_ids"][0] =
            serde_yaml::Value::String("kingfisher.unknown".into());
        let error = first_party_rules(&serde_yaml::to_string(&unknown).unwrap(), &[]).unwrap_err();
        assert!(error.to_string().contains("unknown first-party rule"));
        let error = first_party_rules(
            FIRST_PARTY_FIXTURE,
            &["rules: [{id: kingfisher.connection-string.password.test}]"],
        )
        .unwrap_err();
        assert!(error.to_string().contains("overlaps imported rule"));
    }

    #[test]
    fn first_party_rules_require_namespaced_content_detectors_and_examples() {
        let baseline: serde_yaml::Value = serde_yaml::from_str(FIRST_PARTY_FIXTURE).unwrap();
        for id in ["custom.password", "kingfisher.", "kingfisher..password", "kingfisher.Bad"] {
            let mut source = baseline.clone();
            source["rules"][0]["id"] = serde_yaml::Value::String(id.into());
            let error =
                first_party_rules(&serde_yaml::to_string(&source).unwrap(), &[]).unwrap_err();
            assert!(error.to_string().contains("namespace"), "{error:#}");
        }
        for field in ["pattern", "examples", "negative_examples"] {
            let mut source = baseline.clone();
            source["rules"][0].as_mapping_mut().unwrap().remove(field);
            assert!(first_party_rules(&serde_yaml::to_string(&source).unwrap(), &[]).is_err());
        }
    }

    fn fixture() -> tempfile::TempDir {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let fixture = tempfile::tempdir().unwrap();
        let manifest_path = format!("{GENERATED}/provenance.json");
        let manifest: Value =
            serde_json::from_slice(&fs::read(root.join(&manifest_path)).unwrap()).unwrap();
        let paths = manifest["generator_input_sha256"]
            .as_object()
            .unwrap()
            .keys()
            .chain(manifest["artifact_sha256"].as_object().unwrap().keys())
            .chain(std::iter::once(&manifest_path));
        for path in paths {
            let target = fixture.path().join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::copy(root.join(path), target).unwrap();
        }
        fixture
    }

    #[test]
    fn generated_bundle_is_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        generate(root, Some("--check")).unwrap();
    }

    #[test]
    fn check_rejects_corrupt_bundle_without_repairing_it() {
        let fixture = fixture();
        let path = fixture.path().join(format!("{GENERATED}/builtin-rules.gz"));
        fs::write(&path, b"corrupt bundle").unwrap();
        let error = generate(fixture.path(), Some("--check")).unwrap_err();
        assert!(error.to_string().contains("stale generated artifacts"), "{error:#}");
        assert_eq!(fs::read(path).unwrap(), b"corrupt bundle");
    }

    #[test]
    fn check_rejects_obsolete_service_files_without_removing_them() {
        let fixture = fixture();
        let path = fixture.path().join(format!("{GENERATED}/rules/betterleaks/obsolete.yml"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"rules: []\n").unwrap();
        let error = generate(fixture.path(), Some("--check")).unwrap_err();
        assert!(error.to_string().contains("obsolete generated rule files"));
        assert!(path.exists());
        generate(fixture.path(), None).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn missing_archived_source_fails_without_fetching() {
        let fixture = fixture();
        let path = fixture.path().join(format!("{GENERATED}/upstream-sources.json.gz"));
        let mut sources: Sources =
            serde_json::from_reader(GzDecoder::new(fs::File::open(&path).unwrap())).unwrap();
        let url = sources.keys().find(|url| url.ends_with("list.go")).unwrap().clone();
        sources.remove(&url);
        fs::write(path, gzip(&serde_json::to_vec(&sources).unwrap()).unwrap()).unwrap();
        let error = generate(fixture.path(), Some("--check")).unwrap_err();
        assert!(format!("{error:#}").contains("missing archived input"));
    }
}
