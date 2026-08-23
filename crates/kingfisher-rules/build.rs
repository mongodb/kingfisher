#[path = "build_support/betterleaks.rs"]
mod betterleaks;
#[path = "build_support/builtin_docs.rs"]
mod builtin_docs;
#[path = "build_support/imported_capabilities.rs"]
mod imported_capabilities;
#[path = "build_support/veles.rs"]
mod veles;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};

// Source permalink: https://github.com/betterleaks/betterleaks/blob/3d798ac55d89f14a60c8df65d4d2bda6fccb1ea1/config/betterleaks.toml
const BETTERLEAKS_CONFIG_URL: &str = "https://raw.githubusercontent.com/betterleaks/betterleaks/3d798ac55d89f14a60c8df65d4d2bda6fccb1ea1/config/betterleaks.toml";
const BETTERLEAKS_CONFIG_SHA256: &str =
    "386d0e06be50d7887048a6b31b801ed22c7067f251c36ab226be78fff4ee6166";
const BUNDLE_MAGIC: &[u8] = b"KFRULES\x01";
const CAPABILITY_OVERLAY: &str = "data/imported-rules-capabilities.yml";
const VELES_CONFIG: &str = "data/veles-rules.yml";
const BUILTIN_RULES_DOC: &str = "docs-site/docs/rules/builtin-rules.md";

fn main() {
    println!("cargo:rerun-if-env-changed=KINGFISHER_BETTERLEAKS_CONFIG");
    println!("cargo:rerun-if-env-changed=KINGFISHER_BETTERLEAKS_CONFIG_URL");
    println!("cargo:rerun-if-changed={CAPABILITY_OVERLAY}");
    println!("cargo:rerun-if-changed={VELES_CONFIG}");
    println!("cargo:rerun-if-changed=build_support/betterleaks.rs");
    println!("cargo:rerun-if-changed=build_support/builtin_docs.rs");
    println!("cargo:rerun-if-changed=build_support/imported_capabilities.rs");
    println!("cargo:rerun-if-changed=build_support/veles.rs");

    build_default_bundle().expect("failed to build the default rule bundle");
}

fn build_default_bundle() -> Result<()> {
    let source_url = std::env::var("KINGFISHER_BETTERLEAKS_CONFIG_URL")
        .unwrap_or_else(|_| BETTERLEAKS_CONFIG_URL.to_string());
    let local_override = std::env::var_os("KINGFISHER_BETTERLEAKS_CONFIG");
    let contents = match local_override.as_ref() {
        Some(path) => {
            let path = PathBuf::from(path);
            println!("cargo:rerun-if-changed={}", path.display());
            fs::read_to_string(&path)
                .with_context(|| format!("failed to read Betterleaks config {}", path.display()))?
        }
        None => download_config(&source_url)?,
    };
    if local_override.is_none() && source_url == BETTERLEAKS_CONFIG_URL {
        let actual = Sha256::digest(contents.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if actual != BETTERLEAKS_CONFIG_SHA256 {
            bail!(
                "Betterleaks config digest mismatch: expected {BETTERLEAKS_CONFIG_SHA256}, got {actual}"
            );
        }
    } else if local_override.is_some() {
        println!(
            "cargo:warning=using KINGFISHER_BETTERLEAKS_CONFIG override; source digest verification is disabled"
        );
    } else {
        println!(
            "cargo:warning=using KINGFISHER_BETTERLEAKS_CONFIG_URL override; source digest verification is disabled"
        );
    }

    let capabilities = fs::read_to_string(CAPABILITY_OVERLAY)
        .with_context(|| format!("failed to read {CAPABILITY_OVERLAY}"))?;
    let (betterleaks_capabilities, veles_capabilities) =
        imported_capabilities::split_config(&capabilities)?;
    let yaml = betterleaks::import_config(&contents, &source_url, &betterleaks_capabilities)
        .context("failed to parse the Betterleaks default configuration")?;
    let veles_config = fs::read_to_string(VELES_CONFIG)
        .with_context(|| format!("failed to read {VELES_CONFIG}"))?;
    let veles_yaml = veles::import_config(&veles_config, &veles_capabilities, download_config)
        .context("failed to import selected Veles rules")?;

    let output_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    write_rule_bundle(
        [
            (Path::new("betterleaks.yml"), yaml.as_bytes()),
            (Path::new("veles.yml"), veles_yaml.as_bytes()),
        ],
        &output_dir.join("builtin-rules.gz"),
    )?;
    let docs = builtin_docs::generate_builtin_rules_page(&[
        ("Betterleaks", &yaml),
        ("Veles", &veles_yaml),
    ])?;
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .context("kingfisher-rules must be inside the workspace crates directory")?;
    write_if_changed(&workspace_root.join(BUILTIN_RULES_DOC), docs.as_bytes())?;
    Ok(())
}

fn download_config(url: &str) -> Result<String> {
    // ClusterFuzzLite exports sanitizer CFLAGS globally. Use the platform TLS
    // backend here so the build-only downloader does not pull in ring, whose C
    // objects would otherwise be sanitizer-instrumented and linked into this
    // non-fuzz build script.
    let agent = ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::NativeTls).build(),
        )
        .build()
        .new_agent();
    let mut response = agent
        .get(url)
        .header("User-Agent", "kingfisher-build")
        .call()
        .with_context(|| format!("failed to download {url}"))?;
    response
        .body_mut()
        .read_to_string()
        .with_context(|| format!("failed to read rules downloaded from {url}"))
}

fn write_rule_bundle<'a, I>(files: I, output: &Path) -> Result<()>
where
    I: IntoIterator<Item = (&'a Path, &'a [u8])>,
{
    let mut encoder = GzEncoder::new(fs::File::create(output)?, Compression::best());
    encoder.write_all(BUNDLE_MAGIC)?;

    for (path, contents) in files {
        let name = path.to_str().expect("builtin rule paths must be UTF-8");
        let name_len = u32::try_from(name.len()).expect("rule path exceeds bundle limit");
        let contents_len = u64::try_from(contents.len()).expect("rule file exceeds bundle limit");

        encoder.write_all(&name_len.to_le_bytes())?;
        encoder.write_all(&contents_len.to_le_bytes())?;
        encoder.write_all(name.as_bytes())?;
        encoder.write_all(contents)?;
    }

    encoder.write_all(&0_u32.to_le_bytes())?;
    encoder.finish()?;
    Ok(())
}

fn write_if_changed(path: &Path, contents: &[u8]) -> Result<()> {
    if fs::read(path).is_ok_and(|existing| existing == contents) {
        return Ok(());
    }
    fs::write(path, contents).with_context(|| format!("failed to update {}", path.display()))
}
