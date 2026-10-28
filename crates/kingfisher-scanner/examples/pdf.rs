//! cargo run -p kingfisher-scanner --features extraction --example pdf -- document.pdf
use std::{fs::File, io::Read, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use kingfisher_scanner::{
    Blob, RulesDatabase, ScanControl, Scanner,
    extraction::pdf::extract_pdf_text_from_bytes_with_budget_strict, get_builtin_rules,
};

fn main() -> Result<()> {
    let path = PathBuf::from(std::env::args_os().nth(1).context("provide a PDF file path")?);
    let max_bytes = 64 * 1024 * 1024;
    // This example propagates errors, rather than silently scanning raw PDF bytes.
    // The strict variant also rejects an undecodable stream instead of skipping
    // it. Use extract_pdf_text_from_bytes_with_budget for best-effort page text.
    // Input/output caps are separate, not a total memory cap. Individual parser
    // calls cannot be preempted; controls are cooperative around/between calls.
    let control = ScanControl::default().with_timeout(Duration::from_secs(10))?;
    let mut bytes = Vec::new();
    File::open(&path)?.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    let pages = extract_pdf_text_from_bytes_with_budget_strict(&bytes, max_bytes, &control)?;
    let scanner =
        Scanner::new(Arc::new(RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?));
    for (name, text) in pages {
        // Keep original repository/object provenance separately in your application.
        // Finding coordinates are page-text offsets, not PDF file offsets.
        let logical = format!("{}!{name}", path.display());
        let findings =
            scanner.scan_blob_at_path_with_control(&Blob::from_bytes(text), &logical, &control)?;
        // Never print secrets. Detection does not validate or revoke credentials.
        println!(
            "{logical}: {} visible findings",
            findings.iter().filter(|f| f.rule().syntax().visible).count()
        );
    }
    Ok(())
}
