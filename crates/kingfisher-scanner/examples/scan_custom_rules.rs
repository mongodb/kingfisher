//! Load private YAML/TOML rules and scan a file, preserving source-path filters.
use std::{path::PathBuf, sync::Arc};

use anyhow::ensure;
use kingfisher_rules::{Confidence, Rules};
use kingfisher_scanner::{RulesDatabase, Scanner, ScannerConfig};

fn main() -> anyhow::Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(args.len() == 2, "usage: scan_custom_rules <rules-file-or-directory> <input-file>");
    let rules = Rules::from_paths([&args[0]], Confidence::Low)?;
    let database = RulesDatabase::from_rule_collection(rules)?;
    let scanner = Scanner::with_config(
        Arc::new(database),
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );
    for finding in scanner.scan_file(&args[1])?.into_iter().filter(|f| f.rule().visible()) {
        println!("{} at {}:{}", finding.rule_id, finding.line(), finding.column());
    }
    // Loading validation metadata does not execute it. See http_validation.rs.
    Ok(())
}
