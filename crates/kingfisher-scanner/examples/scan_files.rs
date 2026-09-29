//! Scan an explicit file list and emit JSON Lines without credential values.
use std::{path::PathBuf, sync::Arc};

use anyhow::ensure;
use kingfisher_scanner::{RulesDatabase, Scanner, ScannerConfig, get_builtin_rules};
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let paths: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(!paths.is_empty(), "usage: scan_files <file> [file ...]");
    let database = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
    let scanner = Scanner::with_config(
        Arc::new(database),
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );
    for path in paths {
        // Propagate I/O and scan errors: a failed file must not look clean.
        for finding in scanner.scan_file(&path)?.into_iter().filter(|f| f.rule().visible()) {
            println!(
                "{}",
                json!({
                    "path": path.to_string_lossy(),
                    "rule_id": finding.rule_id,
                    "line": finding.line(),
                    "column": finding.column(),
                    "validation_outcome": "not_attempted",
                })
            );
        }
    }
    // This is a report producer. A CI gate can instead return a nonzero exit
    // status when findings are present, independently of validation status.
    Ok(())
}
