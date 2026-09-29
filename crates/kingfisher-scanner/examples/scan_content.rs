//! Scan synthetic content, or pass a file path to scan with the embedded catalog.
use std::sync::Arc;

use kingfisher_scanner::{
    Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig, get_builtin_rules,
};

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    let database = if path.is_some() {
        RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?
    } else {
        RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
            "acme.demo",
            "Synthetic example token",
            r"(?P<token>demo_[a-z0-9]{16})",
        ))])?
    };
    let scanner = Arc::new(Scanner::with_config(
        Arc::new(database),
        ScannerConfig { redact_secrets: true, ..Default::default() },
    ));
    let findings = match path {
        Some(path) => scanner.scan_file(path)?,
        None => scanner.scan_bytes(b"token=demo_abcd1234efgh5678")?,
    };
    for finding in findings.iter().filter(|finding| finding.rule().visible()) {
        println!("{} at {}:{}: [REDACTED]", finding.rule_id, finding.line(), finding.column());
    }
    // Reuse the same compiled database and scanner on a worker thread.
    let worker = Arc::clone(&scanner);
    let clean = std::thread::spawn(move || worker.scan_bytes(b"ordinary content"))
        .join()
        .expect("scan worker panicked")?;
    assert!(clean.is_empty());
    Ok(())
}
