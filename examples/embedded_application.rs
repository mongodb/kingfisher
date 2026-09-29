//! The kingfisher-bin package exposes its library under the name `kingfisher`.
use std::sync::Arc;

use kingfisher::kingfisher_scanner::{Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig};

fn main() -> anyhow::Result<()> {
    let rule = Rule::new(RuleSyntax::new("acme.demo", "Demo", r"(demo_[a-z0-9]{16})"));
    let database = Arc::new(RulesDatabase::from_rules(vec![rule])?);
    let scanner = Scanner::with_config(
        database,
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );
    let findings = scanner.scan_bytes(b"token=demo_abcd1234efgh5678")?;
    assert_eq!(findings.len(), 1);
    println!("{}: {}", findings[0].rule_id, findings[0].secret);
    Ok(())
}
