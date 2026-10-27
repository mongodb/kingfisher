//! Scan a file using trusted custom HTTP rules; alternative environments are opt-in.
//! cargo run -p kingfisher-scanner --features validation --example http_fallbacks -- RULES.yml INPUT [--fallbacks]
use std::{path::PathBuf, sync::Arc};

use anyhow::ensure;
use kingfisher_rules::{Confidence, Rules};
use kingfisher_scanner::{RulesDatabase, Scanner, Validator};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2 || (args.len() == 3 && args[2] == "--fallbacks"),
        "Usage: http_fallbacks RULES.yml INPUT [--fallbacks]"
    );
    let rules = Rules::from_paths([PathBuf::from(&args[0])], Confidence::Low)?;
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules)?));
    // Detection is offline. Retain all helpers until validation binds components.
    let findings = scanner.scan_bytes(&std::fs::read(PathBuf::from(&args[1]))?)?;
    let validator = Validator::builder().http_fallbacks(args.len() == 3).build()?;
    for result in validator.validate_findings(findings).await {
        // Never print private selection URLs or credentials. Revocation is separate
        // and can explicitly reuse this result via Revoker::revoke_validated.
        let result = result.into_redacted();
        println!("{} {:?} {:?}", result.finding.rule_id, result.outcome, result.reason);
    }
    Ok(())
}
