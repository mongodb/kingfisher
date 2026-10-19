//! Explicitly scan a local file and validate with an OAuth2-protected custom rule.
//! Usage: oauth2_validation company-rules.yml input.txt
//! Configure literal HTTPS endpoints and credential environment-variable names
//! in the rule's validation.content.auth.oauth2 block before running this example.
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, ensure};
use kingfisher_rules::{Confidence, Rules};
use kingfisher_scanner::{RulesDatabase, Scanner, Validator};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    ensure!(args.len() == 2, "Usage: oauth2_validation RULES.yml INPUT");
    let rules = Rules::from_paths([&args[0]], Confidence::Low)?;
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules)?));
    let input = std::fs::read(&args[1]).context("Cannot read scan input")?;
    // Keep this validator for the session: clones share token reuse, refresh,
    // failure backoff and the validation concurrency limit. Scanning stays offline.
    let validator = Validator::builder().concurrency(4).timeout(Duration::from_secs(10)).build()?;
    for result in validator.validate_findings(scanner.scan_bytes(&input)?).await {
        let result = result.into_redacted();
        println!("{} {:?} {:?}", result.finding.rule_id, result.outcome, result.reason);
    }
    Ok(())
}
