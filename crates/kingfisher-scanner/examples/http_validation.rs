//! Scan and validate using the high-level API and a loopback-only mock provider.
mod support;

use std::{path::Path, sync::Arc, time::Duration};

use kingfisher_rules::{Confidence, Rules};
use kingfisher_scanner::{RulesDatabase, Scanner, ValidationOutcome, Validator};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let rules = Rules::from_paths_and_contents(
        [(Path::new("acme-http.yml"), include_bytes!("fixtures/acme-http.yml").as_slice())],
        Confidence::Low,
    )?;
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules)?));
    let (endpoint, mock) = support::mock_provider().await?;
    let validator = Validator::builder()
        .timeout(Duration::from_secs(5))
        .concurrency(4)
        .variable("ENDPOINT", endpoint)
        .allow_internal_ips(true) // Only for this trusted loopback mock.
        .build()?;

    for expected in [
        ValidationOutcome::VerifiedActive,
        ValidationOutcome::VerifiedInactive,
        ValidationOutcome::Unavailable,
        ValidationOutcome::Unavailable,
    ] {
        // Keep raw captures until validation finishes; pass the entire scan result
        // so the validator can bind supporting credentials, including hidden rules.
        let findings = scanner.scan_bytes(b"token=demo_abcd1234efgh5678")?;
        for result in validator.validate_findings(findings).await {
            assert_eq!(result.outcome, expected);
            let result = result.into_redacted();
            println!("{}", json!({"rule_id": result.finding.rule_id, "outcome": result.outcome}));
        }
    }
    tokio::time::timeout(Duration::from_secs(5), mock).await???;
    Ok(())
}
