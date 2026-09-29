//! Scan a file with built-ins, then explicitly validate detected credentials.
//! Unlike http_validation, this example can contact real credential providers.
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use kingfisher_scanner::{RulesDatabase, Scanner, Validator, get_builtin_rules};
use serde_json::json;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let path = PathBuf::from(std::env::args_os().nth(1).context("usage: validate_file <file>")?);
    let findings = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let database = RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?;
        Scanner::new(Arc::new(database)).scan_file(path)
    })
    .await??;
    let validator = Validator::builder().timeout(Duration::from_secs(10)).concurrency(4).build()?;
    for result in validator.validate_findings(findings).await {
        if !result.finding.rule().visible() {
            continue;
        }
        let result = result.into_redacted();
        println!(
            "{}",
            json!({
                "rule_id": result.finding.rule_id,
                "line": result.finding.line(),
                "outcome": result.outcome,
                "reason": result.reason,
            })
        );
    }
    Ok(())
}
