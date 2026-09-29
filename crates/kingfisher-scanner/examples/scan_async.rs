//! Reuse one scanner with bounded CPU work in an async application.
use std::sync::Arc;

use kingfisher_scanner::{Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig};
use tokio::sync::Semaphore;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // In a service, build this once at startup, outside request handlers.
    let scanner = tokio::task::spawn_blocking(|| -> anyhow::Result<Scanner> {
        let database = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
            "acme.demo",
            "Synthetic example token",
            r"\b(demo_[a-z0-9]{16})\b",
        ))])?;
        Ok(Scanner::with_config(
            Arc::new(database),
            ScannerConfig { redact_secrets: true, ..Default::default() },
        ))
    })
    .await??;
    let scanner = Arc::new(scanner);
    let workers = Arc::new(Semaphore::new(2));
    let inputs = ["ordinary content", "token=demo_abcd1234efgh5678"];
    let mut jobs = Vec::new();
    for input in inputs {
        // Acquire before scheduling to bound queued and running blocking work.
        let permit = Arc::clone(&workers).acquire_owned().await?;
        let scanner = Arc::clone(&scanner);
        let bytes = input.as_bytes().to_vec();
        jobs.push(tokio::task::spawn_blocking(move || {
            let _permit = permit;
            scanner.scan_bytes(&bytes)
        }));
    }
    for job in jobs {
        let findings = job.await??;
        println!("visible findings={}", findings.iter().filter(|f| f.rule().visible()).count());
    }
    Ok(())
}
