//! Scan committed history without a Git subprocess, fetch, checkout or writes.
//!
//! cargo run -p kingfisher-scanner --features git --example git_inputs -- /path/to/repo
use std::{path::PathBuf, sync::Arc, time::Duration};

use kingfisher_scanner::{
    Blob, RulesDatabase, ScanControl, Scanner, ScannerConfig, get_builtin_rules,
    git::{GitEvent, GitInputs, GitOptions, GitScope},
};

fn main() -> anyhow::Result<()> {
    let repository = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: git_inputs /path/to/repo"))?;
    // Compile once and reuse for all file versions. Redaction protects the
    // reported secret; provenance and paths may still contain private data.
    let rules = Arc::new(RulesDatabase::from_rule_collection(get_builtin_rules(None)?)?);
    let scanner =
        Scanner::with_config(rules, ScannerConfig { redact_secrets: true, ..Default::default() });
    // This deadline covers descriptor preparation AND the iterator lifetime,
    // including time spent scanning yielded inputs. Keep detection independent
    // by using a separate control if acquisition and scanning need different budgets.
    let control = ScanControl::default().with_timeout(Duration::from_secs(60))?;
    let options = GitOptions {
        discover: false, // Require the given repository root; don't search parents.
        max_blob_size: Some(16 * 1024 * 1024),
        max_commits: Some(100_000),
        max_inputs: Some(1_000_000),
        // Missing blobs fail: no network fetch is performed for partial clones.
        skip_missing_blobs: false,
    };
    // The default scope visits HEAD ancestry, including merge parents. Each
    // version is compared with its first parent; unchanged subtrees are skipped.
    for event in GitInputs::open(repository, GitScope::default(), options, control.clone())? {
        match event? {
            GitEvent::Input(input) => {
                // Preserve the repository-relative path for path-aware rules.
                // raw_path retains exact bytes if Git names are not UTF-8.
                let blob = Blob::from_bytes(input.data);
                let findings =
                    scanner.scan_blob_at_path_with_control(&blob, &input.path, &control)?;
                for finding in findings.into_iter().filter(|finding| finding.rule.syntax().visible)
                {
                    // Commit messages/emails are intentionally excluded from logs.
                    println!("{}: {} {}", input.path, finding.rule_id, finding.secret);
                }
            }
            GitEvent::Skipped { blob_id, reason, .. } => {
                // A size skip is a coverage gap, never evidence of a clean input.
                eprintln!("Git blob {blob_id} skipped: {reason:?}");
            }
        }
    }
    Ok(())
}
