//! Path-only database contracts and regressions for the native placeholder budget.

use kingfisher_vectorscan::BlockScanner;

use super::*;
use crate::rule::RuleSyntax;

fn path_rule(id: &str, path: &str) -> Rule {
    let mut syntax = RuleSyntax::new(id, "Path-only fixture", "(?:)");
    syntax.betterleaks_path_only = true;
    syntax.path = Some(path.to_owned());
    Rule::new(syntax)
}

fn path_rules() -> Vec<Rule> {
    vec![path_rule("acme.file-key", r"\.key$"), path_rule("acme.file-p12", r"\.p12$")]
}

fn mixed_rules() -> Vec<Rule> {
    vec![
        path_rule("acme.file-key", r"\.key$"),
        Rule::new(RuleSyntax::new("acme.demo", "Demo fixture", "demo_[0-9]{4}")),
        path_rule("acme.file-p12", r"\.p12$"),
        Rule::new(RuleSyntax::new("acme.secret", "Secret fixture", "secret_[0-9]{4}")),
    ]
}

fn native_callbacks(database: &RulesDatabase, bytes: &[u8]) -> Result<Vec<(u32, u64)>> {
    let mut scanner = BlockScanner::new(database.vectorscan_db())?;
    let mut callbacks = Vec::new();
    scanner.scan(bytes, |id, _from, to, _flags| {
        callbacks.push((id, to));
        Scan::Continue
    })?;
    callbacks.sort_unstable();
    Ok(callbacks)
}

fn path_findings(
    database: &RulesDatabase,
    path: &str,
    bytes: &[u8],
) -> Result<Vec<(usize, String, String)>> {
    Ok(database
        .path_only_rules_for_source(path, None, bytes)?
        .into_iter()
        .map(|(index, rule)| {
            (index, rule.id().to_owned(), rule.finding_sha1_fingerprint().to_owned())
        })
        .collect())
}

#[test]
fn path_only_contract_all_path_only_findings_are_independent_of_content() -> Result<()> {
    let rules = path_rules();
    let fingerprints =
        rules.iter().map(|rule| rule.finding_sha1_fingerprint().to_owned()).collect::<Vec<_>>();
    let database = RulesDatabase::from_rules(rules)?;
    assert_eq!(database.num_rules(), 2);
    assert!(native_callbacks(&database, b"ordinary text")?.is_empty());
    for bytes in [&b""[..], &b"unrelated content"[..], &[0, 0, 0, 0][..]] {
        assert_eq!(
            path_findings(&database, "secrets/private.key", bytes)?,
            vec![(0, "acme.file-key".to_owned(), fingerprints[0].clone())]
        );
        assert_eq!(
            path_findings(&database, "secrets/archive.p12", bytes)?,
            vec![(1, "acme.file-p12".to_owned(), fingerprints[1].clone())]
        );
        assert!(path_findings(&database, "source.rs", bytes)?.is_empty());
    }
    let error = RulesDatabase::from_rules(Vec::new()).err().expect("empty rules must fail");
    assert_eq!(error.to_string(), "No rules to compile");
    Ok(())
}

#[test]
fn path_only_contract_mixed_rules_keep_catalog_ids_and_repeated_content_hits() -> Result<()> {
    let rules = mixed_rules();
    let key_fingerprint = rules[0].finding_sha1_fingerprint().to_owned();
    let p12_fingerprint = rules[2].finding_sha1_fingerprint().to_owned();
    let database = RulesDatabase::from_rules(rules)?;
    let bytes = b"demo_1234 secret_5678 demo_9012 secret_3456";
    let ids = native_callbacks(&database, bytes)?.into_iter().map(|(id, _)| id).collect::<Vec<_>>();
    assert_eq!(ids, vec![1, 1, 3, 3]);
    assert_eq!(database.rules()[1].id(), "acme.demo");
    assert_eq!(database.rules()[3].id(), "acme.secret");
    assert_eq!(
        path_findings(&database, "private.key", bytes)?,
        vec![(0, "acme.file-key".to_owned(), key_fingerprint)]
    );
    assert_eq!(
        path_findings(&database, "archive.p12", b"unrelated")?,
        vec![(2, "acme.file-p12".to_owned(), p12_fingerprint)]
    );
    Ok(())
}

#[test]
fn path_only_contract_cache_roundtrip_preserves_native_and_path_results() -> Result<()> {
    for rules in [path_rules(), mixed_rules()] {
        let cache_dir = env::temp_dir()
            .join(format!("kingfisher-path-only-cache-test-{}", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let cache = RuleCacheConfig::new(&cache_dir);
            let bytes = b"demo_1234\0secret_5678\0demo_9012";
            let stored = RulesDatabase::from_rules_with_cache(rules.clone(), &cache)?;
            assert_eq!(stored.cache_status(), RuleCacheStatus::Stored);
            let native = native_callbacks(&stored, bytes)?;
            let key = path_findings(&stored, "private.key", bytes)?;
            let p12 = path_findings(&stored, "archive.p12", bytes)?;
            let loaded = RulesDatabase::from_rules_with_cache(rules, &cache)?;
            assert_eq!(loaded.cache_status(), RuleCacheStatus::Loaded);
            assert_eq!(native_callbacks(&loaded, bytes)?, native);
            assert_eq!(path_findings(&loaded, "private.key", bytes)?, key);
            assert_eq!(path_findings(&loaded, "archive.p12", bytes)?, p12);
            assert!(path_findings(&loaded, "source.rs", bytes)?.is_empty());
            Ok(())
        })();
        // All databases/scanners and native cache file handles are closed first.
        let cleanup = fs::remove_dir_all(&cache_dir);
        result?;
        cleanup?;
    }
    let error =
        RulesDatabase::from_rules_with_cache(Vec::new(), &RuleCacheConfig::new(PathBuf::new()))
            .err()
            .expect("empty cached rules must fail");
    assert_eq!(error.to_string(), "No rules to compile");
    Ok(())
}

#[test]
fn path_only_regression_native_callbacks_are_bounded_per_rule_per_block() -> Result<()> {
    let content = b"demo_1234 secret_5678 demo_9012 secret_3456";
    let mut middle = content[..10].to_vec();
    middle.extend_from_slice(&[0; 64]);
    middle.extend_from_slice(&content[10..]);
    let mut end = content.to_vec();
    end.extend_from_slice(&[0; 64]);
    let mut start = vec![0; 64];
    start.extend_from_slice(content);
    let blocks = [middle, end, start, content.to_vec()];
    for (rules, path_ids, content_ids) in [
        (path_rules(), vec![0_u32, 1], Vec::new()),
        (mixed_rules(), vec![0_u32, 2], vec![1_u32, 1, 3, 3]),
    ] {
        let database = RulesDatabase::from_rules(rules)?;
        let mut scanner = BlockScanner::new(database.vectorscan_db())?;
        // Reuse native scratch across block calls: each call resets SINGLEMATCH.
        for _ in 0..2 {
            for block in &blocks {
                let mut callbacks = Vec::new();
                scanner.scan(block, |id, _from, _to, _flags| {
                    callbacks.push(id);
                    Scan::Continue
                })?;
                for path_id in &path_ids {
                    let count = callbacks.iter().filter(|id| *id == path_id).count();
                    assert_eq!(
                        count,
                        usize::from(block.contains(&0)),
                        "path-only rule {path_id} must retain any-position NUL detection, bounded to one callback per block"
                    );
                }
                let mut actual_content =
                    callbacks.into_iter().filter(|id| !path_ids.contains(id)).collect::<Vec<_>>();
                actual_content.sort_unstable();
                assert_eq!(actual_content, content_ids);
            }
        }
    }
    Ok(())
}

#[test]
fn path_only_regression_cache_key_distinguishes_content_and_path_only_modes() {
    let mut syntax = RuleSyntax::new("acme.cache-mode", "Cache mode fixture", "token_[0-9]{4}");
    let content = Rule::new(syntax.clone());
    syntax.betterleaks_path_only = true;
    let path_only = Rule::new(syntax);
    assert_eq!(content.id(), path_only.id());
    assert_eq!(content.syntax().pattern, path_only.syntax().pattern);
    assert_eq!(content.finding_sha1_fingerprint(), path_only.finding_sha1_fingerprint());
    assert_ne!(compute_rule_cache_key(&[content]), compute_rule_cache_key(&[path_only]));
}
