
use std::path::PathBuf;
use std::sync::Barrier;

use super::*;
use crate::origin::Origin;
use crate::rules::rule::{BetterleaksExpr, RuleSyntax};

const TOKEN: &[u8] = b"prefix acme_Q7M2V8L4 suffix";

fn rules(path: Option<&str>) -> RulesDatabase {
    let mut rule = RuleSyntax::new("acme.removal-worker", "Removal worker", r"(acme_[A-Z0-9]{8})");
    rule.path = path.map(str::to_owned);
    RulesDatabase::from_rules(vec![Rule::new(rule)]).unwrap()
}

fn pool(rules: &RulesDatabase) -> Arc<ScannerPool> {
    Arc::new(ScannerPool::new(Arc::new(rules.vectorscan_db().clone())))
}

fn origin(path: &str) -> OriginSet {
    Origin::from_file(PathBuf::from(path)).into()
}

fn stats(stats: &MatcherStats) -> (u64, u64, u64, u64) {
    (stats.blobs_seen, stats.blobs_scanned, stats.bytes_seen, stats.bytes_scanned)
}

#[test]
fn statistic_merges_accumulate_each_counter_and_leave_the_source_unchanged() {
    let mut total =
        MatcherStats { blobs_seen: 2, blobs_scanned: 1, bytes_seen: 100, bytes_scanned: 60 };
    let increment =
        MatcherStats { blobs_seen: 5, blobs_scanned: 3, bytes_seen: 700, bytes_scanned: 420 };
    total.update(&increment);
    assert_eq!(stats(&total), (7, 4, 800, 480));
    assert_eq!(stats(&increment), (5, 3, 700, 420));
    total.update(&MatcherStats::default());
    assert_eq!(stats(&total), (7, 4, 800, 480));
}

#[test]
fn statistics_publish_on_worker_drop_and_include_repeated_scans() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let global = Mutex::new(MatcherStats::default());
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let source = origin("worker.env");
    let mut matcher = Matcher::new(
        &database,
        pool(&database),
        &seen,
        Some(&global),
        false,
        None,
        &[],
        false,
        true,
    )
    .unwrap();
    assert!(
        matches!(matcher.scan_blob(&blob, &source, None, false, false, true).unwrap(), ScanResult::New(found) if found.len() == 1)
    );
    assert!(matches!(
        matcher.scan_blob(&blob, &source, None, false, false, true).unwrap(),
        ScanResult::SeenWithMatches
    ));
    assert_eq!(stats(&global.lock().unwrap()), (0, 0, 0, 0));
    drop(matcher);
    let bytes = TOKEN.len() as u64 * 2;
    assert_eq!(stats(&global.lock().unwrap()), (2, 2, bytes, bytes));
}

#[test]
fn source_prefiltered_inputs_are_seen_but_not_scanned_or_cached() {
    let rule =
        Rule::new(RuleSyntax::new("betterleaks.removal-worker", "Worker", r"(acme_[A-Z0-9]{8})"));
    let database = RulesDatabase::from_rules_with_betterleaks_prefilter(
        vec![rule],
        Some(BetterleaksExpr::Bool { value: true }),
    )
    .unwrap();
    let seen = BlobIdMap::new();
    let global = Mutex::new(MatcherStats::default());
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let mut matcher = Matcher::new(
        &database,
        pool(&database),
        &seen,
        Some(&global),
        false,
        None,
        &[],
        false,
        true,
    )
    .unwrap();
    assert!(
        matches!(matcher.scan_blob(&blob, &origin("excluded.env"), None, false, false, true).unwrap(), ScanResult::New(found) if found.is_empty())
    );
    assert!(seen.is_empty());
    drop(matcher);
    assert_eq!(stats(&global.lock().unwrap()), (1, 0, TOKEN.len() as u64, 0));
}

#[test]
fn identical_bytes_are_rescanned_for_each_source_path_before_deduplication() {
    let database = rules(Some(r"\.env$"));
    let seen = BlobIdMap::new();
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let mut matcher =
        Matcher::new(&database, pool(&database), &seen, None, false, None, &[], false, true)
            .unwrap();
    let skipped = origin("not-selected.txt");
    let selected = origin("selected.env");
    assert!(
        matches!(matcher.scan_blob(&blob, &skipped, None, false, false, true).unwrap(), ScanResult::New(found) if found.is_empty())
    );
    assert!(seen.is_empty());
    assert!(
        matches!(matcher.scan_blob(&blob, &selected, None, false, false, true).unwrap(), ScanResult::New(found) if found.len() == 1)
    );
    assert_eq!(seen.get(blob.id_ref()), Some(true));
    assert!(
        matches!(matcher.scan_blob(&blob, &skipped, None, false, false, true).unwrap(), ScanResult::New(found) if found.is_empty())
    );
    assert!(matches!(
        matcher.scan_blob(&blob, &selected, None, false, false, true).unwrap(),
        ScanResult::SeenWithMatches
    ));
}

#[test]
fn a_preexisting_false_cache_entry_keeps_the_result_branch_and_is_updated() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let blob = Blob::from_bytes(TOKEN.to_vec());
    assert_eq!(seen.insert(blob.id(), false), None);
    let mut matcher =
        Matcher::new(&database, pool(&database), &seen, None, false, None, &[], false, true)
            .unwrap();
    assert!(matches!(
        matcher.scan_blob(&blob, &origin("source.env"), None, false, false, true).unwrap(),
        ScanResult::SeenSansMatches
    ));
    assert_eq!(seen.get(blob.id_ref()), Some(true));
}

#[test]
fn disabling_deduplication_bypasses_cache_reads_and_writes() {
    let database = rules(None);
    let scanner_pool = pool(&database);
    let blob = Blob::from_bytes(TOKEN.to_vec());
    for previous in [None, Some(false), Some(true)] {
        let seen = BlobIdMap::new();
        if let Some(value) = previous {
            seen.insert(blob.id(), value);
        }
        let mut matcher = Matcher::new(
            &database,
            scanner_pool.clone(),
            &seen,
            None,
            false,
            None,
            &[],
            false,
            true,
        )
        .unwrap();
        for _ in 0..2 {
            assert!(
                matches!(matcher.scan_blob(&blob, &origin("source.env"), None, false, true, true).unwrap(), ScanResult::New(found) if found.len() == 1)
            );
        }
        assert_eq!(seen.get(blob.id_ref()), previous);
    }
}

#[test]
fn clean_and_empty_blobs_do_not_occupy_the_scan_wide_cache() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let mut matcher =
        Matcher::new(&database, pool(&database), &seen, None, false, None, &[], false, true)
            .unwrap();
    for bytes in [b"ordinary clean contents".as_slice(), b"".as_slice()] {
        let blob = Blob::from_bytes(bytes.to_vec());
        for _ in 0..2 {
            assert!(
                matches!(matcher.scan_blob(&blob, &origin("clean.env"), None, false, false, true).unwrap(), ScanResult::New(found) if found.is_empty())
            );
        }
        assert_eq!(seen.get(blob.id_ref()), None);
    }
    assert!(seen.is_empty());
}

#[test]
fn parallel_workers_share_deduplication_and_publish_complete_totals() {
    const WORKERS: usize = 4;
    let database = rules(None);
    let scanner_pool = pool(&database);
    let seen = BlobIdMap::new();
    let global = Mutex::new(MatcherStats::default());
    let barrier = Barrier::new(WORKERS);
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let source = origin("shared.env");
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..WORKERS {
            let (database, seen, global, barrier, blob, source) =
                (&database, &seen, &global, &barrier, &blob, &source);
            let scanner_pool = scanner_pool.clone();
            handles.push(scope.spawn(move || {
                let mut matcher = Matcher::new(
                    database,
                    scanner_pool,
                    seen,
                    Some(global),
                    false,
                    None,
                    &[],
                    false,
                    true,
                )
                .unwrap();
                barrier.wait();
                match matcher.scan_blob(blob, source, None, false, false, true).unwrap() {
                    ScanResult::New(found) => {
                        assert_eq!(found.len(), 1);
                        true
                    }
                    ScanResult::SeenWithMatches => false,
                    ScanResult::SeenSansMatches => panic!("no worker records a false entry"),
                }
            }));
        }
        handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(results.into_iter().filter(|new| *new).count(), 1);
    assert_eq!(seen.len(), 1);
    let bytes = TOKEN.len() as u64 * WORKERS as u64;
    assert_eq!(stats(&global.lock().unwrap()), (WORKERS as u64, WORKERS as u64, bytes, bytes));
}

#[test]
fn pristine_worker_clones_publish_their_own_scans_and_share_the_cache() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let global = Mutex::new(MatcherStats::default());
    let template = Matcher::new(
        &database,
        pool(&database),
        &seen,
        Some(&global),
        false,
        None,
        &[],
        false,
        true,
    )
    .unwrap();
    let mut first = template.clone();
    let mut second = template.clone();
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let source = origin("clones.env");
    assert!(
        matches!(first.scan_blob(&blob, &source, None, false, false, true).unwrap(), ScanResult::New(found) if found.len() == 1)
    );
    assert!(matches!(
        second.scan_blob(&blob, &source, None, false, false, true).unwrap(),
        ScanResult::SeenWithMatches
    ));
    drop(first);
    assert_eq!(stats(&global.lock().unwrap()), (1, 1, TOKEN.len() as u64, TOKEN.len() as u64));
    drop(second);
    drop(template);
    let bytes = TOKEN.len() as u64 * 2;
    assert_eq!(stats(&global.lock().unwrap()), (2, 2, bytes, bytes));
}

#[test]
fn constructor_retains_disabled_enabled_and_explicit_shared_profiling_modes() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let scanner_pool = pool(&database);
    let plain =
        Matcher::new(&database, scanner_pool.clone(), &seen, None, false, None, &[], false, true)
            .unwrap();
    assert!(plain.get_profiling_report().is_none());
    let enabled =
        Matcher::new(&database, scanner_pool.clone(), &seen, None, true, None, &[], false, true)
            .unwrap();
    assert!(enabled.get_profiling_report().unwrap().is_empty());
    let shared = Arc::new(ConcurrentRuleProfiler::new());
    shared.start_rule("seed", "Seed", "pattern", "source");
    shared.end_rule("seed", true, 1, 0, "source");
    let explicit =
        Matcher::new(&database, scanner_pool, &seen, None, false, Some(shared), &[], false, true)
            .unwrap();
    let report = explicit.get_profiling_report().unwrap();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].rule_id, "seed");
    assert_eq!(report[0].total_matches, 1);
}

#[test]
fn cloning_a_used_worker_preserves_and_publishes_its_existing_counters() {
    let database = rules(None);
    let seen = BlobIdMap::new();
    let global = Mutex::new(MatcherStats::default());
    let blob = Blob::from_bytes(TOKEN.to_vec());
    let source = origin("used-clone.env");
    let mut original = Matcher::new(
        &database,
        pool(&database),
        &seen,
        Some(&global),
        false,
        None,
        &[],
        false,
        true,
    )
    .unwrap();
    assert!(matches!(
        original.scan_blob(&blob, &source, None, false, false, true).unwrap(),
        ScanResult::New(found) if found.len() == 1
    ));
    let mut copied = original.clone();
    assert!(matches!(
        copied.scan_blob(&blob, &source, None, false, false, true).unwrap(),
        ScanResult::SeenWithMatches
    ));
    assert_eq!(stats(&global.lock().unwrap()), (0, 0, 0, 0));
    drop(copied);
    let bytes = TOKEN.len() as u64;
    assert_eq!(stats(&global.lock().unwrap()), (2, 2, bytes * 2, bytes * 2));
    drop(original);
    assert_eq!(stats(&global.lock().unwrap()), (3, 3, bytes * 3, bytes * 3));
}
