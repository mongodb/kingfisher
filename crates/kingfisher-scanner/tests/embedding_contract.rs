use std::sync::Arc;

use kingfisher_core::Blob;
use kingfisher_rules::{BetterleaksExpr, Rule, RuleSyntax, RulesDatabase};
use kingfisher_scanner::{Scanner, ScannerConfig, ScannerPool, SerializableCaptures};

fn database() -> Arc<RulesDatabase> {
    Arc::new(
        RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
            "acme.token",
            "Acme token",
            r"(?P<token>secret_[a-z0-9]{8})",
        ))])
        .unwrap(),
    )
}

#[test]
fn public_record_match_keeps_the_vector_based_embedding_signature() {
    use kingfisher_core::OffsetSpan;
    use kingfisher_scanner::primitives::record_match;
    use rustc_hash::FxHashMap;

    let mut spans: FxHashMap<usize, Vec<OffsetSpan>> = FxHashMap::default();
    assert!(record_match(&mut spans, 7, OffsetSpan { start: 2, end: 8 }));
    assert!(!record_match(&mut spans, 7, OffsetSpan { start: 3, end: 6 }));
    assert!(record_match(&mut spans, 7, OffsetSpan { start: 9, end: 12 }));
    assert_eq!(spans[&7].len(), 2);
}

#[test]
fn shared_scanner_is_repeatable_and_thread_safe_by_default() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Scanner>();
    send_sync::<RulesDatabase>();
    send_sync::<ScannerPool>();
    let scanner = Arc::new(Scanner::new(database()));
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let scanner = Arc::clone(&scanner);
            scope.spawn(move || {
                for _ in 0..2 {
                    assert_eq!(scanner.scan_bytes(b"secret_abcd1234").unwrap().len(), 1);
                }
            });
        }
    });
}

#[test]
fn dedup_is_opt_in_path_aware_and_resettable() {
    let scanner = Scanner::with_config(
        database(),
        ScannerConfig { enable_dedup: true, ..Default::default() },
    );
    let blob = Blob::from_bytes(b"secret_abcd1234".to_vec());
    assert_eq!(scanner.scan_blob_at_path(&blob, "first.env").unwrap().len(), 1);
    assert!(scanner.scan_blob_at_path(&blob, "first.env").unwrap().is_empty());
    assert_eq!(scanner.scan_blob_at_path(&blob, "second.env").unwrap().len(), 1);
    scanner.reset_dedup();
    assert_eq!(scanner.scan_blob_at_path(&blob, "first.env").unwrap().len(), 1);
}

#[test]
fn redaction_covers_captures_and_preserves_fingerprints() {
    let plain = Scanner::new(database());
    let redacted = Scanner::with_config(
        database(),
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );
    for input in [b"secret_abcd1234".as_slice(), b"c2VjcmV0X2FiY2QxMjM0c2VjcmV0X2FiY2QxMjM0"] {
        let original = plain.scan_bytes(input).unwrap();
        let hidden = redacted.scan_bytes(input).unwrap();
        assert!(!original.is_empty());
        assert_eq!(original.len(), hidden.len());
        for (original, hidden) in original.iter().zip(&hidden) {
            assert_eq!(original.fingerprint, hidden.fingerprint);
            assert_eq!(hidden.secret, "[REDACTED]");
            assert!(!hidden.captures.is_empty());
            assert!(hidden.captures.values().all(|v| v == "[REDACTED]"));
        }
        assert!(!serde_json::to_string(&hidden).unwrap().contains("secret_abcd1234"));
    }
}

#[test]
fn filter_errors_are_not_empty_successes_for_bytes_or_base64() {
    let mut rule = RuleSyntax::new("acme.bad-filter", "Bad filter", r"(secret_[a-z0-9]{8})");
    rule.betterleaks_filter = Some(BetterleaksExpr::Unary {
        operator: "unsupported".into(),
        node: Box::new(BetterleaksExpr::Bool { value: true }),
    });
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(rule)]).unwrap()));
    assert!(scanner.scan_bytes(b"secret_abcd1234").is_err());
    assert!(scanner.scan_bytes(b"c2VjcmV0X2FiY2QxMjM0c2VjcmV0X2FiY2QxMjM0").is_err());
}

#[test]
fn pool_reentrancy_returns_an_error_and_recovers() {
    let database = database();
    let pool = ScannerPool::new(Arc::new(database.vectorscan_db().clone()));
    pool.try_with(|_| assert!(pool.try_with(|_| ()).is_err())).unwrap();
    assert!(pool.try_with(|_| ()).is_ok());
}

#[test]
fn file_and_buffer_scans_agree_for_utf16_and_report_io_errors() {
    let scanner = Scanner::new(database());
    let mut input = vec![0xff, 0xfe];
    input.extend("secret_abcd1234".encode_utf16().flat_map(u16::to_le_bytes));
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.txt");
    std::fs::write(&path, &input).unwrap();
    let bytes = scanner.scan_bytes(&input).unwrap();
    let file = scanner.scan_file(&path).unwrap();
    assert_eq!(bytes.len(), 1);
    assert_eq!(file.len(), 1);
    assert_eq!(file[0].blob_id, bytes[0].blob_id);
    assert_eq!(file[0].fingerprint, bytes[0].fingerprint);
    assert_eq!(file[0].location.start_offset, 0);
    assert_eq!(file[0].location.end_offset, "secret_abcd1234".len());
    assert!(scanner.scan_file(temp.path().join("missing")).is_err());
}

#[test]
fn capture_values_outlive_the_regex_and_input_without_static_storage() {
    let captures = {
        let regex = regex::bytes::Regex::new(r"(?P<token>secret_[a-z0-9]{8})").unwrap();
        let bytes = b"secret_abcd1234".to_vec();
        SerializableCaptures::from_captures(&regex.captures(&bytes).unwrap(), &bytes, &regex)
    };
    assert_eq!(captures.captures[0].name.as_deref(), Some("token"));
    assert_eq!(captures.captures[0].raw_value(), "secret_abcd1234");
}

#[test]
fn redaction_handles_multibyte_secrets() {
    let rule = Rule::new(RuleSyntax::new("acme.unicode", "Unicode token", "(ééééé)"));
    let database = Arc::new(RulesDatabase::from_rules(vec![rule]).unwrap());
    let scanner = Scanner::with_config(
        database,
        ScannerConfig { redact_secrets: true, ..Default::default() },
    );
    let findings = scanner.scan_bytes("ééééé".as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret, "[REDACTED]");
}

#[test]
fn indexed_confirmation_preserves_alternatives_multiline_and_locations() {
    let pattern = r"(?m)(?P<token>secret_[a-z0-9]{8})$|(?P<other>alternate_[a-z0-9]{8})";
    let db = Arc::new(
        RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
            "acme.alternatives",
            "Alternatives",
            pattern,
        ))])
        .unwrap(),
    );
    let input = b"prefix\nsecret_abcd1234\nalternate_1234abcd\nordinary";
    // Endpoint confirmation cannot return an earlier line just because (?m) is enabled.
    let index =
        kingfisher_scanner::primitives::CandidateMatchIndex::new(&db.anchored_regexes()[0], input);
    assert!(
        index
            .captures(&db.anchored_regexes()[0], db.endpoint_regex(0), input, 0)
            .all(|captures| captures.get(0).unwrap().end() != input.len())
    );
    let findings = Scanner::with_config(
        db,
        ScannerConfig { enable_base64_decoding: false, ..Default::default() },
    )
    .scan_bytes(input)
    .unwrap();
    assert_eq!(findings.len(), 2);
    for (secret, offset, line) in [("secret_abcd1234", 7, 2), ("alternate_1234abcd", 23, 3)] {
        let finding = findings.iter().find(|f| f.secret == secret).unwrap();
        assert_eq!(finding.location.start_offset, offset);
        assert_eq!(finding.line(), line);
    }
}

#[test]
fn repeated_hex_candidates_are_confirmed_once_and_still_filtered() {
    let mut rules = kingfisher_rules::get_builtin_rules(None).unwrap();
    let original = rules.rules.remove("betterleaks.alibaba-sts-access-key-secret").unwrap();
    let input = "key: 0123456789abcdef13579bdf02468ace\n".repeat(2500);
    let db = Arc::new(RulesDatabase::from_rules(vec![Rule::new(original.clone())]).unwrap());
    // This deterministic work-count assertion guards against the quadratic capture loop.
    assert_eq!(db.anchored_regexes()[0].captures_iter(input.as_bytes()).count(), 2500);
    let index = kingfisher_scanner::primitives::CandidateMatchIndex::new(
        &db.anchored_regexes()[0],
        input.as_bytes(),
    );
    assert_eq!(
        index
            .captures(&db.anchored_regexes()[0], db.endpoint_regex(0), input.as_bytes(), 0)
            .count(),
        1
    );
    assert!(Scanner::new(db).scan_bytes(input.as_bytes()).unwrap().is_empty());
    let mut bare = original;
    bare.betterleaks_filter = None;
    bare.depends_on_rule.clear();
    let scanner = Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(vec![Rule::new(bare)]).unwrap()),
        ScannerConfig { enable_base64_decoding: false, ..Default::default() },
    );
    let findings = scanner.scan_bytes(input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 2500);
    assert!(findings.iter().all(|f| f.secret == "0123456789abcdef13579bdf02468ace"));
}

#[test]
fn interrupted_scans_do_not_commit_dedup_or_poison_the_pool() {
    use kingfisher_scanner::{CancellationToken, ScanAborted, ScanControl};
    use std::time::{Duration, Instant};
    let scanner = Scanner::with_config(
        database(),
        ScannerConfig { enable_dedup: true, ..Default::default() },
    );
    let token = CancellationToken::default();
    let other_thread = token.clone();
    std::thread::spawn(move || other_thread.cancel()).join().unwrap();
    assert!(token.is_cancelled());
    let controls = [
        (ScanControl::default().with_cancellation(token), ScanAborted::Cancelled),
        (
            ScanControl::default().with_deadline(Instant::now() - Duration::from_secs(1)),
            ScanAborted::TimedOut,
        ),
    ];
    for (control, expected) in controls {
        let error = scanner.scan_bytes_with_control(b"secret_abcd1234", &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&expected));
        // Even empty inputs must respect a cancelled call.
        assert!(scanner.scan_bytes_with_control(b"", &control).is_err());
        assert!(
            scanner.scan_file_with_control("missing", &control).unwrap_err().is::<ScanAborted>()
        );
    }
    assert_eq!(scanner.scan_bytes(b"secret_abcd1234").unwrap().len(), 1);
    assert!(scanner.scan_bytes(b"secret_abcd1234").unwrap().is_empty());
    scanner.reset_dedup();
    assert_eq!(
        scanner.scan_bytes_with_control(b"secret_abcd1234", &ScanControl::default()).unwrap().len(),
        1
    );
    assert!(ScanControl::default().with_timeout(Duration::MAX).is_err());
}

#[test]
fn indexed_confirmation_does_not_merge_lazy_matches_or_add_overlapping_alternatives() {
    for (pattern, input, mut expected) in [
        (
            r"(?s)(BEGIN.*?END)",
            "BEGIN alpha END gap BEGIN beta END",
            vec!["BEGIN alpha END", "BEGIN beta END"],
        ),
        (r"(ab)|(bc)", "abc", vec!["ab"]),
        (r"(z)|(ar)|(bar$)", "zbar!", vec!["bar"]),
    ] {
        let db = Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
                "acme.selection",
                "Original match selection",
                pattern,
            ))])
            .unwrap(),
        );
        let scanner = Scanner::with_config(
            db,
            ScannerConfig { enable_base64_decoding: false, ..Default::default() },
        );
        let findings = scanner.scan_bytes(input.as_bytes()).unwrap();
        let mut actual: Vec<_> = findings.iter().map(|f| f.secret.as_str()).collect();
        actual.sort();
        expected.sort();
        assert_eq!(actual, expected);
    }
}
