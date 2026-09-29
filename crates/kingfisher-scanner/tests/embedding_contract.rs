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
