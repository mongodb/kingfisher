use super::*;
use crate::rules::rule::RuleSyntax;

fn capture(
    name: Option<&'static str>,
    number: i32,
    start: usize,
    end: usize,
    value: &str,
) -> SerializableCapture {
    SerializableCapture { name, match_number: number, start, end, value: Arc::from(value) }
}

fn finding(captures: Vec<SerializableCapture>) -> Match {
    Match {
        location: Location::with_source_span(OffsetSpan::from_range(0..8), None),
        groups: SerializableCaptures { captures: captures.into_iter().collect() },
        blob_id: BlobId::new(b"independent finding fixture"),
        finding_fingerprint: 42,
        rule: Arc::new(Rule::new(RuleSyntax::new("acme.finding-id", "Finding ID", "(fixture)"))),
        validation_response_body: None,
        validation_response_status: 100,
        validation_success: false,
        validation_outcome: ValidationOutcome::NotAttempted,
        calculated_entropy: 0.0,
        visible: true,
        is_base64: false,
        dependent_captures: Default::default(),
        ambiguous_dependencies: Default::default(),
        dependency_candidates: Default::default(),
    }
}

fn run_child(test: &str, mode: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("KF_TEST_FINDING_ID_CHILD", mode)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "the child must execute exactly the named test: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn finding_id_preserves_independently_calculated_golden_values() {
    const NAME: &str = "matcher::conversion::removal_finding_id_contract_tests::finding_id_preserves_independently_calculated_golden_values";
    if std::env::var("KF_TEST_FINDING_ID_CHILD").as_deref() != Ok("plain") {
        run_child(NAME, "plain");
        return;
    }
    assert!(!crate::util::redaction_enabled());
    let large = "Q7mZ2pL9xR4vN8kT".repeat(64);
    let cases = [
        (vec![], "192667126840766663"),
        (vec![capture(None, 1, 2, 6, "a\"b\n")], "4774428090246600280"),
        (
            vec![
                capture(Some("TOKEN"), 2, 12, 17, "café"),
                capture(Some("FIELD"), 1, 0, 12, "路径\\zero\0"),
            ],
            "4058566868579930002",
        ),
        (vec![capture(Some("TOKEN"), 1, 0, 1024, &large)], "8692399759728029280"),
        // The C oracle returns 11321698363312483542 before the sign bit is cleared.
        (vec![capture(Some("TOKEN"), 1, 0, 1, "1")], "2098326326457707734"),
    ];
    for (captures, expected) in cases {
        let finding = finding(captures);
        assert_eq!(finding.rule.finding_sha1_fingerprint(), "def6a0a1aeae03f2");
        assert_eq!(finding.finding_id(), expected);
        assert_eq!(finding.finding_id(), expected, "repeated ID computation must be stable");
        assert!(finding.finding_id().parse::<i64>().unwrap() >= 0);
    }
}

#[test]
fn finding_id_keeps_capture_serde_redaction_bytes_without_mutating_parent_state() {
    const NAME: &str = "matcher::conversion::removal_finding_id_contract_tests::finding_id_keeps_capture_serde_redaction_bytes_without_mutating_parent_state";
    if std::env::var("KF_TEST_FINDING_ID_CHILD").as_deref() != Ok("redacted") {
        run_child(NAME, "redacted");
        return;
    }
    let finding = finding(vec![capture(Some("TOKEN"), 1, 0, 1, "1")]);
    assert!(!crate::util::redaction_enabled());
    let original = finding.finding_id();
    assert_eq!(original, "2098326326457707734");
    // This test is the only selected test in this child. The parent process's global
    // redaction state is never changed, including when this assertion fails.
    crate::util::set_redaction_enabled(true);
    let displayed = crate::util::display_value("1").into_owned();
    assert!(displayed.starts_with("[REDACTED:"));
    let quoted_displayed = serde_json::to_string(&displayed).unwrap();
    let expected_json = format!(
        "{{\"captures\":[{{\"name\":\"TOKEN\",\"match_number\":1,\"start\":0,\"end\":1,\"value\":{quoted_displayed}}}]}}"
    );
    assert_eq!(serde_json::to_string(&finding.groups).unwrap(), expected_json);
    // A batch oracle expresses the persisted byte protocol independently of the
    // replacement's buffering/writer strategy. The salt makes a fixed redacted ID
    // inappropriate; exact plaintext goldens above cover the hashing algorithm.
    let mut protocol = b"def6a0a1aeae03f2\0".to_vec();
    protocol.extend_from_slice(expected_json.as_bytes());
    let expected = (xxh3_64(&protocol) & 0x7fff_ffff_ffff_ffff).to_string();
    let redacted = finding.finding_id();
    assert_eq!(redacted, expected);
    assert_ne!(redacted, original);
    assert_eq!(finding.groups.captures[0].raw_value(), "1");
    assert_eq!(finding.finding_id(), redacted);
}

#[test]
fn finding_id_matches_batch_protocol_at_streaming_boundaries_and_capture_layouts() {
    const NAME: &str = concat!(
        "matcher::conversion::removal_finding_id_contract_tests::",
        "finding_id_matches_batch_protocol_at_streaming_boundaries_and_capture_layouts"
    );
    if std::env::var("KF_TEST_FINDING_ID_CHILD").as_deref() != Ok("streaming-boundaries") {
        run_child(NAME, "streaming-boundaries");
        return;
    }
    assert!(!crate::util::redaction_enabled());
    let protocol = |value: &Match| {
        let mut bytes = value.rule.finding_sha1_fingerprint().as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&serde_json::to_vec(&value.groups).unwrap());
        bytes
    };
    let check = |value: Match, length: Option<usize>| {
        let bytes = protocol(&value);
        if let Some(length) = length {
            assert_eq!(bytes.len(), length);
        }
        let expected = (xxh3_64(&bytes) & 0x7fff_ffff_ffff_ffff).to_string();
        assert_eq!(value.finding_id(), expected);
        assert_eq!(value.finding_id(), expected);
    };
    // Keep the serialized metadata fixed so the complete hash input, rather than
    // just the capture text, lands on short/midsize and streaming block edges.
    let empty = finding(vec![capture(Some("TOKEN"), 1, 0, 0, "")]);
    let overhead = protocol(&empty).len();
    assert!(overhead <= 127);
    for length in
        [127, 128, 129, 239, 240, 241, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4096]
    {
        let text = "x".repeat(length - overhead);
        check(finding(vec![capture(Some("TOKEN"), 1, 0, 0, &text)]), Some(length));
    }
    check(finding(Vec::new()), None);
    check(
        finding(vec![
            capture(None, 0, 0, 0, ""),
            capture(Some("TOKEN"), -1, 3, 8, "quote\"\\\n\r\t\0"),
            capture(Some("路径\0\""), i32::MAX, 1, usize::MAX, "café\u{2028}🙂"),
            capture(Some("TOKEN"), 2, 0, 8, "duplicate"),
            capture(Some("TOKEN"), 2, 0, 8, "duplicate"),
        ]),
        None,
    );
}
