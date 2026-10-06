#![cfg(feature = "context")]
use kingfisher_scanner::{
    Blob, Rule, RuleSyntax, RulesDatabase, ScanControl, Scanner, ScannerConfig,
    context::DetectionOptions,
};
use std::sync::Arc;

fn scanner(pattern: &str) -> Scanner {
    let db = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "acme.context",
        "Context",
        pattern,
    ))])
    .unwrap();
    Scanner::with_config(Arc::new(db), ScannerConfig { redact_secrets: true, ..Default::default() })
}

#[test]
fn inline_and_markup_filters_run_before_redaction() {
    let scanner = scanner(r"(demo_[a-z0-9]{16})");
    let options = DetectionOptions::default();
    let control = ScanControl::default();
    let ignored = Blob::from_bytes(b"demo_abcd1234efgh5678 # kingfisher:ignore".to_vec());
    assert_eq!(scanner.scan_blob(&ignored).unwrap().len(), 1);
    assert!(
        scanner
            .scan_blob_at_path_with_options_and_control(&ignored, "config.env", &options, &control)
            .unwrap()
            .is_empty()
    );
    let comment = Blob::from_bytes(b"<!-- demo_abcd1234efgh5678 -->".to_vec());
    assert!(
        scanner
            .scan_blob_at_path_with_options_and_control(&comment, "config.html", &options, &control)
            .unwrap()
            .is_empty()
    );
    let attribute = Blob::from_bytes(b"<input password=\"demo_abcd1234efgh5678\">".to_vec());
    let findings = scanner
        .scan_blob_at_path_with_options_and_control(&attribute, "config.html", &options, &control)
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret, "[REDACTED]");
}

#[test]
fn dense_markup_keeps_confirmed_values_and_rejects_comment_only_values() {
    let scanner = scanner(r"(demo_[a-z0-9]{16})");
    let mut bytes = Vec::new();
    // Repeated occurrences of one value share confirmation, including an
    // occurrence in a comment when the same value has valid structural context.
    for _ in 0..1000 {
        bytes.extend_from_slice(b"<!-- demo_abcd1234efgh5678 demo_1234abcd5678efgh -->\n");
        bytes.extend_from_slice(b"<input value=\"demo_abcd1234efgh5678\">\n");
    }
    let blob = Blob::from_bytes(bytes);
    let findings = scanner
        .scan_blob_at_path_with_options_and_control(
            &blob,
            "dense.html",
            &DetectionOptions { inline_ignores: false, ..Default::default() },
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!(findings.len(), 2000);
    assert!(findings.iter().all(|finding| finding.rule_id == "acme.context"));
    assert!(findings.iter().all(|finding| finding.secret == "[REDACTED]"));
}

#[test]
fn self_identifying_and_base64_candidates_bypass_markup() {
    let scanner = scanner(r"(ghp_[a-z0-9]{16})");
    let blob = Blob::from_bytes(b"<!-- ghp_abcd1234efgh5678 -->".to_vec());
    assert_eq!(
        scanner
            .scan_blob_at_path_with_options_and_control(
                &blob,
                "config.html",
                &DetectionOptions::default(),
                &ScanControl::default()
            )
            .unwrap()
            .len(),
        1
    );
    let scanner = self::scanner(r"(demo_[a-z0-9]{16})");
    let blob = Blob::from_bytes(b"<!-- dG9rZW49ZGVtb19hYmNkMTIzNGVmZ2g1Njc4 -->".to_vec());
    let findings = scanner
        .scan_blob_at_path_with_options_and_control(
            &blob,
            "config.html",
            &DetectionOptions::default(),
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
}

#[test]
fn ignored_required_helper_cannot_satisfy_components() {
    use kingfisher_rules::rule::DependsOnRule;
    let mut primary = RuleSyntax::new("acme.primary", "Primary", r"(demo_[a-z0-9]{16})");
    primary.depends_on_rule = vec![Some(DependsOnRule {
        rule_id: "acme.helper".into(),
        variable: "ACCOUNT".into(),
        optional: false,
        within: Some("2L".into()),
        verify_candidates: false,
    })];
    let mut helper = RuleSyntax::new("acme.helper", "Helper", r"(account_[a-z0-9]{4})");
    helper.visible = false;
    let scanner = Scanner::new(Arc::new(
        RulesDatabase::from_rules(vec![Rule::new(primary), Rule::new(helper)]).unwrap(),
    ));
    let blob =
        Blob::from_bytes(b"account_abcd # kingfisher:ignore\ndemo_abcd1234efgh5678".to_vec());
    assert_eq!(scanner.scan_blob(&blob).unwrap().len(), 2);
    let findings = scanner
        .scan_blob_at_path_with_options_and_control(
            &blob,
            "config.env",
            &DetectionOptions::default(),
            &ScanControl::default(),
        )
        .unwrap();
    assert!(findings.is_empty());
}

#[test]
fn markup_preserves_non_utf8_secrets() {
    let scanner = scanner(r"(demo_[^\x22]{4})");
    for (path, bytes) in [
        ("config.html", b"<input password=\"demo_abc\xff\">".as_slice()),
        ("config.css", b"body { password: \"demo_abc\xff\"; }".as_slice()),
    ] {
        let blob = Blob::from_bytes(bytes.to_vec());
        let original = scanner.scan_blob(&blob).unwrap();
        assert_eq!(original.len(), 1);
        let findings = scanner
            .scan_blob_at_path_with_options_and_control(
                &blob,
                path,
                &DetectionOptions::default(),
                &ScanControl::default(),
            )
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.start_offset, original[0].location.start_offset);
        assert_eq!(findings[0].location.end_offset, original[0].location.end_offset);
        assert_eq!(findings[0].secret, "[REDACTED]");
    }
}

#[test]
fn markup_verifies_selected_secret_group() {
    let mut rule =
        RuleSyntax::new("acme.context", "Context", r"(password)\s*=\s*[\x22]?(demo_[a-z0-9]{16})");
    rule.betterleaks_secret_group = Some(2);
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(rule)]).unwrap()));
    let blob = Blob::from_bytes(b"<input password=\"demo_abcd1234efgh5678\">".to_vec());
    let findings = scanner
        .scan_blob_at_path_with_options_and_control(
            &blob,
            "config.html",
            &DetectionOptions::default(),
            &ScanControl::default(),
        )
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].secret, "demo_abcd1234efgh5678");
}

#[test]
fn interrupted_context_scans_return_errors_without_committing_dedup() {
    use kingfisher_scanner::{CancellationToken, ScanAborted};
    let scanner = Scanner::with_config(
        Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
                "acme.context",
                "Context",
                r"(demo_[a-z0-9]{16})",
            ))])
            .unwrap(),
        ),
        ScannerConfig { enable_dedup: true, ..Default::default() },
    );
    let blob = Blob::from_bytes(b"<input password=\"demo_abcd1234efgh5678\">".to_vec());
    let options = DetectionOptions::default();
    let token = CancellationToken::default();
    token.cancel();
    for (control, expected) in [
        (ScanControl::default().with_cancellation(token), ScanAborted::Cancelled),
        (ScanControl::default().with_deadline(std::time::Instant::now()), ScanAborted::TimedOut),
    ] {
        let error = scanner
            .scan_blob_at_path_with_options_and_control(&blob, "config.html", &options, &control)
            .unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&expected));
    }
    assert_eq!(
        scanner
            .scan_blob_at_path_with_options_and_control(
                &blob,
                "config.html",
                &options,
                &ScanControl::default()
            )
            .unwrap()
            .len(),
        1
    );
    assert!(
        scanner
            .scan_blob_at_path_with_options_and_control(
                &blob,
                "config.html",
                &options,
                &ScanControl::default()
            )
            .unwrap()
            .is_empty()
    );
}

#[test]
fn cli_policy_uses_full_match_component_anchors_without_changing_reported_locations() {
    use kingfisher_rules::DependsOnRule;
    let mut primary =
        RuleSyntax::new("acme.primary", "Primary", r"PREFIX_x{48}(PRIMARY_[a-z0-9]{8})");
    primary.depends_on_rule = vec![Some(DependsOnRule {
        rule_id: "acme.helper".into(),
        variable: "HELP".into(),
        within: Some("16C".into()),
        optional: false,
        verify_candidates: false,
    })];
    let helper = RuleSyntax::new("acme.helper", "Helper", r"(HELP_[a-z0-9]{8})");
    let scanner = Scanner::new(Arc::new(
        RulesDatabase::from_rules(vec![Rule::new(primary), Rule::new(helper)]).unwrap(),
    ));
    let input = format!("HELP_efgh5678 PREFIX_{}PRIMARY_abcd1234", "x".repeat(48));
    let blob = Blob::from_bytes(input.as_bytes().to_vec());
    assert!(scanner.scan_blob(&blob).unwrap().iter().all(|f| f.rule_id != "acme.primary"));
    let findings = scanner
        .scan_blob_at_path_with_options(&blob, "config.env", &DetectionOptions::default())
        .unwrap();
    let finding = findings.iter().find(|f| f.rule_id == "acme.primary").unwrap();
    assert_eq!(finding.secret, "PRIMARY_abcd1234");
    assert_eq!(&input[finding.location.start_offset..finding.location.end_offset], finding.secret);
    let legacy = DetectionOptions { cli_match_semantics: false, ..Default::default() };
    assert!(
        scanner
            .scan_blob_at_path_with_options(&blob, "config.env", &legacy)
            .unwrap()
            .iter()
            .all(|f| f.rule_id != "acme.primary")
    );
}

#[test]
fn nested_base64_depth_and_input_caps_preserve_legacy_defaults() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let scanner = scanner(r"(demo_[a-z0-9]{16})");
    let once = STANDARD.encode(b"token=demo_abcd1234efgh5678");
    let twice = STANDARD.encode(&once);
    let thrice = STANDARD.encode(&twice);
    let blob = Blob::from_bytes(twice.as_bytes().to_vec());
    assert!(scanner.scan_blob(&blob).unwrap().is_empty());
    let options = DetectionOptions::default();
    let findings = scanner.scan_blob_at_path_with_options(&blob, "config.env", &options).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    assert_eq!(
        (findings[0].location.start_offset, findings[0].location.end_offset),
        (0, twice.len())
    );
    for capped in [
        DetectionOptions { base64_max_depth: 1, ..Default::default() },
        DetectionOptions { base64_max_depth: 0, ..Default::default() },
        DetectionOptions { base64_max_input_bytes: Some(twice.len() - 1), ..Default::default() },
    ] {
        assert!(
            scanner
                .scan_blob_at_path_with_options(&blob, "config.env", &capped)
                .unwrap()
                .is_empty()
        );
    }
    let exactly =
        DetectionOptions { base64_max_input_bytes: Some(twice.len()), ..Default::default() };
    assert_eq!(
        scanner.scan_blob_at_path_with_options(&blob, "config.env", &exactly).unwrap().len(),
        1
    );
    let blob = Blob::from_bytes(thrice.as_bytes().to_vec());
    assert!(
        scanner.scan_blob_at_path_with_options(&blob, "config.env", &options).unwrap().is_empty()
    );
    let deeper = DetectionOptions {
        base64_max_depth: 3,
        base64_max_input_bytes: None,
        ..Default::default()
    };
    assert_eq!(
        scanner.scan_blob_at_path_with_options(&blob, "config.env", &deeper).unwrap().len(),
        1
    );
    let raw = Blob::from_bytes(b"token=demo_abcd1234efgh5678".to_vec());
    let capped = DetectionOptions { base64_max_input_bytes: Some(0), ..Default::default() };
    assert_eq!(
        scanner.scan_blob_at_path_with_options(&raw, "config.env", &capped).unwrap().len(),
        1
    );
}
