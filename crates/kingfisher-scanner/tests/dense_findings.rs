use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use kingfisher_rules::{BetterleaksExpr, DependsOnRule, Rule, RuleSyntax, RulesDatabase};
use kingfisher_scanner::{Blob, Scanner, ScannerConfig};

fn scanner(rules: Vec<RuleSyntax>, base64: bool) -> Scanner {
    Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(rules.into_iter().map(Rule::new).collect()).unwrap()),
        ScannerConfig { enable_base64_decoding: base64, ..Default::default() },
    )
}

fn line_filter_rule() -> RuleSyntax {
    let mut rule = RuleSyntax::new("acme.dense-line", "Dense line", r"(token_[a-z0-9]{8})");
    rule.betterleaks_filter = Some(BetterleaksExpr::Call {
        callee: Box::new(BetterleaksExpr::Identifier { value: "matchesAny".into() }),
        arguments: vec![
            BetterleaksExpr::Member {
                node: Box::new(BetterleaksExpr::Identifier { value: "finding".into() }),
                property: Box::new(BetterleaksExpr::String { value: "line".into() }),
                optional: false,
                method: false,
            },
            BetterleaksExpr::Array {
                nodes: vec![BetterleaksExpr::String { value: "^SKIP".into() }],
            },
        ],
    });
    rule
}

#[test]
fn dense_line_filters_preserve_raw_and_decoded_values_and_offsets() {
    let scanner = scanner(vec![line_filter_rule()], true);
    for prefix in [b"prefix ".as_slice(), b"prefix \xff "] {
        let mut input = prefix.to_vec();
        let expected: Vec<_> = (0..2048).map(|i| format!("token_{i:08x}")).collect();
        for secret in &expected {
            input.extend_from_slice(secret.as_bytes());
            input.push(b' ');
        }
        input.extend_from_slice(b"\nSKIP token_deadbeef\n");
        let mut findings = scanner.scan_bytes(&input).unwrap();
        findings.sort_by_key(|finding| finding.location.start_offset);
        assert_eq!(findings.len(), expected.len());
        for (i, (finding, secret)) in findings.iter().zip(&expected).enumerate() {
            assert_eq!(&finding.secret, secret);
            let start = prefix.len() + i * (secret.len() + 1);
            assert_eq!(finding.location.start_offset, start);
            assert_eq!(finding.location.end_offset, start + secret.len());
            assert_eq!(finding.line(), 1);
            assert_eq!(finding.column(), start);
        }
        // The scanner only decodes ASCII Base64 payloads.
        if prefix.is_ascii() {
            let encoded = STANDARD.encode(&input);
            let decoded = scanner.scan_bytes(encoded.as_bytes()).unwrap();
            assert_eq!(decoded.len(), expected.len());
            for (finding, secret) in decoded.iter().zip(&expected) {
                assert_eq!(&finding.secret, secret);
                assert!(finding.is_base64_encoded);
                assert_eq!(finding.location.start_offset, 0);
                assert_eq!(finding.location.end_offset, encoded.len());
            }
        }
    }
}

#[test]
fn reverse_component_cascade_removes_only_unsupported_findings() {
    let mut rules = Vec::new();
    for (id, dependency, prefix) in [("acme.a", "acme.b", "A"), ("acme.b", "acme.a", "B")] {
        let mut rule = RuleSyntax::new(id, "Chain", format!(r"({prefix}_[a-z0-9]{{8}})"));
        rule.depends_on_rule = vec![Some(DependsOnRule {
            rule_id: dependency.into(),
            variable: "SUPPORT".into(),
            within: Some("-2L".into()),
            optional: false,
            verify_candidates: false,
        })];
        rules.push(rule);
    }
    let scanner = scanner(rules, false);
    let mut input = String::new();
    for i in 0..4000 {
        input.push_str(&format!("{}_{i:08x}\n", if i % 2 == 0 { "A" } else { "B" }));
    }
    // A separate live cycle is self-supporting on the same line.
    input.push_str("\nA_abcd1234 B_efgh5678\n");
    let blob = Blob::from_bytes(input.into_bytes());
    let assert_survivors = |findings: Vec<kingfisher_scanner::Finding>| {
        let mut secrets: Vec<_> = findings.iter().map(|finding| finding.secret.as_str()).collect();
        secrets.sort_unstable();
        assert_eq!(secrets, ["A_abcd1234", "B_efgh5678"]);
    };
    assert_survivors(scanner.scan_blob(&blob).unwrap());
    #[cfg(feature = "context")]
    assert_survivors(
        scanner
            .scan_blob_at_path_with_options(
                &blob,
                "chain.txt",
                &kingfisher_scanner::context::DetectionOptions {
                    cli_match_semantics: true,
                    inline_ignores: false,
                    markup_context: false,
                    ..Default::default()
                },
            )
            .unwrap(),
    );
}
