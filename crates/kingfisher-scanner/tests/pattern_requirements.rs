use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use kingfisher_rules::{Rule, RuleSyntax, RulesDatabase};
use kingfisher_scanner::Scanner;
use serde_json::{Value, json};

fn assert_requirement(pattern: &str, requirements: Value, input: &str, expected: &[&str]) {
    let mut syntax = RuleSyntax::new("acme.requirements", "Pattern requirements", pattern);
    syntax.pattern_requirements = Some(serde_json::from_value(requirements).unwrap());
    let scanner =
        Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap()));
    // Exercise the raw and decoded paths with the same candidates. Padding ensures
    // even short fixtures meet the standalone Base64 decoder's minimum length.
    let padded = format!("prefix padding: {input}\nend padding");
    for (bytes, encoded) in [(padded.clone(), false), (STANDARD.encode(&padded), true)] {
        let findings = scanner.scan_bytes(bytes.as_bytes()).unwrap();
        assert_eq!(findings.iter().map(|f| f.secret.as_str()).collect::<Vec<_>>(), expected);
        assert!(findings.iter().all(|f| f.is_base64_encoded == encoded));
    }
}

#[test]
fn character_minimums_and_custom_special_characters_filter_each_candidate() {
    let pattern = r"token=([A-Za-z0-9!$]{6})";
    for (requirements, input, expected) in [
        (json!({"min_digits": 2}), "token=Abcde1 token=Abcd12", "Abcd12"),
        (json!({"min_uppercase": 2}), "token=Abcde1 token=ABcde1", "ABcde1"),
        (json!({"min_lowercase": 2}), "token=ABCDEa token=ABCDea", "ABCDea"),
        (json!({"min_special_chars": 2}), "token=Abcd1! token=Abc1!$", "Abc1!$"),
        (
            json!({"min_special_chars": 1, "special_chars": "$"}),
            "token=Abcd1! token=Abcd1$",
            "Abcd1$",
        ),
        (
            json!({"ignore_if_contains": ["", "  ", " dEmO "]}),
            "token=demo12 token=Abcd12",
            "Abcd12",
        ),
    ] {
        assert_requirement(pattern, requirements, input, &[expected]);
    }
}

#[test]
fn requirements_select_the_same_bytes_as_the_cli() {
    // Single unnamed capture: the uppercase prefix cannot satisfy the secret's requirement.
    assert_requirement(r"TOKEN=([a-z0-9]{6})", json!({"min_uppercase": 5}), "TOKEN=abc123", &[]);
    // No capture, named capture, and multiple captures: validate the full match.
    for (pattern, expected) in [
        (r"TOKEN=[a-z0-9]{6}", "TOKEN=abc123"),
        (r"TOKEN=(?P<token>[a-z0-9]{6})", "abc123"),
        (r"TOKEN=([a-z]{3})([0-9]{3})", "abc"),
    ] {
        assert_requirement(pattern, json!({"min_uppercase": 5}), "TOKEN=abc123", &[expected]);
        assert_requirement(pattern, json!({"ignore_if_contains": ["token="]}), "TOKEN=abc123", &[]);
    }
}

#[test]
fn checksums_receive_named_captures_aliases_and_match_context() {
    let pattern = r"token=(?P<body>[a-z]{3})(?P<checksum>[0-9])?";
    let mut requirements = json!({"checksum": {
        "actual": {
            "template": "{{ checksum }}:{{ BODY }}:{{ MATCH }}",
            "requires_capture": "checksum"
        },
        "expected": "{{ body | size }}:{{ body }}:{{ FULL_MATCH }}"
    }});
    assert_requirement(pattern, requirements.clone(), "token=abc3 token=abc4 token=def", &["abc"]);
    requirements["checksum"]["skip_if_missing"] = json!(true);
    assert_requirement(pattern, requirements, "token=abc4 token=def", &["def"]);
}

#[test]
fn mismatched_or_unrenderable_checksums_discard_findings() {
    for actual in ["0", "{{ MATCH | nonexistent_filter }}", "{{ missing }}"] {
        assert_requirement(
            r"card ([0-9][0-9 -]{11,25}[0-9])",
            json!({"checksum": {"actual": {"template": actual}, "expected": "1", "skip_if_missing": true}}),
            "card 4111 1111 1111 1111",
            &[],
        );
    }
}

#[test]
fn luhn_and_iban_filters_work_in_offline_checksum_templates() {
    assert_requirement(
        r"card ([0-9][0-9 -]{11,25}[0-9])",
        json!({"checksum": {"actual": {"template": "{{ MATCH | luhn_valid }}"}, "expected": "true"}}),
        "card 4111 1111 1111 1111\ncard 4111 1111 1111 1112",
        &["4111 1111 1111 1111"],
    );
    assert_requirement(
        r"iban ([A-Z]{2}[0-9]{2}[A-Z0-9]{18})",
        json!({"checksum": {"actual": {"template": "{{ MATCH | iban_valid }}"}, "expected": "true"}}),
        "iban GB82WEST12345698765432\niban GB82WEST12345698765433",
        &["GB82WEST12345698765432"],
    );
}
