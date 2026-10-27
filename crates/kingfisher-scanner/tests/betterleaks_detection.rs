use std::{collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kingfisher_rules::{Confidence, Rule, RuleSyntax, Rules, RulesDatabase};
use kingfisher_scanner::{Blob, Scanner, ScannerConfig};

fn from_toml(config: &str) -> Scanner {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.toml");
    std::fs::write(&path, config).unwrap();
    let rules = Rules::from_toml_file(&path, Confidence::Low).unwrap();
    Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules).unwrap()))
}

#[test]
fn path_only_rules_detect_empty_files_and_obey_path_filters_and_visibility() {
    let scanner = from_toml(
        r#"
[[rules]]
id = "key-file"
description = "Private key file"
path = '\.key$'
tags = ["inventory"]
filter = 'attributes.path startsWith "fixtures/"'
[[rules]]
id = "hidden-file"
path = '\.key$'
skipReport = true
"#,
    );
    for bytes in [b"".as_slice(), b"content", b"\x00\x00"] {
        let findings =
            scanner.scan_blob_at_path(&Blob::from_borrowed(bytes), "private.key").unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "custom.key-file");
        assert!(findings[0].secret.is_empty());
        assert_eq!(findings[0].rule().syntax().tags, ["inventory"]);
        assert!(
            scanner
                .scan_blob_at_path(&Blob::from_borrowed(bytes), "fixtures/private.key")
                .unwrap()
                .is_empty()
        );
        assert!(
            scanner
                .scan_blob_at_path(&Blob::from_borrowed(bytes), "private.txt")
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn path_only_rules_run_once_even_with_decoded_content() {
    let scanner = from_toml("[[rules]]\nid='key-file'\npath='\\.key$'\n");
    let encoded = STANDARD.encode("content with enough padding to trigger base64 scanning");
    let findings =
        scanner.scan_blob_at_path(&Blob::from_borrowed(encoded.as_bytes()), "private.key").unwrap();
    assert_eq!(findings.len(), 1);
    assert!(!findings[0].is_base64_encoded);
    let blob = Blob::from_borrowed(b"content");
    let attributes = BTreeMap::from([
        ("path".into(), "private.key".into()),
        ("fs.first_fragment".into(), "false".into()),
    ]);
    assert!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().is_empty());
}

#[test]
fn specificity_applies_to_contained_values_on_the_same_line_with_equal_rank_ties() {
    for (rank, expected) in [(10, 1), (0, 2), (-1, 2)] {
        let mut specific = RuleSyntax::new("acme.specific", "Specific", r"(svc_Q7m2V9r4)");
        specific.specificity = rank;
        let generic = RuleSyntax::new("acme.generic", "Generic", r"(Q7m2V9r4)");
        let scanner = Scanner::new(Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(specific), Rule::new(generic)]).unwrap(),
        ));
        let findings = scanner.scan_bytes(b"svc_Q7m2V9r4").unwrap();
        assert_eq!(findings.len(), expected, "specificity {rank}");
        if rank > 0 {
            assert_eq!(findings[0].rule_id, "acme.specific");
        }
    }
}

#[test]
fn specificity_does_not_suppress_a_matching_value_on_another_line() {
    let scanner = from_toml(
        r#"
[[rules]]
id='specific'
regex='(svc_Q7m2V9r4)'
specificity=10
[[rules]]
id='generic'
regex='(Q7m2V9r4)'
"#,
    );
    let findings = scanner.scan_bytes(b"svc_Q7m2V9r4\nQ7m2V9r4").unwrap();
    assert_eq!(findings.len(), 2);
    assert!(
        findings.iter().any(|finding| finding.rule_id == "custom.generic" && finding.line() == 2)
    );
}

#[test]
fn orphan_hidden_helpers_do_not_suppress_visible_findings() {
    let scanner = from_toml(
        r#"
[[rules]]
id='hidden'
regex='(svc_Q7m2V9r4)'
specificity=10
skipReport=true
[[rules]]
id='generic'
regex='(Q7m2V9r4)'
"#,
    );
    let findings = scanner.scan_bytes(b"svc_Q7m2V9r4").unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "custom.generic" && finding.rule().visible())
    );
}

#[test]
fn hidden_helper_precedence_applies_only_to_attached_occurrences() {
    let scanner = from_toml(
        r#"
[[rules]]
id='primary'
regex='(svc_Q7m2V9r4)'
components=[{id='helper',within='1L'}]
[[rules]]
id='helper'
regex='(Q7m2V9r4)'
specificity=10
skipReport=true
[[rules]]
id='generic'
regex='(V9r4)'
"#,
    );
    let findings = scanner.scan_bytes(b"svc_Q7m2V9r4\n\nQ7m2V9r4").unwrap();
    assert!(findings.iter().any(|finding| finding.rule_id == "custom.primary"));
    let generic: Vec<_> =
        findings.iter().filter(|finding| finding.rule_id == "custom.generic").collect();
    assert_eq!(generic.len(), 1);
    assert_eq!(generic[0].line(), 3);
}

#[cfg(feature = "validation")]
#[tokio::test]
async fn lower_ranked_visible_components_remain_available_for_validation_without_reporting() {
    let scanner = from_toml(
        r#"
[[rules]]
id='primary'
regex='svc_(Q7m2V9r4)'
specificity=10
components=[{id='helper',within='1L'}]
validate='components["helper"].secret == finding.secret ? {result:"valid"} : {result:"invalid"}'
[[rules]]
id='helper'
regex='(Q7m2V9r4)'
"#,
    );
    let blob = Blob::from_borrowed(b"svc_Q7m2V9r4");
    let output = scanner.scan_blob_with_context(&blob, "config.env").unwrap();
    let primary =
        output.findings.iter().find(|finding| finding.rule_id == "custom.primary").unwrap();
    let helper = output.findings.iter().find(|finding| finding.rule_id == "custom.helper").unwrap();
    assert!(!helper.rule().visible());
    let validator =
        kingfisher_scanner::Validator::builder().build().unwrap().with_scan_context(output.context);
    let validated = validator.validate_finding_with_context(primary, &output.findings).await;
    assert_eq!(validated.outcome, kingfisher_scanner::ValidationOutcome::VerifiedActive);
    assert_eq!(validated.credential.unwrap().components.len(), 1);
}

#[test]
fn explicit_source_attributes_apply_to_prefilters_raw_decoded_and_path_only_findings() {
    let scanner = from_toml(
        r#"
prefilter = 'attributes["git.author_name"] == "fixture"'
[[rules]]
id='token'
regex='(svc_Q7m2V9r4)'
filter='attributes["git.message"] startsWith "sample"'
[[rules]]
id='key-file'
path='\.key$'
filter='attributes["git.message"] startsWith "sample"'
"#,
    );
    for content in [
        "svc_Q7m2V9r4".to_owned(),
        STANDARD.encode("svc_Q7m2V9r4 with extra padding for the decoder"),
    ] {
        let blob = Blob::from_borrowed(content.as_bytes());
        let mut attributes = BTreeMap::from([
            ("path".into(), "private.key".into()),
            ("git.author_name".into(), "alice".into()),
            ("git.message".into(), "production change".into()),
        ]);
        assert_eq!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().len(), 2);
        attributes.insert("git.author_name".into(), "fixture".into());
        assert!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().is_empty());
        attributes.insert("git.author_name".into(), "alice".into());
        attributes.insert("git.message".into(), "sample change".into());
        assert!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().is_empty());
    }
}

#[test]
fn source_attribute_dedup_keeps_distinct_metadata_contexts() {
    let rule = Rule::new(RuleSyntax::new("acme.token", "Token", "(svc_Q7m2V9r4)"));
    let scanner = Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(vec![rule]).unwrap()),
        ScannerConfig { enable_dedup: true, ..Default::default() },
    );
    let blob = Blob::from_borrowed(b"svc_Q7m2V9r4");
    let mut attributes = BTreeMap::from([("git.sha".into(), "first".into())]);
    assert_eq!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().len(), 1);
    attributes.insert("git.sha".into(), "second".into());
    assert_eq!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().len(), 1);
    assert!(scanner.scan_blob_with_attributes(&blob, &attributes).unwrap().is_empty());
}

#[test]
fn imported_keywords_gate_raw_and_decoded_source_fragments_case_insensitively() {
    let scanner = from_toml(
        r#"
[[rules]]
id='keyword-token'
regex='(svc_Q7m2V9r4)'
keywords=['provider']
"#,
    );
    assert!(scanner.scan_bytes(b"svc_Q7m2V9r4").unwrap().is_empty());
    assert_eq!(scanner.scan_bytes(b"PrOvIdEr svc_Q7m2V9r4").unwrap().len(), 1);
    let encoded = STANDARD.encode("PrOvIdEr svc_Q7m2V9r4 with padding for decoding");
    assert_eq!(scanner.scan_bytes(encoded.as_bytes()).unwrap().len(), 1);
    let encoded = format!("provider {}", STANDARD.encode("svc_Q7m2V9r4 with padding for decoding"));
    assert!(scanner.scan_bytes(encoded.as_bytes()).unwrap().is_empty());
}

#[test]
fn path_only_keywords_use_source_content_and_preserve_empty_fragment_filter_context() {
    let scanner = from_toml(
        r#"
[[rules]]
id='keyword-path'
path='\.key$'
keywords=['inventory']
filter='finding.fragment_raw != ""'
"#,
    );
    assert!(
        scanner.scan_blob_at_path(&Blob::from_borrowed(b""), "inventory.key").unwrap().is_empty()
    );
    assert!(
        scanner
            .scan_blob_at_path(&Blob::from_borrowed(b"unrelated"), "private.key")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        scanner
            .scan_blob_at_path(&Blob::from_borrowed(b"INVENTORY entry"), "private.key")
            .unwrap()
            .len(),
        1
    );
}
