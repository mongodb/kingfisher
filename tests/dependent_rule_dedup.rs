use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use kingfisher::{
    blob::{BlobId, BlobMetadata},
    findings_store::{FindingsStore, FindingsStoreMessage},
    location::{Location, OffsetSpan, SourcePoint, SourceSpan},
    matcher::{Match, SerializableCapture, SerializableCaptures},
    origin::{Origin, OriginSet},
    rules::rule::{Confidence, DependsOnRule, Rule, RuleSyntax},
    util::intern,
};
use smallvec::smallvec;

fn make_rule(rule_id: &str, depends_on_rule: Vec<Option<DependsOnRule>>) -> Arc<Rule> {
    Arc::new(Rule::new(RuleSyntax {
        name: format!("{rule_id} rule"),
        id: rule_id.to_string(),
        pattern: "dummy".to_string(),
        min_entropy: 0.0,
        confidence: Confidence::Low,
        visible: true,
        examples: vec![],
        negative_examples: vec![],
        references: vec![],
        validation: None,
        revocation: None,
        depends_on_rule,
        pattern_requirements: None,
        tls_mode: None,
    }))
}

fn make_match(rule: Arc<Rule>, blob_id: BlobId, value: &str) -> Match {
    Match {
        location: Location::with_source_span(
            OffsetSpan { start: 0, end: value.len() },
            Some(SourceSpan {
                start: SourcePoint { line: 1, column: 0 },
                end: SourcePoint { line: 1, column: value.len() },
            }),
        ),
        groups: SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 0,
                end: value.len(),
                value: intern(value),
            }],
        },
        blob_id,
        finding_fingerprint: 123,
        rule,
        validation_response_body: None,
        validation_response_status: 0,
        validation_success: false,
        calculated_entropy: 0.0,
        visible: true,
        is_base64: false,
        dependent_captures: std::collections::BTreeMap::new(),
    }
}

fn record_match(
    origin: &Arc<OriginSet>,
    blob_metadata: &Arc<BlobMetadata>,
    m: Match,
) -> FindingsStoreMessage {
    (origin.clone(), blob_metadata.clone(), m)
}

#[test]
fn dedup_preserves_dependency_provider_matches_per_blob() -> Result<()> {
    let provider_rule = make_rule("RULE.PROVIDER", vec![]);
    let dependent_rule = make_rule(
        "RULE.DEPENDENT",
        vec![Some(DependsOnRule {
            rule_id: "RULE.PROVIDER".to_string(),
            variable: "TOKEN".into(),
        })],
    );

    let mut store = FindingsStore::new(PathBuf::from("/tmp"));
    store.record_rules(&[provider_rule.clone(), dependent_rule]);

    let origin = Arc::new(OriginSet::single(Origin::from_file(PathBuf::from("a.txt"))));
    let blob_a = Arc::new(BlobMetadata {
        id: BlobId::new(b"blob-a"),
        num_bytes: 10,
        mime_essence: None,
        language: None,
    });
    let blob_b = Arc::new(BlobMetadata {
        id: BlobId::new(b"blob-b"),
        num_bytes: 10,
        mime_essence: None,
        language: None,
    });

    let matches = vec![
        record_match(
            &origin,
            &blob_a,
            make_match(provider_rule.clone(), blob_a.id, "shared_token"),
        ),
        record_match(&origin, &blob_b, make_match(provider_rule, blob_b.id, "shared_token")),
    ];

    store.record(matches, true);

    assert_eq!(store.get_matches().len(), 2);

    Ok(())
}

#[test]
fn dedup_still_merges_non_dependency_rules_across_blobs() -> Result<()> {
    let rule = make_rule("RULE.SIMPLE", vec![]);
    let mut store = FindingsStore::new(PathBuf::from("/tmp"));
    store.record_rules(std::slice::from_ref(&rule));

    let origin = Arc::new(OriginSet::single(Origin::from_file(PathBuf::from("b.txt"))));
    let blob_a = Arc::new(BlobMetadata {
        id: BlobId::new(b"blob-a"),
        num_bytes: 10,
        mime_essence: None,
        language: None,
    });
    let blob_b = Arc::new(BlobMetadata {
        id: BlobId::new(b"blob-b"),
        num_bytes: 10,
        mime_essence: None,
        language: None,
    });

    let matches = vec![
        record_match(&origin, &blob_a, make_match(rule.clone(), blob_a.id, "shared_token")),
        record_match(&origin, &blob_b, make_match(rule, blob_b.id, "shared_token")),
    ];

    store.record(matches, true);

    assert_eq!(store.get_matches().len(), 1);

    Ok(())
}
