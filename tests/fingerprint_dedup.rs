//! tests/dedup_git.rs
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use gix::{ObjectId, date};
use kingfisher::{
    blob::{BlobId, BlobMetadata},
    findings_store::FindingsStore,
    git_commit_metadata::CommitMetadata,
    location::{Location, OffsetSpan, SourcePoint, SourceSpan},
    matcher::{Match, SerializableCapture, SerializableCaptures},
    origin::{Origin, OriginSet},
    reporter::{DetailsReporter, ReportMatch, styles::Styles},
    rules::rule::{Confidence, Rule, RuleSyntax},
    util::intern,
};
use smallvec::smallvec;
// ---- helpers -------------------------------------------------------------------------------

fn make_match(fp: u64, rule_id: &str) -> Match {
    let syntax = RuleSyntax {
        name: "Example Rule".to_string(),
        id: rule_id.to_string(),
        pattern: "dummy".to_string(),
        min_entropy: 0.0,
        confidence: Confidence::Medium,
        visible: true,
        examples: vec![],
        negative_examples: vec![],
        references: vec![],
        validation: None,
        revocation: None,
        depends_on_rule: vec![],
        pattern_requirements: None,
        tls_mode: None,
    };
    let rule = Arc::new(Rule::new(syntax));
    Match {
        location: Location::with_source_span(
            OffsetSpan { start: 0, end: 10 },
            Some(SourceSpan {
                start: SourcePoint { line: 1, column: 0 },
                end: SourcePoint { line: 1, column: 10 },
            }),
        ),
        groups: SerializableCaptures {
            captures: smallvec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 0,
                end: 10,
                value: intern("dummy"),
            }],
        },
        blob_id: BlobId::new(b"dummy"),
        finding_fingerprint: fp,
        rule,
        validation_response_body: None,
        validation_response_status: 0,
        validation_success: false,
        validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
        calculated_entropy: 0.0,
        visible: true,
        is_base64: false,
        dependent_captures: std::collections::BTreeMap::new(),
    }
}

/// Return a dummy commit object whose types match the current struct.
fn dummy_commit(commit_id: &str) -> CommitMetadata {
    // Parse the supplied hex string into a Git object‑id.
    let oid = ObjectId::from_hex(commit_id.as_bytes())
        .expect("commit_id must be a valid 40‑character hex string");

    // A zero‑epoch timestamp is fine for tests.
    let ts = date::parse("1970-01-01 00:00:00 +0000", None).unwrap();

    CommitMetadata {
        commit_id: oid,
        committer_name: "tester".into(),
        committer_email: "tester@exmple.com".into(),
        committer_timestamp: ts,
    }
}

/// Create a Git origin whose only difference is the commit‐id.
fn git_origin(commit_id: &str) -> OriginSet {
    // Most fields are irrelevant for this test – we just need a publicly visible commit_id.
    let md = dummy_commit(commit_id);

    OriginSet::single(Origin::from_git_repo_with_first_commit(
        Arc::new(PathBuf::from("/tmp/repo")),
        Arc::new(md),
        String::from("dummy.txt"),
    ))
}

// ---- the actual test -----------------------------------------------------------------------

#[test]
fn reporter_deduplicates_across_git_commits() -> Result<()> {
    // Build two matches with the same fingerprint.
    let m1 = make_match(0xBADC0FFE, "RULE.1");
    let m2 = make_match(0xBADC0FFE, "RULE.1");

    // Different commit ids -- old dedup logic *fails* to merge them.
    let origin_a = git_origin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let origin_b = git_origin("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // We can skip FindingsStore and talk straight to the reporter.
    let reporter = DetailsReporter {
        datastore: Arc::new(Mutex::new(FindingsStore::new(PathBuf::from("/tmp")))),
        styles: Styles::new(false),
        validation_filter: kingfisher::cli::commands::scan::ValidationFilter::All,
        audit_context: None,
    };

    let matches = vec![
        ReportMatch {
            origin: origin_a,
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                language: None,
            },
            m: m1,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
        },
        ReportMatch {
            origin: origin_b,
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                language: None,
            },
            m: m2,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
        },
    ];

    // no_dedup = false ⇒ we expect true deduplication.
    let deduped = reporter.deduplicate_matches(matches, /* no_dedup= */ false);

    // Old code ⇒ len == 2  (fails).  Fixed code ⇒ len == 1  (passes).
    assert_eq!(deduped.len(), 1, "identical findings across commits must be merged");

    Ok(())
}

#[test]
fn dedup_preserves_distinct_rules_with_same_fingerprint() -> Result<()> {
    let shared_fp = 0xDEADC0DE;
    let m1 = make_match(shared_fp, "RULE.OPENAI");
    let m2 = make_match(shared_fp, "RULE.DEEPSEEK");

    let origin = git_origin("cccccccccccccccccccccccccccccccccccccccc");

    let reporter = DetailsReporter {
        datastore: Arc::new(Mutex::new(FindingsStore::new(PathBuf::from("/tmp")))),
        styles: Styles::new(false),
        validation_filter: kingfisher::cli::commands::scan::ValidationFilter::All,
        audit_context: None,
    };

    let matches = vec![
        ReportMatch {
            origin: origin.clone(),
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                language: None,
            },
            m: m1,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
        },
        ReportMatch {
            origin,
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                language: None,
            },
            m: m2,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: None,
            validation_response_status: 0,
            validation_success: false,
            validation_outcome: kingfisher_core::ValidationOutcome::NotAttempted,
        },
    ];

    let deduped = reporter.deduplicate_matches(matches, /* no_dedup= */ false);

    assert_eq!(deduped.len(), 2, "matches from distinct rules must not be deduplicated");

    Ok(())
}
