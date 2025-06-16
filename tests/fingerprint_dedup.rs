//! tests/dedup_git.rs
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use bstr::BString;
use gix::{date, ObjectId};
use kingfisher::{
    blob::{BlobId, BlobMetadata},
    findings_store::FindingsStore,
    git_commit_metadata::CommitMetadata,
    location::{Location, OffsetSpan, SourcePoint, SourceSpan},
    matcher::{Match, SerializableCapture, SerializableCaptures},
    origin::{Origin, OriginSet},
    reporter::{styles::Styles, DetailsReporter, ReportMatch},
    rules::rule::Confidence,
};
// ---- helpers -------------------------------------------------------------------------------

fn make_match(fp: u64) -> Match {
    Match {
        location: Location {
            offset_span: OffsetSpan { start: 0, end: 10 },
            source_span: SourceSpan {
                start: SourcePoint { line: 1, column: 0 },
                end: SourcePoint { line: 1, column: 10 },
            },
        },
        groups: SerializableCaptures {
            captures: vec![SerializableCapture {
                name: None,
                match_number: 0,
                start: 0,
                end: 10,
                value: "dummy".into(),
            }],
        },
        blob_id: BlobId::new(b"dummy"),
        finding_fingerprint: fp,
        rule_finding_fingerprint: "structural.1".into(),
        rule_text_id: "RULE.1".into(),
        rule_name: "Example Rule".into(),
        rule_confidence: Confidence::Medium,
        validation_response_body: String::new(),
        validation_response_status: 0,
        validation_success: false,
        calculated_entropy: 0.0,
        visible: true,
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
        committer_name: BString::from("tester"),
        committer_email: BString::from("tester@example.com"),
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
        BString::from("dummy.txt"),
    ))
}

// ---- the actual test -----------------------------------------------------------------------

#[test]
fn reporter_deduplicates_across_git_commits() -> Result<()> {
    // Build two matches with the same fingerprint.
    let m1 = make_match(0xBADC0FFE);
    let m2 = make_match(0xBADC0FFE);

    // Different commit ids -- old dedup logic *fails* to merge them.
    let origin_a = git_origin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let origin_b = git_origin("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    // We can skip FindingsStore and talk straight to the reporter.
    let reporter = DetailsReporter {
        datastore: Arc::new(Mutex::new(FindingsStore::new(PathBuf::from("/tmp")))),
        styles: Styles::new(false),
        only_valid: false,
    };

    let matches = vec![
        ReportMatch {
            origin: origin_a,
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                charset: None,
                language: None,
            },
            m: m1,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: String::new(),
            validation_response_status: 0,
            validation_success: false,
        },
        ReportMatch {
            origin: origin_b,
            blob_metadata: BlobMetadata {
                id: BlobId::new(b"dummy"),
                num_bytes: 10,
                mime_essence: None,
                charset: None,
                language: None,
            },
            m: m2,
            comment: None,
            match_confidence: Confidence::Medium,
            visible: true,
            validation_response_body: String::new(),
            validation_response_status: 0,
            validation_success: false,
        },
    ];

    // no_dedup = false ⇒ we expect true deduplication.
    let deduped = reporter.deduplicate_matches(matches, /* no_dedup= */ false);

    // Old code ⇒ len == 2  (fails).  Fixed code ⇒ len == 1  (passes).
    assert_eq!(deduped.len(), 1, "identical findings across commits must be merged");

    Ok(())
}
