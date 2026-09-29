//! Borrow content and map byte offsets to source locations without a scanner.
use kingfisher_core::{Blob, BlobId, LocationMapping, OffsetSpan, ValidationOutcome};

fn main() {
    let bytes = b"name=example\ntoken=demo_value\n";
    let blob = Blob::from_borrowed(bytes);
    let span = OffsetSpan::from_range(19..29);
    let source = LocationMapping::new(blob.bytes()).get_source_span(&span);
    println!(
        "blob={} bytes={} line={} column={}",
        blob.id(),
        blob.len(),
        source.start.line,
        source.start.column
    );
    // Full hashing is useful when an application needs a complete-content identifier.
    let full_id = BlobId::compute_from_bytes(bytes);
    assert_eq!(BlobId::from_hex(&full_id.hex()).unwrap(), full_id);
    assert!(!ValidationOutcome::Assumed.is_verified_active());
}
