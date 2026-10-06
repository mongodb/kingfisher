//! Opt into CLI detection policies while keeping legacy scanning available.
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD};
use kingfisher_scanner::{
    Blob, Rule, RuleSyntax, RulesDatabase, ScanControl, Scanner, context::DetectionOptions,
};

fn main() -> anyhow::Result<()> {
    let database = RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
        "acme.demo",
        "Synthetic example token",
        r"(demo_[a-z0-9]{16})",
    ))])?;
    let scanner = Scanner::new(Arc::new(database));
    let encoded = STANDARD.encode(STANDARD.encode(b"token=demo_abcd1234efgh5678"));
    let blob = Blob::from_bytes(encoded.into_bytes());

    // Existing entry points retain one-layer decoding and legacy matching defaults.
    assert!(scanner.scan_blob(&blob)?.is_empty());
    // Options default to CLI matching, two Base64 layers, and a 64 MiB decoding cap.
    let options = DetectionOptions::default();
    let findings = scanner.scan_blob_at_path_with_options(&blob, "config.env", &options)?;
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    // Encoded findings still point to the outer input envelope.
    assert_eq!(findings[0].location.end_offset, blob.len());

    let bounded = DetectionOptions { base64_max_depth: 1, ..options };
    let control = ScanControl::default().with_timeout(std::time::Duration::from_secs(5))?;
    assert!(
        scanner
            .scan_blob_at_path_with_options_and_control(&blob, "config.env", &bounded, &control)?
            .is_empty()
    );
    // Decode limits affect only Base64; raw candidates are still scanned.
    let raw = Blob::from_bytes(b"token=demo_abcd1234efgh5678".to_vec());
    let no_decoding = DetectionOptions { base64_max_depth: 0, ..Default::default() };
    assert_eq!(scanner.scan_blob_at_path_with_options(&raw, "config.env", &no_decoding)?.len(), 1);
    println!("Detected one nested Base64 token; explicit limits preserve raw detection.");
    Ok(())
}
