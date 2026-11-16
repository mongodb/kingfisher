//! Public byte-scanning contracts that require no optional scanner features.

use std::sync::Arc;

use kingfisher_scanner::{Blob, Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig};

#[test]
fn byte_only_scanning_preserves_findings_and_redaction() -> anyhow::Result<()> {
    let input = b"header\ncredential=offline_abcd1234efgh5678\n";
    let secret = "offline_abcd1234efgh5678";

    // Both legacy engine-hint values must preserve the byte-scanning contract
    // without validators, runtimes, archives, or extraction machinery.
    for vectorscan_compatible in [true, false] {
        let mut syntax = RuleSyntax::new(
            "acme.offline",
            "Offline fixture",
            r"\b(?P<token>offline_[a-z0-9]{16})\b",
        );
        syntax.vectorscan_compatible = vectorscan_compatible;
        let rules = Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax)])?);
        let config = ScannerConfig { enable_base64_decoding: false, ..Default::default() };
        let scanner = Scanner::with_config(Arc::clone(&rules), config.clone());
        let findings = scanner.scan_bytes(input)?;
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "acme.offline");
        assert_eq!(finding.secret, secret);
        assert_eq!(finding.captures.get("token").map(String::as_str), Some(secret));
        assert_eq!(finding.location.start_offset, 18);
        assert_eq!(finding.location.end_offset, 42);
        assert_eq!(finding.line(), 2);
        assert_eq!(finding.column(), 11);
        assert_eq!(finding.blob_id, Blob::from_borrowed(input).id());
        assert!(!finding.is_base64_encoded);
        assert_eq!(scanner.scan_bytes(input)?[0].fingerprint, finding.fingerprint);
        assert!(scanner.scan_bytes(b"no credentials here")?.is_empty());

        let redacted =
            Scanner::with_config(rules, ScannerConfig { redact_secrets: true, ..config })
                .scan_bytes(input)?;
        assert_eq!(redacted.len(), 1);
        assert_eq!(redacted[0].secret, "[REDACTED]");
        assert!(redacted[0].captures.values().all(|value| value == "[REDACTED]"));
        assert_eq!(redacted[0].fingerprint, finding.fingerprint);
        assert_eq!(redacted[0].blob_id, finding.blob_id);
        assert_eq!(redacted[0].location.start_offset, finding.location.start_offset);
        assert_eq!(redacted[0].location.end_offset, finding.location.end_offset);
    }
    Ok(())
}
