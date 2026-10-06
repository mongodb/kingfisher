use kingfisher::parser::{Language, verify_match_in_context};
use regex::bytes::Regex;

#[test]
fn context_verifier_preserves_capture_selection() -> anyhow::Result<()> {
    let source = br#"secret = "prefix-value""#;
    let cases: [(&str, &[u8], &[u8]); 7] = [
        (r"(?P<label>prefix)-(?P<tOkEn>value)", b"value", b"prefix"),
        (r"(?P<optional>missing)?(?P<secret>prefix)-value", b"prefix", b"value"),
        (r"(?P<TOKEN>missing)?(?P<secret>prefix)-value", b"prefix", b"value"),
        (r"(prefix)-(?P<secret>value)", b"value", b"prefix"),
        (r"(prefix)-(value)", b"prefix", b"value"),
        (r"prefix-value", b"prefix-value", b"prefix"),
        (r"(missing)?prefix-value", b"prefix-value", b"value"),
    ];

    for (pattern, selected, unselected) in cases {
        let re = Regex::new(pattern)?;
        assert!(
            verify_match_in_context(source, &Language::Python, &re, selected)?,
            "expected the selected capture for {pattern}"
        );
        assert!(
            !verify_match_in_context(source, &Language::Python, &re, unselected)?,
            "must not verify an unselected capture for {pattern}"
        );
    }
    Ok(())
}

#[test]
fn context_verifier_checks_later_matches_and_candidates() -> anyhow::Result<()> {
    let re = Regex::new(r"(other|target)")?;
    let sources: [&[u8]; 2] =
        [br#"secrets = "other target""#, b"first = \"other\"\nsecond = \"target\"\n"];
    for source in sources {
        assert!(verify_match_in_context(source, &Language::Python, &re, b"target")?);
    }
    Ok(())
}

#[test]
fn context_verifier_rejects_comments_and_missing_secrets() -> anyhow::Result<()> {
    let re = Regex::new(r"(other|target)")?;
    let source = b"# secret = \"target\"\nsecret = \"other\"\n";
    assert!(!verify_match_in_context(source, &Language::Python, &re, b"target")?);
    assert!(!verify_match_in_context(source, &Language::Python, &re, b"missing")?);
    assert!(!verify_match_in_context(b"", &Language::Python, &re, b"target")?);
    Ok(())
}
