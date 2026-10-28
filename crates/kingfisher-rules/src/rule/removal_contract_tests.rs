use super::*;

#[test]
fn stripped_comments_preserve_existing_syntax_and_whitespace_rules() {
    let cases = [
        ("(alpha)(?# discarded)(beta)", "(alpha)(beta)"),
        ("a(?# first)B(?# second)C", "aBC"),
        ("a(?# line one\nline two)b", "ab"),
        ("a # ASCII words", "a"),
        ("a  # ASCII words", "a "),
        ("a\u{2003}# ASCII words", "a"),
        ("# starts at column zero", "# starts at column zero"),
        ("a# adjacent hash", "a# adjacent hash"),
        ("a # contains 42", "a # contains 42"),
        ("a # café", "a # café"),
        ("a(?# unclosed", "a(?# unclosed"),
        ("a(?#)b", "ab"),
        // Preserve the established textual behavior even inside escaped/class syntax.
        (r"\(?# text)", r"\"),
        ("[(?# text)]", "[]"),
        // The current trailing-comment syntax permits whitespace, including newlines.
        ("a # note\nb", "a"),
    ];
    for (pattern, expected) in cases {
        let syntax = RuleSyntax::new("acme.comments", "Comments", pattern);
        assert_eq!(syntax.uncommented_pattern(), expected, "{pattern:?}");
        assert_eq!(RULE_COMMENTS_PATTERN.replace_all(pattern, ""), expected);
    }
}

#[test]
fn comment_free_patterns_remain_borrowed() {
    let syntax = RuleSyntax::new("acme.borrowed", "Borrowed", r"(?i)(token_[a-f0-9]+)");
    let uncommented = syntax.uncommented_pattern();
    assert!(matches!(uncommented, Cow::Borrowed(_)));
    assert!(std::ptr::eq(uncommented.as_ptr(), syntax.pattern.as_ptr()));
}

#[test]
fn byte_regex_flags_and_captures_remain_available() {
    let syntax = RuleSyntax::new(
        "acme.bytes",
        "Bytes",
        r"(?i)(?P<kind>token)=(?P<secret>\w+)(?# explanation)",
    );
    let regex = syntax.as_regex().unwrap();
    let captures = regex.captures(b"TOKEN=abc_42").unwrap();
    assert_eq!(&captures["kind"], b"TOKEN");
    assert_eq!(&captures["secret"], b"abc_42");
    assert!(!regex.is_match("token=é".as_bytes()));
    assert!(RuleSyntax::new("acme.dot", "Dot", r"(.)").as_regex().unwrap().is_match(b"\xff"));
    assert!(
        RuleSyntax::new("acme.unicode", "Unicode", r"(?u:(\p{Greek}+))")
            .as_regex()
            .unwrap()
            .is_match("Ω".as_bytes())
    );
}

#[test]
fn anchoring_preserves_alternation_and_multiline_contracts() {
    let alternatives = RuleSyntax::new("acme.alternatives", "Alternatives", "a|b");
    assert_eq!(alternatives.as_anchored_regex().unwrap().as_str(), "a|b$");
    assert!(alternatives.as_anchored_regex().unwrap().is_match(b"a suffix"));
    assert!(!alternatives.as_endpoint_regex().unwrap().is_match(b"a suffix"));
    assert!(alternatives.as_endpoint_regex().unwrap().is_match(b"prefix b"));
    assert_eq!(alternatives.as_endpoint_regex().unwrap().as_str(), r"(?:a|b)\z");

    let multiline = RuleSyntax::new("acme.multiline", "Multiline", "(?m)token");
    assert!(multiline.as_anchored_regex().unwrap().is_match(b"token\nsuffix"));
    assert!(!multiline.as_endpoint_regex().unwrap().is_match(b"token\nsuffix"));
    assert!(multiline.as_endpoint_regex().unwrap().is_match(b"prefix\ntoken"));
}

#[test]
fn regex_builder_errors_keep_context_and_the_size_limit() {
    let invalid = RuleSyntax::new("acme.invalid", "Invalid", "(");
    for result in [invalid.as_regex(), invalid.as_anchored_regex(), invalid.as_endpoint_regex()] {
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "Failed to build regex");
        assert!(error.chain().any(|cause| cause.to_string().contains("unclosed group")));
    }
    // Exercise the deliberate increase over RegexBuilder's 10 MiB default without
    // tying the fixture to regex-automata's per-instruction memory representation.
    let mut accepts_a_pattern_above_the_default = false;
    for repeats in [400_000, 500_000, 600_000, 700_000, 800_000, 900_000, 1_000_000] {
        let pattern = format!("a{{{repeats}}}");
        let default_limit = regex::bytes::RegexBuilder::new(&pattern).unicode(false).build();
        let increased_limit = RuleSyntax::new("acme.large", "Large", pattern).as_regex();
        if default_limit.is_err() && increased_limit.is_ok() {
            accepts_a_pattern_above_the_default = true;
            break;
        }
    }
    assert!(accepts_a_pattern_above_the_default);
    let too_large = RuleSyntax::new("acme.too-large", "Too large", "a{10000000}");
    assert!(too_large.as_regex().is_err());
}

#[test]
fn rule_constructor_matches_minimal_yaml_defaults() {
    let loaded: RuleSyntax =
        serde_yaml::from_str("id: acme.defaults\nname: Defaults\npattern: '(secret_[a-z]+)'\n")
            .unwrap();
    let constructed = RuleSyntax::new("acme.defaults", "Defaults", "(secret_[a-z]+)");
    assert_eq!(loaded, constructed);
    assert_eq!(constructed.confidence, Confidence::Medium);
    assert!(
        constructed.visible && constructed.authoritative && constructed.vectorscan_compatible()
    );
    assert_eq!(constructed.betterleaks_secret_group(), None);
    assert!(constructed.matches_path("any/path"));
    let mut restricted = constructed;
    restricted.path = Some(r"\.env$".into());
    assert!(restricted.matches_path("config/.env"));
    assert!(!restricted.matches_path("config/example.txt"));
    restricted.path = Some("(".into());
    assert!(!restricted.matches_path("config/.env"));
}
