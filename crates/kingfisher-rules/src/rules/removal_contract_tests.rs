use std::path::PathBuf;

use super::*;
use serde_json::{Value, json};

struct RuleDirectory(PathBuf);

impl RuleDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .join(format!("kingfisher-removal-rule-contract-{}", uuid::Uuid::new_v4(),));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.0.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for RuleDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn definition(id: &str, name: &str) -> Value {
    json!({"id": id, "name": name, "pattern": "(acme_[A-Za-z0-9]+)"})
}

fn document(rules: Vec<Value>) -> String {
    serde_yaml::to_string(&json!({"rules": rules})).unwrap()
}

fn parse(document: &str, confidence: Confidence) -> Rules {
    Rules::from_paths_and_contents([(Path::new("custom.yml"), document.as_bytes())], confidence)
        .unwrap()
}

#[test]
fn collection_loading_preserves_defaults_confidence_and_deterministic_order() {
    let mut low = definition("acme.low", "Low");
    low["confidence"] = json!("LOW");
    let medium = definition("acme.medium", "Medium");
    let mut high = definition("acme.high", "High");
    high["confidence"] = json!("hIgH");
    let yaml = document(vec![medium, low, high]);
    for (confidence, ids) in [
        (Confidence::Low, vec!["acme.high", "acme.low", "acme.medium"]),
        (Confidence::Medium, vec!["acme.high", "acme.medium"]),
        (Confidence::High, vec!["acme.high"]),
    ] {
        let rules = parse(&yaml, confidence);
        assert_eq!(rules.iter_rules().map(|rule| rule.id.as_str()).collect::<Vec<_>>(), ids);
        assert_eq!(rules.num_rules(), ids.len());
        assert!(!rules.is_empty());
        assert_eq!(rules.into_iter().map(|rule| rule.id).collect::<Vec<_>>(), ids);
    }
    assert!(Rules::new().is_empty());
    assert!(Rules::default().is_empty());
    assert!(parse("rules: []", Confidence::Low).is_empty());
}

#[test]
fn duplicate_ids_use_the_last_accepted_definition_in_source_order() {
    let first = document(vec![definition("acme.same", "First"), definition("acme.same", "Second")]);
    let second = document(vec![definition("acme.same", "Third")]);
    let rules = Rules::from_paths_and_contents(
        [(Path::new("first.yml"), first.as_bytes()), (Path::new("second.yml"), second.as_bytes())],
        Confidence::Low,
    )
    .unwrap();
    assert_eq!(rules.num_rules(), 1);
    assert_eq!(rules.rules["acme.same"].name, "Third");

    let mut skipped = definition("acme.same", "Skipped low confidence");
    skipped["confidence"] = json!("low");
    let yaml = document(vec![definition("acme.same", "Kept medium confidence"), skipped]);
    assert_eq!(parse(&yaml, Confidence::Medium).rules["acme.same"].name, "Kept medium confidence");
}

#[test]
fn update_keeps_prefilters_left_associated_and_preserves_rule_replacement() {
    let make = |id: &str, name: &str, prefilter: Option<BetterleaksExpr>| Rules {
        rules: [(id.into(), RuleSyntax::new(id, name, "(secret)"))].into(),
        betterleaks_prefilter: prefilter,
    };
    let a = BetterleaksExpr::Identifier { value: "a".into() };
    let b = BetterleaksExpr::Identifier { value: "b".into() };
    let c = BetterleaksExpr::Identifier { value: "c".into() };
    let mut rules = make("acme.same", "First", Some(a.clone()));
    rules.update(make("acme.other", "Other", None));
    rules.update(make("acme.same", "Replacement", Some(b.clone())));
    rules.update(make("acme.last", "Last", Some(c.clone())));
    assert_eq!(rules.rules["acme.same"].name, "Replacement");
    assert_eq!(rules.num_rules(), 3);
    let or = |left, right| BetterleaksExpr::Binary {
        operator: "||".into(),
        left: Box::new(left),
        right: Box::new(right),
    };
    assert_eq!(rules.betterleaks_prefilter, Some(or(or(a, b), c)));
}

#[test]
fn yaml_file_and_memory_loading_have_identical_rules_and_prefilters() {
    let directory = RuleDirectory::new();
    let yaml = serde_yaml::to_string(&json!({
        "betterleaks_prefilter": {"kind": "bool", "value": true},
        "rules": [definition("acme.equivalence", "Equivalence")],
    }))
    .unwrap();
    let path = directory.write("custom.yml", &yaml);
    let file = Rules::from_yaml_file(&path, Confidence::Low).unwrap();
    let memory = parse(&yaml, Confidence::Low);
    assert_eq!(file.rules, memory.rules);
    assert_eq!(file.betterleaks_prefilter, memory.betterleaks_prefilter);
    assert_eq!(file.betterleaks_prefilter, Some(BetterleaksExpr::Bool { value: true }));
    let many_files = Rules::from_yaml_files([&path], Confidence::Low).unwrap();
    assert_eq!(many_files.rules, memory.rules);
    assert_eq!(many_files.betterleaks_prefilter, memory.betterleaks_prefilter);
}

#[test]
fn accepted_http_validation_and_revocation_require_nonempty_matchers() {
    let directory = RuleDirectory::new();
    for field in ["validation", "revocation"] {
        for response_matcher in [None, Some(json!([]))] {
            let mut rule = definition("acme.missing-matcher", "Missing matcher");
            let mut request = json!({"method": "GET", "url": "https://example.invalid/check"});
            if let Some(matcher) = response_matcher {
                request["response_matcher"] = matcher;
            }
            rule[field] = json!({"type": "Http", "content": {"request": request}});
            let yaml = document(vec![rule]);
            let path = directory.write("missing-matcher.yml", &yaml);
            for error in [
                Rules::from_paths_and_contents(
                    [(path.as_path(), yaml.as_bytes())],
                    Confidence::Low,
                )
                .err()
                .expect("memory load must reject missing matcher"),
                Rules::from_yaml_file(&path, Confidence::Low)
                    .err()
                    .expect("file load must reject missing matcher"),
            ] {
                match (field, error.downcast_ref::<RulesError>().unwrap()) {
                    ("validation", RulesError::MissingResponseMatcher { rule_id, path: found })
                    | (
                        "revocation",
                        RulesError::MissingRevocationMatcher { rule_id, path: found },
                    ) => {
                        assert_eq!(rule_id, "acme.missing-matcher");
                        assert_eq!(found, &path.display().to_string());
                    }
                    (_, unexpected) => panic!("wrong rejection: {unexpected:?}"),
                }
            }
        }
    }
}

#[test]
fn confidence_filter_runs_before_http_matcher_validation() {
    let directory = RuleDirectory::new();
    let mut filtered = definition("acme.filtered", "Filtered invalid HTTP");
    filtered["confidence"] = json!("low");
    filtered["validation"] = json!({"type": "Http", "content": {"request": {
        "method": "GET", "url": "https://example.invalid/check",
    }}});
    let yaml = document(vec![filtered, definition("acme.accepted", "Accepted")]);
    let path = directory.write("filtered.yml", &yaml);
    let memory = parse(&yaml, Confidence::Medium);
    let file = Rules::from_yaml_file(path, Confidence::Medium).unwrap();
    assert_eq!(memory.rules, file.rules);
    assert_eq!(
        memory.iter_rules().map(|rule| rule.id.as_str()).collect::<Vec<_>>(),
        ["acme.accepted"]
    );
}

#[test]
fn invalid_yaml_and_invalid_input_preserve_path_and_error_categories() {
    let directory = RuleDirectory::new();
    let path = directory.write("broken.yml", "rules:\n  - id: [\n");
    let memory = Rules::from_paths_and_contents(
        [(path.as_path(), b"rules:\n  - id: [\n".as_slice())],
        Confidence::Low,
    )
    .err()
    .expect("invalid memory YAML must fail");
    match memory.downcast_ref::<RulesError>().unwrap() {
        RulesError::InvalidResponseMatcherVariant(found, line, column) => {
            assert_eq!(found, &path.display().to_string());
            assert!(*line > 0 && *column > 0);
        }
        unexpected => panic!("wrong memory parse rejection: {unexpected:?}"),
    }
    let file = Rules::from_yaml_file(&path, Confidence::Low).err().unwrap();
    assert!(matches!(file.downcast_ref::<RulesError>(), Some(RulesError::YamlParseError(_))));
    assert!(file.to_string().contains(&path.display().to_string()));
    let absent = directory.0.join("does-not-exist.yml");
    let invalid = Rules::from_paths([&absent], Confidence::Low).err().unwrap();
    assert!(
        matches!(invalid.downcast_ref::<RulesError>(), Some(RulesError::InvalidInputError(found))
        if found == &absent.display().to_string())
    );
}

#[test]
fn directory_loading_is_recursive_sorted_and_includes_hidden_and_ignored_yaml() {
    let directory = RuleDirectory::new();
    directory.write(".gitignore", "*.yml\n");
    directory.write(".hidden.yml", &document(vec![definition("acme.hidden", "Hidden")]));
    directory.write("a.yml", &document(vec![definition("acme.same", "First")]));
    directory.write("nested/inner.yml", &document(vec![definition("acme.nested", "Nested")]));
    directory.write("z.yaml", &document(vec![definition("acme.same", "Last")]));
    directory.write("ignored.txt", "This is not YAML");
    let loaded = Rules::from_directory(&directory.0, Confidence::Low).unwrap();
    assert_eq!(loaded.num_rules(), 3);
    assert_eq!(loaded.rules["acme.same"].name, "Last");
    assert!(loaded.rules.contains_key("acme.hidden"));
    assert!(loaded.rules.contains_key("acme.nested"));
}

#[test]
fn supplied_path_order_overrides_the_order_between_directories_and_files() {
    let directory = RuleDirectory::new();
    let first = directory.write("first.yml", &document(vec![definition("acme.same", "First")]));
    let last = directory.write("last.yml", &document(vec![definition("acme.same", "Last")]));
    assert_eq!(
        Rules::from_paths([&last, &first], Confidence::Low).unwrap().rules["acme.same"].name,
        "First"
    );
    assert_eq!(
        Rules::from_yaml_files([&first, &last], Confidence::Low).unwrap().rules["acme.same"].name,
        "Last"
    );
}

#[test]
fn standalone_syntax_loader_accepts_sequence_and_mapping_without_collapsing_duplicates() {
    let directory = RuleDirectory::new();
    let rules = vec![definition("acme.same", "First"), definition("acme.same", "Last")];
    for (name, yaml) in [
        ("sequence.yml", serde_yaml::to_string(&rules).unwrap()),
        ("mapping.yml", document(rules.clone())),
    ] {
        let path = directory.write(name, &yaml);
        let loaded = RuleSyntax::from_yaml_file(path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "First");
        assert_eq!(loaded[1].name, "Last");
    }
}

#[test]
fn empty_and_fully_filtered_documents_keep_left_associated_prefilters() {
    let directory = RuleDirectory::new();
    let a = BetterleaksExpr::Identifier { value: "a".into() };
    let b = BetterleaksExpr::Identifier { value: "b".into() };
    let c = BetterleaksExpr::Identifier { value: "c".into() };
    let mut filtered = definition("acme.filtered-prefilter", "Filtered");
    filtered["confidence"] = json!("low");
    let documents = [
        serde_yaml::to_string(&json!({"betterleaks_prefilter": a, "rules": []})).unwrap(),
        serde_yaml::to_string(&json!({"betterleaks_prefilter": b, "rules": [filtered]})).unwrap(),
        serde_yaml::to_string(&json!({"betterleaks_prefilter": c, "rules": []})).unwrap(),
    ];
    let paths = [
        directory.write("empty-a.yml", &documents[0]),
        directory.write("filtered-b.yml", &documents[1]),
        directory.write("empty-c.yml", &documents[2]),
    ];
    let or = |left, right| BetterleaksExpr::Binary {
        operator: "||".into(),
        left: Box::new(left),
        right: Box::new(right),
    };
    let expected = Some(or(or(a, b), c));
    let memory = Rules::from_paths_and_contents(
        paths.iter().zip(&documents).map(|(path, yaml)| (path.as_path(), yaml.as_bytes())),
        Confidence::High,
    )
    .unwrap();
    let files = Rules::from_yaml_files(&paths, Confidence::High).unwrap();
    for loaded in [memory, files] {
        assert!(loaded.is_empty());
        assert_eq!(loaded.betterleaks_prefilter, expected);
    }
}

#[test]
fn memory_yaml_ignores_path_extension_and_mixed_files_keep_source_precedence() {
    let directory = RuleDirectory::new();
    let id = "custom.loading-boundary";
    let yaml = document(vec![definition(id, "From YAML")]);
    let memory = Rules::from_paths_and_contents(
        [(Path::new("memory-only.toml"), yaml.as_bytes())],
        Confidence::Low,
    )
    .unwrap();
    let expected_yaml = memory.rules[id].clone();
    let yaml_path = directory.write("a.yml", &yaml);
    let toml = r#"
[[rules]]
id = "loading-boundary"
description = "From TOML"
regex = '''(toml_[A-Za-z0-9]+)'''
"#;
    let toml_path = directory.write("z.toml", toml);
    assert!(
        Rules::from_paths_and_contents([(toml_path.as_path(), toml.as_bytes())], Confidence::Low,)
            .is_err(),
        "the in-memory API always parses YAML, even for a .toml path"
    );
    let expected_toml =
        Rules::from_toml_file(&toml_path, Confidence::Low).unwrap().rules[id].clone();
    assert_ne!(expected_yaml, expected_toml);
    assert_eq!(
        Rules::from_directory(&directory.0, Confidence::Low).unwrap().rules[id],
        expected_toml,
        "sorted a.yml then z.toml uses the later accepted TOML definition"
    );
    assert_eq!(
        Rules::from_paths([&toml_path, &yaml_path], Confidence::Low).unwrap().rules[id],
        expected_yaml
    );
    assert_eq!(
        Rules::from_paths([&yaml_path, &toml_path], Confidence::Low).unwrap().rules[id],
        expected_toml
    );
}

#[test]
fn source_iteration_stops_at_the_first_parse_or_http_matcher_error() {
    let mut missing_matcher = definition("acme.first-error", "First error");
    missing_matcher["validation"] = json!({"type": "Http", "content": {"request": {
        "method": "GET", "url": "https://example.invalid/check",
    }}});
    for (parse_error, yaml) in
        [(true, "rules:\n  - id: [\n".to_owned()), (false, document(vec![missing_matcher]))]
    {
        let polled = std::cell::Cell::new(0);
        let inputs = std::iter::from_fn(|| {
            polled.set(polled.get() + 1);
            assert_eq!(polled.get(), 1, "must not request another source after the first error");
            Some((Path::new("first-error.yml"), yaml.as_bytes()))
        });
        let error = Rules::from_paths_and_contents(inputs, Confidence::Low)
            .err()
            .expect("the first document must fail");
        assert_eq!(polled.get(), 1);
        match error.downcast_ref::<RulesError>().unwrap() {
            RulesError::InvalidResponseMatcherVariant(path, _, _) if parse_error => {
                assert_eq!(path, "first-error.yml");
            }
            RulesError::MissingResponseMatcher { path, rule_id } if !parse_error => {
                assert_eq!(path, "first-error.yml");
                assert_eq!(rule_id, "acme.first-error");
            }
            unexpected => panic!("wrong first error: {unexpected:?}"),
        }
    }
}

#[test]
fn confidence_filter_does_not_bypass_serde_revocation_security_checks() {
    let directory = RuleDirectory::new();
    for field in ["validation", "revocation"] {
        let mut filtered = definition("acme.filtered-http", "Filtered HTTP");
        filtered["confidence"] = json!("low");
        filtered[field] = json!({"type": "Http", "content": {"request": {
            "method": "GET", "url": "https://example.invalid/check",
        }}});
        let yaml = document(vec![filtered, definition("acme.accepted", "Accepted")]);
        let path = directory.write(&format!("filtered-{field}.yml"), &yaml);
        let memory = parse(&yaml, Confidence::Medium);
        let file = Rules::from_yaml_file(&path, Confidence::Medium).unwrap();
        assert_eq!(memory.rules, file.rules);
        assert_eq!(
            memory.iter_rules().map(|rule| rule.id.as_str()).collect::<Vec<_>>(),
            ["acme.accepted"]
        );
    }

    let password = "synthetic-boundary-password";
    let client_secret = "synthetic-boundary-client-secret";
    let mut forbidden = definition("acme.filtered-auth", "Forbidden low-confidence auth");
    forbidden["confidence"] = json!("low");
    forbidden["revocation"] = json!({"type": "Http", "content": {
        "auth": {"oauth2": {
            "token_endpoint": "https://idp.example.invalid/token",
            "ropc": {"username": "fixture", "password": password,
                "client_id": "fixture", "client_secret": client_secret},
        }},
        "request": {"method": "DELETE", "url": "https://example.invalid/token",
            "response_matcher": [{"type": "StatusMatch", "status": [204]}]},
    }});
    let yaml = document(vec![forbidden]);
    let raw_error = serde_yaml::from_str::<RawRules>(&yaml).err().unwrap().to_string();
    assert!(raw_error.contains("OAuth2 auth is supported for validation only"));
    let path = directory.write("forbidden-auth.yml", &yaml);
    let memory =
        Rules::from_paths_and_contents([(path.as_path(), yaml.as_bytes())], Confidence::High)
            .err()
            .expect("Serde security rejects the low-confidence rule before filtering");
    assert!(matches!(
        memory.downcast_ref::<RulesError>(),
        Some(RulesError::InvalidResponseMatcherVariant(_, _, _))
    ));
    let file = Rules::from_yaml_file(&path, Confidence::High)
        .err()
        .expect("file loading must reject the same forbidden auth before filtering");
    assert!(matches!(file.downcast_ref::<RulesError>(), Some(RulesError::YamlParseError(_))));
    for error in [raw_error, memory.to_string(), file.to_string()] {
        assert!(!error.contains(password));
        assert!(!error.contains(client_secret));
    }
}
