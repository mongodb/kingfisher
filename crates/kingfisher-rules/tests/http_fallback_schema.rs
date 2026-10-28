use std::path::Path;

use kingfisher_rules::{Confidence, RuleSyntax, Rules};
use serde_json::{Value, json};

fn primary() -> Value {
    json!({"id":"custom.legacy", "name":"Legacy token", "pattern":"(secret)",
    "validation":{"type":"Http","content":{"request":{
        "method":"GET","url":"https://primary.example/me",
        "headers":{"Authorization":"Bearer {{ TOKEN }}"},
        "response_matcher":[{"type":"StatusMatch","status":[200]}]
    }}}})
}

fn load(rule: Value) -> anyhow::Result<Rules> {
    let document = serde_json::to_vec(&json!({"rules":[rule]}))?;
    Rules::from_paths_and_contents(
        [(Path::new("legacy.yml"), document.as_slice())],
        Confidence::Low,
    )
}

#[test]
fn unmodified_legacy_scalar_rules_keep_their_primary_configuration() {
    let rules = load(primary()).unwrap();
    let rule = &rules.rules["custom.legacy"];
    assert!(rule.fallbacks.is_empty());
    assert_eq!(rule.http_validations(false).unwrap(), rule.http_validations(true).unwrap());
    assert!(serde_json::to_value(rule).unwrap().get("fallbacks").is_none());
}

#[test]
fn boolean_reuse_and_independent_validation_round_trip() {
    let mut rule = primary();
    rule["validation"]["content"]["request"]["method"] = json!("POST");
    rule["validation"]["content"]["request"]["body"] = json!("{{ TOKEN }}");
    rule["validation"]["content"]["request"]["response_is_html"] = json!(true);
    rule["fallbacks"] = json!([
        {"id":"secondary","reuse_primary_validation_logic":true,"url":"https://secondary.example/me"},
        {"id":"third","validation":primary()["validation"]}
    ]);
    let rules = load(rule).unwrap();
    let syntax = &rules.rules["custom.legacy"];
    assert!(!syntax.fallbacks[1].reuse_primary_validation_logic);
    assert_eq!(syntax.http_validations(false).unwrap().len(), 1);
    let configurations = syntax.http_validations(true).unwrap();
    assert_eq!(configurations.len(), 3);
    assert_eq!(configurations[1].0, Some("secondary"));
    assert_eq!(configurations[1].1.request.headers, configurations[0].1.request.headers);
    assert_eq!(configurations[1].1.request.url, "https://secondary.example/me");
    let mut expected = configurations[0].1.clone();
    expected.request.url = "https://secondary.example/me".into();
    assert_eq!(configurations[1].1, expected);
    assert!(syntax.selected_revocation(Some("secondary")).unwrap().is_none());
    let round_trip: RuleSyntax =
        serde_yaml::from_str(&serde_yaml::to_string(syntax).unwrap()).unwrap();
    assert_eq!(&round_trip, syntax);
}

#[test]
fn ambiguous_incomplete_nested_and_over_budget_profiles_are_rejected() {
    let independent = primary()["validation"].clone();
    for fallbacks in [
        json!([{"id":"secondary","url":"https://secondary.example/me"}]),
        json!([{"id":"secondary","reuse_primary_validation_logic":true}]),
        json!([{"id":"secondary","reuse_primary_validation_logic":true,"url":"  "}]),
        json!([{"id":"secondary","reuse_primary_validation_logic":true,"url":"https://secondary.example/me","validation":independent}]),
        json!([{"id":"secondary","reuse_primary_validation_logic":false,"url":"https://secondary.example/me","validation":independent}]),
        json!([{"id":"secondary","validation":{"type":"AWS"}}]),
        json!([{"id":"primary","validation":independent}]),
        json!([{"id":"same","validation":independent},{"id":"same","validation":independent}]),
        json!([{"id":"a","validation":independent},{"id":"b","validation":independent},{"id":"c","validation":independent}]),
        json!([{"id":"secondary","validation":independent,"fallbacks":[]}]),
    ] {
        let mut rule = primary();
        rule["fallbacks"] = fallbacks;
        assert!(load(rule).is_err());
    }
}

#[test]
fn legacy_url_lists_remain_readable_but_require_execution_opt_in() {
    let mut rule = primary();
    rule["validation"]["content"]["request"]["url"] =
        json!(["https://primary.example/me", "https://secondary.example/me"]);
    let rules = load(rule).unwrap();
    let syntax = &rules.rules["custom.legacy"];
    assert_eq!(syntax.http_validations(false).unwrap().len(), 1);
    assert_eq!(syntax.http_validations(true).unwrap().len(), 2);
}

#[test]
fn long_legacy_url_lists_keep_primary_validation_and_bound_alternatives() {
    let mut rule = primary();
    rule["validation"]["content"]["request"]["url"] = json!([
        "https://primary.example/me",
        "https://secondary.example/me",
        "https://third.example/me",
        "https://fourth.example/me",
    ]);
    let rules = load(rule).unwrap();
    let syntax = &rules.rules["custom.legacy"];
    assert_eq!(syntax.http_validations(false).unwrap().len(), 1);
    let validations = syntax.http_validations(true).unwrap();
    assert_eq!(validations.len(), 3);
    assert_eq!(validations[0].1.request.url, "https://primary.example/me");
    assert_eq!(validations[2].1.request.url, "https://third.example/me");
}

#[test]
fn unmodified_legacy_toml_still_loads_without_new_fields() {
    let directory =
        std::env::temp_dir().join(format!("kingfisher-legacy-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("legacy.toml");
    std::fs::write(
        &path,
        r#"
[[rules]]
id = "legacy-token"
description = "Legacy TOML detector"
regex = '''(legacy_[a-z0-9]{16})'''
secretGroup = 1
"#,
    )
    .unwrap();
    let result = Rules::from_paths([&path], Confidence::Low);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&directory).unwrap();
    let rules = result.unwrap();
    assert_eq!(rules.rules.len(), 1);
    assert!(rules.rules["custom.legacy-token"].fallbacks.is_empty());
}

#[test]
fn programmatic_rule_construction_cannot_bypass_the_profile_cap() {
    let mut rule = primary();
    rule["fallbacks"] = json!([
        {"id":"a","reuse_primary_validation_logic":true,"url":"https://a.example/me"},
        {"id":"b","reuse_primary_validation_logic":true,"url":"https://b.example/me"},
        {"id":"c","reuse_primary_validation_logic":true,"url":"https://c.example/me"}
    ]);
    let syntax: RuleSyntax = serde_json::from_value(rule).unwrap();
    assert!(
        kingfisher_rules::RulesDatabase::from_rules(vec![kingfisher_rules::Rule::new(syntax)])
            .is_err()
    );
}

#[test]
fn inspection_redacts_operator_credentials_in_independent_fallbacks() {
    let mut rule = primary();
    let mut validation = primary()["validation"].clone();
    validation["content"]["auth"] = json!({"oauth2":{
        "token_endpoint":"https://identity.example/token",
        "ropc":{"username":"operator","password":"private-operator-password",
            "client_id":"scanner","client_secret":"private-client-secret"}
    }});
    rule["fallbacks"] = json!([{"id":"secondary","validation":validation}]);
    let rules = load(rule).unwrap();
    let syntax = &rules.rules["custom.legacy"];
    let inspected = serde_json::to_string(&syntax.redacted_for_inspection()).unwrap();
    assert!(!inspected.contains("private-operator-password"));
    assert!(!inspected.contains("private-client-secret"));
    assert!(serde_json::to_string(syntax).unwrap().contains("private-operator-password"));

    // YAML rejects OAuth2 auth on revocation, but public Rust structs can still
    // contain it. Inspection must never leak these operator credentials either.
    let mut syntax = syntax.clone();
    let kingfisher_rules::Validation::Http(http) = syntax.fallbacks[0].validation.clone().unwrap()
    else {
        panic!("HTTP fixture")
    };
    syntax.revocation = Some(kingfisher_rules::Revocation::Http(http.clone()));
    syntax.fallbacks[0].revocation = Some(kingfisher_rules::Revocation::Http(http));
    let inspected = serde_json::to_string(&syntax.redacted_for_inspection()).unwrap();
    for secret in ["operator", "private-operator-password", "private-client-secret"] {
        assert!(!inspected.contains(secret));
        assert!(serde_json::to_string(&syntax).unwrap().contains(secret));
    }
}

fn primary_with_revocation() -> Value {
    let mut rule = primary();
    rule["revocation"] = rule["validation"].clone();
    rule["revocation"]["content"]["request"]["method"] = json!("DELETE");
    rule["revocation"]["content"]["request"]["url"] = json!("https://primary.example/revoke");
    rule["revocation"]["content"]["request"]["body"] = json!("{{ TOKEN }}");
    rule["fallbacks"] = json!([{"id":"secondary","reuse_primary_validation_logic":true,
        "url":"https://secondary.example/me"}]);
    rule
}

#[test]
fn revocation_reuse_is_independent_defaults_off_and_changes_only_the_url() {
    let original = load(primary_with_revocation()).unwrap();
    let syntax = &original.rules["custom.legacy"];
    assert!(!syntax.fallbacks[0].reuse_primary_revocation_logic);
    assert!(syntax.selected_revocation(Some("secondary")).unwrap().is_none());
    assert!(matches!(
        syntax.selected_revocation(None).unwrap(),
        Some(std::borrow::Cow::Borrowed(_))
    ));

    let mut rule = primary_with_revocation();
    rule["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
    rule["fallbacks"][0]["revocation_url"] = json!("https://secondary.example/revoke");
    let loaded = load(rule).unwrap();
    let syntax = &loaded.rules["custom.legacy"];
    let selected = syntax.selected_revocation(Some("secondary")).unwrap().unwrap();
    let mut expected = syntax.revocation.clone().unwrap();
    let kingfisher_rules::Revocation::Http(http) = &mut expected else { panic!("HTTP action") };
    http.request.url = "https://secondary.example/revoke".into();
    assert_eq!(selected.as_ref(), &expected);
    assert_eq!(syntax.revocation, original.rules["custom.legacy"].revocation);
    let round_trip: RuleSyntax =
        serde_yaml::from_str(&serde_yaml::to_string(syntax).unwrap()).unwrap();
    assert_eq!(&round_trip, syntax);
}

fn primary_with_multi_step_revocation() -> Value {
    let mut rule = primary_with_revocation();
    let first = json!({"name":"lookup","request":{"method":"GET","url":"https://primary.example/keys",
        "headers":{"Authorization":"Bearer {{ TOKEN }}"}},
        "extract":{"KEY_ID":{"type":"JsonPath","path":"$.id"}}});
    let last = json!({"name":"delete","request":{"method":"DELETE",
        "url":"https://primary.example/keys/{{ KEY_ID }}","body":"{{ TOKEN }}",
        "response_matcher":[{"type":"StatusMatch","status":[204]}]}});
    rule["revocation"] = json!({"type":"HttpMultiStep","content":{"steps":[first,last]}});
    rule
}

#[test]
fn multi_step_reuse_preserves_the_program_and_maps_exactly_one_url_per_step() {
    let mut rule = primary_with_multi_step_revocation();
    rule["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
    rule["fallbacks"][0]["revocation_urls"] =
        json!(["https://secondary.example/keys", "https://secondary.example/keys/{{ KEY_ID }}"]);
    let loaded = load(rule).unwrap();
    let syntax = &loaded.rules["custom.legacy"];
    let mut expected = syntax.revocation.clone().unwrap();
    let kingfisher_rules::Revocation::HttpMultiStep(multi) = &mut expected else {
        panic!("multi-step action")
    };
    multi.steps[0].request.url = "https://secondary.example/keys".into();
    multi.steps[1].request.url = "https://secondary.example/keys/{{ KEY_ID }}".into();
    assert_eq!(syntax.selected_revocation(Some("secondary")).unwrap().unwrap().as_ref(), &expected);
}

#[test]
fn ambiguous_missing_and_wrong_kind_revocation_reuse_is_rejected() {
    for overrides in [
        json!({"revocation_url":"https://secondary.example/revoke"}),
        json!({"revocation_urls":["https://secondary.example/revoke"]}),
        json!({"reuse_primary_revocation_logic":true}),
        json!({"reuse_primary_revocation_logic":true,"revocation_url":" "}),
        json!({"reuse_primary_revocation_logic":true,"revocation_urls":["https://secondary.example/revoke"]}),
        json!({"reuse_primary_revocation_logic":true,"revocation_url":"https://secondary.example/revoke",
            "revocation":primary_with_revocation()["revocation"]}),
    ] {
        let mut rule = primary_with_revocation();
        rule["fallbacks"][0]
            .as_object_mut()
            .unwrap()
            .extend(overrides.as_object().unwrap().clone());
        assert!(load(rule).is_err());
    }
    for action in [Value::Null, json!({"type":"AWS"})] {
        let mut rule = primary_with_revocation();
        rule["revocation"] = action;
        rule["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
        rule["fallbacks"][0]["revocation_url"] = json!("https://secondary.example/revoke");
        assert!(load(rule).is_err());
    }
    for urls in [
        json!([]),
        json!(["https://secondary.example/keys"]),
        json!(["https://secondary.example/keys", " "]),
        json!([
            "https://secondary.example/a",
            "https://secondary.example/b",
            "https://secondary.example/c"
        ]),
    ] {
        let mut rule = primary_with_multi_step_revocation();
        rule["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
        rule["fallbacks"][0]["revocation_urls"] = urls;
        assert!(load(rule).is_err());
    }
}

#[test]
fn logic_reuse_names_round_trip_with_only_the_documented_fields_and_explicit_urls() {
    let mut current = primary_with_revocation();
    current["fallbacks"][0]["reuse_primary_revocation_logic"] = json!(true);
    current["fallbacks"][0]["revocation_url"] = json!("https://secondary.example/revoke");
    let loaded = load(current).unwrap();
    let rule = &loaded.rules["custom.legacy"];
    assert_eq!(
        rule.http_validations(true).unwrap()[1].1.request.url,
        "https://secondary.example/me"
    );
    let serialized = serde_json::to_value(rule).unwrap();
    assert_eq!(serialized["fallbacks"][0]["reuse_primary_validation_logic"], true);
    assert_eq!(serialized["fallbacks"][0]["reuse_primary_revocation_logic"], true);
    assert_eq!(
        serialized["fallbacks"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([
            "id",
            "reuse_primary_validation_logic",
            "url",
            "reuse_primary_revocation_logic",
            "revocation_url"
        ])
    );
    assert_eq!(serde_json::from_value::<RuleSyntax>(serialized).unwrap(), *rule);
}
