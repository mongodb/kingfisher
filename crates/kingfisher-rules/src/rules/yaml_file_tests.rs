use super::{Confidence, RawRules, Rules, RulesError, Validation, load_yaml_file};
use crate::rule::{HttpRequest, Revocation, RuleSyntax};

// Keep these inputs and expectations fixed across YAML implementations. They
// describe the legacy YAML contract, not merely a parser round-trip.
const LEGACY_YAML: &str = r#"rules:
  - id: acme.legacy
    name: yes
    pattern: |-
      (token_[a-z]+)
    tags: [on, off, yes, '0123']
    confidence: MeDiUm
    validation:
      type: Http
      content:
        request:
          method: GET
          url: https://legacy.example.invalid/{{ TOKEN }}
          headers: &headers
            X-Token: '{{ TOKEN }}'
          body: >-
            first line
            second line
          response_matcher: &matchers
            - type: StatusMatch
              status: [200]
    revocation:
      type: Http
      content:
        request:
          method: DELETE
          url:
            - https://legacy.example.invalid/{{ TOKEN }}
            - https://backup.example.invalid/{{ TOKEN }}
          headers: *headers
          response_matcher: *matchers
  - id: acme.defaults
    name: Defaults
    pattern: '(secret_[a-z]+)'
"#;

struct YamlTestFile(std::path::PathBuf);

impl YamlTestFile {
    fn new(content: &[u8]) -> Self {
        Self::with_extension(content, "yml")
    }

    fn with_extension(content: &[u8], extension: &str) -> Self {
        use std::io::Write;
        let path = std::env::temp_dir()
            .join(format!("kingfisher-yaml-loader-{}.{extension}", uuid::Uuid::new_v4()));
        let mut file =
            std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.write_all(content).unwrap();
        drop(file);
        Self(path)
    }
}

impl Drop for YamlTestFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.0).ok();
    }
}

#[test]
fn yaml_file_loader_supports_owned_generic_values() {
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct Settings {
        name: String,
        bytes: Vec<u16>,
        empty: Option<String>,
    }
    let file = YamlTestFile::new("name: clé\nbytes: [0, 255, 65535]\nempty: null\n".as_bytes());
    assert_eq!(
        load_yaml_file::<Settings, _>(&file.0).unwrap(),
        Settings { name: "clé".into(), bytes: vec![0, 255, 65535], empty: None }
    );
    let file = YamlTestFile::new(b"");
    assert_eq!(load_yaml_file::<Option<String>, _>(&file.0).unwrap(), None);
}

#[test]
fn yaml_file_loader_preserves_open_error_context() {
    let file = YamlTestFile::new(b"{}");
    std::fs::remove_file(&file.0).unwrap();
    let error = load_yaml_file::<serde_json::Value, _>(&file.0).unwrap_err();
    assert_eq!(error.to_string(), format!("Failed to open YAML file: {}", file.0.display()));
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn yaml_file_loader_preserves_parse_error_context_and_sources() {
    for input in [b"name: [\n".as_slice(), b"\xff", b"---\n1\n---\n2\n"] {
        let file = YamlTestFile::new(input);
        let error = load_yaml_file::<serde_json::Value, _>(&file.0).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Failed to parse YAML from file: {}", file.0.display())
        );
        let cause = error.downcast_ref::<yaml_serde::Error>().unwrap();
        assert!(!cause.to_string().is_empty());
        if input.starts_with(b"---") {
            assert_eq!(
                cause.to_string(),
                "deserializing from YAML containing more than one document is not supported"
            );
        }
    }
    let file = YamlTestFile::new(b"- 999999999999999999999999999999999999999999");
    let error = load_yaml_file::<Vec<u8>, _>(&file.0).unwrap_err();
    assert_eq!(error.to_string(), format!("Failed to parse YAML from file: {}", file.0.display()));
    assert!(error.downcast_ref::<yaml_serde::Error>().is_some());
}

#[test]
fn legacy_yaml_entrypoints_preserve_defaults_anchors_and_block_scalars() {
    let file = YamlTestFile::new(LEGACY_YAML.as_bytes());
    let raw: RawRules = load_yaml_file(&file.0).unwrap();
    let syntax = RuleSyntax::from_yaml_file(&file.0).unwrap();
    assert_eq!(raw.rules, syntax);
    let memory = Rules::from_paths_and_contents(
        [(file.0.as_path(), LEGACY_YAML.as_bytes())],
        Confidence::Low,
    )
    .unwrap();
    let loaded = Rules::from_yaml_file(&file.0, Confidence::Low).unwrap();
    assert_eq!(memory.rules, loaded.rules);
    let (runtime, prefilter) = Rules::load_runtime_rules([&file.0], Confidence::Low).unwrap();
    assert_eq!(prefilter, loaded.betterleaks_prefilter);
    assert_eq!(runtime.len(), loaded.num_rules());
    for rule in runtime {
        assert_eq!(rule.syntax(), &loaded.rules[rule.id()]);
        assert!(!rule.allow_internal_ips());
    }
    assert_eq!(syntax.len(), 2);
    assert_eq!(syntax[0].name, "yes");
    assert_eq!(syntax[0].pattern, "(token_[a-z]+)");
    assert_eq!(syntax[0].tags, ["on", "off", "yes", "0123"]);
    assert_eq!(syntax[0].confidence, Confidence::Medium);
    assert!(syntax[0].fallbacks.is_empty());
    assert_eq!(syntax[1], RuleSyntax::new("acme.defaults", "Defaults", "(secret_[a-z]+)"));
    let Some(Validation::Http(validation)) = &syntax[0].validation else {
        panic!("expected legacy HTTP validation");
    };
    let Some(Revocation::Http(revocation)) = &syntax[0].revocation else {
        panic!("expected legacy HTTP revocation");
    };
    assert_eq!(validation.request.body.as_deref(), Some("first line second line"));
    assert_eq!(validation.request.headers, revocation.request.headers);
    assert_eq!(validation.request.headers["X-Token"], "{{ TOKEN }}");
    assert_eq!(validation.request.response_matcher, revocation.request.response_matcher);
    assert_eq!(validation.request.fallback_urls, Vec::<String>::new());
    assert!(!validation.request.response_is_html);
    assert_eq!(
        revocation.request.urls().collect::<Vec<_>>(),
        [
            "https://legacy.example.invalid/{{ TOKEN }}",
            "https://backup.example.invalid/{{ TOKEN }}"
        ]
    );
}

#[test]
fn runtime_policy_follows_the_winning_rule_definition() {
    let allowed = YamlTestFile::new(
        br#"rules:
  - id: custom.policy
    name: Permit
    pattern: token
    allow_internal_ips: true
  - id: custom.disabled
    name: Deny
    pattern: token
    allow_internal_ips: false
  - id: custom.default
    name: Default
    pattern: token
  - id: custom.duplicate
    name: Earlier duplicate
    pattern: token
    allow_internal_ips: true
  - id: custom.duplicate
    name: Later duplicate
    pattern: token
"#,
    );
    let replacement = YamlTestFile::new(
        br#"rules:
  - id: custom.policy
    name: Replacement YAML
    pattern: token
    allow_internal_ips: false
"#,
    );
    let toml = YamlTestFile::with_extension(
        br#"[[rules]]
id = "policy"
description = "Replacement TOML"
regex = "(token)"
"#,
        "toml",
    );
    let (rules, _) = Rules::load_runtime_rules([&allowed.0], Confidence::Low).unwrap();
    let requests: Vec<_> =
        rules.iter().filter(|rule| rule.allow_internal_ips()).map(|rule| rule.id()).collect();
    assert_eq!(requests, ["custom.policy"]);

    for later in [&replacement, &toml] {
        let (rules, _) =
            Rules::load_runtime_rules([&allowed.0, &later.0], Confidence::Low).unwrap();
        assert!(rules.iter().all(|rule| !rule.allow_internal_ips()));

        let (rules, _) =
            Rules::load_runtime_rules([&later.0, &allowed.0], Confidence::Low).unwrap();
        assert!(
            rules.iter().find(|rule| rule.id() == "custom.policy").unwrap().allow_internal_ips()
        );
    }
}

#[test]
fn legacy_yaml_rule_sequence_and_mapping_documents_still_load() {
    let rule = "id: acme.sequence\nname: Sequence\npattern: '(secret_[a-z]+)'\n";
    let sequence = format!("- {}", rule.replace('\n', "\n  ").trim_end());
    let mapping = format!("rules:\n  - {}", rule.replace('\n', "\n    ").trim_end());
    let expected = vec![RuleSyntax::new("acme.sequence", "Sequence", "(secret_[a-z]+)")];
    for contents in [sequence, mapping] {
        let file = YamlTestFile::new(contents.as_bytes());
        assert_eq!(RuleSyntax::from_yaml_file(&file.0).unwrap(), expected);
    }
}

#[test]
fn legacy_yaml_http_url_serialization_preserves_scalar_and_ordered_list_shapes() {
    for (url, expected) in [
        (
            "https://one.example.invalid",
            yaml_serde::Value::String("https://one.example.invalid".into()),
        ),
        (
            "[https://one.example.invalid, https://two.example.invalid]",
            yaml_serde::Value::Sequence(vec![
                yaml_serde::Value::String("https://one.example.invalid".into()),
                yaml_serde::Value::String("https://two.example.invalid".into()),
            ]),
        ),
    ] {
        let request: HttpRequest =
            yaml_serde::from_str(&format!("method: GET\nurl: {url}\n")).unwrap();
        let value = yaml_serde::to_value(&request).unwrap();
        assert_eq!(value["url"], expected);
        let emitted = yaml_serde::to_string(&request).unwrap();
        assert_eq!(yaml_serde::from_str::<HttpRequest>(&emitted).unwrap(), request);
    }
    for url in ["[]", "['']", "[https://one.example.invalid, '  ']"] {
        let error =
            yaml_serde::from_str::<HttpRequest>(&format!("method: GET\nurl: {url}\n")).unwrap_err();
        assert!(error.to_string().contains("HTTP url list"));
    }
}

#[test]
fn legacy_yaml_scalar_resolution_and_emission_remain_unchanged() {
    let value: yaml_serde::Value = yaml_serde::from_str(
        "yes: no\nswitch: on\ntruth: true\nnothing: ~\ncode: '0123'\nint: 0x10\nliteral: |-\n  line one\n  line two\n",
    )
    .unwrap();
    assert_eq!(value["yes"].as_str(), Some("no"));
    assert_eq!(value["switch"].as_str(), Some("on"));
    assert_eq!(value["truth"].as_bool(), Some(true));
    assert!(value["nothing"].is_null());
    assert_eq!(value["code"].as_str(), Some("0123"));
    assert_eq!(value["int"].as_i64(), Some(16));
    assert_eq!(value["literal"].as_str(), Some("line one\nline two"));
    let emitted = yaml_serde::to_string(&value).unwrap();
    assert_eq!(
        emitted,
        "yes: no\nswitch: on\ntruth: true\nnothing: null\ncode: '0123'\nint: 16\nliteral: |-\n  line one\n  line two\n"
    );
    for non_boolean in ["yes", "no", "on", "off"] {
        assert!(yaml_serde::from_str::<bool>(non_boolean).is_err());
    }
}

#[test]
fn legacy_yaml_tagged_enums_keep_their_wire_format() {
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    enum LegacyEnum {
        Unit,
        Text(String),
        Fields { enabled: bool },
    }
    let input = "- Unit\n- !Text 'yes'\n- !Fields\n  enabled: true\n";
    let parsed: Vec<LegacyEnum> = yaml_serde::from_str(input).unwrap();
    assert_eq!(
        parsed,
        [LegacyEnum::Unit, LegacyEnum::Text("yes".into()), LegacyEnum::Fields { enabled: true }]
    );
    assert_eq!(
        yaml_serde::to_string(&parsed).unwrap(),
        "- Unit\n- !Text yes\n- !Fields\n  enabled: true\n"
    );
    let value: yaml_serde::Value = yaml_serde::from_str("!Text hello\n").unwrap();
    assert!(matches!(value, yaml_serde::Value::Tagged(_)));
    assert_eq!(yaml_serde::to_string(&value).unwrap(), "!Text hello\n");
}

#[test]
fn legacy_yaml_parse_errors_keep_locations_paths_and_duplicate_key_rejection() {
    let error =
        yaml_serde::from_str::<yaml_serde::Value>("name: first\nname: second\n").unwrap_err();
    assert_eq!(error.to_string(), "duplicate entry with key \"name\"");
    let input = "rules:\n  - id: acme.bad\n    name: Bad\n    pattern: 'unterminated\n";
    let file = YamlTestFile::new(input.as_bytes());
    let parser_error = yaml_serde::from_str::<RawRules>(input).err().unwrap();
    let location = parser_error.location().unwrap();
    let memory =
        Rules::from_paths_and_contents([(file.0.as_path(), input.as_bytes())], Confidence::Low)
            .err()
            .unwrap();
    match memory.downcast_ref::<RulesError>().unwrap() {
        RulesError::InvalidResponseMatcherVariant(path, line, column) => {
            assert_eq!(path, &file.0.display().to_string());
            assert_eq!((*line, *column), (location.line(), location.column()));
        }
        error => panic!("unexpected legacy error category: {error}"),
    }
    let syntax = RuleSyntax::from_yaml_file(&file.0).unwrap_err().to_string();
    assert!(syntax.starts_with(&format!(
        "Failed to parse YAML from {} at line {} column {}:",
        file.0.display(),
        location.line(),
        location.column()
    )));
}
