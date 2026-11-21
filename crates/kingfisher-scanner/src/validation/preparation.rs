//! Offline, credential-free input inspection using the execution template parser.
use std::collections::{BTreeMap, BTreeSet};

use kingfisher_rules::{HttpRequest, MultipartConfig, ResponseExtractor, Revocation, Validation};
use liquid::{Object, model::Value};
use serde::Serialize;

use super::{
    http_validation::with_request_template_globals,
    template_vars::{extract_template_vars, required_template_vars},
};

/// One actionable input issue. Contains names and categories, never input values,
/// rendered URLs, template source, or provider/parser error text.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct CredentialInputDiagnostic {
    /// dependency, validation, or revocation.
    pub stage: &'static str,
    /// missing_dependency, ambiguous_dependency, missing_variable,
    /// redacted_input, or invalid_configuration.
    pub code: &'static str,
    pub variable: Option<String>,
    /// Supporting detector ID when this issue concerns a component.
    pub rule_id: Option<String>,
}

impl CredentialInputDiagnostic {
    pub(crate) fn new(stage: &'static str, code: &'static str, variable: Option<String>) -> Self {
        Self { stage, code, variable, rule_id: None }
    }
}

fn template(
    parser: &liquid::Parser,
    text: &str,
    globals: &Object,
    stage: &'static str,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    let Ok(parsed) = parser.parse(text) else {
        diagnostics.push(CredentialInputDiagnostic::new(stage, "invalid_configuration", None));
        return;
    };
    let missing = |text: &str| -> Vec<String> {
        extract_template_vars(text)
            .into_iter()
            .filter(|name| !globals.contains_key(name.as_str()))
            .collect()
    };
    // Never repeat crypto execution (including randomness) during offline preparation.
    // Only provable external requirements are authoritative here; the legacy lexical
    // extractor does not understand local bindings, optional branches, or object paths.
    if kingfisher_rules::liquid_filters::template_uses_crypto_filters(text) {
        diagnostics.extend(
            required_template_vars(text)
                .into_iter()
                .filter(|name| !globals.contains_key(name.as_str()))
                .map(|name| CredentialInputDiagnostic::new(stage, "missing_variable", Some(name))),
        );
        return;
    }
    if parsed.render(globals).is_ok() {
        return;
    }
    let missing = missing(text);
    if missing.is_empty() {
        diagnostics.push(CredentialInputDiagnostic::new(stage, "invalid_configuration", None));
    } else {
        // This is advisory lexical naming after a real render failure. Conditional
        // expressions/filter fallbacks can over-report names; no parser error or
        // rendered secret is retained. Liquid control-flow tags may lack names.
        diagnostics.extend(
            missing
                .into_iter()
                .map(|name| CredentialInputDiagnostic::new(stage, "missing_variable", Some(name))),
        );
    }
}

fn multipart(
    parser: &liquid::Parser,
    config: Option<&MultipartConfig>,
    globals: &Object,
    stage: &'static str,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    if let Some(config) = config {
        for part in &config.parts {
            template(parser, &part.name, globals, stage, diagnostics);
            template(parser, &part.content, globals, stage, diagnostics);
            if let Some(content_type) = &part.content_type {
                template(parser, content_type, globals, stage, diagnostics);
            }
        }
    }
}

fn request(
    parser: &liquid::Parser,
    request: &HttpRequest,
    globals: &Object,
    stage: &'static str,
    endpoint_index: Option<usize>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    if let Some(index) = endpoint_index.filter(|_| !request.fallback_urls.is_empty()) {
        if let Some(url) = request.urls().nth(index) {
            template(parser, url, globals, stage, diagnostics);
        } else {
            diagnostics.push(CredentialInputDiagnostic::new(stage, "invalid_configuration", None));
        }
    } else {
        let mut url_diagnostics = Vec::new();
        let mut renderable = false;
        for url in request.urls() {
            let mut issues = Vec::new();
            template(parser, url, globals, stage, &mut issues);
            renderable |= issues.is_empty();
            url_diagnostics.extend(issues);
        }
        if !renderable {
            diagnostics.extend(url_diagnostics);
        }
    }
    for (name, value) in &request.headers {
        template(parser, name, globals, stage, diagnostics);
        template(parser, value, globals, stage, diagnostics);
    }
    if let Some(body) = &request.body {
        template(parser, body, globals, stage, diagnostics);
    }
    multipart(parser, request.multipart.as_ref(), globals, stage, diagnostics);
}

/// Inspect only executable alternatives. Retain template diagnostics only when
/// no enabled configuration is usable. This performs no network requests.
pub fn rule_validation(
    parser: &liquid::Parser,
    rule: &kingfisher_rules::RuleSyntax,
    http_fallbacks: bool,
    values: &BTreeMap<String, String>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    if matches!(rule.validation, Some(Validation::Http(_))) {
        let configurations = match rule.http_validations(http_fallbacks) {
            Ok(configurations) => configurations,
            Err(_) => {
                diagnostics.push(CredentialInputDiagnostic::new(
                    "validation",
                    "invalid_configuration",
                    None,
                ));
                return;
            }
        };
        let mut all_issues = Vec::new();
        for (_, http) in configurations {
            let mut issues = Vec::new();
            validation(parser, Some(&Validation::Http(http)), values, &mut issues);
            if issues.is_empty() {
                return;
            }
            all_issues.extend(issues);
        }
        diagnostics.extend(all_issues);
    } else {
        validation(parser, rule.validation.as_ref(), values, diagnostics);
    }
}

pub(crate) fn validation(
    parser: &liquid::Parser,
    validation: Option<&Validation>,
    values: &BTreeMap<String, String>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    let globals = with_request_template_globals(
        &values.iter().map(|(k, v)| (k.clone().into(), Value::scalar(v.clone()))).collect(),
    );
    let required = match validation {
        Some(Validation::Http(http)) => {
            request(parser, &http.request, &globals, "validation", None, diagnostics);
            multipart(parser, http.multipart.as_ref(), &globals, "validation", diagnostics);
            BTreeSet::new()
        }
        Some(Validation::Grpc(grpc)) => {
            template(parser, &grpc.request.url, &globals, "validation", diagnostics);
            for (name, value) in &grpc.request.headers {
                template(parser, name, &globals, "validation", diagnostics);
                template(parser, value, &globals, "validation", diagnostics);
            }
            if let Some(body) = &grpc.request.body {
                template(parser, body, &globals, "validation", diagnostics);
            }
            BTreeSet::new()
        }
        Some(Validation::AWS) => {
            if has_value(values, &["AKID", "ACCESS_KEY_ID"]) {
                BTreeSet::new()
            } else {
                BTreeSet::from(["AKID".into()])
            }
        }
        Some(Validation::AzureStorage) => {
            if has_value(values, &["AZURENAME", "STORAGE_ACCOUNT"])
                || values.get("TOKEN").is_some_and(|token| token.trim_start().starts_with('{'))
            {
                BTreeSet::new()
            } else {
                BTreeSet::from(["AZURENAME".into()])
            }
        }
        Some(Validation::Coinbase) => {
            if has_value(values, &["CRED_NAME", "KEY_ID"]) {
                BTreeSet::new()
            } else {
                BTreeSet::from(["CRED_NAME".into()])
            }
        }
        Some(Validation::Raw(raw)) => super::raw::required_vars(raw),
        // Betterleaks optional components/conditional expression branches are
        // handled by its evaluator; don't assume every component is required.
        _ => BTreeSet::new(),
    };
    for name in required {
        if !has_value(values, &[&name]) {
            diagnostics.push(CredentialInputDiagnostic::new(
                "validation",
                "missing_variable",
                Some(name),
            ));
        }
    }
}

/// Inspect revocation inputs offline. Placeholders do not establish a validated target.
pub fn revocation(
    parser: &liquid::Parser,
    revocation: &Revocation,
    values: &BTreeMap<String, String>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    revocation_with_endpoint(parser, revocation, values, None, diagnostics);
}

// The optional index must come from the validator's private accepted-endpoint
// snapshot, not from caller-provided VALIDATION_* variables.
pub(crate) fn revocation_with_endpoint(
    parser: &liquid::Parser,
    revocation: &Revocation,
    values: &BTreeMap<String, String>,
    endpoint_index: Option<usize>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    let mut globals = with_request_template_globals(
        &values.iter().map(|(k, v)| (k.clone().into(), Value::scalar(v.clone()))).collect(),
    );
    // These values come from successful validation, not caller inputs. Preflight
    // only checks template syntax; the revoker still requires a real selection.
    for (name, placeholder) in [
        ("VALIDATION_ENDPOINT_INDEX", "0"),
        ("VALIDATION_ENDPOINT_COUNT", "1"),
        ("VALIDATION_URL", "https://prepared.example/identity"),
        ("VALIDATION_ORIGIN", "https://prepared.example"),
    ] {
        globals.entry(name).or_insert_with(|| Value::scalar(placeholder));
    }
    match revocation {
        Revocation::AWS => {
            if !has_value(values, &["AKID", "ACCESS_KEY_ID"]) {
                diagnostics.push(CredentialInputDiagnostic::new(
                    "revocation",
                    "missing_variable",
                    Some("AKID".into()),
                ));
            }
        }
        Revocation::GCP | Revocation::Betterleaks(_) => {} // Expression branches handle optional inputs.
        Revocation::Http(http) => {
            request(parser, &http.request, &globals, "revocation", endpoint_index, diagnostics);
            multipart(parser, http.multipart.as_ref(), &globals, "revocation", diagnostics);
        }
        Revocation::HttpMultiStep(multi) => {
            for step in &multi.steps {
                request(parser, &step.request, &globals, "revocation", endpoint_index, diagnostics);
                multipart(parser, step.multipart.as_ref(), &globals, "revocation", diagnostics);
                for extractor in step.extract.iter().flat_map(|extract| extract.values()) {
                    let text = match extractor {
                        ResponseExtractor::JsonPath { path } => path,
                        ResponseExtractor::Regex { pattern } => pattern,
                        ResponseExtractor::Header { name } => name,
                        ResponseExtractor::Body | ResponseExtractor::StatusCode => continue,
                    };
                    template(parser, text, &globals, "revocation", diagnostics);
                }
                // Response-derived values are not caller inputs. Only earlier
                // steps supply them; a later extraction cannot satisfy step one.
                for name in step.extract.iter().flat_map(|extract| extract.keys()) {
                    globals.insert(
                        name.to_uppercase().into(),
                        Value::scalar("prepared-response-value"),
                    );
                }
            }
        }
    }
}

fn has_value(values: &BTreeMap<String, String>, names: &[&str]) -> bool {
    names.iter().any(|name| values.get(*name).is_some_and(|value| !value.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_templates_are_checked_lexically_not_rendered() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let globals = liquid::object!({"TOKEN": "secret"});
        // Out-of-range PBKDF2 would fail a speculative render; preparation must not run it.
        let source = "{{ TOKEN | b64enc | pbkdf2_sha256: '', 1000001, 32 }}";
        let mut diagnostics = Vec::new();
        template(&parser, source, &globals, "validation", &mut diagnostics);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        let source = "{{ MISSING | ecdsa_sign: TOKEN, 'P-256' }}";
        template(&parser, source, &globals, "validation", &mut diagnostics);
        assert_eq!(
            diagnostics,
            [CredentialInputDiagnostic::new(
                "validation",
                "missing_variable",
                Some("MISSING".into())
            )]
        );
    }

    #[test]
    fn crypto_preparation_accepts_locals_and_optional_control_flow_without_rendering() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let globals = liquid::object!({"TOKEN": "not-base64"});
        let source = "{%- assign derived = TOKEN | pbkdf2_sha256: '', 1000001, 32 -%}\n\
             {%- capture proof -%}{{ derived }}{%- endcapture -%}\n\
             {% if false %}{{ UNREACHABLE | sha512 }}{% endif %}\n\
             {% for item in OPTIONAL_ITEMS %}{{ item | sha512 }}{% endfor %}\n\
             {{ proof }}";
        let mut diagnostics = Vec::new();
        template(&parser, source, &globals, "validation", &mut diagnostics);
        // Invalid Base64 and out-of-range PBKDF2 would fail any speculative render.
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn crypto_preparation_checks_exact_global_roots_and_simple_filter_arguments() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let globals = liquid::object!({
            "TOKEN": "not-base64", "account": {"id": "tenant"}, "lowercase": "present"
        });
        let mut diagnostics = Vec::new();
        for source in [
            "{{ account.id | sha512 }}{{ lowercase | sha512 }}",
            "{{ OPTIONAL | default: TOKEN | sha512 }}",
            r"{{ TOKEN | append: '\' | append: '| ecdsa_sign: MISSING }}' | sha512 }}",
            r#"{{ TOKEN | append: "\" | append: "| ecdsa_sign: MISSING }}" | sha512 }}"#,
        ] {
            template(&parser, source, &globals, "validation", &mut diagnostics);
        }
        assert!(diagnostics.is_empty(), "{diagnostics:?}");

        template(
            &parser,
            "{{ TOKEN | ecdsa_sign: SIGNING_KEY, 'P-256' }}{{ MISSING_ACCOUNT.id | sha512 }}\
             {{ TOKEN | hmac_sha512: HMAC_KEY }}",
            &globals,
            "validation",
            &mut diagnostics,
        );
        assert_eq!(
            diagnostics,
            ["HMAC_KEY", "MISSING_ACCOUNT", "SIGNING_KEY"].map(|name| {
                CredentialInputDiagnostic::new("validation", "missing_variable", Some(name.into()))
            })
        );
    }

    #[test]
    fn packaged_crypto_scaffold_prepares_without_executing_crypto() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let source = include_str!("../../examples/rules/cryptographic-auth.yml");
        let rules = kingfisher_rules::Rules::from_paths_and_contents(
            [(std::path::Path::new("cryptographic-auth.yml"), source.as_bytes())],
            kingfisher_rules::Confidence::Low,
        )
        .unwrap();
        let rule = rules.rules.get("custom.crypto-demo.liquid-p256").unwrap();
        // Deliberately invalid signing material makes rendering inappropriate here.
        let values = BTreeMap::from([
            ("TOKEN".into(), "not-base64".into()),
            ("CLIENT_ID".into(), "tenant-fixture".into()),
        ]);
        let mut diagnostics = Vec::new();
        rule_validation(&parser, rule, false, &values, &mut diagnostics);
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
    }

    #[test]
    fn crypto_revocation_preparation_only_uses_earlier_extractor_values() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let values = BTreeMap::from([("TOKEN".into(), "not-base64".into())]);
        for (first_body, missing) in [("lookup", false), ("{{ CHALLENGE | sha512 }}", true)] {
            let action: Revocation = serde_json::from_value(serde_json::json!({
                "type": "HttpMultiStep",
                "content": {"steps": [
                    {"request": {"method": "GET", "url": "https://example.invalid/lookup",
                                 "body": first_body},
                     "extract": {"CHALLENGE": {"type": "Body"}}},
                    {"request": {"method": "DELETE", "url": "{{ VALIDATION_ORIGIN }}/revoke",
                                 "body": "{% assign signed = CHALLENGE | ecdsa_sign: TOKEN, 'P-256' %}{{ signed }}"}}
                ]}
            }))
            .unwrap();
            let mut diagnostics = Vec::new();
            revocation(&parser, &action, &values, &mut diagnostics);
            if missing {
                assert_eq!(
                    diagnostics,
                    [CredentialInputDiagnostic::new(
                        "revocation",
                        "missing_variable",
                        Some("CHALLENGE".into())
                    )]
                );
            } else {
                assert!(diagnostics.is_empty(), "{diagnostics:?}");
            }
        }
    }

    #[test]
    fn legacy_preparation_still_renders_before_lexical_missing_checks() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let globals = liquid::object!({"TOKEN": "secret"});
        let mut diagnostics = Vec::new();
        template(
            &parser,
            "{% assign local = TOKEN %}{{ local }}{% if false %}{{ MISSING }}{% endif %}",
            &globals,
            "validation",
            &mut diagnostics,
        );
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        template(
            &parser,
            "{{ TOKEN | slice: 'not-an-integer' }}",
            &globals,
            "validation",
            &mut diagnostics,
        );
        assert_eq!(
            diagnostics,
            [CredentialInputDiagnostic::new("validation", "invalid_configuration", None)]
        );
    }
}
