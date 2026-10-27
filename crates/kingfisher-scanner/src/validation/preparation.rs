//! Offline, credential-free input inspection using the execution template parser.
use std::collections::{BTreeMap, BTreeSet};

use kingfisher_rules::{HttpRequest, MultipartConfig, ResponseExtractor, Revocation, Validation};
use liquid::{Object, model::Value};
use serde::Serialize;

use super::{http_validation::with_request_template_globals, template_vars::extract_template_vars};

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
    if parsed.render(globals).is_ok() {
        return;
    }
    let missing: Vec<_> = extract_template_vars(text)
        .into_iter()
        .filter(|name| !globals.contains_key(name.as_str()))
        .collect();
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
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
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
            request(parser, &http.request, &globals, "validation", diagnostics);
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
            request(parser, &http.request, &globals, "revocation", diagnostics);
            multipart(parser, http.multipart.as_ref(), &globals, "revocation", diagnostics);
        }
        Revocation::HttpMultiStep(multi) => {
            for step in &multi.steps {
                request(parser, &step.request, &globals, "revocation", diagnostics);
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
