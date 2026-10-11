//! Offline, credential-free input inspection using the execution template parser.
use std::collections::{BTreeMap, BTreeSet};

use kingfisher_rules::{HttpRequest, MultipartConfig, Revocation, Validation};
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
    template(parser, &request.url, globals, stage, diagnostics);
    for (name, value) in &request.headers {
        template(parser, name, globals, stage, diagnostics);
        template(parser, value, globals, stage, diagnostics);
    }
    if let Some(body) = &request.body {
        template(parser, body, globals, stage, diagnostics);
    }
    multipart(parser, request.multipart.as_ref(), globals, stage, diagnostics);
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

pub(crate) fn revocation(
    parser: &liquid::Parser,
    revocation: &Revocation,
    values: &BTreeMap<String, String>,
    diagnostics: &mut Vec<CredentialInputDiagnostic>,
) {
    let mut globals = with_request_template_globals(
        &values.iter().map(|(k, v)| (k.clone().into(), Value::scalar(v.clone()))).collect(),
    );
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
        Revocation::GCP => {} // KEY_ID can come from the service-account JSON.
        Revocation::Http(http) => {
            request(parser, &http.request, &globals, "revocation", diagnostics);
            multipart(parser, http.multipart.as_ref(), &globals, "revocation", diagnostics);
        }
        Revocation::HttpMultiStep(multi) => {
            for step in &multi.steps {
                request(parser, &step.request, &globals, "revocation", diagnostics);
                multipart(parser, step.multipart.as_ref(), &globals, "revocation", diagnostics);
                // Response-derived values are not caller inputs. Only earlier
                // steps supply them; a later extraction cannot satisfy step one.
                for name in step.extract.iter().flat_map(|extract| extract.keys()) {
                    globals.insert(name.clone().into(), Value::scalar("prepared-response-value"));
                }
            }
        }
    }
}

fn has_value(values: &BTreeMap<String, String>, names: &[&str]) -> bool {
    names.iter().any(|name| values.get(*name).is_some_and(|value| !value.is_empty()))
}
