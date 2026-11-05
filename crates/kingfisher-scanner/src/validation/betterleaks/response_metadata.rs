//! Bounded identity summaries for Kingfisher's opted-in provider capabilities.
//!
//! Preserve the pinned validation programs and their private analysis handoff. This
//! is reporting only: never evaluate `analyze`, make requests, or copy provider maps.

use std::collections::BTreeMap;

use kingfisher_rules::rule::{BetterleaksAccessMapHandler, BetterleaksValidation};
use serde_json::Value as JsonValue;

use super::{BetterleaksValidationOutcome, Value};

const MAX_IDENTITY_FIELD_BYTES: usize = 2048;
// Avoid suppressing identity fields for short auxiliary captures/globals, such as
// region "us" or index "1". Explicit primary/component secrets have no minimum.
const MIN_ECHO_INPUT_BYTES: usize = 8;
static UNSAFE_IDENTITY_CHARACTERS: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r"[\p{Cc}\p{Cf}]").expect("identity character regex must compile")
    });

pub(super) fn include(
    result: &mut BetterleaksValidationOutcome,
    validation: &BetterleaksValidation,
    variables: &BTreeMap<String, Value>,
) {
    if !result.valid {
        return;
    }
    let Some(provider) = validation.capabilities.access_map.as_ref().map(|map| map.handler) else {
        return;
    };
    use BetterleaksAccessMapHandler as Provider;
    // Explicit source paths and output names, not a recursive key-name allowlist:
    // e.g. Hugging Face's auth object and organization memberships remain private.
    let fields: &[(&str, &str)] = match provider {
        Provider::Aws => &[("arn", "/arn"), ("account", "/account"), ("userid", "/userid")],
        Provider::Huggingface => {
            &[("id", "/id"), ("username", "/username"), ("role", "/auth/accessToken/role")]
        }
        Provider::Github => &[("id", "/id"), ("username", "/username")],
        Provider::Gitlab | Provider::Fastly => {
            &[("user_id", "/user_id"), ("token_id", "/token_id")]
        }
        Provider::Circleci => &[("id", "/identity/id"), ("username", "/identity/username")],
        // GCP and Azure already publish their approved identifiers in metadata.
        _ => return,
    };
    let Some(evidence) = result.analysis_data.as_ref().and_then(|value| value.get("analysis"))
    else {
        return;
    };
    let mut inputs = Vec::new();
    for name in ["finding", "components"] {
        if let Some(value) = variables.get(name) {
            if name == "finding" {
                collect_secret(value, &mut inputs);
            } else if let Value::Object(components) = value {
                for component in components.values() {
                    collect_secret(component, &mut inputs);
                }
            }
            collect_inputs(value, &mut inputs);
        }
    }
    let metadata: serde_json::Map<_, _> = fields
        .iter()
        .filter_map(|(name, path)| {
            let value = evidence.pointer(path)?.as_str()?;
            // Do not turn malformed provider data into an unbounded response or
            // accidentally echo primary/component credentials in an identity field.
            if value.len() > MAX_IDENTITY_FIELD_BYTES
                || value.trim().is_empty()
                || UNSAFE_IDENTITY_CHARACTERS.is_match(value)
                || inputs.iter().any(|input| value.contains(input))
                || (provider == Provider::Aws && *name == "arn" && !value.starts_with("arn:"))
                // The pinned GitLab program uses zero for absent numeric IDs.
                || (provider == Provider::Gitlab && value == "0")
                || (provider == Provider::Huggingface
                    && *name == "role"
                    && !matches!(value, "read" | "write" | "fineGrained"))
            {
                return None;
            }
            Some(((*name).to_string(), JsonValue::String(value.to_string())))
        })
        .collect();
    if metadata.is_empty() {
        return;
    }
    let Ok(JsonValue::Object(mut body)) = serde_json::from_str(&result.body) else {
        return;
    };
    let Some(reported) = body
        .entry("metadata")
        .or_insert_with(|| JsonValue::Object(Default::default()))
        .as_object_mut()
    else {
        return;
    };
    for (name, value) in metadata {
        // Explicit public metadata from the rule always takes precedence.
        reported.entry(name).or_insert(value);
    }
    if let Ok(body) = serde_json::to_string(&body) {
        result.body = body;
    }
}

// Explicit credentials remain sensitive regardless of their length. Apply the
// auxiliary-input threshold only after protecting these known secret fields.
fn collect_secret<'a>(value: &'a Value, inputs: &mut Vec<&'a str>) {
    if let Value::Object(fields) = value
        && let Some(Value::String(secret)) = fields.get("secret")
        && !secret.is_empty()
    {
        inputs.push(secret);
    }
}

fn collect_inputs<'a>(value: &'a Value, inputs: &mut Vec<&'a str>) {
    match value {
        Value::String(value) if value.len() >= MIN_ECHO_INPUT_BYTES => inputs.push(value),
        Value::Array(values) => {
            for value in values {
                collect_inputs(value, inputs);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_inputs(value, inputs);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(
        provider: Option<&str>,
        evidence: JsonValue,
        inputs: JsonValue,
    ) -> BetterleaksValidationOutcome {
        let mut validation: BetterleaksValidation =
            serde_json::from_value(serde_json::json!({"expression": "true"})).unwrap();
        if let Some(provider) = provider {
            validation.capabilities.access_map =
                Some(serde_json::from_value(serde_json::json!({"handler": provider})).unwrap());
        }
        let mut result = super::super::classify(Value::from_json(evidence.clone()), None);
        let Value::Object(inputs) = Value::from_json(inputs) else {
            panic!("expected input object");
        };
        include(&mut result, &validation, &inputs);
        assert_eq!(result.analysis_data.as_ref(), Some(&evidence));
        result
    }

    #[test]
    fn identity_metadata_keeps_the_private_handoff_and_explicit_public_fields() {
        let result = response(
            Some("aws"),
            serde_json::json!({
                "result": "valid", "metadata": {"account": "explicit-account", "existing": true},
                "analysis": {"arn": "arn:aws:iam::123456789012:user/example", "account": "123456789012", "userid": "example-user-id", "access_token": "private-token"}
            }),
            serde_json::json!({}),
        );
        let body: JsonValue = serde_json::from_str(&result.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "result": "valid", "metadata": {
                    "arn": "arn:aws:iam::123456789012:user/example", "account": "explicit-account",
                    "userid": "example-user-id", "existing": true
                }
            })
        );
        assert!(!format!("{result:?}").contains("example-user-id"));
        assert!(!result.body.contains("private-token"));
    }

    #[test]
    fn identity_metadata_requires_a_supported_capability_and_successful_validation() {
        for provider in [None, Some("openai"), Some("gcp"), Some("azure_client_secret")] {
            let result = response(
                provider,
                serde_json::json!({"result":"valid", "analysis":{"arn":"private-arn", "id":"private-id"}}),
                serde_json::json!({}),
            );
            assert_eq!(result.body, r#"{"result":"valid"}"#);
        }
        for status in ["invalid", "revoked", "unknown", "skipped"] {
            let result = response(
                Some("aws"),
                serde_json::json!({"result":status, "analysis":{"arn":"unconfirmed-arn"}}),
                serde_json::json!({}),
            );
            assert!(!result.body.contains("unconfirmed-arn"));
            assert!(!result.body.contains("metadata"));
        }
    }

    #[test]
    fn identity_metadata_omits_malformed_empty_oversized_and_secret_bearing_fields() {
        for value in [
            JsonValue::Null,
            serde_json::json!(42),
            serde_json::json!({"access_token":"private-token"}),
            serde_json::json!(["private-token"]),
            serde_json::json!("  "),
            serde_json::json!("alice\nforged-line"),
            serde_json::json!("alice\u{202e}forged"),
            serde_json::json!("alice\u{200b}hidden"),
            serde_json::json!("alice\u{2066}isolated\u{2069}"),
            serde_json::json!("x".repeat(2049)),
            serde_json::json!("Bearer primary-secret"),
            serde_json::json!("prefix-component-secret"),
            serde_json::json!("capture-secret"),
        ] {
            let result = response(
                Some("huggingface"),
                serde_json::json!({"result":"valid", "analysis":{"username":value}}),
                serde_json::json!({
                    "finding":{"secret":"primary-secret", "captures":{"token":"capture-secret"}},
                    "components":{"helper":{"secret":"component-secret"}}
                }),
            );
            assert_eq!(result.body, r#"{"result":"valid"}"#);
        }
    }

    #[test]
    fn identity_metadata_omits_short_primary_and_component_secret_echoes() {
        for secret in ["x", "short", "秘密"] {
            for inputs in [
                serde_json::json!({"finding":{"secret":secret}}),
                serde_json::json!({"components":{"helper":{"secret":secret}}}),
            ] {
                let result = response(
                    Some("github"),
                    serde_json::json!({
                        "result":"valid", "analysis":{"username":format!("user-{secret}")}
                    }),
                    inputs,
                );
                assert_eq!(result.body, r#"{"result":"valid"}"#);
            }
        }
        let result = response(
            Some("github"),
            serde_json::json!({"result":"valid", "analysis":{"username":"user"}}),
            serde_json::json!({
                "finding":{"secret":""}, "components":{"helper":{"secret":""}}
            }),
        );
        let body: JsonValue = serde_json::from_str(&result.body).unwrap();
        assert_eq!(body["metadata"], serde_json::json!({"username":"user"}));
    }

    #[test]
    fn short_captures_do_not_suppress_real_identity_values() {
        let result = response(
            Some("github"),
            serde_json::json!({"result":"valid", "analysis":{"id":"12345", "username":"user"}}),
            serde_json::json!({"finding":{"secret":"primary-secret", "captures":{"index":"1", "region":"us"}}}),
        );
        let body: JsonValue = serde_json::from_str(&result.body).unwrap();
        assert_eq!(body["metadata"], serde_json::json!({"id":"12345", "username":"user"}));
    }

    #[test]
    fn identity_metadata_never_copies_huggingface_auth_or_organization_objects() {
        let result = response(
            Some("huggingface"),
            serde_json::json!({
                "result":"valid", "analysis":{
                    "id":"user-7", "username":"alice", "email":"private@example.test",
                    "orgs":[{"id":"organization-8", "secret":"org-secret"}],
                    "auth":{"accessToken":{"role":"fineGrained", "token":"minted-secret", "fineGrained":{"scoped":["private-grants"]}}}
                }
            }),
            serde_json::json!({}),
        );
        assert_eq!(
            serde_json::from_str::<JsonValue>(&result.body).unwrap(),
            serde_json::json!({
                "result":"valid", "metadata":{"id":"user-7", "username":"alice", "role":"fineGrained"}
            })
        );
    }

    #[test]
    fn identity_metadata_preserves_non_object_metadata_and_missing_evidence() {
        for metadata in [JsonValue::Null, serde_json::json!([]), serde_json::json!("custom")] {
            let result = response(
                Some("aws"),
                serde_json::json!({"result":"valid", "metadata":metadata, "analysis":{"arn":"arn:aws:iam::123456789012:root"}}),
                serde_json::json!({}),
            );
            assert_eq!(
                serde_json::from_str::<JsonValue>(&result.body).unwrap(),
                serde_json::json!({"result":"valid", "metadata":metadata})
            );
        }
        for analysis in [JsonValue::Null, serde_json::json!({}), serde_json::json!([])] {
            let result = response(
                Some("aws"),
                serde_json::json!({"result":"valid", "analysis":analysis}),
                serde_json::json!({}),
            );
            assert_eq!(result.body, r#"{"result":"valid"}"#);
        }
        for (provider, analysis) in [
            ("aws", serde_json::json!({"arn":"Unknown"})),
            ("gitlab", serde_json::json!({"user_id":"0", "token_id":"0"})),
            ("huggingface", serde_json::json!({"auth":{"accessToken":{"role":"opaque-secret"}}})),
        ] {
            let result = response(
                Some(provider),
                serde_json::json!({"result":"valid", "analysis":analysis}),
                serde_json::json!({}),
            );
            assert_eq!(result.body, r#"{"result":"valid"}"#);
        }
    }
}
