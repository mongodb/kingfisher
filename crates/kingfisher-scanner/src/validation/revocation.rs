//! Shared HTTP revocation execution used by the CLI and language bindings.
//! Callers must explicitly authorize revocation and configure transport policy.
use super::{build_request_builder, validate_response};
use anyhow::{Context, Result, anyhow, bail};
use kingfisher_rules::{
    HttpMultiStepRevocation, HttpRequest, HttpValidation, ResponseExtractor, RevocationStep,
};
use liquid::{Object, model::Value};
use regex::Regex;
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::Serialize;
use std::time::Duration;
use tracing::debug;

/// An error after submission cannot prove that a remote mutation did not happen.
#[derive(Debug, thiserror::Error)]
#[error("revocation request may have been sent; verify provider state before retrying")]
#[doc(hidden)]
pub struct RevocationSubmitted;

/// A provider program completed without confirming whether revocation happened.
/// This is an indeterminate outcome and must not be treated as a safe retry.
#[derive(Debug, thiserror::Error)]
#[error("provider could not confirm credential revocation; verify provider state before retrying")]
pub struct RevocationIndeterminate;

fn submitted_error(error: anyhow::Error, may_mutate: bool) -> anyhow::Error {
    if may_mutate { error.context(RevocationSubmitted) } else { error }
}

fn is_mutating_method(method: &str) -> bool {
    !matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
}

fn selected_url<'a>(request: &'a HttpRequest, globals: &Object) -> Result<&'a str> {
    if request.fallback_urls.is_empty() {
        return Ok(&request.url);
    }
    use liquid_core::ValueView;
    let index = globals
        .get("VALIDATION_ENDPOINT_INDEX")
        .and_then(|value| value.to_kstr().parse::<usize>().ok())
        .context(
            "Revocation URL lists require VALIDATION_ENDPOINT_INDEX from successful validation",
        )?;
    request.urls().nth(index).context("Validated endpoint index is outside the revocation URL list")
}

async fn send_revocation_request(
    request: RequestBuilder,
    retries: u32,
    may_mutate: bool,
) -> Result<Response> {
    // Resolve deferred builder errors before any request can be submitted.
    let (client, request) = request.build_split();
    let request = request.context("Cannot build revocation request")?;
    for attempt in 0..=retries {
        let response = client
            .execute(request.try_clone().context("Cannot clone revocation request")?)
            .await
            .map_err(|error| {
                let could_submit = may_mutate && !error.is_builder();
                submitted_error(error.into(), could_submit)
            })?;
        // A custom endpoint can return 429 after applying a mutation. Only
        // read-only lookup steps can safely retry rate-limited requests.
        if response.status() != StatusCode::TOO_MANY_REQUESTS || may_mutate || attempt == retries {
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                return response
                    .error_for_status()
                    .map_err(|error| submitted_error(error.into(), may_mutate));
            }
            if response.status().is_server_error()
                || response.status() == StatusCode::REQUEST_TIMEOUT
            {
                return response
                    .error_for_status()
                    .map_err(|error| submitted_error(error.into(), may_mutate));
            }
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_millis(100 * (1u64 << attempt.min(4)))).await;
    }
    unreachable!("bounded HTTP retry loop always returns")
}

/// Result of a direct revocation attempt.
#[derive(Debug, Clone, Serialize)]
pub struct DirectRevocationResult {
    /// The rule ID that was used for revocation.
    pub rule_id: String,
    /// The rule name.
    pub rule_name: String,
    /// Whether the secret was revoked successfully.
    pub revoked: bool,
    /// HTTP status code from the revocation request (if applicable).
    pub status_code: Option<u16>,
    /// Response body or error message.
    pub message: String,
}

/// Render the revocation URL using Liquid templates.
async fn render_and_parse_url(
    parser: &liquid::Parser,
    globals: &Object,
    url_template: &str,
) -> Result<reqwest::Url> {
    let template =
        parser.parse(url_template).map_err(|e| anyhow!("Failed to parse URL template: {}", e))?;

    let rendered =
        template.render(globals).map_err(|e| anyhow!("Failed to render URL template: {}", e))?;

    reqwest::Url::parse(&rendered).map_err(|e| anyhow!("Invalid URL '{}': {}", rendered, e))
}

async fn revocation_url(
    parser: &liquid::Parser,
    globals: &Object,
    request: &HttpRequest,
) -> Result<reqwest::Url> {
    use liquid_core::ValueView;
    let url = render_and_parse_url(parser, globals, selected_url(request, globals)?).await?;
    let fallback_validation = globals
        .get("VALIDATION_ENDPOINT_COUNT")
        .is_some_and(|value| value.to_kstr().parse::<usize>().is_ok_and(|count| count > 1))
        && globals.get("VALIDATION_ENDPOINT_INDEX").is_none_or(|value| value.to_kstr() != "0");
    if fallback_validation
        || globals.contains_key("VALIDATION_FALLBACK_ID")
        || !request.fallback_urls.is_empty()
    {
        let accepted_origin = globals
            .get("VALIDATION_ORIGIN")
            .context("Fallback revocation requires VALIDATION_ORIGIN from successful validation")?;
        anyhow::ensure!(
            accepted_origin.to_kstr() == url.origin().ascii_serialization(),
            "Revocation must use the origin that accepted the credential; use VALIDATION_ORIGIN or a matching URL list"
        );
    }
    Ok(url)
}

/// Render Liquid templates within an extractor's string fields.
///
/// This allows extraction patterns/paths to use `{{ TOKEN | prefix: 8 }}` etc.
/// so that multi-step revocations can locate the correct item in a list response.
fn render_extractor(
    extractor: &ResponseExtractor,
    parser: &liquid::Parser,
    globals: &Object,
) -> Result<ResponseExtractor> {
    let render = |template_str: &str| -> Result<String> {
        if !template_str.contains("{{") && !template_str.contains("{%") {
            return Ok(template_str.to_string());
        }
        let template = parser
            .parse(template_str)
            .map_err(|e| anyhow!("Failed to parse extractor template: {}", e))?;
        template.render(globals).map_err(|e| anyhow!("Failed to render extractor template: {}", e))
    };

    match extractor {
        ResponseExtractor::JsonPath { path } => {
            Ok(ResponseExtractor::JsonPath { path: render(path)? })
        }
        ResponseExtractor::Regex { pattern } => {
            Ok(ResponseExtractor::Regex { pattern: render(pattern)? })
        }
        ResponseExtractor::Header { name } => Ok(ResponseExtractor::Header { name: render(name)? }),
        // Body and StatusCode have no string fields to render
        other => Ok(other.clone()),
    }
}

fn truncate_with_ellipsis(input: &str, max_chars: usize) -> String {
    let truncated: String = input.chars().take(max_chars).collect();
    if input.chars().count() > max_chars { format!("{}...", truncated) } else { input.to_string() }
}

/// Extract a value from an HTTP response using the specified extractor.
fn extract_value_from_response(
    extractor: &ResponseExtractor,
    body: &str,
    headers: &reqwest::header::HeaderMap,
    status: &reqwest::StatusCode,
) -> Result<String> {
    match extractor {
        ResponseExtractor::JsonPath { path } => {
            let json: serde_json::Value =
                serde_json::from_str(body).context("Response body is not valid JSON")?;

            // Simple JSONPath implementation supporting basic paths like:
            // $.field, $.field.nested, $.array[0], $.array[0].field, $[0], $[0].field
            let normalized = path.trim_start_matches('$').trim_start_matches('.');
            let path_parts: Vec<&str> = normalized.split('.').collect();

            let mut current = &json;
            for part in path_parts {
                if let Some((array_name, index_str)) = part.split_once('[') {
                    let index: usize =
                        index_str.trim_end_matches(']').parse().context("Invalid array index")?;

                    if !array_name.is_empty() {
                        current = current
                            .get(array_name)
                            .ok_or_else(|| anyhow!("Field '{}' not found", array_name))?;
                    }

                    current = current
                        .get(index)
                        .ok_or_else(|| anyhow!("Array index {} not found", index))?;
                } else {
                    current =
                        current.get(part).ok_or_else(|| anyhow!("Field '{}' not found", part))?;
                }
            }

            match current {
                serde_json::Value::String(s) => Ok(s.clone()),
                serde_json::Value::Number(n) => Ok(n.to_string()),
                serde_json::Value::Bool(b) => Ok(b.to_string()),
                _ => Ok(current.to_string()),
            }
        }
        ResponseExtractor::Regex { pattern } => {
            let re = Regex::new(pattern).context(format!("Invalid regex pattern: {}", pattern))?;
            let caps = re
                .captures(body)
                .ok_or_else(|| anyhow!("Regex pattern did not match response body"))?;

            caps.get(1)
                .map(|m| m.as_str().to_string())
                .ok_or_else(|| anyhow!("No capture group found in regex pattern"))
        }
        ResponseExtractor::Header { name } => headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Header '{}' not found in response", name)),
        ResponseExtractor::Body => Ok(body.to_string()),
        ResponseExtractor::StatusCode => Ok(status.as_u16().to_string()),
    }
}

/// Execute HTTP revocation against the provided rule.
pub async fn execute_http_revocation(
    http_revocation: &HttpValidation,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
) -> Result<DirectRevocationResult> {
    anyhow::ensure!(http_revocation.auth.is_none(), "OAuth2 auth is supported for validation only");
    let matchers = http_revocation
        .request
        .response_matcher
        .as_deref()
        .filter(|matchers| !matchers.is_empty())
        .context("Revocation response_matcher is required")?;
    let url = revocation_url(parser, globals, &http_revocation.request).await?;

    debug!("Submitting HTTP revocation");

    let request_builder = build_request_builder(
        client,
        &http_revocation.request.method,
        &url,
        &http_revocation.request.headers,
        &http_revocation.request.body,
        timeout,
        parser,
        globals,
    )
    .map_err(|e| anyhow!("Failed to build request: {e}"))?;

    let response =
        send_revocation_request(request_builder, retries, true).await.context("Request failed")?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .context("Failed to read response body")
        .context(RevocationSubmitted)?;

    let display_body = truncate_with_ellipsis(&body, 500);
    let body_len = body.chars().count();

    debug!("Revocation response status: {}", status);
    debug!("Revocation response body (len={}): {}", body_len, display_body);

    let html_allowed = http_revocation.request.response_is_html;
    let revoked = validate_response(matchers, &body, &status, &headers, html_allowed);

    Ok(DirectRevocationResult {
        rule_id: String::new(),
        rule_name: String::new(),
        revoked,
        status_code: Some(status.as_u16()),
        message: display_body,
    })
}

/// Execute a single revocation step and extract variables from the response.
#[allow(clippy::too_many_arguments)]
async fn execute_revocation_step(
    step: &RevocationStep,
    globals: &mut Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
    step_number: usize,
    is_final_step: bool,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String)> {
    let default_step_name = format!("step_{}", step_number);
    let step_name = step.name.as_deref().unwrap_or(&default_step_name);

    debug!("Executing revocation step {}: {}", step_number, step_name);

    let url = revocation_url(parser, globals, &step.request).await?;

    let request_builder = build_request_builder(
        client,
        &step.request.method,
        &url,
        &step.request.headers,
        &step.request.body,
        timeout,
        parser,
        globals,
    )
    .map_err(|e| anyhow!("Failed to build request for {step_name}: {e}"))?;

    // The final step is the revocation action, even for a custom GET endpoint.
    let may_mutate = is_final_step || is_mutating_method(&step.request.method);
    let response = send_revocation_request(request_builder, retries, may_mutate)
        .await
        .with_context(|| format!("Request failed for {step_name}"))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .with_context(|| format!("Failed to read response body for {}", step_name))
        .map_err(|error| submitted_error(error, may_mutate))?;

    let display_body = truncate_with_ellipsis(&body, 500);
    let body_len = body.chars().count();

    debug!("Step {} response status: {}", step_number, status);
    debug!("Step {} response body (len={}): {}", step_number, body_len, display_body);

    // Extract variables from the response if configured
    if let Some(extractors) = &step.extract {
        debug!("Extracting {} variable(s) from step {} response", extractors.len(), step_number);

        for (var_name, extractor) in extractors {
            // Render any Liquid templates in the extractor (e.g., {{ TOKEN | prefix: 8 }})
            let rendered_extractor = render_extractor(extractor, parser, globals)
                .with_context(|| {
                    format!(
                        "Failed to render extractor template for '{}' in step {}",
                        var_name, step_number
                    )
                })
                .map_err(|error| submitted_error(error, may_mutate))?;
            debug!(
                "Step {}: Rendered extractor for '{}': {:?}",
                step_number, var_name, rendered_extractor
            );

            match extract_value_from_response(&rendered_extractor, &body, &headers, &status) {
                Ok(value) => {
                    debug!("Step {}: Extracted variable {}", step_number, var_name);
                    globals.insert(var_name.to_uppercase().into(), Value::scalar(value));
                }
                Err(e) => {
                    return Err(submitted_error(
                        anyhow!(
                            "Failed to extract variable '{}' in step {}: {}\nResponse status: {}\nResponse body: {}",
                            var_name,
                            step_number,
                            e,
                            status,
                            display_body
                        ),
                        may_mutate,
                    ));
                }
            }
        }
    }

    Ok((status, headers, body))
}

/// Execute multi-step HTTP revocation.
pub async fn execute_multi_step_revocation(
    multi_step: &HttpMultiStepRevocation,
    globals: &mut Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
) -> Result<DirectRevocationResult> {
    if multi_step.steps.is_empty() {
        bail!("Multi-step revocation must have at least one step");
    }

    if multi_step.steps.len() > 2 {
        bail!(
            "Multi-step revocation supports a maximum of 2 steps, got {}",
            multi_step.steps.len()
        );
    }

    if multi_step
        .steps
        .last()
        .and_then(|step| step.request.response_matcher.as_ref())
        .is_none_or(|matchers| matchers.is_empty())
    {
        bail!("Final revocation step must have response_matcher");
    }
    // Resolve every endpoint selection before any step may mutate provider state.
    let mut endpoint_globals = globals.clone();
    for step in &multi_step.steps {
        anyhow::ensure!(
            !step.extract.iter().flat_map(|extract| extract.keys()).any(|name| {
                super::http_validation::is_validation_endpoint_var(&name.to_uppercase())
            }),
            "Revocation response extractors cannot replace validated endpoint variables"
        );
        selected_url(&step.request, globals)?;
        if globals.contains_key("VALIDATION_ENDPOINT_COUNT")
            || globals.contains_key("VALIDATION_FALLBACK_ID")
            || !step.request.fallback_urls.is_empty()
        {
            revocation_url(parser, &endpoint_globals, &step.request).await?;
        }
        for name in step.extract.iter().flat_map(|extract| extract.keys()) {
            endpoint_globals
                .insert(name.to_uppercase().into(), Value::scalar("prepared-response-value"));
        }
    }
    let num_steps = multi_step.steps.len();
    debug!("Executing {}-step revocation", num_steps);

    // Preserve ambiguity if a later configuration failure follows a mutating step.
    let mut mutation_completed = false;
    for (i, step) in multi_step.steps.iter().enumerate() {
        let step_number = i + 1;
        let is_final_step = step_number == num_steps;

        let (status, headers, body) = match execute_revocation_step(
            step,
            globals,
            client,
            parser,
            timeout,
            retries,
            step_number,
            is_final_step,
        )
        .await
        {
            Ok(response) => response,
            Err(error) if mutation_completed => return Err(error.context(RevocationSubmitted)),
            Err(error) => return Err(error),
        };
        mutation_completed |= is_mutating_method(&step.request.method);

        if is_final_step {
            // Final step: validate response to determine success
            let display_body = truncate_with_ellipsis(&body, 500);

            let matchers = step
                .request
                .response_matcher
                .as_deref()
                .ok_or_else(|| anyhow!("Final revocation step must have response_matcher"))?;

            let html_allowed = step.request.response_is_html;
            let revoked = validate_response(matchers, &body, &status, &headers, html_allowed);

            return Ok(DirectRevocationResult {
                rule_id: String::new(),
                rule_name: String::new(),
                revoked,
                status_code: Some(status.as_u16()),
                message: display_body,
            });
        } else {
            // Intermediate step: just log the response
            debug!("Step {} completed with status {}", step_number, status);
        }
    }

    // This should never happen due to the checks above, but keep for safety
    Err(anyhow!("Multi-step revocation did not complete"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::StatusCode;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[tokio::test]
    async fn fallback_id_alone_checks_every_origin_before_the_first_mutation() {
        use std::net::{Ipv4Addr, TcpListener};
        let accepted = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let other = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        accepted.set_nonblocking(true).unwrap();
        other.set_nonblocking(true).unwrap();
        let accepted_origin = format!("http://{}", accepted.local_addr().unwrap());
        let other_origin = format!("http://{}", other.local_addr().unwrap());
        let program: HttpMultiStepRevocation = serde_json::from_value(serde_json::json!({"steps":[
            {"request":{"method":"DELETE","url":format!("{accepted_origin}/first")}},
            {"request":{"method":"DELETE","url":format!("{other_origin}/last"),
                "response_matcher":[{"type":"StatusMatch","status":[200]}]}}
        ]}))
        .unwrap();
        let mut globals = liquid::object!({
            "VALIDATION_FALLBACK_ID": "secondary",
            "VALIDATION_ORIGIN": accepted_origin,
        });
        let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
        let error = execute_multi_step_revocation(
            &program,
            &mut globals,
            &Client::new(),
            &parser,
            Duration::from_secs(2),
            0,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("origin that accepted"));
        assert_eq!(accepted.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(other.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
    }
    // ---- extract_value_from_response: JsonPath ----

    #[test]
    fn jsonpath_simple_field() {
        let ext = ResponseExtractor::JsonPath { path: "$.name".into() };
        let body = r#"{"name":"alice"}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "alice");
    }

    #[test]
    fn jsonpath_nested_field() {
        let ext = ResponseExtractor::JsonPath { path: "$.data.user.id".into() };
        let body = r#"{"data":{"user":{"id":"u-123"}}}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "u-123");
    }

    #[test]
    fn jsonpath_numeric_value() {
        let ext = ResponseExtractor::JsonPath { path: "$.count".into() };
        let body = r#"{"count":42}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "42");
    }

    #[test]
    fn jsonpath_boolean_value() {
        let ext = ResponseExtractor::JsonPath { path: "$.active".into() };
        let body = r#"{"active":true}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "true");
    }

    #[test]
    fn jsonpath_array_index_zero() {
        let ext = ResponseExtractor::JsonPath { path: "$.items[0]".into() };
        let body = r#"{"items":["first","second","third"]}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "first");
    }

    #[test]
    fn jsonpath_array_index_nested_field() {
        let ext = ResponseExtractor::JsonPath { path: "$.items[0].token_id".into() };
        let body = r#"{"items":[{"token_id":"tok-abc"},{"token_id":"tok-def"}]}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "tok-abc");
    }

    #[test]
    fn jsonpath_array_second_element() {
        let ext = ResponseExtractor::JsonPath { path: "$.data[1].name".into() };
        let body = r#"{"data":[{"name":"a"},{"name":"b"}]}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "b");
    }

    #[test]
    fn jsonpath_root_array_index_field() {
        // Used by custom.jira.3 revocation: GET /rest/pat/latest/tokens
        // returns a JSON array at the document root, and the rule extracts
        // JIRA_TOKEN_ID with path "$[0].id".
        let ext = ResponseExtractor::JsonPath { path: "$[0].id".into() };
        let body = r#"[{"id":278,"name":"ITSYSENG-8330"}]"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "278");
    }

    #[test]
    fn jsonpath_root_array_index_scalar() {
        let ext = ResponseExtractor::JsonPath { path: "$[1]".into() };
        let body = r#"["a","b","c"]"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "b");
    }

    #[test]
    fn jsonpath_missing_top_level_field() {
        let ext = ResponseExtractor::JsonPath { path: "$.nonexistent".into() };
        let body = r#"{"name":"alice"}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"), "Expected 'not found', got: {}", err);
    }

    #[test]
    fn jsonpath_missing_nested_field() {
        let ext = ResponseExtractor::JsonPath { path: "$.data.missing.deep".into() };
        let body = r#"{"data":{"other":"value"}}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert!(result.is_err());
    }

    #[test]
    fn jsonpath_array_index_out_of_bounds() {
        let ext = ResponseExtractor::JsonPath { path: "$.items[5]".into() };
        let body = r#"{"items":["only","two"]}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"), "Expected 'not found', got: {}", err);
    }

    #[test]
    fn jsonpath_invalid_json_body() {
        let ext = ResponseExtractor::JsonPath { path: "$.field".into() };
        let body = "not json at all";
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("not valid JSON"),
            "Expected JSON parse error, got: {}",
            err
        );
    }

    #[test]
    fn jsonpath_object_value_returns_json_string() {
        let ext = ResponseExtractor::JsonPath { path: "$.nested".into() };
        let body = r#"{"nested":{"a":1,"b":2}}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let val = result.unwrap();
        // When the value is not a string/number/bool, it should be serialized as JSON
        let parsed: serde_json::Value = serde_json::from_str(&val).unwrap();
        assert_eq!(parsed["a"], 1);
        assert_eq!(parsed["b"], 2);
    }

    // ---- extract_value_from_response: Regex ----

    #[test]
    fn regex_with_capture_group() {
        let ext = ResponseExtractor::Regex { pattern: r#"token_id":\s*"([^"]+)"#.into() };
        let body = r#"{"token_id": "abc-123-def"}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "abc-123-def");
    }

    #[test]
    fn regex_no_capture_group() {
        let ext = ResponseExtractor::Regex { pattern: r"token_id".into() };
        let body = r#"{"token_id": "abc"}"#;
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("No capture group"),
            "Expected 'No capture group', got: {}",
            err
        );
    }

    #[test]
    fn regex_pattern_does_not_match() {
        let ext = ResponseExtractor::Regex { pattern: r"xyz_(\d+)".into() };
        let body = "no match here";
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("did not match"),
            "Expected 'did not match', got: {}",
            err
        );
    }

    #[test]
    fn regex_invalid_pattern() {
        let ext = ResponseExtractor::Regex { pattern: r"[invalid".into() };
        let body = "anything";
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert!(result.is_err());
    }

    #[test]
    fn regex_multiple_capture_groups_uses_first() {
        let ext = ResponseExtractor::Regex { pattern: r"(\w+):(\w+)".into() };
        let body = "key:value";
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "key");
    }

    // ---- extract_value_from_response: Header ----

    #[test]
    fn header_extraction_found() {
        let ext = ResponseExtractor::Header { name: "x-request-id".into() };
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("req-456"));
        let result = extract_value_from_response(&ext, "", &headers, &StatusCode::OK);
        assert_eq!(result.unwrap(), "req-456");
    }

    #[test]
    fn header_extraction_missing() {
        let ext = ResponseExtractor::Header { name: "x-missing".into() };
        let result = extract_value_from_response(&ext, "", &HeaderMap::new(), &StatusCode::OK);
        let err = result.unwrap_err();
        assert!(err.to_string().contains("not found"), "Expected 'not found', got: {}", err);
    }

    // ---- extract_value_from_response: Body ----

    #[test]
    fn body_extraction() {
        let ext = ResponseExtractor::Body;
        let body = "the full response body";
        let result = extract_value_from_response(&ext, body, &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "the full response body");
    }

    #[test]
    fn body_extraction_empty() {
        let ext = ResponseExtractor::Body;
        let result = extract_value_from_response(&ext, "", &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "");
    }

    // ---- extract_value_from_response: StatusCode ----

    #[test]
    fn status_code_extraction_200() {
        let ext = ResponseExtractor::StatusCode;
        let result = extract_value_from_response(&ext, "", &HeaderMap::new(), &StatusCode::OK);
        assert_eq!(result.unwrap(), "200");
    }

    #[test]
    fn status_code_extraction_404() {
        let ext = ResponseExtractor::StatusCode;
        let result =
            extract_value_from_response(&ext, "", &HeaderMap::new(), &StatusCode::NOT_FOUND);
        assert_eq!(result.unwrap(), "404");
    }

    #[test]
    fn status_code_extraction_201() {
        let ext = ResponseExtractor::StatusCode;
        let result = extract_value_from_response(&ext, "", &HeaderMap::new(), &StatusCode::CREATED);
        assert_eq!(result.unwrap(), "201");
    }

    // ---- extract_template_vars ----

    #[test]
    fn render_extractor_renders_liquid_in_regex() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let mut globals = Object::new();
        globals.insert(
            "TOKEN".into(),
            // kingfisher:ignore (test fixture, not a real token)
            Value::scalar("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".to_string()),
        );

        let extractor = ResponseExtractor::Regex {
            pattern: r#""key":"([^"]+)","token":"{{ TOKEN | prefix: 8 }}"#.to_string(),
        };

        let rendered = render_extractor(&extractor, &parser, &globals).unwrap();
        match rendered {
            ResponseExtractor::Regex { pattern } => {
                assert_eq!(pattern, r#""key":"([^"]+)","token":"npm_rmll"#);
            }
            _ => panic!("Expected Regex variant"),
        }
    }

    #[test]
    fn render_extractor_regex_matches_correct_token_in_npm_response() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let mut globals = Object::new();
        let token = "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"; // kingfisher:ignore
        globals.insert("TOKEN".into(), Value::scalar(token.to_string()));

        // Match both ends exposed by npm's truncated token response.
        let extractor = ResponseExtractor::Regex {
            pattern:
                r#""key":"([^"]+)","token":"{{ TOKEN | prefix: 8 }}\.\.\.{{ TOKEN | suffix: 4 }}""#
                    .to_string(),
        };
        let rendered = render_extractor(&extractor, &parser, &globals).unwrap();

        // Simulated npm API response with multiple tokens
        let body = r#"{"objects":[{"key":"e089a40c-800b-4ec0-95b1-c17a63305887","token":"npm_yJcQ...rEf1"},{"key":"43c14e2d-8b5d-4f8b-91cd-280a7afead0c","token":"npm_rmll...aQIU"},{"key":"1ced5278-29a9-4266-bf8e-03223bc9c30c","token":"npm_ahWC...2pw1"}]}"#;

        let result =
            extract_value_from_response(&rendered, body, &HeaderMap::new(), &StatusCode::OK)
                .unwrap();

        // Should extract the key for the token matching both ends, not merely the first prefix.
        assert_eq!(result, "43c14e2d-8b5d-4f8b-91cd-280a7afead0c");
    }

    #[test]
    fn render_extractor_leaves_non_template_patterns_unchanged() {
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()
                .unwrap();
        let globals = Object::new();

        let extractor = ResponseExtractor::JsonPath { path: "$.objects[0].key".to_string() };
        let rendered = render_extractor(&extractor, &parser, &globals).unwrap();
        match rendered {
            ResponseExtractor::JsonPath { path } => {
                assert_eq!(path, "$.objects[0].key");
            }
            _ => panic!("Expected JsonPath variant"),
        }
    }

    // ---- truncate_with_ellipsis ----

    #[test]
    fn truncate_with_ellipsis_no_truncation() {
        let input = "ok";
        let output = truncate_with_ellipsis(input, 500);
        assert_eq!(output, input);
    }

    #[test]
    fn truncate_with_ellipsis_handles_unicode() {
        let input = "é".repeat(501);
        let output = truncate_with_ellipsis(&input, 500);

        assert!(output.ends_with("..."));
        assert_eq!(output.chars().count(), 503);
        assert!(output.chars().take(500).all(|ch| ch == 'é'));
    }
}
