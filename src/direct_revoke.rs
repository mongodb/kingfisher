//! Direct secret revocation without pattern matching.
//!
//! This module provides functionality to revoke a known secret directly against
//! a rule's revocation configuration, bypassing the normal pattern-matching phase.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use liquid::Object;
use liquid_core::{Value, ValueView};
use regex::Regex;
use reqwest::Client;
use serde::Serialize;
use tracing::debug;

use crate::{
    cli::{commands::revoke::RevokeArgs, global::GlobalArgs},
    liquid_filters::register_all,
    provider_endpoints::{ProviderEndpointOverrides, hydrate_endpoint_globals_for_rule},
    rule_loader::RuleLoader,
    template_vars::extract_template_vars,
    validation::GLOBAL_USER_AGENT,
    validation::aws::{revoke_aws_access_key, validate_aws_credentials_input},
    validation::gcp::revoke_gcp_service_account_key,
    validation::httpvalidation::{build_request_builder, retry_request, validate_response},
};

use kingfisher_rules::{
    HttpMultiStepRevocation, HttpValidation, ResponseExtractor, Revocation, RevocationStep, Rule,
};

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

/// Find all rules matching an ID or prefix.
///
/// Returns all matching rules, or an error if no rules match.
fn find_rules_by_selector<'a>(
    selector: &str,
    rules: &'a BTreeMap<String, Rule>,
) -> Result<Vec<&'a Rule>> {
    let mut matches: Vec<&Rule> = Vec::new();

    let selectors_to_try: Vec<std::borrow::Cow<'_, str>> = if selector.starts_with("kingfisher.") {
        vec![std::borrow::Cow::Borrowed(selector)]
    } else {
        vec![
            std::borrow::Cow::Borrowed(selector),
            std::borrow::Cow::Owned(format!("kingfisher.{}", selector)),
        ]
    };

    for try_selector in &selectors_to_try {
        for (id, rule) in rules {
            if id == try_selector.as_ref()
                || (id.starts_with(try_selector.as_ref())
                    && id.as_bytes().get(try_selector.len()) == Some(&b'.'))
            {
                matches.push(rule);
            }
        }
        if !matches.is_empty() {
            break;
        }
    }

    if matches.is_empty() {
        bail!(
            "No rule found matching '{}'. Use `kingfisher rules list` to see available rules.",
            selector
        );
    }

    Ok(matches)
}

/// Extract all template variables used in a revocation configuration.
fn extract_revocation_vars(revocation: &Revocation) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    match revocation {
        Revocation::AWS => {
            vars.insert("AKID".to_string());
            vars.insert("TOKEN".to_string());
        }
        Revocation::GCP => {
            vars.insert("TOKEN".to_string());
        }
        Revocation::Http(http) => {
            vars.extend(extract_template_vars(&http.request.url));
            for (key, value) in &http.request.headers {
                vars.extend(extract_template_vars(key));
                vars.extend(extract_template_vars(value));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Revocation::HttpMultiStep(multi_step) => {
            // Extract variables from all steps
            // Note: Variables extracted in step 1 are available in step 2,
            // but we only track initial input variables here
            for step in &multi_step.steps {
                vars.extend(extract_template_vars(&step.request.url));
                for (key, value) in &step.request.headers {
                    vars.extend(extract_template_vars(key));
                    vars.extend(extract_template_vars(value));
                }
                if let Some(body) = &step.request.body {
                    vars.extend(extract_template_vars(body));
                }
            }
        }
    }

    vars
}

/// Extract a string value from the globals object.
fn get_global_var(globals: &Object, name: &str) -> Option<String> {
    globals.get(name).and_then(|v| v.to_kstr().to_string().into())
}

/// Build the globals object for Liquid template rendering.
fn build_globals(
    rule_id: &str,
    secret: &str,
    args: &[String],
    variables: &[String],
    template_vars: &BTreeSet<String>,
    endpoint_overrides: &ProviderEndpointOverrides,
) -> Result<Object> {
    let mut globals = Object::new();
    globals.insert("TOKEN".into(), Value::scalar(secret.to_string()));

    endpoint_overrides.apply_defaults(&mut globals);

    let auto_assign_vars: Vec<&String> = template_vars
        .iter()
        .filter(|v| *v != "TOKEN" && !globals.contains_key(v.as_str()))
        .collect();

    for (i, arg_value) in args.iter().enumerate() {
        if i < auto_assign_vars.len() {
            let var_name = auto_assign_vars[i];
            debug!("Auto-assigning --arg '{}' to variable '{}'", arg_value, var_name);
            globals.insert(var_name.clone().into(), Value::scalar(arg_value.clone()));
        }
    }

    for var in variables {
        let (name, value) = var
            .split_once('=')
            .ok_or_else(|| anyhow!("Invalid variable format '{}'. Expected NAME=VALUE", var))?;

        let name = name.trim().to_uppercase();
        let value = value.trim().to_string();

        if name.is_empty() {
            bail!("Variable name cannot be empty in '{}'", var);
        }

        globals.insert(name.into(), Value::scalar(value));
    }

    hydrate_endpoint_globals_for_rule(rule_id, &mut globals);

    Ok(globals)
}

/// Read the secret value from the provided argument or stdin.
fn read_secret(secret_arg: Option<&str>) -> Result<String> {
    match secret_arg {
        Some("-") => {
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer).context("Failed to read secret from stdin")?;
            Ok(buffer.trim().to_string())
        }
        Some(s) => Ok(s.to_string()),
        None => {
            bail!("No secret provided. Pass a secret as an argument or use '-' to read from stdin.")
        }
    }
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
async fn execute_http_revocation(
    http_revocation: &HttpValidation,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
) -> Result<DirectRevocationResult> {
    let url = render_and_parse_url(parser, globals, &http_revocation.request.url).await?;

    debug!("Revoking against URL: {}", url);

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
    .map_err(|e| anyhow!("Failed to build request: {}", e))?;

    let backoff_min = Duration::from_millis(100);
    let backoff_max = Duration::from_secs(2);

    let response = retry_request(request_builder, retries, backoff_min, backoff_max)
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.context("Failed to read response body")?;

    let display_body = truncate_with_ellipsis(&body, 500);
    let body_len = body.chars().count();

    debug!("Revocation response status: {}", status);
    debug!("Revocation response body (len={}): {}", body_len, display_body);

    let matchers = http_revocation
        .request
        .response_matcher
        .as_deref()
        .ok_or_else(|| anyhow!("Revocation response_matcher is required"))?;
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
async fn execute_revocation_step(
    step: &RevocationStep,
    globals: &mut Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
    step_number: usize,
) -> Result<(reqwest::StatusCode, reqwest::header::HeaderMap, String)> {
    let default_step_name = format!("step_{}", step_number);
    let step_name = step.name.as_deref().unwrap_or(&default_step_name);

    debug!("Executing revocation step {}: {}", step_number, step_name);

    let url = render_and_parse_url(parser, globals, &step.request.url).await?;
    debug!("Step {} URL: {}", step_number, url);

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
    .map_err(|e| anyhow!("Failed to build request for {}: {}", step_name, e))?;

    let backoff_min = Duration::from_millis(100);
    let backoff_max = Duration::from_secs(2);

    let response = retry_request(request_builder, retries, backoff_min, backoff_max)
        .await
        .map_err(|e| anyhow!("Request failed for {}: {}", step_name, e))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .text()
        .await
        .with_context(|| format!("Failed to read response body for {}", step_name))?;

    let display_body = truncate_with_ellipsis(&body, 500);
    let body_len = body.chars().count();

    debug!("Step {} response status: {}", step_number, status);
    debug!("Step {} response body (len={}): {}", step_number, body_len, display_body);

    // Extract variables from the response if configured
    if let Some(extractors) = &step.extract {
        debug!("Extracting {} variable(s) from step {} response", extractors.len(), step_number);

        for (var_name, extractor) in extractors {
            // Render any Liquid templates in the extractor (e.g., {{ TOKEN | prefix: 8 }})
            let rendered_extractor =
                render_extractor(extractor, parser, globals).with_context(|| {
                    format!(
                        "Failed to render extractor template for '{}' in step {}",
                        var_name, step_number
                    )
                })?;
            debug!(
                "Step {}: Rendered extractor for '{}': {:?}",
                step_number, var_name, rendered_extractor
            );

            match extract_value_from_response(&rendered_extractor, &body, &headers, &status) {
                Ok(value) => {
                    debug!("Step {}: Extracted variable {} = '{}'", step_number, var_name, value);
                    globals.insert(var_name.to_uppercase().into(), Value::scalar(value));
                }
                Err(e) => {
                    return Err(anyhow!(
                        "Failed to extract variable '{}' in step {}: {}\nResponse status: {}\nResponse body: {}",
                        var_name,
                        step_number,
                        e,
                        status,
                        display_body
                    ));
                }
            }
        }
    }

    Ok((status, headers, body))
}

/// Execute multi-step HTTP revocation.
async fn execute_multi_step_revocation(
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

    let num_steps = multi_step.steps.len();
    debug!("Executing {}-step revocation", num_steps);

    // Execute each step sequentially
    for (i, step) in multi_step.steps.iter().enumerate() {
        let step_number = i + 1;
        let is_final_step = step_number == num_steps;

        let (status, headers, body) =
            execute_revocation_step(step, globals, client, parser, timeout, retries, step_number)
                .await?;

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

/// Run direct revocation of a secret against one or more rules.
pub async fn run_direct_revocation(
    args: &RevokeArgs,
    global_args: &GlobalArgs,
) -> Result<Vec<DirectRevocationResult>> {
    let secret = read_secret(args.secret.as_deref())?;

    if secret.is_empty() {
        bail!("Secret cannot be empty");
    }

    let loader = RuleLoader::new()
        .load_builtins(!args.no_builtins)
        .additional_rule_load_paths(&args.rules_path);

    let scan_args = crate::direct_validate::create_minimal_scan_args();
    let loaded = loader.load(&scan_args)?;

    let matching_rules = find_rules_by_selector(&args.rule, loaded.id_to_rule())?;
    let num_matching_rules = matching_rules.len();

    if num_matching_rules > 1 {
        debug!("Rule selector '{}' matches {} rules, trying all", args.rule, num_matching_rules);
    }

    let client = Client::builder()
        .danger_accept_invalid_certs(global_args.ignore_certs)
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .gzip(true)
        .deflate(true)
        .brotli(true)
        .build()
        .context("Failed to build HTTP client")?;

    let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
    let timeout = Duration::from_secs(args.timeout);
    let endpoint_overrides = ProviderEndpointOverrides::from_global_args(global_args)?;

    let mut results = Vec::new();

    for rule in matching_rules {
        let rule_id = rule.id().to_string();
        let rule_name = rule.name().to_string();

        debug!("Trying rule: {} ({})", rule_name, rule_id);

        let revocation = match rule.syntax().revocation.as_ref() {
            Some(v) => v,
            None => {
                debug!("Rule '{}' has no revocation defined, skipping", rule_id);
                continue;
            }
        };

        let template_vars = extract_revocation_vars(revocation);
        let non_token_vars: Vec<&String> = template_vars.iter().filter(|v| *v != "TOKEN").collect();

        if args.args.len() > non_token_vars.len() {
            if num_matching_rules > 1 {
                debug!(
                    "Rule '{}' expects {} variable(s) but {} --arg value(s) provided, skipping",
                    rule_id,
                    non_token_vars.len(),
                    args.args.len()
                );
                continue;
            } else {
                let var_list = if non_token_vars.is_empty() {
                    "none".to_string()
                } else {
                    non_token_vars.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                };
                bail!(
                    "Too many --arg values provided. Rule '{}' expects {} additional variable(s): {}",
                    rule_id,
                    non_token_vars.len(),
                    var_list
                );
            }
        }

        let globals = build_globals(
            &rule_id,
            &secret,
            &args.args,
            &args.variables,
            &template_vars,
            &endpoint_overrides,
        )?;

        if !non_token_vars.is_empty() && !args.args.is_empty() {
            debug!(
                "Rule '{}' uses variables: {:?}, auto-assigned from --arg: {:?}",
                rule_id, non_token_vars, args.args
            );
        }

        let mut result = match revocation {
            Revocation::AWS => {
                let akid = get_global_var(&globals, "AKID")
                    .or_else(|| get_global_var(&globals, "ACCESS_KEY_ID"))
                    .ok_or_else(|| {
                        anyhow!(
                            "AWS revocation requires AKID variable. Use: --var AKID=<access_key_id> <secret_access_key>"
                        )
                    })?;

                if let Err(err) = validate_aws_credentials_input(&akid, &secret) {
                    DirectRevocationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        revoked: false,
                        status_code: None,
                        message: format!("Invalid AWS credentials: {}", err),
                    }
                } else {
                    match revoke_aws_access_key(&akid, &secret).await {
                        Ok((revoked, message)) => DirectRevocationResult {
                            rule_id: String::new(),
                            rule_name: String::new(),
                            revoked,
                            status_code: None,
                            message,
                        },
                        Err(e) => DirectRevocationResult {
                            rule_id: String::new(),
                            rule_name: String::new(),
                            revoked: false,
                            status_code: None,
                            message: format!("AWS revocation error: {}", e),
                        },
                    }
                }
            }
            Revocation::GCP => {
                let key_id_override = get_global_var(&globals, "KEY_ID")
                    .or_else(|| get_global_var(&globals, "PRIVATE_KEY_ID"));
                match revoke_gcp_service_account_key(&secret, key_id_override.as_deref()).await {
                    Ok(outcome) => DirectRevocationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        revoked: outcome.revoked,
                        status_code: outcome.status_code,
                        message: outcome.message,
                    },
                    Err(e) => DirectRevocationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        revoked: false,
                        status_code: None,
                        message: format!("GCP revocation error: {}", e),
                    },
                }
            }
            Revocation::Http(http_revocation) => {
                execute_http_revocation(
                    http_revocation,
                    &globals,
                    &client,
                    &parser,
                    timeout,
                    args.retries,
                )
                .await?
            }
            Revocation::HttpMultiStep(multi_step) => {
                let mut globals_mut = globals.clone();
                execute_multi_step_revocation(
                    multi_step,
                    &mut globals_mut,
                    &client,
                    &parser,
                    timeout,
                    args.retries,
                )
                .await?
            }
        };

        result.rule_id = rule_id;
        result.rule_name = rule_name;
        results.push(result);
    }

    if results.is_empty() {
        bail!(
            "No rules with revocation found matching '{}'. \
             Use `kingfisher rules list` to see available rules.",
            args.rule
        );
    }

    Ok(results)
}

/// Print revocation results to stdout.
pub fn print_results(results: &[DirectRevocationResult], format: &str, use_color: bool) {
    match format {
        "json" => {
            if results.len() == 1 {
                println!("{}", serde_json::to_string_pretty(&results[0]).unwrap());
            } else {
                println!("{}", serde_json::to_string_pretty(results).unwrap());
            }
        }
        "toon" => {
            let value = if results.len() == 1 {
                serde_json::to_value(&results[0]).unwrap()
            } else {
                serde_json::to_value(results).unwrap()
            };
            println!("{}", crate::toon::encode_llm_friendly(&value).unwrap());
        }
        _ => {
            for (i, result) in results.iter().enumerate() {
                if i > 0 {
                    println!();
                }

                let revoked_str = if result.revoked {
                    if use_color { "\x1b[32m✓ REVOKED\x1b[0m" } else { "REVOKED" }
                } else if use_color {
                    "\x1b[31m✗ FAILED\x1b[0m"
                } else {
                    "FAILED"
                };

                println!("Rule:     {} ({})", result.rule_name, result.rule_id);
                println!("Result:   {}", revoked_str);
                if let Some(status) = result.status_code {
                    println!("Status:   {}", status);
                }
                if !result.message.is_empty() {
                    println!("Response: {}", result.message);
                }
            }
        }
    }
}

/// Check if any result was revoked.
pub fn any_revoked(results: &[DirectRevocationResult]) -> bool {
    results.iter().any(|r| r.revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kingfisher_rules::{HttpValidation, ResponseExtractor, Revocation};
    use reqwest::StatusCode;
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::collections::{BTreeMap, BTreeSet};

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
        // Used by kingfisher.jira.3 revocation: GET /rest/pat/latest/tokens
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
    fn template_vars_basic() {
        let vars = extract_template_vars("https://api.example.com/{{ TOKEN }}/revoke");
        assert!(vars.contains("TOKEN"));
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn template_vars_multiple() {
        let vars = extract_template_vars(
            "https://api.example.com/{{ AKID }}/keys/{{ KEY_ID }}?token={{ TOKEN }}",
        );
        assert!(vars.contains("AKID"));
        assert!(vars.contains("KEY_ID"));
        assert!(vars.contains("TOKEN"));
        assert_eq!(vars.len(), 3);
    }

    #[test]
    fn template_vars_with_filters() {
        let vars = extract_template_vars("{{ TOKEN | base64_encode }}");
        assert!(vars.contains("TOKEN"));
        assert_eq!(vars.len(), 1);
    }

    #[test]
    fn template_vars_no_vars() {
        let vars = extract_template_vars("https://api.example.com/revoke");
        assert!(vars.is_empty());
    }

    #[test]
    fn template_vars_case_normalization() {
        // Variables are uppercased on extraction
        let vars = extract_template_vars("{{ token }}");
        assert!(vars.contains("TOKEN"));
    }

    // ---- build_globals ----

    #[test]
    fn build_globals_sets_token() {
        let template_vars = BTreeSet::from(["TOKEN".to_string()]);
        let globals = build_globals(
            "kingfisher.test.1",
            "my-secret",
            &[],
            &[],
            &template_vars,
            &ProviderEndpointOverrides::default(),
        )
        .unwrap();
        assert_eq!(globals.get("TOKEN"), Some(Value::scalar("my-secret".to_string())).as_ref());
    }

    #[test]
    fn build_globals_auto_assigns_args() {
        let template_vars =
            BTreeSet::from(["TOKEN".to_string(), "AKID".to_string(), "REGION".to_string()]);
        let args = vec!["my-akid".to_string(), "us-east-1".to_string()];
        let globals = build_globals(
            "kingfisher.test.1",
            "secret",
            &args,
            &[],
            &template_vars,
            &ProviderEndpointOverrides::default(),
        )
        .unwrap();

        assert_eq!(globals.get("TOKEN"), Some(Value::scalar("secret".to_string())).as_ref());
        assert_eq!(globals.get("AKID"), Some(Value::scalar("my-akid".to_string())).as_ref());
        assert_eq!(globals.get("REGION"), Some(Value::scalar("us-east-1".to_string())).as_ref());
    }

    #[test]
    fn build_globals_explicit_variables() {
        let template_vars = BTreeSet::from(["TOKEN".to_string(), "AKID".to_string()]);
        let vars = vec!["AKID=explicit-value".to_string()];
        let globals = build_globals(
            "kingfisher.test.1",
            "secret",
            &[],
            &vars,
            &template_vars,
            &ProviderEndpointOverrides::default(),
        )
        .unwrap();

        assert_eq!(globals.get("AKID"), Some(Value::scalar("explicit-value".to_string())).as_ref());
    }

    #[test]
    fn build_globals_invalid_var_format() {
        let template_vars = BTreeSet::new();
        let vars = vec!["NO_EQUALS_SIGN".to_string()];
        let result = build_globals(
            "kingfisher.test.1",
            "secret",
            &[],
            &vars,
            &template_vars,
            &ProviderEndpointOverrides::default(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Expected NAME=VALUE"));
    }

    #[test]
    fn build_globals_empty_var_name() {
        let template_vars = BTreeSet::new();
        let vars = vec!["=value".to_string()];
        let result = build_globals(
            "kingfisher.test.1",
            "secret",
            &[],
            &vars,
            &template_vars,
            &ProviderEndpointOverrides::default(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));
    }

    // ---- extract_revocation_vars ----

    #[test]
    fn extract_revocation_vars_aws() {
        let vars = extract_revocation_vars(&Revocation::AWS);
        assert!(vars.contains("AKID"));
        assert!(vars.contains("TOKEN"));
    }

    #[test]
    fn extract_revocation_vars_gcp() {
        let vars = extract_revocation_vars(&Revocation::GCP);
        assert!(vars.contains("TOKEN"));
    }

    #[test]
    fn extract_revocation_vars_http() {
        use kingfisher_rules::HttpRequest;

        let http = HttpValidation {
            request: HttpRequest {
                method: "DELETE".into(),
                url: "https://api.example.com/{{ AKID }}/{{ TOKEN }}".into(),
                headers: BTreeMap::from([("Authorization".into(), "Bearer {{ TOKEN }}".into())]),
                body: Some(r#"{"key":"{{ KEY_ID }}"}"#.into()),
                response_matcher: None,
                multipart: None,
                response_is_html: false,
            },
            multipart: None,
        };
        let vars = extract_revocation_vars(&Revocation::Http(http));
        assert!(vars.contains("AKID"));
        assert!(vars.contains("TOKEN"));
        assert!(vars.contains("KEY_ID"));
    }

    #[test]
    fn extract_revocation_vars_multi_step() {
        use kingfisher_rules::{HttpMultiStepRevocation, HttpRequest, RevocationStep};

        let multi = HttpMultiStepRevocation {
            steps: vec![
                RevocationStep {
                    name: Some("lookup".into()),
                    request: HttpRequest {
                        method: "GET".into(),
                        url: "https://api.example.com/{{ TOKEN }}/info".into(),
                        headers: BTreeMap::new(),
                        body: None,
                        response_matcher: None,
                        multipart: None,
                        response_is_html: false,
                    },
                    multipart: None,
                    extract: None,
                },
                RevocationStep {
                    name: Some("delete".into()),
                    request: HttpRequest {
                        method: "DELETE".into(),
                        url: "https://api.example.com/{{ KEY_ID }}".into(),
                        headers: BTreeMap::from([("X-Api-Key".into(), "{{ API_KEY }}".into())]),
                        body: None,
                        response_matcher: None,
                        multipart: None,
                        response_is_html: false,
                    },
                    multipart: None,
                    extract: None,
                },
            ],
        };
        let vars = extract_revocation_vars(&Revocation::HttpMultiStep(multi));
        assert!(vars.contains("TOKEN"));
        assert!(vars.contains("KEY_ID"));
        assert!(vars.contains("API_KEY"));
    }

    // ---- find_rules_by_selector ----

    fn make_test_rule(id: &str, name: &str) -> Rule {
        Rule::new(kingfisher_rules::RuleSyntax {
            name: name.to_string(),
            id: id.to_string(),
            pattern: r"\btest\b".to_string(),
            min_entropy: 0.0,
            confidence: Default::default(),
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        })
    }

    #[test]
    fn find_rules_exact_match() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "kingfisher.github.1".into(),
            make_test_rule("kingfisher.github.1", "GitHub Token"),
        );
        rules.insert(
            "kingfisher.gitlab.1".into(),
            make_test_rule("kingfisher.gitlab.1", "GitLab Token"),
        );

        let matched = find_rules_by_selector("kingfisher.github.1", &rules).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id(), "kingfisher.github.1");
    }

    #[test]
    fn find_rules_prefix_match() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "kingfisher.github.1".into(),
            make_test_rule("kingfisher.github.1", "GitHub PAT"),
        );
        rules.insert(
            "kingfisher.github.2".into(),
            make_test_rule("kingfisher.github.2", "GitHub App"),
        );
        rules.insert(
            "kingfisher.gitlab.1".into(),
            make_test_rule("kingfisher.gitlab.1", "GitLab Token"),
        );

        let matched = find_rules_by_selector("kingfisher.github", &rules).unwrap();
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn find_rules_auto_prefix_kingfisher() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "kingfisher.github.1".into(),
            make_test_rule("kingfisher.github.1", "GitHub Token"),
        );

        // Searching without "kingfisher." prefix should still find the rule
        let matched = find_rules_by_selector("github.1", &rules).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id(), "kingfisher.github.1");
    }

    #[test]
    fn find_rules_no_match() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "kingfisher.github.1".into(),
            make_test_rule("kingfisher.github.1", "GitHub Token"),
        );

        let result = find_rules_by_selector("nonexistent", &rules);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No rule found"));
    }

    #[test]
    fn find_rules_prefix_boundary() {
        // "kingfisher.git" should NOT match "kingfisher.github.1" because
        // "github" does not start after a '.' boundary following "git"
        let mut rules = BTreeMap::new();
        rules.insert(
            "kingfisher.github.1".into(),
            make_test_rule("kingfisher.github.1", "GitHub Token"),
        );

        let result = find_rules_by_selector("kingfisher.git", &rules);
        assert!(result.is_err(), "Prefix 'kingfisher.git' should not match 'kingfisher.github.1'");
    }

    // ---- render_extractor ----

    #[test]
    fn render_extractor_renders_liquid_in_regex() {
        let parser = crate::liquid_filters::register_all(liquid::ParserBuilder::with_stdlib())
            .build()
            .unwrap();
        let mut globals = Object::new();
        // kingfisher:ignore (test fixture, not a real token)
        globals.insert(
            "TOKEN".into(),
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
        let parser = crate::liquid_filters::register_all(liquid::ParserBuilder::with_stdlib())
            .build()
            .unwrap();
        let mut globals = Object::new();
        // kingfisher:ignore (test fixture, not a real token)
        globals.insert(
            "TOKEN".into(),
            Value::scalar("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".to_string()),
        );

        let extractor = ResponseExtractor::Regex {
            pattern: r#""key":"([^"]+)","token":"{{ TOKEN | prefix: 8 }}"#.to_string(),
        };
        let rendered = render_extractor(&extractor, &parser, &globals).unwrap();

        // Simulated npm API response with multiple tokens
        let body = r#"{"objects":[{"key":"e089a40c-800b-4ec0-95b1-c17a63305887","token":"npm_yJcQ...rEf1"},{"key":"43c14e2d-8b5d-4f8b-91cd-280a7afead0c","token":"npm_rmll...aQIU"},{"key":"1ced5278-29a9-4266-bf8e-03223bc9c30c","token":"npm_ahWC...2pw1"}]}"#;

        let result =
            extract_value_from_response(&rendered, body, &HeaderMap::new(), &StatusCode::OK)
                .unwrap();

        // Should extract the key for the token matching prefix "npm_rmll", NOT the first one
        assert_eq!(result, "43c14e2d-8b5d-4f8b-91cd-280a7afead0c");
    }

    #[test]
    fn render_extractor_leaves_non_template_patterns_unchanged() {
        let parser = crate::liquid_filters::register_all(liquid::ParserBuilder::with_stdlib())
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
