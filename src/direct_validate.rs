//! Direct secret validation without pattern matching.
//!
//! This module provides functionality to validate a known secret directly against
//! a rule's validator, bypassing the normal pattern-matching detection phase.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Read},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use crossbeam_skiplist::SkipMap;
use liquid::Object;
use liquid_core::{Value, ValueView};
use reqwest::Client;
use serde::Serialize;
use tracing::debug;

use crate::{
    cli::{commands::validate::ValidateArgs, global::GlobalArgs},
    liquid_filters::register_all,
    provider_endpoints::{ProviderEndpointOverrides, hydrate_endpoint_globals_for_rule},
    rule_loader::RuleLoader,
    rules::{HttpValidation, Validation, rule::Rule},
    template_vars::extract_template_vars,
    validation::{
        GLOBAL_USER_AGENT,
        aws::validate_aws_credentials,
        azure::validate_azure_storage_credentials,
        coinbase::validate_cdp_api_key,
        gcp::GcpValidator,
        httpvalidation::is_auto_provided_request_var,
        httpvalidation::validate_response,
        httpvalidation::{build_request_builder, retry_request},
        jdbc::validate_jdbc,
        jwt::validate_jwt,
        mongodb::validate_mongodb,
        mysql::validate_mysql,
        postgres::validate_postgres,
    },
    validation_body,
    validation_rate_limit::{ValidationRateLimiter, should_rate_limit_validation},
};

use crate::grpc_validation;

fn preview_body_for_display(body: &str, max_bytes: usize) -> String {
    if body.len() <= max_bytes {
        return body.to_string();
    }

    // `String` slicing must be on a UTF-8 char boundary to avoid panics.
    let mut end = max_bytes.min(body.len());
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }

    format!("{}...", &body[..end])
}

/// Result of a direct validation attempt.
#[derive(Debug, Clone, Serialize)]
pub struct DirectValidationResult {
    /// The rule ID that was used for validation.
    pub rule_id: String,
    /// The rule name.
    pub rule_name: String,
    /// Whether the secret was validated as valid.
    pub is_valid: bool,
    /// HTTP status code from the validation request (if applicable).
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

    // Try the selector as-is first, then with "kingfisher." prefix as fallback.
    // This allows users to pass `--rule aws` instead of `--rule kingfisher.aws`.
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
            // Exact match OR "selector." is a prefix of id
            if id == try_selector.as_ref()
                || (id.starts_with(try_selector.as_ref())
                    && id.as_bytes().get(try_selector.len()) == Some(&b'.'))
            {
                matches.push(rule);
            }
        }
        // If we matched with this selector, no need to try the fallback
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

/// Extract a string value from the globals object.
fn get_global_var(globals: &Object, name: &str) -> Option<String> {
    globals.get(name).and_then(|v| v.to_kstr().to_string().into())
}

/// Extract all template variables used in a validation configuration.
fn extract_validation_vars(validation: &Validation) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();

    match validation {
        Validation::Http(http) => {
            // Extract from URL
            vars.extend(extract_template_vars(&http.request.url));

            // Extract from headers
            for (key, value) in &http.request.headers {
                vars.extend(extract_template_vars(key));
                vars.extend(extract_template_vars(value));
            }

            // Extract from body
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Validation::Grpc(grpc) => {
            // Extract from URL
            vars.extend(extract_template_vars(&grpc.request.url));

            // Extract from headers
            for (key, value) in &grpc.request.headers {
                vars.extend(extract_template_vars(key));
                vars.extend(extract_template_vars(value));
            }

            // Extract from body
            if let Some(body) = &grpc.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        // Non-HTTP validators typically use fixed variable names
        Validation::AWS => {
            vars.insert("AKID".to_string());
            vars.insert("TOKEN".to_string());
        }
        Validation::GCP => {
            vars.insert("TOKEN".to_string());
        }
        Validation::MongoDB => {
            vars.insert("TOKEN".to_string());
        }
        Validation::MySQL => {
            vars.insert("TOKEN".to_string());
        }
        Validation::Postgres => {
            vars.insert("TOKEN".to_string());
        }
        Validation::Jdbc => {
            vars.insert("TOKEN".to_string());
        }
        Validation::JWT => {
            vars.insert("TOKEN".to_string());
        }
        Validation::AzureStorage => {
            vars.insert("TOKEN".to_string());
            // AZURENAME matches the depends_on_rule variable in azurestorage.yml
            // STORAGE_ACCOUNT is kept for backward compatibility
            vars.insert("AZURENAME".to_string());
        }
        Validation::Coinbase => {
            vars.insert("TOKEN".to_string());
            vars.insert("CRED_NAME".to_string());
        }
        Validation::Raw(raw) => {
            vars.extend(kingfisher_scanner::validation::raw::required_vars(raw));
        }
    }

    vars.retain(|var| !is_auto_provided_request_var(var));

    vars
}

/// Build the globals object for Liquid template rendering.
///
/// - `secret`: The main secret value, assigned to TOKEN
/// - `args`: Unnamed values to auto-assign to template variables (excluding TOKEN)
/// - `variables`: Named variables in NAME=VALUE format (explicit overrides)
/// - `template_vars`: Set of variable names used in the validation template
fn build_globals(
    rule_id: &str,
    secret: &str,
    args: &[String],
    variables: &[String],
    template_vars: &BTreeSet<String>,
    endpoint_overrides: &ProviderEndpointOverrides,
) -> Result<Object> {
    let mut globals = Object::new();

    // Set TOKEN to the provided secret
    globals.insert("TOKEN".into(), Value::scalar(secret.to_string()));

    endpoint_overrides.apply_defaults(&mut globals);

    // Get non-TOKEN variables in alphabetical order for auto-assignment
    let auto_assign_vars: Vec<&String> = template_vars
        .iter()
        .filter(|v| *v != "TOKEN" && !globals.contains_key(v.as_str()))
        .collect();

    // Auto-assign --arg values to template variables
    for (i, arg_value) in args.iter().enumerate() {
        if i < auto_assign_vars.len() {
            let var_name = auto_assign_vars[i];
            debug!("Auto-assigning --arg '{}' to variable '{}'", arg_value, var_name);
            globals.insert(var_name.clone().into(), Value::scalar(arg_value.clone()));
        }
    }

    // Parse and add any --var overrides (these take precedence)
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
            // Read from stdin
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

/// Render the validation URL using Liquid templates.
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

/// Execute HTTP validation against the provided rule.
async fn execute_http_validation(
    http_validation: &HttpValidation,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    timeout: Duration,
    retries: u32,
    allow_internal_ips: bool,
) -> Result<DirectValidationResult> {
    let request_globals = kingfisher_scanner::validation::with_request_template_globals(globals);

    // Render the URL
    let url = render_and_parse_url(parser, &request_globals, &http_validation.request.url).await?;

    // SSRF check: verify the resolved IP is public before making the request
    crate::validation::utils::check_url_resolvable(&url, allow_internal_ips)
        .await
        .map_err(|e| anyhow!("URL resolution failed: {}", e))?;

    debug!("Validating against URL: {}", url);

    // Build the request
    let request_builder = build_request_builder(
        client,
        &http_validation.request.method,
        &url,
        &http_validation.request.headers,
        &http_validation.request.body,
        timeout,
        parser,
        &request_globals,
    )
    .map_err(|e| anyhow!("Failed to build request: {}", e))?;

    // Execute the request with retries
    let backoff_min = Duration::from_millis(100);
    let backoff_max = Duration::from_secs(2);

    let response = retry_request(request_builder, retries, backoff_min, backoff_max)
        .await
        .map_err(|e| anyhow!("Request failed: {}", e))?;

    let status = response.status();
    let headers = response.headers().clone();
    let body =
        response.text().await.unwrap_or_else(|e| format!("Failed to read response body: {}", e));

    // Validate the response
    let matchers = http_validation.request.response_matcher.as_deref().unwrap_or(&[]);
    let html_allowed = http_validation.request.response_is_html;
    let display_body = if html_allowed {
        crate::validation::utils::format_response_body_for_display(&body, 500, true)
    } else {
        preview_body_for_display(&body, 500)
    };
    let is_valid = validate_response(matchers, &body, &status, &headers, html_allowed);

    Ok(DirectValidationResult {
        rule_id: String::new(), // Will be filled in by caller
        rule_name: String::new(),
        is_valid,
        status_code: Some(status.as_u16()),
        message: display_body,
    })
}

/// Execute gRPC validation against the provided rule.
async fn execute_grpc_validation(
    grpc_validation_cfg: &kingfisher_rules::GrpcValidation,
    globals: &Object,
    parser: &liquid::Parser,
    timeout: Duration,
    allow_internal_ips: bool,
) -> Result<DirectValidationResult> {
    let request_globals = kingfisher_scanner::validation::with_request_template_globals(globals);

    // Render the URL
    let url =
        render_and_parse_url(parser, &request_globals, &grpc_validation_cfg.request.url).await?;

    // SSRF check: verify the resolved IP is public before making the request
    crate::validation::utils::check_url_resolvable(&url, allow_internal_ips)
        .await
        .map_err(|e| anyhow!("URL resolution failed: {}", e))?;

    debug!("Validating against gRPC URL: {}", url);

    let res = grpc_validation::grpc_unary_call_from_rule(
        &url,
        &grpc_validation_cfg.request.headers,
        &grpc_validation_cfg.request.body,
        parser,
        &request_globals,
        timeout,
    )
    .await
    .map_err(|e| anyhow!("gRPC request failed: {e}"))?;

    let status = res.http_status;
    let headers = res.headers;
    let mut body = String::from_utf8_lossy(&res.body_bytes).to_string();
    let grpc_status =
        headers.get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let grpc_message =
        headers.get("grpc-message").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if grpc_status == "0" {
        body = "grpc-status=0".to_string();
    } else if body.trim().is_empty() && (!grpc_status.is_empty() || !grpc_message.is_empty()) {
        body = format!("grpc-status={grpc_status} grpc-message={grpc_message}");
    } else if body.as_bytes().contains(&0) {
        body = format!("grpc-status={grpc_status} grpc-message={grpc_message}");
    }

    // Truncate body for display if too long
    let display_body = preview_body_for_display(&body, 500);

    // Validate the response
    let matchers = grpc_validation_cfg.request.response_matcher.as_deref().unwrap_or(&[]);
    let is_valid = validate_response(matchers, &body, &status, &headers, false);

    Ok(DirectValidationResult {
        rule_id: String::new(), // Will be filled in by caller
        rule_name: String::new(),
        is_valid,
        status_code: Some(status.as_u16()),
        message: display_body,
    })
}

/// Run direct validation of a secret against one or more rules.
///
/// If the rule selector matches multiple rules, all matching rules are tried.
/// Returns results for all rules that have validation defined.
pub async fn run_direct_validation(
    args: &ValidateArgs,
    global_args: &GlobalArgs,
) -> Result<Vec<DirectValidationResult>> {
    // Read the secret
    let secret = read_secret(args.secret.as_deref())?;

    if secret.is_empty() {
        bail!("Secret cannot be empty");
    }

    // Load rules
    let loader = RuleLoader::new()
        .load_builtins(!args.no_builtins)
        .additional_rule_load_paths(&args.rules_path);

    // Create minimal scan args for rule loading
    let scan_args = create_minimal_scan_args();
    let loaded = loader.load(&scan_args)?;

    // Find all matching rules
    let matching_rules = find_rules_by_selector(&args.rule, loaded.id_to_rule())?;
    let num_matching_rules = matching_rules.len();

    if num_matching_rules > 1 {
        debug!("Rule selector '{}' matches {} rules, trying all", args.rule, num_matching_rules);
    }

    // Determine if we should use lax TLS for non-HTTP validators
    // For direct validation (explicit user command), lax mode applies globally
    let use_lax_tls = matches!(
        global_args.tls_mode,
        crate::cli::global::TlsMode::Off | crate::cli::global::TlsMode::Lax
    );

    // Build HTTP client with SSRF-safe redirect policy when applicable
    let client = Client::builder()
        .danger_accept_invalid_certs(use_lax_tls)
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .redirect(if global_args.allow_internal_ips {
            reqwest::redirect::Policy::default()
        } else {
            crate::validation::ssrf_safe_redirect_policy()
        })
        .gzip(true)
        .deflate(true)
        .brotli(true)
        .build()
        .context("Failed to build HTTP client")?;

    // Build Liquid parser
    let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
    let endpoint_overrides = ProviderEndpointOverrides::from_global_args(global_args)?;

    let timeout = Duration::from_secs(args.timeout);
    let rate_limiter =
        ValidationRateLimiter::from_cli(args.validation_rps, &args.validation_rps_rule)?
            .map(Arc::new);

    let mut results = Vec::new();

    // Try each matching rule
    for rule in matching_rules {
        let rule_id = rule.id().to_string();
        let rule_name = rule.name().to_string();

        debug!("Trying rule: {} ({})", rule_name, rule_id);

        // Check if the rule has validation
        let validation = match rule.syntax().validation.as_ref() {
            Some(v) => v,
            None => {
                debug!("Rule '{}' has no validation defined, skipping", rule_id);
                continue;
            }
        };

        // Extract template variables from validation and build globals
        let template_vars = extract_validation_vars(validation);

        // Check if --arg values can be assigned to this rule's variables
        let non_token_vars: Vec<&String> = template_vars.iter().filter(|v| *v != "TOKEN").collect();

        // If more --arg values than variables, skip this rule when trying multiple rules
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
                // Single rule match - give a clear error
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

        // Log auto-assignment info for debugging
        if !non_token_vars.is_empty() && !args.args.is_empty() {
            debug!(
                "Rule '{}' uses variables: {:?}, auto-assigned from --arg: {:?}",
                rule_id, non_token_vars, args.args
            );
        }

        // Check for missing variables and provide helpful error messages
        let missing_vars: Vec<&String> =
            template_vars.iter().filter(|var| globals.get(var.as_str()).is_none()).collect();

        if !missing_vars.is_empty() {
            // Build a map from variable name to the rule it depends on
            let depends_on_map: BTreeMap<String, &str> = rule
                .syntax()
                .depends_on_rule
                .iter()
                .flatten()
                .map(|dep| (dep.variable.to_uppercase(), dep.rule_id.as_str()))
                .collect();

            let mut error_parts = Vec::new();
            let mut var_hints = Vec::new();

            for var in &missing_vars {
                if let Some(source_rule) = depends_on_map.get(*var) {
                    error_parts
                        .push(format!("  {} (normally captured from rule '{}')", var, source_rule));
                } else {
                    error_parts.push(format!("  {}", var));
                }
                var_hints.push(format!("--var {}=<value>", var));
            }

            bail!(
                "Rule '{}' requires the following variable(s):\n{}\n\nProvide them using: kingfisher validate --rule {} {} <secret>",
                rule_id,
                error_parts.join("\n"),
                rule_id,
                var_hints.join(" ")
            );
        }

        if let Some(limiter) = rate_limiter.as_deref() {
            if should_rate_limit_validation(validation) {
                limiter.wait_for_rule(&rule_id).await;
            }
        }

        // Execute validation based on type. Errors from the HTTP / gRPC
        // pathways (DNS failure, SSRF preflight, request build, request
        // execution, timeout) used to short-circuit the whole `validate`
        // command via `?`, which left stdout empty and made downstream
        // tools (and integration tests) unable to distinguish "no rule"
        // from "validation attempted, infrastructure failed". Match the
        // pattern used by AWS / GCP / raw branches below: surface the
        // failure as a non-valid result with a generic `message`. The
        // underlying error is intentionally NOT included in stdout or in
        // debug logs because the rendered URL / headers / body can
        // contain `{{ TOKEN }}` substituted to the secret (and any
        // `--var` / `--arg` values).
        let mut result = match validation {
            Validation::Http(http_validation) => {
                match execute_http_validation(
                    http_validation,
                    &globals,
                    &client,
                    &parser,
                    timeout,
                    args.retries,
                    global_args.allow_internal_ips,
                )
                .await
                {
                    Ok(r) => r,
                    Err(_e) => {
                        // Intentionally drop the underlying error: it can
                        // embed the rendered URL with `{{ TOKEN }}`
                        // substituted (i.e. the secret) or `--var` /
                        // `--arg` values. Logging it (even at debug) would
                        // leak credentials into stderr when -v is on.
                        debug!("HTTP validation failed");
                        DirectValidationResult {
                            rule_id: rule_id.clone(),
                            rule_name: rule_name.clone(),
                            is_valid: false,
                            status_code: None,
                            message: "HTTP validation failed".to_string(),
                        }
                    }
                }
            }
            Validation::Grpc(grpc_validation_cfg) => {
                match execute_grpc_validation(
                    grpc_validation_cfg,
                    &globals,
                    &parser,
                    timeout,
                    global_args.allow_internal_ips,
                )
                .await
                {
                    Ok(r) => r,
                    Err(_e) => {
                        debug!("gRPC validation failed");
                        DirectValidationResult {
                            rule_id: rule_id.clone(),
                            rule_name: rule_name.clone(),
                            is_valid: false,
                            status_code: None,
                            message: "gRPC validation failed".to_string(),
                        }
                    }
                }
            }

            Validation::AWS => {
                // AWS needs AKID and TOKEN (secret access key)
                let akid = get_global_var(&globals, "AKID")
                .or_else(|| get_global_var(&globals, "ACCESS_KEY_ID"))
                .ok_or_else(|| anyhow!(
                    "AWS validation requires AKID variable. Use: --var AKID=<access_key_id> <secret_access_key>"
                ))?;

                match validate_aws_credentials(&akid, &secret).await {
                    Ok((is_valid, message)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message,
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("AWS validation error: {}", e),
                    },
                }
            }

            Validation::GCP => {
                // GCP expects the full service account JSON as the secret
                match GcpValidator::new() {
                    Ok(validator) => {
                        match validator.validate_gcp_credentials(secret.as_bytes()).await {
                            Ok((is_valid, metadata)) => DirectValidationResult {
                                rule_id: String::new(),
                                rule_name: String::new(),
                                is_valid,
                                status_code: None,
                                message: if metadata.is_empty() {
                                    "GCP credential validation completed".to_string()
                                } else {
                                    metadata.join(", ")
                                },
                            },
                            Err(e) => DirectValidationResult {
                                rule_id: String::new(),
                                rule_name: String::new(),
                                is_valid: false,
                                status_code: None,
                                message: format!("GCP validation error: {}", e),
                            },
                        }
                    }
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("Failed to initialize GCP validator: {}", e),
                    },
                }
            }

            Validation::MongoDB => {
                // MongoDB expects a connection URI as the secret
                match validate_mongodb(&secret, use_lax_tls).await {
                    Ok((is_valid, message)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message,
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("MongoDB validation error: {}", e),
                    },
                }
            }

            Validation::MySQL => {
                // MySQL expects a connection URL as the secret
                match validate_mysql(&secret, use_lax_tls).await {
                    Ok((is_valid, metadata)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message: if metadata.is_empty() {
                            "MySQL validation completed".to_string()
                        } else {
                            metadata.join(", ")
                        },
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("MySQL validation error: {}", e),
                    },
                }
            }

            Validation::Postgres => {
                // Postgres expects a connection URL as the secret
                match validate_postgres(&secret, use_lax_tls).await {
                    Ok((is_valid, metadata)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message: if metadata.is_empty() {
                            "Postgres validation completed".to_string()
                        } else {
                            metadata.join(", ")
                        },
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("Postgres validation error: {}", e),
                    },
                }
            }

            Validation::Jdbc => {
                // JDBC expects a JDBC connection string as the secret
                match validate_jdbc(&secret, use_lax_tls).await {
                    Ok(outcome) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: outcome.valid,
                        status_code: Some(outcome.status.as_u16()),
                        message: outcome.message,
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("JDBC validation error: {}", e),
                    },
                }
            }

            Validation::JWT => {
                // JWT expects a JWT token as the secret
                match validate_jwt(&secret, use_lax_tls, global_args.allow_internal_ips).await {
                    Ok((is_valid, message)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message,
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("JWT validation error: {}", e),
                    },
                }
            }

            Validation::AzureStorage => {
                // Azure Storage expects JSON with storage_account and storage_key
                // Or use --var AZURENAME=xxx (or STORAGE_ACCOUNT for backward compat) and pass the storage key as the secret
                let azure_json = if secret.starts_with('{') {
                    // Secret is already JSON
                    secret.clone()
                } else {
                    // Build JSON from variables
                    // AZURENAME matches the depends_on_rule variable in azurestorage.yml
                    // STORAGE_ACCOUNT is kept for backward compatibility
                    let storage_account = get_global_var(&globals, "AZURENAME")
                    .or_else(|| get_global_var(&globals, "STORAGE_ACCOUNT"))
                    .ok_or_else(|| anyhow!(
                        "Azure Storage validation requires either JSON input or --var AZURENAME=<account_name> <storage_key>"
                    ))?;
                    serde_json::json!({
                        "storage_account": storage_account,
                        "storage_key": secret
                    })
                    .to_string()
                };

                let cache: Arc<SkipMap<String, crate::validation::CachedResponse>> =
                    Arc::new(SkipMap::new());
                match validate_azure_storage_credentials(&azure_json, &cache).await {
                    Ok((is_valid, body)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message: validation_body::clone_as_string(&body),
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("Azure Storage validation error: {}", e),
                    },
                }
            }

            Validation::Coinbase => {
                // Coinbase needs credential name and private key PEM
                let cred_name = get_global_var(&globals, "CRED_NAME")
                .or_else(|| get_global_var(&globals, "KEY_ID"))
                .ok_or_else(|| anyhow!(
                    "Coinbase validation requires CRED_NAME variable. Use: --var CRED_NAME=<key_id> <private_key_pem>"
                ))?;

                let cache: Arc<SkipMap<String, crate::validation::CachedResponse>> =
                    Arc::new(SkipMap::new());
                match validate_cdp_api_key(&cred_name, &secret, &client, &parser, &cache).await {
                    Ok((is_valid, body)) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid,
                        status_code: None,
                        message: validation_body::clone_as_string(&body),
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("Coinbase validation error: {}", e),
                    },
                }
            }

            Validation::Raw(raw) => {
                match kingfisher_scanner::validation::raw::validate_raw(
                    raw,
                    &globals,
                    &client,
                    use_lax_tls,
                    global_args.allow_internal_ips,
                )
                .await
                {
                    Ok(result) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: result.valid,
                        status_code: Some(result.status.as_u16()),
                        message: result.body,
                    },
                    Err(e) => DirectValidationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        is_valid: false,
                        status_code: None,
                        message: format!("Raw validation error: {}", e),
                    },
                }
            }
        };

        result.rule_id = rule_id;
        result.rule_name = rule_name;
        results.push(result);
    }

    if results.is_empty() {
        bail!(
            "No rules with validation found matching '{}'. \
             Use `kingfisher rules list` to see available rules.",
            args.rule
        );
    }

    Ok(results)
}

/// Create minimal scan args for rule loading.
pub(crate) fn create_minimal_scan_args() -> crate::cli::commands::scan::ScanArgs {
    use crate::cli::commands::{
        azure::AzureRepoType,
        bitbucket::BitbucketAuthArgs,
        bitbucket::BitbucketRepoType,
        gitea::GiteaRepoType,
        github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
        gitlab::GitLabRepoType,
        inputs::{ContentFilteringArgs, InputSpecifierArgs},
        output::{OutputArgs, ReportOutputFormat},
        rules::RuleSpecifierArgs,
        scan::{ConfidenceLevel, ScanArgs},
    };
    use url::Url;

    ScanArgs {
        num_jobs: 1,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            git_clone_dir: None,
            keep_clones: false,
            repo_clone_limit: None,
            include_contributors: false,
            github_user: Vec::new(),
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::All,
            gitlab_include_subgroups: false,
            huggingface_user: Vec::new(),
            huggingface_organization: Vec::new(),
            huggingface_model: Vec::new(),
            huggingface_dataset: Vec::new(),
            huggingface_space: Vec::new(),
            huggingface_exclude: Vec::new(),
            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,
            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),
            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
            azure_repo_type: AzureRepoType::Source,
            jira_url: None,
            jql: None,
            jira_include_comments: false,
            jira_include_changelog: false,
            confluence_url: None,
            cql: None,
            max_results: 100,
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            teams_query: None,
            teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),
            postman_workspaces: Vec::new(),
            postman_collections: Vec::new(),
            postman_environments: Vec::new(),
            postman_all: false,
            postman_include_mocks_monitors: false,
            postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
            docker_image: Vec::new(),
            docker_archive: Vec::new(),
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
            branch_root: false,
            branch_root_commit: None,
            staged: false,
        },
        extra_ignore_comments: Vec::new(),
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: true,
            extraction_depth: 2,
            exclude: Vec::new(),
            no_binary: true,
        },
        confidence: ConfidenceLevel::Low, // Load all rules regardless of confidence
        no_validate: true,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800,
        no_dedup: false,
        view_report: false,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
        skip_aws_account: Vec::new(),
        skip_aws_account_file: None,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_base64: false,
        turbo: false,
        no_inline_ignore: false,
        no_ignore_if_contains: false,
        view_report_port: 7890,
        view_report_address: "127.0.0.1".to_string(),
        alert_webhook: Vec::new(),
        alert_format: None,
        alert_on: crate::alerts::AlertOn::Findings,
        alert_min_confidence: ConfidenceLevel::Medium,
        alert_include_secret: false,
        alert_report_url: None,
        alert_detail: crate::alerts::AlertDetail::Auto,
        config_webhook_overrides: Vec::new(),
        validation_timeout: 10,
        validation_retries: 1,
        validation_rps: None,
        validation_rps_rule: Vec::new(),
        full_validation_response: false,
        max_validation_response_length: 2048,
    }
}

/// Print validation results to stdout.
pub fn print_results(results: &[DirectValidationResult], format: &str, use_color: bool) {
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
                    println!(); // Separator between results
                }

                let valid_str = if result.is_valid {
                    if use_color { "\x1b[32m✓ VALID\x1b[0m" } else { "VALID" }
                } else if use_color {
                    "\x1b[31m✗ INVALID\x1b[0m"
                } else {
                    "INVALID"
                };

                println!("Rule:     {} ({})", result.rule_name, result.rule_id);
                println!("Result:   {}", valid_str);
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

/// Check if any result is valid.
pub fn any_valid(results: &[DirectValidationResult]) -> bool {
    results.iter().any(|r| r.is_valid)
}
