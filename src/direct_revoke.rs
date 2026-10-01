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
use reqwest::Client;
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
};

use kingfisher_rules::{Revocation, Rule};

pub use kingfisher_scanner::validation::revocation::DirectRevocationResult;
use kingfisher_scanner::validation::revocation::{
    execute_http_revocation, execute_multi_step_revocation,
};

/// Find all rules matching an ID or prefix.
///
/// Returns all matching rules, or an error if no rules match.
fn find_rules_by_selector<'a>(
    selector: &str,
    rules: &'a BTreeMap<String, Rule>,
) -> Result<Vec<&'a Rule>> {
    let mut matches: Vec<&Rule> = Vec::new();

    let mut selectors_to_try = vec![std::borrow::Cow::Borrowed(selector)];
    if !selector.starts_with("betterleaks.") && !selector.starts_with("kingfisher.") {
        selectors_to_try.push(std::borrow::Cow::Owned(format!("betterleaks.{selector}")));
        selectors_to_try.push(std::borrow::Cow::Owned(format!("kingfisher.{selector}")));
    }

    for try_selector in &selectors_to_try {
        for (id, rule) in rules {
            if id == try_selector.as_ref()
                || (id.starts_with(try_selector.as_ref())
                    && matches!(id.as_bytes().get(try_selector.len()), Some(b'.' | b'-')))
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
    use kingfisher_rules::HttpValidation;
    use std::collections::{BTreeMap, BTreeSet};

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
            "custom.test.1",
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
            "custom.test.1",
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
            "custom.test.1",
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
            "custom.test.1",
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
            "custom.test.1",
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
            path: None,
            betterleaks_filter: None,
            betterleaks_secret_group: None,
            authoritative: true,
            vectorscan_compatible: true,
        })
    }

    #[test]
    fn find_rules_exact_match() {
        let mut rules = BTreeMap::new();
        rules.insert("custom.github.1".into(), make_test_rule("custom.github.1", "GitHub Token"));
        rules.insert("custom.gitlab.1".into(), make_test_rule("custom.gitlab.1", "GitLab Token"));

        let matched = find_rules_by_selector("custom.github.1", &rules).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id(), "custom.github.1");
    }

    #[test]
    fn find_rules_prefix_match() {
        let mut rules = BTreeMap::new();
        rules.insert("custom.github.1".into(), make_test_rule("custom.github.1", "GitHub PAT"));
        rules.insert("custom.github.2".into(), make_test_rule("custom.github.2", "GitHub App"));
        rules.insert("custom.gitlab.1".into(), make_test_rule("custom.gitlab.1", "GitLab Token"));

        let matched = find_rules_by_selector("custom.github", &rules).unwrap();
        assert_eq!(matched.len(), 2);
    }

    #[test]
    fn find_rules_auto_prefix_betterleaks() {
        let mut rules = BTreeMap::new();
        rules.insert(
            "betterleaks.github-pat".into(),
            make_test_rule("betterleaks.github-pat", "GitHub Token"),
        );

        let matched = find_rules_by_selector("github-pat", &rules).unwrap();
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id(), "betterleaks.github-pat");
    }

    #[test]
    fn find_rules_auto_prefix_legacy_kingfisher() {
        let rules = BTreeMap::from_iter([(
            "kingfisher.github.1".to_string(),
            make_test_rule("kingfisher.github.1", "GitHub Token"),
        )]);

        let matched = find_rules_by_selector("github.1", &rules).unwrap();

        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].id(), "kingfisher.github.1");
    }

    #[test]
    fn find_rules_no_match() {
        let mut rules = BTreeMap::new();
        rules.insert("custom.github.1".into(), make_test_rule("custom.github.1", "GitHub Token"));

        let result = find_rules_by_selector("nonexistent", &rules);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No rule found"));
    }

    #[test]
    fn find_rules_prefix_boundary() {
        // "custom.git" should NOT match "custom.github.1" because
        // "github" does not start after a '.' boundary following "git"
        let mut rules = BTreeMap::new();
        rules.insert("custom.github.1".into(), make_test_rule("custom.github.1", "GitHub Token"));

        let result = find_rules_by_selector("custom.git", &rules);
        assert!(result.is_err(), "Prefix 'custom.git' should not match 'custom.github.1'");
    }

    // ---- render_extractor ----
}
