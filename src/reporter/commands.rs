//! Suggested validation, revocation, and access-map commands for reported findings.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use kingfisher_scanner::validation::http_validation::is_auto_provided_request_var;

use crate::{
    rules::Revocation,
    template_vars::extract_template_vars,
    validation_body::{self, ValidationResponseBody},
};

/// Shell-escape a string for POSIX shells using single quotes.
/// Generated commands must be adapted before use in PowerShell or cmd.exe.
fn escape_for_shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn required_vars_for_validation(validation: &crate::rules::Validation) -> BTreeSet<String> {
    use crate::rules::Validation;
    let mut vars = BTreeSet::new();

    match validation {
        Validation::Assumed => {}
        Validation::Ethereum(_) => {
            vars.insert("TOKEN".to_string());
        }
        Validation::Http(http) => {
            vars.extend(extract_template_vars(&http.request.url));
            for (k, v) in &http.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Validation::Grpc(grpc) => {
            vars.extend(extract_template_vars(&grpc.request.url));
            for (k, v) in &grpc.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &grpc.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Validation::Betterleaks(validation) => {
            vars.insert("TOKEN".to_string());
            vars.extend(validation.components.values().cloned());
        }
        Validation::AWS => {
            vars.insert("AKID".to_string());
            vars.insert("TOKEN".to_string());
        }
        Validation::GCP => {
            vars.insert("TOKEN".to_string());
        }
        Validation::MongoDB
        | Validation::MySQL
        | Validation::Postgres
        | Validation::Jdbc
        | Validation::CredentialUri
        | Validation::JWT => {
            vars.insert("TOKEN".to_string());
        }
        Validation::AzureStorage => {
            vars.insert("TOKEN".to_string());
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

fn required_vars_for_revocation(revocation: &Revocation) -> BTreeSet<String> {
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
            for (k, v) in &http.request.headers {
                vars.extend(extract_template_vars(k));
                vars.extend(extract_template_vars(v));
            }
            if let Some(body) = &http.request.body {
                vars.extend(extract_template_vars(body));
            }
        }
        Revocation::HttpMultiStep(multi) => {
            for step in &multi.steps {
                vars.extend(extract_template_vars(&step.request.url));
                for (k, v) in &step.request.headers {
                    vars.extend(extract_template_vars(k));
                    vars.extend(extract_template_vars(v));
                }
                if let Some(body) = &step.request.body {
                    vars.extend(extract_template_vars(body));
                }
            }
        }
    }

    vars
}

/// Build the --var arguments string from dependent captures, but only for variables that are
/// required by the validation/revocation templates.
fn build_var_args(
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
    required_vars: &BTreeSet<String>,
) -> String {
    let mut var_args = Vec::new();

    // Add AKID if available (for AWS)
    let dependent_akid_is_present =
        dependent_captures.get("AKID").is_some_and(|value| !value.is_empty());
    if let Some(akid) = akid_from_captures.or(akid_from_validation_body)
        && !akid.is_empty()
        && required_vars.contains("AKID")
        && !dependent_akid_is_present
    {
        var_args.push(format!("--var AKID={}", escape_for_shell(akid)));
    }

    // Add dependent captures only when required by the templates.
    // This avoids generating commands like `--var BODY=...` for tokens whose named captures
    // are just internal parsing aids (e.g., checksum payloads).
    for (name, value) in dependent_captures {
        let name_upper = name.to_ascii_uppercase();
        if required_vars.contains(&name_upper)
            && !name.eq_ignore_ascii_case("TOKEN")
            && !value.is_empty()
        {
            var_args.push(format!("--var {}={}", name, escape_for_shell(value)));
        }
    }

    if var_args.is_empty() { String::new() } else { format!("{} ", var_args.join(" ")) }
}

/// Build rule-loading flags for a direct command emitted from a scan result.
fn build_rule_loading_args(rules_path: &[PathBuf], load_builtins: bool) -> Option<String> {
    let mut args = rules_path
        .iter()
        .map(|path| path.to_str().map(|path| format!("--rules-path {}", escape_for_shell(path))))
        .collect::<Option<Vec<_>>>()?;
    if !load_builtins {
        args.push("--no-builtins".to_string());
    }

    Some(if args.is_empty() { String::new() } else { format!("{} ", args.join(" ")) })
}

/// Generate a kingfisher revoke command for an active credential if the rule supports revocation.
///
/// Returns `None` if:
/// - The credential is not active
/// - The rule doesn't have revocation configured
/// - Required data (like AWS AKID) cannot be determined
pub(super) fn build_revoke_command(
    rule_id: &str,
    revocation: &Revocation,
    snippet: &str,
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
) -> Option<String> {
    let required_vars = required_vars_for_revocation(revocation);

    let var_args = build_var_args(
        dependent_captures,
        akid_from_captures,
        akid_from_validation_body,
        &required_vars,
    );

    match revocation {
        Revocation::AWS => {
            // AWS needs the access key ID (AKID) in addition to the secret
            // Try to get it from captures first, then from validation response body
            let akid = dependent_captures
                .get("AKID")
                .map(String::as_str)
                .or(akid_from_captures)
                .or(akid_from_validation_body)?;
            if akid.is_empty() {
                return None;
            }
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                escape_for_shell(rule_id),
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::GCP => {
            // GCP revocation uses the service account JSON key (which is the snippet)
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                escape_for_shell(rule_id),
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::Http(_) => {
            // HTTP-based revocation with dependent variables
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                escape_for_shell(rule_id),
                var_args,
                escape_for_shell(snippet)
            ))
        }
        Revocation::HttpMultiStep(_) => {
            // Multi-step HTTP revocation with dependent variables
            Some(format!(
                "kingfisher revoke --rule {} {}{}",
                escape_for_shell(rule_id),
                var_args,
                escape_for_shell(snippet)
            ))
        }
    }
}

pub(super) fn resolve_betterleaks_capability_source<'a>(
    source: &str,
    finding_secret: &'a str,
    validation: &crate::rules::BetterleaksValidation,
    dependent_captures: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    if source == "finding.secret" {
        return Some(finding_secret);
    }
    let component_id = source.strip_prefix("components.")?;
    let variable = validation.components.get(component_id)?;
    dependent_captures.get(variable).map(String::as_str)
}

/// Generate a kingfisher validate command for a finding.
///
/// Returns `None` if the rule doesn't have validation configured or required data is missing.
pub(super) fn build_validate_command(
    rule_id: &str,
    validation: &crate::rules::Validation,
    snippet: &str,
    dependent_captures: &std::collections::BTreeMap<String, String>,
    akid_from_captures: Option<&str>,
    akid_from_validation_body: Option<&str>,
) -> Option<String> {
    use crate::rules::Validation;

    let mut required_vars = required_vars_for_validation(validation);
    let is_aws_session_token = matches!(validation, Validation::AWS)
        && dependent_captures.get("AWS_SECRET_ACCESS_KEY").is_some_and(|value| !value.is_empty());
    if is_aws_session_token {
        required_vars.insert("AWS_SECRET_ACCESS_KEY".to_string());
    }

    let var_args = build_var_args(
        dependent_captures,
        akid_from_captures,
        akid_from_validation_body,
        &required_vars,
    );

    let command_secret = match validation {
        Validation::Assumed => return None,
        Validation::AWS => {
            // AWS needs the access key ID (AKID) in addition to the secret.
            dependent_captures
                .get("AKID")
                .map(String::as_str)
                .filter(|value| !value.is_empty())
                .or(akid_from_captures.filter(|value| !value.is_empty()))
                .or(akid_from_validation_body.filter(|value| !value.is_empty()))?;
            snippet
        }
        Validation::CredentialUri => dependent_captures
            .get("URI")
            .map(String::as_str)
            .filter(|uri| !uri.is_empty())
            .unwrap_or(snippet),
        _ => snippet,
    };
    Some(format!(
        "kingfisher validate --rule {} {}{}",
        escape_for_shell(rule_id),
        var_args,
        escape_for_shell(command_secret)
    ))
}

pub(super) struct BlastRadiusCommandContext<'a> {
    pub(super) dependent_captures: &'a BTreeMap<String, String>,
    pub(super) akid_from_captures: Option<&'a str>,
    pub(super) akid_from_validation_body: Option<&'a str>,
    pub(super) rules_path: &'a [PathBuf],
    pub(super) load_builtins: bool,
}

/// Generate a direct blast-radius command when the finding can be mapped by a known handler.
pub(super) fn build_blast_radius_command(
    rule_id: &str,
    validation: &crate::rules::Validation,
    is_aws_session_token: bool,
    snippet: &str,
    context: &BlastRadiusCommandContext<'_>,
) -> Option<String> {
    use crate::rules::Validation;

    let BlastRadiusCommandContext {
        dependent_captures,
        akid_from_captures,
        akid_from_validation_body,
        rules_path,
        load_builtins,
    } = context;

    let mut required_vars = BTreeSet::new();
    let command_secret = match validation {
        Validation::CredentialUri => {
            let uri = dependent_captures
                .get("URI")
                .map(String::as_str)
                .filter(|uri| !uri.is_empty())
                .unwrap_or(snippet);
            let scheme = dependent_captures.get("SCHEME").map(String::as_str);
            match crate::validation::classify_credential_uri(uri, scheme) {
                crate::validation::CredentialUriTarget::Postgres(_)
                | crate::validation::CredentialUriTarget::MongoDB(_)
                | crate::validation::CredentialUriTarget::MySQL(_) => uri,
                crate::validation::CredentialUriTarget::Http(_)
                | crate::validation::CredentialUriTarget::Jdbc(_)
                | crate::validation::CredentialUriTarget::Unsupported(_) => return None,
            }
        }
        _ => snippet,
    };
    match validation {
        Validation::Betterleaks(validation) => {
            let mapping = validation.capabilities.access_map.as_ref()?;
            for source in mapping.inputs.values() {
                if let Some(component) = source.strip_prefix("components.") {
                    let variable = validation.components.get(component)?.to_ascii_uppercase();
                    if dependent_captures.get(&variable).is_none_or(String::is_empty) {
                        return None;
                    }
                    required_vars.insert(variable);
                }
            }
        }
        Validation::AWS => {
            required_vars.insert("AKID".to_string());
            let akid_from_dependencies = dependent_captures
                .get("AKID")
                .map(String::as_str)
                .filter(|value| !value.is_empty());
            let has_secret_access_key = dependent_captures
                .get("AWS_SECRET_ACCESS_KEY")
                .is_some_and(|value| !value.is_empty());
            if is_aws_session_token && !has_secret_access_key {
                return None;
            }
            if has_secret_access_key {
                required_vars.insert("AWS_SECRET_ACCESS_KEY".to_string());
            }
            akid_from_dependencies
                .or(akid_from_captures.filter(|value| !value.is_empty()))
                .or(akid_from_validation_body.filter(|value| !value.is_empty()))?;
        }
        Validation::GCP => {}
        Validation::AzureStorage => {
            required_vars.insert("AZURENAME".to_string());
            if dependent_captures.get("AZURENAME").is_none_or(String::is_empty) {
                return None;
            }
        }
        Validation::CredentialUri
        | Validation::Postgres
        | Validation::MongoDB
        | Validation::MySQL => {}
        _ => return None,
    }
    let var_args = build_var_args(
        dependent_captures,
        *akid_from_captures,
        *akid_from_validation_body,
        &required_vars,
    );
    let rule_loading_args = build_rule_loading_args(rules_path, *load_builtins)?;
    Some(format!(
        "kingfisher blast-radius --rule {} {}{}{}",
        escape_for_shell(rule_id),
        rule_loading_args,
        var_args,
        escape_for_shell(command_secret)
    ))
}

/// Extract AWS Access Key ID from validation response body if present.
pub(super) fn extract_akid_from_validation_body(body: &ValidationResponseBody) -> Option<String> {
    static AKID_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"(?xi)\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}\b",
        )
        .expect("AKID regex should compile")
    });

    let text = validation_body::clone_as_string(body);
    AKID_RE.find(&text).map(|m| m.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::Confidence;

    fn default_blast_radius_context(
        dependent_captures: &BTreeMap<String, String>,
    ) -> BlastRadiusCommandContext<'_> {
        BlastRadiusCommandContext {
            dependent_captures,
            akid_from_captures: None,
            akid_from_validation_body: None,
            rules_path: &[],
            load_builtins: true,
        }
    }

    #[test]
    fn build_var_args_ignores_unrequired_named_captures() {
        let dependent = BTreeMap::from([
            ("BODY".to_string(), "payload-part".to_string()),
            ("CHECKSUM".to_string(), "abc123".to_string()),
        ]);
        let required = BTreeSet::from(["TOKEN".to_string()]);

        let args = build_var_args(&dependent, None, None, &required);
        assert_eq!(args, "");
    }

    #[test]
    fn build_validate_command_omits_body_checksum_vars_for_vercel_like_http_rule() {
        let validation = crate::rules::Validation::Http(crate::rules::HttpValidation {
            request: crate::rules::HttpRequest {
                method: "GET".to_string(),
                url: "https://api.vercel.com/v2/user".to_string(),
                headers: BTreeMap::from([(
                    "Authorization".to_string(),
                    "Bearer {{TOKEN}}".to_string(),
                )]),
                body: None,
                response_matcher: None,
                multipart: None,
                response_is_html: false,
            },
            multipart: None,
        });
        let dependent = BTreeMap::from([
            ("BODY".to_string(), "payload-part".to_string()),
            ("CHECKSUM".to_string(), "abc123".to_string()),
        ]);

        let cmd = build_validate_command(
            "custom.vercel.token",
            &validation,
            "vcp_testtoken",
            &dependent,
            None,
            None,
        )
        .expect("validate command should be generated");

        assert!(!cmd.contains("--var BODY="), "command should not include BODY var: {}", cmd);
        assert!(
            !cmd.contains("--var CHECKSUM="),
            "command should not include CHECKSUM var: {}",
            cmd
        );
        assert!(cmd.contains("kingfisher validate --rule 'custom.vercel.token'"));
    }

    #[test]
    fn credential_uri_validate_command_uses_uri_instead_of_reported_password() {
        let uri = "postgresql://alice:hunter2@db.internal/app";
        let dependent = BTreeMap::from([("URI".to_string(), uri.to_string())]);

        let command = build_validate_command(
            "betterleaks.generic-credential-uri",
            &crate::rules::Validation::CredentialUri,
            "hunter2",
            &dependent,
            None,
            None,
        )
        .expect("validate command should be generated");

        assert!(command.contains(uri));
        assert!(!command.ends_with("'hunter2'"));
    }

    #[test]
    fn credential_uri_blast_radius_command_requires_supported_database_target() {
        let database_uri = "postgresql://alice:hunter2@db.internal/app";
        let database_captures = BTreeMap::from([
            ("URI".to_string(), database_uri.to_string()),
            ("SCHEME".to_string(), "postgresql".to_string()),
        ]);
        let database_command = build_blast_radius_command(
            "betterleaks.generic-credential-uri",
            &crate::rules::Validation::CredentialUri,
            false,
            "hunter2",
            &default_blast_radius_context(&database_captures),
        )
        .expect("database credential URI should support blast-radius mapping");
        assert!(database_command.contains(database_uri));

        let http_captures = BTreeMap::from([
            ("URI".to_string(), "https://alice:hunter2@service.example/api".to_string()),
            ("SCHEME".to_string(), "https".to_string()),
        ]);
        assert!(
            build_blast_radius_command(
                "betterleaks.generic-credential-uri",
                &crate::rules::Validation::CredentialUri,
                false,
                "hunter2",
                &default_blast_radius_context(&http_captures),
            )
            .is_none()
        );
    }

    #[test]
    fn build_validate_command_includes_static_secret_for_aws_session_token() {
        let dependent = BTreeMap::from([(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "aws-static-secret".to_string(),
        )]);

        let cmd = build_validate_command(
            "custom.aws.session-token",
            &crate::rules::Validation::AWS,
            "session-token",
            &dependent,
            Some("ASIAIOSFODNN7EXAMPLE"),
            None,
        )
        .expect("validate command should be generated");

        assert!(cmd.contains("--var AKID='ASIAIOSFODNN7EXAMPLE'"), "{cmd}");
        assert!(cmd.contains("--var AWS_SECRET_ACCESS_KEY='aws-static-secret'"), "{cmd}");
        assert!(cmd.ends_with("'session-token'"), "{cmd}");
    }

    #[test]
    fn aws_session_token_blast_radius_command_requires_static_secret() {
        assert!(
            build_blast_radius_command(
                "betterleaks.aws-session-token",
                &crate::rules::Validation::AWS,
                true,
                "session-token",
                &BlastRadiusCommandContext {
                    dependent_captures: &BTreeMap::new(),
                    akid_from_captures: Some("ASIAIOSFODNN7EXAMPLE"),
                    akid_from_validation_body: None,
                    rules_path: &[],
                    load_builtins: true,
                },
            )
            .is_none()
        );

        let dependent = BTreeMap::from([(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "aws-static-secret".to_string(),
        )]);
        let command = build_blast_radius_command(
            "betterleaks.aws-session-token",
            &crate::rules::Validation::AWS,
            true,
            "session-token",
            &BlastRadiusCommandContext {
                dependent_captures: &dependent,
                akid_from_captures: Some("ASIAIOSFODNN7EXAMPLE"),
                akid_from_validation_body: None,
                rules_path: &[],
                load_builtins: true,
            },
        )
        .expect("complete session credentials should produce a blast-radius command");
        assert!(command.contains("--var AWS_SECRET_ACCESS_KEY='aws-static-secret'"));
    }

    #[test]
    fn aws_session_token_commands_accept_dependency_only_access_key_id() {
        let dependent = BTreeMap::from([
            ("AKID".to_string(), "ASIAIOSFODNN7EXAMPLE".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "aws-static-secret".to_string()),
        ]);

        let validate_command = build_validate_command(
            "betterleaks.aws-session-token",
            &crate::rules::Validation::AWS,
            "session-token",
            &dependent,
            None,
            None,
        )
        .expect("dependency-only credentials should produce a validate command");
        assert!(validate_command.contains("--var AKID='ASIAIOSFODNN7EXAMPLE'"));

        let blast_radius_command = build_blast_radius_command(
            "betterleaks.aws-session-token",
            &crate::rules::Validation::AWS,
            true,
            "session-token",
            &default_blast_radius_context(&dependent),
        )
        .expect("dependency-only credentials should produce a blast-radius command");
        assert!(blast_radius_command.contains("--var AKID='ASIAIOSFODNN7EXAMPLE'"));
        assert!(blast_radius_command.contains("--var AWS_SECRET_ACCESS_KEY='aws-static-secret'"));
    }

    #[test]
    fn aws_commands_ignore_empty_dependency_values() {
        let dependent = BTreeMap::from([
            ("AKID".to_string(), String::new()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "aws-static-secret".to_string()),
        ]);

        let command = build_blast_radius_command(
            "betterleaks.aws-session-token",
            &crate::rules::Validation::AWS,
            true,
            "session-token",
            &BlastRadiusCommandContext {
                dependent_captures: &dependent,
                akid_from_captures: Some("ASIAIOSFODNN7EXAMPLE"),
                akid_from_validation_body: None,
                rules_path: &[],
                load_builtins: true,
            },
        )
        .expect("a non-empty captured access key ID should be used as a fallback");

        assert!(command.contains("--var AKID='ASIAIOSFODNN7EXAMPLE'"));
        assert!(!command.contains("--var AKID=''"));
    }

    #[test]
    fn blast_radius_command_preserves_custom_rule_loading_flags() {
        let rules_path = PathBuf::from("team's rules");
        let command = build_blast_radius_command(
            "custom.example",
            &crate::rules::Validation::GCP,
            false,
            "credential",
            &BlastRadiusCommandContext {
                dependent_captures: &BTreeMap::new(),
                akid_from_captures: None,
                akid_from_validation_body: None,
                rules_path: &[rules_path],
                load_builtins: false,
            },
        )
        .expect("custom rule should produce a blast-radius command");

        assert!(command.contains("--rule 'custom.example'"), "{command}");
        assert!(command.contains("--rules-path 'team'\\''s rules'"), "{command}");
        assert!(command.contains("--no-builtins"), "{command}");
    }

    #[test]
    fn generated_commands_quote_custom_rule_ids() {
        let rule_id = "custom.example; echo unsafe";
        let validation = crate::rules::Validation::GCP;
        let validate = build_validate_command(
            rule_id,
            &validation,
            "credential",
            &BTreeMap::new(),
            None,
            None,
        )
        .expect("custom rule should produce a validate command");
        let blast_radius = build_blast_radius_command(
            rule_id,
            &validation,
            false,
            "credential",
            &default_blast_radius_context(&BTreeMap::new()),
        )
        .expect("custom rule should produce a blast-radius command");

        assert!(validate.contains("--rule 'custom.example; echo unsafe'"), "{validate}");
        assert!(blast_radius.contains("--rule 'custom.example; echo unsafe'"), "{blast_radius}");
    }

    #[test]
    fn extract_template_vars_includes_filter_argument_vars() {
        let text = "Basic {{ NEXT_PUBLIC_VERCEL_APP_CLIENT_ID | default: VERCEL_APP_CLIENT_ID | append: ':' | append: VERCEL_APP_CLIENT_SECRET | b64enc }}";
        let vars = extract_template_vars(text);

        assert!(vars.contains("NEXT_PUBLIC_VERCEL_APP_CLIENT_ID"));
        assert!(vars.contains("VERCEL_APP_CLIENT_ID"));
        assert!(vars.contains("VERCEL_APP_CLIENT_SECRET"));
        assert!(!vars.contains("APPEND"));
        assert!(!vars.contains("DEFAULT"));
        assert!(!vars.contains("B64ENC"));
    }

    #[test]
    fn build_revoke_command_is_emitted_when_required_vars_missing() {
        // Revocation template requires ACCOUNTIDENTIFIER, but the finding doesn't have it.
        let revocation = Revocation::Http(crate::rules::HttpValidation {
            request: crate::rules::HttpRequest {
                method: "DELETE".to_string(),
                url: "https://example.com/revoke?accountIdentifier={{ ACCOUNTIDENTIFIER }}&token={{ TOKEN }}"
                    .to_string(),
                headers: BTreeMap::new(),
                body: None,
                response_matcher: None,
                multipart: None,
                response_is_html: false,
            },
            multipart: None,
        });

        let cmd = build_revoke_command(
            "custom.example.token",
            &revocation,
            "secret",
            &BTreeMap::new(),
            None,
            None,
        );

        let cmd = cmd.expect("command should still be emitted when vars are missing");
        assert!(cmd.contains("kingfisher revoke --rule 'custom.example.token'"));
        assert!(cmd.contains("'secret'"));
    }

    #[test]
    fn betterleaks_aws_revocation_binding_uses_component_as_secret() {
        let mut rules = crate::defaults::get_builtin_rules(Some(Confidence::Low)).unwrap();
        let syntax = rules.rules.remove("betterleaks.aws-access-token").unwrap();
        let Some(crate::rules::Validation::Betterleaks(validation)) = &syntax.validation else {
            panic!("AWS should use Betterleaks validation");
        };
        let bindings = validation.capabilities.revocation_bindings.as_ref().unwrap();
        let component_variable = validation.components["aws-secret-access-key"].clone();
        let mut variables = BTreeMap::from([(
            component_variable,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
        )]);
        let finding_secret = "AKIAIOSFODNN7EXAMPLE";
        let revocation_secret = resolve_betterleaks_capability_source(
            &bindings.secret,
            finding_secret,
            validation,
            &variables,
        )
        .unwrap()
        .to_string();
        for (name, source) in &bindings.variables {
            let value = resolve_betterleaks_capability_source(
                source,
                finding_secret,
                validation,
                &variables,
            )
            .unwrap()
            .to_string();
            variables.insert(name.clone(), value);
        }

        let cmd = build_revoke_command(
            &syntax.id,
            syntax.revocation.as_ref().unwrap(),
            &revocation_secret,
            &variables,
            None,
            None,
        )
        .unwrap();

        assert!(cmd.contains("--var AKID='AKIAIOSFODNN7EXAMPLE'"), "{cmd}");
        assert!(cmd.ends_with("'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"), "{cmd}");
    }
}
