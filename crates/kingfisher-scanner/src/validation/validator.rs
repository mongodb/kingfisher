//! Application-owned validation orchestration for scanner findings.
use super::limits::ResourceTimeout;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, ensure};
use futures::{StreamExt, stream};
use kingfisher_rules::Validation;
use liquid::{Object, model::Value};
use reqwest::Client;
use tokio::sync::Semaphore;

#[cfg(test)]
use super::engine::text;
use super::{CredentialInputDiagnostic, ValidationEngine, ValidationReason, ValidationResult};
use crate::{Finding, ValidationOutcome, scanner::finding_is_within};

/// Credential inputs resolved once from one scan input. Contains secrets.
///
/// Debug omits all values. Serialization is deliberately left to callers.
#[derive(Clone)]
#[non_exhaustive]
pub struct ResolvedCredential {
    pub secret: String,
    /// Validation variables, including trusted endpoint overrides; excludes TOKEN.
    pub variables: BTreeMap<String, String>,
    /// One representative supporting finding per resolved dependency. Repeated
    /// occurrences of the same value do not enlarge the retained snapshot.
    /// Unrelated and out-of-window findings are excluded.
    pub components: Vec<Finding>,
    pub revocation: Option<RevocationInputs>,
    /// Missing/redacted/invalid revocation bindings, independently of validation.
    pub revocation_reason: Option<ValidationReason>,
}

/// Inputs to the rule's revocation action. Contains secrets.
#[derive(Clone)]
#[non_exhaustive]
pub struct RevocationInputs {
    pub secret: String,
    /// Resolved captures, components, endpoint overrides and capability bindings.
    pub variables: BTreeMap<String, String>,
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedCredential")
            .field("component_count", &self.components.len())
            .field("revocation_reason", &self.revocation_reason)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RevocationInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevocationInputs").finish_non_exhaustive()
    }
}

impl ResolvedCredential {
    fn globals(&self) -> Object {
        let mut values = self.variables.clone();
        values.insert("TOKEN".into(), self.secret.clone());
        values.into_iter().map(|(k, v)| (k.into(), Value::scalar(v))).collect()
    }
}

/// A finding paired with its validation state. The finding still contains secrets.
///
/// Debug output omits credential values. Call [`Self::into_redacted`] before
/// serializing; this type deliberately does not implement `Serialize`.
#[derive(Clone)]
#[non_exhaustive]
pub struct ValidatedFinding {
    pub finding: Finding,
    pub outcome: ValidationOutcome,
    pub reason: Option<ValidationReason>,
    pub http_status: Option<u16>,
    /// Snapshot of the inputs used by validation, before any reporting filters.
    pub credential: Option<ResolvedCredential>,
    /// Offline names/categories from the exact input context and trusted variables.
    pub input_diagnostics: Vec<CredentialInputDiagnostic>,
}

impl ValidatedFinding {
    /// Redact the primary secret and captures after validation is complete.
    /// This does not securely erase prior copies or caller-owned input.
    pub fn into_redacted(mut self) -> Self {
        self.finding.secret = "[REDACTED]".into();
        for value in self.finding.captures.values_mut() {
            *value = "[REDACTED]".into();
        }
        // Drop retained inputs rather than leave a second copy of raw secrets.
        self.credential = None;
        self
    }

    /// Whether both snapshots identify the same rule, original revocation
    /// definition and complete action inputs. Different endpoint/configuration
    /// snapshots and different compound credential pairs remain distinct.
    pub fn same_revocation_target(&self, other: &Self) -> bool {
        self.finding.rule_id == other.finding.rule_id
            && self.finding.rule().syntax().revocation == other.finding.rule().syntax().revocation
            && match (
                self.credential.as_ref().and_then(|c| c.revocation.as_ref()),
                other.credential.as_ref().and_then(|c| c.revocation.as_ref()),
            ) {
                (Some(a), Some(b)) => a.secret == b.secret && a.variables == b.variables,
                _ => false,
            }
    }

    /// Whether the original rule defines a revocation action (not readiness).
    pub fn revocation_supported(&self) -> bool {
        self.finding.rule().syntax().revocation.is_some()
    }
}

impl fmt::Debug for ValidatedFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedFinding")
            .field("rule_id", &self.finding.rule_id)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("http_status", &self.http_status)
            .finish_non_exhaustive()
    }
}

impl ValidationResult {
    fn attach(
        self,
        finding: Finding,
        credential: Option<ResolvedCredential>,
        input_diagnostics: Vec<CredentialInputDiagnostic>,
    ) -> ValidatedFinding {
        ValidatedFinding {
            finding,
            outcome: self.outcome,
            reason: self.reason,
            http_status: self.http_status,
            credential,
            input_diagnostics,
        }
    }
}

/// Reusable validator. Clones share the HTTP pool and concurrency limit.
///
/// Available with `validation`. Call explicitly: scanning alone never
/// invokes this type. Requires a Tokio runtime with I/O and time enabled.
/// No process-wide validation cache or configuration is installed.
#[derive(Clone)]
pub struct Validator {
    client: Client,
    parser: Arc<liquid::Parser>,
    permits: Arc<Semaphore>,
    concurrency: usize,
    timeout: Duration,
    retries: u32,
    max_response_bytes: usize,
    allow_internal_ips: bool,
    variables: BTreeMap<String, String>,
}

/// Configuration for [`Validator`]. Build once and reuse across requests.
///
/// Defaults: 8 concurrent checks, 10-second total deadline per started check
/// (including waiting for a shared permit), 1 MiB HTTP body limit, strict TLS,
/// no redirects, and internal network addresses blocked.
pub struct ValidatorBuilder {
    client: Option<Client>,
    concurrency: usize,
    timeout: Duration,
    retries: u32,
    max_response_bytes: usize,
    allow_internal_ips: bool,
    variables: BTreeMap<String, String>,
}

impl Default for ValidatorBuilder {
    fn default() -> Self {
        Self {
            client: None,
            concurrency: 8,
            timeout: Duration::from_secs(10),
            retries: 0,
            max_response_bytes: 1 << 20,
            allow_internal_ips: false,
            variables: BTreeMap::new(),
        }
    }
}

impl ValidatorBuilder {
    /// Supply a pooled client for HTTP, Betterleaks HTTP, Raw HTTP, and Coinbase.
    /// Configure it with redirects disabled and suitable TLS/proxy policy.
    /// SDK/database/gRPC validators manage their own transports; the outer
    /// deadline and concurrency limit still apply to every validator.
    pub fn client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }
    /// Maximum checks in flight across this validator and all its clones.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.concurrency = concurrency;
        self
    }
    /// Total deadline including permit acquisition, DNS, and multi-step requests.
    /// Zero disables Kingfisher timeouts; injected clients retain their own settings.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    /// Number of YAML HTTP retries after the initial attempt. Defaults to zero.
    /// Retries share the total deadline and rebuild multipart request bodies.
    pub fn retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }
    /// Maximum YAML HTTP response size. Zero also disables Betterleaks and gRPC body caps.
    /// Nonzero values leave the other families' default limits unchanged.
    pub fn max_response_bytes(mut self, limit: usize) -> Self {
        self.max_response_bytes = limit;
        self
    }
    /// Allow internal addresses for explicitly trusted local/private services.
    /// Defaults to false. This is not a DNS-pinning or network sandbox guarantee.
    pub fn allow_internal_ips(mut self, allow: bool) -> Self {
        self.allow_internal_ips = allow;
        self
    }
    /// Set a trusted template/environment variable, such as an enterprise API URL.
    /// Names are uppercased. Detected captures and components take precedence.
    pub fn variable(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.variables.insert(name.into().to_uppercase(), value.into());
        self
    }
    /// Validate configuration and initialize the pooled client and template filters.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or excessive concurrency, or if the HTTP client
    /// or Liquid template parser cannot be initialized.
    pub fn build(self) -> Result<Validator> {
        ensure!(
            self.concurrency > 0 && self.concurrency <= Semaphore::MAX_PERMITS,
            "validation concurrency must be between 1 and Semaphore::MAX_PERMITS"
        );
        let client = match self.client {
            Some(client) => client,
            None => Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .resource_timeout(self.timeout)
                .build()?,
        };
        let parser =
            kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()?;
        Ok(Validator {
            client,
            parser: Arc::new(parser),
            permits: Arc::new(Semaphore::new(self.concurrency)),
            concurrency: self.concurrency,
            timeout: self.timeout,
            retries: self.retries,
            max_response_bytes: self.max_response_bytes,
            allow_internal_ips: self.allow_internal_ips,
            variables: self.variables,
        })
    }
}

impl Validator {
    /// Start a validator configuration with default limits and transport policy.
    pub fn builder() -> ValidatorBuilder {
        ValidatorBuilder::default()
    }

    /// Validate a standalone finding. Missing required components yield `Skipped`.
    pub async fn validate_finding(&self, finding: &Finding) -> ValidatedFinding {
        self.validate_finding_with_context(finding, &[]).await
    }

    /// Validate using supporting findings from the same scan input.
    ///
    /// Association requires the same blob and encoding and honors `within`.
    /// Distinct competing values are skipped instead of guessing or trying all
    /// credentials. Pass raw findings including invisible helpers.
    pub async fn validate_finding_with_context(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> ValidatedFinding {
        let (result, credential, diagnostics) = self.check_finding(finding, context, false).await;
        result.attach(finding.clone(), credential, diagnostics)
    }

    async fn check_finding(
        &self,
        finding: &Finding,
        context: &[Finding],
        preflight: bool,
    ) -> (ValidationResult, Option<ResolvedCredential>, Vec<CredentialInputDiagnostic>) {
        // Missing inputs cannot change states that do not execute validation.
        let syntax = finding.rule().syntax();
        let cheap_result = if syntax.validation.is_none() {
            Some(ValidationResult::outcome(ValidationOutcome::NotAttempted))
        } else if !syntax.is_authoritative() {
            Some(
                ValidationResult::outcome(ValidationOutcome::NotAttempted)
                    .reason(ValidationReason::NonAuthoritative),
            )
        } else if matches!(syntax.validation, Some(Validation::Assumed)) {
            Some(ValidationResult::outcome(ValidationOutcome::Assumed))
        } else {
            None
        };
        if let Some(result) = cheap_result {
            return (result, None, Vec::new());
        }
        let input_diagnostics = self.input_diagnostics(finding, context);
        if preflight
            && let Some(issue) = input_diagnostics.iter().find(|issue| issue.stage != "revocation")
        {
            return (ValidationResult::skipped(diagnostic_reason(issue)), None, input_diagnostics);
        }
        let mut credential = None;
        let work = async {
            if finding.secret == "[REDACTED]"
                || finding.captures.values().any(|v| v == "[REDACTED]")
            {
                return ValidationResult::skipped(ValidationReason::RedactedInput);
            }
            let mut bound = match self.bind(finding, context) {
                Ok(bound) => bound,
                Err(reason) => return ValidationResult::skipped(reason),
            };
            if let Some(issue) = input_diagnostics.iter().find(|issue| issue.stage == "revocation")
            {
                bound.revocation = None;
                // Capability binding already supplied its precise failure category.
                // Template inspection adds a reason only when binding succeeded.
                bound.revocation_reason.get_or_insert(diagnostic_reason(issue));
            }
            let globals = bound.globals();
            credential = Some(bound);
            let Ok(_permit) = self.permits.acquire().await else {
                return ValidationResult::unavailable(ValidationReason::RequestFailed);
            };
            ValidationEngine::new(&self.client, &self.parser)
                .timeout(self.timeout)
                .retries(self.retries)
                .max_response_bytes(self.max_response_bytes)
                .allow_internal_ips(self.allow_internal_ips)
                .validate(finding.rule(), &globals)
                .await
        };
        let result = super::limits::timeout(self.timeout, work)
            .await
            .unwrap_or_else(|_| ValidationResult::unavailable(ValidationReason::DeadlineExceeded));
        (result, credential, input_diagnostics)
    }

    /// Validate a single scan's full result set, preserving input order.
    ///
    /// Includes invisible helpers so components can be associated before callers
    /// filter reports. Work is bounded; no detached tasks are spawned. Separate
    /// unrelated inputs into separate calls even if their bytes are identical.
    pub async fn validate_findings(&self, findings: Vec<Finding>) -> Vec<ValidatedFinding> {
        let checked: Vec<_> = stream::iter(findings.iter())
            .map(|finding| self.check_finding(finding, &findings, false))
            .buffered(self.concurrency)
            .collect()
            .await;
        findings
            .into_iter()
            .zip(checked)
            .map(|(finding, (result, credential, diagnostics))| {
                result.attach(finding, credential, diagnostics)
            })
            .collect()
    }

    /// Explicitly validate selected prepared candidates using complete context
    /// from one input. Missing/ambiguous/redacted/template inputs skip provider
    /// work; supporting context is associated but is not itself validated.
    /// Preserves candidate order and the configured concurrency bound.
    pub async fn validate_prepared_findings(
        &self,
        candidates: Vec<Finding>,
        context: &[Finding],
    ) -> Vec<ValidatedFinding> {
        let checked: Vec<_> = stream::iter(candidates.iter())
            .map(|finding| self.check_finding(finding, context, true))
            .buffered(self.concurrency)
            .collect()
            .await;
        candidates
            .into_iter()
            .zip(checked)
            .map(|(finding, (result, credential, diagnostics))| {
                result.attach(finding, credential, diagnostics)
            })
            .collect()
    }

    /// Clone execution policy/client and overlay explicit, case-insensitive variables.
    /// Captures and associated components still take precedence during binding.
    pub fn with_variables(&self, variables: BTreeMap<String, String>) -> Self {
        let mut clone = self.clone();
        clone
            .variables
            .extend(variables.into_iter().map(|(key, value)| (key.to_uppercase(), value)));
        clone
    }

    /// Inspect one candidate and its complete same-input context without provider
    /// requests. Uses the same defaults, capture precedence and component windows
    /// as validation, plus real Liquid parsing/rendering of HTTP/gRPC templates.
    /// Diagnostics omit values, source/endpoint URLs and parser/provider bodies.
    /// Conditional templates may over-report lexical names after a render error;
    /// Betterleaks expression branches and provider permissions aren't proven here.
    pub fn input_diagnostics(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> Vec<CredentialInputDiagnostic> {
        let mut diagnostics = Vec::new();
        let mut values = match self.binding_values(finding) {
            Ok(values) => values,
            Err(_) => {
                return vec![CredentialInputDiagnostic::new(
                    "dependency",
                    "ambiguous_dependency",
                    None,
                )];
            }
        };
        for (name, value) in &values {
            if value == "[REDACTED]" {
                diagnostics.push(CredentialInputDiagnostic::new(
                    "dependency",
                    "redacted_input",
                    Some(name.clone()),
                ));
            }
        }
        for dependency in finding.rule().syntax().depends_on_rule.iter().flatten() {
            if dependency.variable.eq_ignore_ascii_case("TOKEN") {
                continue;
            }
            let matching = dependency_matches(finding, context, dependency);
            let distinct: BTreeSet<_> =
                matching.iter().map(|candidate| candidate.secret.as_str()).collect();
            let code = if distinct.len() > 1 {
                Some("ambiguous_dependency")
            } else if let Some(value) = distinct.first() {
                values.insert(dependency.variable.to_uppercase(), (*value).into());
                (*value == "[REDACTED]").then_some("redacted_input")
            } else {
                (!dependency.optional).then_some("missing_dependency")
            };
            if let Some(code) = code {
                let mut diagnostic = CredentialInputDiagnostic::new(
                    "dependency",
                    code,
                    Some(dependency.variable.to_uppercase()),
                );
                diagnostic.rule_id = Some(dependency.rule_id.clone());
                diagnostics.push(diagnostic);
            }
        }
        super::preparation::validation(
            &self.parser,
            finding.rule().syntax().validation.as_ref(),
            &values,
            &mut diagnostics,
        );
        if let Some(action) = &finding.rule().syntax().revocation {
            let mut credential = ResolvedCredential {
                secret: finding.secret.clone(),
                variables: values.clone(),
                components: Vec::new(),
                revocation: None,
                revocation_reason: None,
            };
            credential.variables.remove("TOKEN");
            match resolve_revocation(finding, &credential) {
                Ok(inputs) => {
                    let mut values = inputs.variables;
                    values.insert("TOKEN".into(), inputs.secret);
                    super::preparation::revocation(&self.parser, action, &values, &mut diagnostics);
                }
                Err(reason) => {
                    let code = match reason {
                        ValidationReason::RedactedInput => "redacted_input",
                        ValidationReason::MissingDependency => "missing_dependency",
                        _ => "invalid_configuration",
                    };
                    let mut named = false;
                    if let Some(Validation::Betterleaks(validation)) =
                        &finding.rule().syntax().validation
                        && let Some(bindings) = &validation.capabilities.revocation_bindings
                    {
                        for source in
                            std::iter::once(&bindings.secret).chain(bindings.variables.values())
                        {
                            if let Some(component) = source.strip_prefix("components.")
                                && let Some(variable) = validation.components.get(component)
                                && !values.contains_key(&variable.to_uppercase())
                            {
                                diagnostics.push(CredentialInputDiagnostic::new(
                                    "revocation",
                                    code,
                                    Some(variable.to_uppercase()),
                                ));
                                named = true;
                            }
                        }
                    }
                    if !named {
                        diagnostics.push(CredentialInputDiagnostic::new("revocation", code, None));
                    }
                }
            }
        }
        let mut seen = BTreeSet::new();
        diagnostics.retain(|issue| {
            seen.insert((issue.stage, issue.code, issue.variable.clone(), issue.rule_id.clone()))
        });
        diagnostics
    }

    fn binding_values(
        &self,
        finding: &Finding,
    ) -> std::result::Result<BTreeMap<String, String>, ValidationReason> {
        let mut values = self.variables.clone();
        // Betterleaks uses GITHUB_BASE_URL; YAML rules use GITHUB_API_BASE_URL.
        // Either trusted API override should apply to both unless both are supplied.
        if let Some(base) = values.get("GITHUB_API_BASE_URL").cloned() {
            values.entry("GITHUB_BASE_URL".into()).or_insert(base);
        }
        if let Some(base) = values.get("GITHUB_BASE_URL").cloned() {
            values.entry("GITHUB_API_BASE_URL".into()).or_insert(base);
        }
        // Public provider defaults; enterprise endpoints can override these explicitly.
        for (name, value) in [
            ("GITHUB_API_BASE_URL", "https://api.github.com"),
            ("GITHUB_BASE_URL", "https://api.github.com"),
            ("GITHUB_WEB_BASE_URL", "https://github.com"),
            ("GITLAB_API_BASE_URL", "https://gitlab.com/api/v4"),
            ("GITEA_API_BASE_URL", "https://gitea.com/api/v1"),
        ] {
            values.entry(name.into()).or_insert_with(|| value.into());
        }
        let mut captures = BTreeMap::new();
        for (name, value) in &finding.captures {
            let name = name.to_uppercase();
            if name != "TOKEN"
                && captures.insert(name, value.clone()).is_some_and(|previous| previous != *value)
            {
                return Err(ValidationReason::AmbiguousDependency);
            }
        }
        values.extend(captures);
        values.insert("TOKEN".into(), finding.secret.clone());
        Ok(values)
    }

    fn bind(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> std::result::Result<ResolvedCredential, ValidationReason> {
        let mut values = self.binding_values(finding)?;
        let mut components = Vec::new();
        for dependency in finding.rule().syntax().depends_on_rule.iter().flatten() {
            if dependency.variable.eq_ignore_ascii_case("TOKEN") {
                continue;
            }
            let matching = dependency_matches(finding, context, dependency);
            let candidates: BTreeSet<&str> = matching.iter().map(|f| f.secret.as_str()).collect();
            if candidates.len() > 1 {
                return Err(ValidationReason::AmbiguousDependency);
            }
            if let Some(value) = candidates.first() {
                if *value == "[REDACTED]" {
                    return Err(ValidationReason::RedactedInput);
                }
                values.insert(dependency.variable.to_uppercase(), (*value).into());
                // All candidates have the same value; retain one occurrence.
                components.push(matching[0].clone());
            } else if !dependency.optional {
                return Err(ValidationReason::MissingDependency);
            }
        }
        values.remove("TOKEN");
        let mut credential = ResolvedCredential {
            secret: finding.secret.clone(),
            variables: values,
            components,
            revocation: None,
            revocation_reason: None,
        };
        if finding.rule().syntax().revocation.is_some() {
            match resolve_revocation(finding, &credential) {
                Ok(inputs) => credential.revocation = Some(inputs),
                Err(reason) => credential.revocation_reason = Some(reason),
            }
        }
        Ok(credential)
    }
}

fn dependency_matches<'a>(
    finding: &Finding,
    context: &'a [Finding],
    dependency: &kingfisher_rules::DependsOnRule,
) -> Vec<&'a Finding> {
    context
        .iter()
        .filter(|candidate| {
            candidate.rule_id == dependency.rule_id
                && candidate.blob_id == finding.blob_id
                && candidate.is_base64_encoded == finding.is_base64_encoded
                && dependency
                    .within
                    .as_deref()
                    .is_none_or(|within| finding_is_within(finding, candidate, within))
        })
        .collect()
}

fn diagnostic_reason(issue: &CredentialInputDiagnostic) -> ValidationReason {
    match issue.code {
        "ambiguous_dependency" => ValidationReason::AmbiguousDependency,
        "redacted_input" => ValidationReason::RedactedInput,
        "invalid_configuration" => ValidationReason::InvalidConfiguration,
        _ => ValidationReason::MissingDependency,
    }
}

// Resolve capability bindings from the exact variables already used to validate.
// This deliberately does not re-associate findings or consult the environment.
fn resolve_revocation(
    finding: &Finding,
    credential: &ResolvedCredential,
) -> std::result::Result<RevocationInputs, ValidationReason> {
    let mut inputs = RevocationInputs {
        secret: credential.secret.clone(),
        variables: credential.variables.clone(),
    };
    if let Some(Validation::Betterleaks(validation)) = &finding.rule().syntax().validation
        && let Some(bindings) = &validation.capabilities.revocation_bindings
    {
        let resolve = |source: &str| {
            if source == "finding.secret" {
                return Ok(credential.secret.clone());
            }
            let component =
                source.strip_prefix("components.").ok_or(ValidationReason::InvalidConfiguration)?;
            let variable = validation
                .components
                .get(component)
                .ok_or(ValidationReason::InvalidConfiguration)?;
            credential
                .variables
                .get(&variable.to_uppercase())
                .cloned()
                .ok_or(ValidationReason::MissingDependency)
        };
        inputs.secret = resolve(&bindings.secret)?;
        for (name, source) in &bindings.variables {
            if name.eq_ignore_ascii_case("TOKEN") {
                return Err(ValidationReason::InvalidConfiguration);
            }
            inputs.variables.insert(name.to_uppercase(), resolve(source)?);
        }
    }
    if inputs.secret.is_empty()
        || inputs.secret == "[REDACTED]"
        || inputs.variables.values().any(|value| value == "[REDACTED]")
    {
        return Err(ValidationReason::RedactedInput);
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Rule, RuleSyntax, RulesDatabase, Scanner};

    fn aws_findings() -> Vec<Finding> {
        let mut rules = kingfisher_rules::get_builtin_rules(None).unwrap();
        // Preserve the real AWS dependencies and capability bindings, but use
        // synthetic detection patterns so these tests never contain live keys.
        let mut aws = rules.rules.remove("betterleaks.aws-access-token").unwrap();
        aws.pattern = "(AKIAABCDEFGHIJKLMNOP)".into();
        aws.betterleaks_filter = None;
        aws.min_entropy = 0.0;
        for dependency in aws.depends_on_rule.iter_mut().flatten() {
            dependency.verify_candidates = false;
        }
        let helper =
            RuleSyntax::new("betterleaks.aws-secret-access-key", "Secret", "(secret_[a-z]{4})");
        Scanner::new(Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(aws), Rule::new(helper)]).unwrap(),
        ))
        .scan_bytes(b"secret_efgh\n\n\n\n\n\nAKIAABCDEFGHIJKLMNOP\nsecret_abcd\nsecret_abcd")
        .unwrap()
    }

    #[test]
    fn aws_revocation_uses_the_exact_resolved_validation_pair() {
        let findings = aws_findings();
        let primary =
            findings.iter().find(|f| f.rule_id == "betterleaks.aws-access-token").unwrap();
        let validator =
            Validator::builder().variable("AWS_SECRET_ACCESS_KEY", "wrong").build().unwrap();
        let credential = validator.bind(primary, &findings).unwrap();
        assert_eq!(credential.secret, "AKIAABCDEFGHIJKLMNOP");
        assert_eq!(credential.variables["AWS_SECRET_ACCESS_KEY"], "secret_abcd");
        assert_eq!(credential.components.len(), 1);
        assert!(credential.components.iter().all(|f| f.secret == "secret_abcd"));
        let action = credential.revocation.as_ref().unwrap();
        assert_eq!(action.secret, "secret_abcd");
        assert_eq!(action.variables["AKID"], primary.secret);
        assert!(!action.variables.contains_key("TOKEN"));
        assert!(!format!("{credential:?}").contains("secret_abcd"));
        assert!(!format!("{action:?}").contains(&primary.secret));
        let validated = ValidationResult::outcome(ValidationOutcome::VerifiedActive).attach(
            primary.clone(),
            Some(credential),
            Vec::new(),
        );
        assert!(validated.revocation_supported());
        let redacted = validated.into_redacted();
        assert!(redacted.credential.is_none());
        assert_eq!(redacted.finding.secret, "[REDACTED]");
    }

    #[test]
    fn aws_components_reject_missing_ambiguous_and_redacted_values() {
        let mut findings = aws_findings();
        let primary =
            findings.iter().find(|f| f.rule_id == "betterleaks.aws-access-token").unwrap().clone();
        let validator = Validator::builder().build().unwrap();
        assert_eq!(validator.bind(&primary, &[]).unwrap_err(), ValidationReason::MissingDependency);
        let helper = findings.iter_mut().find(|f| f.secret == "secret_abcd").unwrap();
        helper.secret = "different_secret".into();
        assert_eq!(
            validator.bind(&primary, &findings).unwrap_err(),
            ValidationReason::AmbiguousDependency
        );
        for helper in &mut findings {
            if helper.rule_id == "betterleaks.aws-secret-access-key" {
                helper.secret = "[REDACTED]".into();
            }
        }
        assert_eq!(
            validator.bind(&primary, &findings).unwrap_err(),
            ValidationReason::RedactedInput
        );
    }

    #[test]
    fn github_api_override_applies_to_both_template_conventions() {
        let scanner = Scanner::new(Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(RuleSyntax::new(
                "acme.demo",
                "Demo",
                "(synthetic-token)",
            ))])
            .unwrap(),
        ));
        let finding = scanner.scan_bytes(b"synthetic-token").unwrap().remove(0);
        for name in ["GITHUB_BASE_URL", "GITHUB_API_BASE_URL"] {
            let validator = Validator::builder()
                .variable(name, "https://github.example/api/v3")
                .build()
                .unwrap();
            let globals = validator.bind(&finding, &[]).unwrap().globals();
            assert_eq!(text(&globals, "GITHUB_BASE_URL"), "https://github.example/api/v3");
            assert_eq!(text(&globals, "GITHUB_API_BASE_URL"), "https://github.example/api/v3");
        }
    }
}
