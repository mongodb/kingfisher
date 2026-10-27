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
use liquid_core::ValueView;
use reqwest::Client;
use tokio::sync::Semaphore;

#[cfg(test)]
use super::engine::text;
use super::{CredentialInputDiagnostic, ValidationEngine, ValidationReason, ValidationResult};
use crate::{Finding, ValidationOutcome, scanner::finding_is_within};

// Per-call cache: keys hash the complete rule and resolved inputs. Completed
// provider results, including transient failures, are shared within this batch.
// A deadline permits one retry with a larger budget; capping retries avoids
// repeated attempts for nearly equal candidate-search budgets. Cancellation
// commits nothing; the next validation call always gets a fresh cache.
type ValidationCacheCell = tokio::sync::Mutex<Option<CachedValidationResult>>;
type ValidationCache =
    parking_lot::Mutex<std::collections::HashMap<[u8; 32], Arc<ValidationCacheCell>>>;

struct CachedValidationResult {
    result: ValidationResult,
    timeout: Duration,
    deadline_retry_used: bool,
}

impl CachedValidationResult {
    fn reusable_with(&self, timeout: Duration) -> bool {
        self.result.reason != Some(ValidationReason::DeadlineExceeded)
            || self.deadline_retry_used
            || self.timeout.is_zero()
            || (!timeout.is_zero() && timeout <= self.timeout)
    }
}

fn validation_cache_cell(
    cache: &ValidationCache,
    inputs: &impl serde::Serialize,
) -> Arc<ValidationCacheCell> {
    use sha2::{Digest, Sha256};
    let Ok(inputs) = serde_json::to_vec(inputs) else {
        // Memoization is optional: an unsupported future rule representation
        // must not panic or share a result under an incomplete cache key.
        return Arc::default();
    };
    let key: [u8; 32] = Sha256::digest(inputs).into();
    cache.lock().entry(key).or_default().clone()
}

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
    // Private validation evidence is retained only for explicitly requested analysis.
    analysis_data: Option<serde_json::Value>,
    selected_http_fallback: Option<String>,
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
        self.analysis_data = None;
        self
    }

    /// Whether both snapshots identify the same rule, original revocation
    /// definition and complete action inputs. Different endpoint/configuration
    /// snapshots and different compound credential pairs remain distinct.
    pub fn same_revocation_target(&self, other: &Self) -> bool {
        self.finding.rule_id == other.finding.rule_id
            && self.finding.rule().syntax().revocation == other.finding.rule().syntax().revocation
            && self.finding.rule().syntax().fallbacks == other.finding.rule().syntax().fallbacks
            && match (
                self.credential.as_ref().and_then(|c| c.revocation.as_ref()),
                other.credential.as_ref().and_then(|c| c.revocation.as_ref()),
            ) {
                (Some(a), Some(b)) => a.secret == b.secret && a.variables == b.variables,
                _ => false,
            }
    }

    /// Whether the selected environment defines a revocation action (not readiness).
    pub fn revocation_supported(&self) -> bool {
        self.finding
            .rule()
            .syntax()
            .selected_revocation(self.selected_http_fallback.as_deref())
            .ok()
            .flatten()
            .is_some()
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
        mut credential: Option<ResolvedCredential>,
        mut input_diagnostics: Vec<CredentialInputDiagnostic>,
        parser: &liquid::Parser,
    ) -> ValidatedFinding {
        if matches!(finding.rule().syntax().validation, Some(Validation::Http(_)))
            && let Some(credential) = credential.as_mut()
        {
            // Endpoint identity is trusted execution state, never a finding's
            // capture or a caller-supplied override. Replace any such bindings.
            let endpoint_variables = self.endpoint_variables();
            for variables in std::iter::once(&mut credential.variables)
                .chain(credential.revocation.iter_mut().map(|inputs| &mut inputs.variables))
            {
                for name in [
                    "VALIDATION_ENDPOINT_INDEX",
                    "VALIDATION_FALLBACK_ID",
                    "VALIDATION_ENDPOINT_COUNT",
                    "VALIDATION_URL",
                    "VALIDATION_ORIGIN",
                ] {
                    variables.remove(name);
                }
                variables.extend(endpoint_variables.clone());
            }
            if let Some(id) = self.accepted_http_fallback.as_deref() {
                input_diagnostics.retain(|issue| issue.stage != "revocation");
                credential.revocation_reason = None;
                let action = finding.rule().syntax().selected_revocation(Some(id)).ok().flatten();
                let mut issues = Vec::new();
                if let Some(action) = action.as_deref() {
                    let mut values = credential.variables.clone();
                    values.insert("TOKEN".into(), credential.secret.clone());
                    super::preparation::revocation(parser, action, &values, &mut issues);
                }
                credential.revocation =
                    action.filter(|_| issues.is_empty()).map(|_| RevocationInputs {
                        secret: credential.secret.clone(),
                        variables: credential.variables.clone(),
                    });
                credential.revocation_reason = issues.first().map(diagnostic_reason);
                input_diagnostics.extend(issues);
            }
        }
        input_diagnostics.extend(self.input_diagnostics);
        ValidatedFinding {
            analysis_data: self.analysis_data,
            selected_http_fallback: self.accepted_http_fallback,
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
    oauth2_tokens: super::OAuth2TokenCache,
    parser: Arc<liquid::Parser>,
    permits: Arc<Semaphore>,
    concurrency: usize,
    timeout: Duration,
    retries: u32,
    http_fallbacks: bool,
    max_response_bytes: usize,
    allow_internal_ips: bool,
    variables: BTreeMap<String, String>,
    scan_contexts: Vec<Arc<crate::ScanContext>>,
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
    http_fallbacks: bool,
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
            http_fallbacks: false,
            max_response_bytes: 1 << 20,
            allow_internal_ips: false,
            variables: BTreeMap::new(),
        }
    }
}

impl ValidatorBuilder {
    /// Explicitly permit up to two configured HTTP fallback environments. Defaults to false.
    pub fn http_fallbacks(mut self, enabled: bool) -> Self {
        self.http_fallbacks = enabled;
        self
    }

    /// Supply a pooled client for HTTP, Betterleaks HTTP, Raw HTTP, and Coinbase.
    /// Configure it with redirects disabled and suitable TLS/proxy policy.
    /// OAuth2-authenticated HTTP validators use a separate strict-TLS transport
    /// for both token and verifier requests; this client does not apply to them.
    /// SDK/database/gRPC validators also manage their own transports; the outer
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
            scan_contexts: Vec::new(),
            client,
            oauth2_tokens: Default::default(),
            parser: Arc::new(parser),
            permits: Arc::new(Semaphore::new(self.concurrency)),
            concurrency: self.concurrency,
            timeout: self.timeout,
            retries: self.retries,
            http_fallbacks: self.http_fallbacks,
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
    /// Distinct values are skipped unless every ambiguous dependency explicitly
    /// opts into supported, bounded candidate verification. Pass invisible helpers too.
    pub async fn validate_finding_with_context(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> ValidatedFinding {
        let cache = ValidationCache::default();
        let (result, credential, diagnostics) =
            self.check_finding(finding, context, false, &cache).await;
        result.attach(finding.clone(), credential, diagnostics, &self.parser)
    }

    async fn check_finding(
        &self,
        finding: &Finding,
        context: &[Finding],
        preflight: bool,
        cache: &ValidationCache,
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
        let mut input_diagnostics = self.input_diagnostics(finding, context);
        let can_verify = self.can_verify_candidates(finding, context);
        if preflight
            && let Some(issue) = input_diagnostics.iter().find(|issue| {
                issue.stage != "revocation" && !(can_verify && issue.code == "ambiguous_dependency")
            })
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
                Err(ValidationReason::AmbiguousDependency) if can_verify => {
                    let (result, mut selected) =
                        self.verify_candidates(finding, context, cache).await;
                    if let Some(bound) = selected.as_mut() {
                        apply_revocation_diagnostics(bound, &input_diagnostics);
                    }
                    credential = selected;
                    return result;
                }
                Err(reason) => return ValidationResult::skipped(reason),
            };
            apply_revocation_diagnostics(&mut bound, &input_diagnostics);
            let result = self.validate_bound(finding, &bound, self.timeout, cache).await;
            credential = Some(bound);
            result
        };
        // Each bound check owns its deadline so a timeout can be shared with
        // duplicates before cancellation drops the in-flight cache initializer.
        // Candidate searches separately account for their total remaining budget.
        let result = work.await;
        if credential.is_some() {
            input_diagnostics.retain(|issue| issue.code != "ambiguous_dependency");
        }
        (result, credential, input_diagnostics)
    }

    /// Validate a single scan's full result set, preserving input order.
    ///
    /// Includes invisible helpers so components can be associated before callers
    /// filter reports. Work is bounded; no detached tasks are spawned. Separate
    /// unrelated inputs into separate calls even if their bytes are identical.
    pub async fn validate_findings(&self, findings: Vec<Finding>) -> Vec<ValidatedFinding> {
        let cache = ValidationCache::default();
        let checked: Vec<_> = stream::iter(findings.iter())
            .map(|finding| self.check_finding(finding, &findings, false, &cache))
            .buffered(self.concurrency)
            .collect()
            .await;
        findings
            .into_iter()
            .zip(checked)
            .map(|(finding, (result, credential, diagnostics))| {
                result.attach(finding, credential, diagnostics, &self.parser)
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
        let cache = ValidationCache::default();
        let checked: Vec<_> = stream::iter(candidates.iter())
            .map(|finding| self.check_finding(finding, context, true, &cache))
            .buffered(self.concurrency)
            .collect()
            .await;
        candidates
            .into_iter()
            .zip(checked)
            .map(|(finding, (result, credential, diagnostics))| {
                result.attach(finding, credential, diagnostics, &self.parser)
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

    /// Analyze a verified credential using its original rule and resolved inputs.
    ///
    /// This explicit operation may make additional provider requests. Ordinary
    /// validation never runs the rule's analysis expression. Private evidence from
    /// that exact validation is reused without re-associating components or reading
    /// process environment. Returned provider data may contain sensitive information.
    ///
    /// # Errors
    ///
    /// Rejects non-active findings, unavailable snapshots and absent analysis
    /// expressions. Evaluation, transport and total-deadline failures return errors.
    pub async fn analyze_validated(
        &self,
        validated: &ValidatedFinding,
    ) -> Result<serde_json::Value> {
        ensure!(
            validated.outcome.is_verified_active(),
            "Analysis requires verified_active validation"
        );
        let Some(Validation::Betterleaks(config)) = &validated.finding.rule().syntax().validation
        else {
            anyhow::bail!("Rule has no Betterleaks analysis expression");
        };
        let credential = validated
            .credential
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No resolved credential inputs"))?;
        let analysis_data = validated
            .analysis_data
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No private validation result"))?;
        let mut globals = credential.globals();
        super::betterleaks::add_finding_globals(
            &mut globals,
            &validated.finding,
            &credential.components,
        );
        let captures = globals
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_kstr().to_string(), 0, 0))
            .collect::<Vec<_>>();
        super::limits::NetworkLimits {
            no_timeouts: self.timeout.is_zero(),
            unlimited_response: self.max_response_bytes == 0,
            unlimited_results: false,
        }
        .scope(async {
            super::limits::timeout(self.timeout, async {
                let _permit = self
                    .permits
                    .acquire()
                    .await
                    .map_err(|_| anyhow::anyhow!("Credential analysis executor is closed"))?;
                super::betterleaks::analyze(
                    config,
                    &captures,
                    &globals,
                    &self.client,
                    self.allow_internal_ips,
                    analysis_data,
                )
                .await
            })
            .await
            .map_err(|_| anyhow::anyhow!("Credential analysis timed out"))?
        })
        .await
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
            let matching = self.dependency_matches(finding, context, dependency);
            let distinct: BTreeSet<_> =
                matching.iter().map(|candidate| candidate.secret.as_str()).collect();
            let code = if distinct.len() > 1 {
                // Render only to inspect template syntax/other inputs. Ambiguity
                // still blocks requests unless explicit verification resolves it.
                values.insert(
                    dependency.variable.to_uppercase(),
                    (*distinct.first().unwrap()).into(),
                );
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
        super::preparation::rule_validation(
            &self.parser,
            finding.rule().syntax(),
            self.http_fallbacks,
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

    /// Use compact metadata returned by `Scanner::scan_blob_with_context` for
    /// full-match dependency windows, decoded-buffer isolation and candidate ranking.
    /// Add each input's context once; clones share immutable metadata.
    pub fn with_scan_context(mut self, context: Arc<crate::ScanContext>) -> Self {
        if !self.scan_contexts.iter().any(|existing| Arc::ptr_eq(existing, &context)) {
            self.scan_contexts.push(context);
        }
        self
    }

    fn match_context(&self, finding: &Finding) -> Option<&crate::scan_context::MatchContext> {
        self.scan_contexts.iter().find_map(|context| context.get(finding))
    }

    fn dependency_matches<'a>(
        &self,
        finding: &Finding,
        context: &'a [Finding],
        dependency: &kingfisher_rules::DependsOnRule,
    ) -> Vec<&'a Finding> {
        let metadata = self
            .scan_contexts
            .iter()
            .find_map(|source| source.get(finding).map(|primary| (source, primary)));
        context
            .iter()
            .filter(|candidate| {
                if candidate.rule_id != dependency.rule_id
                    || candidate.blob_id != finding.blob_id
                    || candidate.is_base64_encoded != finding.is_base64_encoded
                {
                    return false;
                }
                if let Some((source, primary)) = metadata {
                    source.get(candidate).is_some_and(|candidate| {
                        primary.buffer == candidate.buffer
                            && dependency.within.as_deref().is_none_or(|within| {
                                crate::scanner::locations_are_within(
                                    &primary.location,
                                    &candidate.location,
                                    within,
                                )
                            })
                    })
                } else {
                    dependency
                        .within
                        .as_deref()
                        .is_none_or(|within| finding_is_within(finding, candidate, within))
                }
            })
            .collect()
    }

    async fn validate_bound(
        &self,
        finding: &Finding,
        bound: &ResolvedCredential,
        timeout: Duration,
        cache: &ValidationCache,
    ) -> ValidationResult {
        let mut globals = bound.globals();
        let cell = if matches!(finding.rule().syntax().validation, Some(Validation::Betterleaks(_)))
        {
            super::betterleaks::add_finding_globals(&mut globals, finding, &bound.components);
            let component_captures: Vec<_> = bound
                .components
                .iter()
                .map(|component| (&component.rule_id, &component.secret, &component.captures))
                .collect();
            validation_cache_cell(
                cache,
                &(
                    finding.rule().syntax(),
                    &bound.secret,
                    &bound.variables,
                    &finding.captures,
                    component_captures,
                ),
            )
        } else {
            validation_cache_cell(
                cache,
                &(finding.rule().syntax(), &bound.secret, &bound.variables, self.http_fallbacks),
            )
        };
        let timeout = if super::limits::NetworkLimits::current().no_timeouts {
            Duration::ZERO
        } else {
            timeout
        };
        let started = tokio::time::Instant::now();
        let (mut cached, attempt_timeout) = match cell.try_lock() {
            // Keep equal configured budgets equal on the uncontended path.
            Ok(cached) => (cached, timeout),
            Err(_) => {
                let Ok(cached) = super::limits::timeout(timeout, cell.lock()).await else {
                    return ValidationResult::unavailable(ValidationReason::DeadlineExceeded);
                };
                let remaining = if timeout.is_zero() {
                    Duration::ZERO
                } else {
                    timeout.saturating_sub(started.elapsed())
                };
                if !timeout.is_zero() && remaining.is_zero() {
                    return ValidationResult::unavailable(ValidationReason::DeadlineExceeded);
                }
                (cached, remaining)
            }
        };
        if let Some(cached) = cached.as_ref()
            && cached.reusable_with(attempt_timeout)
        {
            return cached.result.clone();
        }
        let deadline_retry_used = cached.as_ref().is_some_and(|cached| {
            cached.deadline_retry_used
                || cached.result.reason == Some(ValidationReason::DeadlineExceeded)
        });
        let result = super::limits::timeout(attempt_timeout, async {
            let Ok(_permit) = self.permits.acquire().await else {
                return ValidationResult::unavailable(ValidationReason::RequestFailed);
            };
            ValidationEngine::new(&self.client, &self.parser)
                .oauth2_token_cache(self.oauth2_tokens.clone())
                .timeout(attempt_timeout)
                .retries(self.retries)
                .http_fallbacks(self.http_fallbacks)
                .max_response_bytes(self.max_response_bytes)
                .allow_internal_ips(self.allow_internal_ips)
                .validate(finding.rule(), &globals)
                .await
        })
        .await
        .unwrap_or_else(|_| ValidationResult::unavailable(ValidationReason::DeadlineExceeded));
        // Holding this key's lock coalesces concurrent attempts. External
        // cancellation drops the guard without committing an incomplete result.
        // Record only the budget available after any per-key lock wait.
        *cached = Some(CachedValidationResult {
            result: result.clone(),
            timeout: attempt_timeout,
            deadline_retry_used,
        });
        result
    }

    fn can_verify_candidates(&self, finding: &Finding, context: &[Finding]) -> bool {
        let rule = finding.rule().syntax();
        if !rule.depends_on_rule.iter().flatten().any(|dep| dep.verify_candidates)
            || !super::candidates::supported_with_fallbacks(rule, self.http_fallbacks)
        {
            return false;
        }
        let mut ambiguous = false;
        for dep in rule.depends_on_rule.iter().flatten() {
            let matching = self.dependency_matches(finding, context, dep);
            let distinct: BTreeSet<_> = matching.iter().map(|f| f.secret.as_str()).collect();
            if distinct.len() > 1 {
                if !super::candidates::eligible_dependency(rule, dep) {
                    return false;
                }
                ambiguous = true;
            } else if distinct.is_empty() && !dep.optional {
                return false;
            }
        }
        ambiguous
    }

    async fn verify_candidates(
        &self,
        finding: &Finding,
        context: &[Finding],
        cache: &ValidationCache,
    ) -> (ValidationResult, Option<ResolvedCredential>) {
        use super::candidates::CandidateCheck;
        let mut choices = BTreeMap::new();
        for dep in finding.rule().syntax().depends_on_rule.iter().flatten() {
            let mut matching = self.dependency_matches(finding, context, dep);
            matching.sort_by_key(|candidate| {
                let (matching_name, same_scope, distance) =
                    match (self.match_context(finding), self.match_context(candidate)) {
                        (Some(primary), Some(candidate)) => (
                            primary.family.is_some() && primary.family == candidate.family,
                            primary.scope != 0 && primary.scope == candidate.scope,
                            primary.secret_start.abs_diff(candidate.secret_start),
                        ),
                        _ => (
                            false,
                            false,
                            candidate.location.start_offset.abs_diff(finding.location.start_offset),
                        ),
                    };
                (!matching_name, !same_scope, distance, candidate.secret.as_str())
            });
            let mut seen = BTreeSet::new();
            matching.retain(|candidate| seen.insert(candidate.secret.as_str()));
            if matching.iter().any(|candidate| {
                candidate.secret == "[REDACTED]"
                    || candidate.captures.values().any(|value| value == "[REDACTED]")
            }) {
                return (ValidationResult::skipped(ValidationReason::RedactedInput), None);
            }
            if matching.len() > 1 {
                choices.insert(dep.variable.to_uppercase(), matching);
            }
        }
        let variables: Vec<_> = choices.keys().cloned().collect();
        let lengths: Vec<_> = choices.values().map(Vec::len).collect();
        let result = super::candidates::search(&lengths, self.timeout, |indices, remaining| {
            let selected = variables
                .iter()
                .enumerate()
                .map(|(i, key)| (key.clone(), choices[key][indices[i]]))
                .collect();
            let bound = self.bind_selected(finding, context, &selected);
            async move {
                let Ok(bound) = bound else {
                    return CandidateCheck::Unresolved {
                        reason: "verification was skipped",
                        unavailable: false,
                    };
                };
                let result = self.validate_bound(finding, &bound, remaining, cache).await;
                if result.http_status.is_some_and(|status| (300..400).contains(&status)) {
                    CandidateCheck::Unresolved {
                        reason: "verification returned a redirect",
                        unavailable: true,
                    }
                } else if result.outcome.is_verified_active() {
                    CandidateCheck::Accepted((result, bound))
                } else if result.outcome == ValidationOutcome::VerifiedInactive {
                    CandidateCheck::Rejected
                } else {
                    let skipped = matches!(
                        result.outcome,
                        ValidationOutcome::Skipped | ValidationOutcome::NotAttempted
                    );
                    CandidateCheck::Unresolved {
                        reason: if skipped {
                            "verification was skipped"
                        } else {
                            "verification was unavailable or timed out"
                        },
                        unavailable: !skipped,
                    }
                }
            }
        })
        .await;
        match result {
            Ok((result, bound)) => (result, Some(bound)),
            Err(failure) => {
                tracing::debug!(
                    attempted = failure.attempted,
                    reason = failure.reason,
                    "Credential pairing unresolved"
                );
                (
                    if failure.unavailable {
                        ValidationResult::unavailable(ValidationReason::RequestFailed)
                    } else {
                        ValidationResult::skipped(ValidationReason::AmbiguousDependency)
                    },
                    None,
                )
            }
        }
    }

    fn bind(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> std::result::Result<ResolvedCredential, ValidationReason> {
        self.bind_selected(finding, context, &BTreeMap::new())
    }

    fn bind_selected(
        &self,
        finding: &Finding,
        context: &[Finding],
        selected: &BTreeMap<String, &Finding>,
    ) -> std::result::Result<ResolvedCredential, ValidationReason> {
        let mut values = self.binding_values(finding)?;
        let mut components = Vec::new();
        for dependency in finding.rule().syntax().depends_on_rule.iter().flatten() {
            if dependency.variable.eq_ignore_ascii_case("TOKEN") {
                continue;
            }
            let matching =
                if let Some(&candidate) = selected.get(&dependency.variable.to_uppercase()) {
                    vec![candidate]
                } else {
                    self.dependency_matches(finding, context, dependency)
                };
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

fn apply_revocation_diagnostics(
    bound: &mut ResolvedCredential,
    diagnostics: &[CredentialInputDiagnostic],
) {
    if let Some(issue) = diagnostics.iter().find(|issue| issue.stage == "revocation") {
        bound.revocation = None;
        // Preserve the more precise capability-binding failure when present.
        bound.revocation_reason.get_or_insert(diagnostic_reason(issue));
    }
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
    if !matches!(
        finding.rule().syntax().revocation,
        Some(kingfisher_rules::Revocation::Betterleaks(_))
    ) && let Some(Validation::Betterleaks(validation)) = &finding.rule().syntax().validation
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

    #[tokio::test]
    async fn cache_key_serialization_failure_executes_without_memoizing() {
        struct Unserializable;
        impl serde::Serialize for Unserializable {
            fn serialize<S: serde::Serializer>(
                &self,
                _: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("unsupported cache-key representation"))
            }
        }
        let cache = ValidationCache::default();
        let calls = std::cell::Cell::new(0);
        for _ in 0..2 {
            let cell = validation_cache_cell(&cache, &Unserializable);
            let mut cached = cell.lock().await;
            let result = cached.get_or_insert_with(|| {
                calls.set(calls.get() + 1);
                CachedValidationResult {
                    result: ValidationResult::outcome(ValidationOutcome::VerifiedActive),
                    timeout: Duration::from_secs(1),
                    deadline_retry_used: false,
                }
            });
            assert_eq!(result.result.outcome, ValidationOutcome::VerifiedActive);
        }
        assert_eq!(calls.get(), 2);
        assert!(cache.lock().is_empty());
        let first = validation_cache_cell(&cache, &"supported");
        let second = validation_cache_cell(&cache, &"supported");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cache.lock().len(), 1);
    }

    fn cache_test_inputs(url: &str, concurrency: usize) -> (Validator, Finding) {
        let mut syntax = RuleSyntax::new("acme.cache", "Cache fixture", "(secret)");
        syntax.validation = Some(
            serde_json::from_value(serde_json::json!({
                "type": "Http", "content": {"request": {
                    "method": "GET", "url": url,
                    "response_matcher": [{"type": "StatusMatch", "status": [200]}]
                }}
            }))
            .unwrap(),
        );
        let scanner =
            Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap()));
        let finding = scanner.scan_bytes(b"secret").unwrap().remove(0);
        let validator = Validator::builder()
            .allow_internal_ips(true)
            .client(Client::builder().no_proxy().build().unwrap())
            .concurrency(concurrency)
            .build()
            .unwrap();
        (validator, finding)
    }

    struct CacheTestServer(tokio::task::JoinHandle<()>);

    impl Drop for CacheTestServer {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[tokio::test]
    async fn transient_provider_results_are_shared_only_within_each_validation_call() {
        use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

        for status in [429, 503] {
            // Exercise both queued duplicates and simultaneous per-key waiters.
            for concurrency in [1, 4] {
                let requests = Arc::new(AtomicUsize::new(0));
                let response_status = Arc::new(AtomicU16::new(status));
                let app = axum::Router::new().route(
                    "/verify",
                    axum::routing::get({
                        let requests = requests.clone();
                        let response_status = response_status.clone();
                        move || {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let status = reqwest::StatusCode::from_u16(
                                response_status.load(Ordering::SeqCst),
                            )
                            .unwrap();
                            async move { (status, "authenticated") }
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let url = format!("http://{}/verify", listener.local_addr().unwrap());
                let _server = CacheTestServer(tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                }));
                let (validator, finding) = cache_test_inputs(&url, concurrency);
                let duplicates = vec![finding.clone(); 12];
                // Resolved credentials must still be separate cache keys.
                let mut distinct = finding.clone();
                distinct.secret = "different-secret".into();
                let mut batch = duplicates.clone();
                batch.push(distinct);
                let results = tokio::time::timeout(
                    Duration::from_secs(5),
                    validator.validate_findings(batch),
                )
                .await
                .expect("duplicate provider checks must finish");
                assert_eq!(results.len(), 13);
                assert!(results.iter().all(|result| {
                    result.outcome == ValidationOutcome::Unavailable
                        && result.reason == Some(ValidationReason::RequestFailed)
                        && result.http_status == Some(status)
                }));
                assert_eq!(requests.load(Ordering::SeqCst), 2);

                let prepared =
                    validator.validate_prepared_findings(duplicates.clone(), &duplicates).await;
                assert_eq!(prepared.len(), 12);
                assert!(prepared.iter().all(|result| {
                    result.outcome == ValidationOutcome::Unavailable
                        && result.http_status == Some(status)
                }));
                assert_eq!(requests.load(Ordering::SeqCst), 3);
                // Standalone calls must not inherit a previous batch failure.
                for _ in 0..2 {
                    assert_eq!(
                        validator.validate_finding(&finding).await.outcome,
                        ValidationOutcome::Unavailable
                    );
                }
                assert_eq!(requests.load(Ordering::SeqCst), 5);

                response_status.store(200, Ordering::SeqCst);
                let recovered = validator.validate_findings(duplicates.clone()).await;
                assert!(recovered.iter().all(|result| {
                    result.outcome == ValidationOutcome::VerifiedActive
                        && result.http_status == Some(200)
                }));
                assert_eq!(requests.load(Ordering::SeqCst), 6);
                let prepared =
                    validator.validate_prepared_findings(duplicates.clone(), &duplicates).await;
                assert!(
                    prepared
                        .iter()
                        .all(|result| { result.outcome == ValidationOutcome::VerifiedActive })
                );
                assert_eq!(requests.load(Ordering::SeqCst), 7);
            }
        }
    }

    #[tokio::test]
    async fn hung_provider_attempts_are_bounded_per_batch_even_with_growing_budgets() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        for concurrency in [1, 4] {
            let blocked = Arc::new(AtomicBool::new(true));
            let requests = Arc::new(AtomicUsize::new(0));
            let app = axum::Router::new().route(
                "/verify",
                axum::routing::get({
                    let blocked = blocked.clone();
                    let requests = requests.clone();
                    move || {
                        let blocked = blocked.clone();
                        requests.fetch_add(1, Ordering::SeqCst);
                        async move {
                            if blocked.load(Ordering::SeqCst) {
                                std::future::pending::<()>().await;
                            }
                            "authenticated"
                        }
                    }
                }),
            );
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let url = format!("http://{}/verify", listener.local_addr().unwrap());
            let _server = CacheTestServer(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
            let (mut validator, finding) = cache_test_inputs(&url, concurrency);
            validator.timeout = Duration::from_millis(500);
            let duplicates = vec![finding.clone(); 12];
            let results = tokio::time::timeout(
                Duration::from_secs(5),
                validator.validate_findings(duplicates.clone()),
            )
            .await
            .expect("hung duplicates must share a single deadline, not time out sequentially");
            assert!(results.iter().all(|result| {
                result.outcome == ValidationOutcome::Unavailable
                    && result.reason == Some(ValidationReason::DeadlineExceeded)
            }));
            assert_eq!(requests.load(Ordering::SeqCst), 1);
            let prepared = tokio::time::timeout(
                Duration::from_secs(5),
                validator.validate_prepared_findings(duplicates.clone(), &duplicates),
            )
            .await
            .expect("prepared duplicates must also share a single deadline");
            assert!(
                prepared
                    .iter()
                    .all(|result| { result.reason == Some(ValidationReason::DeadlineExceeded) })
            );
            assert_eq!(requests.load(Ordering::SeqCst), 2);

            let bound = validator.bind(&finding, &[]).unwrap();
            let cache = ValidationCache::default();
            let before = requests.load(Ordering::SeqCst);
            for millis in 20..30 {
                let result = validator
                    .validate_bound(&finding, &bound, Duration::from_millis(millis), &cache)
                    .await;
                assert_eq!(result.reason, Some(ValidationReason::DeadlineExceeded));
            }
            // Slightly increasing candidate budgets cannot trigger unbounded
            // attempts. One genuinely larger-budget retry is permitted.
            assert!(requests.load(Ordering::SeqCst) - before <= 2);
            let cell = validation_cache_cell(
                &cache,
                &(
                    finding.rule().syntax(),
                    &bound.secret,
                    &bound.variables,
                    validator.http_fallbacks,
                ),
            );
            assert!(cell.lock().await.as_ref().unwrap().deadline_retry_used);

            blocked.store(false, Ordering::SeqCst);
            let recovered = validator.validate_findings(duplicates).await;
            assert!(
                recovered
                    .iter()
                    .all(|result| { result.outcome == ValidationOutcome::VerifiedActive })
            );
        }
    }

    #[tokio::test]
    async fn candidate_deadline_remains_retryable_with_a_larger_budget() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let blocked = Arc::new(AtomicBool::new(true));
        let app = axum::Router::new().route(
            "/verify",
            axum::routing::get({
                let blocked = blocked.clone();
                move || {
                    let blocked = blocked.clone();
                    async move {
                        if blocked.load(Ordering::SeqCst) {
                            std::future::pending::<()>().await;
                        }
                        "authenticated"
                    }
                }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("http://{}/verify", listener.local_addr().unwrap());
        let _server = CacheTestServer(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let (validator, finding) = cache_test_inputs(&url, 1);
        let bound = validator.bind(&finding, &[]).unwrap();
        let cache = ValidationCache::default();
        let expired =
            validator.validate_bound(&finding, &bound, Duration::from_millis(20), &cache).await;
        assert_eq!(expired.reason, Some(ValidationReason::DeadlineExceeded));
        let cell = validation_cache_cell(
            &cache,
            &(finding.rule().syntax(), &bound.secret, &bound.variables, validator.http_fallbacks),
        );
        assert_eq!(
            cell.lock().await.as_ref().unwrap().result.reason,
            Some(ValidationReason::DeadlineExceeded)
        );
        // Equal/smaller budgets share the timed-out attempt even after recovery.
        blocked.store(false, Ordering::SeqCst);
        for timeout in [Duration::from_millis(20), Duration::from_millis(10)] {
            let result = validator.validate_bound(&finding, &bound, timeout, &cache).await;
            assert_eq!(result.reason, Some(ValidationReason::DeadlineExceeded));
        }
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            validator.validate_bound(&finding, &bound, Duration::from_secs(2), &cache),
        )
        .await
        .expect("a larger candidate budget must retry the expired check");
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    }

    #[tokio::test]
    async fn cancelled_batch_initializer_leaves_the_same_credential_retryable() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let blocked = Arc::new(AtomicBool::new(true));
        let requests = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(tokio::sync::Notify::new());
        let app = axum::Router::new().route(
            "/verify",
            axum::routing::get({
                let blocked = blocked.clone();
                let requests = requests.clone();
                let received = received.clone();
                move || {
                    let blocked = blocked.clone();
                    let received = received.clone();
                    requests.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if blocked.load(Ordering::SeqCst) {
                            received.notify_one();
                            std::future::pending::<()>().await;
                        }
                        "authenticated"
                    }
                }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("http://{}/verify", listener.local_addr().unwrap());
        let _server = CacheTestServer(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let (validator, finding) = cache_test_inputs(&url, 1);
        let bound = validator.bind(&finding, &[]).unwrap();
        let cache = ValidationCache::default();
        {
            let pending =
                validator.validate_bound(&finding, &bound, Duration::from_secs(10), &cache);
            tokio::pin!(pending);
            tokio::select! {
                received = tokio::time::timeout(Duration::from_secs(5), received.notified()) => {
                    received.expect("the initializing request must reach the provider");
                }
                result = &mut pending => panic!("check must remain pending: {result:?}"),
            }
            // Drop the initializing future while retaining this batch's cache.
        }
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        blocked.store(false, Ordering::SeqCst);
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            validator.validate_bound(&finding, &bound, Duration::from_secs(2), &cache),
        )
        .await
        .expect("cancellation must release the cell and shared permit");
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn definitive_batch_cache_entries_are_reused_across_timeout_budgets() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Server(tokio::task::JoinHandle<()>);
        impl Drop for Server {
            fn drop(&mut self) {
                self.0.abort();
            }
        }

        for (status, expected) in [
            (reqwest::StatusCode::OK, ValidationOutcome::VerifiedActive),
            (reqwest::StatusCode::UNAUTHORIZED, ValidationOutcome::VerifiedInactive),
        ] {
            let requests = Arc::new(AtomicUsize::new(0));
            let app = axum::Router::new().route(
                "/verify",
                axum::routing::get({
                    let requests = requests.clone();
                    move || {
                        requests.fetch_add(1, Ordering::SeqCst);
                        async move { (status, "authenticated") }
                    }
                }),
            );
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let url = format!("http://{}/verify", listener.local_addr().unwrap());
            let _server = Server(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
            let mut syntax = RuleSyntax::new("acme.cache", "Cache fixture", "(secret)");
            syntax.validation = Some(
                serde_json::from_value(serde_json::json!({
                    "type": "Http", "content": {"request": {
                        "method": "GET", "url": url,
                        "response_matcher": [{"type": "StatusMatch", "status": [200]}]
                    }}
                }))
                .unwrap(),
            );
            let scanner =
                Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap()));
            let finding = scanner.scan_bytes(b"secret").unwrap().remove(0);
            let validator = Validator::builder()
                .allow_internal_ips(true)
                .client(Client::builder().no_proxy().build().unwrap())
                .build()
                .unwrap();
            let bound = validator.bind(&finding, &[]).unwrap();
            let cache = ValidationCache::default();
            for seconds in [1, 1, 2, 2] {
                let result = tokio::time::timeout(
                    Duration::from_secs(5),
                    validator.validate_bound(
                        &finding,
                        &bound,
                        Duration::from_secs(seconds),
                        &cache,
                    ),
                )
                .await
                .expect("cache probe must finish");
                assert_eq!(result.outcome, expected);
            }
            // Definitive outcomes remain evidence for these inputs even when
            // later occurrences have a different remaining candidate budget.
            assert_eq!(requests.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn repeated_candidate_searches_share_definitive_component_checks() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Server(tokio::task::JoinHandle<()>);
        impl Drop for Server {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let requests = Arc::new(AtomicUsize::new(0));
        let app = axum::Router::new().route(
            "/verify",
            axum::routing::get({
                let requests = requests.clone();
                move |headers: reqwest::header::HeaderMap| {
                    requests.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if headers.get("X-Secret").is_some_and(|value| value == "secret_good1234") {
                            (reqwest::StatusCode::OK, "authenticated")
                        } else {
                            (reqwest::StatusCode::UNAUTHORIZED, "rejected")
                        }
                    }
                }
            }),
        );
        let listener =
            tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = format!("http://{}/verify", listener.local_addr().unwrap());
        let _server =
            Server(tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }));
        let mut primary = RuleSyntax::new("acme.primary", "Primary", "(primary_[a-z]{8})");
        primary.validation = Some(
            serde_json::from_value(serde_json::json!({
                "type": "Http", "content": {"request": {
                    "method": "GET", "url": url,
                    "headers": {"X-Secret": "{{ SECRET }}"},
                    "response_matcher": [{"type": "StatusMatch", "status": [200]}]
                }}
            }))
            .unwrap(),
        );
        primary.depends_on_rule = vec![Some(kingfisher_rules::DependsOnRule {
            rule_id: "acme.component".into(),
            variable: "SECRET".into(),
            optional: false,
            within: None,
            verify_candidates: true,
        })];
        let mut component = RuleSyntax::new("acme.component", "Component", "(secret_[a-z0-9]{8})");
        component.visible = false;
        let scanner = Scanner::new(Arc::new(
            RulesDatabase::from_rules(vec![Rule::new(primary), Rule::new(component)]).unwrap(),
        ));
        let findings = scanner.scan_bytes(
            b"secret_bad12345 primary_abcdefgh primary_abcdefgh\npadding padding padding secret_good1234",
        ).unwrap();
        let validator = Validator::builder()
            .allow_internal_ips(true)
            .client(Client::builder().no_proxy().build().unwrap())
            .concurrency(1)
            .build()
            .unwrap();
        let results =
            tokio::time::timeout(Duration::from_secs(5), validator.validate_findings(findings))
                .await
                .expect("candidate searches must finish");
        let primary: Vec<_> =
            results.iter().filter(|result| result.finding.rule_id == "acme.primary").collect();
        assert_eq!(primary.len(), 2);
        assert!(primary.iter().all(|result| result.outcome == ValidationOutcome::VerifiedActive));
        assert!(primary.iter().all(|result| {
            result.credential.as_ref().unwrap().variables["SECRET"] == "secret_good1234"
        }));
        // Both occurrences must share the rejected and accepted component checks,
        // even though each candidate search has its own remaining timeout budget.
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

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
            &validator.parser,
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
