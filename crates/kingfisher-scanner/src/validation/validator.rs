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
use super::{ValidationEngine, ValidationReason, ValidationResult};
use crate::{Finding, ValidationOutcome, scanner::finding_is_within};

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
}

impl ValidatedFinding {
    /// Redact the primary secret and captures after validation is complete.
    /// This does not securely erase prior copies or caller-owned input.
    pub fn into_redacted(mut self) -> Self {
        self.finding.secret = "[REDACTED]".into();
        for value in self.finding.captures.values_mut() {
            *value = "[REDACTED]".into();
        }
        self
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
    fn attach(self, finding: Finding) -> ValidatedFinding {
        ValidatedFinding {
            finding,
            outcome: self.outcome,
            reason: self.reason,
            http_status: self.http_status,
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
        self.check_finding(finding, context).await.attach(finding.clone())
    }

    async fn check_finding(&self, finding: &Finding, context: &[Finding]) -> ValidationResult {
        let work = async {
            // Preserve cheap/non-network states even when other checks occupy all permits.
            let Some(validation) = &finding.rule().syntax().validation else {
                return ValidationResult::outcome(ValidationOutcome::NotAttempted);
            };
            if !finding.rule().syntax().is_authoritative() {
                return ValidationResult::outcome(ValidationOutcome::NotAttempted)
                    .reason(ValidationReason::NonAuthoritative);
            }
            if matches!(validation, Validation::Assumed) {
                return ValidationResult::outcome(ValidationOutcome::Assumed);
            }
            if finding.secret == "[REDACTED]"
                || finding.captures.values().any(|v| v == "[REDACTED]")
            {
                return ValidationResult::skipped(ValidationReason::RedactedInput);
            }
            let globals = match self.bind(finding, context) {
                Ok(globals) => globals,
                Err(reason) => return ValidationResult::skipped(reason),
            };
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
        super::limits::timeout(self.timeout, work)
            .await
            .unwrap_or_else(|_| ValidationResult::unavailable(ValidationReason::DeadlineExceeded))
    }

    /// Validate a single scan's full result set, preserving input order.
    ///
    /// Includes invisible helpers so components can be associated before callers
    /// filter reports. Work is bounded; no detached tasks are spawned. Separate
    /// unrelated inputs into separate calls even if their bytes are identical.
    pub async fn validate_findings(&self, findings: Vec<Finding>) -> Vec<ValidatedFinding> {
        let checks: Vec<_> = stream::iter(findings.iter())
            .map(|finding| self.check_finding(finding, &findings))
            .buffered(self.concurrency)
            .collect()
            .await;
        findings.into_iter().zip(checks).map(|(finding, check)| check.attach(finding)).collect()
    }

    fn bind(
        &self,
        finding: &Finding,
        context: &[Finding],
    ) -> std::result::Result<Object, ValidationReason> {
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
        for dependency in finding.rule().syntax().depends_on_rule.iter().flatten() {
            if dependency.variable.eq_ignore_ascii_case("TOKEN") {
                continue;
            }
            let candidates: BTreeSet<&str> = context
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
                .map(|candidate| candidate.secret.as_str())
                .collect();
            if candidates.len() > 1 {
                return Err(ValidationReason::AmbiguousDependency);
            }
            if let Some(value) = candidates.first() {
                if *value == "[REDACTED]" {
                    return Err(ValidationReason::RedactedInput);
                }
                values.insert(dependency.variable.to_uppercase(), (*value).into());
            } else if !dependency.optional {
                return Err(ValidationReason::MissingDependency);
            }
        }
        Ok(values.into_iter().map(|(k, v)| (k.into(), Value::scalar(v))).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Rule, RuleSyntax, RulesDatabase, Scanner};

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
            let globals = validator.bind(&finding, &[]).unwrap();
            assert_eq!(text(&globals, "GITHUB_BASE_URL"), "https://github.example/api/v3");
            assert_eq!(text(&globals, "GITHUB_API_BASE_URL"), "https://github.example/api/v3");
        }
    }
}
