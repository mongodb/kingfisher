//! Explicit, rule-driven credential revocation for embedding applications.
use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context, Result, ensure};
use kingfisher_rules::{Revocation, Rule};
use liquid::{Object, model::Value};
use reqwest::Client;

use super::revocation::{
    DirectRevocationResult, execute_http_revocation, execute_multi_step_revocation,
};

/// Reusable, explicitly invoked revocation runner (requires `validation`).
///
/// Scanning and validation never call this API. The caller selects the credential
/// and supplies companion variables and endpoint overrides required by the rule.
/// HTTP rule requests are not retried. AWS retains its provider-specific retry
/// policy. Requires a Tokio runtime with I/O and time enabled.
/// Provider responses in results and errors may contain sensitive information.
pub struct Revoker {
    client: Client,
    parser: liquid::Parser,
    timeout: Duration,
}

impl Revoker {
    /// Create a runner with strict TLS, redirects disabled, and a 10-second deadline.
    pub fn new() -> Result<Self> {
        Self::with_client(Client::builder().redirect(reqwest::redirect::Policy::none()).build()?)
    }

    /// Use an application-owned HTTP client. Configure TLS, proxies, and redirects
    /// for the intended endpoints. AWS and GCP helpers use their own transports;
    /// the total deadline still applies. HTTP rules may reach internal addresses.
    pub fn with_client(client: Client) -> Result<Self> {
        Ok(Self {
            client,
            parser: kingfisher_rules::register_liquid_filters(liquid::ParserBuilder::with_stdlib())
                .build()?,
            timeout: Duration::from_secs(10),
        })
    }

    /// Set a nonzero total deadline for each call, including multi-step requests.
    /// A timeout cannot undo an already submitted revocation request; its outcome
    /// may be unknown. Do not automatically retry a timed-out operation.
    pub fn timeout(mut self, timeout: Duration) -> Result<Self> {
        ensure!(!timeout.is_zero(), "Revocation timeout must be nonzero");
        self.timeout = timeout;
        Ok(self)
    }

    /// Revoke a known secret using a built-in or custom rule, without scanning.
    ///
    /// Variable names are case-sensitive (normally uppercase). `TOKEN` is reserved
    /// and always comes from `secret`. No environment variables or CLI defaults are
    /// read. Missing configuration and execution failures return errors;
    /// a completed provider response is evaluated by the rule's success matcher.
    pub async fn revoke(
        &self,
        rule: &Rule,
        secret: &str,
        variables: &BTreeMap<String, String>,
    ) -> Result<DirectRevocationResult> {
        ensure!(!secret.is_empty(), "Secret cannot be empty");
        ensure!(!variables.contains_key("TOKEN"), "TOKEN is reserved; pass it as the secret");
        let revocation = rule.syntax().revocation.as_ref().context("Rule has no revocation")?;
        let mut globals = Object::new();
        for (name, value) in variables {
            globals.insert(name.clone().into(), Value::scalar(value.clone()));
        }
        globals.insert("TOKEN".into(), Value::scalar(secret.to_owned()));

        let operation = async {
            let mut result = match revocation {
                Revocation::Http(http) => {
                    ensure!(
                        http.request.response_matcher.as_ref().is_some_and(|m| !m.is_empty()),
                        "Revocation requires a response matcher"
                    );
                    execute_http_revocation(
                        http,
                        &globals,
                        &self.client,
                        &self.parser,
                        self.timeout,
                        0,
                    )
                    .await?
                }
                Revocation::HttpMultiStep(multi) => {
                    ensure!(
                        (1..=2).contains(&multi.steps.len()),
                        "Revocation requires one or two steps"
                    );
                    ensure!(
                        multi
                            .steps
                            .last()
                            .and_then(|step| step.request.response_matcher.as_ref())
                            .is_some_and(|m| !m.is_empty()),
                        "Final revocation step requires a response matcher"
                    );
                    execute_multi_step_revocation(
                        multi,
                        &mut globals,
                        &self.client,
                        &self.parser,
                        self.timeout,
                        0,
                    )
                    .await?
                }
                Revocation::AWS => {
                    let akid = variables
                        .get("AKID")
                        .or_else(|| variables.get("ACCESS_KEY_ID"))
                        .context("AWS revocation requires AKID or ACCESS_KEY_ID")?;
                    super::aws::validate_aws_credentials_input(akid, secret)
                        .map_err(anyhow::Error::msg)?;
                    let (revoked, message) =
                        super::aws::revoke_aws_access_key(akid, secret).await?;
                    DirectRevocationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        revoked,
                        status_code: None,
                        message,
                    }
                }
                Revocation::GCP => {
                    let key_id =
                        variables.get("KEY_ID").or_else(|| variables.get("PRIVATE_KEY_ID"));
                    let outcome = super::gcp::revoke_gcp_service_account_key(
                        secret,
                        key_id.map(String::as_str),
                    )
                    .await?;
                    DirectRevocationResult {
                        rule_id: String::new(),
                        rule_name: String::new(),
                        revoked: outcome.revoked,
                        status_code: outcome.status_code,
                        message: outcome.message,
                    }
                }
            };
            result.rule_id = rule.id().to_owned();
            result.rule_name = rule.name().to_owned();
            Ok(result)
        };
        tokio::time::timeout(self.timeout, operation)
            .await
            .context("Revocation timed out; the credential may already have been revoked")?
    }
}
