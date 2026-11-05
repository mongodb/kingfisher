use std::{collections::BTreeMap, sync::Arc};

use kingfisher_scanner::{Finding, Revoker, ScanContext, ValidatedFinding, Validator};
use napi::{Env, Result, bindgen_prelude::PromiseRaw};
use napi_derive::napi;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::{
    control::{
        NativeCancellationToken, blocking, control, controlled, duration, failure, interrupted,
        invalid,
    },
    findings::{NativeFinding, report},
    rules::NativeRules,
};

fn diagnostic(value: &kingfisher_scanner::CredentialInputDiagnostic) -> Value {
    json!({ "stage": value.stage, "code": value.code, "variable": value.variable, "ruleId": value.rule_id })
}

fn findings(values: Vec<&NativeFinding>) -> Result<(Vec<Finding>, Option<Arc<ScanContext>>)> {
    let context = values.first().map(|value| value.context.clone());
    if let Some(context) = &context
        && values.iter().any(|value| !Arc::ptr_eq(context, &value.context))
    {
        return Err(invalid("keep findings from one scan input together; do not mix batches"));
    }
    Ok((values.into_iter().map(|value| value.finding.clone()).collect(), context))
}

#[napi(object)]
pub struct NativeValidatorOptions {
    pub timeout_ms: f64,
    pub concurrency: u32,
    pub retries: u32,
    pub max_response_bytes: u32,
    pub allow_internal_ips: bool,
    pub variables: BTreeMap<String, String>,
    pub http_fallbacks: bool,
}

#[napi]
pub struct NativeValidator {
    validator: Validator,
}

#[napi]
impl NativeValidator {
    #[napi(constructor, catch_unwind)]
    pub fn new(options: NativeValidatorOptions) -> Result<Self> {
        let mut builder = Validator::builder()
            .timeout(duration(options.timeout_ms, true)?)
            .concurrency(options.concurrency as usize)
            .retries(options.retries)
            .max_response_bytes(options.max_response_bytes as usize)
            .allow_internal_ips(options.allow_internal_ips)
            .http_fallbacks(options.http_fallbacks);
        for (name, value) in options.variables {
            builder = builder.variable(name, value);
        }
        Ok(Self {
            validator: builder.build().map_err(|_| invalid("invalid validator configuration"))?,
        })
    }

    #[napi(catch_unwind)]
    pub fn with_variables(&self, variables: BTreeMap<String, String>) -> Self {
        Self { validator: self.validator.with_variables(variables) }
    }

    #[napi(catch_unwind)]
    pub fn validate<'env>(
        &self,
        env: &'env Env,
        values: Vec<&NativeFinding>,
        candidate_indices: Option<Vec<u32>>,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Vec<NativeValidatedFinding>>> {
        let control = control(timeout_ms, token)?;
        let (values, context) = findings(values)?;
        let mut validator = self.validator.clone();
        if let Some(context) = &context {
            validator = validator.with_scan_context(context.clone());
        }
        let candidates = if let Some(indices) = candidate_indices {
            if indices.iter().any(|index| *index as usize >= values.len()) {
                return Err(invalid("candidate index is outside the scan batch"));
            }
            Some(indices.into_iter().map(|index| values[index as usize].clone()).collect())
        } else {
            None
        };
        env.spawn_future(async move {
            let results = controlled(&control, async {
                Ok(if let Some(candidates) = candidates {
                    validator.validate_prepared_findings(candidates, &values).await
                } else {
                    validator.validate_findings(values).await
                })
            })
            .await?;
            let Some(context) = context else {
                return Ok(Vec::new());
            };
            Ok(results
                .into_iter()
                .map(|validated| NativeValidatedFinding { validated, context: context.clone() })
                .collect())
        })
    }

    #[napi(catch_unwind)]
    pub fn inspect<'env>(
        &self,
        env: &'env Env,
        values: Vec<&NativeFinding>,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Value>> {
        let control = control(timeout_ms, token)?;
        let (values, context) = findings(values)?;
        let mut validator = self.validator.clone();
        if let Some(context) = context {
            validator = validator.with_scan_context(context);
        }
        env.spawn_future(blocking(control, move |control| {
            let mut groups = Vec::new();
            for finding in &values {
                control.check().map_err(interrupted)?;
                groups.push(Value::Array(
                    validator.input_diagnostics(finding, &values).iter().map(diagnostic).collect(),
                ));
            }
            Ok(Value::Array(groups))
        }))
    }

    #[napi(catch_unwind)]
    pub fn analyze<'env>(
        &self,
        env: &'env Env,
        result: &NativeValidatedFinding,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Value>> {
        let control = control(timeout_ms, token)?;
        let validator = self.validator.clone();
        let validated = result.validated.clone();
        env.spawn_future(async move {
            controlled(&control, async {
                validator
                    .analyze_validated(&validated)
                    .await
                    .map_err(|_| failure("KF_ANALYSIS", "credential analysis failed"))
            })
            .await
        })
    }
}

#[napi]
pub struct NativeValidatedFinding {
    validated: ValidatedFinding,
    context: Arc<ScanContext>,
}

#[napi]
impl NativeValidatedFinding {
    #[napi(catch_unwind)]
    pub fn redacted(&self) -> Self {
        Self { validated: self.validated.clone().into_redacted(), context: self.context.clone() }
    }

    #[napi(getter, catch_unwind)]
    pub fn finding(&self) -> NativeFinding {
        NativeFinding { finding: self.validated.finding.clone(), context: self.context.clone() }
    }

    #[napi(catch_unwind)]
    pub fn to_object(&self, redact: bool) -> Value {
        json!({
            "finding": report(&self.validated.finding, redact),
            "outcome": self.validated.outcome,
            "reason": self.validated.reason,
            "httpStatus": self.validated.http_status,
            "revocationSupported": self.validated.revocation_supported(),
            "revocationReady": self.revocation_ready(),
            "revocationReason": self.validated.credential.as_ref()
                .and_then(|credential| credential.revocation_reason),
            "inputDiagnostics": self.validated.input_diagnostics.iter().map(diagnostic).collect::<Vec<_>>(),
        })
    }

    #[napi(catch_unwind)]
    pub fn credential(&self, redact: bool) -> Value {
        let Some(credential) = &self.validated.credential else {
            return Value::Null;
        };
        let variables = |values: &BTreeMap<String, String>| -> BTreeMap<String, String> {
            values
                .iter()
                .map(|(key, value)| {
                    (key.clone(), if redact { "[REDACTED]".into() } else { value.clone() })
                })
                .collect()
        };
        json!({
            "secret": if redact { "[REDACTED]" } else { &credential.secret },
            "variables": variables(&credential.variables),
            "components": credential.components.iter().map(|finding| report(finding, redact)).collect::<Vec<_>>(),
            "revocation": credential.revocation.as_ref().map(|inputs| json!({
                "secret": if redact { "[REDACTED]" } else { &inputs.secret },
                "variables": variables(&inputs.variables),
            })),
        })
    }

    #[napi(catch_unwind)]
    pub fn same_revocation_as(&self, other: &NativeValidatedFinding) -> bool {
        self.validated.same_revocation_target(&other.validated)
    }

    fn revocation_ready(&self) -> bool {
        self.validated.outcome.is_verified_active()
            && self
                .validated
                .credential
                .as_ref()
                .is_some_and(|credential| credential.revocation.is_some())
    }
}

#[napi]
pub struct NativeRevoker {
    rules: NativeRules,
    revoker: Arc<Revoker>,
    permits: Arc<Semaphore>,
}

fn revocation_error(error: anyhow::Error) -> napi::Error {
    use kingfisher_scanner::validation::revocation::{
        RevocationIndeterminate, RevocationSubmitted,
    };
    let code = if error.is::<RevocationSubmitted>() || error.is::<RevocationIndeterminate>() {
        "KF_REVOCATION_UNKNOWN"
    } else {
        "KF_REVOCATION_FAILED"
    };
    failure(code, "revocation failed; inspect provider state before retrying")
}

fn revocation_interruption(error: napi::Error) -> napi::Error {
    if error.reason.starts_with("KF_CANCELLED:") {
        failure("KF_REVOCATION_CANCELLED", "revocation cancelled; outcome may be unknown")
    } else if error.reason.starts_with("KF_TIMEOUT:") {
        failure("KF_REVOCATION_TIMEOUT", "revocation timed out; outcome may be unknown")
    } else {
        error
    }
}

#[napi]
impl NativeRevoker {
    #[napi(constructor, catch_unwind)]
    pub fn new(rules: &NativeRules, timeout_ms: f64) -> Result<Self> {
        let revoker = Revoker::new()
            .map_err(|_| failure("KF_NATIVE", "revoker initialization failed"))?
            .timeout(duration(timeout_ms, false)?)
            .map_err(|_| invalid("revocation timeout must be positive"))?;
        Ok(Self {
            rules: rules.clone(),
            revoker: Arc::new(revoker),
            permits: Arc::new(Semaphore::new(1)),
        })
    }

    #[napi(catch_unwind)]
    pub fn revoke_validated<'env>(
        &self,
        env: &'env Env,
        result: &NativeValidatedFinding,
        confirm: bool,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Value>> {
        if !confirm {
            return Err(invalid("revocation requires confirm=true"));
        }
        let control = control(timeout_ms, token)?;
        if !result.revocation_ready() {
            return Err(invalid(
                "a verified_active snapshot with resolved revocation inputs is required",
            ));
        }
        let result = result.validated.clone();
        let revoker = self.revoker.clone();
        let permits = self.permits.clone();
        env.spawn_future(async move {
            let _permit = controlled(&control, async {
                permits.acquire_owned().await.map_err(|_| failure("KF_CLOSED", "revoker closed"))
            })
            .await?;
            let response = controlled(&control, async {
                revoker.revoke_validated(&result).await.map_err(revocation_error)
            })
            .await
            .map_err(revocation_interruption)?;
            Ok(json!({ "ruleId": response.rule_id, "revoked": response.revoked,
                "httpStatus": response.status_code }))
        })
    }

    #[napi(catch_unwind)]
    #[allow(clippy::too_many_arguments)] // Private FFI entrypoint; the JS API accepts an options object.
    pub fn revoke_secret<'env>(
        &self,
        env: &'env Env,
        rule_id: String,
        secret: String,
        variables: BTreeMap<String, String>,
        confirm: bool,
        timeout_ms: Option<f64>,
        token: Option<&NativeCancellationToken>,
    ) -> Result<PromiseRaw<'env, Value>> {
        if !confirm {
            return Err(invalid("revocation requires confirm=true"));
        }
        let control = control(timeout_ms, token)?;
        if secret.is_empty() || secret == "[REDACTED]" {
            return Err(invalid("a non-redacted secret is required"));
        }
        let rule = self
            .rules
            .db
            .get_rule_by_text_id(&rule_id)
            .ok_or_else(|| invalid("unknown exact rule ID"))?
            .clone();
        let variables: BTreeMap<_, _> =
            variables.into_iter().map(|(key, value)| (key.to_uppercase(), value)).collect();
        if variables.keys().any(|key| {
            kingfisher_scanner::validation::http_validation::is_validation_endpoint_var(key)
        }) {
            return Err(invalid(
                "VALIDATION_* endpoint state is reserved; pass an original validated snapshot",
            ));
        }
        if variables.contains_key("TOKEN") {
            return Err(invalid("TOKEN is reserved; pass the secret separately"));
        }
        let revoker = self.revoker.clone();
        let permits = self.permits.clone();
        env.spawn_future(async move {
            let _permit = controlled(&control, async {
                permits.acquire_owned().await.map_err(|_| failure("KF_CLOSED", "revoker closed"))
            })
            .await?;
            let response = controlled(&control, async {
                revoker.revoke(&rule, &secret, &variables).await.map_err(revocation_error)
            })
            .await
            .map_err(revocation_interruption)?;
            Ok(json!({ "ruleId": response.rule_id, "revoked": response.revoked,
                "httpStatus": response.status_code }))
        })
    }
}
