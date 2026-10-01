//! In-process Python bindings. No CLI subprocess or Python-owned async runtime.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use kingfisher_rules::{Confidence, Rules, RulesDatabase};
use kingfisher_scanner::{Finding, Revoker, Scanner, ScannerConfig, Validator};
use pyo3::{
    exceptions::{PyRuntimeError, PyValueError},
    prelude::*,
};
use tokio::runtime::Runtime;

fn error(err: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}
fn duration(seconds: f64) -> PyResult<Duration> {
    let value = Duration::try_from_secs_f64(seconds)
        .map_err(|_| PyValueError::new_err("timeout must be finite and positive"))?;
    if value.is_zero() {
        return Err(PyValueError::new_err("timeout must be positive"));
    }
    Ok(value)
}
fn runtime() -> PyResult<&'static Runtime> {
    // Share workers across Python objects and keep runtime destruction out of
    // arbitrary Python/Rust async contexts.
    static RUNTIME: OnceLock<std::io::Result<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()
        })
        .as_ref()
        .map_err(error)
}

#[pyclass(module = "kingfisher_sdk._native", name = "Rules", frozen, skip_from_py_object)]
#[derive(Clone)]
struct PyRules {
    db: Arc<RulesDatabase>,
}

#[pymethods]
impl PyRules {
    #[new]
    #[pyo3(signature = (paths, builtins, confidence))]
    fn new(
        py: Python<'_>,
        paths: Vec<PathBuf>,
        builtins: bool,
        confidence: &str,
    ) -> PyResult<Self> {
        let confidence = match confidence {
            "low" => Confidence::Low,
            "medium" => Confidence::Medium,
            "high" => Confidence::High,
            _ => return Err(PyValueError::new_err("confidence must be low, medium, or high")),
        };
        py.detach(move || {
            let mut rules = if builtins {
                kingfisher_rules::get_builtin_rules(Some(confidence)).map_err(error)?
            } else {
                Rules::new()
            };
            if !paths.is_empty() {
                rules.update(Rules::from_paths(paths, confidence).map_err(error)?);
            }
            if rules.is_empty() {
                return Err(PyValueError::new_err("no rules loaded"));
            }
            Ok(Self { db: Arc::new(RulesDatabase::from_rule_collection(rules).map_err(error)?) })
        })
    }
    fn metadata(&self) -> PyResult<String> {
        let rules: Vec<_> = self.db.rules().iter().map(|rule| serde_json::json!({
            "id": rule.id(), "name": rule.name(), "visible": rule.syntax().visible,
            "validation": rule.syntax().validation.is_some(), "revocation": rule.syntax().revocation.is_some(),
        })).collect();
        serde_json::to_string(&rules).map_err(error)
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Finding", frozen, from_py_object)]
#[derive(Clone)]
struct PyFinding {
    finding: Finding,
}
#[pymethods]
impl PyFinding {
    fn to_json(&self, redact: bool) -> PyResult<String> {
        let mut finding = self.finding.clone();
        if redact {
            finding.secret = "[REDACTED]".into();
            for v in finding.captures.values_mut() {
                *v = "[REDACTED]".into();
            }
        }
        serde_json::to_string(&finding).map_err(error)
    }
    #[getter]
    fn visible(&self) -> bool {
        self.finding.rule.syntax().visible
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Scanner", frozen)]
struct PyScanner {
    scanner: Scanner,
}
#[pymethods]
impl PyScanner {
    #[new]
    fn new(
        rules: &PyRules,
        base64: bool,
        dedup: bool,
        redact: bool,
        min_entropy: Option<f32>,
    ) -> PyResult<Self> {
        if min_entropy.is_some_and(|v| !v.is_finite() || !(0.0..=8.0).contains(&v)) {
            return Err(PyValueError::new_err("min_entropy must be between 0 and 8"));
        }
        Ok(Self {
            scanner: Scanner::with_config(
                rules.db.clone(),
                ScannerConfig {
                    enable_base64_decoding: base64,
                    enable_dedup: dedup,
                    redact_secrets: redact,
                    min_entropy_override: min_entropy,
                },
            ),
        })
    }
    fn scan_bytes(&self, py: Python<'_>, data: Vec<u8>) -> PyResult<Vec<PyFinding>> {
        py.detach(|| {
            self.scanner
                .scan_bytes(&data)
                .map(|v| v.into_iter().map(|finding| PyFinding { finding }).collect())
                .map_err(error)
        })
    }
    fn scan_file(&self, py: Python<'_>, path: PathBuf) -> PyResult<Vec<PyFinding>> {
        py.detach(|| {
            self.scanner
                .scan_file(path)
                .map(|v| v.into_iter().map(|finding| PyFinding { finding }).collect())
                .map_err(error)
        })
    }
    fn reset_dedup(&self) {
        self.scanner.reset_dedup();
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Validator", frozen)]
struct PyValidator {
    validator: Validator,
    runtime: &'static Runtime,
}
#[pymethods]
impl PyValidator {
    #[new]
    fn new(
        timeout: f64,
        concurrency: usize,
        retries: u32,
        max_response_bytes: usize,
        allow_internal_ips: bool,
        variables: BTreeMap<String, String>,
    ) -> PyResult<Self> {
        let mut builder = Validator::builder()
            .timeout(duration(timeout)?)
            .concurrency(concurrency)
            .retries(retries)
            .max_response_bytes(max_response_bytes)
            .allow_internal_ips(allow_internal_ips);
        for (k, v) in variables {
            builder = builder.variable(k, v);
        }
        Ok(Self { validator: builder.build().map_err(error)?, runtime: runtime()? })
    }
    fn validate(&self, py: Python<'_>, findings: Vec<PyFinding>) -> PyResult<String> {
        py.detach(|| {
            let results = self.runtime.block_on(
                self.validator.validate_findings(findings.into_iter().map(|v| v.finding).collect()),
            );
            let results: Vec<_> = results
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "outcome": r.outcome, "reason": r.reason, "http_status": r.http_status,
                    })
                })
                .collect();
            serde_json::to_string(&results).map_err(error)
        })
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Revoker", frozen)]
struct PyRevoker {
    rules: PyRules,
    revoker: Revoker,
    runtime: &'static Runtime,
}
#[pymethods]
impl PyRevoker {
    #[new]
    fn new(rules: &PyRules, timeout: f64) -> PyResult<Self> {
        Ok(Self {
            rules: rules.clone(),
            revoker: Revoker::new().map_err(error)?.timeout(duration(timeout)?).map_err(error)?,
            runtime: runtime()?,
        })
    }
    fn revoke(
        &self,
        py: Python<'_>,
        rule_id: String,
        secret: String,
        variables: BTreeMap<String, String>,
    ) -> PyResult<String> {
        if secret.is_empty() || secret == "[REDACTED]" {
            return Err(PyValueError::new_err("a non-redacted secret is required"));
        }
        let rule = self
            .rules
            .db
            .get_rule_by_text_id(&rule_id)
            .ok_or_else(|| PyValueError::new_err("unknown exact rule ID"))?;
        if rule.syntax().revocation.is_none() {
            return Err(PyValueError::new_err("rule has no revocation"));
        }
        // Preserve Python's case-insensitive variable names and secret precedence.
        let mut variables: BTreeMap<_, _> =
            variables.into_iter().map(|(name, value)| (name.to_uppercase(), value)).collect();
        variables.remove("TOKEN");
        // Keep invalid AWS inputs as ValueError in the Python facade.
        if matches!(rule.syntax().revocation, Some(kingfisher_rules::Revocation::AWS)) {
            let akid = variables
                .get("AKID")
                .or_else(|| variables.get("ACCESS_KEY_ID"))
                .ok_or_else(|| PyValueError::new_err("AWS revocation requires AKID"))?;
            kingfisher_scanner::validation::aws::validate_aws_credentials_input(akid, &secret)
                .map_err(|_| PyValueError::new_err("invalid AWS credential format"))?;
        }
        py.detach(|| {
            let result = self
                .runtime
                .block_on(self.revoker.revoke(&rule, &secret, &variables))
                .map_err(|_| error("revocation request failed; outcome may be unknown"))?;
            Ok(serde_json::json!({
                "rule_id": result.rule_id,
                "revoked": result.revoked,
                "http_status": result.status_code,
            })
            .to_string())
        })
    }
}

#[pyfunction]
fn shannon_entropy(data: &[u8]) -> f32 {
    kingfisher_core::calculate_shannon_entropy(data)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyRules>()?;
    m.add_class::<PyScanner>()?;
    m.add_class::<PyFinding>()?;
    m.add_class::<PyValidator>()?;
    m.add_class::<PyRevoker>()?;
    m.add_function(wrap_pyfunction!(shannon_entropy, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn runtime_is_shared_and_can_be_obtained_inside_an_async_context() {
        let first = super::runtime().unwrap();
        let second = super::runtime().unwrap();
        assert!(std::ptr::eq(first, second));
        first.block_on(async {
            assert!(std::ptr::eq(first, super::runtime().unwrap()));
        });
    }
}
