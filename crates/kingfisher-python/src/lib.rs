//! In-process Python bindings. No CLI subprocess or Python-owned async runtime.
mod git_inputs;
mod inputs;

use std::{
    collections::BTreeMap,
    future::Future,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use kingfisher_rules::{Confidence, RuleCacheConfig, Rules, RulesDatabase};
use kingfisher_scanner::{
    CancellationToken, Finding, Revoker, ScanAborted, ScanControl, Scanner, ScannerConfig,
    Validator,
};
use pyo3::{
    IntoPyObjectExt,
    exceptions::{PyRuntimeError, PyTimeoutError, PyValueError},
    prelude::*,
    pybacked::PyBackedBytes,
    types::{PyDict, PyList},
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
            let workers = std::thread::available_parallelism().map_or(2, usize::from).clamp(2, 32);
            tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()
        })
        .as_ref()
        .map_err(error)
}

/// Convert structured results without allocating and reparsing a JSON string.
pub(crate) fn json_to_python(py: Python<'_>, value: serde_json::Value) -> PyResult<Py<PyAny>> {
    use serde_json::Value;
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => value.into_py_any(py),
        Value::Number(value) => {
            if let Some(value) = value.as_u64() {
                value.into_py_any(py)
            } else if let Some(value) = value.as_i64() {
                value.into_py_any(py)
            } else {
                value.as_f64().into_py_any(py)
            }
        }
        Value::String(value) => value.into_py_any(py),
        Value::Array(values) => {
            let list = PyList::empty(py);
            for value in values {
                list.append(json_to_python(py, value)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, value) in values {
                dict.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Rules", frozen, skip_from_py_object)]
#[derive(Clone)]
struct PyRules {
    db: Arc<RulesDatabase>,
}

#[pymethods]
impl PyRules {
    #[new]
    #[pyo3(signature = (paths, builtins, confidence, *, cache=true, cache_dir=None))]
    fn new(
        py: Python<'_>,
        paths: Vec<PathBuf>,
        builtins: bool,
        confidence: &str,
        cache: bool,
        cache_dir: Option<PathBuf>,
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
            let db = if cache {
                RulesDatabase::from_rule_collection_with_cache(
                    rules,
                    &RuleCacheConfig::from_dir_or_env(cache_dir),
                )
            } else {
                RulesDatabase::from_rule_collection(rules)
            };
            Ok(Self { db: Arc::new(db.map_err(error)?) })
        })
    }
    fn metadata(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let rules: Vec<_> = self.db.rules().iter().map(|rule| serde_json::json!({
            "id": rule.id(), "name": rule.name(), "visible": rule.syntax().visible,
            "validation": rule.syntax().validation.is_some(), "revocation": rule.syntax().revocation.is_some(),
        })).collect();
        json_to_python(py, serde_json::Value::Array(rules))
    }
    fn detail(&self, py: Python<'_>, rule_id: &str) -> PyResult<Py<PyAny>> {
        let (index, rule) =
            self.db.rules().iter().enumerate().find(|(_, rule)| rule.id() == rule_id).ok_or_else(
                || PyValueError::new_err(format!("unknown exact rule ID: {rule_id}")),
            )?;
        // Inspect the already-loaded definition and confirmation regex without
        // recompilation, provider requests, or modifying the shared database.
        let mut detail = serde_json::to_value(rule.syntax()).map_err(error)?;
        detail["detection_regex"] = serde_json::json!(self.db.anchored_regexes()[index].as_str());
        json_to_python(py, detail)
    }
    fn __len__(&self) -> usize {
        self.db.num_rules()
    }
    #[getter]
    fn cache_status(&self) -> &'static str {
        use kingfisher_rules::RuleCacheStatus;
        match self.db.cache_status() {
            RuleCacheStatus::Loaded => "loaded",
            RuleCacheStatus::Stored => "stored",
            _ => "bypassed",
        }
    }
}

#[pyclass(module = "kingfisher_sdk._native", name = "Finding", frozen, from_py_object)]
#[derive(Clone)]
struct PyFinding {
    finding: Finding,
}
#[pymethods]
impl PyFinding {
    fn to_dict(&self, py: Python<'_>, redact: bool) -> PyResult<Py<PyAny>> {
        // Serialize once into structured values. Never clone the full finding or
        // round-trip text merely to inspect a field.
        let mut finding = serde_json::to_value(&self.finding).map_err(error)?;
        if redact {
            finding["secret"] = "[REDACTED]".into();
            if let Some(captures) = finding["captures"].as_object_mut() {
                for value in captures.values_mut() {
                    *value = "[REDACTED]".into();
                }
            }
        }
        json_to_python(py, finding)
    }
    #[getter]
    fn rule_id(&self) -> &str {
        &self.finding.rule_id
    }
    #[getter]
    fn rule_name(&self) -> &str {
        &self.finding.rule_name
    }
    #[getter]
    fn secret(&self) -> &str {
        &self.finding.secret
    }
    #[getter]
    fn entropy(&self) -> f32 {
        self.finding.entropy
    }
    #[getter]
    fn fingerprint(&self) -> u64 {
        self.finding.fingerprint
    }
    #[getter]
    fn blob_id(&self) -> String {
        self.finding.blob_id.hex()
    }
    #[getter]
    fn is_base64_encoded(&self) -> bool {
        self.finding.is_base64_encoded
    }
    #[getter]
    fn confidence(&self) -> &'static str {
        match self.finding.confidence {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
    #[getter]
    fn location(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_python(py, serde_json::to_value(&self.finding.location).map_err(error)?)
    }
    #[getter]
    fn captures(&self) -> BTreeMap<String, String> {
        self.finding.captures.iter().map(|(key, value)| (key.clone(), value.clone())).collect()
    }
    #[getter]
    fn visible(&self) -> bool {
        self.finding.rule.syntax().visible
    }
}

/// A signal that can be cancelled from another Python thread while scanning.
#[pyclass(module = "kingfisher_sdk._native", name = "CancellationToken", frozen)]
struct PyCancellationToken {
    token: CancellationToken,
}

#[pymethods]
impl PyCancellationToken {
    #[new]
    fn new() -> Self {
        Self { token: CancellationToken::default() }
    }
    fn cancel(&self) {
        self.token.cancel();
    }
    #[getter]
    fn is_cancelled(&self) -> bool {
        self.token.is_cancelled()
    }
}

fn scan_control(
    timeout: Option<f64>,
    cancellation: Option<CancellationToken>,
) -> PyResult<ScanControl> {
    let mut control = ScanControl::default();
    if let Some(timeout) = timeout {
        control = control
            .with_timeout(duration(timeout)?)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
    }
    if let Some(token) = cancellation {
        control = control.with_cancellation(token);
    }
    Ok(control)
}

fn scan_error(err: anyhow::Error) -> PyErr {
    match err.downcast_ref::<ScanAborted>() {
        Some(ScanAborted::TimedOut) => PyTimeoutError::new_err(err.to_string()),
        _ => error(err),
    }
}

/// Await provider work on the calling thread so Ctrl-C can be checked while
/// Python is detached. Dropping the future cancels pending I/O, not a request
/// the provider has already applied. No detached tasks or retries are added.
fn run_async<T: Send, F: Future<Output = T>>(
    py: Python<'_>,
    runtime: &Runtime,
    control: ScanControl,
    operation: impl FnOnce() -> F + Send,
) -> PyResult<T> {
    py.detach(|| {
        runtime.block_on(async {
            control.check().map_err(|err| scan_error(err.into()))?;
            Python::attach(|py| py.check_signals())?;
            let operation = operation();
            tokio::pin!(operation);
            let mut ticks = tokio::time::interval(Duration::from_millis(10));
            loop {
                tokio::select! {
                    result = &mut operation => {
                        control.check().map_err(|err| scan_error(err.into()))?;
                        return Ok(result);
                    }
                    _ = ticks.tick() => {
                        control.check().map_err(|err| scan_error(err.into()))?;
                        Python::attach(|py| py.check_signals())?;
                    }
                }
            }
        })
    })
}

#[derive(FromPyObject)]
struct PyDetectionPolicy {
    inline_ignores: bool,
    ignore_comments: Vec<String>,
    markup_context: bool,
    language: Option<String>,
    cli_match_semantics: bool,
    base64_max_depth: usize,
    base64_max_input_bytes: Option<usize>,
}

#[pyclass(module = "kingfisher_sdk._native", name = "Scanner", frozen)]
struct PyScanner {
    scanner: Scanner,
    detection: Option<kingfisher_scanner::context::DetectionOptions>,
}
#[pymethods]
impl PyScanner {
    #[new]
    #[pyo3(signature = (rules, base64, dedup, redact, min_entropy, *, policy=None))]
    fn new(
        rules: &PyRules,
        base64: bool,
        dedup: bool,
        redact: bool,
        min_entropy: Option<f32>,
        policy: Option<PyDetectionPolicy>,
    ) -> PyResult<Self> {
        if min_entropy.is_some_and(|v| !v.is_finite() || !(0.0..=8.0).contains(&v)) {
            return Err(PyValueError::new_err("min_entropy must be between 0 and 8"));
        }
        Ok(Self {
            detection: policy.map(|policy| kingfisher_scanner::context::DetectionOptions {
                inline_ignores: policy.inline_ignores,
                ignore_comments: policy.ignore_comments,
                markup_context: policy.markup_context,
                language: policy.language,
                cli_match_semantics: policy.cli_match_semantics,
                base64_max_depth: policy.base64_max_depth,
                base64_max_input_bytes: policy.base64_max_input_bytes,
            }),
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
    #[pyo3(signature = (data, *, timeout=None, cancellation=None))]
    fn scan_bytes(
        &self,
        py: Python<'_>,
        data: PyBackedBytes,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Vec<PyFinding>> {
        self.scan_input(py, data, String::new(), timeout, cancellation)
    }
    #[pyo3(signature = (path, *, timeout=None, cancellation=None))]
    fn scan_file(
        &self,
        py: Python<'_>,
        path: PathBuf,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Vec<PyFinding>> {
        let control = scan_control(timeout, cancellation.map(|token| token.token.clone()))?;
        py.detach(|| {
            control.check()?;
            let blob = kingfisher_scanner::Blob::from_file(&path)?;
            self.detect(&blob, &path.to_string_lossy(), &control)
        })
        .map_err(scan_error)
    }
    #[pyo3(signature = (data, path, *, timeout=None, cancellation=None))]
    fn scan_input(
        &self,
        py: Python<'_>,
        data: PyBackedBytes,
        path: String,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Vec<PyFinding>> {
        let control = scan_control(timeout, cancellation.map(|token| token.token.clone()))?;
        py.detach(|| {
            control.check()?;
            let blob = kingfisher_scanner::Blob::from_borrowed(&data);
            self.detect(&blob, &path, &control)
        })
        .map_err(scan_error)
    }
    fn reset_dedup(&self) {
        self.scanner.reset_dedup();
    }
}

impl PyScanner {
    fn detect(
        &self,
        blob: &kingfisher_scanner::Blob,
        path: &str,
        control: &ScanControl,
    ) -> anyhow::Result<Vec<PyFinding>> {
        let findings = match self.detection.as_ref() {
            Some(options) => self
                .scanner
                .scan_blob_at_path_with_options_and_control(blob, path, options, control),
            None => self.scanner.scan_blob_at_path_with_control(blob, path, control),
        }?;
        Ok(findings.into_iter().map(|finding| PyFinding { finding }).collect())
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
    #[pyo3(signature = (findings, *, timeout=None, cancellation=None))]
    fn validate(
        &self,
        py: Python<'_>,
        findings: Vec<PyFinding>,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Py<PyAny>> {
        let control = scan_control(timeout, cancellation.map(|token| token.token.clone()))?;
        let results = run_async(py, self.runtime, control, || {
            self.validator.validate_findings(findings.into_iter().map(|v| v.finding).collect())
        })?;
        let results: Vec<_> = results
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "outcome": r.outcome, "reason": r.reason, "http_status": r.http_status,
                })
            })
            .collect();
        json_to_python(py, serde_json::Value::Array(results))
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
    #[pyo3(signature = (rule_id, secret, variables, *, timeout=None, cancellation=None))]
    fn revoke(
        &self,
        py: Python<'_>,
        rule_id: String,
        secret: String,
        variables: BTreeMap<String, String>,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Py<PyAny>> {
        let control = scan_control(timeout, cancellation.map(|token| token.token.clone()))?;
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
        let result = run_async(py, self.runtime, control, || {
            self.revoker.revoke(&rule, &secret, &variables)
        })?
        .map_err(|err| {
            error(format!(
                "revocation request failed ({}); outcome may be unknown",
                kingfisher_scanner::validation::Revoker::error_category(&err),
            ))
        })?;
        json_to_python(
            py,
            serde_json::json!({
                "rule_id": result.rule_id,
                "revoked": result.revoked,
                "http_status": result.status_code,
            }),
        )
    }
}

#[pyfunction]
fn shannon_entropy(data: &[u8]) -> f32 {
    kingfisher_core::calculate_shannon_entropy(data)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<inputs::Filesystem>()?;
    m.add_class::<git_inputs::GitInputs>()?;
    m.add_class::<git_inputs::GitCommit>()?;
    m.add_function(wrap_pyfunction!(inputs::expand_archive, m)?)?;
    m.add_function(wrap_pyfunction!(inputs::expand_content, m)?)?;
    m.add_class::<PyRules>()?;
    m.add_class::<PyScanner>()?;
    m.add_class::<PyCancellationToken>()?;
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
