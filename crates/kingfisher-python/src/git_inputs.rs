//! PyO3 conversion and ownership for the shared, read-only Git enumerator.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Result, bail};
use kingfisher_scanner::git::{self, GitEvent, GitMode, GitOptions, GitSkipReason};
use pyo3::{prelude::*, types::PyBytes};

use crate::{PyCancellationToken, scan_control, scan_error};

#[derive(FromPyObject)]
struct Scope {
    mode: String,
    refs: Option<Vec<String>>,
    since_commit: Option<String>,
    since_hours: Option<f64>,
    since_time: Option<i64>,
    until_time: Option<i64>,
    branch_root: Option<String>,
    include_unreachable: bool,
}
impl Scope {
    fn into_shared(self) -> Result<git::GitScope> {
        Ok(git::GitScope {
            mode: match self.mode.as_str() {
                "history" => GitMode::History,
                "snapshot" => GitMode::Snapshot,
                "diff" => GitMode::Diff,
                "staged" => GitMode::Staged,
                _ => bail!("unknown Git scope mode"),
            },
            refs: self.refs,
            since_commit: self.since_commit,
            since_hours: self.since_hours,
            since_time: self.since_time,
            until_time: self.until_time,
            branch_root: self.branch_root,
            include_unreachable: self.include_unreachable,
        })
    }
}

/// The shared Arc holds each message and signature once across file descriptors.
#[pyclass(module = "kingfisher_sdk._native", frozen)]
pub(crate) struct GitCommit {
    inner: Arc<git::GitCommit>,
}
type Signature = (String, String, i64, i32);
#[pymethods]
impl GitCommit {
    #[getter]
    fn id(&self) -> String {
        self.inner.id.to_string()
    }
    #[getter]
    fn author(&self) -> Signature {
        signature(&self.inner.author)
    }
    #[getter]
    fn committer(&self) -> Signature {
        signature(&self.inner.committer)
    }
    #[getter]
    fn parents(&self) -> Vec<String> {
        self.inner.parents.iter().map(ToString::to_string).collect()
    }
    #[getter]
    fn message(&self) -> &str {
        &self.inner.message
    }
}
fn signature(sig: &git::GitSignature) -> Signature {
    (sig.name.clone(), sig.email.clone(), sig.timestamp, sig.timezone_offset)
}

type PyItem = (
    String,
    Option<Py<PyBytes>>,
    String,
    Vec<GitCommit>,
    bool,
    Option<bool>,
    Py<PyBytes>,
    Option<&'static str>,
);

#[pyclass(module = "kingfisher_sdk._native", frozen)]
pub(crate) struct GitInputs {
    inner: Mutex<git::GitInputs>,
}

#[pymethods]
impl GitInputs {
    #[new]
    #[pyo3(signature = (path, scope, *, timeout=None, cancellation=None, discover=true, max_blob_size=None, max_commits=None, max_inputs=None, skip_missing_blobs=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        path: PathBuf,
        scope: Scope,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
        discover: bool,
        max_blob_size: Option<u64>,
        max_commits: Option<usize>,
        max_inputs: Option<usize>,
        skip_missing_blobs: bool,
    ) -> PyResult<Self> {
        let control = scan_control(timeout, cancellation.map(|v| v.token.clone()))?;
        py.detach(move || -> Result<Self> {
            let options =
                GitOptions { discover, max_blob_size, max_commits, max_inputs, skip_missing_blobs };
            Ok(Self {
                inner: Mutex::new(git::GitInputs::open(
                    path,
                    scope.into_shared()?,
                    options,
                    control,
                )?),
            })
        })
        .map_err(scan_error)
    }
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__(&self, py: Python<'_>) -> PyResult<Option<PyItem>> {
        let output = py
            .detach(|| -> Result<_> {
                self.inner
                    .lock()
                    .map_err(|_| anyhow::anyhow!("iterator lock poisoned"))?
                    .next()
                    .transpose()
            })
            .map_err(scan_error)?;
        Ok(output.map(|event| match event {
            GitEvent::Input(input) => (
                input.path,
                Some(PyBytes::new(py, &input.data).unbind()),
                input.blob_id.to_string(),
                input.origins.into_iter().map(|inner| GitCommit { inner }).collect(),
                input.staged,
                input.unreachable,
                PyBytes::new(py, &input.raw_path).unbind(),
                None,
            ),
            GitEvent::Skipped { path, raw_path, blob_id, reason } => (
                path,
                None,
                blob_id.to_string(),
                Vec::new(),
                false,
                None,
                PyBytes::new(py, &raw_path).unbind(),
                Some(match reason {
                    GitSkipReason::Missing => "missing",
                    GitSkipReason::Oversized => "max_blob_size",
                }),
            ),
        }))
    }
}
