//! Incremental, offline input enumeration. No CLI or Git subprocesses.
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Result, bail};
use kingfisher_scanner::{
    ScanControl,
    archive::decompress::{self, CompressedContent},
    extraction::ExtractionLimitExceeded,
};
use pyo3::{exceptions::PyValueError, prelude::*, pybacked::PyBackedBytes, types::PyBytes};

use crate::{PyCancellationToken, scan_control, scan_error};

#[pyclass(module = "kingfisher_sdk._native", name = "Filesystem", frozen)]
pub(crate) struct Filesystem {
    walk: Mutex<ignore::Walk>,
    control: ScanControl,
}

#[pymethods]
impl Filesystem {
    #[new]
    #[pyo3(signature = (roots, *, gitignore=true, hidden=false, max_file_size=None, timeout=None, cancellation=None))]
    fn new(
        roots: Vec<PathBuf>,
        gitignore: bool,
        hidden: bool,
        max_file_size: Option<u64>,
        timeout: Option<f64>,
        cancellation: Option<PyRef<'_, PyCancellationToken>>,
    ) -> PyResult<Self> {
        if roots.is_empty() {
            return Err(PyValueError::new_err("at least one filesystem root is required"));
        }
        let control = scan_control(timeout, cancellation.map(|v| v.token.clone()))?;
        let mut builder = ignore::WalkBuilder::new(&roots[0]);
        for root in &roots[1..] {
            builder.add(root);
        }
        // Avoid machine-global excludes: only the requested roots and their ignore files.
        builder
            .hidden(!hidden)
            .git_ignore(gitignore)
            .git_exclude(gitignore)
            .git_global(false)
            .ignore(gitignore)
            .follow_links(false)
            .max_filesize(max_file_size)
            .filter_entry(|entry| {
                !entry.file_name().to_str().is_some_and(|name| name.eq_ignore_ascii_case(".git"))
            });
        Ok(Self { walk: Mutex::new(builder.build()), control })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<PathBuf>> {
        py.detach(|| {
            let mut walk =
                self.walk.lock().map_err(|_| anyhow::anyhow!("iterator lock poisoned"))?;
            loop {
                self.control.check()?;
                let Some(entry) = walk.next() else { return Ok(None) };
                let entry = entry?;
                if entry.file_type().is_some_and(|kind| kind.is_file()) {
                    return Ok(Some(entry.into_path()));
                }
            }
        })
        .map_err(scan_error)
    }
}

fn recognized_archive(path: &str, data: &[u8]) -> bool {
    let ext =
        Path::new(path).extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    decompress::looks_like_zip(data)
        || decompress::ZIP_BASED_FORMATS.contains(&ext.as_str())
        || matches!(
            ext.as_str(),
            "tar" | "gz" | "gzip" | "tgz" | "bz2" | "bzip2" | "xz" | "zlib" | "asar" | "hwp"
        )
}

fn read_bounded(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?.take(max_bytes.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > max_bytes {
        bail!("input exceeds max_bytes budget");
    }
    Ok(data)
}

enum InputBytes {
    Python(PyBackedBytes),
    Owned(Vec<u8>),
}

impl AsRef<[u8]> for InputBytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Python(bytes) => bytes.as_ref(),
            Self::Owned(bytes) => bytes,
        }
    }
}

fn staging_tempdir(temp_dir: Option<&Path>) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("kingfisher-extract-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Apply owner-only mode during creation, before any plaintext is staged.
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    Ok(match temp_dir {
        Some(path) => builder.tempdir_in(path)?,
        None => builder.tempdir()?,
    })
}

#[allow(clippy::too_many_arguments)]
fn expand(
    path: String,
    data: InputBytes,
    depth: usize,
    max_bytes: u64,
    max_entries: usize,
    control: &ScanControl,
    temp_dir: Option<&Path>,
) -> Result<Vec<(String, InputBytes)>> {
    let mut pending = vec![(path, data, depth)];
    let mut output = Vec::new();
    let mut total_bytes = 0u64;
    let mut total_entries = 0usize;
    while let Some((path, data, depth)) = pending.pop() {
        control.check()?;
        if data.as_ref().len() as u64 > max_bytes {
            bail!("input exceeds archive max_bytes budget");
        }
        if depth == 0 || !recognized_archive(&path, data.as_ref()) {
            output.push((path, data));
            continue;
        }
        let remaining_bytes = max_bytes.saturating_sub(total_bytes);
        let remaining_entries = max_entries.saturating_sub(total_entries);
        // Small ZIPs can be decoded directly from pinned Python bytes. No
        // plaintext archive or members are staged on disk for this route.
        if decompress::looks_like_zip(data.as_ref())
            && data.as_ref().len() <= decompress::MAX_INMEM_ZIP_ARCHIVE_BYTES
        {
            let (entries, inspected) = decompress::extract_zip_archive_in_memory_with_budget(
                data.as_ref(),
                &path,
                remaining_bytes,
                remaining_entries,
                control,
            )?;
            total_bytes += entries.iter().map(|(_, bytes)| bytes.len() as u64).sum::<u64>();
            total_entries += inspected;
            for (path, bytes) in entries.into_iter().rev() {
                pending.push((path, InputBytes::Owned(bytes), depth - 1));
            }
            continue;
        }
        let staging = staging_tempdir(temp_dir)?;
        // Logical paths may contain Windows reserved names, URL characters or '!'.
        // Stage a fixed safe basename while preserving the codec suffix.
        let filename =
            Path::new(&path).file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        let extension =
            Path::new(&path).extension().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
        let suffix = ["tar.gz", "tar.gzip", "tar.bz2", "tar.bzip2", "tar.xz"]
            .into_iter()
            .find(|suffix| filename.ends_with(&format!(".{suffix}")))
            .unwrap_or(&extension);
        let basename = if !suffix.is_empty()
            && suffix.len() <= 16
            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        {
            format!("archive.{suffix}")
        } else {
            "archive".to_owned()
        };
        let staged = staging.path().join(basename);
        std::fs::write(&staged, data.as_ref())?;
        let extracted = staging_tempdir(temp_dir)?;
        let expansion = decompress::decompress_file_with_budget(
            &staged,
            extracted.path(),
            remaining_bytes,
            remaining_entries,
            control,
        )?;
        control.check()?;
        let mut entries = match expansion.content {
            CompressedContent::Archive(entries) => entries,
            CompressedContent::ArchiveFiles(entries) => {
                if entries.len() > max_entries.saturating_sub(total_entries) {
                    bail!("archive exceeds max_entries budget");
                }
                let mut buffers = Vec::new();
                let mut layer_bytes = 0u64;
                for (name, file) in entries {
                    control.check()?;
                    let data =
                        read_bounded(&file, max_bytes.saturating_sub(total_bytes + layer_bytes))?;
                    layer_bytes += data.len() as u64;
                    buffers.push((name, data));
                }
                buffers
            }
            CompressedContent::Raw(data) => vec![("content".to_owned(), data)],
            CompressedContent::RawFile(file) => {
                let data = read_bounded(&file, max_bytes.saturating_sub(total_bytes))?;
                vec![("content".to_owned(), data)]
            }
        };
        // Every layer consumes the same per-root budget, including nested containers.
        let retained = entries.iter().map(|(_, data)| data.len() as u64).sum::<u64>();
        if retained > max_bytes.saturating_sub(total_bytes) {
            bail!("archive exceeds max_bytes budget");
        }
        total_bytes += retained;
        total_entries += expansion.inspected_entries;
        if total_entries > max_entries {
            bail!("archive exceeds max_entries budget");
        }
        for (name, data) in entries.drain(..).rev() {
            // Remove physical temp roots before splitting the archive delimiter:
            // a user's temp directory may itself contain '!'.
            let relative = name
                .strip_prefix(&staging.path().display().to_string())
                .or_else(|| name.strip_prefix(&extracted.path().display().to_string()))
                .unwrap_or(&name);
            let logical = if let Some((_, suffix)) = relative.split_once('!') {
                format!("{path}!{suffix}")
            } else {
                format!("{path}!content")
            };
            pending.push((logical, InputBytes::Owned(data), depth - 1));
        }
    }
    control.check()?;
    Ok(output)
}

type ArchiveItems = Vec<(String, Vec<u8>)>;
type PyArchiveItem = (String, Py<PyBytes>);

// Mirror the independent keyword controls in the Python API.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (path, data, *, file=None, depth=1, max_bytes=268435456, max_entries=10000, timeout=None, cancellation=None, temp_dir=None))]
pub(crate) fn expand_archive(
    py: Python<'_>,
    path: String,
    data: Option<PyBackedBytes>,
    file: Option<PathBuf>,
    depth: usize,
    max_bytes: u64,
    max_entries: usize,
    timeout: Option<f64>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    temp_dir: Option<PathBuf>,
) -> PyResult<Vec<PyArchiveItem>> {
    if depth > 32 || max_bytes == 0 || max_entries == 0 {
        return Err(PyValueError::new_err(
            "depth must be 0..32 and archive budgets must be positive",
        ));
    }
    let control = scan_control(timeout, cancellation.map(|v| v.token.clone()))?;
    let entries = py
        .detach(move || {
            control.check()?;
            let data = match (data, file) {
                (Some(data), None) => InputBytes::Python(data),
                (None, Some(file)) => InputBytes::Owned(read_bounded(&file, max_bytes)?),
                _ => bail!("provide either data or file"),
            };
            expand(path, data, depth, max_bytes, max_entries, &control, temp_dir.as_deref())
        })
        .map_err(scan_error)?;
    Ok(entries
        .into_iter()
        .map(|(path, data)| {
            let bytes = match data {
                InputBytes::Python(data) => data.into_pyobject(py).unwrap().unbind(),
                InputBytes::Owned(data) => PyBytes::new(py, &data).unbind(),
            };
            (path, bytes)
        })
        .collect())
}

/// Shared CLI extraction; failures produce a non-secret diagnostic on raw fallback.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (path, data, *, file=None, sqlite=true, pyc=true, strict=false, max_bytes=268435456, timeout=None, cancellation=None, temp_dir=None))]
pub(crate) fn expand_content(
    py: Python<'_>,
    path: String,
    data: Option<PyBackedBytes>,
    file: Option<PathBuf>,
    sqlite: bool,
    pyc: bool,
    strict: bool,
    max_bytes: u64,
    timeout: Option<f64>,
    cancellation: Option<PyRef<'_, PyCancellationToken>>,
    temp_dir: Option<PathBuf>,
) -> PyResult<(Option<Vec<PyArchiveItem>>, Option<String>)> {
    if max_bytes == 0 {
        return Err(PyValueError::new_err("max_bytes must be positive"));
    }
    let control = scan_control(timeout, cancellation.map(|v| v.token.clone()))?;
    let (output, diagnostic) = py
        .detach(move || -> Result<(Option<ArchiveItems>, Option<String>)> {
            control.check()?;
            let is_pyc =
                pyc && Path::new(&path).extension().is_some_and(|e| e.eq_ignore_ascii_case("pyc"));
            let is_sqlite = match (&data, &file) {
                (Some(data), None) => {
                    if data.len() as u64 > max_bytes
                        && (is_pyc || sqlite && data.starts_with(b"SQLite format 3\0"))
                    {
                        bail!("content input exceeds max_bytes budget");
                    }
                    sqlite && data.starts_with(b"SQLite format 3\0")
                }
                (None, Some(file)) => {
                    let mut header = [0u8; 16];
                    let count = File::open(file)?.read(&mut header)?;
                    sqlite && header[..count].starts_with(b"SQLite format 3\0")
                }
                _ => bail!("provide either data or file"),
            };
            if !is_sqlite && !is_pyc {
                return Ok((None, None));
            }
            let output_cap = max_bytes.min(usize::MAX as u64) as usize;
            let extracted: Result<ArchiveItems> = if is_sqlite {
                let staging = staging_tempdir(temp_dir.as_deref())?;
                let staged = staging.path().join("content");
                // SQLite consumes a separate, closed snapshot; journals and original
                // files are never modified. Avoid holding a duplicate file buffer.
                match (&data, &file) {
                    (Some(bytes), None) => std::fs::write(&staged, bytes.as_ref())?,
                    (None, Some(file)) => {
                        let mut input = File::open(file)?.take(max_bytes.saturating_add(1));
                        let mut output = File::create(&staged)?;
                        let mut copied = 0u64;
                        let mut buffer = [0u8; 32 * 1024];
                        loop {
                            control.check()?;
                            let count = input.read(&mut buffer)?;
                            if count == 0 {
                                break;
                            }
                            copied += count as u64;
                            if copied > max_bytes {
                                bail!("content input exceeds max_bytes budget");
                            }
                            std::io::Write::write_all(&mut output, &buffer[..count])?;
                        }
                    }
                    _ => unreachable!(),
                }
                kingfisher_scanner::extraction::sqlite::extract_sqlite_contents_with_budget(
                    &staged, output_cap, &control,
                )
                .map(|tables| {
                    tables
                        .into_iter()
                        .map(|(name, bytes)| (format!("{path}!{name}"), bytes))
                        .collect()
                })
            } else {
                // Marshal parsing accepts a borrowed, pinned byte view and needs no
                // disk staging. File-backed bytecode is read once under the input cap.
                let owned;
                let bytes = match (&data, &file) {
                    (Some(bytes), None) => bytes.as_ref(),
                    (None, Some(file)) => {
                        owned = read_bounded(file, max_bytes)?;
                        &owned
                    }
                    _ => unreachable!(),
                };
                kingfisher_scanner::extraction::pyc::extract_pyc_strings_from_bytes_with_budget(
                    bytes, output_cap, &control,
                )
                .map(|bytes| {
                    if bytes.is_empty() {
                        Vec::new()
                    } else {
                        vec![(format!("{path}!strings.py"), bytes)]
                    }
                })
            };
            control.check()?;
            match extracted {
                Ok(output) => Ok(((!output.is_empty()).then_some(output), None)),
                Err(err) if strict || err.downcast_ref::<ExtractionLimitExceeded>().is_some() => {
                    Err(err)
                }
                // Do not return parser messages: malformed schemas/bytecode may
                // contain secrets. This stable category is safe to log or serialize.
                Err(_) => Ok((
                    None,
                    Some(if is_sqlite { "malformed_sqlite" } else { "malformed_pyc" }.to_owned()),
                )),
            }
        })
        .map_err(scan_error)?;
    Ok((
        output.map(|items| {
            items
                .into_iter()
                .map(|(path, bytes)| (path, PyBytes::new(py, &bytes).unbind()))
                .collect()
        }),
        diagnostic,
    ))
}

#[cfg(all(test, unix))]
mod staging_tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn staging_directories_exclude_group_and_other_permissions() -> Result<()> {
        let parent = tempfile::tempdir()?;
        for location in [Some(parent.path()), None] {
            let directory = staging_tempdir(location)?;
            let mode = std::fs::metadata(directory.path())?.permissions().mode();
            assert_eq!(mode & 0o077, 0, "plaintext staging must exclude group/other access");
        }
        Ok(())
    }
}
