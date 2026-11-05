use std::path::{Path, PathBuf};

use kingfisher_scanner::{
    archive::decompress::{self, CompressedContent},
    extraction::ExtractionLimitExceeded,
};
use napi::{
    Env, Result,
    bindgen_prelude::{Buffer, PromiseRaw},
};
use napi_derive::napi;

use crate::{
    control::{NativeCancellationToken, blocking, control, failure, interrupted, invalid},
    file_io,
};

#[napi(object)]
pub struct NativeExpandedInput {
    pub path: String,
    pub data: Buffer,
}

#[napi(object)]
pub struct NativeArchiveOptions {
    pub expand: bool,
    pub max_input_bytes: u32,
    pub max_bytes: u32,
    pub max_entries: u32,
    pub temp_dir: Option<String>,
}

#[napi(object)]
pub struct NativeArchiveExpansion {
    // None preserves an unexpanded source without copying or reading its payload.
    pub items: Option<Vec<NativeExpandedInput>>,
    pub inspected_entries: u32,
    pub expanded: bool,
}

#[napi(object)]
pub struct NativeContentOptions {
    pub sqlite: bool,
    pub pyc: bool,
    pub pdf: bool,
    pub strict: bool,
    pub max_bytes: u32,
    pub temp_dir: Option<String>,
}

#[napi(object)]
pub struct NativeContentExpansion {
    pub items: Option<Vec<NativeExpandedInput>>,
    pub diagnostic: Option<String>,
}

fn extraction_error(error: anyhow::Error) -> napi::Error {
    if let Some(reason) = error.downcast_ref::<kingfisher_scanner::ScanAborted>() {
        interrupted(*reason)
    } else if error.is::<ExtractionLimitExceeded>()
        || error.is::<kingfisher_scanner::extraction::pdf::PdfPageLimitExceeded>()
    {
        failure("KF_LIMIT", "content extraction exceeds its output or work budget")
    } else {
        failure("KF_EXTRACTION", "input extraction failed or exceeded its budget")
    }
}

fn staging(parent: Option<&Path>) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("kingfisher-node-extract-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    match parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
    .map_err(|_| failure("KF_IO", "protected extraction staging could not be created"))
}

fn archive_kind(path: &str, data: &[u8]) -> bool {
    let extension = Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    decompress::looks_like_zip(data)
        || decompress::ZIP_BASED_FORMATS.contains(&extension.as_str())
        || matches!(
            extension.as_str(),
            "tar" | "gz" | "gzip" | "tgz" | "bz2" | "bzip2" | "xz" | "zlib" | "asar" | "hwp"
        )
}

fn archive_basename(path: &str) -> String {
    let path = Path::new(path);
    let filename = path.file_name().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
    let extension = path.extension().unwrap_or_default().to_string_lossy().to_ascii_lowercase();
    let suffix = ["tar.gz", "tar.gzip", "tar.bz2", "tar.bzip2", "tar.xz"]
        .into_iter()
        .find(|suffix| filename.ends_with(&format!(".{suffix}")))
        .unwrap_or(&extension);
    if !suffix.is_empty()
        && suffix.len() <= 16
        && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        format!("archive.{suffix}")
    } else {
        "archive".into()
    }
}

#[napi(catch_unwind)]
pub fn expand_archive_once<'env>(
    env: &'env Env,
    path: String,
    data: Option<Buffer>,
    file: Option<String>,
    options: NativeArchiveOptions,
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<PromiseRaw<'env, NativeArchiveExpansion>> {
    let control = control(timeout_ms, token)?;
    if data.is_some() == file.is_some() {
        return Err(invalid("provide exactly one of data or file"));
    }
    // Disabled expansion and ordinary byte inputs must not inherit an archive
    // budget or pay for another full payload snapshot.
    if !options.expand || data.as_ref().is_some_and(|data| !archive_kind(&path, data)) {
        return env.spawn_future(async move {
            control.check().map_err(interrupted)?;
            Ok(NativeArchiveExpansion { items: None, inspected_entries: 0, expanded: false })
        });
    }
    if data.as_ref().is_some_and(|data| data.len() > options.max_input_bytes as usize) {
        return Err(failure("KF_LIMIT", "input exceeds archive maxBytes"));
    }
    let data = data.map(|data| data.to_vec());
    env.spawn_future(blocking(control, move |control| {
        let data = match (data, file) {
            (Some(data), _) => data,
            (_, Some(file)) => {
                let mut input = file_io::open_regular(Path::new(&file), control)?;
                let header = file_io::header(&mut input, control)?;
                if !archive_kind(&path, &header) {
                    return Ok(NativeArchiveExpansion {
                        items: None,
                        inspected_entries: 0,
                        expanded: false,
                    });
                }
                file_io::read_bounded(
                    input,
                    Some(options.max_input_bytes.into()),
                    "input exceeds archive maxBytes",
                    control,
                )?
            }
            _ => return Err(invalid("provide exactly one of data or file")),
        };
        let (items, inspected) = if decompress::looks_like_zip(&data)
            && data.len() <= decompress::MAX_INMEM_ZIP_ARCHIVE_BYTES
        {
            decompress::extract_zip_archive_in_memory_with_budget(
                &data,
                &path,
                options.max_bytes.into(),
                options.max_entries as usize,
                control,
            )
            .map_err(extraction_error)?
        } else {
            let parent = options.temp_dir.map(PathBuf::from);
            let input_stage = staging(parent.as_deref())?;
            let output_stage = staging(parent.as_deref())?;
            let input_file = input_stage.path().join(archive_basename(&path));
            std::fs::write(&input_file, &data)
                .map_err(|_| failure("KF_IO", "archive staging failed"))?;
            let expansion = decompress::decompress_file_with_budget(
                &input_file,
                output_stage.path(),
                options.max_bytes.into(),
                options.max_entries as usize,
                control,
            )
            .map_err(extraction_error)?;
            let mut retained = 0u64;
            let mut items = match expansion.content {
                CompressedContent::Archive(items) => items,
                CompressedContent::Raw(data) => vec![("content".into(), data)],
                CompressedContent::RawFile(file) => vec![(
                    "content".into(),
                    file_io::read_bounded(
                        file_io::open_regular(&file, control)?,
                        Some(options.max_bytes.into()),
                        "archive exceeds its remaining byte budget",
                        control,
                    )?,
                )],
                CompressedContent::ArchiveFiles(files) => {
                    let mut items = Vec::new();
                    for (name, file) in files {
                        let data = file_io::read_bounded(
                            file_io::open_regular(&file, control)?,
                            Some(u64::from(options.max_bytes).saturating_sub(retained)),
                            "archive exceeds its remaining byte budget",
                            control,
                        )?;
                        retained += data.len() as u64;
                        items.push((name, data));
                    }
                    items
                }
            };
            let input_prefix = input_stage.path().display().to_string();
            let output_prefix = output_stage.path().display().to_string();
            for (name, _) in &mut items {
                let relative = name
                    .strip_prefix(&input_prefix)
                    .or_else(|| name.strip_prefix(&output_prefix))
                    .unwrap_or(name);
                *name = relative.split_once('!').map_or_else(
                    || format!("{path}!content"),
                    |(_, suffix)| format!("{path}!{suffix}"),
                );
            }
            (items, expansion.inspected_entries)
        };
        if items.iter().map(|(_, data)| data.len() as u64).sum::<u64>() > options.max_bytes.into() {
            return Err(failure("KF_LIMIT", "archive exceeds its remaining byte budget"));
        }
        control.check().map_err(interrupted)?;
        Ok(NativeArchiveExpansion {
            items: Some(
                items
                    .into_iter()
                    .map(|(path, data)| NativeExpandedInput { path, data: data.into() })
                    .collect(),
            ),
            inspected_entries: inspected
                .try_into()
                .map_err(|_| failure("KF_LIMIT", "archive entry count exceeds the SDK range"))?,
            expanded: true,
        })
    }))
}

#[napi(catch_unwind)]
pub fn expand_content<'env>(
    env: &'env Env,
    path: String,
    data: Option<Buffer>,
    file: Option<String>,
    options: NativeContentOptions,
    timeout_ms: Option<f64>,
    token: Option<&NativeCancellationToken>,
) -> Result<PromiseRaw<'env, NativeContentExpansion>> {
    let control = control(timeout_ms, token)?;
    if data.is_some() == file.is_some() {
        return Err(invalid("provide exactly one of data or file"));
    }
    let data = data.map(|data| data.to_vec());
    env.spawn_future(blocking(control, move |control| {
        let owned_header;
        let mut input_file = None;
        let header = match (&data, &file) {
            (Some(data), _) => data.as_slice(),
            (_, Some(file)) => {
                let mut input = file_io::open_regular(Path::new(file), control)?;
                owned_header = file_io::header(&mut input, control)?;
                input_file = Some(input);
                &owned_header
            }
            _ => return Err(invalid("provide exactly one of data or file")),
        };
        let extension =
            Path::new(&path).extension().and_then(|extension| extension.to_str()).unwrap_or("");
        let sqlite = options.sqlite && header.starts_with(b"SQLite format 3\0");
        let pyc = options.pyc && extension.eq_ignore_ascii_case("pyc");
        let pdf = options.pdf
            && (extension.eq_ignore_ascii_case("pdf")
                || kingfisher_scanner::extraction::pdf::has_pdf_magic(header));
        if !sqlite && !pyc && !pdf {
            return Ok(NativeContentExpansion { items: None, diagnostic: None });
        }
        let data = match (data, input_file) {
            (Some(data), _) if data.len() <= options.max_bytes as usize => data,
            (Some(_), _) => return Err(failure("KF_LIMIT", "content input exceeds maxBytes")),
            (_, Some(input)) => file_io::read_bounded(
                input,
                Some(options.max_bytes.into()),
                "content input exceeds maxBytes",
                control,
            )?,
            _ => return Err(invalid("provide exactly one of data or file")),
        };
        let output: anyhow::Result<Vec<(String, Vec<u8>)>> = if sqlite {
            let parent = options.temp_dir.map(PathBuf::from);
            let stage = staging(parent.as_deref())?;
            let file = stage.path().join("content");
            std::fs::write(&file, &data)
                .map_err(|_| failure("KF_IO", "SQLite snapshot staging failed"))?;
            kingfisher_scanner::extraction::sqlite::extract_sqlite_contents_with_budget(
                &file,
                options.max_bytes as usize,
                control,
            )
            .map(|items| {
                items.into_iter().map(|(name, data)| (format!("{path}!{name}"), data)).collect()
            })
        } else if pdf {
            use kingfisher_scanner::extraction::pdf::{
                extract_pdf_text_from_bytes_with_budget,
                extract_pdf_text_from_bytes_with_budget_strict,
            };
            let pages = if options.strict {
                extract_pdf_text_from_bytes_with_budget_strict(
                    &data,
                    options.max_bytes as usize,
                    control,
                )
            } else {
                extract_pdf_text_from_bytes_with_budget(&data, options.max_bytes as usize, control)
            };
            pages.map(|items| {
                items.into_iter().map(|(name, data)| (format!("{path}!{name}"), data)).collect()
            })
        } else {
            kingfisher_scanner::extraction::pyc::extract_pyc_strings_from_bytes_with_budget(
                &data,
                options.max_bytes as usize,
                control,
            )
            .map(|data| {
                if data.is_empty() {
                    Vec::new()
                } else {
                    vec![(format!("{path}!strings.py"), data)]
                }
            })
        };
        control.check().map_err(interrupted)?;
        match output {
            Ok(items) => Ok(NativeContentExpansion {
                items: (!items.is_empty()).then(|| {
                    items
                        .into_iter()
                        .map(|(path, data)| NativeExpandedInput { path, data: data.into() })
                        .collect()
                }),
                diagnostic: None,
            }),
            Err(error)
                if options.strict
                    || error.is::<ExtractionLimitExceeded>()
                    || error.is::<kingfisher_scanner::extraction::pdf::PdfPageLimitExceeded>() =>
            {
                Err(extraction_error(error))
            }
            Err(_) => Ok(NativeContentExpansion {
                items: None,
                diagnostic: Some(
                    if sqlite {
                        "malformed_sqlite"
                    } else if pdf {
                        "malformed_pdf"
                    } else {
                        "malformed_pyc"
                    }
                    .into(),
                ),
            }),
        }
    }))
}
