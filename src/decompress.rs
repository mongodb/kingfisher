use std::{
    fs,
    io::{BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};

use anyhow::Result;
use asar::AsarReader;
use bzip2_rs::DecoderReader;
use cfb::CompoundFile;
use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
use lzma_rs::xz_decompress;
use memmap2::Mmap;
use tar::Archive;
use tempfile::{TempDir, tempdir};
use uuid::Uuid;
use zip::ZipArchive;

/// Formats that are basically a ZIP container.
pub const ZIP_BASED_FORMATS: &[&str] = &[
    "zip", "zipx", "jar", "war", "ear", "aar", "apk", "aab", "ipa", "jmod", "jhm", "jnlp", "nupkg",
    "vsix", "xap", "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "odf", "epub", "gadget",
    "kmz", "widget", "xpi", "sketch", "pages", "key", "numbers", "hwpx",
];

fn is_tar_wrapped_compression(path: &Path) -> bool {
    let filename = match path.file_name().and_then(|s| s.to_str()) {
        Some(name) => name.to_ascii_lowercase(),
        None => return false,
    };

    filename.ends_with(".tgz")
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tar.gzip")
        || filename.ends_with(".tar.bz2")
        || filename.ends_with(".tar.bzip2")
        || filename.ends_with(".tar.xz")
}

#[derive(Debug)]
pub enum CompressedContent {
    /// Decompressed content fully in memory.
    Raw(Vec<u8>),
    /// Decompressed content streamed to a file on disk.
    RawFile(PathBuf),
    /// Archive entries fully in memory (original approach).
    Archive(Vec<(String, Vec<u8>)>),
    /// Archive entries each extracted to a file on disk (streaming approach).
    ArchiveFiles(Vec<(String, PathBuf)>),
}

pub fn is_safe_extract_path(path: &Path) -> bool {
    if path.is_absolute() {
        return false;
    }

    for comp in path.components() {
        match comp {
            // Never allow parent-directory escapes
            Component::ParentDir => return false,

            // Archive entry names must always be relative to the extraction root.
            Component::Prefix(_) | Component::RootDir => return false,

            _ => {}
        }
    }
    true
}

fn has_parent_or_embedded_prefix(path: &Path) -> bool {
    for (idx, comp) in path.components().enumerate() {
        match comp {
            Component::ParentDir => return true,
            Component::Prefix(_) if idx > 0 => return true,
            _ => {}
        }
    }
    false
}

fn is_zip_format(ext: &str) -> bool {
    ZIP_BASED_FORMATS.iter().any(|z| z == &ext)
}

/* ───────────────────────────────────────────────────────────────
helpers for streaming archives
───────────────────────────────────────────────────────────── */
fn handle_tar_archive_streaming(
    file: &mut fs::File,
    archive_path: &Path,
    base_dir: &Path,
) -> Result<CompressedContent> {
    let mut archive = Archive::new(file);
    let mut entries_on_disk = Vec::new();
    let mut truncated = false;

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("failed to open tar archive {}: {}", archive_path.display(), e);
            return Ok(CompressedContent::RawFile(archive_path.to_owned()));
        }
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                tracing::debug!("tar archive {} ended early: {}", archive_path.display(), e);
                truncated = true;
                break;
            }
        };
        if entry.header().entry_type().is_file() {
            let path_in_tar = match entry.path() {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(e) => {
                    tracing::debug!(
                        "failed to read tar entry path in {}: {}",
                        archive_path.display(),
                        e
                    );
                    truncated = true;
                    break;
                }
            };
            if !is_safe_extract_path(Path::new(&path_in_tar)) {
                tracing::debug!("unsafe tar path: {path_in_tar}");
                continue;
            }
            let logical_path = format!("{}!{}", archive_path.display(), path_in_tar);

            let out_path = base_dir.join(&path_in_tar);
            if let Some(parent) = out_path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                tracing::debug!("failed to create directory {}: {}", parent.display(), e);
                continue;
            }
            match fs::File::create(&out_path) {
                Ok(mut out_file) => {
                    let expected_size = entry.size();
                    let copied = match std::io::copy(&mut entry, &mut out_file) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::debug!("failed to extract {}: {}", out_path.display(), e);
                            // Drop the handle before removing so the partial
                            // file is deletable on Windows, then discard it so
                            // it doesn't accumulate in the temp extraction dir.
                            drop(out_file);
                            let _ = fs::remove_file(&out_path);
                            truncated = true;
                            break;
                        }
                    };
                    if copied != expected_size {
                        tracing::debug!(
                            "tar entry {} in {} was truncated after {copied} of {expected_size} bytes",
                            path_in_tar,
                            archive_path.display()
                        );
                        drop(out_file);
                        let _ = fs::remove_file(&out_path);
                        truncated = true;
                        break;
                    }
                    entries_on_disk.push((logical_path, out_path));
                }
                Err(e) => {
                    tracing::debug!("failed to create file {}: {}", out_path.display(), e);
                    continue;
                }
            }
        }
    }

    if truncated && entries_on_disk.is_empty() {
        tracing::debug!(
            "tar archive {} was truncated before any entry completed; falling back to raw scan",
            archive_path.display()
        );
        return Ok(CompressedContent::RawFile(archive_path.to_owned()));
    }

    Ok(CompressedContent::ArchiveFiles(entries_on_disk))
}

/// Extract every file entry in a ZIP-based archive directly from a byte
/// slice, without touching the filesystem. Intended for the git-blob
/// scan path where blobs already sit in memory and writing them out to a
/// temp file just to read them back imposes substantial overhead in
/// monorepos with many committed `.jar`/`.zip`/`.apk` artifacts.
///
/// `archive_label` is used to construct logical entry paths of the form
/// `<archive_label>!<entry_name>`, matching the convention used by the
/// streaming-to-disk path.
///
/// The same per-entry decompressed-size cap as the streaming-to-disk
/// extractor is enforced so that ZIP bombs cannot allocate unbounded
/// memory.
/// Maximum compressed archive size that the in-memory ZIP extractor will
/// accept. Larger archives fall back to the disk-streaming path so that we
/// never hold both the archive bytes AND every decompressed entry in RAM
/// simultaneously. The threshold is intentionally generous — most committed
/// `.jar`/`.zip`/`.apk` artifacts in real repos are well under 64 MB.
pub const MAX_INMEM_ZIP_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// Aggregate cap on total decompressed bytes the in-memory ZIP extractor
/// will accumulate per archive. Bounds the worst-case footprint of one
/// rayon worker processing one archive: with `num_jobs` workers running
/// in parallel, peak resident memory is bounded by `num_jobs * this`.
/// Independent of the per-entry cap, so a single bomb-style entry can't
/// drain it all but neither can N medium-sized entries.
pub const MAX_INMEM_ZIP_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

pub fn extract_zip_archive_in_memory(
    data: &[u8],
    archive_label: &str,
) -> Result<Vec<(String, Vec<u8>)>> {
    if data.len() > MAX_INMEM_ZIP_ARCHIVE_BYTES {
        anyhow::bail!(
            "zip archive {archive_label} is {} bytes, exceeding {} byte in-memory cap",
            data.len(),
            MAX_INMEM_ZIP_ARCHIVE_BYTES
        );
    }

    // Per-entry cap on decompressed bytes: bounds memory cost of zip bombs.
    // Mirrors the disk-streaming variant's cap.
    // nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
    const MAX_ZIP_ENTRY_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

    let cursor = std::io::Cursor::new(data);
    let mut zip = ZipArchive::new(cursor)?;
    let mut entries = Vec::with_capacity(zip.len());
    let mut total_decompressed: u64 = 0;

    for i in 0..zip.len() {
        if total_decompressed >= MAX_INMEM_ZIP_DECOMPRESSED_BYTES {
            tracing::debug!(
                "in-memory zip {archive_label} exceeded {MAX_INMEM_ZIP_DECOMPRESSED_BYTES} byte aggregate cap at entry {i}/{}; truncating",
                zip.len()
            );
            break;
        }

        let mut zipped_file = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("zip entry {i} read failed: {e}");
                continue;
            }
        };
        if !zipped_file.is_file() {
            continue;
        }
        let name_in_zip = zipped_file.name().to_string();
        // Defense in depth: refuse traversal-style names. The in-memory
        // path never writes to disk, but downstream code may construct
        // file URLs from these strings.
        if !is_safe_extract_path(Path::new(&name_in_zip)) {
            tracing::debug!("unsafe zip entry name in {archive_label}: {name_in_zip}");
            continue;
        }

        // The remaining-budget cap on this read serves two purposes:
        // (1) honor the aggregate budget exactly even if one entry would
        //     individually push us over it, and (2) keep the existing
        //     per-entry zip-bomb cap of 512 MB as a hard upper bound.
        let remaining = MAX_INMEM_ZIP_DECOMPRESSED_BYTES.saturating_sub(total_decompressed);
        let entry_cap = remaining.min(MAX_ZIP_ENTRY_DECOMPRESSED_BYTES);

        let mut buf = Vec::new();
        let mut limited = (&mut zipped_file).take(entry_cap);
        if let Err(e) = limited.read_to_end(&mut buf) {
            tracing::debug!(
                "failed to decompress zip entry {name_in_zip} from {archive_label}: {e}"
            );
            continue;
        }
        if buf.len() as u64 == entry_cap && entry_cap == MAX_ZIP_ENTRY_DECOMPRESSED_BYTES {
            tracing::debug!(
                "zip entry {name_in_zip} in {archive_label} exceeded {MAX_ZIP_ENTRY_DECOMPRESSED_BYTES} byte cap; truncating"
            );
        }
        total_decompressed += buf.len() as u64;
        entries.push((format!("{archive_label}!{name_in_zip}"), buf));
    }
    Ok(entries)
}

/// Return true if `data` begins with a standard ZIP signature. Used both to
/// short-circuit extraction of blobs whose extension matches a ZIP-based format
/// but whose contents are not a real ZIP, and to detect ZIP containers that
/// carry no recognized archive extension (e.g. a Terraform `tf.plan`).
pub fn looks_like_zip(data: &[u8]) -> bool {
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
}

fn handle_zip_archive_streaming(
    file: &mut fs::File,
    archive_path: &Path,
    base_dir: &Path,
) -> Result<CompressedContent> {
    // Per-entry cap on decompressed bytes: bounds CPU/disk cost of zip bombs
    // by refusing to read more than this much from any single entry.
    // nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
    const MAX_ZIP_ENTRY_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

    let mut zip = ZipArchive::new(file)?;
    let mut entries_on_disk = Vec::new();
    let mut total_decompressed: u64 = 0;

    for i in 0..zip.len() {
        if total_decompressed >= MAX_INMEM_ZIP_DECOMPRESSED_BYTES {
            tracing::debug!(
                "zip archive {} exceeded {} byte aggregate cap at entry {i}/{}; truncating",
                archive_path.display(),
                MAX_INMEM_ZIP_DECOMPRESSED_BYTES,
                zip.len()
            );
            break;
        }

        let mut zipped_file = zip.by_index(i)?;
        if zipped_file.is_file() {
            let name_in_zip = zipped_file.name().to_string();
            if !is_safe_extract_path(Path::new(&name_in_zip)) {
                tracing::debug!("unsafe zip path: {name_in_zip}");
                continue;
            }
            let logical_path = format!("{}!{}", archive_path.display(), name_in_zip);

            let out_path = base_dir.join(&name_in_zip);
            if let Some(parent) = out_path.parent()
                && let Err(e) = fs::create_dir_all(parent)
            {
                tracing::debug!("failed to create directory {}: {}", parent.display(), e);
                continue;
            }
            match fs::File::create(&out_path) {
                Ok(mut out_file) => {
                    let remaining =
                        MAX_INMEM_ZIP_DECOMPRESSED_BYTES.saturating_sub(total_decompressed);
                    let entry_cap = remaining.min(MAX_ZIP_ENTRY_DECOMPRESSED_BYTES);
                    let mut limited = (&mut zipped_file).take(entry_cap);
                    let copied = match std::io::copy(&mut limited, &mut out_file) {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::debug!("failed to extract {}: {}", out_path.display(), e);
                            continue;
                        }
                    };
                    total_decompressed += copied;
                    if copied == entry_cap && entry_cap == MAX_ZIP_ENTRY_DECOMPRESSED_BYTES {
                        tracing::debug!(
                            "zip entry {} exceeded {} byte cap; truncating",
                            out_path.display(),
                            MAX_ZIP_ENTRY_DECOMPRESSED_BYTES
                        );
                    }
                    entries_on_disk.push((logical_path, out_path));
                    if total_decompressed >= MAX_INMEM_ZIP_DECOMPRESSED_BYTES {
                        tracing::debug!(
                            "zip archive {} reached {} byte aggregate cap; truncating remaining entries",
                            archive_path.display(),
                            MAX_INMEM_ZIP_DECOMPRESSED_BYTES
                        );
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!("failed to create file {}: {}", out_path.display(), e);
                    continue;
                }
            }
        }
    }
    Ok(CompressedContent::ArchiveFiles(entries_on_disk))
}

/// Extract in-memory ZIP `buffer` via the disk-streaming extractor.
///
/// Used for content-sniffed ZIPs that exceed `MAX_INMEM_ZIP_ARCHIVE_BYTES`, so
/// they take the streaming path (no total-input cap) rather than the in-memory
/// extractor. `label_path` is used only to label entries (`label_path!entry`),
/// keeping report paths consistent with the in-memory branch. Entries are
/// written under `base_dir`.
fn extract_zip_bytes_via_streaming(
    buffer: &[u8],
    label_path: &Path,
    base_dir: &Path,
) -> Result<CompressedContent> {
    let staged = base_dir.join(format!("{}.zip", Uuid::new_v4()));
    let mut out = safe_create_for_write(&staged)?;
    out.write_all(buffer)?;
    drop(out);

    let mut file = safe_open_for_read(&staged)?;
    handle_zip_archive_streaming(&mut file, label_path, base_dir)
}

/// Extract streams from an HWP (Hancom Word Processor) file.
///
/// HWP 5.x uses the Microsoft Compound File Binary (OLE2/CFBF) container.
/// Body streams (e.g. `BodyText/Section*`) are typically raw DEFLATE
/// without a zlib header, others may be zlib-framed, and metadata
/// streams are plaintext UTF-16/ASCII. We try DEFLATE then zlib, and
/// fall back to the raw bytes so the scanner always sees content.
fn handle_hwp_archive_in_memory(path: &Path, archive_path: &Path) -> Result<CompressedContent> {
    // Per-stream caps to defend against malformed or hostile HWP containers
    // (huge CFB streams or deflate bombs). Raw bytes are bounded by the size
    // of the stream on disk; decoded output is capped independently so a
    // small compressed payload can't fan out to gigabytes.
    // nosemgrep: this is the defensive cap we want — do not flag for
    // "magic number" or missing-limit rules, it *is* the limit.
    const MAX_HWP_RAW_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_HWP_DECODED_BYTES: u64 = 512 * 1024 * 1024;

    let file = safe_open_for_read(path)?;
    let mut cf = CompoundFile::open(file)?;
    let stream_paths: Vec<PathBuf> =
        cf.walk().filter(|e| e.is_stream()).map(|e| e.path().to_path_buf()).collect();

    let mut out = Vec::with_capacity(stream_paths.len());
    for sp in stream_paths {
        let mut raw = Vec::new();
        match cf.open_stream(&sp) {
            Ok(s) => {
                let mut limited = s.take(MAX_HWP_RAW_BYTES);
                if let Err(e) = limited.read_to_end(&mut raw) {
                    tracing::debug!("failed to read hwp stream {}: {}", sp.display(), e);
                    continue;
                }
            }
            Err(e) => {
                tracing::debug!("failed to open hwp stream {}: {}", sp.display(), e);
                continue;
            }
        }

        let try_decode = |mut decoder: Box<dyn Read>| -> Option<Vec<u8>> {
            let mut buf = Vec::new();
            match decoder.read_to_end(&mut buf) {
                Ok(_) if !buf.is_empty() => Some(buf),
                _ => None,
            }
        };

        let decoded = if raw.is_empty() {
            raw
        } else {
            let deflate =
                try_decode(Box::new(DeflateDecoder::new(&raw[..]).take(MAX_HWP_DECODED_BYTES)));
            if let Some(buf) = deflate {
                buf
            } else {
                let zlib =
                    try_decode(Box::new(ZlibDecoder::new(&raw[..]).take(MAX_HWP_DECODED_BYTES)));
                zlib.unwrap_or(raw)
            }
        };

        let logical = format!("{}!{}", archive_path.display(), sp.display());
        out.push((logical, decoded));
    }
    Ok(CompressedContent::Archive(out))
}

fn handle_asar_archive_in_memory(buffer: &[u8], archive_path: &Path) -> Result<CompressedContent> {
    // Per-entry cap: ASAR files have an index listing arbitrary sizes, and
    // a malformed or hostile archive could claim a single multi-GB entry.
    // We cap each entry independently even though the outer buffer is
    // already size-limited, to avoid ever copying a giant slice.
    // nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
    const MAX_ASAR_ENTRY_BYTES: usize = 512 * 1024 * 1024;

    match AsarReader::new(buffer, None) {
        Ok(reader) => {
            let mut contents = Vec::new();
            for (path_in_asar, file) in reader.files() {
                let inner_path = path_in_asar.to_string_lossy().replace('\\', "/");
                if !is_safe_extract_path(Path::new(&inner_path)) {
                    tracing::debug!("unsafe asar path: {inner_path}");
                    continue;
                }

                let logical_path = format!("{}!{}", archive_path.display(), inner_path);
                let data = file.data();
                let take = data.len().min(MAX_ASAR_ENTRY_BYTES);
                if take < data.len() {
                    tracing::debug!(
                        "asar entry {} exceeded {} byte cap; truncating",
                        inner_path,
                        MAX_ASAR_ENTRY_BYTES
                    );
                }
                contents.push((logical_path, data[..take].to_vec()));
            }
            Ok(CompressedContent::Archive(contents))
        }
        Err(e) => Err(e.into()),
    }
}

fn materialize_in_memory_archive_entries(
    files: &[(String, Vec<u8>)],
    base_dir: &Path,
) -> Result<()> {
    for (name, data) in files {
        let rel = name.split_once('!').map(|(_, sub)| sub).unwrap_or(name.as_str());
        let normalized_rel = rel.replace('\\', "/");
        let rel_path = Path::new(&normalized_rel);
        if !is_safe_extract_path(rel_path) {
            tracing::debug!("unsafe archive path: {normalized_rel}");
            continue;
        }

        let p = base_dir.join(rel_path);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(p, data)?;
    }
    Ok(())
}

/// Validate and open a file for reading, checking for path traversal attacks.
fn safe_open_for_read(path: &Path) -> Result<fs::File> {
    if has_parent_or_embedded_prefix(path) {
        anyhow::bail!("unsafe input path during decompression: {}", path.display());
    }
    Ok(fs::File::open(path)?)
}

/// Validate and create a file for writing, checking for path traversal attacks.
fn safe_create_for_write(path: &Path) -> Result<fs::File> {
    if has_parent_or_embedded_prefix(path) {
        anyhow::bail!("unsafe output path during decompression: {}", path.display());
    }
    Ok(fs::File::create(path)?)
}

/// Hard cap on the number of bytes a single-stream decompressor
/// (gzip/bzip2/xz/zlib) will write to disk for one input. Mirrors the per-entry
/// decompressed cap enforced by the ZIP extractors so a small "compression
/// bomb" cannot expand without limit and exhaust the scanner's temporary
/// filesystem. Output past the cap is dropped and a truncation warning logged.
// nosemgrep: this is the defensive cap — do not flag for missing-limit rules.
pub const MAX_SINGLE_STREAM_DECOMPRESSED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// `Write` adaptor that drops everything past `remaining` bytes.
///
/// Bounds single-stream decompressors so a high-ratio compression bomb can't
/// fill the disk. Writes past the cap are reported as fully consumed so the
/// underlying decoder runs to completion instead of erroring or looping; the
/// truncation is surfaced via [`CappedWriter::truncated`], matching the
/// truncate-and-warn behavior of the ZIP entry extractor.
struct CappedWriter<W: Write> {
    inner: W,
    remaining: u64,
    truncated: bool,
}

impl<W: Write> CappedWriter<W> {
    fn new(inner: W, cap: u64) -> Self {
        Self { inner, remaining: cap, truncated: false }
    }

    fn truncated(&self) -> bool {
        self.truncated
    }
}

impl<W: Write> Write for CappedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let allowed = (buf.len() as u64).min(self.remaining) as usize;
        if allowed > 0 {
            self.inner.write_all(&buf[..allowed])?;
            self.remaining -= allowed as u64;
        }
        if allowed < buf.len() {
            self.truncated = true;
        }
        // Report the whole buffer as consumed even when the tail was dropped so
        // `io::copy`/`xz_decompress` don't treat the cap as a write error.
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn stream_to_file_capped<R: Read>(
    mut decoder: R,
    out_path: &Path,
    cap: u64,
) -> Result<CompressedContent> {
    let out_file = safe_create_for_write(out_path)?;
    let mut capped = CappedWriter::new(out_file, cap);
    std::io::copy(&mut decoder, &mut capped)?;
    if capped.truncated() {
        tracing::debug!(
            "decompressed stream written to {} exceeded {cap} byte cap; truncating",
            out_path.display()
        );
    }
    Ok(CompressedContent::RawFile(out_path.to_owned()))
}

fn stream_xz_to_file_capped(path: &Path, out_path: &Path, cap: u64) -> Result<CompressedContent> {
    let input = safe_open_for_read(path)?;
    let mut reader = BufReader::new(input);
    let out_file = safe_create_for_write(out_path)?;
    let mut capped = CappedWriter::new(out_file, cap);
    xz_decompress(&mut reader, &mut capped)?;
    if capped.truncated() {
        tracing::debug!(
            "decompressed xz stream written to {} exceeded {cap} byte cap; truncating",
            out_path.display()
        );
    }
    Ok(CompressedContent::RawFile(out_path.to_owned()))
}

/* ───────────────────────────────────────────────────────────────
one *step* of decompression
───────────────────────────────────────────────────────────── */
fn decompress_once_with_single_stream_cap(
    path: &Path,
    base_dir: Option<&Path>,
    single_stream_cap: u64,
) -> Result<CompressedContent> {
    let extension = path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_ascii_lowercase());

    let mut file = safe_open_for_read(path)?;

    if let Some(ext) = extension.as_deref() {
        match ext {
            "asar" => {
                let mmap = unsafe { Mmap::map(&file)? };
                return handle_asar_archive_in_memory(&mmap, path);
            }
            "hwp" => {
                return handle_hwp_archive_in_memory(path, path);
            }
            "egg" => {
                // No open-source EGG (ALZip) extractor exists. Return the
                // raw bytes so plaintext content inside the container is
                // still scanned.
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                return Ok(CompressedContent::Raw(buffer));
            }
            "tar" => {
                if let Some(base) = base_dir {
                    return handle_tar_archive_streaming(&mut file, path, base);
                } else {
                    let temp = tempdir()?;
                    return handle_tar_archive_streaming(&mut file, path, temp.path());
                }
            }
            _ if is_zip_format(ext) => {
                if let Some(base) = base_dir {
                    return handle_zip_archive_streaming(&mut file, path, base);
                } else {
                    let temp = tempdir()?;
                    return handle_zip_archive_streaming(&mut file, path, temp.path());
                }
            }
            "gz" | "gzip" | "tgz" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = GzDecoder::new(BufReader::new(safe_open_for_read(path)?));
                return stream_to_file_capped(decoder, &out_path, single_stream_cap);
            }
            "bz2" | "bzip2" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = DecoderReader::new(BufReader::new(safe_open_for_read(path)?));
                return stream_to_file_capped(decoder, &out_path, single_stream_cap);
            }
            "xz" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                return stream_xz_to_file_capped(path, &out_path, single_stream_cap);
            }
            "zlib" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = ZlibDecoder::new(BufReader::new(safe_open_for_read(path)?));
                return stream_to_file_capped(decoder, &out_path, single_stream_cap);
            }
            _ => {}
        }
    }

    // Unknown extension: read the bytes, then content-sniff. A file whose name
    // carries no archive extension may still be a ZIP (e.g. a `tfplan`). The
    // already-read buffer feeds the bounded in-memory extractor directly.
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if looks_like_zip(&buffer) {
        let archive_label = path.display().to_string();
        if buffer.len() <= MAX_INMEM_ZIP_ARCHIVE_BYTES {
            match extract_zip_archive_in_memory(&buffer, &archive_label) {
                // Only treat it as an archive if it yielded entries; an empty or
                // unreadable result falls through to scanning the raw bytes.
                Ok(entries) if !entries.is_empty() => {
                    return Ok(CompressedContent::Archive(entries));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(
                        "content-sniffed zip extract failed for {archive_label}: {e:#}; scanning raw bytes"
                    );
                }
            }
        } else if let Some(base) = base_dir {
            // Larger than the in-memory cap: stage the bytes and use the
            // streaming extractor (no total-input cap) instead of dropping to a
            // raw scan of the compressed bytes. Only viable when the caller owns
            // a base dir the extracted files can live in; otherwise fall through
            // to scanning the raw bytes.
            match extract_zip_bytes_via_streaming(&buffer, path, base) {
                Ok(content) => return Ok(content),
                Err(e) => {
                    tracing::debug!(
                        "content-sniffed streaming zip extract failed for {archive_label}: {e:#}; scanning raw bytes"
                    );
                }
            }
        }
    }

    Ok(CompressedContent::Raw(buffer))
}

/* ───────────────────────────────────────────────────────────────
public entry point – keeps peeling layers
───────────────────────────────────────────────────────────── */
pub fn decompress_file(path: &Path, base_dir: Option<&Path>) -> Result<CompressedContent> {
    decompress_file_with_single_stream_cap(path, base_dir, MAX_SINGLE_STREAM_DECOMPRESSED_BYTES)
}

pub fn decompress_file_with_single_stream_cap(
    path: &Path,
    base_dir: Option<&Path>,
    single_stream_cap: u64,
) -> Result<CompressedContent> {
    let mut current_path: &Path = path;
    let mut owned_buf: Option<PathBuf>;

    loop {
        let should_extract_tar = is_tar_wrapped_compression(current_path);
        let content =
            decompress_once_with_single_stream_cap(current_path, base_dir, single_stream_cap)?;

        // If the step produced a single on-disk file that is itself a .tar,
        // recurse on that file.
        if let CompressedContent::RawFile(ref p) = content
            && should_extract_tar
        {
            owned_buf = Some(p.clone()); // own the path
            current_path = owned_buf.as_ref().unwrap();
            continue;
        }
        return Ok(content);
    }
}

fn make_output_path(path: &Path, base: Option<&Path>, extension: &str) -> PathBuf {
    if let Some(b) = base {
        let stem = path.file_stem().unwrap_or_default();
        b.join(stem).with_extension(extension)
    } else {
        std::env::temp_dir().join(format!(
            "kingfisher-{}-{}-{}",
            std::process::id(),
            Uuid::new_v4(),
            extension
        ))
    }
}

pub fn decompress_file_to_temp(path: &Path) -> Result<(CompressedContent, TempDir)> {
    let temp_dir = tempdir()?;
    let mut content = decompress_file(path, Some(temp_dir.path()))?;

    // if let CompressedContent::Archive(ref files) = content {
    let mut prefix_for_replace = None;
    if let Some(stem) = path.file_stem() {
        let candidate = temp_dir.path().join(stem).with_extension("decomp.tar");
        prefix_for_replace = Some(candidate);
    }

    if let CompressedContent::Archive(ref mut files) = content {
        if let Some(prefix) = &prefix_for_replace {
            let prefix_str = prefix.display().to_string();
            for (name, _) in files.iter_mut() {
                if let Some(rest) = name.strip_prefix(&prefix_str)
                    && let Some((_, suffix)) = rest.split_once('!')
                {
                    *name = format!("{}!{}", path.display(), suffix);
                }
            }
        }
        materialize_in_memory_archive_entries(files, temp_dir.path())?;
    } else if let CompressedContent::ArchiveFiles(ref mut entries) = content
        && let Some(prefix) = &prefix_for_replace
    {
        let prefix_str = prefix.display().to_string();
        for (name, _) in entries.iter_mut() {
            if let Some(rest) = name.strip_prefix(&prefix_str)
                && let Some((_, suffix)) = rest.split_once('!')
            {
                *name = format!("{}!{}", path.display(), suffix);
            }
        }
    }
    Ok((content, temp_dir))
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, path::Path};

    use flate2::{Compression, write::GzEncoder};
    use tar::Builder;
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::{
        CompressedContent, decompress_file_to_temp, materialize_in_memory_archive_entries,
    };

    fn decompress_once(path: &Path, base_dir: Option<&Path>) -> anyhow::Result<CompressedContent> {
        super::decompress_once_with_single_stream_cap(
            path,
            base_dir,
            super::MAX_SINGLE_STREAM_DECOMPRESSED_BYTES,
        )
    }

    /// A ZIP body written under a name with no recognized archive extension
    /// (mirroring a Terraform `tf.plan`) must still be extracted via content
    /// sniffing rather than scanned as opaque bytes.
    #[test]
    fn decompress_sniffs_zip_without_archive_extension() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let plan = dir.path().join("tf.plan");
        let github_pat = "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"; // this is not a real secret

        {
            let f = File::create(&plan)?;
            let mut zip = ZipWriter::new(f);
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zip.start_file("tfstate", opts)?;
            zip.write_all(format!("token={github_pat}\n").as_bytes())?;
            zip.finish()?;
        }

        match decompress_once(&plan, Some(dir.path()))? {
            CompressedContent::Archive(entries) => {
                let found = entries.iter().any(|(logical, bytes)| {
                    logical.ends_with("!tfstate")
                        && std::str::from_utf8(bytes).is_ok_and(|s| s.contains(github_pat))
                });
                assert!(found, "expected tfstate entry with secret, got {entries:?}");
            }
            other => panic!("expected Archive from content-sniffed zip, got {other:?}"),
        }

        Ok(())
    }

    /// A non-ZIP file with an unrecognized extension must be returned verbatim
    /// as raw bytes — content sniffing must not alter non-archive handling.
    #[test]
    fn decompress_leaves_non_zip_unknown_extension_as_raw() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let plan = dir.path().join("notes.plan");
        let body = b"plain text plan, definitely not a zip\n";
        std::fs::write(&plan, body)?;

        match decompress_once(&plan, Some(dir.path()))? {
            CompressedContent::Raw(bytes) => assert_eq!(bytes, body),
            other => panic!("expected Raw for non-zip file, got {other:?}"),
        }

        Ok(())
    }

    /// A valid but empty ZIP begins with a ZIP signature yet extracts to zero
    /// entries; it must fall back to raw bytes rather than being dropped.
    #[test]
    fn decompress_empty_zip_falls_back_to_raw() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let plan = dir.path().join("empty.plan");

        let mut bytes = Vec::new();
        {
            let w = ZipWriter::new(std::io::Cursor::new(&mut bytes));
            w.finish()?;
        }
        std::fs::write(&plan, &bytes)?;

        match decompress_once(&plan, Some(dir.path()))? {
            CompressedContent::Raw(raw) => assert_eq!(raw, bytes),
            other => panic!("expected Raw for empty zip, got {other:?}"),
        }

        Ok(())
    }

    /// The streaming route for large content-sniffed ZIPs (exercised here with a
    /// small ZIP to avoid a >64 MB fixture) must extract entries to disk and
    /// label them `label_path!entry`, matching the in-memory branch.
    #[test]
    fn streaming_zip_bytes_extracts_and_labels_by_path() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let github_pat = "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"; // this is not a real secret

        let mut bytes = Vec::new();
        {
            let mut zip = ZipWriter::new(std::io::Cursor::new(&mut bytes));
            let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            zip.start_file("tfstate", opts)?;
            zip.write_all(format!("token={github_pat}\n").as_bytes())?;
            zip.finish()?;
        }

        // The label path is logical only; it need not exist on disk.
        let label = Path::new("tf.plan");
        match super::extract_zip_bytes_via_streaming(&bytes, label, dir.path())? {
            CompressedContent::ArchiveFiles(entries) => {
                let (_, on_disk) = entries
                    .iter()
                    .find(|(logical, _)| logical == "tf.plan!tfstate")
                    .expect("expected tf.plan!tfstate entry");
                let txt = std::fs::read_to_string(on_disk)?;
                assert!(txt.contains(github_pat));
            }
            other => panic!("expected ArchiveFiles from streaming extract, got {other:?}"),
        }

        Ok(())
    }

    /// 1) Fully unpack:
    ///    - 1st decompress `.gz` -- get a `.tar` file
    ///
    ///    - 2nd decompress that `.tar` -- get ArchiveFiles
    #[test]
    fn smoke_decompress_tar_gz_archive() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tar_gz = dir.path().join("payload.tar.gz");
        let github_pat = "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"; // this is not a real secret

        // build payload.tar.gz containing secret.txt
        {
            let f = File::create(&tar_gz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let data = format!("token={github_pat}\n");
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "secret.txt", data.as_bytes())?;

            // finish archive + gzip stream
            tar.into_inner()?.finish()?;
        }

        // 1) peel off .gz -- RawFile(tar_path)
        let tmp = tempdir()?;
        let layer1 = decompress_once(&tar_gz, Some(tmp.path()))?;
        let tar_path = match layer1 {
            CompressedContent::RawFile(p) => p,
            other => panic!("expected RawFile on first pass, got {:?}", other),
        };

        // 2) unpack the .tar -- ArchiveFiles
        let content = decompress_once(&tar_path, Some(tmp.path()))?;
        if let CompressedContent::ArchiveFiles(files) = content {
            // find secret.txt
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("!secret.txt") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(github_pat));
                    found = true;
                }
            }
            assert!(found, "did not find secret.txt in ArchiveFiles");
        } else {
            panic!("expected ArchiveFiles on second pass, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_tgz_archive() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tgz = dir.path().join("payload.tgz");
        let github_pat = "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"; // this is not a real secret

        {
            let f = File::create(&tgz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let data = format!("token={github_pat}\n");
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "secret.txt", data.as_bytes())?;

            tar.into_inner()?.finish()?;
        }

        let (content, _tmp) = decompress_file_to_temp(&tgz)?;
        if let CompressedContent::ArchiveFiles(files) = content {
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("payload.tgz!secret.txt") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(github_pat));
                    found = true;
                }
            }
            assert!(found, "did not find secret.txt in tgz ArchiveFiles");
        } else {
            panic!("expected ArchiveFiles for tgz archive, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_truncated_tgz_archive_keeps_partial_entries() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tgz = dir.path().join("payload.tgz");
        let github_pat = "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"; // this is not a real secret

        {
            let f = File::create(&tgz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let first = format!("token={github_pat}\n");
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(first.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "first.txt", first.as_bytes())?;

            let second = vec![b'B'; 4096];
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(second.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "second.txt", second.as_slice())?;

            tar.into_inner()?.finish()?;
        }

        let tmp = tempdir()?;
        let content = super::decompress_file_with_single_stream_cap(&tgz, Some(tmp.path()), 1536)?;
        if let CompressedContent::ArchiveFiles(files) = content {
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("!first.txt") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(github_pat));
                    found = true;
                }
            }
            assert!(found, "did not recover first.txt from truncated archive");
        } else {
            panic!("expected ArchiveFiles for truncated tgz, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_truncated_tgz_archive_falls_back_to_raw_when_no_entry_completes()
    -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tgz = dir.path().join("payload.tgz");

        {
            let f = File::create(&tgz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let first = vec![b'A'; 2048];
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(first.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "secret.txt", first.as_slice())?;

            tar.into_inner()?.finish()?;
        }

        let tmp = tempdir()?;
        let content = super::decompress_file_with_single_stream_cap(&tgz, Some(tmp.path()), 600)?;
        match content {
            CompressedContent::RawFile(path) => {
                let data = std::fs::read(&path)?;
                let as_str = String::from_utf8_lossy(&data);
                assert!(
                    as_str.contains("secret.txt") || data.windows(5).any(|w| w == b"ustar"),
                    "raw fallback should preserve tar bytes"
                );
            }
            other => panic!("expected RawFile for heavily truncated tgz, got {:?}", other),
        }

        Ok(())
    }

    /// 2) No-extract flag: just peel the `.gz` layer (no base_dir -- use NamedTempFile), and verify
    ///    you get back a RawFile, whose contents are the tar archive itself.
    #[test]
    fn smoke_decompress_without_extract_archives() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tar_gz = dir.path().join("payload.tar.gz");
        let github_pat = "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";

        // ── build payload.tar.gz containing secret.txt ──────────────────────────────
        {
            let f = File::create(&tar_gz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let data = format!("token={github_pat}\n");
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "secret.txt", data.as_bytes())?;

            // finish archive + gzip stream
            tar.into_inner()?.finish()?;
        }

        // peel only the .gz -- get a RawFile, but do NOT unpack tar
        let content = decompress_once(&tar_gz, None)?;
        match content {
            CompressedContent::RawFile(path) => {
                // ensure the file exists and contains the tar header or our secret name
                let data = std::fs::read(&path)?;
                let as_str = String::from_utf8_lossy(&data);
                assert!(
                    as_str.contains("secret.txt") || data.windows(5).any(|w| w == b"ustar"),
                    "raw file isn’t a tar archive"
                );
            }
            other => panic!("expected RawFile, got {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_zip_archive() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let zip_path = dir.path().join("payload.zip");
        let github_pat = "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"; // this is not a real secret

        {
            let file = File::create(&zip_path)?;
            let mut zip = ZipWriter::new(file);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);

            zip.start_file("nested/secret.txt", options)?;
            zip.write_all(format!("token={github_pat}\n").as_bytes())?;
            zip.finish()?;
        }

        let tmp = tempdir()?;
        let content = decompress_once(&zip_path, Some(tmp.path()))?;
        if let CompressedContent::ArchiveFiles(files) = content {
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("!nested/secret.txt") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(github_pat));
                    found = true;
                }
            }
            assert!(found, "did not find nested/secret.txt in ArchiveFiles");
        } else {
            panic!("expected ArchiveFiles for zip archive, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn materialize_in_memory_archive_entries_skips_unsafe_paths() -> anyhow::Result<()> {
        let sandbox = tempdir()?;
        let extract_root = sandbox.path().join("extract");
        std::fs::create_dir(&extract_root)?;

        let outside_parent = sandbox.path().join("outside-parent.txt");
        let outside_absolute = sandbox.path().join("outside-absolute.txt");
        let entries = vec![
            ("archive.asar!nested/safe.txt".to_string(), b"safe".to_vec()),
            ("archive.asar!../outside-parent.txt".to_string(), b"bad".to_vec()),
            (format!("archive.asar!{}", outside_absolute.display()), b"bad".to_vec()),
        ];

        materialize_in_memory_archive_entries(&entries, &extract_root)?;

        assert_eq!(std::fs::read(extract_root.join("nested/safe.txt"))?, b"safe");
        assert!(!outside_parent.exists());
        assert!(!outside_absolute.exists());
        Ok(())
    }

    #[test]
    fn decompress_asar_skips_parent_dir_entries() -> anyhow::Result<()> {
        use asar::AsarWriter;

        let mut writer = AsarWriter::new();
        writer.write_file("safe.txt", b"safe", false)?;
        writer.write_file("aa/bb/escape.txt", b"bad", false)?;

        let mut archive = Vec::new();
        writer.finalize(&mut archive)?;

        let json_size = u32::from_le_bytes(archive[12..16].try_into().unwrap()) as usize;
        let header = &mut archive[16..16 + json_size];
        let header_str = std::str::from_utf8(header)?;
        assert!(header_str.contains("\"aa\""));
        assert!(header_str.contains("\"bb\""));

        let patched = header_str.replace("\"aa\"", "\"..\"").replace("\"bb\"", "\"..\"");
        assert_eq!(patched.len(), header_str.len());
        header.copy_from_slice(patched.as_bytes());

        let dir = tempdir()?;
        let asar_path = dir.path().join("malicious.asar");
        std::fs::write(&asar_path, archive)?;

        let (content, _tmp) = decompress_file_to_temp(&asar_path)?;
        let CompressedContent::Archive(entries) = content else {
            panic!("expected Archive for asar");
        };

        assert_eq!(entries.len(), 1);
        assert!(
            entries
                .iter()
                .any(|(name, data)| name.ends_with("!safe.txt") && data.as_slice() == b"safe")
        );
        assert!(!entries.iter().any(|(name, _)| name.contains("..")));
        Ok(())
    }

    /// 3) Nested archive: outer.tar.gz  ──▶  outer.tar  (contains inner.tar.gz) └──▶  inner.tar.gz
    ///    ──▶  inner.tar  (contains secret.txt)
    #[test]
    fn smoke_decompress_nested_tar_gz_archives() -> anyhow::Result<()> {
        use std::{fs::File, io::Read, path::PathBuf};

        use flate2::{Compression, write::GzEncoder};
        use tar::Builder;
        use tempfile::tempdir;

        use super::CompressedContent;

        let tmp = tempdir()?;

        /* ── build INNER tar.gz ──────────────────────────────────────────────── */
        let inner_tgz = tmp.path().join("inner.tar.gz");
        {
            let f = File::create(&inner_tgz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let data = b"nested_secret=shh\n";
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "secret.txt", &data[..])?;

            tar.into_inner()?.finish()?;
        }

        /* ── read inner archive into memory so we can embed it ──────────────── */
        let mut inner_bytes = Vec::new();
        File::open(&inner_tgz)?.read_to_end(&mut inner_bytes)?;

        /* ── build OUTER tar.gz that contains the inner .tar.gz ─────────────── */
        let outer_tgz = tmp.path().join("outer.tar.gz");
        {
            let f = File::create(&outer_tgz)?;
            let gz = GzEncoder::new(f, Compression::default());
            let mut tar = Builder::new(gz);

            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(inner_bytes.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_cksum();
            tar.append_data(&mut hdr, "inner.tar.gz", inner_bytes.as_slice())?;

            tar.into_inner()?.finish()?;
        }

        /* ── Layer 1: gunzip outer.tar.gz ───────────────────────────────────── */
        let scratch = tempdir()?; // where intermediate layers land
        let tar_path = match decompress_once(&outer_tgz, Some(scratch.path()))? {
            CompressedContent::RawFile(p) => p,
            other => panic!("expected RawFile after gunzip, got {:?}", other),
        };

        /* ── Layer 2: untar outer.tar  -> find inner.tar.gz on disk ─────────── */
        let inner_on_disk: PathBuf = match decompress_once(&tar_path, Some(scratch.path()))? {
            CompressedContent::ArchiveFiles(files) => files
                .into_iter()
                .find(|(logical, _)| logical.ends_with("!inner.tar.gz"))
                .map(|(_, p)| p)
                .expect("inner.tar.gz not found in outer archive"),
            other => panic!("expected ArchiveFiles after untar, got {:?}", other),
        };

        /* ── Layer 3: gunzip inner.tar.gz ───────────────────────────────────── */
        let inner_tar = match decompress_once(&inner_on_disk, Some(scratch.path()))? {
            CompressedContent::RawFile(p) => p,
            other => panic!("expected RawFile after gunzip inner, got {:?}", other),
        };

        /* ── Layer 4: untar inner.tar  -> secret.txt should be present ──────── */
        match decompress_once(&inner_tar, Some(scratch.path()))? {
            CompressedContent::ArchiveFiles(files) => {
                let mut found = false;
                for (logical, path) in files {
                    if logical.ends_with("!secret.txt") {
                        let txt = std::fs::read_to_string(&path)?;
                        assert!(txt.contains("nested_secret=shh"), "secret.txt content corrupted");
                        found = true;
                    }
                }
                assert!(found, "secret.txt not extracted from nested archive");
            }
            other => panic!("expected ArchiveFiles after untar inner, got {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_apk_archive() -> anyhow::Result<()> {
        // APKs are ZIP containers. We expect Kingfisher to recognize the .apk
        // extension and extract its entries so embedded secrets get scanned.
        let dir = tempdir()?;
        let apk_path = dir.path().join("aws_leak.apk");
        let aws_key = "AKIAIOSFODNN7EXAMPLE"; // canonical AWS sample, not real

        {
            let file = File::create(&apk_path)?;
            let mut zip = ZipWriter::new(file);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);

            zip.start_file("res/values/strings.xml", options)?;
            zip.write_all(
                format!(
                    "<?xml version=\"1.0\"?><resources><string name=\"aws\">{aws_key}</string></resources>"
                )
                .as_bytes(),
            )?;
            zip.finish()?;
        }

        let tmp = tempdir()?;
        let content = decompress_once(&apk_path, Some(tmp.path()))?;
        if let CompressedContent::ArchiveFiles(files) = content {
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("!res/values/strings.xml") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(aws_key));
                    found = true;
                }
            }
            assert!(found, "did not find res/values/strings.xml in apk ArchiveFiles");
        } else {
            panic!("expected ArchiveFiles for apk archive, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_hwpx_archive() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let hwpx_path = dir.path().join("document.hwpx");
        let github_pat = "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"; // this is not a real secret

        {
            let file = File::create(&hwpx_path)?;
            let mut zip = ZipWriter::new(file);
            let options = SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .unix_permissions(0o644);

            zip.start_file("Contents/section0.xml", options)?;
            zip.write_all(
                format!("<?xml version=\"1.0\"?><doc>token={github_pat}</doc>").as_bytes(),
            )?;
            zip.finish()?;
        }

        let tmp = tempdir()?;
        let content = decompress_once(&hwpx_path, Some(tmp.path()))?;
        if let CompressedContent::ArchiveFiles(files) = content {
            let mut found = false;
            for (logical, path) in files {
                if logical.ends_with("!Contents/section0.xml") {
                    let txt = std::fs::read_to_string(&path)?;
                    assert!(txt.contains(github_pat));
                    found = true;
                }
            }
            assert!(found, "did not find Contents/section0.xml in hwpx ArchiveFiles");
        } else {
            panic!("expected ArchiveFiles for hwpx archive, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_hwp_archive() -> anyhow::Result<()> {
        use cfb::CompoundFile;
        use flate2::{Compression, write::ZlibEncoder};

        let dir = tempdir()?;
        let hwp_path = dir.path().join("document.hwp");
        let github_pat = "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"; // this is not a real secret

        // Build a minimal CFB with two streams: one plaintext, one zlib-framed.
        {
            let file = File::create(&hwp_path)?;
            let mut cf = CompoundFile::create(file)?;
            cf.create_storage("/BodyText")?;

            let mut s_plain = cf.create_stream("/DocInfo")?;
            s_plain.write_all(format!("metadata token={github_pat}").as_bytes())?;
            drop(s_plain);

            let mut zencoder = ZlibEncoder::new(Vec::new(), Compression::default());
            zencoder.write_all(format!("body token={github_pat}").as_bytes())?;
            let zbytes = zencoder.finish()?;
            let mut s_body = cf.create_stream("/BodyText/Section0")?;
            s_body.write_all(&zbytes)?;
            drop(s_body);

            cf.flush()?;
        }

        let content = decompress_once(&hwp_path, None)?;
        if let CompressedContent::Archive(entries) = content {
            let mut saw_plain = false;
            let mut saw_body = false;
            for (logical, bytes) in &entries {
                let as_str = String::from_utf8_lossy(bytes);
                if logical.contains("DocInfo") && as_str.contains(github_pat) {
                    saw_plain = true;
                }
                if logical.contains("Section0") && as_str.contains(github_pat) {
                    saw_body = true;
                }
            }
            assert!(saw_plain, "plaintext DocInfo stream missing or not decoded");
            assert!(saw_body, "zlib-framed BodyText/Section0 stream missing or not decoded");
        } else {
            panic!("expected Archive for hwp, got {:?}", content);
        }

        Ok(())
    }

    #[test]
    fn smoke_decompress_egg_raw() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let egg_path = dir.path().join("archive.egg");
        let github_pat = "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"; // this is not a real secret

        {
            let mut f = File::create(&egg_path)?;
            f.write_all(format!("EGG-pretend-header\ntoken={github_pat}\n").as_bytes())?;
        }

        let content = decompress_once(&egg_path, None)?;
        match content {
            CompressedContent::Raw(bytes) => {
                let as_str = String::from_utf8_lossy(&bytes);
                assert!(
                    as_str.contains(github_pat),
                    "raw egg bytes did not contain the embedded pat"
                );
            }
            other => panic!("expected Raw for egg, got {:?}", other),
        }

        Ok(())
    }

    #[test]
    fn capped_writer_drops_bytes_past_cap() {
        use std::io::Write;

        use super::CappedWriter;

        let mut sink = Vec::new();
        let mut capped = CappedWriter::new(&mut sink, 40);
        // Report full consumption even though the tail is dropped.
        assert_eq!(capped.write(&[0u8; 100]).unwrap(), 100);
        assert!(capped.truncated());
        capped.flush().unwrap();
        assert_eq!(sink.len(), 40);

        let mut sink = Vec::new();
        let mut capped = CappedWriter::new(&mut sink, 40);
        assert_eq!(capped.write(&[0u8; 10]).unwrap(), 10);
        assert!(!capped.truncated());
        assert_eq!(sink.len(), 10);
    }

    #[test]
    fn stream_to_file_capped_truncates_oversized_stream() -> anyhow::Result<()> {
        use std::io::Cursor;

        use super::{CompressedContent, stream_to_file_capped};

        let dir = tempdir()?;
        let out_path = dir.path().join("out.bin");

        // A "decompressed" stream far larger than the cap: only `cap` bytes
        // should ever reach disk, mirroring a small compression bomb.
        let payload = vec![b'A'; 8192];
        let content = stream_to_file_capped(Cursor::new(payload), &out_path, 128)?;

        match content {
            CompressedContent::RawFile(p) => {
                let written = std::fs::metadata(&p)?.len();
                assert_eq!(written, 128, "output must be capped at the byte budget");
            }
            other => panic!("expected RawFile, got {other:?}"),
        }
        Ok(())
    }
}
