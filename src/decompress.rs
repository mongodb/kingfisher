//! src/utils/decompress.rs   (or wherever you keep the module)

use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use anyhow::Result;
use asar::AsarReader;
use bzip2::read::BzDecoder;
use flate2::read::{GzDecoder, ZlibDecoder};
use memmap2::Mmap;
use tar::Archive;
use tempfile::{tempdir, TempDir};
use xz2::read::XzDecoder;
use zip::ZipArchive;

/// Formats that are basically a ZIP container.
pub const ZIP_BASED_FORMATS: &[&str] = &[
    "zip", "zipx", "jar", "war", "ear", "aar", "jmod", "jhm", "jnlp", "nupkg", "vsix", "xap",
    "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg", "odf", "epub", "gadget", "kmz", "widget",
    "xpi", "sketch", "pages", "key", "numbers",
];

/// Break `<name>.<outer>.<inner>` into `(Some(outer), Some(inner))`.
/// For `foo.tar.gz` this returns `("tar", "gz")`.
fn split_extensions(path: &Path) -> (Option<String>, Option<String>) {
    let ext_inner = path.extension().and_then(|e| e.to_str()).map(|s| s.to_ascii_lowercase());

    let ext_outer = path
        .file_stem()
        .and_then(|s| Path::new(s).extension())
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());

    (ext_outer, ext_inner)
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
    for (idx, comp) in path.components().enumerate() {
        match comp {
            // Never allow parent-directory escapes
            Component::ParentDir => return false,

            // Leading "C:\" (Windows) or "/" (Unix) is fine;
            // a prefix later in the path would be suspicious.
            Component::Prefix(_) | Component::RootDir if idx == 0 => continue,

            // A prefix *inside* the path (e.g. "foo/C:\evil") is unsafe
            Component::Prefix(_) => return false,

            _ => {}
        }
    }
    true
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

    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type().is_file() {
            let path_in_tar = entry.path()?.to_string_lossy().to_string();
            let logical_path = format!("{}!{}", archive_path.display(), path_in_tar);

            let out_path = base_dir.join(&path_in_tar);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if !is_safe_extract_path(&out_path) {
                tracing::warn!("unsafe tar path: {}", out_path.display());
                continue;
            }
            let mut out_file = fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out_file)?;

            entries_on_disk.push((logical_path, out_path));
        }
    }
    Ok(CompressedContent::ArchiveFiles(entries_on_disk))
}

fn handle_zip_archive_streaming(
    file: &mut fs::File,
    archive_path: &Path,
    base_dir: &Path,
) -> Result<CompressedContent> {
    let mut zip = ZipArchive::new(file)?;
    let mut entries_on_disk = Vec::new();

    for i in 0..zip.len() {
        let mut zipped_file = zip.by_index(i)?;
        if zipped_file.is_file() {
            let name_in_zip = zipped_file.name().to_string();
            let logical_path = format!("{}!{}", archive_path.display(), name_in_zip);

            let out_path = base_dir.join(&name_in_zip);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if !is_safe_extract_path(&out_path) {
                tracing::warn!("unsafe zip path: {}", out_path.display());
                continue;
            }
            let mut out_file = fs::File::create(&out_path)?;
            std::io::copy(&mut zipped_file, &mut out_file)?;

            entries_on_disk.push((logical_path, out_path));
        }
    }
    Ok(CompressedContent::ArchiveFiles(entries_on_disk))
}

fn handle_asar_archive_in_memory(
    buffer: Vec<u8>,
    archive_path: &Path,
) -> Result<CompressedContent> {
    match AsarReader::new(&buffer, None) {
        Ok(reader) => {
            let mut contents = Vec::new();
            for (path_in_asar, file) in reader.files() {
                let inner_path = path_in_asar.to_string_lossy().to_string();
                let logical_path = format!("{}!{}", archive_path.display(), inner_path);
                contents.push((logical_path, file.data().to_vec()));
            }
            Ok(CompressedContent::Archive(contents))
        }
        Err(_) => Ok(CompressedContent::Archive(Vec::new())),
    }
}

fn stream_to_file<R: Read>(mut decoder: R, out_path: &Path) -> Result<CompressedContent> {
    if !is_safe_extract_path(out_path) {
        anyhow::bail!("unsafe path during decompression: {}", out_path.display());
    }
    let mut out_file = fs::File::create(out_path)?;
    std::io::copy(&mut decoder, &mut out_file)?;
    Ok(CompressedContent::RawFile(out_path.to_owned()))
}

/* ───────────────────────────────────────────────────────────────
one *step* of decompression
───────────────────────────────────────────────────────────── */
fn decompress_once(path: &Path, base_dir: Option<&Path>) -> Result<CompressedContent> {
    let extension = path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_ascii_lowercase());

    let mut file = fs::File::open(path)?;

    if let Some(ext) = extension.as_deref() {
        match ext {
            "asar" => {
                let mmap = unsafe { Mmap::map(&file)? };
                return handle_asar_archive_in_memory(mmap.to_vec(), path);
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
            "gz" | "gzip" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = GzDecoder::new(fs::File::open(path)?);
                return stream_to_file(decoder, &out_path);
            }
            "bz2" | "bzip2" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = BzDecoder::new(fs::File::open(path)?);
                return stream_to_file(decoder, &out_path);
            }
            "xz" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = XzDecoder::new(fs::File::open(path)?);
                return stream_to_file(decoder, &out_path);
            }
            "zlib" => {
                let out_path = make_output_path(path, base_dir, "decomp.tar");
                let decoder = ZlibDecoder::new(fs::File::open(path)?);
                return stream_to_file(decoder, &out_path);
            }
            _ => {}
        }
    }

    // Unknown extension -- just read the bytes
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(CompressedContent::Raw(buffer))
}

/* ───────────────────────────────────────────────────────────────
public entry point – keeps peeling layers
───────────────────────────────────────────────────────────── */
pub fn decompress_file(path: &Path, base_dir: Option<&Path>) -> Result<CompressedContent> {
    let mut current_path: &Path = path;
    let mut owned_buf: Option<PathBuf>;

    loop {
        let content = decompress_once(current_path, base_dir)?;

        // If the step produced a single on-disk file that is itself a .tar,
        // recurse on that file.
        if let CompressedContent::RawFile(ref p) = content {
            if split_extensions(p).0.as_deref() == Some("tar") {
                owned_buf = Some(p.clone());          // own the path
                current_path = owned_buf.as_ref().unwrap();
                continue;
            }
        }
        return Ok(content);
    }
}

fn make_output_path(path: &Path, base: Option<&Path>, extension: &str) -> PathBuf {
    if let Some(b) = base {
        let stem = path.file_stem().unwrap_or_default();
        b.join(stem).with_extension(extension)
    } else {
        tempfile::NamedTempFile::new().unwrap().into_temp_path().to_path_buf()
    }
}

/* ───────────────────────────────────────────────────────────── */
pub fn decompress_file_to_temp(path: &Path) -> Result<(CompressedContent, TempDir)> {
    let temp_dir = tempdir()?;
    let content = decompress_file(path, Some(temp_dir.path()))?;

    if let CompressedContent::Archive(ref files) = content {
        for (name, data) in files {
            let rel = name.split_once('!').map(|(_, sub)| sub).unwrap_or(name);
            let p = temp_dir.path().join(rel.replace('\\', "/"));
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(p, data)?;
        }
    }
    Ok((content, temp_dir))
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write, path::PathBuf};

    use flate2::{write::GzEncoder, Compression};
    use tar::Builder;
    use tempfile::tempdir;

    use super::{decompress_once, CompressedContent};

    /// 1) Fully unpack:
    ///    - 1st decompress `.gz` -- get a `.tar` file
    /// 
    ///    - 2nd decompress that `.tar` -- get ArchiveFiles
    #[test]
    fn smoke_decompress_tar_gz_archive() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tar_gz = dir.path().join("payload.tar.gz");
        let github_pat = "ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa"; // this is not a real secret

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

    /// 2) No-extract flag: just peel the `.gz` layer (no base_dir -- use NamedTempFile), and verify
    ///    you get back a RawFile, whose contents are the tar archive itself.
    #[test]
    fn smoke_decompress_without_extract_archives() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let tar_gz = dir.path().join("payload.tar.gz");
        let github_pat = "ghp_1wuHFikBKQtCcH3EB2FBUkyn8krXhP2qLqPa";

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

    /// 3) Nested archive:
    ///    outer.tar.gz  ──▶  outer.tar  (contains inner.tar.gz)
    ///                               └──▶  inner.tar.gz  ──▶  inner.tar  (contains secret.txt)
    #[test]
    fn smoke_decompress_nested_tar_gz_archives() -> anyhow::Result<()> {
        use std::{
            fs::File,
            io::{Read, Write},
            path::PathBuf,
        };

        use flate2::{write::GzEncoder, Compression};
        use tar::Builder;
        use tempfile::tempdir;

        use super::{decompress_once, CompressedContent};

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
                        assert!(
                            txt.contains("nested_secret=shh"),
                            "secret.txt content corrupted"
                        );
                        found = true;
                    }
                }
                assert!(found, "secret.txt not extracted from nested archive");
            }
            other => panic!("expected ArchiveFiles after untar inner, got {:?}", other),
        }

        Ok(())
    }
}
