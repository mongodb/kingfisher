use std::{
    collections::HashSet,
    io::{self, BufReader, Read, Seek},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use zip::ZipArchive;

use super::{
    ScanArchive, ScanArchiveBuffer, ScanArchiveMember,
    decompress::{
        MAX_INMEM_ZIP_ARCHIVE_BYTES, MAX_INMEM_ZIP_DECOMPRESSED_BYTES, is_safe_extract_path,
    },
    limits::ResourceLimits,
};

/// Read ZIP members from a seekable source. The iterator retains only the current
/// member's storage and uses the same decoded-byte budget as CLI extraction.
#[doc(hidden)]
pub fn scan_zip<R: Read + Seek + Send + 'static>(
    reader: R,
    path: &Path,
    file_size: u64,
    magic_only: bool,
    resources: ResourceLimits,
) -> Result<ScanArchive> {
    let small_sniffed = magic_only && file_size <= MAX_INMEM_ZIP_ARCHIVE_BYTES as u64;
    let label = path.display().to_string();
    let mut zip = ZipArchive::new(BufReader::new(reader))?;
    preflight(&mut zip, &label, small_sniffed)?;

    let mut index = 0;
    let mut total = 0u64;
    let mut members = std::iter::from_fn(move || {
        while index < zip.len() && !resources.reached(total, MAX_INMEM_ZIP_DECOMPRESSED_BYTES) {
            let i = index;
            index += 1;
            let mut entry = match zip.by_index(i) {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::debug!(archive = %label, entry = i, %error, "ZIP entry open failed");
                    continue;
                }
            };
            if !entry.is_file() {
                continue;
            }
            let name = match entry.name() {
                Ok(name) if is_safe_extract_path(Path::new(name.as_ref())) => name.into_owned(),
                Ok(name) => {
                    tracing::debug!(archive = %label, member = %name, "Unsafe ZIP member path");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(archive = %label, entry = i, %error, "ZIP entry name decoding failed");
                    continue;
                }
            };
            let remaining = MAX_INMEM_ZIP_DECOMPRESSED_BYTES.saturating_sub(total);
            let mut output = ScanArchiveBuffer::default();
            let decoded = io::copy(&mut resources.reader(&mut entry, remaining), &mut output)
                .and_then(|count| output.finish().map(|data| (count, data)));
            match decoded {
                Ok((count, data)) => {
                    total += count;
                    return Some(ScanArchiveMember { name: format!("{label}!{name}"), data });
                }
                Err(error) => {
                    tracing::debug!(archive = %label, member = %name, %error, "ZIP member decoding failed");
                }
            }
        }
        None
    });

    // The content-sniffed, small-file path used the raw file when it found no
    // readable members. A named ZIP with zero members remains an empty archive.
    if small_sniffed {
        return Ok(match members.next() {
            Some(first) => ScanArchive::Members(Box::new(std::iter::once(first).chain(members))),
            None => ScanArchive::Original,
        });
    }
    Ok(ScanArchive::Members(Box::new(members)))
}

fn preflight<R: Read + Seek>(
    zip: &mut ZipArchive<R>,
    label: &str,
    small_sniffed: bool,
) -> Result<()> {
    let mut staged_files = HashSet::new();
    let mut staged_dirs = HashSet::new();
    for index in 0..zip.len() {
        // The disk extractor opens each local header before yielding any work to
        // the matcher. Validate the same headers before streaming members so a
        // malformed archive can still be retried with legacy fallback semantics.
        // The seekable ZIP reader drops this entry without decoding its payload.
        let entry = match zip.by_index(index) {
            Ok(entry) => entry,
            Err(_) if small_sniffed => continue,
            Err(error) => return Err(error.into()),
        };
        if !entry.is_file() {
            continue;
        }
        let name = match entry.name() {
            Ok(name) => name,
            Err(_) if small_sniffed => continue,
            Err(error) => return Err(error.into()),
        };
        let path = Path::new(name.as_ref());
        if !is_safe_extract_path(path) {
            continue;
        }

        if small_sniffed {
            // The old in-memory extractor materialized its output as a batch.
            // Replay through that path when staging could fail due to a
            // file/directory collision or an invalid destination.
            let logical = format!("{label}!{name}");
            let rel = logical.split_once('!').map_or(logical.as_str(), |(_, name)| name);
            let normalized = rel.replace('\\', "/");
            let path = Path::new(&normalized);
            if !is_safe_extract_path(path) {
                continue;
            }
            if !can_be_file_path(path) {
                bail!("ZIP member needs legacy path handling");
            }
            // Case-insensitive filesystems can alias names. If there is a
            // possible collision, let the legacy path apply the host rules.
            let key = PathBuf::from(normalized.to_lowercase());
            if staged_dirs.contains(&key) {
                bail!("ZIP contents need legacy path collision handling");
            }
            for parent in key.ancestors().skip(1) {
                if staged_files.contains(parent) {
                    bail!("ZIP contents need legacy path collision handling");
                }
                staged_dirs.insert(parent.to_owned());
            }
            staged_files.insert(key);
        } else if !can_be_file_path(path) {
            bail!("ZIP member needs legacy path handling");
        }
    }
    Ok(())
}

pub(super) fn can_be_file_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    if path.file_name().is_none() || bytes.contains(&0) || bytes.ends_with(b"/.") {
        return false;
    }
    for component in path.components() {
        let component = component.as_os_str().as_encoded_bytes();
        if component.len() > 255 {
            return false;
        }
        #[cfg(windows)]
        if component.ends_with(b".")
            || component.ends_with(b" ")
            || component.iter().any(|&b| b < 32 || b"<>:\"|?*".contains(&b))
            || is_windows_device_name(component)
        {
            return false;
        }
    }
    true
}

#[cfg(windows)]
fn is_windows_device_name(name: &[u8]) -> bool {
    let base = name.split(|&byte| byte == b'.').next().unwrap_or(name);
    [b"CON".as_slice(), b"PRN", b"AUX", b"NUL", b"CONIN$", b"CONOUT$"]
        .iter()
        .any(|reserved| base.eq_ignore_ascii_case(reserved))
        || (base.len() == 4
            && base[3].is_ascii_digit()
            && (base[..3].eq_ignore_ascii_case(b"COM") || base[..3].eq_ignore_ascii_case(b"LPT")))
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{SeekFrom, Write},
    };

    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::archive::ScanArchiveData;

    fn zip_with_entries(entries: &[(&str, &[u8])]) -> Result<File> {
        let mut zip = ZipWriter::new(tempfile::tempfile()?);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, data) in entries {
            zip.start_file(*name, options)?;
            zip.write_all(data)?;
        }
        Ok(zip.finish()?)
    }

    #[test]
    fn scans_members_from_the_original_zip_and_ignores_bad_crc() -> Result<()> {
        let mut file = zip_with_entries(&[
            ("before.txt", b"good before"),
            ("broken.txt", b"data with a stale CRC"),
            ("after.txt", b"good after"),
        ])?;
        let mut zip = ZipArchive::new(file.try_clone()?)?;
        let data_start = zip.by_index(1)?.data_start().expect("local entry data offset");
        drop(zip);
        file.seek(SeekFrom::Start(data_start))?;
        file.write_all(b"D")?;
        let size = file.metadata()?.len();

        let ScanArchive::Members(members) =
            scan_zip(file, Path::new("sample.zip"), size, false, ResourceLimits::default())?
        else {
            panic!("expected ZIP members");
        };
        let members: Vec<_> = members
            .map(|member| match member.data {
                ScanArchiveData::Bytes(bytes) => (member.name, bytes),
                _ => panic!("small member spilled to disk"),
            })
            .collect();
        assert_eq!(
            members,
            [
                ("sample.zip!before.txt".to_owned(), b"good before".to_vec()),
                ("sample.zip!after.txt".to_owned(), b"good after".to_vec()),
            ]
        );
        Ok(())
    }

    #[test]
    fn empty_content_sniffed_zip_preserves_raw_scan() -> Result<()> {
        let file = zip_with_entries(&[])?;
        let size = file.metadata()?.len();
        assert!(matches!(
            scan_zip(file, Path::new("empty.plan"), size, true, ResourceLimits::default())?,
            ScanArchive::Original,
        ));
        Ok(())
    }

    #[test]
    fn small_content_sniffed_zip_detects_legacy_path_collisions() -> Result<()> {
        let file = zip_with_entries(&[("entry", b"first"), ("entry/config", b"second")])?;
        let size = file.metadata()?.len();
        assert!(
            scan_zip(file, Path::new("mixed.plan"), size, true, ResourceLimits::default()).is_err()
        );
        Ok(())
    }
}
