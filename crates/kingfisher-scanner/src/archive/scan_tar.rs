use std::{
    cell::RefCell,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
    thread,
};

use anyhow::{Context, Result};
use bzip2_rs::DecoderReader;
use flate2::read::GzDecoder;
use tar::Archive;

use super::{
    ScanArchive, ScanArchiveBuffer, ScanArchiveData, ScanArchiveMember,
    decompress::{
        MAX_SINGLE_STREAM_DECOMPRESSED_BYTES, MAX_TAR_ARCHIVE_ENTRIES, MAX_TAR_DECOMPRESSED_BYTES,
        MAX_TAR_ENTRY_DECOMPRESSED_BYTES, is_safe_extract_path,
    },
    limits::ResourceLimits,
    scan_zip::can_be_file_path,
};

const MAX_MEMBER_MEMORY: usize = 1024 * 1024;
const MAX_RETAINED_MEMORY: usize = 16 * 1024 * 1024;

enum TarCompression {
    Plain,
    Gzip,
    Bzip2,
    Xz,
}

impl TarCompression {
    fn for_path(path: &Path) -> Option<Self> {
        let extension = path.extension()?.to_str()?;
        if extension.eq_ignore_ascii_case("tar") {
            return Some(Self::Plain);
        }
        let name = path.file_name()?.to_str()?.to_ascii_lowercase();
        if name.ends_with(".tgz") || name.ends_with(".tar.gz") || name.ends_with(".tar.gzip") {
            Some(Self::Gzip)
        } else if name.ends_with(".tar.bz2") || name.ends_with(".tar.bzip2") {
            Some(Self::Bzip2)
        } else if name.ends_with(".tar.xz") {
            Some(Self::Xz)
        } else {
            None
        }
    }
}

/// Parse a TAR directly from the opened input or its compression decoder.
/// `None` lets the caller use the existing extractor when streaming cannot
/// preserve its fallback or path handling.
#[doc(hidden)]
pub fn scan_tar(
    file: &mut File,
    path: &Path,
    resources: ResourceLimits,
) -> Result<Option<ScanArchive>> {
    let Some(compression) = TarCompression::for_path(path) else {
        return Ok(None);
    };
    file.rewind()?;
    scan_tar_reader(file, path, compression, resources)
}

/// Parse a resident TAR or compressed TAR without writing the input to a file.
#[doc(hidden)]
pub fn scan_tar_bytes(
    data: &[u8],
    path: &Path,
    resources: ResourceLimits,
) -> Result<Option<ScanArchive>> {
    let Some(compression) = TarCompression::for_path(path) else {
        return Ok(None);
    };
    if !can_be_file_path(path) {
        return Ok(None);
    }
    scan_tar_reader(data, path, compression, resources)
}

fn scan_tar_reader(
    reader: impl Read + Send,
    path: &Path,
    compression: TarCompression,
    resources: ResourceLimits,
) -> Result<Option<ScanArchive>> {
    match compression {
        TarCompression::Plain => scan_members(reader, path, resources, &RefCell::new(None)),
        TarCompression::Gzip => {
            scan_wrapped(GzDecoder::new(BufReader::new(reader)), path, resources)
        }
        TarCompression::Bzip2 => {
            scan_wrapped(DecoderReader::new(BufReader::new(reader)), path, resources)
        }
        TarCompression::Xz => scan_xz(reader, path, resources),
    }
}

fn scan_xz(
    input: impl Read + Send,
    path: &Path,
    resources: ResourceLimits,
) -> Result<Option<ScanArchive>> {
    // The XZ decoder writes to a sink. A bounded pipe connects it to the TAR
    // reader while keeping ownership of both ends within this call.
    let (reader, mut writer) = io::pipe()?;
    thread::scope(|scope| {
        let decoder =
            thread::Builder::new().name("kingfisher-xz".into()).spawn_scoped(scope, move || {
                lzma_rs::xz_decompress(&mut BufReader::new(input), &mut writer)
            })?;
        let parsed = scan_wrapped(BufReader::new(reader), path, resources);
        // scan_wrapped drops the reader even when it declines a stream, so the
        // worker cannot remain blocked writing to an abandoned pipe.
        let decoded = decoder.join().map_err(|_| anyhow::anyhow!("XZ decoder worker panicked"))?;
        let parsed = parsed?;
        if parsed.is_some() {
            decoded?;
        }
        Ok(parsed)
    })
}

fn scan_wrapped(
    mut decoder: impl Read,
    path: &Path,
    resources: ResourceLimits,
) -> Result<Option<ScanArchive>> {
    let raw = RefCell::new(Some(ScanArchiveBuffer::sparse()));
    let mut input = CaptureReader {
        inner: resources.reader(&mut decoder, MAX_SINGLE_STREAM_DECOMPRESSED_BYTES),
        raw: &raw,
        error: None,
    };
    let members = scan_members(&mut input, path, resources, &raw)?;
    if let Some(error) = input.error.take() {
        return Err(error.into());
    }
    if members.is_none() {
        return Ok(None);
    }
    let completed = match members {
        Some(ScanArchive::Original) => {
            // Retain the full capped stream when the TAR parser fails before
            // finding a complete member. A raw scan needs these exact bytes.
            io::copy(&mut input, &mut io::sink())?;
            let captured = raw.borrow_mut().take().expect("raw TAR fallback is still retained");
            Some(ScanArchive::Raw(captured.finish()?))
        }
        outcome => outcome,
    };
    // The existing extractor reads to the compressor's end, including bytes
    // beyond the decoded cap. Verify the checksum before exposing any members.
    drop(input);
    io::copy(&mut decoder, &mut io::sink())?;
    Ok(completed)
}

struct CaptureReader<'a, R> {
    inner: R,
    raw: &'a RefCell<Option<ScanArchiveBuffer>>,
    error: Option<io::Error>,
}

impl<R: Read> Read for CaptureReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = self.inner.read(buffer).and_then(|size| {
            if let Some(raw) = self.raw.borrow_mut().as_mut() {
                raw.write_all(&buffer[..size])?;
            }
            Ok(size)
        });
        if let Err(error) = &result
            && error.kind() != io::ErrorKind::Interrupted
        {
            // The TAR parser treats errors as a truncated archive; a decoder
            // error must still trigger the original compressed-file fallback.
            self.error = Some(io::Error::new(error.kind(), error.to_string()));
        }
        result
    }
}

enum TarMemberData {
    Bytes(Vec<u8>),
    Spilled { offset: u64, len: usize },
}

#[derive(Debug)]
enum TarMemberError {
    Read(io::Error),
    Spill(io::Error),
}

fn copy_tar_member(
    reader: &mut impl Read,
    writer: &mut impl Write,
    mut remaining: usize,
) -> Result<(), TarMemberError> {
    let mut buffer = [0; 32 * 1024];
    while remaining != 0 {
        let len = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..len]).map_err(TarMemberError::Read)?;
        writer.write_all(&buffer[..len]).map_err(TarMemberError::Spill)?;
        remaining -= len;
    }
    Ok(())
}

fn scan_members(
    reader: impl Read,
    path: &Path,
    resources: ResourceLimits,
    raw: &RefCell<Option<ScanArchiveBuffer>>,
) -> Result<Option<ScanArchive>> {
    let mut archive = Archive::new(reader);
    let mut members = Vec::new();
    let mut retained_memory = 0usize;
    let mut spill = None;
    let mut spill_len = 0u64;
    let mut total = 0u64;
    let mut truncated = false;

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            tracing::debug!(path = %path.display(), %error, "Failed to open TAR archive");
            return Ok(Some(ScanArchive::Original));
        }
    };
    for (index, entry) in entries.enumerate() {
        if resources.reached(index, MAX_TAR_ARCHIVE_ENTRIES) {
            truncated = true;
            break;
        }
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "TAR archive ended early");
                truncated = true;
                break;
            }
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = match entry.path() {
            Ok(name) => name.to_string_lossy().into_owned(),
            Err(error) => {
                tracing::debug!(path = %path.display(), %error, "Failed to read TAR member name");
                truncated = true;
                break;
            }
        };
        let member_path = Path::new(&name);
        if !is_safe_extract_path(member_path) {
            tracing::debug!(path = %path.display(), member = %name, "Skipping unsafe TAR member path");
            continue;
        }
        if !can_be_file_path(member_path)
            || name.strip_suffix('.').unwrap_or(&name).ends_with(std::path::is_separator)
        {
            return Ok(None);
        }

        let size = entry.size();
        if resources.exceeds(size, MAX_TAR_ENTRY_DECOMPRESSED_BYTES) {
            truncated = true;
            continue;
        }
        if resources.exceeds(size, MAX_TAR_DECOMPRESSED_BYTES.saturating_sub(total)) {
            truncated = true;
            break;
        }

        // Stop retaining the raw stream once a member is eligible. On an
        // incomplete first member, retry through the existing extractor to
        // preserve raw fallback without spooling successful TARs.
        let released_raw = raw.borrow_mut().take().is_some();
        let memory = MAX_RETAINED_MEMORY.saturating_sub(retained_memory).min(MAX_MEMBER_MEMORY);
        let len = usize::try_from(size).context("TAR member is too large to address")?;
        let result = if len <= memory {
            let mut bytes = vec![0; len];
            entry
                .read_exact(&mut bytes)
                .map(|()| TarMemberData::Bytes(bytes))
                .map_err(TarMemberError::Read)
        } else {
            let file = match &mut spill {
                Some(file) => file,
                None => spill.insert(tempfile::tempfile().context("Failed to create TAR spill")?),
            };
            copy_tar_member(&mut entry, file, len)
                .map(|()| TarMemberData::Spilled { offset: spill_len, len })
        };
        let data = match result {
            Ok(data) => data,
            Err(TarMemberError::Spill(error)) => {
                return Err(error).with_context(|| format!("Failed to spill TAR member {name}"));
            }
            Err(TarMemberError::Read(error)) => {
                tracing::debug!(path = %path.display(), member = %name, %error, "Failed to read TAR member");
                if released_raw {
                    return Ok(None);
                }
                truncated = true;
                break;
            }
        };
        match &data {
            TarMemberData::Bytes(bytes) => retained_memory += bytes.capacity(),
            TarMemberData::Spilled { .. } => spill_len += size,
        }
        members.push((format!("{}!{name}", path.display()), data));
        total = total.saturating_add(size);
    }

    if truncated && members.is_empty() {
        return Ok(Some(ScanArchive::Original));
    }
    let members = members.into_iter().filter_map(move |(name, data)| {
        let data = match data {
            TarMemberData::Bytes(bytes) => ScanArchiveData::Bytes(bytes),
            TarMemberData::Spilled { offset, len } => {
                let file = spill.as_mut().expect("spilled TAR members share a temporary file");
                // The private spool is never modified after parsing. Every
                // range refers to a complete write and can be mapped on demand.
                let mapped =
                    unsafe { memmap2::MmapOptions::new().offset(offset).len(len).map(&*file) };
                match mapped {
                    Ok(mapped) => ScanArchiveData::Mapped(mapped),
                    Err(error) => {
                        tracing::debug!(member = %name, %error, "Failed to map spilled TAR member");
                        let mut bytes = vec![0; len];
                        if let Err(error) = file.seek(SeekFrom::Start(offset)).and_then(|_| file.read_exact(&mut bytes)) {
                            tracing::debug!(member = %name, %error, "Failed to read spilled TAR member");
                            return None;
                        }
                        ScanArchiveData::Bytes(bytes)
                    }
                }
            }
        };
        Some(ScanArchiveMember { name, data })
    });
    Ok(Some(ScanArchive::Members(Box::new(members))))
}

#[cfg(test)]
mod tests {
    use std::{
        io::{self, Cursor, Write},
        path::Path,
    };

    use flate2::{Compression, write::GzEncoder};

    use super::{
        MAX_MEMBER_MEMORY, MAX_RETAINED_MEMORY, ScanArchive, ScanArchiveData, TarMemberError,
        copy_tar_member, scan_tar,
    };

    fn archive_bytes() -> anyhow::Result<Vec<u8>> {
        let mut archive = tar::Builder::new(Vec::new());
        for bytes in [b"first".as_slice(), b"second".as_slice()] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            archive.append_data(&mut header, "nested/entry.txt", bytes)?;
        }
        Ok(archive.into_inner()?)
    }

    fn gzip(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes)?;
        Ok(encoder.finish()?)
    }

    #[test]
    fn scans_repeated_tar_members_as_distinct_occurrences() -> anyhow::Result<()> {
        let archive = archive_bytes()?;
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut Cursor::new(&archive), &mut xz)?;
        for (label, bytes) in
            [("input.tgz", gzip(&archive)?), ("input.tar.xz", xz), ("input.tar", archive)]
        {
            let mut file = tempfile::tempfile()?;
            file.write_all(&bytes)?;
            let Some(ScanArchive::Members(members)) =
                scan_tar(&mut file, Path::new(label), Default::default())?
            else {
                panic!("expected TAR members");
            };
            let members: Vec<_> = members.collect();
            assert_eq!(members.len(), 2);
            for (member, expected) in
                members.iter().zip([b"first".as_slice(), b"second".as_slice()])
            {
                assert_eq!(member.name, format!("{label}!nested/entry.txt"));
                let ScanArchiveData::Bytes(bytes) = &member.data else {
                    panic!("small TAR member should stay in memory");
                };
                assert_eq!(bytes, expected);
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_tar_header_preserves_the_raw_decoded_byte_stream() -> anyhow::Result<()> {
        let malformed = b"an incomplete TAR header";
        let mut file = tempfile::tempfile()?;
        file.write_all(&gzip(malformed)?)?;
        let Some(ScanArchive::Raw(ScanArchiveData::Bytes(raw))) =
            scan_tar(&mut file, Path::new("input.tgz"), Default::default())?
        else {
            panic!("expected exact raw fallback for malformed TAR");
        };
        assert_eq!(raw, malformed);
        Ok(())
    }

    #[test]
    fn shared_spill_yields_more_than_32_members_with_exact_contents() -> anyhow::Result<()> {
        let mut encoder = GzEncoder::new(tempfile::tempfile()?, Compression::fast());
        let mut archive = tar::Builder::new(&mut encoder);
        let large = vec![b'a'; MAX_MEMBER_MEMORY];
        let in_memory = MAX_RETAINED_MEMORY / MAX_MEMBER_MEMORY;
        for index in 0..in_memory + 1 {
            let mut header = tar::Header::new_gnu();
            header.set_size(large.len() as u64);
            archive.append_data(&mut header, format!("large-{index}.txt"), large.as_slice())?;
        }
        for index in 0..40 {
            let mut header = tar::Header::new_gnu();
            let contents = [index as u8, b'!', b'\n'];
            header.set_size(contents.len() as u64);
            archive.append_data(&mut header, format!("small-{index}.txt"), contents.as_slice())?;
        }
        archive.finish()?;
        drop(archive);

        let mut file = encoder.finish()?;
        let Some(ScanArchive::Members(members)) =
            scan_tar(&mut file, Path::new("spilled.tgz"), Default::default())?
        else {
            panic!("expected streaming TAR extraction to handle the whole archive");
        };
        let members: Vec<_> = members.collect();
        assert_eq!(members.len(), in_memory + 1 + 40);
        let ScanArchiveData::Mapped(mapped) = &members[in_memory].data else {
            panic!("expected a spilled large member");
        };
        assert_eq!(mapped[..], large);
        for (index, member) in members[in_memory + 1..].iter().enumerate() {
            assert_eq!(member.name, format!("spilled.tgz!small-{index}.txt"));
            let ScanArchiveData::Mapped(mapped) = &member.data else {
                panic!("expected a spilled small member");
            };
            assert_eq!(mapped[..], [index as u8, b'!', b'\n']);
        }
        Ok(())
    }

    #[test]
    fn distinguishes_tar_spill_errors_from_incomplete_input() {
        struct FailedSpill;

        impl Write for FailedSpill {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::StorageFull, "spill write failed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        assert!(matches!(
            copy_tar_member(&mut &b"tar"[..], &mut FailedSpill, 3),
            Err(TarMemberError::Spill(error)) if error.kind() == io::ErrorKind::StorageFull
        ));
        assert!(matches!(
            copy_tar_member(&mut &b"ta"[..], &mut FailedSpill, 3),
            Err(TarMemberError::Read(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn invalid_gzip_trailer_discards_completed_tar_members() -> anyhow::Result<()> {
        let mut compressed = gzip(&archive_bytes()?)?;
        let checksum = compressed.len() - 8;
        compressed[checksum] ^= 1;
        let mut file = tempfile::tempfile()?;
        file.write_all(&compressed)?;
        assert!(scan_tar(&mut file, Path::new("input.tgz"), Default::default()).is_err());
        Ok(())
    }
}
