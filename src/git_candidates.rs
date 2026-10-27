//! A conservative, path-independent gate for full-history Git metadata collection.
//!
//! A negative result must be safe before paths, context, and component resolution are
//! available. Positives always go through the ordinary extraction and matching pipeline.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::Result;
use kingfisher_scanner::primitives::is_base64_byte;

use crate::{
    decompress::looks_like_zip,
    limits::ResourceLimits,
    matcher::{CHUNK_OVERLAP, MAX_CHUNK_SIZE},
    scanner_pool::ScannerPool,
};
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024;

pub(crate) struct GitContentFilter {
    scanners: Arc<ScannerPool>,
    num_rules: usize,
    base64: bool,
    archives: bool,
    resources: ResourceLimits,
    max_blob_size: Option<u64>,
    clean_blobs: AtomicU64,
    clean_bytes: AtomicU64,
}

impl GitContentFilter {
    pub(crate) fn new(
        scanners: Arc<ScannerPool>,
        num_rules: usize,
        base64: bool,
        archives: bool,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            scanners,
            num_rules,
            base64,
            archives,
            resources,
            max_blob_size: None,
            clean_blobs: AtomicU64::new(0),
            clean_bytes: AtomicU64::new(0),
        }
    }

    pub(crate) fn with_max_blob_size(mut self, max_blob_size: Option<u64>) -> Self {
        self.max_blob_size = max_blob_size;
        self
    }

    pub(crate) fn exceeds_max_blob_size(&self, size: u64) -> bool {
        self.max_blob_size.is_some_and(|limit| size > limit)
    }

    pub(crate) fn record_clean(&self, blobs: u64, bytes: u64) {
        self.clean_blobs.fetch_add(blobs, Ordering::Relaxed);
        self.clean_bytes.fetch_add(bytes, Ordering::Relaxed);
        crate::scan_progress::scanned(bytes);
    }

    pub(crate) fn clean_stats(&self) -> crate::matcher::MatcherStats {
        let blobs = self.clean_blobs.load(Ordering::Relaxed);
        let bytes = self.clean_bytes.load(Ordering::Relaxed);
        crate::matcher::MatcherStats {
            blobs_seen: blobs,
            blobs_scanned: blobs,
            bytes_seen: bytes,
            bytes_scanned: bytes,
        }
    }

    pub(crate) fn may_match(&self, bytes: &[u8]) -> Result<bool> {
        // Blob normalizes UTF-16/32 before matching. Retain every possible decoded
        // input, but do not mistake every image containing a NUL for Unicode text.
        if possible_unicode(bytes) {
            return Ok(true);
        }
        if self.archives
            && (possible_archive(bytes)
                || kingfisher_scanner::extraction::pdf::has_pdf_magic(bytes))
        {
            return Ok(true);
        }

        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + MAX_CHUNK_SIZE).min(bytes.len());
            let mut found = false;
            self.scanners.try_with(|scanner| {
                scanner.scan(&bytes[offset..end], |rule, _, _, _| {
                    if (rule as usize) < self.num_rules {
                        found = true;
                        kingfisher_vectorscan::Scan::Terminate
                    } else {
                        kingfisher_vectorscan::Scan::Continue
                    }
                })
            })??;
            if found {
                return Ok(true);
            }
            if end == bytes.len() {
                break;
            }
            offset = end - CHUNK_OVERLAP;
        }

        Ok(self.base64
            && !self.resources.exceeds(bytes.len(), BASE64_SCAN_LIMIT)
            && possible_base64(bytes))
    }
}

fn possible_unicode(bytes: &[u8]) -> bool {
    if bytes.starts_with(&[0xff, 0xfe])
        || bytes.starts_with(&[0xfe, 0xff])
        || bytes.starts_with(&[0, 0, 0xfe, 0xff])
    {
        return true;
    }
    if bytes.len() < 8 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    // Any BOM-less UTF-16 guess needs >=60% zeros in one of two equal byte lanes;
    // UTF-32 needs even more. Thus >=30% zeros overall is a necessary condition.
    // Use memchr's SIMD count rather than enumerating individual padding bytes.
    let units = bytes.len() / 2;
    let required = units / 5 * 3 + (units % 5 * 3).div_ceil(5);
    memchr::memchr_iter(0, bytes).count() >= required
}

fn possible_archive(bytes: &[u8]) -> bool {
    // Retain supported extractable formats, not arbitrary binary media assets.
    // Keep this gate in sync with extract_archive_bytes and the archive decompressors.
    // Consult the TAR parser for its checksum-field syntax, including legacy
    // headers, rather than requiring a ustar signature or duplicating its parser.
    looks_like_zip(bytes)
        || bytes.starts_with(&[0x1f, 0x8b])
        || bytes.starts_with(b"BZh")
        || bytes.starts_with(b"\xfd7zXZ\0")
        || bytes.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        || bytes.get(..2).is_some_and(|header| {
            header[0] & 0x0f == 8
                && header[0] >> 4 <= 7
                && u16::from_be_bytes([header[0], header[1]]).is_multiple_of(31)
        })
        || bytes
            .get(..512)
            .is_some_and(|header| tar::Header::from_byte_slice(header).cksum().is_ok())
        // The ASAR reader ignores its nominal magic, but its JSON-length field
        // must fit in the input. Do not require stricter magic than the extractor.
        || bytes.get(12..16).is_some_and(|size| {
            let size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            size > 0 && size <= bytes.len() - 16
        })
}

fn possible_base64(bytes: &[u8]) -> bool {
    // Match the decoder's standalone-run boundaries, minimum length, padding and
    // divisibility requirements, but do not allocate decoded buffers here.
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !is_base64_byte(bytes[i]) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_base64_byte(bytes[i]) {
            i += 1;
        }
        for _ in 0..2 {
            if bytes.get(i) == Some(&b'=') {
                i += 1;
            } else {
                break;
            }
        }
        let len = i - start;
        if len >= 32 && len.is_multiple_of(4) && decodes_to_ascii(&bytes[start..i]) {
            return true;
        }
    }
    false
}

fn base64_sextet(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => 0,
    }
}

fn decodes_to_ascii(bytes: &[u8]) -> bool {
    // The ordinary Base64 decoder only retains ASCII decoded content. Check the
    // high bit of each decoded byte directly, without allocating decoded buffers.
    // Runs already consist of full quartets with at most two trailing '=' bytes.
    // Invalid trailing bits/mixed alphabets can remain conservative positives.
    bytes.as_chunks::<4>().0.iter().all(|quartet| {
        base64_sextet(quartet[0]) < 32
            && (quartet[2] == b'=' || base64_sextet(quartet[1]) & 8 == 0)
            && (quartet[3] == b'=' || base64_sextet(quartet[2]) & 2 == 0)
    })
}

#[cfg(test)]
mod tests {
    use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};

    use super::*;

    fn filter(base64: bool, archives: bool) -> GitContentFilter {
        let db = BlockDatabase::new(vec![Pattern::new(
            b"candidate_secret_[a-z0-9]{16}".to_vec(),
            Flag::default(),
            Some(0),
        )])
        .unwrap();
        GitContentFilter::new(
            Arc::new(ScannerPool::new(Arc::new(db))),
            1,
            base64,
            archives,
            ResourceLimits::default(),
        )
    }

    #[test]
    fn gate_keeps_raw_matches_without_path_or_context_filters() {
        let filter = filter(false, false);
        assert!(filter.may_match(b"candidate_secret_0123456789abcdef").unwrap());
        assert!(!filter.may_match(b"ordinary source text without a matching token").unwrap());
    }

    #[test]
    fn gate_keeps_encoding_and_archive_candidates() {
        let filter = filter(false, true);
        for input in [
            &b"\xff\xfeAA"[..],
            &b"a\0b\0c\0d\0"[..],
            &b"PK\x03\x04 possible ZIP"[..],
            &b"BZh compressed content"[..],
            &b"x^possible zlib content"[..],
            &b"\x1f\x8b compressed content"[..],
        ] {
            assert!(filter.may_match(input).unwrap());
        }
        let mut legacy_tar = vec![b' '; 512];
        legacy_tar[148..156].copy_from_slice(b"0001234 ");
        assert!(filter.may_match(&legacy_tar).unwrap());
    }

    #[test]
    fn base64_gate_is_a_superset_of_the_normal_decoder() {
        use base64::{Engine, engine::general_purpose};

        for engine in [general_purpose::STANDARD, general_purpose::URL_SAFE_NO_PAD] {
            for len in 0..128 {
                let encoded = engine.encode(vec![b'a'; len]);
                for input in [encoded.clone(), format!("value=\"{encoded}\";\n")] {
                    if !crate::matcher::get_base64_strings(input.as_bytes()).is_empty() {
                        assert!(possible_base64(input.as_bytes()));
                    }
                }
            }
        }
        let bytes = b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4";
        assert!(filter(true, false).may_match(bytes).unwrap());
        assert!(!filter(false, false).may_match(bytes).unwrap());
    }

    #[test]
    fn gate_matches_across_normal_scan_segment_boundaries() {
        let mut bytes = vec![b' '; MAX_CHUNK_SIZE + 100];
        let secret = b"candidate_secret_0123456789abcdef";
        let start = MAX_CHUNK_SIZE - 10;
        bytes[start..start + secret.len()].copy_from_slice(secret);
        assert!(filter(false, false).may_match(&bytes).unwrap());
    }

    #[test]
    fn unicode_gate_covers_normal_blob_decoding_including_sparse_bom_padding() {
        use crate::blob::{Blob, BlobId};

        let mut inputs = Vec::new();
        for text in [
            "candidate_secret_0123456789abcdef".to_string(),
            format!("{}candidate_secret_0123456789abcdef", "\u{10400}".repeat(100)),
            format!("{}candidate_secret_0123456789abcdef", "\u{4141}".repeat(100)),
        ] {
            for bom in [false, true] {
                for little_endian in [false, true] {
                    inputs.push(
                        bom.then_some(0xfeff)
                            .into_iter()
                            .chain(text.encode_utf16())
                            .flat_map(|unit| {
                                if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() }
                            })
                            .collect::<Vec<_>>(),
                    );
                    inputs.push(
                        bom.then_some(0xfeff)
                            .into_iter()
                            .chain(text.chars().map(u32::from))
                            .flat_map(|unit| {
                                if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() }
                            })
                            .collect::<Vec<_>>(),
                    );
                }
            }
        }
        // Exercise the normal decoder's integer rounding at short lane lengths.
        for len in [8, 10, 12] {
            for mask in 0..1 << len {
                inputs.push(
                    (0..len).map(|bit| if mask & (1 << bit) == 0 { b'A' } else { 0 }).collect(),
                );
            }
        }
        for bytes in inputs {
            let normalized = Blob::new(BlobId::default(), bytes.clone());
            if normalized.bytes() != bytes.as_slice() {
                assert!(possible_unicode(&bytes));
            }
        }
    }

    #[test]
    fn gate_rejects_nonmatching_binary_media_and_non_ascii_base64() {
        let filter = filter(true, true);
        let mut jpeg = vec![0x80; 1024];
        jpeg[..4].copy_from_slice(b"\xff\xd8\xff\xe0");
        jpeg[100] = 0;
        assert!(!filter.may_match(&jpeg).unwrap());
        jpeg.extend_from_slice(b"candidate_secret_0123456789abcdef");
        assert!(filter.may_match(&jpeg).unwrap());
        assert!(!possible_base64(b"0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn base64_ascii_gate_matches_decoded_high_bits_without_allocating() {
        use base64::{Engine, engine::general_purpose};

        for engine in [general_purpose::STANDARD, general_purpose::URL_SAFE_NO_PAD] {
            for first in 0..=255_u8 {
                for second in [0, 31, 63, 127, 128, 255] {
                    for len in [31, 32, 33] {
                        let mut payload = vec![b'a'; len];
                        payload[0] = first;
                        payload[1] = second;
                        let encoded = engine.encode(&payload);
                        let normal = crate::matcher::get_base64_strings(encoded.as_bytes());
                        if !normal.is_empty() {
                            assert!(possible_base64(encoded.as_bytes()));
                        }
                        if encoded.len().is_multiple_of(4) {
                            assert_eq!(possible_base64(encoded.as_bytes()), payload.is_ascii());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn asar_gate_does_not_assume_the_reader_validates_magic() {
        // The reader ignores the first three u32 fields and reads a JSON-length
        // field at offset 12. A permissive prepass must retain this layout too.
        let mut bytes = vec![0x80; 16];
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes.extend_from_slice(b"{}");
        assert!(possible_archive(&bytes));
    }

    #[test]
    fn archive_gate_keeps_generated_extractable_formats() -> Result<()> {
        use std::io::{Cursor, Write};

        use flate2::{
            Compression,
            write::{GzEncoder, ZlibEncoder},
        };

        let secret = b"candidate_secret_0123456789abcdef";
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(secret)?;
        let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib.write_all(secret)?;
        let mut xz = Vec::new();
        lzma_rs::xz_compress(&mut &secret[..], &mut xz)?;
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        zip.start_file("secret.txt", zip::write::SimpleFileOptions::default())?;
        zip.write_all(secret)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(secret.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        let mut tar = tar::Builder::new(Vec::new());
        tar.append_data(&mut header, "secret.txt", &secret[..])?;
        let filter = filter(false, true);
        for archive in
            [gzip.finish()?, zlib.finish()?, xz, zip.finish()?.into_inner(), tar.into_inner()?]
        {
            assert!(possible_archive(&archive));
            assert!(filter.may_match(&archive)?);
        }
        Ok(())
    }
}
