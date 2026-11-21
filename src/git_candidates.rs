//! A conservative, path-independent gate for full-history Git metadata collection.
//!
//! A negative result must be safe before paths, context, and component resolution are
//! available. Positives always go through the ordinary extraction and matching pipeline.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};

use anyhow::Result;
use kingfisher_rules::scanner_pool::ScannerPool as RulesScannerPool;
use kingfisher_scanner::primitives::has_ascii_base64_candidate;
use parking_lot::Mutex;

use crate::{
    decompress::looks_like_zip,
    limits::ResourceLimits,
    matcher::{CHUNK_OVERLAP, MAX_CHUNK_SIZE},
    scanner_pool::ScannerPool,
};
const BASE64_SCAN_LIMIT: usize = 64 * 1024 * 1024;
const MAX_RETAINED_BLOB_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GitContentCandidate {
    Clean,
    NeedsScan,
    // The raw native scan completed with no candidates. Base64 still needs scanning.
    Base64Only,
}

pub(crate) struct RetainedGitBlob {
    data: Vec<u8>,
    native_negative: bool,
    retained_bytes: Arc<AtomicUsize>,
    reserved: usize,
}

impl RetainedGitBlob {
    fn reservation_size(len: usize) -> usize {
        // Budget the payload plus the entry's allocation and temporary OID storage.
        const ENTRY_OVERHEAD: usize = 3 * size_of::<(gix::ObjectId, Arc<RetainedGitBlob>)>()
            + size_of::<RetainedGitBlob>()
            + 2 * size_of::<usize>();
        len.saturating_add(ENTRY_OVERHEAD)
    }

    fn reserve(
        len: usize,
        native_negative: bool,
        retained_bytes: &Arc<AtomicUsize>,
        limit: usize,
    ) -> Option<Self> {
        let reserved = Self::reservation_size(len);
        retained_bytes
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(reserved).filter(|&total| total <= limit)
            })
            .ok()?;
        Some(Self {
            data: Vec::new(),
            native_negative,
            retained_bytes: Arc::clone(retained_bytes),
            reserved,
        })
    }

    fn copy_payload(mut self, data: &[u8]) -> Arc<Self> {
        // Keep the worker's scratch allocation for subsequent delta decoding.
        self.data = data.to_vec();
        Arc::new(self)
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn native_negative(&self) -> bool {
        self.native_negative
    }

    pub(crate) fn into_data(blob: Arc<Self>) -> Option<(Vec<u8>, bool)> {
        // Ordinarily the final loader owns the only reference. If the metadata
        // was cloned, fall back to the object database and discard the proof.
        Arc::into_inner(blob).map(|mut blob| (std::mem::take(&mut blob.data), blob.native_negative))
    }
}

impl Drop for RetainedGitBlob {
    fn drop(&mut self) {
        drop(std::mem::take(&mut self.data));
        self.retained_bytes.fetch_sub(self.reserved, Ordering::Relaxed);
    }
}

pub(crate) struct GitBlobHandoff<'a> {
    retained_bytes: &'a Arc<AtomicUsize>,
    limit: usize,
    entries: Mutex<BTreeMap<(u8, usize), Arc<RetainedGitBlob>>>,
}

impl GitBlobHandoff<'_> {
    pub(crate) fn offer(
        &self,
        index: usize,
        delta_band: u8,
        data: &[u8],
        candidate: GitContentCandidate,
    ) {
        if RetainedGitBlob::reservation_size(data.len()) > self.limit {
            return;
        }
        let reservation = {
            let mut entries = self.entries.lock();
            loop {
                if let Some(reservation) = RetainedGitBlob::reserve(
                    data.len(),
                    candidate == GitContentCandidate::Base64Only,
                    self.retained_bytes,
                    self.limit,
                ) {
                    break reservation;
                }
                // Other repositories share the byte budget, but only this repository's
                // entries are eligible for replacement. A missed handoff still gets read.
                let Some(entry) = entries.first_entry() else { return };
                if entry.key().0 >= delta_band {
                    return;
                }
                drop(entry.remove());
            }
        };
        // The budget includes this pending entry while the worker copies its payload.
        let retained = reservation.copy_payload(data);
        self.entries.lock().insert((delta_band, index), retained);
    }

    pub(crate) fn into_blobs(
        self,
        ids: &[gix::ObjectId],
    ) -> Vec<(gix::ObjectId, Arc<RetainedGitBlob>)> {
        let mut entries: Vec<_> = self.entries.into_inner().into_iter().collect();
        entries.sort_unstable_by_key(|((_, index), _)| *index);
        entries.into_iter().map(|((_, index), blob)| (ids[index], blob)).collect()
    }
}

type ChunkedPrefilters<'a> = Box<dyn Fn() -> Option<Arc<RulesScannerPool>> + Send + Sync + 'a>;

pub(crate) struct GitContentFilter<'a> {
    scanners: Arc<ScannerPool>,
    chunked_prefilters: Option<ChunkedPrefilters<'a>>,
    num_rules: usize,
    base64: bool,
    archives: bool,
    pdf: bool,
    resources: ResourceLimits,
    max_blob_size: Option<u64>,
    clean_blobs: AtomicU64,
    clean_bytes: AtomicU64,
    // Concurrent repository prepasses in this scan share the same budget.
    retained_bytes: Arc<AtomicUsize>,
}

impl<'a> GitContentFilter<'a> {
    pub(crate) fn new(
        scanners: Arc<ScannerPool>,
        num_rules: usize,
        base64: bool,
        archives: bool,
        resources: ResourceLimits,
    ) -> Self {
        Self {
            scanners,
            chunked_prefilters: None,
            num_rules,
            base64,
            archives,
            pdf: archives,
            resources,
            max_blob_size: None,
            clean_blobs: AtomicU64::new(0),
            clean_bytes: AtomicU64::new(0),
            retained_bytes: Arc::default(),
        }
    }

    pub(crate) fn with_chunked_prefilters(
        mut self,
        scanners: impl Fn() -> Option<Arc<RulesScannerPool>> + Send + Sync + 'a,
    ) -> Self {
        self.chunked_prefilters = Some(Box::new(scanners));
        self
    }

    pub(crate) fn with_max_blob_size(mut self, max_blob_size: Option<u64>) -> Self {
        self.max_blob_size = max_blob_size;
        self
    }

    pub(crate) fn with_archive_depth(mut self, depth: Option<usize>) -> Self {
        // PDF text is a leaf transform even when archive expansion is disabled by depth.
        self.archives &= depth != Some(0);
        self
    }

    pub(crate) fn exceeds_max_blob_size(&self, size: u64) -> bool {
        self.max_blob_size.is_some_and(|limit| size > limit)
    }

    #[cfg(test)]
    pub(crate) fn retain_blob(&self, data: &[u8]) -> Option<Arc<RetainedGitBlob>> {
        Some(
            RetainedGitBlob::reserve(
                data.len(),
                self.classify(data).ok()? == GitContentCandidate::Base64Only,
                &self.retained_bytes,
                MAX_RETAINED_BLOB_BYTES,
            )?
            .copy_payload(data),
        )
    }

    pub(crate) fn blob_handoff(&self) -> GitBlobHandoff<'_> {
        GitBlobHandoff {
            retained_bytes: &self.retained_bytes,
            limit: MAX_RETAINED_BLOB_BYTES,
            entries: Mutex::default(),
        }
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

    #[cfg(test)]
    fn may_match(&self, bytes: &[u8]) -> Result<bool> {
        Ok(self.classify(bytes)? != GitContentCandidate::Clean)
    }

    pub(crate) fn classify(&self, bytes: &[u8]) -> Result<GitContentCandidate> {
        use GitContentCandidate::{Base64Only, Clean, NeedsScan};
        // Blob normalizes UTF-16/32 before matching. Retain every possible decoded
        // input, but do not mistake every image containing a NUL for Unicode text.
        if possible_unicode(bytes) {
            return Ok(NeedsScan);
        }
        if (self.archives && possible_archive(bytes))
            || (self.pdf && kingfisher_scanner::extraction::pdf::has_pdf_magic(bytes))
        {
            return Ok(NeedsScan);
        }

        // Exact whole-language gates can miss long matches crossing the chunk overlap.
        // Keep the former broad gates for those inputs, including conservative retention
        // if their auxiliary native database could not be compiled.
        let chunked_prefilters = if bytes.len() > MAX_CHUNK_SIZE
            && let Some(chunked_prefilters) = &self.chunked_prefilters
        {
            let Some(scanners) = chunked_prefilters() else {
                return Ok(NeedsScan);
            };
            Some(scanners)
        } else {
            None
        };

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
                return Ok(NeedsScan);
            }
            if let Some(scanners) = &chunked_prefilters {
                scanners.try_with(|scanner| {
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
                    return Ok(NeedsScan);
                }
            }
            if end == bytes.len() {
                break;
            }
            offset = end - CHUNK_OVERLAP;
        }

        if !self.base64
            || self.resources.exceeds(bytes.len(), BASE64_SCAN_LIMIT)
            || !has_ascii_base64_candidate(bytes)
        {
            return Ok(Clean);
        }
        // The final matcher uses the same native database for one segment.
        // Leave segmented matching to the normal path with its own fallback.
        Ok(if bytes.len() <= MAX_CHUNK_SIZE { Base64Only } else { NeedsScan })
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
        || bytes.get(..512).is_some_and(|bytes| {
            let header = tar::Header::from_byte_slice(bytes);
            // A valid octal field contains a digit. Avoid constructing parse errors
            // for ordinary source text, while retaining the parser's full syntax.
            header.as_old().cksum.iter().any(|byte| matches!(byte, b'0'..=b'7'))
                && header.cksum().is_ok()
        })
        // The ASAR reader ignores its nominal magic, but its JSON-length field
        // must fit in the input. Do not require stricter magic than the extractor.
        || bytes.get(12..16).is_some_and(|size| {
            let size = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            size > 0 && size <= bytes.len() - 16
        })
}

#[cfg(test)]
mod tests {
    use kingfisher_vectorscan::{BlockDatabase, Flag, Pattern};

    use super::*;

    fn filter(base64: bool, archives: bool) -> GitContentFilter<'static> {
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
    fn retained_git_blob_budget_releases_on_consume_or_drop() {
        let budget = Arc::new(AtomicUsize::new(0));
        let data = b"synthetic retained Git content";
        let blob =
            RetainedGitBlob::reserve(data.len(), true, &budget, 1024).unwrap().copy_payload(data);
        let limit = budget.load(Ordering::Relaxed);
        assert!(RetainedGitBlob::reserve(data.len(), false, &budget, limit).is_none());

        let shared = Arc::clone(&blob);
        assert!(RetainedGitBlob::into_data(blob).is_none());
        assert_eq!(budget.load(Ordering::Relaxed), limit);
        assert_eq!(RetainedGitBlob::into_data(shared).unwrap(), (data.to_vec(), true));
        assert_eq!(budget.load(Ordering::Relaxed), 0);

        drop(RetainedGitBlob::reserve(data.len(), false, &budget, limit).unwrap());
        assert_eq!(budget.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handoff_prefers_higher_delta_depth_and_restores_object_order() {
        let budget = Arc::new(AtomicUsize::new(0));
        let limit = 2 * RetainedGitBlob::reservation_size(12);
        let handoff = GitBlobHandoff { retained_bytes: &budget, limit, entries: Mutex::default() };
        use GitContentCandidate::{Base64Only, NeedsScan};
        handoff.offer(3, 1, b"first object", NeedsScan);
        handoff.offer(0, 0, b"cheap object", NeedsScan);
        handoff.offer(2, 1, b"third object", NeedsScan);
        handoff.offer(1, 2, b"costly entry", Base64Only);
        handoff.offer(4, 3, &[0; 1024], NeedsScan);
        assert_eq!(budget.load(Ordering::Relaxed), limit);
        let ids = [0, 1, 2, 3, 4].map(|i| gix::ObjectId::Sha1([i; 20]));
        let retained: Vec<_> = handoff
            .into_blobs(&ids)
            .into_iter()
            .map(|(oid, blob)| (oid, RetainedGitBlob::into_data(blob).unwrap()))
            .collect();
        assert_eq!(
            retained,
            [
                (ids[1], (b"costly entry".to_vec(), true)),
                (ids[3], (b"first object".to_vec(), false))
            ]
        );
        assert_eq!(budget.load(Ordering::Relaxed), 0);
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
    fn gate_keeps_pdf_candidates_without_expanding_archive_layers() -> Result<()> {
        let pdf = b"%PDF-1.7 synthetic content without a raw match";
        let zip = b"PK\x03\x04 synthetic content without a raw match";
        let depth_zero = filter(false, true).with_archive_depth(Some(0));
        assert!(depth_zero.may_match(pdf)?);
        assert!(!depth_zero.may_match(zip)?);
        assert!(!filter(false, false).with_archive_depth(Some(0)).may_match(pdf)?);
        Ok(())
    }

    #[test]
    fn base64_gate_is_a_superset_of_the_normal_decoder() {
        use base64::{Engine, engine::general_purpose};

        for engine in [general_purpose::STANDARD, general_purpose::URL_SAFE_NO_PAD] {
            for len in 0..128 {
                let encoded = engine.encode(vec![b'a'; len]);
                for input in [encoded.clone(), format!("value=\"{encoded}\";\n")] {
                    if !crate::matcher::get_base64_strings(input.as_bytes()).is_empty() {
                        assert!(has_ascii_base64_candidate(input.as_bytes()));
                    }
                }
            }
        }
        let bytes = b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4";
        let with_base64 = filter(true, false);
        assert_eq!(with_base64.classify(bytes).unwrap(), GitContentCandidate::Base64Only);
        let mut mixed = bytes.to_vec();
        mixed.extend_from_slice(b"\ncandidate_secret_0123456789abcdef");
        assert_eq!(with_base64.classify(&mixed).unwrap(), GitContentCandidate::NeedsScan);
        assert_eq!(filter(false, false).classify(bytes).unwrap(), GitContentCandidate::Clean);
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
    fn chunked_prefilter_keeps_matches_longer_than_the_segment_overlap() {
        let pattern = b"long_gate_start[ ]+long_gate_end";
        let exact =
            BlockDatabase::new(vec![Pattern::new(pattern.to_vec(), Flag::SINGLEMATCH, Some(0))])
                .unwrap();
        let filter = GitContentFilter::new(
            Arc::new(ScannerPool::new(Arc::new(exact))),
            1,
            false,
            false,
            ResourceLimits::default(),
        );
        let mut bytes = vec![b'.'; MAX_CHUNK_SIZE + 64];
        let start = MAX_CHUNK_SIZE - CHUNK_OVERLAP - 1;
        let prefix = b"long_gate_start";
        let suffix = b"long_gate_end";
        let suffix_start = bytes.len() - suffix.len();
        bytes[start..start + prefix.len()].copy_from_slice(prefix);
        bytes[start + prefix.len()..suffix_start].fill(b' ');
        bytes[suffix_start..].copy_from_slice(suffix);
        assert!(
            regex::bytes::Regex::new(std::str::from_utf8(pattern).unwrap())
                .unwrap()
                .is_match(&bytes)
        );
        // Neither original chunk contains the complete exact-language match.
        assert!(!filter.may_match(&bytes).unwrap());

        // Model a broad necessary-condition gate by its retained literal prefix.
        let broad = BlockDatabase::new(vec![Pattern::new(
            prefix.to_vec(),
            Flag::PREFILTER | Flag::SINGLEMATCH,
            Some(0),
        )])
        .unwrap();
        let broad = Arc::new(RulesScannerPool::new(Arc::new(broad)));
        let filter = filter.with_chunked_prefilters(move || Some(Arc::clone(&broad)));
        assert!(filter.may_match(&bytes).unwrap());
        assert!(!filter.may_match(b"long_gate_start but no valid ending").unwrap());
    }

    #[test]
    fn missing_chunked_prefilters_conservatively_keep_only_large_inputs() {
        let initialized = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let scanner_initialized = Arc::clone(&initialized);
        let filter = filter(false, false).with_chunked_prefilters(move || {
            scanner_initialized.store(true, Ordering::Relaxed);
            None
        });
        assert!(!filter.may_match(b"ordinary text").unwrap());
        assert!(!initialized.load(Ordering::Relaxed));
        assert!(filter.may_match(&vec![b'.'; MAX_CHUNK_SIZE + 1]).unwrap());
        assert!(initialized.load(Ordering::Relaxed));
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
        assert!(!has_ascii_base64_candidate(b"0123456789abcdef0123456789abcdef01234567"));
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
                            assert!(has_ascii_base64_candidate(encoded.as_bytes()));
                        }
                        if encoded.len().is_multiple_of(4) {
                            assert_eq!(
                                has_ascii_base64_candidate(encoded.as_bytes()),
                                payload.is_ascii()
                            );
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
