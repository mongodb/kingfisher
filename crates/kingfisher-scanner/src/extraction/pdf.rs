//! Offline PDF page text extraction, without rendering, OCR, or executing PDF actions.
//!
//! Uses lopdf rather than printpdf's creation/layout stack or pdf_oxide's
//! non-configurable parser budgets. Bound loading AND page/font decompression.
use std::{collections::HashSet, fs::File, io::Read, path::Path};

use anyhow::{Result, bail};
use lopdf::{DecompressError, Document, LoadOptions, Object, ObjectId};

use super::ExtractionLimitExceeded;
use crate::{ScanControl, archive::limits::ResourceLimits};

const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAGES: usize = 10_000;

/// A PDF exceeded the page-work cap. Callers must not silently fall back to raw
/// content when a strict extraction budget is exhausted.
#[derive(Debug, thiserror::Error)]
#[error("PDF extraction exceeds page limit")]
pub struct PdfPageLimitExceeded;

/// Recognize PDF data by its header, independently of the filename extension.
#[must_use]
pub fn has_pdf_magic(data: &[u8]) -> bool {
    data.starts_with(b"%PDF-")
}

/// Extract a file into `(page-N.txt, UTF-8 text)` pairs with CLI resource policy.
/// Empty pages are omitted. Errors never return a partial page set.
pub fn extract_pdf_text_with_limits(
    path: &Path,
    resources: ResourceLimits,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut bytes = Vec::new();
    resources.reader(File::open(path)?, MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    extract_pdf_text_from_bytes_with_limits(&bytes, resources)
}

/// Extract resident PDF bytes under CLI resource policy.
pub fn extract_pdf_text_from_bytes_with_limits(
    data: &[u8],
    resources: ResourceLimits,
) -> Result<Vec<(String, Vec<u8>)>> {
    extract_pdf_text_from_bytes_with_control(data, resources, &ScanControl::default())
}

/// Extract resident PDF bytes with resource policy and cooperative execution control.
/// Unlike the convenience wrapper, this preserves a caller's operation deadline.
pub fn extract_pdf_text_from_bytes_with_control(
    data: &[u8],
    resources: ResourceLimits,
    control: &ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    extract_pdf(data, resources.limit(MAX_BYTES), control, false)
}

/// Extract PDF text with separate input/output byte caps and cooperative control.
///
/// Loading divides `max_bytes` across a conservative count of stream markers,
/// also capped at 32 MiB per stream. Page/font decoding has a separate aggregate
/// `max_bytes` work budget, charging shared streams on each page that uses them.
/// Each page/font stream is also capped at `min(max_bytes, 32 MiB)`;
/// at most 10,000 pages are inspected. The aggregate UTF-8 output is capped at
/// `max_bytes`. Limits fail rather than truncate or return partial pages.
/// Controls are checked before/after parsing and between pages, but cannot
/// preempt an individual lopdf call. Caps are not a total process-memory bound.
/// Encrypted PDFs are rejected; image-only pages produce no text (no OCR).
/// Undecodable streams are skipped, as in lopdf; memory-limit errors still fail
/// the extraction rather than returning an incomplete result as a success.
/// Embedded files, annotations, and text inside Form XObjects are not extracted.
/// Finding offsets refer to each extracted page, not the original PDF bytes.
pub fn extract_pdf_text_from_bytes_with_budget(
    data: &[u8],
    max_bytes: usize,
    control: &ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    extract_pdf(data, Some(max_bytes), control, false)
}

/// Extract with the same budgets as [`extract_pdf_text_from_bytes_with_budget`],
/// but fail on reported page/font stream decoding errors instead of skipping them.
/// No partial page set is returned. Unsupported features such as OCR, embedded
/// files and Form XObjects remain outside the extraction scope in either mode.
/// Some codecs recover malformed data without reporting errors; strict mode is
/// not a guarantee of complete text coverage.
pub fn extract_pdf_text_from_bytes_with_budget_strict(
    data: &[u8],
    max_bytes: usize,
    control: &ScanControl,
) -> Result<Vec<(String, Vec<u8>)>> {
    extract_pdf(data, Some(max_bytes), control, true)
}

fn pdf_error(error: lopdf::Error) -> anyhow::Error {
    if matches!(error, lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. })) {
        ExtractionLimitExceeded::Bytes.into()
    } else {
        // Parser errors can embed PDF content. Do not expose secret-bearing messages.
        anyhow::anyhow!("invalid or unsupported PDF")
    }
}

// lopdf resolves indirect inherited resources, but not inline dictionaries on
// ancestor Pages nodes. Resolve the PDF inheritance once before extraction.
fn inherit_resources(document: &mut Document, page: ObjectId) -> Result<()> {
    let mut node = page;
    let mut visited = std::collections::HashSet::new();
    loop {
        if visited.len() >= 256 || !visited.insert(node) {
            bail!("invalid PDF resource inheritance");
        }
        let dictionary = document.get_dictionary(node).map_err(pdf_error)?;
        if let Ok(resources) = dictionary.get(b"Resources") {
            let resources = resources.clone();
            document.get_dictionary_mut(page).map_err(pdf_error)?.set("Resources", resources);
            return Ok(());
        }
        match dictionary.get(b"Parent").and_then(Object::as_reference) {
            Ok(parent) => node = parent,
            Err(_) => return Ok(()),
        }
    }
}

// Decode streams in place so shared page/font streams are not inflated again
// for every page. Charge their decoded size on every use anyway: repeatedly
// parsing/copying a large shared stream is work even when inflation is cached.
fn prepare_page_streams(
    document: &mut Document,
    page: ObjectId,
    remaining: &mut usize,
    control: &ScanControl,
    strict_streams: bool,
) -> Result<()> {
    let mut streams = document.get_page_contents(page);
    for font in document.get_page_fonts(page).map_err(pdf_error)?.values() {
        if let Ok(object) = font.get(b"ToUnicode")
            && let Ok((Some(id), Object::Stream(_))) = document.dereference(object)
        {
            streams.push(id);
        }
    }
    for id in streams {
        control.check()?;
        let Ok(stream) = document.get_object_mut(id).and_then(Object::as_stream_mut) else {
            continue;
        };
        let limit = (*remaining).min(MAX_STREAM_BYTES);
        if stream.is_compressed()
            && let Err(error) = stream.decompress_with_limit(limit)
        {
            if strict_streams
                || matches!(
                    error,
                    lopdf::Error::Decompress(DecompressError::MemoryLimitExceeded { .. })
                )
            {
                return Err(pdf_error(error));
            }
            // Match lopdf's best-effort handling of undecodable streams. One
            // corrupt/unsupported stream must not discard other pages' text.
            // The text API still applies its own bounded decoding on retry.
            continue;
        }
        if stream.content.len() > limit {
            return Err(ExtractionLimitExceeded::Bytes.into());
        }
        *remaining -= stream.content.len();
    }
    Ok(())
}

fn extract_pdf(
    data: &[u8],
    max_bytes: Option<usize>,
    control: &ScanControl,
    strict_streams: bool,
) -> Result<Vec<(String, Vec<u8>)>> {
    control.check()?;
    if max_bytes.is_some_and(|max| data.len() > max) {
        return Err(ExtractionLimitExceeded::Bytes.into());
    }
    if !has_pdf_magic(data) {
        bail!("invalid PDF header");
    }
    let stream_limit = max_bytes.map(|max| max.min(MAX_STREAM_BYTES));
    // Object streams are decoded eagerly and retained by lopdf. A per-stream
    // cap alone allows an aggregate decompression bomb before page extraction.
    // Every PDF stream needs a literal `stream` keyword, even when /Type uses
    // escaped names (e.g. /Obj#53tm). Count keyword boundaries, not `endstream`.
    // False positives in payloads/comments only tighten the budget. Do not rely
    // on /ObjStm spelling or untrusted /Length or /N values.
    // This bounds aggregate eager stream payloads, not parser/object overhead.
    let loading_limit = max_bytes.map(|max| {
        let streams = data
            .windows(6)
            .enumerate()
            .filter(|(index, word)| {
                *word == b"stream"
                    && (*index == 0
                        || data[*index - 1].is_ascii_whitespace()
                        || b"()<>[]{}/%\0".contains(&data[*index - 1]))
            })
            .count();
        (max / streams.max(1)).min(MAX_STREAM_BYTES)
    });
    let parsed = Document::load_mem_with_options(
        data,
        LoadOptions { strict: true, max_decompressed_size: loading_limit, ..Default::default() },
    );
    control.check()?;
    let mut document = parsed.map_err(pdf_error)?;
    if document.is_encrypted() {
        bail!("encrypted PDFs are not supported");
    }
    // Do not trust the page tree's Count value or allocate from it.
    let mut pages = Vec::new();
    let mut seen = HashSet::new();
    for (index, page) in document.page_iter().enumerate() {
        control.check()?;
        if max_bytes.is_some() && index >= MAX_PAGES {
            return Err(PdfPageLimitExceeded.into());
        }
        if seen.insert(page) {
            pages.push((index + 1, page));
        }
    }
    if pages.is_empty() {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    let mut total = 0usize;
    let mut remaining_work = max_bytes.unwrap_or(usize::MAX);
    // lopdf's text API rebuilds its page-number map on every call. Point a
    // single-page view at just the current page so each lookup is constant
    // work, while preserving original Parent links for resource inheritance.
    // Only the root's Kids/Count change; fonts, streams and ancestors stay put.
    let page_tree = document
        .catalog()
        .and_then(|catalog| catalog.get(b"Pages"))
        .and_then(Object::as_reference)
        .map_err(pdf_error)?;
    document.get_dictionary_mut(page_tree).map_err(pdf_error)?.set("Count", 1);
    for (number, page) in pages {
        control.check()?;
        inherit_resources(&mut document, page)?;
        if max_bytes.is_some() {
            prepare_page_streams(
                &mut document,
                page,
                &mut remaining_work,
                control,
                strict_streams,
            )?;
        }
        document
            .get_dictionary_mut(page_tree)
            .map_err(pdf_error)?
            .set("Kids", vec![Object::Reference(page)]);
        let extracted = match stream_limit {
            Some(limit) => document.extract_text_with_limit(&[1], limit),
            None => document.extract_text(&[1]),
        };
        control.check()?;
        let text = extracted.map_err(pdf_error)?;
        if max_bytes.is_some_and(|max| text.len() > max.saturating_sub(total)) {
            return Err(ExtractionLimitExceeded::Bytes.into());
        }
        total += text.len();
        if !text.trim().is_empty() {
            output.push((format!("page-{number}.txt"), text.into_bytes()));
        }
    }
    control.check()?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CancellationToken, ScanAborted};

    fn fixture() -> Vec<u8> {
        let hex: String = include_str!("testdata/pages.pdf.hex").split_whitespace().collect();
        (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
    }

    fn save(document: &mut Document) -> Vec<u8> {
        let mut bytes = Vec::new();
        document.save_to(&mut bytes).unwrap();
        bytes
    }

    fn extract(bytes: &[u8], max: usize) -> Result<Vec<(String, Vec<u8>)>> {
        extract_pdf_text_from_bytes_with_budget(bytes, max, &ScanControl::default())
    }

    #[test]
    fn pdf_extracts_hex_strings_and_split_tokens_with_inherited_fonts() {
        let bytes = fixture();
        let document = Document::load_mem_with_options(
            &bytes,
            LoadOptions { strict: true, ..Default::default() },
        )
        .unwrap();
        assert_eq!(document.page_iter().count(), 2, "{document:?}");
        assert!(!bytes.windows(5).any(|window| window == b"demo_"));
        let pages = extract(&bytes, MAX_BYTES).unwrap();
        assert_eq!(
            pages,
            vec![
                ("page-1.txt".into(), b"token=demo_abcd1234efgh5678\n".to_vec()),
                ("page-2.txt".into(), b"demo_1234abcd5678efgh \n".to_vec()),
            ]
        );
    }

    #[test]
    fn pdf_large_page_tree_preserves_page_boundaries_and_original_inheritance() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        let mut kids = Vec::new();
        for index in 0..128 {
            let mut page = doc.get_dictionary((3, 0)).unwrap().clone();
            let stream = doc.add_object(lopdf::Stream::new(
                lopdf::Dictionary::new(),
                format!("BT /F1 12 Tf (page {index}) Tj /F1 12 Tf ( tail) Tj ET").into_bytes(),
            ));
            page.set("Contents", stream);
            kids.push(Object::Reference(doc.add_object(page)));
        }
        doc.get_dictionary_mut((2, 0)).unwrap().set("Kids", kids);
        doc.get_dictionary_mut((2, 0)).unwrap().set("Count", 128);
        let pages = extract(&save(&mut doc), MAX_BYTES).unwrap();
        assert_eq!(pages.len(), 128);
        for (index, (name, text)) in pages.iter().enumerate() {
            assert_eq!(name, &format!("page-{}.txt", index + 1));
            assert_eq!(text, format!("page {index} tail\n").as_bytes());
        }
    }

    #[test]
    fn pdf_extracts_compressed_streams_and_file_inputs() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.compress();
        let bytes = save(&mut doc);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("document.pdf");
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(
            extract_pdf_text_with_limits(&path, ResourceLimits::default()).unwrap(),
            extract(&fixture(), MAX_BYTES).unwrap()
        );
    }

    #[test]
    fn pdf_corrupt_streams_do_not_discard_readable_page_text() {
        for replace_page in [false, true] {
            let mut doc = Document::load_mem(&fixture()).unwrap();
            let corrupt = doc.add_object(lopdf::Stream::new(
                // Brotli reports a real decode error. lopdf's Flate decoder can
                // instead recover corruption as an empty successful output.
                lopdf::dictionary! { "Filter" => "BrotliDecode" },
                b"not a brotli stream".to_vec(),
            ));
            doc.get_dictionary_mut((3, 0)).unwrap().set(
                "Contents",
                if replace_page {
                    Object::Reference(corrupt)
                } else {
                    Object::Array(vec![Object::Reference((4, 0)), Object::Reference(corrupt)])
                },
            );
            let mut expected = extract(&fixture(), MAX_BYTES).unwrap();
            if replace_page {
                expected.remove(0);
            }
            let bytes = save(&mut doc);
            assert_eq!(extract(&bytes, MAX_BYTES).unwrap(), expected);
            let error = extract_pdf_text_from_bytes_with_budget_strict(
                &bytes,
                MAX_BYTES,
                &ScanControl::default(),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), "invalid or unsupported PDF");
        }
    }

    #[test]
    fn pdf_input_and_decompressed_page_budgets_are_strict() {
        assert!(
            extract(&fixture(), 16)
                .unwrap_err()
                .downcast_ref::<ExtractionLimitExceeded>()
                .is_some()
        );
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.get_object_mut((4, 0))
            .unwrap()
            .as_stream_mut()
            .unwrap()
            .set_content(format!("BT /F1 12 Tf ({}) Tj ET", "x".repeat(1024 * 1024)).into_bytes());
        doc.compress();
        let bytes = save(&mut doc);
        assert!(bytes.len() < 16 * 1024);
        assert!(
            extract(&bytes, 16 * 1024)
                .unwrap_err()
                .downcast_ref::<ExtractionLimitExceeded>()
                .is_some()
        );
    }

    #[test]
    fn pdf_aggregate_output_budget_does_not_return_partial_pages() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        for id in [(4, 0), (6, 0)] {
            doc.get_object_mut(id)
                .unwrap()
                .as_stream_mut()
                .unwrap()
                .set_content(format!("BT /F1 12 Tf ({}) Tj ET", "x".repeat(800)).into_bytes());
        }
        doc.compress();
        let bytes = save(&mut doc);
        let cap = bytes.len().max(1024);
        assert!(cap < 1600);
        assert!(
            extract(&bytes, cap).unwrap_err().downcast_ref::<ExtractionLimitExceeded>().is_some()
        );
    }

    #[test]
    fn pdf_shared_stream_work_is_bounded_even_when_it_produces_little_text() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.get_object_mut((4, 0))
            .unwrap()
            .as_stream_mut()
            .unwrap()
            .set_content([vec![b' '; 4096], b"BT /F1 12 Tf (small) Tj ET".to_vec()].concat());
        let page = doc.get_dictionary((3, 0)).unwrap().clone();
        let kids: Vec<Object> = (0..32).map(|_| doc.add_object(page.clone()).into()).collect();
        doc.get_dictionary_mut((2, 0)).unwrap().set("Kids", kids);
        doc.get_dictionary_mut((2, 0)).unwrap().set("Count", 32);
        doc.compress();
        let bytes = save(&mut doc);
        assert!(bytes.len() < 16 * 1024);
        assert!(extract(&bytes, 16 * 1024).unwrap_err().is::<ExtractionLimitExceeded>());
    }

    #[test]
    fn pdf_repeated_page_ids_are_extracted_only_once_with_original_page_numbers() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.get_dictionary_mut((2, 0)).unwrap().set(
            "Kids",
            vec![Object::Reference((3, 0)), Object::Reference((3, 0)), Object::Reference((5, 0))],
        );
        doc.get_dictionary_mut((2, 0)).unwrap().set("Count", 3);
        let pages = extract(&save(&mut doc), MAX_BYTES).unwrap();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].0, "page-1.txt");
        assert_eq!(pages[1].0, "page-3.txt");
    }

    #[test]
    fn pdf_malformed_later_page_fails_without_partial_output() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.get_object_mut((6, 0)).unwrap().as_stream_mut().unwrap().set_content(b"Tf".to_vec());
        assert!(extract(&save(&mut doc), MAX_BYTES).is_err());
        let error = extract(b"%PDF-1.4\nsecret-in-malformed-document", MAX_BYTES).unwrap_err();
        assert!(!error.to_string().contains("secret-in-malformed-document"));
    }

    #[test]
    fn pdf_font_cmap_decompression_is_bounded() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        let cmap =
            doc.add_object(lopdf::Stream::new(lopdf::Dictionary::new(), vec![b' '; 1024 * 1024]));
        doc.get_dictionary_mut((7, 0)).unwrap().set("ToUnicode", cmap);
        doc.get_dictionary_mut((7, 0)).unwrap().remove(b"Encoding");
        doc.compress();
        let bytes = save(&mut doc);
        assert!(bytes.len() < 16 * 1024);
        assert!(
            extract(&bytes, 16 * 1024)
                .unwrap_err()
                .downcast_ref::<ExtractionLimitExceeded>()
                .is_some()
        );
    }

    #[test]
    fn pdf_decodes_non_ascii_font_encodings() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.get_object_mut((4, 0))
            .unwrap()
            .as_stream_mut()
            .unwrap()
            .set_content(b"BT /F1 12 Tf <636166e9> Tj ET".to_vec());
        assert_eq!(extract(&save(&mut doc), MAX_BYTES).unwrap()[0].1, "café\n".as_bytes());
    }

    #[test]
    fn pdf_loading_object_stream_decompression_is_bounded() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        let mut stream = lopdf::Stream::new(
            // lopdf's writer discards old ObjStm containers. Use an equal-length
            // placeholder, then restore the type without changing xref offsets.
            lopdf::dictionary! { "Type" => "KFTest", "N" => 1, "First" => 5 },
            [b"9 0 ".as_slice(), &vec![b' '; 1024 * 1024]].concat(),
        );
        stream.compress().unwrap();
        doc.add_object(stream);
        let mut bytes = save(&mut doc);
        let offset = bytes.windows(7).position(|w| w == b"/KFTest").unwrap() + 1;
        bytes[offset..offset + 6].copy_from_slice(b"ObjStm");
        assert!(bytes.len() < 16 * 1024);
        assert!(
            extract(&bytes, 16 * 1024)
                .unwrap_err()
                .downcast_ref::<ExtractionLimitExceeded>()
                .is_some()
        );
    }

    #[test]
    fn pdf_loading_budget_does_not_count_endstream_as_another_stream() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        let mut stream = lopdf::Stream::new(
            lopdf::dictionary! { "Type" => "KFTest", "N" => 1, "First" => 6 },
            format!("100 0 ({})", "x".repeat(4000)).into_bytes(),
        );
        stream.compress().unwrap();
        doc.add_object(stream);
        let mut bytes = save(&mut doc);
        let offset = bytes.windows(7).position(|word| word == b"/KFTest").unwrap() + 1;
        bytes[offset..offset + 6].copy_from_slice(b"ObjStm");
        assert_eq!(extract(&bytes, 16 * 1024).unwrap(), extract(&fixture(), MAX_BYTES).unwrap());
    }

    #[test]
    fn pdf_aggregate_loading_budget_covers_multiple_and_escaped_object_streams() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        for index in 0..8 {
            let header = format!("{} 0 ", 100 + index);
            let mut stream = lopdf::Stream::new(
                // Equal-length placeholder keeps the saved xref offsets valid.
                lopdf::dictionary! { "Type" => "KFTester", "N" => 1, "First" => header.len() as i64 },
                format!("{header}({})", "x".repeat(4000)).into_bytes(),
            );
            stream.compress().unwrap();
            doc.add_object(stream);
        }
        let mut bytes = save(&mut doc);
        while let Some(offset) = bytes.windows(9).position(|w| w == b"/KFTester") {
            bytes[offset + 1..offset + 9].copy_from_slice(b"Obj#53tm");
        }
        let cap = 16 * 1024;
        assert!(bytes.len() < cap);
        // Every stream fits the old individual cap, but not the aggregate budget.
        Document::load_mem_with_options(
            &bytes,
            LoadOptions { strict: true, max_decompressed_size: Some(cap), ..Default::default() },
        )
        .unwrap();
        assert!(
            extract(&bytes, cap).unwrap_err().downcast_ref::<ExtractionLimitExceeded>().is_some()
        );
    }

    #[test]
    fn pdf_missing_or_direct_page_tree_remains_an_empty_extraction() {
        for pages in [None, Some(Object::Dictionary(lopdf::Dictionary::new()))] {
            let mut doc = Document::load_mem(&fixture()).unwrap();
            let catalog = doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
            let catalog = doc.get_dictionary_mut(catalog).unwrap();
            catalog.remove(b"Pages");
            if let Some(pages) = pages {
                catalog.set("Pages", pages);
            }
            assert!(extract(&save(&mut doc), MAX_BYTES).unwrap().is_empty());
        }
    }

    #[test]
    fn pdf_encrypted_documents_fail_without_partial_text() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        doc.trailer.set(
            "ID",
            vec![Object::string_literal("fixture-id"), Object::string_literal("fixture-id")],
        );
        let state = lopdf::EncryptionState::try_from(lopdf::EncryptionVersion::V1 {
            document: &doc,
            owner_password: "fixture-owner",
            user_password: "fixture-user",
            permissions: lopdf::Permissions::all(),
        })
        .unwrap();
        doc.encrypt(&state).unwrap();
        assert!(extract(&save(&mut doc), MAX_BYTES).is_err());
    }

    #[test]
    fn pdf_page_limit_is_checked_before_returning_any_text() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        let page = doc.get_dictionary((3, 0)).unwrap().clone();
        let kids: Vec<Object> =
            (0..=MAX_PAGES).map(|_| doc.add_object(page.clone()).into()).collect();
        doc.get_dictionary_mut((2, 0)).unwrap().set("Kids", kids);
        doc.get_dictionary_mut((2, 0)).unwrap().set("Count", (MAX_PAGES + 1) as i64);
        let error = extract(&save(&mut doc), MAX_BYTES).unwrap_err();
        assert!(matches!(error.downcast_ref::<PdfPageLimitExceeded>(), Some(PdfPageLimitExceeded)));
    }

    #[test]
    fn pdf_cancellation_between_pages_does_not_return_partial_output() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let checks = Arc::new(AtomicUsize::new(0));
        let control = ScanControl::default().with_check_observer(move |_| {
            if checks.fetch_add(1, Ordering::Relaxed) == 6 {
                Err(ScanAborted::Cancelled)
            } else {
                Ok(())
            }
        });
        let error =
            extract_pdf_text_from_bytes_with_budget(&fixture(), MAX_BYTES, &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::Cancelled));
    }

    #[test]
    fn pdf_empty_pages_have_no_text_and_controls_propagate() {
        let mut doc = Document::load_mem(&fixture()).unwrap();
        for id in [(4, 0), (6, 0)] {
            doc.get_object_mut(id).unwrap().as_stream_mut().unwrap().set_content(Vec::new());
        }
        assert!(extract(&save(&mut doc), MAX_BYTES).unwrap().is_empty());
        let token = CancellationToken::default();
        token.cancel();
        let control = ScanControl::default().with_cancellation(token);
        let error =
            extract_pdf_text_from_bytes_with_budget(&fixture(), MAX_BYTES, &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::Cancelled));
        let control = ScanControl::default().with_deadline(std::time::Instant::now());
        let error =
            extract_pdf_text_from_bytes_with_budget(&fixture(), MAX_BYTES, &control).unwrap_err();
        assert_eq!(error.downcast_ref::<ScanAborted>(), Some(&ScanAborted::TimedOut));
    }
}
