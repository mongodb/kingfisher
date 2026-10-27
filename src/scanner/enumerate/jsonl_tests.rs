//! JSONL enumeration compatibility before inherited helper replacement.

use std::path::Path;

use anyhow::Result;
use rayon::iter::ParallelIterator;
use serde_json::json;

use super::{Content, EnumeratorFileResult, LoadedBlob, Origin, ParallelBlobIterator};

fn enumerate(path: &Path) -> Vec<Result<LoadedBlob<'static>>> {
    EnumeratorFileResult { path: path.to_owned() }.into_blob_iter().unwrap().unwrap().collect()
}

#[test]
fn content_adapters_preserve_utf8_base64_binary_and_empty_values() {
    for (value, expected) in [
        (json!({"content": "café\n\u{0000}"}), "café\n\0".as_bytes().to_vec()),
        (json!({"content": ""}), Vec::new()),
        (json!({"content_base64": "/wBh"}), vec![0xff, 0, b'a']),
        (json!({"content_base64": ""}), Vec::new()),
    ] {
        let content: Content = serde_json::from_value(value).unwrap();
        assert_eq!(content.as_bytes(), expected);
    }
    for value in [
        json!({"content": null}),
        json!({"content": 7}),
        json!({"content_base64": null}),
        json!({"content_base64": [1, 2]}),
        json!({"content_base64": "not padded?!"}),
    ] {
        assert!(serde_json::from_value::<Content>(value).is_err());
    }
}

#[test]
fn jsonl_preserves_payload_origin_and_each_record_across_crlf_and_final_line() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("enumerator.jsonl");
    let origins = [json!({"path": "first.env", "nested": [1, "value"]}), json!("external source")];
    let first = json!({"content": "first payload", "origin": origins[0], "extra": "ignored"});
    let second = json!({"content_base64": "/wBh", "origin": origins[1]});
    std::fs::write(&path, format!("{first}\r\n{second}")).unwrap();
    let mut rows = enumerate(&path).into_iter().map(Result::unwrap).collect::<Vec<_>>();
    rows.sort_by(|left, right| left.1.bytes().cmp(right.1.bytes()));
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1.bytes(), b"first payload");
    assert_eq!(rows[0].0.first(), &Origin::from_extended(origins[0].clone()));
    assert!(rows[0].2.is_none());
    assert_eq!(rows[1].1.bytes(), &[0xff, 0, b'a']);
    assert_eq!(rows[1].0.first(), &Origin::from_extended(origins[1].clone()));
}

#[test]
fn jsonl_reports_bad_records_with_original_one_based_line_numbers() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bad-records.jsonl");
    let good = json!({"content": "valid", "origin": null});
    std::fs::write(
        &path,
        format!("{good}\n\n{{broken json}}\n{{\"content\":\"missing origin\"}}\n{good}\n"),
    )
    .unwrap();
    let rows = enumerate(&path);
    assert_eq!(rows.iter().filter(|row| row.is_ok()).count(), 2);
    let mut errors =
        rows.into_iter().filter_map(|row| row.err()).map(|e| e.to_string()).collect::<Vec<_>>();
    errors.sort();
    let mut expected =
        [2, 3, 4].map(|line| format!("Error in enumerator {}:{line}", path.display())).to_vec();
    expected.sort();
    assert_eq!(errors, expected);
}

#[test]
fn empty_enumerator_is_a_valid_empty_stream() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("empty.jsonl");
    std::fs::write(&path, []).unwrap();
    assert!(enumerate(&path).is_empty());
}

#[test]
fn invalid_utf8_line_is_skipped_without_renumbering_later_json_errors() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("invalid-utf8.jsonl");
    let mut bytes = vec![0xff, b'\n'];
    bytes.extend_from_slice(b"{broken}\n{\"content\":\"accepted\",\"origin\":{}}\n");
    std::fs::write(&path, bytes).unwrap();
    let rows = enumerate(&path);
    assert_eq!(rows.len(), 2, "the existing line-read policy skips invalid UTF-8");
    assert_eq!(rows.iter().filter(|row| row.is_ok()).count(), 1);
    let error = rows.into_iter().find_map(|row| row.err()).unwrap();
    assert_eq!(error.to_string(), format!("Error in enumerator {}:2", path.display()));
}

#[test]
fn path_selection_filters_origins_without_hiding_parse_errors() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("selection.jsonl");
    let records = [
        json!({"content": "keep", "origin": {"path": "configs/key.env"}}),
        json!({"content": "skip extension", "origin": {"path": "configs/key.txt"}}),
        json!({"content": "skip prefix", "origin": {"path": "other/key.env"}}),
        json!({"content": "pathless", "origin": {"source": "opaque"}}),
    ];
    let mut text = records.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n");
    text.push_str("\ninvalid json\n");
    std::fs::write(&path, text).unwrap();
    let mut iter = EnumeratorFileResult { path: path.clone() }.into_blob_iter().unwrap().unwrap();
    iter.path_selection = crate::path_selection::PathSelection {
        include_prefixes: vec!["configs/".into()],
        include_extensions: vec!["env".into()],
        ..Default::default()
    };
    let rows = iter.collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.iter().filter_map(|row| row.as_ref().ok()).next().unwrap().1.bytes(), b"keep");
    assert!(rows.iter().any(|row| row.as_ref().err().is_some_and(
        |error| error.to_string() == format!("Error in enumerator {}:5", path.display())
    )));
}

#[test]
fn opening_a_missing_enumerator_preserves_the_io_error() {
    let temp = tempfile::tempdir().unwrap();
    let error = EnumeratorFileResult { path: temp.path().join("absent.jsonl") }
        .into_blob_iter()
        .err()
        .expect("missing input must fail before iteration");
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::NotFound
    );
}

// Append to the existing cfg(test) JSONL module before changing production logic.

fn base64_payload_document(raw: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    json!({"content_base64": STANDARD.encode(raw)})
}

fn assert_jsonl_payload_identity(
    mut document: serde_json::Value,
    original: &[u8],
    expected_content: &[u8],
) {
    // Check the existing borrowed adapter before Blob performs Unicode decoding.
    let content: Content = serde_json::from_value(document.clone()).unwrap();
    assert_eq!(content.as_bytes(), original);

    let origin = json!({"path": "fixtures/payload.bin", "metadata": [null, "fixture"]});
    document["origin"] = origin.clone();
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("owned-payload.jsonl");
    std::fs::write(&path, format!("{document}\n")).unwrap();
    let mut rows = enumerate(&path);
    assert_eq!(rows.len(), 1);
    let (origins, blob, archive) = rows.pop().unwrap().unwrap();
    assert_eq!(origins.first(), &Origin::from_extended(origin));
    assert!(archive.is_none());
    assert_eq!(blob.bytes(), expected_content);
    assert_eq!(blob.id(), crate::blob::BlobId::new(original));
    if original != expected_content {
        assert_ne!(blob.id(), crate::blob::BlobId::new(expected_content));
    }
}

#[test]
fn jsonl_owned_utf8_binary_and_empty_payloads_keep_original_identity() {
    for text in ["", "café\n\0raw", "\u{feff}plain UTF-8 text"] {
        // Public literal variants and the borrowed adapter remain supported.
        let literal = Content::Utf8(text.to_owned());
        assert_eq!(literal.as_bytes(), text.as_bytes());
        assert_jsonl_payload_identity(json!({"content": text}), text.as_bytes(), text.as_bytes());
    }
    for bytes in [&b""[..], &[0, 0xff, 0x80, 0, b'a', b'\n', b'\r'][..]] {
        let literal = Content::Base64(bstr::BString::from(bytes.to_vec()));
        assert_eq!(literal.as_bytes(), bytes);
        assert_jsonl_payload_identity(base64_payload_document(bytes), bytes, bytes);
    }
}

#[test]
fn jsonl_unicode_decoding_retains_the_predecode_blob_id() {
    let text = "fixture=λ🔑\0ok";
    for little_endian in [true, false] {
        let utf16: Vec<u8> = std::iter::once(0xfeff_u16)
            .chain(text.encode_utf16())
            .flat_map(|unit| if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() })
            .collect();
        assert_jsonl_payload_identity(base64_payload_document(&utf16), &utf16, text.as_bytes());

        let utf32: Vec<u8> = std::iter::once(0xfeff_u32)
            .chain(text.chars().map(u32::from))
            .flat_map(|unit| if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() })
            .collect();
        assert_jsonl_payload_identity(base64_payload_document(&utf32), &utf32, text.as_bytes());

        let plain = "fixture-value=ASCII123";
        let bomless: Vec<u8> = plain
            .encode_utf16()
            .flat_map(|unit| if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() })
            .collect();
        assert_jsonl_payload_identity(
            base64_payload_document(&bomless),
            &bomless,
            plain.as_bytes(),
        );
    }
}

#[test]
fn jsonl_bom_only_and_malformed_unicode_preserve_existing_content_and_ids() {
    for (original, expected) in [
        (&[0xff, 0xfe][..], &[0xff, 0xfe][..]),
        (&[0xff, 0xfe, 0, 0][..], &[0xff, 0xfe, 0, 0][..]),
        (&[0xff, 0xfe, b'A', 0, 0x99][..], &b"A"[..]),
        (&[0xff, 0xfe, 0, 0, b'a', 0][..], &b"\0a"[..]),
        (&[0xff, 0xfe, 0, 0xdc, b'A', 0, 0, 0xd8, b'B', 0][..], "\u{fffd}A\u{fffd}B".as_bytes()),
        (&[0, 0, 0xfe, 0xff, 0, 0x11, 0, 0][..], "\u{fffd}".as_bytes()),
    ] {
        assert_jsonl_payload_identity(base64_payload_document(original), original, expected);
    }
}

#[test]
fn jsonl_large_owned_payloads_keep_the_existing_sampled_id_policy() {
    let text = "raw-payload:".repeat(12_000);
    let original = text.as_bytes();
    assert!(original.len() > 128 * 1024);
    assert_ne!(
        crate::blob::BlobId::new(original),
        crate::blob::BlobId::compute_from_bytes(original),
    );
    assert_jsonl_payload_identity(json!({"content": text}), original, original);
    assert_jsonl_payload_identity(base64_payload_document(original), original, original);
}
