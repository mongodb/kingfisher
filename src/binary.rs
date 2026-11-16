use std::{fs, io::Read, path::Path};

use anyhow::Result;

use crate::util::is_safe_path;
const MAX_PEEK_SIZE: usize = 1024;
/// Preserve the scanner's lightweight binary heuristic, not UTF-8 validation.
/// A leading Unicode BOM makes even NUL-containing content textual. Otherwise,
/// only NULs within the peek window and the PDF/PNG signatures mark it binary.
pub fn is_binary(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(MAX_PEEK_SIZE)];
    // UTF-32LE starts with the UTF-16LE BOM; both are text for this predicate.
    let has_text_bom = matches!(
        sample,
        [0xef, 0xbb, 0xbf, ..] | [0xff, 0xfe, ..] | [0xfe, 0xff, ..] | [0x00, 0x00, 0xfe, 0xff, ..]
    );
    !has_text_bom
        && (memchr::memchr(0, sample).is_some()
            || sample.starts_with(b"%PDF")
            || sample.starts_with(b"\x89PNG"))
}

pub fn is_binary_file(path: &Path) -> Result<bool> {
    if !is_safe_path(path)? {
        return Err(anyhow::anyhow!("Unsafe file path"));
    }

    let mut file = fs::File::open(path)?;

    let mut buffer = vec![0; 8192];
    let n = file.read(&mut buffer)?;
    buffer.truncate(n);
    Ok(is_binary(&buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_non_null_bytes_are_text_without_utf8_validation() {
        for text in
            [b"".as_slice(), b"hello\nworld\r\n", b"\xff\xff\x01\x7f\x80", "秘密".as_bytes()]
        {
            assert!(!is_binary(text), "{text:?}");
        }
        // Preserve the heuristic, rather than replacing it with UTF-8 decoding.
        for byte in 1..=u8::MAX {
            assert!(!is_binary(&[byte]), "byte {byte}");
        }
        assert!(is_binary(&[0]));
    }

    #[test]
    fn unicode_byte_order_marks_take_precedence_over_binary_content() {
        for bom in [
            b"\xef\xbb\xbf".as_slice(),
            b"\xff\xfe",
            b"\xfe\xff",
            b"\x00\x00\xfe\xff",
            b"\xff\xfe\x00\x00",
        ] {
            assert!(!is_binary(bom), "BOM {bom:?}");
            for suffix in [b"\x00\x00".as_slice(), b"%PDF", b"\x89PNG"] {
                let mut data = bom.to_vec();
                data.extend_from_slice(suffix);
                assert!(!is_binary(&data), "BOM {bom:?}, suffix {suffix:?}");
            }
        }
        assert!(is_binary(b"\x00\x00\xfe"));
        assert!(is_binary(b"\xef\xbb\x00"));
        assert!(is_binary(b"x\xff\xfe\x00"));
    }

    #[test]
    fn pdf_and_png_markers_are_exact_binary_prefixes() {
        for marker in [b"%PDF".as_slice(), b"\x89PNG"] {
            assert!(is_binary(marker));
            assert!(is_binary(&[marker, b"payload"].concat()));
            for length in 0..marker.len() {
                assert!(!is_binary(&marker[..length]));
            }
            assert!(!is_binary(&[b" ".as_slice(), marker].concat()));
        }
        assert!(!is_binary(b"%pdf"));
        assert!(!is_binary(b"\x89Png"));
    }

    #[test]
    fn null_detection_stops_at_the_exact_peek_boundary() {
        for position in 0..MAX_PEEK_SIZE {
            let mut data = vec![b'x'; MAX_PEEK_SIZE + 1];
            data[position] = 0;
            assert!(is_binary(&data), "null at {position}");
        }
        let mut data = vec![b'x'; MAX_PEEK_SIZE];
        data.extend_from_slice(b"\x00%PDF\x89PNG");
        assert!(!is_binary(&data));
    }

    #[test]
    fn every_two_byte_input_preserves_null_only_detection() {
        for first in 0..=u8::MAX {
            for second in 0..=u8::MAX {
                assert_eq!(is_binary(&[first, second]), first == 0 || second == 0);
            }
        }
    }

    #[test]
    fn file_detection_preserves_bom_and_peek_rules() -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("binary fixture.dat");
        for data in [
            b"hello".to_vec(),
            b"%PDF-1.7".to_vec(),
            b"\xff\xfe\x00\x00".to_vec(),
            [vec![b'x'; MAX_PEEK_SIZE], vec![0; MAX_PEEK_SIZE]].concat(),
        ] {
            fs::write(&path, &data)?;
            assert_eq!(is_binary_file(&path)?, is_binary(&data));
        }
        assert!(is_binary_file(&work.path().join("missing")).is_err());
        Ok(())
    }
}
