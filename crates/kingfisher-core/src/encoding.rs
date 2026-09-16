//! Detection and decoding of common Unicode encodings found in credential files.

/// Decode UTF-16 or UTF-32 text when a BOM or a strong zero-byte pattern identifies it.
pub(crate) fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let (encoding, start) = match input.get(..4) {
        Some([0xff, 0xfe, 0, 0]) => (Encoding::Utf32Le, 4),
        Some([0, 0, 0xfe, 0xff]) => (Encoding::Utf32Be, 4),
        _ => match input.get(..2) {
            Some([0xff, 0xfe]) => (Encoding::Utf16Le, 2),
            Some([0xfe, 0xff]) => (Encoding::Utf16Be, 2),
            _ => guess(input)?,
        },
    };
    let mut output = Vec::new();
    match encoding {
        Encoding::Utf16Le | Encoding::Utf16Be => {
            for chunk in input[start..].chunks_exact(2) {
                let value = if encoding == Encoding::Utf16Le {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                };
                output.extend(
                    char::decode_utf16([value])
                        .map(|c| c.unwrap_or('\u{fffd}'))
                        .collect::<String>()
                        .as_bytes(),
                );
            }
        }
        Encoding::Utf32Le | Encoding::Utf32Be => {
            for chunk in input[start..].chunks_exact(4) {
                let value = if encoding == Encoding::Utf32Le {
                    u32::from_le_bytes(chunk.try_into().unwrap())
                } else {
                    u32::from_be_bytes(chunk.try_into().unwrap())
                };
                output.extend(
                    char::from_u32(value).unwrap_or('\u{fffd}').encode_utf8(&mut [0; 4]).as_bytes(),
                );
            }
        }
    }
    (!output.is_empty()).then_some(output)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

fn guess(input: &[u8]) -> Option<(Encoding, usize)> {
    if input.len() < 8 {
        return None;
    }
    let score = |offset: usize, stride: usize| {
        let bytes = input[offset..].iter().step_by(stride).take(input.len() / stride);
        let (total, zeros) =
            bytes.fold((0, 0), |(total, zeros), &byte| (total + 1, zeros + usize::from(byte == 0)));
        total > 1 && zeros * 100 / total >= 60
    };
    if input.len() % 4 == 0 {
        if score(1, 4) && score(2, 4) && score(3, 4) {
            return Some((Encoding::Utf32Le, 0));
        }
        if score(0, 4) && score(1, 4) && score(2, 4) {
            return Some((Encoding::Utf32Be, 0));
        }
    }
    if input.len() % 2 == 0 {
        if score(1, 2) {
            return Some((Encoding::Utf16Le, 0));
        }
        if score(0, 2) {
            return Some((Encoding::Utf16Be, 0));
        }
    }
    None
}
