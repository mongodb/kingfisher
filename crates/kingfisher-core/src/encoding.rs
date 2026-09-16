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
            let units = input[start..].chunks_exact(2).map(|chunk| {
                if encoding == Encoding::Utf16Le {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                }
            });
            for character in char::decode_utf16(units) {
                output.extend(character.unwrap_or('\u{fffd}').encode_utf8(&mut [0; 4]).as_bytes());
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

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn utf16_preserves_surrogate_pairs() {
        let text = "credential=abc\u{1f511}\u{1d11e}xyz";
        for little_endian in [true, false] {
            for with_bom in [true, false] {
                let units = with_bom.then_some(0xfeff).into_iter().chain(text.encode_utf16());
                let input: Vec<u8> =
                    units
                        .flat_map(|unit| {
                            if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() }
                        })
                        .collect();
                assert_eq!(decode(&input).unwrap(), text.as_bytes());
            }
        }
    }

    #[test]
    fn utf16_replaces_unpaired_surrogates_without_losing_adjacent_text() {
        for little_endian in [true, false] {
            let input: Vec<u8> = [0xfeff_u16, 0xdc00, 0x0041, 0xd800, 0x0042, 0xd800]
                .into_iter()
                .flat_map(
                    |unit| {
                        if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() }
                    },
                )
                .collect();
            assert_eq!(decode(&input).unwrap(), "\u{fffd}A\u{fffd}B\u{fffd}".as_bytes());
        }
    }
}
