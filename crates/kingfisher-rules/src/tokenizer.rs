//! Compact storage for the unchanged cl100k vocabulary used by Betterleaks filters.
//!
//! Keep tiktoken's engine, merge ranks, special tokens and splitting pattern. Only
//! replace its embedded Base64/decimal text with a compressed rank-ordered byte
//! stream. Decoding happens once, lazily, without retaining an uncompressed copy.

use std::{io::Read, sync::LazyLock};

use anyhow::{Context, Result, ensure};
use flate2::read::GzDecoder;
use rustc_hash::FxHashMap;
use tiktoken_rs::{CoreBPE, ENDOFPROMPT, ENDOFTEXT, FIM_MIDDLE, FIM_PREFIX, FIM_SUFFIX};

#[path = "../build_support/tokenizer_data.rs"]
mod data;

const VOCABULARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/cl100k-base.bin.gz"));

// The cl100k splitting pattern from tiktoken-rs (MIT), src/tiktoken_ext/openai_public.rs.
// Exhaustive vocabulary and Unicode parity tests below guard dependency upgrades.
const PATTERN: &str = "'(?i:[sdmt]|ll|ve|re)|[^\\r\\n\\p{L}\\p{N}]?+\\p{L}++|\\p{N}{1,3}+| ?[^\\s\\p{L}\\p{N}]++[\\r\\n]*+|\\s++$|\\s*[\\r\\n]|\\s+(?!\\S)|\\s";

pub(crate) fn cl100k_base_singleton() -> &'static CoreBPE {
    static TOKENIZER: LazyLock<CoreBPE> =
        LazyLock::new(|| load(VOCABULARY).expect("embedded cl100k vocabulary must be valid"));
    &TOKENIZER
}

fn load(compressed: &[u8]) -> Result<CoreBPE> {
    let mut reader = GzDecoder::new(compressed);
    let mut magic = [0; data::MAGIC.len()];
    reader.read_exact(&mut magic).context("truncated cl100k header")?;
    ensure!(magic == data::MAGIC, "invalid cl100k header");
    let mut count = [0; 4];
    reader.read_exact(&mut count).context("truncated cl100k rank count")?;
    ensure!(u32::from_le_bytes(count) == data::MERGEABLE_RANKS, "invalid cl100k rank count");

    let mut encoder =
        FxHashMap::with_capacity_and_hasher(data::MERGEABLE_RANKS as usize, Default::default());
    for rank in 0..data::MERGEABLE_RANKS {
        let mut length = [0];
        reader.read_exact(&mut length).context("truncated cl100k token length")?;
        ensure!(length[0] != 0, "empty cl100k token");
        let mut token = vec![0; usize::from(length[0])];
        reader.read_exact(&mut token).context("truncated cl100k token")?;
        ensure!(encoder.insert(token, rank).is_none(), "duplicate cl100k token");
    }
    let mut trailing = [0];
    ensure!(reader.read(&mut trailing)? == 0, "trailing cl100k data");
    let special = [
        (ENDOFTEXT, 100257),
        (FIM_PREFIX, 100258),
        (FIM_MIDDLE, 100259),
        (FIM_SUFFIX, 100260),
        (ENDOFPROMPT, 100276),
    ]
    .into_iter()
    .map(|(token, rank)| (token.to_string(), rank))
    .collect();
    CoreBPE::new(encoder, special, PATTERN)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::{Compression, write::GzEncoder};
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn every_merge_rank_and_token_matches_upstream() {
        let compact = cl100k_base_singleton();
        let upstream = tiktoken_rs::cl100k_base_singleton();
        for rank in 0..data::MERGEABLE_RANKS {
            let expected = upstream.decode_bytes(&[rank]).unwrap();
            assert_eq!(compact.decode_bytes(&[rank]).unwrap(), expected, "rank {rank}");
            let text = String::from_utf8_lossy(&expected);
            assert_eq!(
                compact.encode_ordinary(&text),
                upstream.encode_ordinary(&text),
                "rank {rank}"
            );
        }
    }

    #[test]
    fn special_tokens_and_split_boundaries_match_upstream() {
        let compact = cl100k_base_singleton();
        let upstream = tiktoken_rs::cl100k_base_singleton();
        for text in [
            "",
            " ",
            "\r\n",
            "hello world",
            "we're I'LL they've can't",
            "foo123456789\r\n  bar\t \n",
            "日本語 中文 한국어 🦆 café e\u{301}",
            "<|endoftext|><|fim_prefix|><|fim_middle|><|fim_suffix|><|endofprompt|>",
        ] {
            assert_eq!(compact.encode_ordinary(text), upstream.encode_ordinary(text));
            assert_eq!(
                compact.encode_with_special_tokens(text),
                upstream.encode_with_special_tokens(text)
            );
        }
    }

    proptest! {
        #[test]
        fn unicode_tokenization_matches_upstream(text in ".{0,256}") {
            prop_assert_eq!(
                cl100k_base_singleton().encode_ordinary(&text),
                tiktoken_rs::cl100k_base_singleton().encode_ordinary(&text)
            );
        }
    }

    #[test]
    fn malformed_vocabulary_is_rejected() {
        for length in [0, 1, 10, VOCABULARY.len() - 1] {
            assert!(load(&VOCABULARY[..length]).is_err());
        }
        for data in [
            b"wrong header".to_vec(),
            [data::MAGIC, &0_u32.to_le_bytes()].concat(),
            [data::MAGIC, &data::MERGEABLE_RANKS.to_le_bytes(), &[0]].concat(),
        ] {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
            encoder.write_all(&data).unwrap();
            assert!(load(&encoder.finish().unwrap()).is_err());
        }
    }
}
