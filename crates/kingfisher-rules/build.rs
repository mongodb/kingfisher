use std::{fs::File, io::Write, path::PathBuf};

use flate2::{Compression, write::GzEncoder};

#[path = "build_support/tokenizer_data.rs"]
mod tokenizer_data;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/tokenizer_data.rs");

    // Use the dependency's public decoder, not its on-disk source layout or a
    // separately maintained vocabulary. Ordinary builds need no network access.
    let tokenizer = tiktoken_rs::cl100k_base_singleton();
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("cl100k-base.bin.gz");
    let mut compressed = GzEncoder::new(File::create(output).unwrap(), Compression::best());
    compressed.write_all(tokenizer_data::MAGIC).unwrap();
    compressed.write_all(&tokenizer_data::MERGEABLE_RANKS.to_le_bytes()).unwrap();
    for rank in 0..tokenizer_data::MERGEABLE_RANKS {
        let token = tokenizer.decode_bytes(&[rank]).expect("cl100k mergeable rank must exist");
        let length = u8::try_from(token.len()).expect("cl100k token exceeds compact length limit");
        assert_ne!(length, 0, "cl100k tokens must not be empty");
        compressed.write_all(&[length]).unwrap();
        compressed.write_all(&token).unwrap();
    }
    assert!(tokenizer.decode_bytes(&[tokenizer_data::MERGEABLE_RANKS]).is_err());
    compressed.finish().expect("failed to compress cl100k vocabulary");
}
