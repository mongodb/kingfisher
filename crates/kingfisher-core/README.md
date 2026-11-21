# kingfisher-core

Shared content, location, provenance, entropy, and validation-outcome types for
embedding Kingfisher in Rust 1.99+ applications. The `2.x` public Rust API follows
semantic versioning; breaking changes require a new major version.

**No Git executable required.** Git object IDs and commit metadata use native Rust types.

```toml
[dependencies]
kingfisher-core = "2.1.0"
```

```rust
use kingfisher_core::{Blob, BlobId, ValidationOutcome};

let input = b"configuration data";
let blob = Blob::from_borrowed(input);
assert_eq!(blob.bytes(), input);
assert_eq!(blob.id(), BlobId::compute_from_bytes(input));
assert!(!ValidationOutcome::Assumed.is_verified_active());
```

`Blob::from_bytes` owns a buffer; `Blob::from_borrowed` borrows it unless decoding
requires an allocation. `Blob::from_file` returns I/O errors and can memory-map
large files. Do not modify or truncate a file while its mapped blob is alive.
UTF-16/32 input is decoded to UTF-8; byte locations refer to that normalized content.
Blob IDs identify the original bytes (or the supplied ID for `Blob::new`).

`ValidationOutcome` distinguishes live verification from assumptions, local
cryptographic derivation, invalid material, unavailable checks, and skipped work.
Use its predicates rather than treating all actionable findings as live credentials.
Serde names are part of the documented data contract; adding variants to an
exhaustive public enum or changing existing serialized names requires a major release.

This crate performs no credential validation or network requests. Use
`kingfisher-scanner` for detection and `kingfisher-rules` for rule loading.

## Migrating to 2.0

Public Git types now use `gix` 0.90. Align direct `gix` dependencies when constructing
`CommitMetadata` or using `BlobId`'s object-ID conversions: old `gix::ObjectId` and
`gix::date::Time` values have different dependency type identities. The core error
conversion is now `From<gix::Error>`, replacing `From<gix::open::Error>`.
Use scanner 4.0.0 when sharing these core types with the scanner. Serialized data,
blob/location behavior, and existing rule files remain compatible. See the
[dependency migration guide](../../docs/LIBRARY.md#dependency-modernization-migration).

Language hints use an embedded extension/filename mapping derived from tokei 14.0.0,
not its runtime parser. The upstream MIT attribution is retained in the packaged
[license](data/tokei-LICENSE-MIT).

## Runnable examples

From the repository checkout:

```sh
cargo run --locked -p kingfisher-core --example blob_locations
```

The packaged [`blob_locations` example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-core/examples/blob_locations.rs) is also available
in the crate source.
