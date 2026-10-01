# kingfisher-core

Shared content, location, provenance, entropy, and validation-outcome types for
embedding Kingfisher in Rust 1.96+ applications. The `1.x` public Rust API follows
semantic versioning; breaking changes require a new major version.

```toml
[dependencies]
kingfisher-core = "1.0.1"
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

## Runnable examples

From the repository checkout:

```sh
cargo run --locked -p kingfisher-core --example blob_locations
```

The packaged [`blob_locations` example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-core/examples/blob_locations.rs) is also available
in the crate source.
