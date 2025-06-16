# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [v0.0.5](https://github.com/bradlarsen/vectorscan-rs/releases/v0.0.5) (2024-12-09)

### Additions
- Added `BlockDatabase::size` and `StreamingDatabase::size`, which return the size in bytes of the database
- Added `StreamingDatabase::stream_size`, which returns the size in bytes of a stream for the database
- A new `asan` feature enables Address Sanitizer in the vendored version of `vectorscan`


## [v0.0.4](https://github.com/bradlarsen/vectorscan-rs/releases/v0.0.4) (2024-11-07)

### Additions
- The streaming APIs are now exposed ([#5](https://github.com/bradlarsen/vectorscan-rs/pull/5)).

- Documentation has been added for many of the Rust APIs ([#5](https://github.com/bradlarsen/vectorscan-rs/pull/5)).

### Fixes
- Debug builds are fixed on macOS using Xcode 15.


## [v0.0.3](https://github.com/bradlarsen/vectorscan-rs/releases/v0.0.3) (2024-08-21)

### Additions
- Several additional Hyperscan functions are exposed, and exposed types implement more traits ([#3](https://github.com/bradlarsen/vectorscan-rs/pull/3)).
  Specifically, the `Flag`, `Pattern`, `ScanMode`, `Scratch`, and `BlockDatabase` types now implement `Clone`, `Debug`, `Send`, and `Sync`.


## [v0.0.2](https://github.com/bradlarsen/vectorscan-rs/releases/v0.0.2) (2024-04-18)

### Additions
- A new `unit_hyperscan` feature causes the Vectorscan unit test suite to be built and run at crate build time ([#2](https://github.com/bradlarsen/vectorscan-rs/pull/2)).

### Fixes
- The compilation of the vendored version of `vectorscan` no longer uses the `-march=native` C and C++ compiler option when the `cpu_native` feature is not specified ([#1](https://github.com/bradlarsen/vectorscan-rs/pull/1)).
  Previously, `-march=native` was used unconditionally, which could cause non-portable code to be generated, leading to `SIGILL` crashes at runtime.


## [v0.0.1](https://github.com/bradlarsen/vectorscan-rs/releases/v0.0.1) (2024-04-04)

This is the initial release of the `vectorscan-rs` and `vectorscan-rs-sys` crates.
These crates were extracted from the [Nosey Parker project](https://github.com/praetorian-inc/noseyparker).

The `vectorscan-rs-sys` crate builds a vendored copy of [Vectorscan](https://github.com/Vectorcamp/vectorscan) 5.4.11.
The `vectorscan-rs` crate provides minimal Rust bindings to Vectorscan's block-based matching APIs.
