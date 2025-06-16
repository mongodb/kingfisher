# `vectorscan-rs`

## Overview

This repository contains Rust bindings to the high-performance [Vectorscan](https://github.com/Vectorcamp/vectorscan) regular expression library.

The bindings are organized into two crates:

- [`vectorscan-rs`](vectorscan-rs): higher-level Rust bindings
- [`vectorscan-rs-sys`](vectorscan-rs-sys): low-level bindings to a vendored copy of the native Vectorscan library

Vectorscan is a fork of [Hyperscan](https://github.com/Intel/hyperscan) that supports additional platforms.
To understand how to use this library, it may be helpful to look at the [documentation for the Hyperscan C bindings](https://intel.github.io/hyperscan/dev-reference/).

## License

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](LICENSE-APACHE))

- [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](LICENSE-MIT))

at your option.

This project also includes a vendored copy of Vectorscan, which is distributed under the BSD license ([LICENSE-VECTORSCAN](LICENSE-VECTORSCAN)).
