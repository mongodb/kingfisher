[![Crates.io](https://img.shields.io/crates/v/sqlite-wasm-rs.svg)](https://crates.io/crates/sqlite-wasm-rs)

`wasm32-unknown-unknown` bindings to the libsqlite3 library.

## Usage

```toml
[dependencies]
sqlite-wasm-rs = "0.5"
```

```toml
[dependencies]
# Encryption is supported by SQLite3MultipleCiphers
# See <https://utelle.github.io/SQLite3MultipleCiphers>
sqlite-wasm-rs = { version = "0.5", features = ["sqlite3mc"] }
```

```rust
use sqlite_wasm_rs as ffi;

fn open_db() {
    // open with memory vfs
    let mut db = std::ptr::null_mut();
    let ret = unsafe {
        ffi::sqlite3_open_v2(
            c"mem.db".as_ptr().cast(),
            &mut db as *mut _,
            ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
            std::ptr::null()
        )
    };
    assert_eq!(ffi::SQLITE_OK, ret);
}
```

## About VFS

```toml
[dependencies]
# It requires sqlite-wasm-rs 0.5.2 or higher to be used,
# for version 0.5.1, use version 0.1 instead.
sqlite-wasm-vfs = "0.2"
```

The following vfs have been implemented:

* [`memory`](./crates/rsqlite-vfs/src/memvfs.rs): as the default vfs, no additional conditions are required, store the database in memory.
* [`sahpool`](./crates/sqlite-wasm-vfs/src/sahpool.rs): ported from sqlite-wasm, store the database in opfs.
* [`relaxed-idb`](./crates/sqlite-wasm-vfs/src/relaxed_idb.rs): store the database in blocks in indexed db.

### VFS Comparison

||MemoryVFS|SyncAccessHandlePoolVFS|RelaxedIdbVFS|
|-|-|-|-|
|Storage|RAM|OPFS|IndexedDB|
|Contexts|All|Dedicated Worker|All|
|Multiple connections|:x:|:x:|:x:|
|Full durability|✅|✅|:x:|
|Relaxed durability|:x:|:x:|✅|
|Multi-database transactions|✅|✅|✅|
|No COOP/COEP requirements|✅|✅|✅|

### How to implement a VFS

Here is an example showing how to use `sqlite-wasm-rs` to implement a simple in-memory VFS, see [`implement-a-vfs`](./examples/implement-a-vfs) example.

## About multithreading

This library is not thread-safe:

* `JsValue` is not cross-threaded, see <https://github.com/rustwasm/wasm-bindgen/pull/955> for details.
* sqlite is compiled with `-DSQLITE_THREADSAFE=0`.

## Use prebuild libsqlite3.a

We provide the ability to use prebuild `libsqlite3.a`, cargo provides a [`links`](https://doc.rust-lang.org/cargo/reference/manifest.html#the-links-field) field that can be used to specify which library to link to. With the help of [overriding build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html#overriding-build-scripts), you can overriding its configuration in your crate and link sqlite to your prebuild `libsqlite3.a`.

More see [`use-prebuild-lib`](./examples/use-prebuild-lib) example.

## Minimum supported Rust version (MSRV)

The minimal officially supported rustc version is 1.81.0.

## Extensions

|Extension|About|
|-|-|
|[sqlite-vec](./extensions/sqlite-vec)|A vector search SQLite extension that runs anywhere!|

Contributions are welcome!

## Related Project

* [`diesel`](https://github.com/diesel-rs/diesel): A safe, extensible ORM and Query Builder for Rust.
* [`rusqlite`](https://github.com/rusqlite/rusqlite): Ergonomic bindings to SQLite for Rust.
* [`sqlite-wasm`](https://github.com/sqlite/sqlite-wasm): SQLite Wasm conveniently wrapped as an ES Module.
* [`sqlite-web-rs`](https://github.com/xmtp/sqlite-web-rs): A SQLite WebAssembly backend for Diesel.
* [`wa-sqlite`](https://github.com/rhashimoto/wa-sqlite): WebAssembly SQLite with support for browser storage extensions.
* [`SQLite3MultipleCiphers`](https://github.com/utelle/SQLite3MultipleCiphers): SQLite3 encryption extension with support for multiple ciphers.
