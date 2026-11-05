//! Conversion and ownership bridge for the JavaScript SDK; no CLI dependency.
// napi-rs omits export registration under cfg(test). Clippy --all-targets still
// type-checks that target; the exports are exercised by the Node integration suite.
#![cfg_attr(test, allow(dead_code))]

mod control;
mod file_io;
mod findings;
mod inputs;
mod rules;
mod scanner;
mod transforms;
mod validation;

use napi_derive::napi;

#[napi]
pub fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
