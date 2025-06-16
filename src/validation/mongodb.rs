// src/validation/mongodb.rs
use std::time::Duration;

use anyhow::Result;
use bson::doc;
use mongodb::{options::ClientOptions, Client};

pub fn looks_like_mongodb_uri(uri: &str) -> bool {
    // quick scheme check first
    if !(uri.starts_with("mongodb://") || uri.starts_with("mongodb+srv://")) {
        return false;
    }
    // pure string-level parse – no network, even for +srv
    mongodb::options::ConnectionString::parse(uri).is_ok()
}

const FAST_CONNECT_MS: u64 = 700; // direct single-host URIs
const FAST_SELECT_MS: u64 = 300;
const SRV_CONNECT_MS: u64 = 15_000; // gives Atlas a fighting chance
const SRV_SELECT_MS: u64 = 15_000;

/// Validates a MongoDB URI in ≤ 2 s. Returns `Ok(true)` on successful ping.
pub async fn validate_mongodb(uri: &str) -> Result<bool> {
    // ---- quick reject without touching the network
    if !looks_like_mongodb_uri(uri) {
        return Ok(false);
    }

    let is_srv = uri.starts_with("mongodb+srv://");

    // ---- build client opts
    let mut opts = ClientOptions::parse(uri).await?;
    if !is_srv {
        // one socket, skip cluster discovery for plain 'mongodb://'
        opts.direct_connection = Some(true);
        opts.connect_timeout = Some(Duration::from_millis(FAST_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(FAST_SELECT_MS));
    } else {
        // SRV needs DNS and replica-set discovery; give it a couple seconds
        opts.connect_timeout = Some(Duration::from_millis(SRV_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(SRV_SELECT_MS));
        // leave direct_connection = None   (driver decides)
    }
    opts.max_pool_size = Some(1);
    opts.min_pool_size = Some(0);

    // ---- dial and ping
    let client = Client::with_options(opts)?;
    Ok(client.database("admin").run_command(doc! { "ping": 1 }).await.is_ok())
}

// pub fn generate_mongodb_cache_key(mongodb_uri: &str) -> String {
//     use sha1::{Digest, Sha1};
//     let mut hasher = Sha1::new();
//     hasher.update(mongodb_uri.as_bytes());
//     format!("MongoDB:{:x}", hasher.finalize())
// }
