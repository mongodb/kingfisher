use std::{net::IpAddr, time::Duration};

use anyhow::Result;
use mongodb::{
    Client,
    bson::doc,
    error::ErrorKind,
    options::{ClientOptions, Tls, TlsOptions},
};
use tokio::time::timeout;
use tracing::debug;

pub fn looks_like_mongodb_uri(uri: &str) -> bool {
    if !(uri.starts_with("mongodb://") || uri.starts_with("mongodb+srv://")) {
        return false;
    }
    mongodb::options::ConnectionString::parse(uri).is_ok()
}

fn uri_targets_localhost(uri: &str) -> bool {
    let rest = uri
        .strip_prefix("mongodb://")
        .or_else(|| uri.strip_prefix("mongodb+srv://"))
        .unwrap_or(uri);

    let authority = rest.split_once('/').map(|(a, _)| a).unwrap_or(rest);

    let auth_lower = authority.to_ascii_lowercase();
    if auth_lower.starts_with("%2f") || authority.starts_with('/') {
        return true;
    }

    let hostlist = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);

    for part in hostlist.split(',') {
        let mut host = part.trim();

        if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 {
            host = &host[1..host.len() - 1];
        }

        if let Some(idx) = host.rfind(':')
            && host[idx + 1..].chars().all(|c| c.is_ascii_digit())
        {
            host = &host[..idx];
        }

        if is_local_host(host) {
            return true;
        }
    }

    false
}

fn is_local_host(h: &str) -> bool {
    let s = h.trim().trim_end_matches('.');
    let s_lower = s.to_ascii_lowercase();

    if matches!(
        s_lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "localhost6"
            | "localhost6.localdomain6"
            | "ip6-localhost"
            | "ip6-loopback"
    ) {
        return true;
    }

    if s_lower.as_str() == "0.0.0.0" || s_lower.as_str() == "::" {
        return true;
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }

    false
}

const FAST_CONNECT_MS: u64 = 700;
const FAST_SELECT_MS: u64 = 300;
const SRV_PARSE_MS: u64 = 2_000;
const SRV_CONNECT_MS: u64 = 2500;
const SRV_SELECT_MS: u64 = 2500;

/// Validates a MongoDB URI in ≤ 2 s.
pub async fn validate_mongodb(uri: &str, lax_tls: bool) -> Result<(bool, String)> {
    if !looks_like_mongodb_uri(uri) {
        return Ok((false, "Invalid MongoDB URI".to_string()));
    }

    if uri_targets_localhost(uri) {
        return Ok((false, "Refusing to validate localhost/loopback MongoDB URIs.".to_string()));
    }

    let is_srv = uri.starts_with("mongodb+srv://");

    let mut opts = if is_srv {
        match timeout(Duration::from_millis(SRV_PARSE_MS), ClientOptions::parse(uri)).await {
            Ok(res) => res?,
            Err(_) => {
                return Ok((false, "MongoDB connection failed: timeout exceeded".to_string()));
            }
        }
    } else {
        ClientOptions::parse(uri).await?
    };

    if !is_srv {
        opts.direct_connection = Some(true);
        opts.connect_timeout = Some(Duration::from_millis(FAST_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(FAST_SELECT_MS));
    } else {
        opts.connect_timeout = Some(Duration::from_millis(SRV_CONNECT_MS));
        opts.server_selection_timeout = Some(Duration::from_millis(SRV_SELECT_MS));
    }
    opts.max_pool_size = Some(1);
    opts.min_pool_size = Some(0);

    if lax_tls {
        debug!("Using lax TLS mode for MongoDB connection");
        let tls_options = TlsOptions::builder().allow_invalid_certificates(true).build();
        opts.tls = Some(Tls::Enabled(tls_options));
    }

    let client = Client::with_options(opts)?;
    let res = client.database("admin").run_command(doc! { "ping": 1 }).await;
    match res {
        Ok(_) => Ok((true, "MongoDB connection is valid.".to_string())),
        Err(e) => {
            let msg = match *e.kind {
                ErrorKind::ServerSelection { .. } => {
                    "MongoDB connection failed: timeout exceeded".to_string()
                }
                _ => "MongoDB connection failed.".to_string(),
            };
            Ok((false, msg))
        }
    }
}

/// Return a stable cache key for the given MongoDB URI.
pub fn generate_mongodb_cache_key(mongodb_uri: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(mongodb_uri.as_bytes());
    format!("MongoDB:{}", hex::encode(hasher.finalize()))
}
