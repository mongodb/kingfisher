use std::{net::IpAddr, time::Duration};

use anyhow::{Result, anyhow};
use mysql_async::{Conn, Opts, OptsBuilder, SslOpts, prelude::Queryable};
use tokio::time::{error::Elapsed, timeout};
use tracing::debug;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn parse_mysql_url(mysql_url: &str) -> Result<Opts> {
    let trimmed = mysql_url.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("MySQL URL is empty"));
    }

    if !trimmed.to_ascii_lowercase().starts_with("mysql://") {
        return Err(anyhow!("MySQL URL must start with mysql://"));
    }

    let parsed = Url::parse(trimmed).map_err(|e| anyhow!("Failed to parse MySQL URL: {e}"))?;

    if parsed.username().is_empty() {
        return Err(anyhow!("MySQL URL is missing a username"));
    }

    if parsed.password().map(str::is_empty).unwrap_or(true) {
        return Err(anyhow!("MySQL URL is missing a password"));
    }

    if parsed.host_str().map(str::is_empty).unwrap_or(true)
        && !parsed.query_pairs().any(|(k, _)| k == "socket")
    {
        return Err(anyhow!("MySQL URL is missing a host"));
    }

    let opts = Opts::from_url(trimmed).map_err(|e| anyhow!("Failed to parse MySQL URL: {e}"))?;

    if opts.user().map(str::is_empty).unwrap_or(true) {
        return Err(anyhow!("MySQL URL is missing a username"));
    }

    if opts.pass().map(str::is_empty).unwrap_or(true) {
        return Err(anyhow!("MySQL URL is missing a password"));
    }

    if opts.ip_or_hostname().is_empty() && opts.socket().is_none() {
        return Err(anyhow!("MySQL URL is missing a host"));
    }

    Ok(opts)
}

pub fn generate_mysql_cache_key(mysql_url: &str) -> String {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(mysql_url.as_bytes());
    format!("MySQL:{}", hex::encode(hasher.finalize()))
}

fn is_local_host(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']').trim();
    let lower = host.to_ascii_lowercase();

    if matches!(
        lower.as_str(),
        "localhost"
            | "localhost.localdomain"
            | "localhost6"
            | "localhost6.localdomain6"
            | "ip6-localhost"
            | "ip6-loopback"
    ) {
        return true;
    }

    if matches!(lower.as_str(), "0.0.0.0" | "::") {
        return true;
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }

    false
}

fn targets_localhost(opts: &Opts) -> bool {
    if opts.socket().is_some() {
        return true;
    }

    is_local_host(opts.ip_or_hostname())
}

/// Validate a MySQL connection URL.
pub async fn validate_mysql(mysql_url: &str, lax_tls: bool) -> Result<(bool, Vec<String>)> {
    let opts = parse_mysql_url(mysql_url)?;

    if targets_localhost(&opts) {
        debug!("Skipping MySQL validation: host is localhost/loopback or unix socket");
        return Ok((false, vec!["skipped localhost/loopback host".into()]));
    }

    let mut builder = OptsBuilder::from_opts(opts).stmt_cache_size(Some(0));

    if lax_tls {
        debug!("Using lax TLS mode for MySQL connection");
        let ssl_opts = SslOpts::default().with_danger_accept_invalid_certs(true);
        builder = builder.ssl_opts(Some(ssl_opts));
    }

    let opts: Opts = builder.into();

    let host = opts.ip_or_hostname().to_string();
    let db_name = opts.db_name().map(|s| s.to_string()).unwrap_or_else(|| "mysql".to_string());
    let user = opts.user().map(|s| s.to_string()).unwrap_or_else(|| "<unknown>".to_string());

    let res: Result<Result<(), mysql_async::Error>, Elapsed> = timeout(CONNECT_TIMEOUT, async {
        let mut conn = Conn::new(opts).await?;
        conn.query_drop("SELECT 1").await?;
        conn.disconnect().await?;
        Ok(())
    })
    .await;

    match res {
        Ok(Ok(())) => Ok((
            true,
            vec![format!("user={user}"), format!("host={host}"), format!("database={db_name}")],
        )),
        Ok(Err(e)) => Err(anyhow!("MySQL connection failed: {e}")),
        Err(_) => Err(anyhow!("MySQL connection timed out after {CONNECT_TIMEOUT:?}")),
    }
}
