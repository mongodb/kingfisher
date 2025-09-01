use std::{str::FromStr, sync::Once, time::Duration};

use anyhow::{anyhow, Result};
use rustls::crypto::{ring, CryptoProvider};
use rustls::{client::ClientConfig, RootCertStore};
use rustls_native_certs::{load_native_certs, CertificateResult};
use sha1::{Digest, Sha1};
use tokio::time::{error::Elapsed, timeout};
use tokio_postgres::{
    config::{Host, SslMode},
    tls::NoTls,
    Config, Error,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::debug;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static INIT_PROVIDER: Once = Once::new();
fn ensure_crypto_provider() {
    INIT_PROVIDER.call_once(|| {
        // If another part of the program already installed a provider,
        // ignore the error — we just need one global provider.
        let _ = CryptoProvider::install_default(ring::default_provider());
    });
}

pub fn generate_postgres_cache_key(postgres_url: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(postgres_url.as_bytes());
    format!("Postgres:{:x}", hasher.finalize())
}

pub async fn validate_postgres(postgres_url: &str) -> Result<(bool, Vec<String>)> {
    let mut cfg =
        Config::from_str(postgres_url).map_err(|e| anyhow!("Failed to parse Postgres URL: {e}"))?;

    // --- skip localhost/loopback/unix-socket targets entirely -------------
    if has_any_local_host(&cfg) {
        debug!("Skipping Postgres validation: host is localhost/loopback or unix socket");
        return Ok((false, vec!["skipped localhost/loopback host".into()]));
    }

    let original_mode = cfg.get_ssl_mode();
    if original_mode == SslMode::Prefer {
        cfg.ssl_mode(SslMode::Disable);
    }

    check_postgres_db_connection(cfg, original_mode).await
}

fn has_any_local_host(cfg: &Config) -> bool {
    cfg.get_hosts().iter().any(|h| match h {
        #[cfg(unix)]
        Host::Unix(_) => true, // local unix socket
        Host::Tcp(s) => is_local_tcp_host(s),
    })
}

fn is_local_tcp_host(s: &str) -> bool {
    // strip URI-style IPv6 brackets if present
    let host = s.trim_matches(|c| c == '[' || c == ']');

    // Direct IPs
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_unspecified() || v4.is_link_local()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local()
            }
        };
    }

    // Common localhost hostnames
    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower.starts_with("localhost.")
        || lower == "localhost6"
        || lower.starts_with("localhost6.")
}

async fn check_postgres_db_connection(
    mut cfg: Config,
    original_mode: SslMode,
) -> Result<(bool, Vec<String>)> {
    // First attempt with caller-supplied sslmode, optional retry without TLS.
    for attempt in 0..=1 {
        let cfg_try = cfg.clone();

        let res: Result<Result<(), Error>, Elapsed> = if cfg_try.get_ssl_mode() == SslMode::Disable
        {
            timeout(CONNECT_TIMEOUT, async {
                let (client, connection) = cfg_try.connect(NoTls).await?;
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("Postgres connection error: {e}");
                    }
                });
                client.batch_execute("SELECT 1").await?;
                Ok(())
            })
            .await
        } else {
            timeout(CONNECT_TIMEOUT, async {
                // Ensure Rustls crypto provider is installed *before* using the builder
                ensure_crypto_provider();

                let CertificateResult { certs, errors, .. } = load_native_certs();
                for err in errors {
                    debug!("native-cert error: {err}");
                }

                let mut roots = RootCertStore::empty();
                let _ = roots.add_parsable_certificates(certs);

                let tls_cfg =
                    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
                let tls = MakeRustlsConnect::new(tls_cfg);

                let (client, connection) = cfg_try.connect(tls).await?;
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        debug!("Postgres connection error: {e}");
                    }
                });
                client.batch_execute("SELECT 1").await?;
                Ok(())
            })
            .await
        };

        match res {
            Ok(Ok(())) => return Ok((true, Vec::new())),

            Ok(Err(e))
                if attempt == 0
                    && e.to_string().contains("sslmode")
                    && original_mode != SslMode::Disable =>
            {
                debug!("SSL-related error: {e}; retrying without SSL");
                cfg.ssl_mode(SslMode::Disable);
                continue;
            }

            Ok(Err(e))
                if attempt == 0
                    && server_requires_encryption(&e.to_string())
                    && cfg.get_ssl_mode() == SslMode::Disable =>
            {
                debug!("Encryption required: {e}; retrying with SSL");
                cfg.ssl_mode(SslMode::Require);
                continue;
            }

            Ok(Err(e)) if missing_cluster_identifier(&e.to_string()) => {
                debug!("Missing cluster identifier: {e}; treating as valid");
                return Ok((true, Vec::new()));
            }

            Ok(Err(e)) if database_not_exists(&e, cfg.get_dbname().unwrap_or("postgres")) => {
                return Ok((true, Vec::new()));
            }

            Ok(Err(e)) => return Err(anyhow!("Postgres connection failed: {e}")),

            Err(_) => {
                return Err(anyhow!("Postgres connection timed out after {CONNECT_TIMEOUT:?}"))
            }
        }
    }

    unreachable!();
}

fn database_not_exists(err: &Error, db_name: &str) -> bool {
    let db = if db_name.is_empty() { "postgres" } else { db_name };
    err.to_string().contains(&format!("database \"{db}\" does not exist"))
}

fn server_requires_encryption(err_msg: &str) -> bool {
    err_msg.contains("server requires encryption")
}

fn missing_cluster_identifier(err_msg: &str) -> bool {
    err_msg.contains("missing cluster identifier")
}

#[cfg(test)]
mod tests {
    use super::{is_local_tcp_host, missing_cluster_identifier, server_requires_encryption};

    #[test]
    fn detects_encryption_requirement() {
        assert!(server_requires_encryption("db error: FATAL: server requires encryption"));
        assert!(!server_requires_encryption("some other error"));
    }

    #[test]
    fn detects_missing_cluster() {
        assert!(missing_cluster_identifier(
            "db error: FATAL: codeParamsRoutingFailed: missing cluster identifier",
        ));
        assert!(!missing_cluster_identifier("another error"));
    }

    #[test]
    fn detects_local_hosts() {
        for h in [
            "localhost",
            "LOCALHOST",
            "localhost.localdomain",
            "localhost6",
            "127.0.0.1",
            "[::1]",
            "::",
        ] {
            assert!(is_local_tcp_host(h), "should treat {h} as local");
        }
        for h in ["db.example.com", "10.0.0.1"] {
            assert!(!is_local_tcp_host(h), "should not treat {h} as local");
        }
    }
}
