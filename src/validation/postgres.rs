use std::{str::FromStr, time::Duration};

use anyhow::{anyhow, Result};
use rustls::{client::ClientConfig, RootCertStore};
use rustls_native_certs::{load_native_certs, CertificateResult};
use sha1::{Digest, Sha1};
use tokio::time::{error::Elapsed, timeout};
use tokio_postgres::{config::SslMode, tls::NoTls, Config, Error};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::debug;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn generate_postgres_cache_key(postgres_url: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(postgres_url.as_bytes());
    format!("Postgres:{:x}", hasher.finalize())
}

pub async fn validate_postgres(postgres_url: &str) -> Result<(bool, Vec<String>)> {
    let mut cfg =
        Config::from_str(postgres_url).map_err(|e| anyhow!("Failed to parse Postgres URL: {e}"))?;

    let original_mode = cfg.get_ssl_mode();
    if original_mode == SslMode::Prefer {
        cfg.ssl_mode(SslMode::Disable);
    }

    check_postgres_db_connection(cfg, original_mode).await
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
