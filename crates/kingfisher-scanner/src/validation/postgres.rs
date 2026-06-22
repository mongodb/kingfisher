use std::{
    str::FromStr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme, client::ClientConfig};
use rustls_native_certs::{CertificateResult, load_native_certs};
use sha1::{Digest, Sha1};
use tokio::time::{error::Elapsed, timeout};
use tokio_postgres::{
    Config, Error,
    config::{Host, SslMode},
    tls::NoTls,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use tracing::debug;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static INIT_PROVIDER: OnceLock<()> = OnceLock::new();
fn ensure_crypto_provider() {
    INIT_PROVIDER.get_or_init(|| {
        let _ = CryptoProvider::install_default(ring::default_provider());
    });
}

#[derive(Debug)]
struct LaxCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for LaxCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub fn generate_postgres_cache_key(postgres_url: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(postgres_url.as_bytes());
    format!("Postgres:{}", hex::encode(hasher.finalize()))
}

pub fn parse_postgres_url(postgres_url: &str) -> Result<Config> {
    match Config::from_str(postgres_url) {
        Ok(cfg) => Ok(cfg),
        Err(e) => {
            if let Some(rest) = postgres_url.strip_prefix("postgis://") {
                let fallback = format!("postgres://{rest}");
                Config::from_str(&fallback)
                    .map_err(|_| anyhow!("Failed to parse Postgres URL: {e}"))
            } else {
                Err(anyhow!("Failed to parse Postgres URL: {e}"))
            }
        }
    }
}

/// Validate a Postgres connection URL.
pub async fn validate_postgres(postgres_url: &str, lax_tls: bool) -> Result<(bool, Vec<String>)> {
    let mut cfg = parse_postgres_url(postgres_url)?;

    if has_any_local_host(&cfg) {
        debug!("Skipping Postgres validation: host is localhost/loopback or unix socket");
        return Ok((false, vec!["skipped localhost/loopback host".into()]));
    }

    let original_mode = cfg.get_ssl_mode();
    if original_mode == SslMode::Prefer {
        cfg.ssl_mode(SslMode::Disable);
    }

    check_postgres_db_connection(cfg, original_mode, lax_tls).await
}

fn has_any_local_host(cfg: &Config) -> bool {
    cfg.get_hosts().iter().any(|h| match h {
        #[cfg(unix)]
        Host::Unix(_) => true,
        Host::Tcp(s) => is_local_tcp_host(s),
    })
}

fn is_local_tcp_host(s: &str) -> bool {
    let host = s.trim_matches(|c| c == '[' || c == ']');

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

    let lower = host.to_ascii_lowercase();
    lower == "localhost"
        || lower.starts_with("localhost.")
        || lower == "localhost6"
        || lower.starts_with("localhost6.")
}

async fn check_postgres_db_connection(
    mut cfg: Config,
    original_mode: SslMode,
    lax_tls: bool,
) -> Result<(bool, Vec<String>)> {
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
                ensure_crypto_provider();

                let tls_cfg = if lax_tls {
                    debug!("Using lax TLS mode for Postgres connection");
                    let provider = Arc::new(ring::default_provider());
                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(LaxCertVerifier(provider)))
                        .with_no_client_auth()
                } else {
                    let CertificateResult { certs, errors, .. } = load_native_certs();
                    for err in errors {
                        debug!("native-cert error: {err}");
                    }

                    let mut roots = RootCertStore::empty();
                    let _ = roots.add_parsable_certificates(certs);

                    ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
                };
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
                return Err(anyhow!("Postgres connection timed out after {CONNECT_TIMEOUT:?}"));
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
