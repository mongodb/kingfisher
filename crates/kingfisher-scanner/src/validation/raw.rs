//! Provider-specific raw validators for secret formats that need custom protocol logic.

use std::{
    collections::BTreeSet,
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac, digest::KeyInit};
use http::StatusCode;
use ldap3::LdapConnSettings;
use liquid::Object;
use liquid_core::ValueView;
use percent_encoding::percent_decode_str;
use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256, Sha512};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use url::Url;

use crate::validation::http_validation::check_url_resolvable;

pub struct RawValidationOutcome {
    pub valid: bool,
    pub status: StatusCode,
    pub body: String,
}

static INIT_PROVIDER: OnceLock<()> = OnceLock::new();
static LAX_PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();

fn ensure_crypto_provider() {
    INIT_PROVIDER.get_or_init(|| {
        let _ = CryptoProvider::install_default(aws_lc_rs::default_provider());
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

pub fn required_vars(kind: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    vars.insert("TOKEN".to_string());

    match kind {
        "azurebatch" => {
            vars.insert("BATCH_URL".to_string());
        }
        "gcs_hmac" => {
            vars.insert("GCS_ACCESS_ID".to_string());
        }
        "kraken" => {
            vars.insert("KRAKEN_API_KEY".to_string());
        }
        _ => {}
    }

    vars
}

pub async fn validate_raw(
    kind: &str,
    globals: &Object,
    client: &Client,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<RawValidationOutcome> {
    if let Some(url) = raw_validation_target_url(kind, globals)? {
        let resolvable = check_url_resolvable(&url, allow_internal_ips).await;
        if let Err(e) = resolvable {
            return Ok(RawValidationOutcome {
                valid: false,
                status: StatusCode::PRECONDITION_REQUIRED,
                body: format!(
                    "Validation skipped - raw validation target blocked or not resolvable: {e}"
                ),
            });
        }
    }

    match kind {
        "azurebatch" => validate_azure_batch(globals, client).await,
        "ftp" => validate_ftp(globals, use_lax_tls).await,
        "gcp_adc" => validate_gcp_adc(globals, client).await,
        "gcp_api_key" => validate_gcp_api_key(globals, client).await,
        "gcs_hmac" => validate_gcs_hmac(globals, client).await,
        "kraken" => validate_kraken(globals, client).await,
        "ldap" => validate_ldap(globals, use_lax_tls).await,
        "rabbitmq" => validate_rabbitmq(globals, use_lax_tls).await,
        "redis" => validate_redis(globals, use_lax_tls).await,
        other => Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::NOT_IMPLEMENTED,
            body: format!("Raw validator `{other}` is not implemented."),
        }),
    }
}

fn raw_validation_target_url(kind: &str, globals: &Object) -> Result<Option<Url>> {
    match kind {
        "azurebatch" => string_var(globals, "BATCH_URL")
            .map(|s| Url::parse(&s).context("invalid BATCH_URL"))
            .transpose(),
        "gcp_api_key" => Ok(Some(
            Url::parse(
                "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig",
            )
            .expect("static GCP validation URL must parse"),
        )),
        "gcp_adc" => {
            let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
            let value: serde_json::Value =
                serde_json::from_str(&token).context("GCP ADC is not valid JSON")?;
            let endpoint = allowed_gcp_token_endpoint(value["token_uri"].as_str())?;
            Ok(Some(Url::parse(endpoint).expect("allowed GCP validation URL must parse")))
        }
        "gcs_hmac" => Ok(Some(
            Url::parse("https://storage.googleapis.com/")
                .expect("static GCS validation URL must parse"),
        )),
        "ftp" | "ldap" | "rabbitmq" | "redis" => string_var(globals, "TOKEN")
            .map(|s| Url::parse(&s).context("invalid raw validation URI"))
            .transpose(),
        _ => Ok(None),
    }
}

fn string_var(globals: &Object, name: &str) -> Option<String> {
    globals.get(name).map(|v| v.to_kstr().to_string()).filter(|s| !s.is_empty())
}

fn decode_userinfo(input: &str) -> String {
    percent_decode_str(input).decode_utf8_lossy().to_string()
}

fn current_unix_millis() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis()
        .to_string()
}

fn rfc1123_now() -> String {
    chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn build_root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert).map_err(|e| anyhow!("failed to add native root cert: {e:?}"))?;
    }
    Ok(roots)
}

fn lax_provider() -> Arc<CryptoProvider> {
    LAX_PROVIDER.get_or_init(|| Arc::new(aws_lc_rs::default_provider())).clone()
}

fn tls_connector(use_lax_tls: bool) -> Result<TlsConnector> {
    let cfg = if use_lax_tls {
        ensure_crypto_provider();
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(LaxCertVerifier(lax_provider())))
            .with_no_client_auth()
    } else {
        ClientConfig::builder().with_root_certificates(build_root_store()?).with_no_client_auth()
    };
    Ok(TlsConnector::from(Arc::new(cfg)))
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type DynStream = Box<dyn AsyncStream>;

async fn connect_plain(host: &str, port: u16) -> Result<DynStream> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
        .await
        .context("connection timed out")??;
    Ok(Box::new(stream))
}

async fn connect_tls(host: &str, port: u16, use_lax_tls: bool) -> Result<DynStream> {
    let stream = timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
        .await
        .context("connection timed out")??;
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|_| anyhow!("invalid TLS host: {host}"))?;
    let tls =
        timeout(Duration::from_secs(10), tls_connector(use_lax_tls)?.connect(server_name, stream))
            .await
            .context("TLS handshake timed out")??;
    Ok(Box::new(tls))
}

async fn connect_from_url(
    url: &Url,
    tls_default_port: u16,
    plain_default_port: u16,
    use_lax_tls: bool,
) -> Result<DynStream> {
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host"))?;
    let tls = matches!(url.scheme(), "ftps" | "amqps" | "rediss" | "ldaps");
    let port = url.port().unwrap_or(if tls { tls_default_port } else { plain_default_port });
    if tls { connect_tls(host, port, use_lax_tls).await } else { connect_plain(host, port).await }
}

async fn validate_azure_batch(globals: &Object, client: &Client) -> Result<RawValidationOutcome> {
    let endpoint = string_var(globals, "BATCH_URL").ok_or_else(|| anyhow!("missing BATCH_URL"))?;
    let account_key = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let parsed = Url::parse(&endpoint).context("invalid BATCH_URL")?;
    let host = parsed.host_str().ok_or_else(|| anyhow!("BATCH_URL is missing host"))?;
    let account_name = host
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("failed to derive Batch account name from host"))?;

    let api_version = "2020-09-01.12.0";
    let url = format!("{endpoint}/applications?api-version={api_version}");
    let date = rfc1123_now();
    let string_to_sign = format!(
        "GET\n\n\n\n\napplication/json\n{}\n\n\n\n\n\n{}\napi-version:{}",
        date,
        format!("/{account_name}/applications").to_lowercase(),
        api_version
    );

    let key = B64.decode(account_key.as_bytes()).context("Azure Batch key is not valid base64")?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
        .map_err(|e| anyhow!("invalid HMAC key: {e}"))?;
    mac.update(string_to_sign.as_bytes());
    let signature = B64.encode(mac.finalize().into_bytes());

    let resp = client
        .get(&url)
        .header("Content-Type", "application/json")
        .header("Date", &date)
        .header("Authorization", format!("SharedKey {account_name}:{signature}"))
        .send()
        .await
        .context("Azure Batch validation request failed")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let valid = status == StatusCode::OK;

    Ok(RawValidationOutcome { valid, status, body })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GcpApiKeyProbeVerdict {
    Active,
    Inactive,
    Inconclusive,
}

fn classify_gcp_api_key_probe(status: StatusCode, body: &str) -> GcpApiKeyProbeVerdict {
    if status == StatusCode::OK {
        return GcpApiKeyProbeVerdict::Active;
    }

    // Both the Identity Toolkit and Generative Language APIs use HTTP 400 for a
    // syntactically well-formed key that Google does not recognize. Betterleaks
    // uses the same distinction for its GCP API-key validator.
    if status == StatusCode::BAD_REQUEST
        && (body.contains("API_KEY_INVALID")
            || body.contains("API key not valid")
            || body.contains("INVALID_ARGUMENT"))
    {
        return GcpApiKeyProbeVerdict::Inactive;
    }

    // Application and API restrictions are evaluated only after Google has
    // recognized the key. A 403 therefore proves liveness even though the
    // scanner's request is not authorized for this particular API or origin.
    if status == StatusCode::FORBIDDEN {
        return GcpApiKeyProbeVerdict::Active;
    }

    GcpApiKeyProbeVerdict::Inconclusive
}

async fn run_gcp_api_key_probe(
    client: &Client,
    url: &str,
    token: &str,
) -> Result<(StatusCode, String)> {
    let response = client
        .get(url)
        .query(&[("key", token)])
        .send()
        .await
        .context("GCP API-key validation request failed")?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Ok((status, body))
}

fn gcp_api_key_active_summary(
    service: &str,
    status: StatusCode,
    prior_probe: Option<(&str, StatusCode)>,
) -> String {
    let result = if status == StatusCode::OK { "accepted" } else { "recognized but restricted" };
    let mut summary =
        format!("Google API key is active. {service} {result} the key (HTTP {status}).");
    if let Some((prior_service, prior_status)) = prior_probe {
        summary.push_str(&format!(
            " The earlier {prior_service} probe was inconclusive (HTTP {prior_status})."
        ));
    }
    summary
}

fn gcp_api_key_inactive_summary(
    service: &str,
    status: StatusCode,
    prior_probe: Option<(&str, StatusCode)>,
) -> String {
    let mut summary = format!("Google rejected the API key as invalid ({service}: HTTP {status}).");
    if let Some((prior_service, prior_status)) = prior_probe {
        summary.push_str(&format!(
            " The earlier {prior_service} probe was inconclusive (HTTP {prior_status})."
        ));
    }
    summary
}

async fn validate_gcp_api_key(globals: &Object, client: &Client) -> Result<RawValidationOutcome> {
    const PROJECT_CONFIG_URL: &str =
        "https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig";
    const GEMINI_MODELS_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";

    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let (project_status, project_body) =
        run_gcp_api_key_probe(client, PROJECT_CONFIG_URL, &token).await?;
    match classify_gcp_api_key_probe(project_status, &project_body) {
        GcpApiKeyProbeVerdict::Active => {
            return Ok(RawValidationOutcome {
                valid: true,
                status: project_status,
                body: gcp_api_key_active_summary("Identity Toolkit", project_status, None),
            });
        }
        GcpApiKeyProbeVerdict::Inactive => {
            return Ok(RawValidationOutcome {
                valid: false,
                status: StatusCode::UNAUTHORIZED,
                body: gcp_api_key_inactive_summary("Identity Toolkit", project_status, None),
            });
        }
        GcpApiKeyProbeVerdict::Inconclusive => {}
    }

    // Fall back to a second read-only Google API. This covers transient or
    // endpoint-specific responses without treating arbitrary JSON as proof of
    // either liveness or revocation.
    let (gemini_status, gemini_body) =
        run_gcp_api_key_probe(client, GEMINI_MODELS_URL, &token).await?;
    match classify_gcp_api_key_probe(gemini_status, &gemini_body) {
        GcpApiKeyProbeVerdict::Active => Ok(RawValidationOutcome {
            valid: true,
            status: gemini_status,
            body: gcp_api_key_active_summary(
                "Generative Language API",
                gemini_status,
                Some(("Identity Toolkit", project_status)),
            ),
        }),
        GcpApiKeyProbeVerdict::Inactive => Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::UNAUTHORIZED,
            body: gcp_api_key_inactive_summary(
                "Generative Language API",
                gemini_status,
                Some(("Identity Toolkit", project_status)),
            ),
        }),
        GcpApiKeyProbeVerdict::Inconclusive => Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::BAD_GATEWAY,
            body: format!(
                "Google API-key validation was inconclusive (Identity Toolkit: HTTP {project_status}; Generative Language API: HTTP {gemini_status}).\nIdentity Toolkit response:\n{project_body}\n\nGenerative Language response:\n{gemini_body}"
            ),
        }),
    }
}

fn allowed_gcp_token_endpoint(value: Option<&str>) -> Result<&'static str> {
    match value.unwrap_or("https://oauth2.googleapis.com/token") {
        "https://oauth2.googleapis.com/token" => Ok("https://oauth2.googleapis.com/token"),
        "https://accounts.google.com/o/oauth2/token" => {
            Ok("https://accounts.google.com/o/oauth2/token")
        }
        other => Err(anyhow!("GCP token_uri is not an allowed Google OAuth endpoint: {other}")),
    }
}

async fn validate_gcp_adc(globals: &Object, client: &Client) -> Result<RawValidationOutcome> {
    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let value: serde_json::Value =
        serde_json::from_str(&token).context("GCP ADC is not valid JSON")?;
    let client_id = value["client_id"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("GCP ADC is missing client_id"))?;
    let client_secret = value["client_secret"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("GCP ADC is missing client_secret"))?;
    let refresh_token = value["refresh_token"]
        .as_str()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("GCP ADC is missing refresh_token"))?;
    let endpoint = allowed_gcp_token_endpoint(value["token_uri"].as_str())?;

    let response = client
        .post(endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("GCP ADC validation request failed")?;
    let remote_status = response.status();
    let body = response.text().await.unwrap_or_default();

    Ok(classify_gcp_adc_response(remote_status, &body))
}

fn classify_gcp_adc_response(remote_status: StatusCode, body: &str) -> RawValidationOutcome {
    if remote_status == StatusCode::OK {
        let valid = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v["access_token"].as_str().map(|s| !s.is_empty()))
            .unwrap_or(false);
        return RawValidationOutcome {
            valid,
            status: if valid { StatusCode::OK } else { StatusCode::BAD_GATEWAY },
            // Never copy the freshly minted bearer token into a scan report.
            body: if valid {
                "Google OAuth accepted the GCP application default credentials.".to_string()
            } else {
                "Google OAuth returned HTTP 200 without an access_token.".to_string()
            },
        };
    }

    if matches!(remote_status, StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED) {
        return RawValidationOutcome {
            valid: false,
            status: StatusCode::UNAUTHORIZED,
            body: body.to_string(),
        };
    }

    RawValidationOutcome {
        valid: false,
        status: StatusCode::BAD_GATEWAY,
        body: format!("Unexpected Google OAuth response HTTP {remote_status}.\n{body}"),
    }
}

struct GcsSigV4Headers {
    amz_date: String,
    payload_hash: String,
    authorization: String,
}

fn hmac_sha256(key: &[u8], data: &str) -> Result<Vec<u8>> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|e| anyhow!("invalid HMAC-SHA256 key: {e}"))?;
    mac.update(data.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn gcs_sigv4_headers(access_id: &str, secret: &str, now: DateTime<Utc>) -> Result<GcsSigV4Headers> {
    const HOST: &str = "storage.googleapis.com";
    const REGION: &str = "auto";
    const SERVICE: &str = "s3";
    const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";

    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let payload_hash = hex::encode(Sha256::digest([]));
    let canonical_headers =
        format!("host:{HOST}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
    let canonical_request =
        format!("GET\n/\n\n{canonical_headers}\n{SIGNED_HEADERS}\n{payload_hash}");
    let canonical_request_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
    let credential_scope = format!("{date}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign =
        format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_request_hash}");

    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), &date)?;
    let region_key = hmac_sha256(&date_key, REGION)?;
    let service_key = hmac_sha256(&region_key, SERVICE)?;
    let signing_key = hmac_sha256(&service_key, "aws4_request")?;
    let signature = hex::encode(hmac_sha256(&signing_key, &string_to_sign)?);
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_id}/{credential_scope}, SignedHeaders={SIGNED_HEADERS}, Signature={signature}"
    );

    Ok(GcsSigV4Headers { amz_date, payload_hash, authorization })
}

fn classify_gcs_hmac_response(status: StatusCode, body: &str) -> RawValidationOutcome {
    if status == StatusCode::OK {
        return RawValidationOutcome {
            valid: true,
            status,
            // A successful ListBuckets response contains bucket names. They
            // prove liveness but do not belong in the scanner's report body.
            body: "GCS accepted the HMAC credentials for ListBuckets.".to_string(),
        };
    }

    if body.contains("<Code>AccessDenied</Code>") {
        return RawValidationOutcome {
            valid: true,
            status,
            body: "GCS verified the HMAC signature but denied ListBuckets access.".to_string(),
        };
    }

    if body.contains("<Code>SignatureDoesNotMatch</Code>")
        || body.contains("<Code>InvalidAccessKeyId</Code>")
    {
        return RawValidationOutcome {
            valid: false,
            status: StatusCode::UNAUTHORIZED,
            body: body.to_string(),
        };
    }

    RawValidationOutcome {
        valid: false,
        status: StatusCode::BAD_GATEWAY,
        body: format!("Unexpected GCS HMAC validation response HTTP {status}.\n{body}"),
    }
}

async fn validate_gcs_hmac(globals: &Object, client: &Client) -> Result<RawValidationOutcome> {
    let access_id =
        string_var(globals, "GCS_ACCESS_ID").ok_or_else(|| anyhow!("missing GCS_ACCESS_ID"))?;
    let secret = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let headers = gcs_sigv4_headers(&access_id, &secret, Utc::now())?;

    let response = client
        .get("https://storage.googleapis.com/")
        .header("X-Amz-Content-Sha256", headers.payload_hash)
        .header("X-Amz-Date", headers.amz_date)
        .header("Authorization", headers.authorization)
        .send()
        .await
        .context("GCS HMAC validation request failed")?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Ok(classify_gcs_hmac_response(status, &body))
}

async fn validate_ftp(globals: &Object, use_lax_tls: bool) -> Result<RawValidationOutcome> {
    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let url = Url::parse(&token).context("invalid FTP URI")?;
    let host = url.host_str().ok_or_else(|| anyhow!("FTP URI is missing host"))?;
    let username = decode_userinfo(url.username());
    let password =
        decode_userinfo(url.password().ok_or_else(|| anyhow!("FTP URI is missing password"))?);
    let scheme = url.scheme().to_ascii_lowercase();

    let mut stream = if scheme == "ftp" {
        BufStream::new(connect_plain(host, url.port().unwrap_or(21)).await?)
    } else {
        let port = url.port().unwrap_or(990);
        if url.port().unwrap_or(990) == 990 {
            BufStream::new(connect_tls(host, port, use_lax_tls).await?)
        } else {
            let tcp = timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
                .await
                .context("connection timed out")??;
            let mut plain = BufStream::new(tcp);
            let _ = read_ftp_reply(&mut plain).await?;
            plain.write_all(b"AUTH TLS\r\n").await?;
            plain.flush().await?;
            let (code, auth_body) = read_ftp_reply(&mut plain).await?;
            if code != 234 {
                return Ok(RawValidationOutcome {
                    valid: false,
                    status: StatusCode::UNAUTHORIZED,
                    body: auth_body,
                });
            }
            let tcp = plain.into_inner();
            let server_name = ServerName::try_from(host.to_string())
                .map_err(|_| anyhow!("invalid TLS host: {host}"))?;
            let tls = timeout(
                Duration::from_secs(10),
                tls_connector(use_lax_tls)?.connect(server_name, tcp),
            )
            .await
            .context("TLS handshake timed out")??;
            BufStream::new(Box::new(tls) as DynStream)
        }
    };

    let _ = read_ftp_reply(&mut stream).await?;
    stream.write_all(format!("USER {username}\r\n").as_bytes()).await?;
    stream.flush().await?;
    let (user_code, user_body) = read_ftp_reply(&mut stream).await?;
    if user_code == 230 {
        return Ok(RawValidationOutcome { valid: true, status: StatusCode::OK, body: user_body });
    }
    if user_code != 331 {
        return Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::UNAUTHORIZED,
            body: user_body,
        });
    }

    stream.write_all(format!("PASS {password}\r\n").as_bytes()).await?;
    stream.flush().await?;
    let (pass_code, pass_body) = read_ftp_reply(&mut stream).await?;
    let _ = stream.write_all(b"QUIT\r\n").await;
    let _ = stream.flush().await;

    Ok(RawValidationOutcome {
        valid: pass_code == 230,
        status: if pass_code == 230 { StatusCode::OK } else { StatusCode::UNAUTHORIZED },
        body: pass_body,
    })
}

async fn read_ftp_reply<S>(stream: &mut BufStream<S>) -> Result<(u16, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut body = String::new();
    let mut code_prefix: Option<String> = None;

    loop {
        let mut line = String::new();
        let read = timeout(Duration::from_secs(10), stream.read_line(&mut line))
            .await
            .context("FTP server did not reply in time")??;
        if read == 0 {
            return Err(anyhow!("FTP server closed the connection"));
        }

        body.push_str(&line);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.len() < 4 {
            continue;
        }

        let code = &trimmed[0..3];
        if !code.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        match trimmed.as_bytes()[3] {
            b' ' => return Ok((code.parse().unwrap_or(0), body)),
            b'-' => {
                code_prefix = Some(code.to_string());
            }
            _ => {}
        }

        if let Some(prefix) = &code_prefix
            && trimmed.starts_with(prefix)
            && trimmed.as_bytes()[3] == b' '
        {
            return Ok((code.parse().unwrap_or(0), body));
        }
    }
}

async fn validate_kraken(globals: &Object, client: &Client) -> Result<RawValidationOutcome> {
    let api_key =
        string_var(globals, "KRAKEN_API_KEY").ok_or_else(|| anyhow!("missing KRAKEN_API_KEY"))?;
    let api_secret = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let secret = B64.decode(api_secret.as_bytes()).context("Kraken secret is not valid base64")?;

    let nonce = current_unix_millis();
    let body = format!("nonce={nonce}");
    let mut sha = Sha256::new();
    sha.update(format!("{nonce}{body}").as_bytes());
    let shasum = sha.finalize();

    let path = "/0/private/Balance";
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&secret)
        .map_err(|e| anyhow!("invalid HMAC key: {e}"))?;
    let mut payload = Vec::with_capacity(path.len() + shasum.len());
    payload.extend_from_slice(path.as_bytes());
    payload.extend_from_slice(&shasum);
    mac.update(&payload);
    let signature = B64.encode(mac.finalize().into_bytes());

    let resp = client
        .post(format!("https://api.kraken.com{path}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("API-Key", api_key)
        .header("API-Sign", signature)
        .body(body)
        .send()
        .await
        .context("Kraken validation request failed")?;

    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let valid = status == StatusCode::OK && body.contains(r#""error":[]"#);

    Ok(RawValidationOutcome { valid, status, body })
}

async fn validate_ldap(globals: &Object, use_lax_tls: bool) -> Result<RawValidationOutcome> {
    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let url = Url::parse(&token).context("invalid LDAP URI")?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str().ok_or_else(|| anyhow!("LDAP URI is missing host"))?;
    let port = url.port().unwrap_or(if scheme == "ldaps" { 636 } else { 389 });
    let bind_dn = if let Some(bind_dn) = string_var(globals, "LDAP_BIND_DN") {
        bind_dn
    } else {
        decode_userinfo(url.username())
    };
    let password = if let Some(password) = string_var(globals, "LDAP_PASSWORD") {
        password
    } else {
        decode_userinfo(url.password().ok_or_else(|| anyhow!("LDAP URI is missing password"))?)
    };

    let ldap_url = format!("{scheme}://{host}:{port}");
    let settings = LdapConnSettings::new().set_no_tls_verify(use_lax_tls);
    let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &ldap_url)
        .await
        .with_context(|| format!("failed to connect to LDAP server {ldap_url}"))?;
    ldap3::drive!(conn);
    let bind_result = ldap.simple_bind(&bind_dn, &password).await;
    let _ = ldap.unbind().await;

    match bind_result {
        Ok(res) => match res.success() {
            Ok(_) => Ok(RawValidationOutcome {
                valid: true,
                status: StatusCode::OK,
                body: "LDAP bind succeeded.".to_string(),
            }),
            Err(err) => Ok(RawValidationOutcome {
                valid: false,
                status: StatusCode::UNAUTHORIZED,
                body: err.to_string(),
            }),
        },
        Err(err) => Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::BAD_GATEWAY,
            body: err.to_string(),
        }),
    }
}

async fn validate_rabbitmq(globals: &Object, use_lax_tls: bool) -> Result<RawValidationOutcome> {
    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let url = Url::parse(&token).context("invalid AMQP URI")?;
    let _host = url.host_str().ok_or_else(|| anyhow!("AMQP URI is missing host"))?;
    let username = decode_userinfo(url.username());
    let password =
        decode_userinfo(url.password().ok_or_else(|| anyhow!("AMQP URI is missing password"))?);

    let mut stream = connect_from_url(&url, 5671, 5672, use_lax_tls).await?;
    timeout(Duration::from_secs(10), stream.write_all(b"AMQP\x00\x00\x09\x01"))
        .await
        .context("failed to write AMQP protocol header")??;
    timeout(Duration::from_secs(10), stream.flush()).await.context("flush timed out")??;

    let (_, _, start_payload) = read_amqp_frame(&mut stream).await?;
    let (class_id, method_id) = amqp_method_ids(&start_payload)?;
    if class_id != 10 || method_id != 10 {
        return Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::BAD_GATEWAY,
            body: format!("unexpected AMQP frame {class_id}.{method_id}"),
        });
    }

    let start_ok = build_amqp_start_ok_frame(&username, &password);
    timeout(Duration::from_secs(10), stream.write_all(&start_ok))
        .await
        .context("failed to write AMQP start-ok frame")??;
    timeout(Duration::from_secs(10), stream.flush()).await.context("flush timed out")??;

    let (_, _, next_payload) = read_amqp_frame(&mut stream).await?;
    let (class_id, method_id) = amqp_method_ids(&next_payload)?;
    let valid = class_id == 10 && method_id == 30;
    Ok(RawValidationOutcome {
        valid,
        status: if valid { StatusCode::OK } else { StatusCode::UNAUTHORIZED },
        body: format!("received AMQP method frame {class_id}.{method_id}"),
    })
}

fn build_amqp_start_ok_frame(username: &str, password: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&10u16.to_be_bytes());
    payload.extend_from_slice(&11u16.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes()); // empty client properties table

    payload.extend_from_slice(&(5u32).to_be_bytes());
    payload.extend_from_slice(b"PLAIN");

    let mut response = Vec::with_capacity(username.len() + password.len() + 2);
    response.push(0);
    response.extend_from_slice(username.as_bytes());
    response.push(0);
    response.extend_from_slice(password.as_bytes());
    payload.extend_from_slice(&(response.len() as u32).to_be_bytes());
    payload.extend_from_slice(&response);

    payload.extend_from_slice(&(5u32).to_be_bytes());
    payload.extend_from_slice(b"en_US");

    let mut frame = Vec::with_capacity(payload.len() + 8);
    frame.push(1); // method frame
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame.push(0xCE);
    frame
}

async fn read_amqp_frame(stream: &mut DynStream) -> Result<(u8, u16, Vec<u8>)> {
    let mut header = [0u8; 7];
    timeout(Duration::from_secs(10), stream.read_exact(&mut header))
        .await
        .context("timed out while reading AMQP frame header")??;
    let frame_type = header[0];
    let channel = u16::from_be_bytes([header[1], header[2]]);
    let size = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    let mut payload = vec![0u8; size];
    timeout(Duration::from_secs(10), stream.read_exact(&mut payload))
        .await
        .context("timed out while reading AMQP frame payload")??;
    let mut end = [0u8; 1];
    timeout(Duration::from_secs(10), stream.read_exact(&mut end))
        .await
        .context("timed out while reading AMQP frame terminator")??;
    if end[0] != 0xCE {
        return Err(anyhow!("invalid AMQP frame terminator"));
    }
    Ok((frame_type, channel, payload))
}

fn amqp_method_ids(payload: &[u8]) -> Result<(u16, u16)> {
    if payload.len() < 4 {
        return Err(anyhow!("AMQP payload too short"));
    }
    Ok((u16::from_be_bytes([payload[0], payload[1]]), u16::from_be_bytes([payload[2], payload[3]])))
}

async fn validate_redis(globals: &Object, use_lax_tls: bool) -> Result<RawValidationOutcome> {
    let token = string_var(globals, "TOKEN").ok_or_else(|| anyhow!("missing TOKEN"))?;
    let url = Url::parse(&token).context("invalid Redis URI")?;
    let username = if let Some(username) = string_var(globals, "USERNAME") {
        username
    } else if !url.username().is_empty() {
        decode_userinfo(url.username())
    } else {
        String::new()
    };
    let password = if let Some(password) = string_var(globals, "PASSWORD") {
        password
    } else {
        decode_userinfo(url.password().ok_or_else(|| anyhow!("Redis URI is missing password"))?)
    };

    let mut stream = BufStream::new(connect_from_url(&url, 6380, 6379, use_lax_tls).await?);
    let auth_cmd = if username.is_empty() {
        format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password)
    } else {
        format!(
            "*3\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n${}\r\n{}\r\n",
            username.len(),
            username,
            password.len(),
            password
        )
    };
    stream.write_all(auth_cmd.as_bytes()).await?;
    stream.flush().await?;
    let auth_reply = read_resp_line(&mut stream).await?;
    if !auth_reply.starts_with("+OK") {
        return Ok(RawValidationOutcome {
            valid: false,
            status: StatusCode::UNAUTHORIZED,
            body: auth_reply,
        });
    }

    stream.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
    stream.flush().await?;
    let ping_reply = read_resp_line(&mut stream).await?;
    Ok(RawValidationOutcome {
        valid: ping_reply.starts_with("+PONG"),
        status: if ping_reply.starts_with("+PONG") {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        },
        body: ping_reply,
    })
}

async fn read_resp_line<S>(stream: &mut BufStream<S>) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut line = String::new();
    timeout(Duration::from_secs(10), stream.read_line(&mut line))
        .await
        .context("Redis server did not reply in time")??;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn gcp_api_key_probe_distinguishes_liveness_from_transport_failures() {
        assert_eq!(
            classify_gcp_api_key_probe(StatusCode::OK, r#"{"projectId":"example"}"#),
            GcpApiKeyProbeVerdict::Active
        );
        assert_eq!(
            classify_gcp_api_key_probe(StatusCode::BAD_REQUEST, r#"{"reason":"API_KEY_INVALID"}"#,),
            GcpApiKeyProbeVerdict::Inactive
        );
        assert_eq!(
            classify_gcp_api_key_probe(
                StatusCode::FORBIDDEN,
                r#"{"reason":"API_KEY_HTTP_REFERRER_BLOCKED"}"#,
            ),
            GcpApiKeyProbeVerdict::Active
        );
        assert_eq!(
            classify_gcp_api_key_probe(StatusCode::INTERNAL_SERVER_ERROR, "server error"),
            GcpApiKeyProbeVerdict::Inconclusive
        );
    }

    #[test]
    fn gcp_api_key_active_summary_leads_with_the_successful_probe() {
        assert_eq!(
            gcp_api_key_active_summary(
                "Generative Language API",
                StatusCode::OK,
                Some(("Identity Toolkit", StatusCode::UNAUTHORIZED)),
            ),
            "Google API key is active. Generative Language API accepted the key (HTTP 200 OK). The earlier Identity Toolkit probe was inconclusive (HTTP 401 Unauthorized)."
        );

        assert_eq!(
            gcp_api_key_active_summary("Generative Language API", StatusCode::FORBIDDEN, None,),
            "Google API key is active. Generative Language API recognized but restricted the key (HTTP 403 Forbidden)."
        );
    }

    #[test]
    fn gcp_adc_allows_only_google_token_endpoints() {
        assert_eq!(
            allowed_gcp_token_endpoint(None).unwrap(),
            "https://oauth2.googleapis.com/token"
        );
        assert_eq!(
            allowed_gcp_token_endpoint(Some("https://accounts.google.com/o/oauth2/token")).unwrap(),
            "https://accounts.google.com/o/oauth2/token"
        );
        assert!(
            allowed_gcp_token_endpoint(Some("https://attacker.example/token")).is_err(),
            "an ADC file must not redirect validation to an attacker-controlled token endpoint"
        );
    }

    #[test]
    fn gcp_adc_validation_does_not_report_the_minted_access_token() {
        let outcome = classify_gcp_adc_response(
            StatusCode::OK,
            r#"{"access_token":"ya29.fresh-bearer-token","token_type":"Bearer"}"#,
        );

        assert!(outcome.valid);
        assert_eq!(outcome.status, StatusCode::OK);
        assert!(!outcome.body.contains("ya29.fresh-bearer-token"));
    }

    #[test]
    fn gcs_hmac_response_classification_matches_gcs_error_semantics() {
        let list_buckets = classify_gcs_hmac_response(
            StatusCode::OK,
            "<ListAllMyBucketsResult><Name>private-bucket</Name></ListAllMyBucketsResult>",
        );
        assert!(list_buckets.valid);
        assert!(!list_buckets.body.contains("private-bucket"));
        assert!(
            classify_gcs_hmac_response(
                StatusCode::FORBIDDEN,
                "<Error><Code>AccessDenied</Code></Error>",
            )
            .valid
        );

        let invalid = classify_gcs_hmac_response(
            StatusCode::FORBIDDEN,
            "<Error><Code>SignatureDoesNotMatch</Code></Error>",
        );
        assert!(!invalid.valid);
        assert_eq!(invalid.status, StatusCode::UNAUTHORIZED);

        let unknown = classify_gcs_hmac_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "<Error><Code>SlowDown</Code></Error>",
        );
        assert!(!unknown.valid);
        assert_eq!(unknown.status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn gcs_sigv4_headers_are_deterministic_and_scoped_to_gcs() {
        let now = Utc.with_ymd_and_hms(2025, 11, 7, 18, 17, 14).unwrap();
        let headers = gcs_sigv4_headers(
            "GOOG1EXAMPLEACCESSID",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            now,
        )
        .unwrap();

        assert_eq!(headers.amz_date, "20251107T181714Z");
        assert_eq!(
            headers.payload_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert!(
            headers
                .authorization
                .contains("Credential=GOOG1EXAMPLEACCESSID/20251107/auto/s3/aws4_request")
        );
        assert!(
            headers.authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
        );
    }

    #[test]
    fn gcs_hmac_raw_validator_requires_the_access_id_pair() {
        assert_eq!(
            required_vars("gcs_hmac"),
            BTreeSet::from(["GCS_ACCESS_ID".to_string(), "TOKEN".to_string()])
        );
    }
}
