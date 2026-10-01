use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use h2::client;
use http::{HeaderMap, HeaderValue, Request, Uri, header::HeaderName};
use std::sync::OnceLock;

use liquid::Object;
use reqwest::Url;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Result of a gRPC unary call over HTTP/2.
pub struct GrpcCallResult {
    pub http_status: http::StatusCode,
    /// Response headers + trailers merged into one map.
    pub headers: HeaderMap,
    pub body_bytes: Vec<u8>,
}

fn build_root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        // Best-effort: still proceed if we got any certs.
        // (Some platforms may have a few unparsable roots.)
    }
    for cert in native.certs {
        roots.add(cert).map_err(|e| anyhow!("Failed to add native root cert: {e:?}"))?;
    }
    Ok(roots)
}

fn cached_h2_tls_config() -> Result<Arc<ClientConfig>> {
    static TLS_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

    if let Some(cfg) = TLS_CONFIG.get() {
        return Ok(Arc::clone(cfg));
    }
    // Loading native roots can be relatively expensive; do it once and reuse.
    let mut cfg =
        ClientConfig::builder().with_root_certificates(build_root_store()?).with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let cfg = Arc::new(cfg);
    // Another thread may have raced us; that's fine — just use whoever won.
    Ok(Arc::clone(TLS_CONFIG.get_or_init(|| cfg)))
}

fn url_to_h2_uri(url: &Url) -> Result<Uri> {
    let scheme = url.scheme();
    if scheme != "https" {
        return Err(anyhow!("gRPC validation only supports https URLs, got: {scheme}"));
    }
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let authority = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let path_and_query = &url[url::Position::BeforePath..];
    Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .context("Failed to build HTTP/2 URI for gRPC request")
}

fn header_map_from_templates(
    templates: &BTreeMap<String, String>,
    parser: &liquid::Parser,
    globals: &Object,
) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();
    for (k, v_template) in templates {
        // Header names in YAML are expected to be static.
        let name = HeaderName::from_bytes(k.as_bytes())
            .with_context(|| format!("Invalid header name in GrpcValidation: '{k}'"))?;

        let tmpl = parser
            .parse(v_template)
            .map_err(|e| anyhow!("Failed to parse header template '{k}': {e}"))?;
        let rendered = tmpl
            .render(globals)
            .map_err(|e| anyhow!("Failed to render header template '{k}': {e}"))?;

        let value = HeaderValue::from_str(&rendered)
            .with_context(|| format!("Invalid header value for '{k}'"))?;
        out.append(name, value);
    }
    Ok(out)
}

/// Execute a single unary gRPC request over HTTP/2 and return headers + trailers.
///
/// This is intentionally low-level so that rules can validate gRPC-only APIs
/// without pretending they are REST endpoints.
pub async fn grpc_unary_call(
    url: &Url,
    headers: HeaderMap,
    body: Vec<u8>,
    timeout: Duration,
) -> Result<GrpcCallResult> {
    let uri = url_to_h2_uri(url)?;
    let host = url.host_str().ok_or_else(|| anyhow!("URL is missing host: {url}"))?;
    let port = url.port_or_known_default().unwrap_or(443);

    let addr = format!("{host}:{port}");
    let tcp = super::limits::timeout(timeout, TcpStream::connect(addr))
        .await
        .context("Timed out connecting to gRPC host")?
        .context("Failed to connect to gRPC host")?;

    let connector = TlsConnector::from(cached_h2_tls_config()?);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("Invalid TLS server name: {host}"))?;

    let tls = super::limits::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .context("Timed out during TLS handshake")?
        .context("TLS handshake failed")?;

    let (mut h2_client, connection) = super::limits::timeout(timeout, client::handshake(tls))
        .await
        .context("Timed out during HTTP/2 handshake")?
        .context("HTTP/2 handshake failed")?;

    // Drive the HTTP/2 connection in the background.
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _driver = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));

    let mut req_builder = Request::builder().method("POST").uri(uri);
    {
        let hdrs = req_builder.headers_mut().expect("headers_mut should exist");
        for (k, v) in headers.iter() {
            hdrs.append(k, v.clone());
        }
    }

    let request = req_builder.body(()).context("Failed to build HTTP/2 request")?;

    let (response_future, mut send_stream) =
        h2_client.send_request(request, false).context("Failed to send gRPC request headers")?;

    // Send gRPC request bytes (including the 5-byte gRPC frame prefix).
    send_stream.send_data(Bytes::from(body), true).context("Failed to send gRPC request body")?;

    let response = super::limits::timeout(timeout, response_future)
        .await
        .context("Timed out waiting for gRPC response headers")?
        .context("Failed to receive gRPC response headers")?;

    let http_status = response.status();
    let (parts, mut recv_stream) = response.into_parts();
    let mut merged_headers = parts.headers;

    // Read data frames (may be empty).
    let mut body_bytes: Vec<u8> = Vec::new();
    loop {
        // h2 returns `Option<Result<Bytes, h2::Error>>` here:
        // - None => end of stream
        // - Some(Ok(bytes)) => a data chunk
        // - Some(Err(err)) => stream error
        let next_opt = super::limits::timeout(timeout, recv_stream.data())
            .await
            .context("Timed out reading gRPC response data")?;

        match next_opt {
            Some(Ok(b)) => {
                if !super::limits::NetworkLimits::current().unlimited_response
                    && body_bytes.len().saturating_add(b.len()) > (1 << 20)
                {
                    return Err(anyhow!("gRPC validation response exceeded size limit"));
                }
                body_bytes.extend_from_slice(b.as_ref());
                recv_stream.flow_control().release_capacity(b.len())?;
            }
            Some(Err(e)) => return Err(anyhow!("Error reading gRPC response data: {e}")),
            None => break,
        }
    }

    // Read trailers (where grpc-status is typically reported).
    if let Some(trailers) = super::limits::timeout(timeout, recv_stream.trailers())
        .await
        .context("Timed out reading gRPC response trailers")?
        .context("Error reading gRPC response trailers")?
    {
        for (k, v) in trailers.iter() {
            merged_headers.append(k, v.clone());
        }
    }

    Ok(GrpcCallResult { http_status, headers: merged_headers, body_bytes })
}

/// Helper to render & execute a gRPC request from rule templates.
pub async fn grpc_unary_call_from_rule(
    url: &Url,
    header_templates: &BTreeMap<String, String>,
    body_template: &Option<String>,
    parser: &liquid::Parser,
    globals: &Object,
    timeout: Duration,
) -> Result<GrpcCallResult> {
    let headers = header_map_from_templates(header_templates, parser, globals)?;
    let body = match body_template {
        Some(t) => {
            let tmpl =
                parser.parse(t).map_err(|e| anyhow!("Failed to parse gRPC body template: {e}"))?;
            let rendered = tmpl
                .render(globals)
                .map_err(|e| anyhow!("Failed to render gRPC body template: {e}"))?;
            rendered.into_bytes()
        }
        None => Vec::new(),
    };

    grpc_unary_call(url, headers, body, timeout).await
}
