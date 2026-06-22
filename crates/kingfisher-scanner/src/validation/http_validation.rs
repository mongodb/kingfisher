use std::{collections::BTreeMap, future::Future, net::IpAddr, str::FromStr, time::Duration};

use anyhow::{Error, Result, anyhow};
use http::StatusCode;
use liquid::Object;
use liquid_core::Value;
use quick_xml::de::from_str as xml_from_str;
use reqwest::{
    Client, Method, RequestBuilder, Response, Url, header,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::de::IgnoredAny;
use sha1::{Digest, Sha1};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use tokio::{net::lookup_host, time::sleep};
use tracing::debug;

/// Error returned by [`check_url_resolvable`] when an IP address fails the
/// SSRF safety check. Callers can downcast `Box<dyn Error>` to distinguish
/// SSRF blocks from other resolution failures.
#[derive(Debug)]
pub struct SsrfBlockedError(pub String);

impl std::fmt::Display for SsrfBlockedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SsrfBlockedError {}

use super::GLOBAL_USER_AGENT;
use kingfisher_rules::ResponseMatcher;

/// Build a deterministic cache key from the immutable parts of an HTTP request.
pub fn generate_http_cache_key_parts(
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&str>,
) -> String {
    let method = method.to_uppercase();

    let mut hasher = Sha1::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\0");
    hasher.update(url.as_bytes());
    hasher.update(b"\0");

    for (k, v) in headers {
        hasher.update(k.as_bytes());
        hasher.update(b":");
        hasher.update(v.as_bytes());
        hasher.update(b"\0");
    }

    if let Some(b) = body {
        hasher.update(b"BODY\0");
        hasher.update(b.as_bytes());
        hasher.update(b"\0");
    }

    format!("HTTP:{}", hex::encode(hasher.finalize()))
}

/// Parse an HTTP method from a string.
pub fn parse_http_method(method_str: &str) -> Result<Method, String> {
    Method::from_str(method_str).map_err(|_| format!("Invalid HTTP method: {}", method_str))
}

fn format_rfc1123(now: OffsetDateTime) -> String {
    let rendered =
        now.format(&Rfc2822).unwrap_or_else(|_| "Thu, 01 Jan 1970 00:00:00 +0000".to_string());
    rendered.strip_suffix(" +0000").map(|prefix| format!("{prefix} GMT")).unwrap_or(rendered)
}

pub fn is_auto_provided_request_var(var: &str) -> bool {
    matches!(var, "REQUEST_RFC1123_DATE" | "REQUEST_UNIX_MILLIS")
}

/// Clone `globals` and add stable request-scoped values for templated request rendering.
///
/// These values are computed once so the same generated timestamp can be reused across the URL,
/// headers, body, and multipart parts of a single request.
pub fn with_request_template_globals(globals: &Object) -> Object {
    let mut out = globals.clone();
    let now = OffsetDateTime::now_utc();

    if !out.contains_key("REQUEST_RFC1123_DATE") {
        out.insert("REQUEST_RFC1123_DATE".into(), Value::scalar(format_rfc1123(now)));
    }
    if !out.contains_key("REQUEST_UNIX_MILLIS") {
        out.insert(
            "REQUEST_UNIX_MILLIS".into(),
            Value::scalar((now.unix_timestamp_nanos() / 1_000_000).to_string()),
        );
    }

    out
}

/// Clone `globals` and add stable placeholder values for request-scoped template vars that
/// would otherwise make HTTP validation cache keys vary per execution.
pub fn with_cache_key_template_globals(globals: &Object) -> Object {
    let mut out = globals.clone();

    if !out.contains_key("REQUEST_RFC1123_DATE") {
        out.insert("REQUEST_RFC1123_DATE".into(), Value::scalar("REQUEST_RFC1123_DATE"));
    }
    if !out.contains_key("REQUEST_UNIX_MILLIS") {
        out.insert("REQUEST_UNIX_MILLIS".into(), Value::scalar("REQUEST_UNIX_MILLIS"));
    }

    out
}

/// Build a reqwest RequestBuilder using the provided parameters.
#[allow(clippy::too_many_arguments)]
pub fn build_request_builder(
    client: &Client,
    method_str: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
    body: &Option<String>,
    timeout: Duration,
    parser: &liquid::Parser,
    globals: &liquid::Object,
) -> Result<RequestBuilder, String> {
    let method = parse_http_method(method_str).map_err(|err_msg| {
        debug!("{}", err_msg);
        err_msg
    })?;
    let mut request_builder = client.request(method, url.clone()).timeout(timeout);
    let custom_headers = process_headers(headers, parser, globals, url)
        .map_err(|e| format!("Error processing headers: {}", e))?;

    let user_agent = GLOBAL_USER_AGENT.as_str();
    let standard_headers = [
        (header::USER_AGENT, user_agent),
        (
            header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        ),
        (header::ACCEPT_LANGUAGE, "en-US,en;q=0.5"),
        (header::ACCEPT_ENCODING, "gzip, deflate, br"),
        (header::CONNECTION, "keep-alive"),
    ];
    let mut combined_headers = HeaderMap::new();
    for (name, value) in &standard_headers {
        if let Ok(hv) = HeaderValue::from_str(value) {
            combined_headers.insert(name.clone(), hv);
        }
    }
    for (name, value) in custom_headers.iter() {
        combined_headers.insert(name.clone(), value.clone());
    }
    request_builder = request_builder.headers(combined_headers);

    if let Some(body_template) = body {
        let template = parser
            .parse(body_template)
            .map_err(|e| format!("Error parsing body template: {}", e))?;
        let rendered_body = template
            .render(globals)
            .map_err(|e| format!("Error rendering body template: {}", e))?;
        request_builder = request_builder.body(rendered_body);
    }

    Ok(request_builder)
}

/// Process headers from a BTreeMap, rendering any Liquid templates.
pub fn process_headers(
    headers: &BTreeMap<String, String>,
    parser: &liquid::Parser,
    globals: &Object,
    url: &Url,
) -> Result<HeaderMap> {
    let mut headers_map = HeaderMap::new();
    for (key, value) in headers {
        let template = match parser.parse(value) {
            Ok(t) => t,
            Err(e) => {
                debug!("Error parsing Liquid template for '{}': {}", key, e);
                continue;
            }
        };

        let header_value = match template.render(globals) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    "Failed to render header template. URL = <{}> | Key '{}': {}",
                    url.as_str(),
                    key,
                    e
                );
                continue;
            }
        };

        let cleaned_key = key.trim().replace(&['\n', '\r'][..], "");
        let cleaned_value = header_value.trim().replace(&['\n', '\r'][..], "");
        let name = match HeaderName::from_str(&cleaned_key) {
            Ok(n) => n,
            Err(e) => {
                debug!(
                    "Invalid header name. URL = <{}> | Key '{}': {}",
                    url.as_str(),
                    cleaned_key,
                    e
                );
                continue;
            }
        };
        let value = match HeaderValue::from_str(&cleaned_value) {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    "Invalid header value. URL = <{}> | Value '{}': {}",
                    url.as_str(),
                    cleaned_value,
                    e
                );
                continue;
            }
        };
        headers_map.insert(name, value);
    }
    Ok(headers_map)
}

/// Exponential‐backoff retry helper that always returns `Result<T, anyhow::Error>`.
async fn retry_with_backoff<F, Fut, T>(
    mut operation: F,
    is_retryable: impl Fn(&Result<T, Error>, usize) -> bool,
    max_retries: usize,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut retries = 0;
    while retries <= max_retries {
        let result = operation().await;
        if !is_retryable(&result, retries) {
            return result;
        }
        retries += 1;
        if retries > max_retries {
            break;
        }
        let backoff = backoff_min.saturating_mul(2u32.pow(retries as u32)).min(backoff_max);
        sleep(backoff).await;
    }
    Err(anyhow!("Max retries reached"))
}

pub async fn retry_multipart_request<F, Fut>(
    mut build_request: F,
    max_retries: usize,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<Response, Error>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = RequestBuilder>,
{
    retry_with_backoff(
        move || {
            let fut = build_request();
            async move {
                let rb = fut.await;
                rb.send().await.map_err(Error::from)
            }
        },
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                        // Common when validation concurrency hits per-service limits.
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::REQUEST_TIMEOUT
                ) =>
            {
                true
            }
            Err(_) => true,
            _ => false,
        },
        max_retries,
        backoff_min,
        backoff_max,
    )
    .await
}

pub async fn retry_request(
    request_builder: RequestBuilder,
    max_retries: u32,
    backoff_min: Duration,
    backoff_max: Duration,
) -> Result<Response, Error> {
    retry_with_backoff(
        move || {
            let rb =
                request_builder.try_clone().expect("retry_request: failed to clone RequestBuilder");
            async move { rb.send().await.map_err(Error::from) }
        },
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
                        // Common when validation concurrency hits per-service limits.
                        | StatusCode::TOO_MANY_REQUESTS
                        | StatusCode::REQUEST_TIMEOUT
                ) =>
            {
                true
            }
            Err(_) => true,
            _ => false,
        },
        max_retries as usize,
        backoff_min,
        backoff_max,
    )
    .await
}

/// Return `true` when the body is very likely HTML.
fn body_looks_like_html(body: &str, headers: &HeaderMap) -> bool {
    let header_says_html = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            let ct = ct.to_ascii_lowercase();
            ct.contains("text/html") || ct.contains("application/xhtml")
        })
        .unwrap_or(false);

    let mut end = 1024.min(body.len());
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let probe = &body[..end];
    let trimmed = probe.trim_start_matches(|c: char| c.is_whitespace());
    let probe = trimmed.to_ascii_lowercase();
    let body_looks_htmlish = probe.starts_with('<') && probe.contains("<html");

    header_says_html && body_looks_htmlish
}

/// Validate the response by checking word and status matchers.
pub fn validate_response(
    matchers: &[ResponseMatcher],
    body: &str,
    status: &StatusCode,
    headers: &HeaderMap,
    html_allowed: bool,
) -> bool {
    let word_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::WordMatch { words, match_all_words, negative, .. } = m {
                let raw = if *match_all_words {
                    words.iter().all(|w| body.contains(w))
                } else {
                    words.iter().any(|w| body.contains(w))
                };
                Some(if *negative { !raw } else { raw })
            } else {
                None
            }
        })
        .all(|b| b);

    let status_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::StatusMatch {
                status: expected,
                match_all_status,
                negative,
                ..
            } = m
            {
                let raw = if *match_all_status {
                    expected.iter().all(|s| s.to_string() == status.as_str())
                } else {
                    expected.iter().any(|s| s.to_string() == status.as_str())
                };
                Some(if *negative { !raw } else { raw })
            } else {
                None
            }
        })
        .all(|b| b);

    let header_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::HeaderMatch { header, expected, match_all_values, .. } = m {
                let val = headers
                    .get(header)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                Some(if *match_all_values {
                    expected.iter().all(|e| val.contains(&e.to_ascii_lowercase()))
                } else {
                    expected.iter().any(|e| val.contains(&e.to_ascii_lowercase()))
                })
            } else {
                None
            }
        })
        .all(|b| b);

    let json_ok = matchers
        .iter()
        .filter_map(|m| {
            if matches!(m, ResponseMatcher::JsonValid { .. }) {
                Some(serde_json::from_str::<serde_json::Value>(body).is_ok())
            } else {
                None
            }
        })
        .all(|b| b);

    let xml_ok = matchers
        .iter()
        .filter_map(|m| {
            if matches!(m, ResponseMatcher::XmlValid { .. }) {
                Some(xml_from_str::<IgnoredAny>(body).is_ok())
            } else {
                None
            }
        })
        .all(|b| b);

    let html_detected = body_looks_like_html(body, headers);
    let html_ok = html_allowed || !html_detected;

    word_ok && status_ok && header_ok && json_ok && xml_ok && html_ok
}

/// Returns `true` if the IP address is safe for outbound validation requests
/// (i.e., it is a publicly routable address, not internal/reserved).
///
/// Blocks common IANA special-purpose ranges from RFC 6890 and RFC 8190.
pub fn is_ssrf_safe_ip(ip: &IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8 — "This host on this network" (RFC 1122); not routable
            if octets[0] == 0 {
                return false;
            }
            // Private ranges (RFC 1918)
            if octets[0] == 10 {
                return false;
            }
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return false;
            }
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }
            // Link-local (169.254.0.0/16) — includes AWS metadata 169.254.169.254
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }
            // CGNAT / Shared Address Space (100.64.0.0/10)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return false;
            }
            // IANA Special Purpose (192.0.0.0/24, RFC 6890)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return false;
            }
            // Documentation ranges (RFC 5737)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return false;
            }
            // 6to4 relay anycast (192.88.99.0/24, RFC 7526 — deprecated)
            if octets[0] == 192 && octets[1] == 88 && octets[2] == 99 {
                return false;
            }
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return false;
            }
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return false;
            }
            // Benchmarking (198.18.0.0/15)
            if octets[0] == 198 && (18..=19).contains(&octets[1]) {
                return false;
            }
            // Reserved for future use (240.0.0.0/4) — not routable
            if octets[0] >= 240 {
                return false;
            }
            true
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) — apply IPv4 checks
            // to prevent bypassing via e.g. ::ffff:127.0.0.1 or ::ffff:10.0.0.1
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_ssrf_safe_ip(&IpAddr::V4(mapped));
            }
            let segments = v6.segments();
            // IPv4-compatible IPv6 addresses (::/96, e.g., ::127.0.0.1) are
            // deprecated (RFC 4291 §2.5.5.1) and can bypass IPv4-only checks.
            // Reject the entire ::/96 range.
            if segments[..6].iter().all(|&s| s == 0) {
                return false;
            }
            // Unique local (fc00::/7)
            if segments[0] & 0xfe00 == 0xfc00 {
                return false;
            }
            // Link-local (fe80::/10)
            if segments[0] & 0xffc0 == 0xfe80 {
                return false;
            }
            // Site-local (fec0::/10) — deprecated (RFC 3879) but still non-routable
            if segments[0] & 0xffc0 == 0xfec0 {
                return false;
            }
            // Benchmarking (2001:2::/48, RFC 5180)
            if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 {
                return false;
            }
            // Documentation (2001:db8::/32)
            if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                return false;
            }
            true
        }
    }
}

/// Check if a URL can be resolved via DNS, with SSRF protection against
/// internal/private IP addresses.
///
/// **Note:** This is a preflight check — the HTTP client will perform its own
/// DNS resolution when connecting. A DNS-rebinding attack could theoretically
/// return a public IP for this check and a private IP for the actual connection.
/// Fully eliminating this TOCTOU gap would require a custom resolver/connector
/// that pins resolved IPs. In practice, callers should also disable automatic
/// redirects or use a redirect-blocking policy on the HTTP client to mitigate
/// the most practical exploitation paths.
pub async fn check_url_resolvable(
    url: &Url,
    allow_internal_ips: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let host = url.host_str().ok_or("No host in URL")?;

    // If the host is already an IP literal, check it directly without DNS.
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !allow_internal_ips && !is_ssrf_safe_ip(&ip) {
            return Err(SsrfBlockedError(format!(
                "SSRF protection: resolved IP {} for host '{}' is not a public address. \
                 Use --allow-internal-ips to permit internal addresses.",
                ip, host
            ))
            .into());
        }
        return Ok(());
    }

    // Hostname — resolve via DNS and check each resolved address.
    let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let addr = format!("{}:{}", host, port);
    let mut resolved_any = false;
    for socket_addr in lookup_host(&addr).await? {
        resolved_any = true;
        if !allow_internal_ips && !is_ssrf_safe_ip(&socket_addr.ip()) {
            return Err(SsrfBlockedError(format!(
                "SSRF protection: resolved IP {} for host '{}' is not a public address. \
                 Use --allow-internal-ips to permit internal addresses.",
                socket_addr.ip(),
                host
            ))
            .into());
        }
    }
    if !resolved_any {
        return Err("Failed to resolve URL".into());
    }
    Ok(())
}

/// Backwards-compatible wrapper: checks URL resolvability with SSRF protection
/// enabled (i.e., `allow_internal_ips = false`).
#[deprecated(since = "0.1.0", note = "use check_url_resolvable(url, allow_internal_ips) instead")]
pub async fn check_url_resolvable_safe(url: &Url) -> Result<(), Box<dyn std::error::Error>> {
    check_url_resolvable(url, false).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use liquid_core::ValueView;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use time::OffsetDateTime;

    #[test]
    fn request_template_globals_add_stable_values() {
        let globals = Object::new();
        let rendered = with_request_template_globals(&globals);

        let date = rendered.get("REQUEST_RFC1123_DATE").unwrap().to_kstr().to_string();
        let millis = rendered.get("REQUEST_UNIX_MILLIS").unwrap().to_kstr().to_string();

        assert!(date.ends_with(" GMT"), "unexpected date format: {date}");
        assert!(OffsetDateTime::parse(&date.replace(" GMT", " +0000"), &Rfc2822).is_ok());

        let millis_val: i128 = millis.parse().unwrap();
        assert!(millis_val > 0);
    }

    #[test]
    fn request_template_globals_preserve_explicit_overrides() {
        let mut globals = Object::new();
        globals.insert("REQUEST_RFC1123_DATE".into(), Value::scalar("custom-date"));
        globals.insert("REQUEST_UNIX_MILLIS".into(), Value::scalar("123"));

        let rendered = with_request_template_globals(&globals);

        assert_eq!(rendered.get("REQUEST_RFC1123_DATE").unwrap().to_kstr(), "custom-date");
        assert_eq!(rendered.get("REQUEST_UNIX_MILLIS").unwrap().to_kstr(), "123");
    }

    #[test]
    fn cache_key_template_globals_use_stable_placeholders() {
        let globals = Object::new();
        let rendered = with_cache_key_template_globals(&globals);

        assert_eq!(rendered.get("REQUEST_RFC1123_DATE").unwrap().to_kstr(), "REQUEST_RFC1123_DATE");
        assert_eq!(rendered.get("REQUEST_UNIX_MILLIS").unwrap().to_kstr(), "REQUEST_UNIX_MILLIS");
    }

    #[test]
    fn cache_key_template_globals_preserve_explicit_overrides() {
        let mut globals = Object::new();
        globals.insert("REQUEST_RFC1123_DATE".into(), Value::scalar("custom-date"));
        globals.insert("REQUEST_UNIX_MILLIS".into(), Value::scalar("123"));

        let rendered = with_cache_key_template_globals(&globals);

        assert_eq!(rendered.get("REQUEST_RFC1123_DATE").unwrap().to_kstr(), "custom-date");
        assert_eq!(rendered.get("REQUEST_UNIX_MILLIS").unwrap().to_kstr(), "123");
    }

    #[test]
    fn rejects_ipv4_loopback() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
    }

    #[test]
    fn rejects_ipv4_unspecified() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn rejects_ipv4_this_network() {
        // 0.0.0.0/8 — "This host on this network" (RFC 1122)
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(0, 255, 255, 255))));
    }

    #[test]
    fn rejects_ipv4_private_rfc1918() {
        // 10.0.0.0/8
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        // 172.16.0.0/12
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        // 192.168.0.0/16
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));
    }

    #[test]
    fn rejects_link_local_and_metadata() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));
        // AWS/GCP/Azure metadata endpoint
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    }

    #[test]
    fn rejects_cgnat() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
    }

    #[test]
    fn rejects_documentation_ranges() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn rejects_benchmarking() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(198, 19, 255, 255))));
    }

    #[test]
    fn rejects_reserved_and_broadcast() {
        // 240.0.0.0/4 — reserved for future use (includes broadcast)
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(250, 1, 2, 3))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::BROADCAST)));
    }

    #[test]
    fn rejects_multicast() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_ipv6_unspecified() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn rejects_ipv6_unique_local() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn rejects_ipv6_link_local() {
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn rejects_ipv6_site_local() {
        // fec0::/10 — deprecated site-local (RFC 3879)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0xfeff, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn rejects_ipv6_documentation() {
        // 2001:db8::/32 — documentation range (RFC 3849)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))));
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1 — IPv4-mapped loopback
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001
        ))));
        // ::ffff:10.0.0.1 — IPv4-mapped private
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001
        ))));
        // ::ffff:169.254.169.254 — IPv4-mapped metadata endpoint
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xa9fe, 0xa9fe
        ))));
        // ::ffff:192.168.1.1 — IPv4-mapped private
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101
        ))));
        // ::ffff:8.8.8.8 — IPv4-mapped public (should be allowed)
        assert!(is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808))));
    }

    #[test]
    fn rejects_ipv4_compatible_ipv6() {
        // ::127.0.0.1 — deprecated IPv4-compatible IPv6 (loopback)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7f00, 0x0001))));
        // ::10.0.0.1 — deprecated IPv4-compatible IPv6 (private)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0a00, 0x0001))));
        // ::8.8.8.8 — even public IPv4 in ::/96 is rejected (deprecated range)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0808, 0x0808))));
    }

    #[test]
    fn rejects_iana_special_purpose() {
        // 192.0.0.0/24 — IANA special-purpose (RFC 6890)
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 0, 1))));
    }

    #[test]
    fn rejects_6to4_relay_anycast() {
        // 192.88.99.0/24 — 6to4 relay anycast (RFC 7526, deprecated)
        assert!(!is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
    }

    #[test]
    fn rejects_ipv6_benchmarking() {
        // 2001:2::/48 — benchmarking (RFC 5180)
        assert!(!is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn accepts_public_ipv6() {
        assert!(is_ssrf_safe_ip(&IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111))));
    }

    #[test]
    fn accepts_edge_cases_outside_private_ranges() {
        // 172.15.x.x is NOT private (private is 172.16-31)
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(172, 15, 255, 255))));
        // 172.32.x.x is NOT private
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
        // 100.63.x.x is NOT CGNAT (CGNAT is 100.64-127)
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        // 100.128.x.x is NOT CGNAT
        assert!(is_ssrf_safe_ip(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[tokio::test]
    async fn check_url_resolvable_rejects_localhost() {
        let url = Url::parse("https://localhost/test").unwrap();
        let result = check_url_resolvable(&url, false).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SSRF protection"), "expected SSRF error, got: {}", err);
    }

    #[tokio::test]
    async fn check_url_resolvable_allows_localhost_when_permitted() {
        let url = Url::parse("https://localhost/test").unwrap();
        // With allow_internal_ips=true, localhost should resolve successfully
        let result = check_url_resolvable(&url, true).await;
        assert!(result.is_ok(), "expected Ok with allow_internal_ips=true, got: {:?}", result);
    }

    #[tokio::test]
    async fn check_url_resolvable_rejects_ipv6_loopback_literal() {
        // IPv6 literal URL — brackets are handled by reqwest::Url, host_str() returns "::1"
        let url = Url::parse("https://[::1]/test").unwrap();
        let result = check_url_resolvable(&url, false).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SSRF protection"), "expected SSRF error, got: {}", err);
    }
}
