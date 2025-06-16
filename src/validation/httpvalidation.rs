use std::{collections::BTreeMap, future::Future, str::FromStr, time::Duration};

use anyhow::{anyhow, Error, Result};
use http::StatusCode;
use liquid::Object;
use quick_xml::de::from_str as xml_from_str;
use reqwest::{
    header,
    header::{HeaderMap, HeaderName, HeaderValue},
    Client, Method, RequestBuilder, Response, Url,
};
use serde::de::IgnoredAny;
use sha1::{Digest, Sha1};
use tokio::time::sleep;
use tracing::debug;

use crate::rules::rule::ResponseMatcher;

/// Build a deterministic cache key from the immutable parts of an HTTP request.
///
/// * `method`   – case-insensitive HTTP verb (“GET”, “POST”…)
/// * `url`      – fully-qualified URL (any query string should already be present)
/// * `headers`  – *logical* headers you intend to send (template-rendered, lower-level additions
///   such as `User-Agent` may be appended by the caller)
///
/// The parts are concatenated with `\0` separators before hashing to avoid accidental
/// collisions such as `"GET/foo"` vs `"GE" + "T/foo"`.
pub fn generate_http_cache_key_parts(
    method: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
) -> String {
    let method = method.to_uppercase(); // ensure "get" == "GET"
    let url = url.as_str(); // canonical form from `reqwest::Url`

    let mut hasher = Sha1::new();
    hasher.update(method.as_bytes());
    hasher.update(b"\0");
    hasher.update(url.as_bytes());
    hasher.update(b"\0");

    // Collect headers sorted lexicographically (BTreeMap is already sorted),
    // then hash as `key:value\0`
    for (k, v) in headers {
        hasher.update(k.as_bytes());
        hasher.update(b":");
        hasher.update(v.as_bytes());
        hasher.update(b"\0");
    }

    // Hex-encode and prefix so callers can tell this key came from HTTP logic
    format!("HTTP:{:x}", hasher.finalize())
}

/// Parse an HTTP method from a string.
pub fn parse_http_method(method_str: &str) -> Result<Method, String> {
    Method::from_str(method_str).map_err(|_| format!("Invalid HTTP method: {}", method_str))
}

/// Build a reqwest RequestBuilder using the provided parameters.
pub fn build_request_builder(
    client: &Client,
    method_str: &str,
    url: &Url,
    headers: &BTreeMap<String, String>,
    parser: &liquid::Parser,
    globals: &liquid::Object,
) -> Result<RequestBuilder, String> {
    let method = parse_http_method(method_str).map_err(|err_msg| {
        debug!("{}", err_msg);
        err_msg
    })?;
    let mut request_builder = client.request(method, url.clone()).timeout(Duration::from_secs(10));
    let custom_headers = process_headers(headers, parser, globals, url)
        .map_err(|e| format!("Error processing headers: {}", e))?;

    // Prepare a standard set of headers.
    let user_agent = format!(
        "{}/{}",
        //"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    let standard_headers = [
        (header::USER_AGENT, user_agent.as_str()),
        (
            header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        ),
        (header::ACCEPT_LANGUAGE, "en-US,en;q=0.5"),
        (header::ACCEPT_ENCODING, "gzip, deflate, br"),
        (header::CONNECTION, "keep-alive"),
    ];
    // Extend custom headers with the standard ones (overwriting any duplicates).
    let mut combined_headers = custom_headers;
    for (name, value) in &standard_headers {
        if let Ok(hv) = HeaderValue::from_str(value) {
            combined_headers.insert(name.clone(), hv);
        }
    }
    request_builder = request_builder.headers(combined_headers);
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
        // Render the template
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
        // Clean key and value
        let cleaned_key = key.trim().replace(&['\n', '\r'][..], "");
        let cleaned_value = header_value.trim().replace(&['\n', '\r'][..], "");
        // Validate header name
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
        // Validate header value
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

/// Exponential‐backoff retry helper that always returns `Result<T, anyhow::Error>`
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
        // If this result is *not* retryable, return it directly (Ok or Err).
        if !is_retryable(&result, retries) {
            return result;
        }
        retries += 1;
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
        // 1) operation: build + send
        move || {
            let fut = build_request();
            async move {
                let rb = fut.await;
                rb.send().await.map_err(Error::from)
            }
        },
        // 2) same retry logic
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
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
        // 1) operation: clone + send, yielding Result<Response, Error>
        move || {
            let rb =
                request_builder.try_clone().expect("retry_request: failed to clone RequestBuilder");
            async move { rb.send().await.map_err(Error::from) }
        },
        // 2) is_retryable: transient HTTP status or network error
        |res: &Result<_, Error>, _attempt| match res {
            Ok(resp)
                if matches!(
                    resp.status(),
                    StatusCode::BAD_GATEWAY
                        | StatusCode::SERVICE_UNAVAILABLE
                        | StatusCode::GATEWAY_TIMEOUT
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
///
/// Heuristics (fast):
///   1. Content-Type header says “text/html” or “application/xhtml+xml”.
///   2. First 1 kB starts with “<” **and** contains “<html”.
fn body_looks_like_html(body: &str, headers: &HeaderMap) -> bool {
    // ---- 1. header heuristic ---------------------------------------------
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        let ct = ct.to_ascii_lowercase();
        if ct.contains("text/html") || ct.contains("application/xhtml") {
            return true;
        }
    }

    // ---- 2. early-body scan (<=1024 bytes) --------------------------------
    let probe = body[..body.len().min(1024)].to_ascii_lowercase();
    probe.starts_with('<') && probe.contains("<html")
}

/// Validate the response by checking word and status matchers.
pub fn validate_response(
    matchers: &[ResponseMatcher],
    body: &str,
    status: &StatusCode,
    headers: &HeaderMap,
    html_allowed: bool,
) -> bool {
    // Since match_all_types is always true here, we simply require all word and status conditions
    // to hold.
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

    // ── Header checks ──────────────────────────────────────────
    let header_ok = matchers
        .iter()
        .filter_map(|m| {
            if let ResponseMatcher::HeaderMatch { header, expected, match_all_values, .. } = m {
                // header names are case-insensitive
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

    // ----- JsonValid ----------------------------------------------------------
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
                // succeeds if `body` is well-formed XML
                Some(xml_from_str::<IgnoredAny>(body).is_ok())
            } else {
                None
            }
        })
        .all(|b| b);

    let html_detected = body_looks_like_html(body, headers);
    let html_ok = html_allowed || !html_detected;

    // // ── debug line ─-
    // debug!(
    //     "validate_response -- word:{}, status:{}, header:{}, json:{}, xml:{}  ⇒  {}",
    //     word_ok, status_ok, header_ok, json_ok, xml_ok, all_ok
    // );
    // // ──────────────────────────────────────────────────────────────

    let all_ok = word_ok && status_ok && header_ok && json_ok && xml_ok && html_ok;
    all_ok
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    static INIT: Once = Once::new();
    fn init() {
        INIT.call_once(|| {
            let _ = tracing_subscriber::fmt::try_init();
        });
    }

    #[test]
    fn test_build_request_builder() {
        init();
        let client = Client::builder()
            .gzip(true) // enable gzip
            .deflate(true) // enable deflate
            .brotli(true) // enable brotli
            .build()
            .expect("building reqwest client");
        let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
        let globals = liquid::Object::new();
        let headers =
            BTreeMap::from([("Content-Type".to_string(), "application/json".to_string())]);
        let url = Url::from_str("https://example.com").unwrap();
        let result = build_request_builder(&client, "GET", &url, &headers, &parser, &globals);
        assert!(result.is_ok());
    }
    #[tokio::test]
    async fn test_retry_request() {
        init();
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock_server)
            .await;
        let client = Client::builder()
            .gzip(true) // enable gzip
            .deflate(true) // enable deflate
            .brotli(true) // enable brotli
            .build()
            .expect("building reqwest client");
        let request_builder = client.get(&format!("{}/test", mock_server.uri()));
        let response = retry_request(
            request_builder,
            3,
            Duration::from_millis(50),
            Duration::from_millis(200),
        )
        .await;
        assert!(response.is_ok());
    }
    #[test]
    fn test_validate_response() {
        // --- arrange ----------------------------------------------------------
        let matchers = vec![ResponseMatcher::WordMatch {
            r#type: "word-match".to_string(),
            words: vec!["test".to_string()],
            match_all_words: true,
            negative: false,
        }];
        let status = StatusCode::OK;
        let body = "This is a test";
        let headers = HeaderMap::new(); // empty header map
        let html_allowed = false;

        // --- act --------------------------------------------------------------
        let result = validate_response(&matchers, body, &status, &headers, html_allowed);

        // --- assert -----------------------------------------------------------
        assert!(result);
    }
}
