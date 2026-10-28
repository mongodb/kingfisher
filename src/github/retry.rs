//! Bounded retries for replayable GitHub API requests. Return the final response so
//! callers retain their existing error and best-effort discovery behavior.

use std::{
    env,
    future::Future,
    io::Read,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use kingfisher_scanner::validation::limits::{ResourceTimeout, timeout};
use reqwest::{ResponseBuilderExt, StatusCode, header::HeaderMap};
use tracing::warn;

const MAX_RETRIES: u32 = 3;
const DEFAULT_MAX_RETRY_WAIT: Duration = Duration::from_secs(120);
const MAX_RETRY_WAIT_ENV: &str = "KF_GITHUB_MAX_RETRY_WAIT_SECS";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
// Secondary-limit detection and error diagnostics are not scannable content. Keep
// these prefixes bounded even when scan content/result limits are disabled.
const MAX_FORBIDDEN_BODY_BYTES: usize = 64 * 1024;
const ERROR_BODY_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn send(
    request: reqwest::RequestBuilder,
    action: &str,
) -> Result<reqwest::Response> {
    send_with_sleep(
        || std::future::ready(request.try_clone().context("GitHub API request cannot be replayed")),
        action,
        DEFAULT_MAX_RETRY_WAIT,
        tokio::time::sleep,
    )
    .await
}

/// Retry API reads with fresh authentication on every attempt. Token exchanges
/// retain the short default budget so a refresh cannot block other workers for an hour.
pub(crate) async fn send_with_request<M, R>(
    make_request: M,
    action: &str,
) -> Result<reqwest::Response>
where
    M: FnMut() -> R,
    R: Future<Output = Result<reqwest::RequestBuilder>>,
{
    let value = match env::var(MAX_RETRY_WAIT_ENV) {
        Ok(value) => Some(value),
        Err(env::VarError::NotPresent) => None,
        Err(error) => return Err(error).with_context(|| format!("Invalid {MAX_RETRY_WAIT_ENV}")),
    };
    let max_retry_wait = parse_max_retry_wait(value.as_deref())?;
    send_with_sleep(make_request, action, max_retry_wait, tokio::time::sleep).await
}

fn parse_max_retry_wait(value: Option<&str>) -> Result<Duration> {
    let Some(value) = value else { return Ok(DEFAULT_MAX_RETRY_WAIT) };
    let seconds = value.trim().parse::<u64>().with_context(|| {
        format!("{MAX_RETRY_WAIT_ENV} must be a non-negative integer in seconds")
    })?;
    let duration = Duration::from_secs(seconds);
    // Reject values that cannot be represented by the platform's sleep clock.
    Instant::now()
        .checked_add(duration)
        .with_context(|| format!("{MAX_RETRY_WAIT_ENV} is too large for the system clock"))?;
    Ok(duration)
}

pub(crate) async fn send_with_sleep<M, R, S, F>(
    mut make_request: M,
    action: &str,
    max_retry_wait: Duration,
    mut sleep: S,
) -> Result<reqwest::Response>
where
    M: FnMut() -> R,
    R: Future<Output = Result<reqwest::RequestBuilder>>,
    S: FnMut(Duration) -> F,
    F: Future<Output = ()>,
{
    let mut retries = 0;
    let mut waited = Duration::ZERO;
    loop {
        let mut response = make_request().await?.resource_timeout(REQUEST_TIMEOUT).send().await?;

        // A 403 can also mean missing permissions. GitHub secondary limits may
        // only be identified in the JSON message, without rate-limit headers.
        let mut body = Vec::new();
        if response.status() == StatusCode::FORBIDDEN && !has_rate_limit_headers(response.headers())
        {
            let mut headers = response.headers().clone();
            let url = response.url().clone();
            let version = response.version();
            body = read_body_prefix(&mut response, MAX_FORBIDDEN_BODY_BYTES).await?;
            // The synthetic body may be a prefix; do not retain its original wire length.
            headers.remove(reqwest::header::CONTENT_LENGTH);
            headers.remove(reqwest::header::TRANSFER_ENCODING);
            let mut buffered = http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .version(version)
                .url(url)
                .body(body.clone())?;
            *buffered.headers_mut() = headers;
            response = buffered.into();
        }

        let Some(delay) =
            retry_delay(response.status(), response.headers(), &body, retries, Utc::now())
        else {
            return Ok(response);
        };
        if retries >= MAX_RETRIES {
            warn!(
                "GitHub API request while {action}: HTTP {} ({}); giving up after {retries} retries",
                response.status(),
                response.url()
            );
            return Ok(response);
        }
        if delay > max_retry_wait.saturating_sub(waited) {
            warn!(
                "GitHub API request while {action}: HTTP {} ({}); retry requires {:.1}s, exceeding the remaining {:.1}s retry wait budget",
                response.status(),
                response.url(),
                delay.as_secs_f64(),
                max_retry_wait.saturating_sub(waited).as_secs_f64()
            );
            return Ok(response);
        }

        retries += 1;
        warn!(
            "GitHub API request while {action}: HTTP {} ({}); retry {retries}/{MAX_RETRIES} in {:.1}s",
            response.status(),
            response.url(),
            delay.as_secs_f64()
        );
        // Release the response before waiting; the factory preserves the URL and
        // pagination parameters and refreshes expiring authentication as needed.
        drop(response);
        sleep(delay).await;
        waited += delay;
    }
}

/// Retry an installation-token exchange on a synchronous clone worker.
///
/// The caller configures HTTP timeouts on the blocking client. Authentication
/// failures are returned immediately, just as for asynchronous requests.
pub(crate) fn send_blocking(
    request: reqwest::blocking::RequestBuilder,
    action: &str,
) -> Result<reqwest::blocking::Response> {
    send_blocking_with_sleep(request, action, std::thread::sleep)
}

fn send_blocking_with_sleep<S>(
    request: reqwest::blocking::RequestBuilder,
    action: &str,
    mut sleep: S,
) -> Result<reqwest::blocking::Response>
where
    S: FnMut(Duration),
{
    let mut retries = 0;
    let mut waited = Duration::ZERO;
    loop {
        let mut response =
            request.try_clone().context("GitHub API request cannot be replayed")?.send()?;

        let mut body = Vec::new();
        if response.status() == StatusCode::FORBIDDEN && !has_rate_limit_headers(response.headers())
        {
            let mut headers = response.headers().clone();
            let url = response.url().clone();
            let version = response.version();
            Read::by_ref(&mut response)
                .take(MAX_FORBIDDEN_BODY_BYTES as u64)
                .read_to_end(&mut body)
                .context("Failed to read GitHub error body")?;
            headers.remove(reqwest::header::CONTENT_LENGTH);
            headers.remove(reqwest::header::TRANSFER_ENCODING);
            let mut buffered = http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .version(version)
                .url(url)
                .body(body.clone())?;
            *buffered.headers_mut() = headers;
            response = buffered.into();
        }

        let Some(delay) =
            retry_delay(response.status(), response.headers(), &body, retries, Utc::now())
        else {
            return Ok(response);
        };
        if retries >= MAX_RETRIES {
            warn!(
                "GitHub API request while {action}: HTTP {} ({}); giving up after {retries} retries",
                response.status(),
                response.url()
            );
            return Ok(response);
        }
        if delay > DEFAULT_MAX_RETRY_WAIT.saturating_sub(waited) {
            warn!(
                "GitHub API request while {action}: HTTP {} ({}); retry requires {:.1}s, exceeding the remaining {:.1}s retry wait budget",
                response.status(),
                response.url(),
                delay.as_secs_f64(),
                DEFAULT_MAX_RETRY_WAIT.saturating_sub(waited).as_secs_f64()
            );
            return Ok(response);
        }

        retries += 1;
        warn!(
            "GitHub API request while {action}: HTTP {} ({}); retry {retries}/{MAX_RETRIES} in {:.1}s",
            response.status(),
            response.url(),
            delay.as_secs_f64()
        );
        drop(response);
        sleep(delay);
        waited += delay;
    }
}

pub(crate) async fn read_body_prefix(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    read_body_prefix_with_timeout(response, max_bytes, ERROR_BODY_TIMEOUT).await
}

async fn read_body_prefix_with_timeout(
    response: &mut reqwest::Response,
    max_bytes: usize,
    duration: Duration,
) -> Result<Vec<u8>> {
    timeout(duration, async {
        let mut body = Vec::new();
        while body.len() < max_bytes {
            let Some(chunk) = response.chunk().await.context("Failed to read GitHub error body")?
            else {
                break;
            };
            let remaining = max_bytes - body.len();
            body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        }
        Ok(body)
    })
    .await
    .context("Timed out reading GitHub error response body")?
}

fn header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers.get(name)?.to_str().ok()?.trim().parse().ok()
}

fn has_rate_limit_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(reqwest::header::RETRY_AFTER)
        || header_u64(headers, "x-ratelimit-remaining") == Some(0)
}

fn rate_limit_message(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let Some(message) = value.get("message").and_then(serde_json::Value::as_str) else {
        return false;
    };
    let message = message.to_ascii_lowercase();
    message.contains("rate limit") || message.contains("abuse detection")
}

fn retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let date = DateTime::parse_from_rfc2822(value).ok()?;
    Some(date.signed_duration_since(now).to_std().unwrap_or_default())
}

pub(crate) fn retry_delay(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    retries: u32,
    now: DateTime<Utc>,
) -> Option<Duration> {
    let rate_limited = status == StatusCode::TOO_MANY_REQUESTS
        || (status == StatusCode::FORBIDDEN
            && (has_rate_limit_headers(headers) || rate_limit_message(body)));
    if !rate_limited && !status.is_server_error() {
        return None;
    }

    let reset = if header_u64(headers, "x-ratelimit-remaining") == Some(0) {
        header_u64(headers, "x-ratelimit-reset").map(|reset| {
            // Wait past the reset second, including when the local clock is
            // fractionally ahead of the advertised timestamp.
            Duration::from_secs(
                reset.saturating_sub(now.timestamp().max(0) as u64).saturating_add(1),
            )
        })
    } else {
        None
    };
    if let Some(delay) = retry_after(headers, now).into_iter().chain(reset).max() {
        return Some(delay);
    }

    // GitHub requires at least one minute for secondary limits without a
    // cooldown header. Jitter spreads clients recovering from server errors.
    let base = if rate_limited { 60 } else { 1 } * (1u64 << retries.min(MAX_RETRIES));
    Some(Duration::from_secs(base) + Duration::from_millis(rand::random_range(0..=base * 250)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;
    use serde_json::json;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    fn now() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        values
            .iter()
            .map(|(name, value)| {
                (name.parse::<reqwest::header::HeaderName>().unwrap(), value.parse().unwrap())
            })
            .collect()
    }

    #[test]
    fn retry_wait_configuration_uses_seconds_and_rejects_invalid_values() {
        assert_eq!(parse_max_retry_wait(None).unwrap(), Duration::from_secs(120));
        for (value, seconds) in [("3900", 3900), (" 600 ", 600), ("0", 0)] {
            assert_eq!(parse_max_retry_wait(Some(value)).unwrap(), Duration::from_secs(seconds));
        }
        for value in ["", " ", "-1", "1.5", "3900s", "invalid", "18446744073709551616"] {
            let error = parse_max_retry_wait(Some(value)).unwrap_err();
            assert!(error.to_string().contains(MAX_RETRY_WAIT_ENV), "{error:#}");
        }
        assert!(parse_max_retry_wait(Some("18446744073709551615")).is_err());
    }

    fn streaming_response(
        stream: impl futures::Stream<Item = std::result::Result<Vec<u8>, std::io::Error>>
        + Send
        + 'static,
    ) -> reqwest::Response {
        http::Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(reqwest::Body::wrap_stream(stream))
            .unwrap()
            .into()
    }

    #[tokio::test]
    async fn error_body_prefix_is_bounded_without_waiting_for_the_stream_to_end() {
        use futures::StreamExt;
        use kingfisher_scanner::validation::limits::NetworkLimits;
        for unlimited_response in [false, true] {
            let prefix = vec![b'x'; MAX_FORBIDDEN_BODY_BYTES + 1];
            let stream = futures::stream::once(std::future::ready(Ok(prefix)))
                .chain(futures::stream::pending());
            let mut response = streaming_response(stream);
            let bytes = tokio::time::timeout(
                Duration::from_secs(10),
                NetworkLimits { unlimited_response, ..Default::default() }
                    .scope(read_body_prefix(&mut response, MAX_FORBIDDEN_BODY_BYTES)),
            )
            .await
            .expect("the reader must stop at its prefix limit")
            .unwrap();
            assert_eq!(bytes, vec![b'x'; MAX_FORBIDDEN_BODY_BYTES]);
        }
    }

    #[tokio::test]
    async fn error_body_deadline_is_control_aware() {
        use kingfisher_scanner::validation::limits::NetworkLimits;
        let (release, receiver) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let mut unlimited_response =
            streaming_response(futures::stream::once(async move { Ok(receiver.await.unwrap()) }));
        let unlimited = NetworkLimits { no_timeouts: true, ..Default::default() }.scope(
            read_body_prefix_with_timeout(&mut unlimited_response, 64, Duration::from_millis(1)),
        );
        tokio::pin!(unlimited);
        std::future::poll_fn(|context| {
            assert!(unlimited.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let mut bounded_response = streaming_response(futures::stream::pending());
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            read_body_prefix_with_timeout(&mut bounded_response, 64, Duration::from_millis(1)),
        )
        .await
        .expect("the body deadline must stop a pending stream")
        .unwrap_err();
        assert!(error.to_string().contains("Timed out reading GitHub"));
        std::future::poll_fn(|context| {
            assert!(unlimited.as_mut().poll(context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        release.send(b"complete".to_vec()).unwrap();
        assert_eq!(unlimited.await.unwrap(), b"complete");
    }

    #[tokio::test]
    async fn oversized_permission_errors_return_a_bounded_prefix_without_retrying() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_bytes(vec![
                b'x';
                MAX_FORBIDDEN_BODY_BYTES
                    + 1
            ]))
            .expect(1)
            .mount(&server)
            .await;
        let response = send(reqwest::Client::new().get(server.uri()), "testing bounded403 probe")
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.bytes().await.unwrap().len(), MAX_FORBIDDEN_BODY_BYTES);
    }

    #[test]
    fn only_transient_statuses_and_rate_limited_forbidden_are_retried() {
        for code in [200, 400, 401, 403, 404, 422] {
            assert!(
                retry_delay(StatusCode::from_u16(code).unwrap(), &HeaderMap::new(), b"", 0, now())
                    .is_none()
            );
        }
        for code in [429, 500, 502, 503, 504, 599] {
            assert!(
                retry_delay(StatusCode::from_u16(code).unwrap(), &HeaderMap::new(), b"", 0, now())
                    .is_some()
            );
        }
        for message in [
            "API rate limit exceeded",
            "You have exceeded a secondary rate limit.",
            "You have triggered an abuse detection mechanism.",
        ] {
            let body = serde_json::to_vec(&json!({"message": message})).unwrap();
            assert!(
                retry_delay(StatusCode::FORBIDDEN, &HeaderMap::new(), &body, 0, now()).unwrap()
                    >= Duration::from_secs(60)
            );
        }
        for body in
            [b"invalid JSON".as_slice(), br#"{"message":"Resource not accessible by integration"}"#]
        {
            assert!(
                retry_delay(StatusCode::FORBIDDEN, &HeaderMap::new(), body, 0, now()).is_none()
            );
        }
    }

    #[test]
    fn honors_retry_after_seconds_dates_and_primary_rate_limit_reset() {
        let cases = [
            (headers(&[("retry-after", "7")]), Duration::from_secs(7)),
            (headers(&[("retry-after", "Tue, 14 Nov 2023 22:13:27 GMT")]), Duration::from_secs(7)),
            (headers(&[("retry-after", "Tue, 14 Nov 2023 22:13:00 GMT")]), Duration::ZERO),
            (
                headers(&[("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1700000007")]),
                Duration::from_secs(8),
            ),
            (
                headers(&[
                    ("retry-after", "2"),
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1700000007"),
                ]),
                Duration::from_secs(8),
            ),
            (
                headers(&[
                    ("retry-after", "bad"),
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1700000007"),
                ]),
                Duration::from_secs(8),
            ),
            (headers(&[("retry-after", "18446744073709551615")]), Duration::from_secs(u64::MAX)),
        ];
        for (headers, expected) in cases {
            for status in [
                StatusCode::FORBIDDEN,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE,
            ] {
                assert_eq!(retry_delay(status, &headers, b"", 0, now()), Some(expected));
            }
        }
    }

    #[test]
    fn missing_or_malformed_headers_use_exponential_backoff() {
        for headers in
            [HeaderMap::new(), headers(&[("retry-after", "bad"), ("x-ratelimit-reset", "bad")])]
        {
            for retry in 0..=MAX_RETRIES {
                for (status, seconds) in
                    [(StatusCode::TOO_MANY_REQUESTS, 60), (StatusCode::INTERNAL_SERVER_ERROR, 1)]
                {
                    let base = Duration::from_secs(seconds * (1 << retry));
                    let delay = retry_delay(status, &headers, b"", retry, now()).unwrap();
                    assert!(delay >= base && delay <= base + base / 4);
                }
            }
        }
    }

    #[tokio::test]
    async fn retries_preserve_request_and_return_success() {
        for status in [403, 429, 500, 502, 503, 504] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "0"))
                .up_to_n_times(1)
                .expect(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!(["recovered"])))
                .expect(1)
                .with_priority(2)
                .mount(&server)
                .await;
            let response = send(
                reqwest::Client::new()
                    .get(format!("{}/api/v3/repos?page=2", server.uri()))
                    .bearer_auth("test-token")
                    .header("User-Agent", "test-agent"),
                "testing retries",
            )
            .await
            .unwrap();
            assert_eq!(response.json::<Vec<String>>().await.unwrap(), ["recovered"]);
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 2);
            for request in requests {
                assert_eq!(request.url.path(), "/api/v3/repos");
                assert_eq!(request.url.query(), Some("page=2"));
                assert_eq!(request.headers["authorization"], "Bearer test-token");
                assert_eq!(request.headers["user-agent"], "test-agent");
            }
        }
    }

    #[tokio::test]
    async fn retry_exhaustion_preserves_final_error_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(503)
                    .insert_header("retry-after", "0")
                    .set_body_string("still unavailable"),
            )
            .expect(u64::from(MAX_RETRIES) + 1)
            .mount(&server)
            .await;
        let response =
            send(reqwest::Client::new().get(server.uri()), "testing retries").await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.text().await.unwrap(), "still unavailable");
    }

    #[tokio::test]
    async fn secondary_limit_message_retries_without_headers() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_json(json!({
                "message": "You have exceeded a secondary rate limit."
            })))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .with_priority(2)
            .mount(&server)
            .await;
        let mut delays = Vec::new();
        let response = send_with_sleep(
            || std::future::ready(Ok(reqwest::Client::new().get(server.uri()))),
            "testing retries",
            DEFAULT_MAX_RETRY_WAIT,
            |delay| {
                delays.push(delay);
                std::future::ready(())
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(delays.len(), 1);
        assert!(delays[0] >= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn configured_budget_waits_for_primary_quota_reset_and_resumes_same_page() {
        let server = MockServer::start().await;
        let reset = Utc::now().timestamp() + 3600;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ratelimit-remaining", "0")
                    .insert_header("x-ratelimit-reset", reset.to_string()),
            )
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!(["recovered"])))
            .expect(1)
            .with_priority(2)
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let mut delays = Vec::new();
        let response = send_with_sleep(
            || {
                std::future::ready(Ok(client
                    .get(format!("{}/users/alice/gists?page=2", server.uri()))
                    .bearer_auth("test-token")))
            },
            "testing hourly quota reset",
            Duration::from_secs(3900),
            |delay| {
                delays.push(delay);
                std::future::ready(())
            },
        )
        .await
        .unwrap();
        assert_eq!(response.json::<Vec<String>>().await.unwrap(), ["recovered"]);
        assert_eq!(delays.len(), 1);
        assert!(delays[0] > Duration::from_secs(120));
        assert!(delays[0] <= Duration::from_secs(3601));
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests {
            assert_eq!(request.url.path(), "/users/alice/gists");
            assert_eq!(request.url.query(), Some("page=2"));
            assert_eq!(request.headers["authorization"], "Bearer test-token");
        }
    }

    #[tokio::test]
    async fn cumulative_wait_is_bounded_and_never_shortens_server_cooldown() {
        for (budget, seconds, requests, sleeps) in [
            (120, 60, 3, 2),
            (120, 61, 2, 1),
            (120, 121, 1, 0),
            (3900, 3600, 2, 1),
            (3900, 1950, 3, 2),
            (3900, 1951, 2, 1),
            (3900, 3901, 1, 0),
            (3900, 1, 4, 3),
            (0, 1, 1, 0),
            (0, 0, 4, 3),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .respond_with(
                    ResponseTemplate::new(429).insert_header("retry-after", seconds.to_string()),
                )
                .expect(requests)
                .mount(&server)
                .await;
            let mut delays = Vec::new();
            let response = send_with_sleep(
                || std::future::ready(Ok(reqwest::Client::new().get(server.uri()))),
                "testing retries",
                Duration::from_secs(budget),
                |delay| {
                    delays.push(delay);
                    std::future::ready(())
                },
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(delays, vec![Duration::from_secs(seconds); sleeps]);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_retries_preserve_installation_exchange_and_secondary_limit_detection() {
        for status in [403, 429, 500, 502, 503, 504] {
            let server = MockServer::start().await;
            let failure = if status == 403 {
                ResponseTemplate::new(status).set_body_json(json!({
                    "message": "You have exceeded a secondary rate limit."
                }))
            } else {
                ResponseTemplate::new(status).insert_header("retry-after", "0")
            };
            Mock::given(method("POST"))
                .respond_with(failure)
                .up_to_n_times(1)
                .expect(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(201).set_body_json(json!({"token": "renewed"})))
                .expect(1)
                .with_priority(2)
                .mount(&server)
                .await;
            let uri = server.uri();
            let delays = tokio::task::spawn_blocking(move || {
                let client =
                    reqwest::blocking::Client::builder().timeout(REQUEST_TIMEOUT).build().unwrap();
                let mut delays = Vec::new();
                let response = send_blocking_with_sleep(
                    client
                        .post(format!("{uri}/api/v3/app/installations/42/access_tokens"))
                        .bearer_auth("test-jwt")
                        .header("User-Agent", "test-agent"),
                    "testing blocking retries",
                    |delay| delays.push(delay),
                )
                .unwrap();
                assert_eq!(response.status(), StatusCode::CREATED);
                assert_eq!(
                    response.json::<serde_json::Value>().unwrap(),
                    json!({"token": "renewed"})
                );
                delays
            })
            .await
            .unwrap();
            assert_eq!(delays.len(), 1);
            if status == 403 {
                assert!(delays[0] >= Duration::from_secs(60));
            } else {
                assert_eq!(delays[0], Duration::ZERO);
            }
            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 2);
            for request in requests {
                assert_eq!(request.url.path(), "/api/v3/app/installations/42/access_tokens");
                assert_eq!(request.headers["authorization"], "Bearer test-jwt");
                assert_eq!(request.headers["user-agent"], "test-agent");
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_permission_errors_keep_a_bounded_body_and_do_not_retry() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_bytes(vec![
                b'x';
                MAX_FORBIDDEN_BODY_BYTES
                    + 1
            ]))
            .expect(1)
            .mount(&server)
            .await;
        let uri = server.uri();
        tokio::task::spawn_blocking(move || {
            let response = send_blocking_with_sleep(
                reqwest::blocking::Client::new().post(uri.clone()),
                "testing blocking permissions",
                |_| panic!("ordinary permission failures must not retry"),
            )
            .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(response.url(), &Url::parse(&uri).unwrap());
            assert!(!response.headers().contains_key(reqwest::header::CONTENT_LENGTH));
            assert_eq!(response.bytes().unwrap().len(), MAX_FORBIDDEN_BODY_BYTES);
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_retry_count_and_wait_budget_are_bounded() {
        for (status, seconds, requests, sleeps) in
            [(429, 60, 3, 2), (429, 61, 2, 1), (429, 121, 1, 0), (503, 0, 4, 3)]
        {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("retry-after", seconds.to_string())
                        .set_body_string("still unavailable"),
                )
                .expect(requests)
                .mount(&server)
                .await;
            let uri = server.uri();
            let delays = tokio::task::spawn_blocking(move || {
                let mut delays = Vec::new();
                let response = send_blocking_with_sleep(
                    reqwest::blocking::Client::new().post(uri),
                    "testing blocking retry budget",
                    |delay| delays.push(delay),
                )
                .unwrap();
                assert_eq!(response.status().as_u16(), status);
                assert_eq!(response.text().unwrap(), "still unavailable");
                delays
            })
            .await
            .unwrap();
            assert_eq!(delays, vec![Duration::from_secs(seconds); sleeps]);
        }
    }

    #[tokio::test]
    async fn long_cooldowns_and_permission_errors_are_not_retried() {
        for (status, headers, body) in [
            (403, vec![], "Resource not accessible by integration"),
            (401, vec![], "Bad credentials"),
            (404, vec![], "Not Found"),
            (429, vec![("retry-after", "3600")], "rate limit exceeded"),
            (503, vec![("retry-after", "3600")], "unavailable"),
            (
                403,
                vec![("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "18446744073709551615")],
                "rate limit exceeded",
            ),
        ] {
            let server = MockServer::start().await;
            let expected = json!({"message": body});
            let mut template = ResponseTemplate::new(status).set_body_json(&expected);
            for (name, value) in headers {
                template = template.insert_header(name, value);
            }
            Mock::given(method("GET")).respond_with(template).expect(1).mount(&server).await;
            let url = Url::parse(&server.uri()).unwrap();
            let response =
                send(reqwest::Client::new().get(url.clone()), "testing retries").await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(response.url(), &url);
            assert_eq!(response.json::<serde_json::Value>().await.unwrap(), expected);
        }
    }
}
