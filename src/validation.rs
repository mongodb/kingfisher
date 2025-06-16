use std::{
    fs,
    hash::{Hash, Hasher},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Result;
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use http::StatusCode;
use liquid::Object;
use liquid_core::{Value, ValueView};
use once_cell::sync::OnceCell;
use reqwest::{header, header::HeaderValue, multipart, Client, Url};
use rustc_hash::FxHashMap;
use tokio::{sync::Notify, time};
use tracing::debug;

use crate::{
    location::OffsetSpan,
    matcher::{OwnedBlobMatch, SerializableCaptures},
    rules::rule::Validation,
};

mod aws;
mod azure;
mod gcp;
mod httpvalidation;
mod mongodb;
mod postgres;
mod utils;

const VALIDATION_CACHE_SECONDS: u64 = 1200; // 20 minutes
const MAX_VALIDATION_BODY_LEN: usize = 512;

// Use SkipMap-based cache instead of a mutex-wrapped FxHashMap.
type Cache = Arc<SkipMap<String, CachedResponse>>;

/// Returns an opaque 64-bit fingerprint for “same secret under the same rule”.
fn secret_fingerprint(m: &OwnedBlobMatch) -> u64 {
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    m.rule.syntax().id.hash(&mut hasher);

    // first capture = the secret text itself
    if let Some(c0) = m.captures.captures.get(0) {
        c0.value.hash(&mut hasher);
    }
    hasher.finish()
}

static VALIDATION_CACHE: OnceCell<DashMap<u64, CachedResponse>> = OnceCell::new();
static IN_FLIGHT: OnceCell<DashMap<u64, Arc<Notify>>> = OnceCell::new();

/// Call this once near program start (e.g. in `main()`)
pub fn init_validation_caches() {
    VALIDATION_CACHE.set(DashMap::new()).ok();
    IN_FLIGHT.set(DashMap::new()).ok();
}

// #[derive(Clone, FilterReflection, ParseFilter)]
// #[filter(
//     name = "b64enc",
//     description = "Encodes the input string using Base64 encoding",
//     parsed(B64EncFilter)
// )]
// pub struct B64EncFilterParser;

// #[derive(Debug, Default, Clone)]
// pub struct B64EncFilter;

// impl std::fmt::Display for B64EncFilter {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         write!(f, "b64enc")
//     }
// }

// impl Filter for B64EncFilter {
//     fn evaluate(
//         &self,
//         input: &dyn ValueView,
//         _runtime: &dyn Runtime,
//     ) -> Result<Value, LiquidError> {
//         let input_str = input.to_kstr().into_owned();
//         let encoded = general_purpose::STANDARD.encode(input_str.as_bytes());
//         Ok(Value::scalar(encoded))
//     }
// }

#[derive(Clone)]
pub struct CachedResponse {
    pub body: String,
    pub status: StatusCode,
    pub is_valid: bool,
    pub timestamp: Instant,
}

impl CachedResponse {
    pub fn new(body: String, status: StatusCode, is_valid: bool) -> Self {
        Self { body, status, is_valid, timestamp: Instant::now() }
    }

    pub fn is_still_valid(&self, cache_duration: Duration) -> bool {
        self.timestamp.elapsed() < cache_duration
    }
}

/// Collect dependent variables and missing dependencies from the provided matches.
pub fn collect_variables_and_dependencies(
    matches: &[OwnedBlobMatch],
) -> (FxHashMap<String, Vec<(String, OffsetSpan)>>, FxHashMap<String, Vec<String>>) {
    let mut variable_map: FxHashMap<String, Vec<(String, OffsetSpan)>> = FxHashMap::default();
    let mut missing_deps: FxHashMap<String, Vec<String>> = FxHashMap::default();

    for m in matches {
        let rule_id = m.rule.syntax().id.clone();
        for dependency in m.rule.syntax().depends_on_rule.iter().flatten() {
            let dependency_rule_id = &dependency.rule_id;
            // Use iterator adapter to get all matching dependencies.
            let matching_dependencies: Vec<_> =
                matches.iter().filter(|x| x.rule.syntax().id == *dependency_rule_id).collect();

            if !matching_dependencies.is_empty() {
                for other_match in matching_dependencies {
                    let matching_input = other_match
                        .captures
                        .captures
                        .get(1)
                        .or_else(|| other_match.captures.captures.get(0))
                        .expect("Expected at least one capture");
                    variable_map
                        .entry(dependency.variable.to_uppercase())
                        .or_insert_with(Vec::new)
                        .push((
                            matching_input.value.to_string(),
                            other_match.matching_input_offset_span,
                        ));
                }
            } else {
                missing_deps.entry(rule_id.clone()).or_default().push(dependency.rule_id.clone());
            }
        }
    }
    (variable_map, missing_deps)
}

/// Render a template and parse the resulting string as a URL.
async fn render_and_parse_url(
    parser: &liquid::Parser,
    globals: &liquid::Object,
    rule_name: &str,
    template_url: &str,
) -> Result<Url, String> {
    let rendered_url_str =
        render_template(parser, globals, rule_name, template_url).await.map_err(|e| {
            let error_msg = format!("Error rendering URL template: <{}> {}", rule_name, e);
            debug!("{}", error_msg);
            error_msg
        })?;

    let url = Url::parse(&rendered_url_str).map_err(|e| {
        let error_msg = format!("Error parsing rendered URL: {}", e);
        debug!("{}", error_msg);
        error_msg
    })?;

    // Check if the URL is resolvable.
    utils::check_url_resolvable(&url).await.map_err(|e| {
        let error_msg = format!("URL resolution failed: {}", e);
        error_msg
    })?;

    Ok(url)
}

/// Render a template string using Liquid.
async fn render_template(
    parser: &liquid::Parser,
    globals: &liquid::Object,
    rule_name: &str,
    template_str: &str,
) -> Result<String, String> {
    parser
        .parse(template_str)
        .map_err(|e| {
            let msg = format!("Error parsing template for rule <{}>: {}", rule_name, e);
            debug!("{}", msg);
            msg
        })
        .and_then(|template| {
            template.render(globals).map_err(|e| {
                let msg = format!("Error rendering template for rule <{}>: {}", rule_name, e);
                debug!("{}", msg);
                msg
            })
        })
}

/// Validate a single match with a timeout of 60 seconds.
pub async fn validate_single_match(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    client: &Client,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
) {
    let timeout_result = time::timeout(Duration::from_secs(60), async {
        timed_validate_single_match(
            m,
            parser,
            client,
            dependent_variables,
            missing_dependencies,
            cache,
        )
        .await
    })
    .await;

    if timeout_result.is_err() {
        m.validation_success = false;
        m.validation_response_body = "Validation timed out after 60 seconds".to_string();
        m.validation_response_status = StatusCode::REQUEST_TIMEOUT;
    }
}

/// Perform the actual validation of a match.
/// Guarantees that each <RULE-ID>|<secret> is validated only once per process,
/// even when `--no-dedup` is used.
async fn timed_validate_single_match<'a>(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    client: &Client,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
) {
    // ──────────────────────────────────────────────────────────
    // 1. process-wide fingerprint de-dup
    // ──────────────────────────────────────────────────────────
    let fp = secret_fingerprint(m);

    if let Some(entry) = VALIDATION_CACHE.get_or_init(DashMap::new).get(&fp) {
        if entry.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = entry.is_valid;
            m.validation_response_body = entry.body.clone();
            m.validation_response_status = entry.status;
            return;
        }
    }
    if let Some(wait) = IN_FLIGHT.get_or_init(DashMap::new).get(&fp) {
        wait.notified().await;
        if let Some(entry) = VALIDATION_CACHE.get().unwrap().get(&fp) {
            m.validation_success = entry.is_valid;
            m.validation_response_body = entry.body.clone();
            m.validation_response_status = entry.status;
        }
        return;
    }
    let notify = Arc::new(Notify::new());
    IN_FLIGHT.get().unwrap().insert(fp, notify.clone());

    // helper to persist result + notify waiters
    let commit_and_return = |m: &OwnedBlobMatch| {
        VALIDATION_CACHE.get().unwrap().insert(
            fp,
            CachedResponse {
                body: m.validation_response_body.clone(),
                status: m.validation_response_status,
                is_valid: m.validation_success,
                timestamp: Instant::now(),
            },
        );
        IN_FLIGHT.get().unwrap().remove(&fp);
        notify.notify_waiters();
    };
    // ──────────────────────────────────────────────────────────

    // 2. dependency check
    if let Some(missing) = missing_dependencies.get(&m.rule.syntax().id) {
        if !missing.is_empty() {
            m.validation_success = false;
            m.validation_response_body =
                format!("Validation skipped – missing dependent rules: {}", missing.join(", "));
            m.validation_response_status = StatusCode::PRECONDITION_REQUIRED;
            commit_and_return(m);
            return;
        }
    }

    // 3. capture processing
    let match_re_result = m.rule.syntax().as_anchored_regex();
    let mut captured_values: Vec<(String, String, usize, usize)> = match match_re_result {
        Ok(_) => utils::process_captures(&m.captures),
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = format!("Regex error: {}", e);
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            commit_and_return(m);
            return;
        }
    };

    for dep in m.rule.syntax().depends_on_rule.iter().flatten() {
        if let Some(vals) = dependent_variables.get(&dep.variable.to_uppercase()) {
            for (val, span) in vals {
                captured_values.push((
                    dep.variable.to_uppercase(),
                    val.clone(),
                    span.start,
                    span.end,
                ));
            }
        }
    }

    let mut globals = Object::new();
    for (k, v, ..) in &captured_values {
        globals.insert(k.to_uppercase().into(), Value::scalar(v.clone()));
    }

    let rule_syntax = m.rule.syntax();

    // ──────────────────────────────────────────────────────────
    // 4. validator switch
    // ──────────────────────────────────────────────────────────
    match &rule_syntax.validation {
        // ---------------------------------------------------- HTTP validator
        Some(Validation::Http(http_validation)) => {
            // render URL
            let url = match render_and_parse_url(
                parser,
                &globals,
                &rule_syntax.name,
                &http_validation.request.url,
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = e;
                    m.validation_response_status = StatusCode::BAD_REQUEST;
                    commit_and_return(m);
                    return;
                }
            };

            // build request builder
            let request_builder = match httpvalidation::build_request_builder(
                client,
                &http_validation.request.method,
                &url,
                &http_validation.request.headers,
                parser,
                &globals,
            ) {
                Ok(rb) => rb,
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = e;
                    m.validation_response_status = StatusCode::BAD_REQUEST;
                    commit_and_return(m);
                    return;
                }
            };

            let is_multipart = http_validation.request.multipart.is_some();
            let mut cache_key = String::new();

            // old per-request cache (optional)
            if !is_multipart {
                cache_key = httpvalidation::generate_http_cache_key_parts(
                    http_validation.request.method.as_str(),
                    &url,
                    &http_validation.request.headers,
                );
                if let Some(cached) = cache.get(&cache_key) {
                    let c = cached.value();
                    if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                        m.validation_success = c.is_valid;
                        m.validation_response_body = c.body.clone();
                        m.validation_response_status = c.status;
                        commit_and_return(m);
                        return;
                    }
                }
            }

            // helper to execute single non-multipart request with retry
            let exec_single = |builder: reqwest::RequestBuilder| async {
                httpvalidation::retry_request(
                    builder,
                    1,
                    Duration::from_millis(500),
                    Duration::from_secs(2),
                )
                .await
            };

            // run request (multipart vs non-multipart)
            let resp_res = if is_multipart {
                // build multipart request each retry
                let build_request = || async {
                    let method = httpvalidation::parse_http_method(&http_validation.request.method)
                        .unwrap_or(reqwest::Method::GET);

                    let mut fresh_builder =
                        client.request(method, url.clone()).timeout(Duration::from_secs(5));

                    if let Ok(mut headers) = httpvalidation::process_headers(
                        &http_validation.request.headers,
                        parser,
                        &globals,
                        &url,
                    ) {
                        // add realistic UA & accept headers
                        let ua = format!(
                            "{} {}/{}",
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                             AppleWebKit/537.36 (KHTML, like Gecko) \
                             Chrome/132.0.0.0 Safari/537.36",
                            env!("CARGO_PKG_NAME"),
                            env!("CARGO_PKG_VERSION")
                        );
                        let std_headers = [
                            (header::USER_AGENT, ua.as_str()),
                            (header::ACCEPT , "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"),
                            (header::ACCEPT_LANGUAGE, "en-US,en;q=0.5"),
                            (header::ACCEPT_ENCODING, "gzip, deflate, br"),
                            (header::CONNECTION, "keep-alive"),
                        ];
                        for (hn, hv) in &std_headers {
                            if let Ok(v) = HeaderValue::from_str(hv) {
                                headers.insert(hn.clone(), v);
                            }
                        }
                        fresh_builder = fresh_builder.headers(headers);
                    }

                    // build multipart form
                    let mut form = multipart::Form::new();
                    for part in http_validation.request.multipart.as_ref().unwrap().parts.iter() {
                        match part.part_type.as_str() {
                            "file" => {
                                let path = render_template(
                                    parser,
                                    &globals,
                                    &rule_syntax.name,
                                    &part.content,
                                )
                                .await
                                .unwrap_or_default();
                                let bytes = fs::read(path).unwrap_or_default();
                                let p = multipart::Part::bytes(bytes)
                                    .mime_str(
                                        part.content_type
                                            .as_deref()
                                            .unwrap_or("application/octet-stream"),
                                    )
                                    .unwrap_or_else(|_| multipart::Part::text("invalid"));
                                form = form.part(part.name.clone(), p);
                            }
                            "text" => {
                                let txt = render_template(
                                    parser,
                                    &globals,
                                    &rule_syntax.name,
                                    &part.content,
                                )
                                .await
                                .unwrap_or_default();
                                let p = multipart::Part::text(txt)
                                    .mime_str(part.content_type.as_deref().unwrap_or("text/plain"))
                                    .unwrap_or_else(|_| multipart::Part::text("invalid"));
                                form = form.part(part.name.clone(), p);
                            }
                            _ => { /* ignore */ }
                        }
                    }
                    fresh_builder.multipart(form)
                };

                httpvalidation::retry_multipart_request(
                    build_request,
                    1,
                    Duration::from_millis(500),
                    Duration::from_secs(2),
                )
                .await
            } else {
                exec_single(request_builder).await
            };

            // handle result
            match resp_res {
                Ok(resp) => {
                    let status = resp.status();
                    let headers = resp.headers().clone();
                    let mut body = match resp.text().await {
                        Ok(b) => b,
                        Err(e) => {
                            m.validation_success = false;
                            m.validation_response_body = format!("Error reading response: {}", e);
                            m.validation_response_status = StatusCode::BAD_GATEWAY;
                            commit_and_return(m);
                            return;
                        }
                    };
                    if body.len() > MAX_VALIDATION_BODY_LEN {
                        body.truncate(MAX_VALIDATION_BODY_LEN);
                    }

                    m.validation_response_status = status;
                    m.validation_response_body = body.clone();
                    m.validation_success = httpvalidation::validate_response(
                        &http_validation.request.response_matcher,
                        &body,
                        &status,
                        &headers,
                        http_validation.request.response_is_html,
                    );

                    if !is_multipart && !cache_key.is_empty() {
                        cache.insert(
                            cache_key,
                            CachedResponse {
                                body,
                                status,
                                is_valid: m.validation_success,
                                timestamp: Instant::now(),
                            },
                        );
                    }
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("HTTP error: {:?}", e);
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                }
            }
        }

        // ---------------------------------------------------- MongoDB validator
        Some(Validation::MongoDB) => {
            let uri = globals
                .get("TOKEN")
                .and_then(|v| v.as_scalar())
                .map(|s| s.into_owned().to_kstr().to_string())
                .unwrap_or_default();

            if uri.is_empty() {
                m.validation_success = false;
                m.validation_response_body = "MongoDB URI not found.".to_string();
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            match mongodb::validate_mongodb(&uri).await {
                Ok(ok) => {
                    m.validation_success = ok;
                    m.validation_response_body = if ok {
                        "MongoDB connection is valid."
                    } else {
                        "MongoDB connection failed."
                    }
                    .to_string();
                    m.validation_response_status =
                        if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("MongoDB validation error: {}", e);
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                }
            }
        }

        // ------------------------------------------------ Azure Storage validator
        Some(Validation::AzureStorage) => {
            let storage_key = captured_values
                .iter()
                .find(|(n, ..)| n == "TOKEN")
                .map(|(_, v, ..)| v.clone())
                .unwrap_or_default();
            let storage_account =
                utils::find_closest_variable(&captured_values, &storage_key, "TOKEN", "AZURENAME")
                    .unwrap_or_default();

            if storage_account.is_empty() || storage_key.is_empty() {
                m.validation_success = false;
                m.validation_response_body = "Missing Azure Storage account or key.".to_string();
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            let creds_json = format!(
                r#"{{"storage_account":"{}","storage_key":"{}"}}"#,
                storage_account, storage_key
            );
            let cache_key = azure::generate_azure_cache_key(&creds_json);

            if let Some(cached) = cache.get(&cache_key) {
                let c = cached.value();
                if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    commit_and_return(m);
                    return;
                }
            }

            match azure::validate_azure_storage_credentials(&creds_json, cache).await {
                Ok((ok, msg)) => {
                    m.validation_success = ok;
                    m.validation_response_body = msg;
                    m.validation_response_status =
                        if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("Azure Storage error: {}", e);
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                }
            }
            cache.insert(
                cache_key,
                CachedResponse {
                    body: m.validation_response_body.clone(),
                    status: m.validation_response_status,
                    is_valid: m.validation_success,
                    timestamp: Instant::now(),
                },
            );
        }

        // ------------------------------------------------ Postgres validator
        Some(Validation::Postgres) => {
            let pg_url = globals
                .get("TOKEN")
                .and_then(|v| v.as_scalar())
                .map(|s| s.into_owned().to_kstr().to_string())
                .unwrap_or_default();

            if pg_url.is_empty() {
                m.validation_success = false;
                m.validation_response_body = "Postgres URL not found.".to_string();
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            let cache_key = postgres::generate_postgres_cache_key(&pg_url);
            if let Some(cached) = cache.get(&cache_key) {
                let c = cached.value();
                if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    commit_and_return(m);
                    return;
                }
            }

            match postgres::validate_postgres(&pg_url).await {
                Ok((ok, meta)) => {
                    m.validation_success = ok;
                    m.validation_response_body = if ok {
                        format!("Postgres connection is valid. Metadata: {:?}", meta)
                    } else {
                        "Postgres connection failed.".to_string()
                    };
                    m.validation_response_status =
                        if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("Postgres error: {}", e);
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                }
            }
            cache.insert(
                cache_key,
                CachedResponse {
                    body: m.validation_response_body.clone(),
                    status: m.validation_response_status,
                    is_valid: m.validation_success,
                    timestamp: Instant::now(),
                },
            );
        }

        // ---------------------------------------------------- AWS validator
        Some(Validation::AWS) => {
            let secret = captured_values
                .iter()
                .find(|(n, ..)| n == "TOKEN")
                .map(|(_, v, ..)| v.clone())
                .unwrap_or_default();
            let akid = utils::find_closest_variable(&captured_values, &secret, "TOKEN", "AKID")
                .unwrap_or_default();

            if akid.is_empty() || secret.is_empty() {
                m.validation_success = false;
                m.validation_response_body = "Missing AWS access-key ID or secret.".to_string();
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            let cache_key = aws::generate_aws_cache_key(&akid, &secret);
            if let Some(cached) = cache.get(&cache_key) {
                let c = cached.value();
                if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    commit_and_return(m);
                    return;
                }
            }

            if let Err(e) = aws::validate_aws_credentials_input(&akid, &secret) {
                m.validation_success = false;
                m.validation_response_body = format!("Invalid AWS credentials ({}): {}", akid, e);
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            match aws::validate_aws_credentials(&akid, &secret, cache).await {
                Ok((ok, arn)) => {
                    m.validation_success = ok;
                    m.validation_response_body = format!("{} --- ARN: {}", akid, arn);
                    m.validation_response_status =
                        if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                    if let Ok(acct) = aws::aws_key_to_account_number(&akid) {
                        m.validation_response_body
                            .push_str(&format!(" --- AWS Account Number: {:012}", acct));
                    }
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("AWS validation error ({}): {}", akid, e);
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                }
            }
            cache.insert(
                cache_key,
                CachedResponse {
                    body: m.validation_response_body.clone(),
                    status: m.validation_response_status,
                    is_valid: m.validation_success,
                    timestamp: Instant::now(),
                },
            );
        }

        // ----------------------------------------------------- GCP validator
        Some(Validation::GCP) => {
            let gcp_json = globals
                .get("TOKEN")
                .and_then(|v| v.as_scalar())
                .map(|s| s.into_owned().to_kstr().to_string())
                .unwrap_or_default();

            if gcp_json.is_empty() {
                m.validation_success = false;
                m.validation_response_body = "GCP JSON not found.".to_string();
                m.validation_response_status = StatusCode::BAD_REQUEST;
                commit_and_return(m);
                return;
            }

            let cache_key = gcp::generate_gcp_cache_key(&gcp_json);
            if let Some(cached) = cache.get(&cache_key) {
                let c = cached.value();
                if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    commit_and_return(m);
                    return;
                }
            }

            match gcp::GcpValidator::new() {
                Ok(validator) => {
                    match validator.validate_gcp_credentials(&gcp_json.as_bytes()).await {
                        Ok((ok, meta)) => {
                            m.validation_success = ok;
                            m.validation_response_body = meta.join("\n");
                            m.validation_response_status =
                                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                        }
                        Err(e) => {
                            m.validation_success = false;
                            m.validation_response_body = format!("GCP validation error: {}", e);
                            m.validation_response_status = StatusCode::BAD_GATEWAY;
                        }
                    }
                }
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body = format!("Failed to create GCP validator: {}", e);
                    m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
                }
            }
            cache.insert(
                cache_key,
                CachedResponse {
                    body: m.validation_response_body.clone(),
                    status: m.validation_response_status,
                    is_valid: m.validation_success,
                    timestamp: Instant::now(),
                },
            );
        }

        // --------------------------------------------------------- Raw / none
        Some(Validation::Raw(raw)) => {
            debug!("Raw validation not implemented: {}", raw);
            m.validation_success = false;
            m.validation_response_body = "Validator not implemented".to_string();
            m.validation_response_status = StatusCode::NOT_IMPLEMENTED;
        }
        None => { /* no validation specified */ }
    }

    // 5. persist result for success path
    commit_and_return(m);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::Result;
    use crossbeam_skiplist::SkipMap;
    use http::StatusCode;
    use rustc_hash::FxHashMap;

    use crate::{
        blob::BlobId,
        liquid_filters::register_all,
        location::OffsetSpan,
        matcher::{OwnedBlobMatch, SerializableCapture, SerializableCaptures},
        rules::{
            rule::{Confidence, Rule},
            Rules,
        },
        validation::{validate_single_match, Cache},
    };
    #[tokio::test]
    async fn test_actual_pypi_token_validation() -> Result<()> {
        // Minimal PyPI YAML snippet for testing
        let pypi_yaml = r#"
rules:
  - name: PyPI Upload Token
    id: kingfisher.pypi.1
    pattern: |
      (?x)
      \b
      (
        pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}
      )
      (?:[^a-zA-Z0-9_-]|$)
    min_entropy: 4.0
    confidence: medium
    examples:
      - '# password = pypi-AgEIcHlwaS5vcmcCJDkwNzYwNzU1LWMwOTUtNGNkOC1iYjQzLTU3OWNhZjI1NDQ1MwACJXsicGVybWCf99lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgSpW5PAywXvchMUQnkF5H6-SolJysfUvIWopMsxE4hCM'
      - 'password: pypi-AgEIcHlwaS5vcmcCJGExMDIxZjRhLTFhZDMtNDc4YS1iOWNmLWQwCf99OTIwZjFjNwACSHsicGVybWlzc2lvbnMiOiB7InByb2plY3RzIjogWyJkamFuZ28tY2hhbm5lbHMtanNvbnJwYyJdfSwgInZlcnNpb24iOiAxfQAABiBZg48cIBQt7HckwM4G3q-462xphsLbm7IZvjqMS4jvQw'
    validation:
      type: Http
      content:
        request:
          method: POST
          url: https://upload.pypi.org/legacy/
          headers:
            Authorization: 'Basic {{ "__token__:" | append: TOKEN | b64enc }}'
          multipart:
            parts:
              - name: name
                type: text
                content: "my-package"
              - name: version
                type: text
                content: "0.0.1"
              - name: filetype
                type: text
                content: "sdist"
              - name: metadata_version
                type: text
                content: "2.1"
              - name: summary
                type: text
                content: "A simple example package"
              - name: home_page
                type: text
                content: "https://github.com/yourusername/my_package"
              - name: sha256_digest
                type: text
                content: "0447379dd46c4ca8b8992bda56d07b358d015efb9300e6e16f224f4536e71d64"
              - name: md5_digest
                type: text
                content: "9b4036ab91a71124ab9f1d32a518e2bb"
              - name: :action
                type: text
                content: "file_upload"
              - name: protocol_version
                type: text
                content: "1"
              - name: content
                type: file
                content: "path/to/my_package-0.0.1.tar.gz"
                content_type: "application/octet-stream"
        "#;
        // Use from_paths_and_contents to parse the YAML snippet into a Rules object
        let data = vec![(std::path::Path::new("pypi_test.yaml"), pypi_yaml.as_bytes())];
        let rules = Rules::from_paths_and_contents(data, Confidence::Low)?;
        // Find the PyPI rule we just loaded
        let pypi_rule_syntax = rules
            .rules
            .iter()
            .find(|r| r.id == "kingfisher.pypi.1")
            .expect("Failed to find PyPI rule in test YAML")
            .clone(); // Clone so we can create a `Rule` from it
                      // Wrap that into a `Rule` object
        let pypi_rule = Rule::new(pypi_rule_syntax);
        //////////////////////////////////////////
        //
        // Your actual PyPI token to test
        let token = "<enter_pypi_token_here>";
        let id = BlobId::new(&pypi_yaml.as_bytes());
        // Construct an `OwnedBlobMatch` (all fields needed):
        let mut owned_blob_match = OwnedBlobMatch {
            rule: pypi_rule.into(),
            blob_id: id,
            finding_fingerprint: 0, // dummy value
            // matching_input: token.as_bytes().to_vec(),
            matching_input_offset_span: OffsetSpan { start: 0, end: token.len() },
            captures: SerializableCaptures {
                captures: vec![SerializableCapture {
                    name: Some("TOKEN".to_string()),
                    match_number: -1,
                    start: 0,
                    end: token.len(),
                    value: token.into(),
                }],
            },
            validation_response_body: String::new(),
            validation_response_status: StatusCode::OK,
            validation_success: false,
            calculated_entropy: 0.0, // or compute your own
        };
        let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
        let client = reqwest::Client::new();
        let cache: Cache = Arc::new(SkipMap::new());
        let dependent_vars = FxHashMap::default();
        let missing_deps = FxHashMap::default();
        // Run the validation
        validate_single_match(
            &mut owned_blob_match,
            &parser,
            &client,
            &dependent_vars,
            &missing_deps,
            &cache,
        )
        .await;
        println!("Success? {:?}", owned_blob_match.validation_success);
        println!("Status: {:?}", owned_blob_match.validation_response_status);
        println!("Body: {:?}", owned_blob_match.validation_response_body);
        Ok(())
    }
}
