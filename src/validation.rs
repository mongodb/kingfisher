use std::{
    collections::BTreeMap,
    fs,
    hash::{Hash, Hasher},
    panic::AssertUnwindSafe,
    sync::Arc,
    time::{Duration, Instant},
};

use std::sync::{LazyLock, OnceLock};

use anyhow::Result;
use dashmap::DashMap;
use futures::FutureExt;
use http::StatusCode;
use liquid::Object;
use liquid_core::{Value, ValueView};
use reqwest::{Client, Url, header, header::HeaderValue, multipart};
use rustc_hash::{FxHashMap, FxHashSet};
use tokio::{sync::Notify, time};
use tracing::{debug, trace, warn};

use crate::{
    cli::global::TlsMode,
    location::OffsetSpan,
    matcher::{OwnedBlobMatch, SerializableCaptures},
    provider_endpoints::{
        ProviderEndpointOverrides, endpoint_var_names, hydrate_endpoint_globals_for_rule,
    },
    rules::rule::Validation,
    validation_body::{self},
};

use crate::grpc_validation;
use crate::validation_rate_limit::should_rate_limit_validation;

// Re-export TlsMode from kingfisher_rules for use in client_for_rule
pub use kingfisher_rules::TlsMode as RuleTlsMode;

pub use kingfisher_scanner::validation::CachedResponse;
pub use kingfisher_scanner::validation::aws;
pub use kingfisher_scanner::validation::http_validation as httpvalidation;
pub use kingfisher_scanner::validation::mysql::validate_mysql;
pub use kingfisher_scanner::validation::postgres::validate_postgres;
pub use kingfisher_scanner::validation::{
    azure, coinbase, gcp, jdbc, jwt, mongodb, mysql, postgres,
};
pub mod utils;

const VALIDATION_CACHE_SECONDS: u64 = 1200; // 20 minutes

fn truncate_to_char_boundary(s: &mut String, max_len: usize) {
    if s.len() <= max_len {
        return;
    }

    let mut new_len = max_len;
    while new_len > 0 && !s.is_char_boundary(new_len) {
        new_len -= 1;
    }

    s.truncate(new_len);
}

/// Build a truncated preview from `body` without cloning the full string.
/// When `max_len` is 0, truncation is disabled and the full body is returned.
fn truncate_preview(body: &str, max_len: usize) -> String {
    if max_len == 0 || body.len() <= max_len {
        return body.to_string();
    }
    let mut end = max_len;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_string()
}

static USER_AGENT_SUFFIX: OnceLock<String> = OnceLock::new();

const BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
         AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/140.0.0.0 Safari/537.36";

fn build_user_agent() -> String {
    let base = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    if let Some(suffix) = USER_AGENT_SUFFIX.get() {
        format!("{base} {suffix} {BROWSER_USER_AGENT}")
    } else {
        format!("{base} {BROWSER_USER_AGENT}")
    }
}

pub static GLOBAL_USER_AGENT: LazyLock<String> = LazyLock::new(build_user_agent);

/// Configure a user-agent suffix that is appended after the Kingfisher package name/version.
///
/// The suffix is inserted before the browser portion of the user-agent. Empty or whitespace-only
/// values are ignored. This should be called once near program start prior to accessing
/// [`GLOBAL_USER_AGENT`].
pub fn set_user_agent_suffix<S: Into<String>>(suffix: Option<S>) {
    if let Some(suffix) = suffix {
        let trimmed = suffix.into().trim().to_string();
        if trimmed.is_empty() {
            return;
        }

        let _ = USER_AGENT_SUFFIX.set(trimmed.clone());
        kingfisher_scanner::validation::set_user_agent_suffix(Some(trimmed));
    }
}

/// Holds HTTP clients for different TLS validation modes.
///
/// This struct is created once at scan startup and passed through the validation chain.
/// The appropriate client is selected based on the global TLS mode and each rule's
/// declared `tls_mode` setting.
#[derive(Clone)]
pub struct ValidationClients {
    /// Client with full TLS certificate validation (WebPKI chain, hostname, expiry).
    strict: Client,
    /// Client that accepts self-signed or invalid certificates.
    /// Used when `--tls-mode=lax` AND the rule opts into lax validation,
    /// or when `--tls-mode=off`.
    lax: Client,
    /// The global TLS mode from CLI arguments.
    pub global_mode: TlsMode,
    /// When true, skip SSRF IP validation and allow requests to internal/private addresses.
    pub allow_internal_ips: bool,
}

/// Build a redirect policy that validates redirect targets against SSRF rules.
///
/// Each redirect hop is checked: IP-literal targets are validated directly via
/// `is_ssrf_safe_ip`, and hostname targets are resolved synchronously via
/// `std::net::ToSocketAddrs` so that all resolved IPs can be checked. This
/// significantly reduces the hostname-redirect SSRF risk (e.g., a public URL
/// that 302s to an attacker-controlled hostname resolving to `169.254.169.254`).
/// This is a best-effort check: reqwest performs its own DNS resolution when
/// connecting, so a malicious DNS server could return different IPs between
/// this check and the actual request (DNS rebinding / TOCTOU). A future
/// hardening step would be a pinned/custom resolver so that validated IPs are
/// exactly those used for the outbound connection.
///
/// **Note:** reqwest runs redirect callbacks on Tokio worker threads. The DNS
/// lookup uses `tokio::task::block_in_place` so the runtime can compensate
/// (e.g., spawn additional worker threads) rather than silently stalling.
pub(crate) fn ssrf_safe_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        // Cap redirect depth (reqwest default is 10)
        if attempt.previous().len() >= 10 {
            return attempt.error("too many redirects");
        }
        // Extract URL info before potentially moving `attempt`.
        let url = attempt.url().clone();
        if let Some(host) = url.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                // IP-literal: check directly without DNS.
                if !kingfisher_scanner::validation::is_ssrf_safe_ip(&ip) {
                    return attempt.error(format!(
                        "SSRF protection: redirect to non-public IP {} blocked",
                        ip
                    ));
                }
            } else {
                // Hostname: resolve and check all resolved IPs. We use
                // block_in_place to signal Tokio that this thread is about to
                // block on synchronous DNS, so the runtime can compensate.
                let port = url.port().unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
                let dns_result = tokio::task::block_in_place(|| {
                    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
                });
                match dns_result {
                    Ok(addrs) => {
                        for addr in addrs {
                            if !kingfisher_scanner::validation::is_ssrf_safe_ip(&addr.ip()) {
                                return attempt.error(format!(
                                    "SSRF protection: redirect to '{}' resolves to non-public IP {} — blocked",
                                    host,
                                    addr.ip()
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        // Fail closed: if we cannot resolve the hostname, we
                        // cannot guarantee the redirect target is SSRF-safe.
                        return attempt.error(format!(
                            "SSRF protection: cannot resolve redirect host '{}' ({}) — blocked",
                            host, e
                        ));
                    }
                }
            }
        }
        attempt.follow()
    })
}

impl ValidationClients {
    /// Create validation clients based on the global TLS mode.
    pub fn new(global_mode: TlsMode, allow_internal_ips: bool) -> anyhow::Result<Self> {
        let timeout = std::time::Duration::from_secs(30);

        let strict = Client::builder()
            .danger_accept_invalid_certs(false)
            .redirect(if allow_internal_ips {
                reqwest::redirect::Policy::default()
            } else {
                ssrf_safe_redirect_policy()
            })
            .timeout(timeout)
            .build()?;

        let lax = Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(if allow_internal_ips {
                reqwest::redirect::Policy::default()
            } else {
                ssrf_safe_redirect_policy()
            })
            .timeout(timeout)
            .build()?;

        Ok(Self { strict, lax, global_mode, allow_internal_ips })
    }

    /// Get the appropriate client for a given rule's TLS mode.
    ///
    /// The effective TLS mode depends on both the global setting and the rule's preference:
    /// - If global mode is `Off`, always use the lax client (no validation).
    /// - If global mode is `Lax` and the rule declares `tls_mode: lax`, use lax client.
    /// - Otherwise, use the strict client.
    pub fn client_for_rule(&self, rule_tls_mode: Option<kingfisher_rules::TlsMode>) -> &Client {
        match self.global_mode {
            TlsMode::Off => &self.lax,
            TlsMode::Lax => {
                // Convert rule's TlsMode to CLI TlsMode for comparison
                let rule_wants_lax = matches!(rule_tls_mode, Some(kingfisher_rules::TlsMode::Lax));
                if rule_wants_lax { &self.lax } else { &self.strict }
            }
            TlsMode::Strict => &self.strict,
        }
    }

    /// Check if lax TLS should be used for a rule.
    ///
    /// This is useful for non-HTTP validators (Postgres, MySQL, etc.) that need to
    /// configure their own TLS settings.
    pub fn should_use_lax(&self, rule_tls_mode: Option<kingfisher_rules::TlsMode>) -> bool {
        match self.global_mode {
            TlsMode::Off => true,
            TlsMode::Lax => matches!(rule_tls_mode, Some(kingfisher_rules::TlsMode::Lax)),
            TlsMode::Strict => false,
        }
    }
}

// Use SkipMap-based cache instead of a mutex-wrapped FxHashMap.
type Cache = kingfisher_scanner::validation::Cache;

/// Returns an opaque 64-bit key for internal validation deduplication.
///
/// This is an INTERNAL key used only for validation deduplication within a single scan.
/// It uses `captures.get(0)` to get the primary secret value. Rules with dependent
/// variables also include blob location because validation can depend on nearby context
/// such as an AWS access-key ID paired with a secret access key.
///
/// **Important**: This is distinct from the EXTERNAL `finding_fingerprint` used for:
/// - Baseline comparisons across scans
/// - Deduplication entries in external systems
/// - Reporting output
///
/// The external fingerprint uses `get(1).or_else(get(0))` for backward compatibility
/// and must remain stable. This internal key can evolve independently.
fn validation_dedup_key(m: &OwnedBlobMatch) -> u64 {
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    m.rule.syntax().id.hash(&mut hasher);

    // Use the first capture (primary secret) for deduplication.
    // Note: capture_value is stored in a variable because it's also used in trace! below.
    let capture_value = m.captures.captures.first().map(|c| c.raw_value());
    if let Some(val) = capture_value {
        val.hash(&mut hasher);
    }

    if !m.rule.syntax().depends_on_rule.is_empty() {
        m.blob_id.hash(&mut hasher);
        m.matching_input_offset_span.start.hash(&mut hasher);
        m.matching_input_offset_span.end.hash(&mut hasher);
    }

    let key = hasher.finish();

    trace!(
        rule_id = %m.rule.syntax().id,
        capture_value = ?capture_value,
        validation_dedup_key = key,
        "Computed internal validation dedup key"
    );

    key
}

static VALIDATION_CACHE: OnceLock<DashMap<u64, CachedResponse>> = OnceLock::new();
static IN_FLIGHT: OnceLock<DashMap<u64, Arc<Notify>>> = OnceLock::new();

fn cache_validation_result(fp: u64, m: &OwnedBlobMatch) {
    VALIDATION_CACHE.get_or_init(DashMap::new).insert(
        fp,
        CachedResponse {
            body: m.validation_response_body.clone(),
            status: m.validation_response_status,
            is_valid: m.validation_success,
            timestamp: Instant::now(),
        },
    );
}

fn clear_in_flight_validation(fp: u64) {
    if let Some((_, notify)) = IN_FLIGHT.get_or_init(DashMap::new).remove(&fp) {
        notify.notify_waiters();
    }
}

/// Call this once near program start (e.g. in `main()`)
pub fn init_validation_caches() {
    VALIDATION_CACHE.set(DashMap::new()).ok();
    IN_FLIGHT.set(DashMap::new()).ok();
    aws::set_aws_validation_concurrency(15);
}

/// Clear the static validation caches to reclaim memory after validation completes.
pub fn clear_validation_caches() {
    if let Some(c) = VALIDATION_CACHE.get() {
        c.clear();
        c.shrink_to_fit();
    }
    if let Some(c) = IN_FLIGHT.get() {
        c.clear();
        c.shrink_to_fit();
    }
}

pub fn set_skip_aws_account_ids<I, S>(ids: I)
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    aws::set_aws_skip_account_ids(ids);
}

/// Returns `true` if the provided string can be parsed as a MongoDB connection URI.
pub fn is_parseable_mongodb_uri(uri: &str) -> bool {
    mongodb::looks_like_mongodb_uri(uri)
}

/// Returns `true` if the provided string can be parsed as a Postgres connection URI.
pub fn is_parseable_postgres_uri(uri: &str) -> bool {
    postgres::parse_postgres_url(uri).is_ok()
}

/// Returns `true` if the provided string can be parsed as a MySQL connection URI.
pub fn is_parseable_mysql_uri(uri: &str) -> bool {
    mysql::parse_mysql_url(uri).is_ok()
}

/// Collect dependent variables and missing dependencies from the provided matches.
#[allow(clippy::type_complexity)]
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
                    // VALIDATION: Use get(0) for the primary capture value when collecting
                    // dependent variables. This ensures we get the main captured value rather
                    // than inner unnamed groups from nested captures like (?<REGEX>...(ABC)...).
                    //
                    // Note: This differs from fingerprint/reporting code which uses
                    // get(1).or_else(get(0)) for backward compatibility.
                    let matching_input = other_match
                        .captures
                        .captures
                        .first()
                        .expect("Expected at least one capture");
                    variable_map.entry(dependency.variable.to_uppercase()).or_default().push((
                        matching_input.raw_value().to_string(),
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
    allow_internal_ips: bool,
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

    // Check if the URL is resolvable (with SSRF protection).
    utils::check_url_resolvable(&url, allow_internal_ips).await.map_err(|e| {
        let error_msg = format!("URL <{}> resolution failed: {}", &url, e);
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

/// Validate a single match with a configurable timeout.
#[allow(clippy::too_many_arguments)]
pub async fn validate_single_match(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    clients: &ValidationClients,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
    validation_timeout: Duration,
    validation_retries: u32,
    rate_limiter: Option<&crate::validation_rate_limit::ValidationRateLimiter>,
    provider_endpoints: &ProviderEndpointOverrides,
    max_body_len: usize,
) {
    let fp = validation_dedup_key(m);
    // Keep the unwind boundary inside this module so the process-wide
    // validation de-dupe state is cleared before the caller observes a panic.
    // The panic branch below overwrites the match with a deterministic failure.
    let timeout_result = time::timeout(
        validation_timeout,
        AssertUnwindSafe(
            timed_validate_single_match(
                m,
                parser,
                clients,
                dependent_variables,
                missing_dependencies,
                cache,
                validation_timeout,
                validation_retries,
                rate_limiter,
                provider_endpoints,
                max_body_len,
            )
            .boxed(),
        )
        .catch_unwind(),
    )
    .await;

    match timeout_result {
        Ok(Ok(())) => {}
        Ok(Err(_panic_payload)) => {
            warn!(
                rule_id = %m.rule.syntax().id,
                "validator panicked; marking match as failed",
            );
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "Validation panicked for rule {}",
                m.rule.syntax().id
            ));
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            cache_validation_result(fp, m);
            clear_in_flight_validation(fp);
        }
        Err(_) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "Validation timed out after {} seconds",
                validation_timeout.as_secs()
            ));
            m.validation_response_status = StatusCode::REQUEST_TIMEOUT;
            cache_validation_result(fp, m);
            clear_in_flight_validation(fp);
        }
    }
}

/// Perform the actual validation of a match.
/// Guarantees that each <RULE-ID>|<secret> is validated only once per process,
/// even when `--no-dedup` is used.
#[allow(clippy::too_many_arguments)]
async fn timed_validate_single_match(
    m: &mut OwnedBlobMatch,
    parser: &liquid::Parser,
    clients: &ValidationClients,
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    missing_dependencies: &FxHashMap<String, Vec<String>>,
    cache: &Cache,
    validation_timeout: Duration,
    validation_retries: u32,
    rate_limiter: Option<&crate::validation_rate_limit::ValidationRateLimiter>,
    provider_endpoints: &ProviderEndpointOverrides,
    max_body_len: usize,
) {
    // Select the appropriate HTTP client based on rule's TLS mode preference
    let rule_tls_mode = m.rule.tls_mode();
    let client = clients.client_for_rule(rule_tls_mode);
    let use_lax_tls = clients.should_use_lax(rule_tls_mode);
    // ──────────────────────────────────────────────────────────
    // 1. process-wide fingerprint de-dup
    // ──────────────────────────────────────────────────────────
    let fp = validation_dedup_key(m);

    if let Some(entry) = VALIDATION_CACHE.get_or_init(DashMap::new).get(&fp)
        && entry.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS)
    {
        m.validation_success = entry.is_valid;
        m.validation_response_body = entry.body.clone();
        m.validation_response_status = entry.status;
        return;
    }
    if let Some(wait) =
        IN_FLIGHT.get_or_init(DashMap::new).get(&fp).map(|entry| entry.value().clone())
    {
        wait.notified().await;
        if let Some(entry) = VALIDATION_CACHE.get().unwrap().get(&fp) {
            m.validation_success = entry.is_valid;
            m.validation_response_body = entry.body.clone();
            m.validation_response_status = entry.status;
        }
        return;
    }
    IN_FLIGHT.get().unwrap().insert(fp, Arc::new(Notify::new()));

    // helper to persist result + notify waiters
    let commit_and_return = |m: &OwnedBlobMatch| {
        cache_validation_result(fp, m);
        clear_in_flight_validation(fp);
    };
    // ──────────────────────────────────────────────────────────

    // 2. dependency check
    if let Some(missing) = missing_dependencies.get(&m.rule.syntax().id)
        && !missing.is_empty()
    {
        m.validation_success = false;
        m.validation_response_body = validation_body::from_string(format!(
            "Validation skipped - missing dependent rules: {}",
            missing.join(", ")
        ));
        m.validation_response_status = StatusCode::PRECONDITION_REQUIRED;
        commit_and_return(m);
        return;
    }

    // 3. capture processing
    let match_re_result = m.rule.syntax().as_anchored_regex();
    let mut captured_values: Vec<(String, String, usize, usize)> = match match_re_result {
        Ok(_) => utils::process_captures(&m.captures),
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Regex error: {}", e));
            m.validation_response_status = StatusCode::INTERNAL_SERVER_ERROR;
            commit_and_return(m);
            return;
        }
    };

    for dep in m.rule.syntax().depends_on_rule.iter().flatten() {
        // Skip adding captured values for TOKEN dependencies
        if dep.variable.eq_ignore_ascii_case("TOKEN") {
            continue;
        }
        let dep_name = dep.variable.to_uppercase();
        if let Some(vals) = dependent_variables.get(&dep_name)
            && let Some((val, span)) =
                select_closest_dependency_value(vals, m.matching_input_offset_span)
        {
            captured_values.push((dep_name.clone(), val.clone(), span.start, span.end));
            // Store the dependent capture for later use in reporting
            // (e.g., generating validate/revoke commands)
            m.dependent_captures.insert(dep_name, val);
        }
    }

    let mut globals = Object::new();
    populate_globals_from_captures(&mut globals, &captured_values);
    hydrate_endpoint_globals_for_rule(m.rule.id(), &mut globals);
    provider_endpoints.apply_scan_overrides(&mut globals);

    // Persist named captures (non-TOKEN) for validate/revoke command generation.
    // This is especially important for gRPC validators like Modal where TOKEN_ID is required.
    for (k, v, ..) in &captured_values {
        if k.eq_ignore_ascii_case("TOKEN") {
            continue;
        }
        m.dependent_captures.entry(k.to_uppercase()).or_insert_with(|| v.clone());
    }
    for endpoint_var in endpoint_var_names() {
        if let Some(value) = globals.get(*endpoint_var).and_then(|v| v.as_scalar()) {
            m.dependent_captures
                .entry((*endpoint_var).to_string())
                .or_insert_with(|| value.to_kstr().to_string());
        }
    }

    {
        let rule_syntax = m.rule.syntax();
        if let (Some(limiter), Some(validation)) = (rate_limiter, rule_syntax.validation.as_ref())
            && should_rate_limit_validation(validation)
        {
            limiter.wait_for_rule(m.rule.id()).await;
        }
    }

    // ──────────────────────────────────────────────────────────
    // 4. validator dispatch
    //
    // Each validator lives in its own async fn so LLVM compiles
    // a separate, smaller poll function for each one.  This
    // prevents the combined stack frame from blowing the stack
    // on large concurrent workloads.
    //
    // We clone the validation enum to release the immutable
    // borrow on `m` before passing `m` mutably to each helper.
    // ──────────────────────────────────────────────────────────
    let rule_name = m.rule.syntax().name.clone();
    let validation = m.rule.syntax().validation.clone();
    let rule_tls_mode_for_raw = m.rule.syntax().tls_mode;

    match &validation {
        Some(Validation::Http(http_validation)) => {
            validate_http(
                m,
                http_validation,
                client,
                parser,
                &globals,
                cache,
                &rule_name,
                clients.allow_internal_ips,
                validation_timeout,
                validation_retries,
                max_body_len,
            )
            .await;
        }
        Some(Validation::Grpc(grpc_validation_cfg)) => {
            validate_grpc(
                m,
                grpc_validation_cfg,
                parser,
                &globals,
                &rule_name,
                clients.allow_internal_ips,
                validation_timeout,
                max_body_len,
            )
            .await;
        }
        Some(Validation::MongoDB) => {
            validate_mongodb_rule(m, &globals, cache, use_lax_tls).await;
        }
        Some(Validation::MySQL) => {
            validate_mysql_rule(m, &globals, cache, use_lax_tls).await;
        }
        Some(Validation::AzureStorage) => {
            validate_azure_storage(m, &captured_values, cache).await;
        }
        Some(Validation::Jdbc) => {
            validate_jdbc_rule(m, &captured_values, cache, use_lax_tls).await;
        }
        Some(Validation::Postgres) => {
            validate_postgres_rule(m, &globals, cache, use_lax_tls).await;
        }
        Some(Validation::JWT) => {
            validate_jwt_rule(m, &captured_values, use_lax_tls, clients.allow_internal_ips).await;
        }
        Some(Validation::AWS) => {
            validate_aws_rule(m, &captured_values, dependent_variables, cache).await;
        }
        Some(Validation::GCP) => {
            validate_gcp_rule(m, &globals, cache).await;
        }
        Some(Validation::Coinbase) => {
            validate_coinbase_rule(m, &globals, client, parser, cache).await;
        }
        Some(Validation::Raw(raw)) => {
            validate_raw_rule(
                m,
                raw,
                &globals,
                client,
                clients.should_use_lax(rule_tls_mode_for_raw),
                clients.allow_internal_ips,
            )
            .await;
        }
        None => { /* no validation specified */ }
    }

    // 5. persist result for success path
    commit_and_return(m);
}

// ═══════════════════════════════════════════════════════════════
// Extracted validator functions
// ═══════════════════════════════════════════════════════════════

#[allow(clippy::too_many_arguments)]
async fn validate_http(
    m: &mut OwnedBlobMatch,
    http_validation: &kingfisher_rules::rule::HttpValidation,
    client: &Client,
    parser: &liquid::Parser,
    globals: &Object,
    cache: &Cache,
    rule_name: &str,
    allow_internal_ips: bool,
    validation_timeout: Duration,
    validation_retries: u32,
    max_body_len: usize,
) {
    let request_timeout = validation_timeout;
    let multipart_timeout = validation_timeout;
    let max_retries: u32 = validation_retries;
    let request_globals = httpvalidation::with_request_template_globals(globals);
    let cache_globals = httpvalidation::with_cache_key_template_globals(globals);

    let url = match render_and_parse_url(
        parser,
        &request_globals,
        rule_name,
        &http_validation.request.url,
        allow_internal_ips,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let request_builder = match httpvalidation::build_request_builder(
        client,
        &http_validation.request.method,
        &url,
        &http_validation.request.headers,
        &http_validation.request.body,
        request_timeout,
        parser,
        &request_globals,
    ) {
        Ok(rb) => rb,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let is_multipart = http_validation.request.multipart.is_some();
    let mut cache_key = String::new();

    if !is_multipart {
        let cache_url =
            render_template(parser, &cache_globals, rule_name, &http_validation.request.url)
                .await
                .unwrap_or_else(|_| http_validation.request.url.clone());

        let rendered_headers = httpvalidation::process_headers(
            &http_validation.request.headers,
            parser,
            &cache_globals,
            &url,
        )
        .unwrap_or_default();

        let mut header_map = BTreeMap::new();
        for (name, value) in rendered_headers.iter() {
            if let Ok(v) = value.to_str() {
                header_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        let rendered_body = http_validation.request.body.as_ref().and_then(|body_template| {
            parser
                .parse(body_template)
                .ok()
                .and_then(|template| template.render(&cache_globals).ok())
        });

        cache_key = httpvalidation::generate_http_cache_key_parts(
            http_validation.request.method.as_str(),
            &cache_url,
            &header_map,
            rendered_body.as_deref(),
        );
        if let Some(cached) = cache.get(&cache_key) {
            let c = cached.value();
            if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                m.validation_success = c.is_valid;
                m.validation_response_body = c.body.clone();
                m.validation_response_status = c.status;
                return;
            }
        }
    }

    let exec_single = |builder: reqwest::RequestBuilder| async {
        httpvalidation::retry_request(
            builder,
            max_retries,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .await
    };

    let resp_res = if is_multipart {
        let build_request = || async {
            let method = httpvalidation::parse_http_method(&http_validation.request.method)
                .unwrap_or(reqwest::Method::GET);

            let mut fresh_builder = client.request(method, url.clone()).timeout(multipart_timeout);

            if let Ok(mut headers) = httpvalidation::process_headers(
                &http_validation.request.headers,
                parser,
                &request_globals,
                &url,
            ) {
                let std_headers = [
                    (header::USER_AGENT, GLOBAL_USER_AGENT.as_str()),
                    (
                        header::ACCEPT,
                        "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    ),
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

            let mut form = multipart::Form::new();
            for part in http_validation.request.multipart.as_ref().unwrap().parts.iter() {
                match part.part_type.as_str() {
                    "file" => {
                        let path =
                            render_template(parser, &request_globals, rule_name, &part.content)
                                .await
                                .unwrap_or_default();
                        let bytes = fs::read(path).unwrap_or_default();
                        let p = multipart::Part::bytes(bytes)
                            .mime_str(
                                part.content_type.as_deref().unwrap_or("application/octet-stream"),
                            )
                            .unwrap_or_else(|_| multipart::Part::text("invalid"));
                        form = form.part(part.name.clone(), p);
                    }
                    "text" => {
                        let txt =
                            render_template(parser, &request_globals, rule_name, &part.content)
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
            max_retries as usize,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .await
    } else {
        exec_single(request_builder).await
    };

    match resp_res {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.text().await {
                Ok(b) => b,
                Err(e) => {
                    m.validation_success = false;
                    m.validation_response_body =
                        validation_body::from_string(format!("Error reading response: {}", e));
                    m.validation_response_status = StatusCode::BAD_GATEWAY;
                    return;
                }
            };
            let display_body = if http_validation.request.response_is_html {
                utils::format_response_body_for_display(&body, max_body_len, true)
            } else {
                truncate_preview(&body, max_body_len)
            };

            m.validation_response_status = status;
            let body_opt = validation_body::from_string(display_body.clone());
            m.validation_response_body = body_opt.clone();
            let matchers = match http_validation.request.response_matcher.as_ref() {
                Some(m) => m,
                None => {
                    m.validation_success = false;
                    m.validation_response_body = validation_body::from_string(format!(
                        "HTTP validation for rule '{}' is missing `response_matcher`",
                        rule_name
                    ));
                    m.validation_response_status = StatusCode::BAD_REQUEST;
                    return;
                }
            };

            m.validation_success = httpvalidation::validate_response(
                matchers,
                &body,
                &status,
                &headers,
                http_validation.request.response_is_html,
            );

            let cacheable_status = !(status.is_server_error()
                || status == StatusCode::TOO_MANY_REQUESTS
                || status == StatusCode::REQUEST_TIMEOUT);
            if !is_multipart && !cache_key.is_empty() && cacheable_status {
                cache.insert(
                    cache_key,
                    CachedResponse {
                        body: body_opt,
                        status,
                        is_valid: m.validation_success,
                        timestamp: Instant::now(),
                    },
                );
            }
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("HTTP error: {:?}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn validate_grpc(
    m: &mut OwnedBlobMatch,
    grpc_validation_cfg: &kingfisher_rules::rule::GrpcValidation,
    parser: &liquid::Parser,
    globals: &Object,
    rule_name: &str,
    allow_internal_ips: bool,
    validation_timeout: Duration,
    max_body_len: usize,
) {
    let request_globals = httpvalidation::with_request_template_globals(globals);

    let url = match render_and_parse_url(
        parser,
        &request_globals,
        rule_name,
        &grpc_validation_cfg.request.url,
        allow_internal_ips,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(e);
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    let res = match grpc_validation::grpc_unary_call_from_rule(
        &url,
        &grpc_validation_cfg.request.headers,
        &grpc_validation_cfg.request.body,
        parser,
        &request_globals,
        validation_timeout,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!("gRPC error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
            return;
        }
    };

    let status = StatusCode::from_u16(res.http_status.as_u16()).unwrap_or(StatusCode::OK);
    let headers = res.headers;
    let mut body = String::from_utf8_lossy(&res.body_bytes).to_string();

    let grpc_status =
        headers.get("grpc-status").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let grpc_message =
        headers.get("grpc-message").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if grpc_status == "0" {
        body = "grpc-status=0".to_string();
    } else if (body.trim().is_empty() && (!grpc_status.is_empty() || !grpc_message.is_empty()))
        || body.as_bytes().contains(&0)
    {
        body = format!("grpc-status={grpc_status} grpc-message={grpc_message}");
    }
    if max_body_len > 0 {
        truncate_to_char_boundary(&mut body, max_body_len);
    }

    m.validation_response_status = status;
    m.validation_response_body = validation_body::from_string(body.clone());

    let matchers = match grpc_validation_cfg.request.response_matcher.as_ref() {
        Some(m) => m,
        None => {
            m.validation_success = false;
            m.validation_response_body = validation_body::from_string(format!(
                "gRPC validation for rule '{}' is missing `response_matcher`",
                rule_name
            ));
            m.validation_response_status = StatusCode::BAD_REQUEST;
            return;
        }
    };

    m.validation_success =
        httpvalidation::validate_response(matchers, &body, &status, &headers, false);
}

async fn validate_mongodb_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
) {
    let uri = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if uri.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("MongoDB URI not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = mongodb::generate_mongodb_cache_key(&uri);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match mongodb::validate_mongodb(&uri, use_lax_tls).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(msg);
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("MongoDB validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

async fn validate_mysql_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
) {
    let mysql_url = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if mysql_url.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("MySQL URL not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = mysql::generate_mysql_cache_key(&mysql_url);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match mysql::validate_mysql(&mysql_url, use_lax_tls).await {
        Ok((ok, meta)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(if ok {
                format!("MySQL connection is valid. Metadata: {:?}", meta)
            } else {
                "MySQL connection failed.".to_string()
            });
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("MySQL error: {}", e));
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

async fn validate_azure_storage(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    cache: &Cache,
) {
    let storage_key = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();
    let storage_account =
        utils::find_closest_variable(captured_values, storage_key.as_str(), "TOKEN", "AZURENAME")
            .unwrap_or_default();

    if storage_account.is_empty() || storage_key.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing Azure Storage account or key.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let creds_json =
        format!(r#"{{"storage_account":"{}","storage_key":"{}"}}"#, storage_account, storage_key);
    let cache_key = azure::generate_azure_cache_key(&creds_json);

    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
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
            m.validation_response_body =
                validation_body::from_string(format!("Azure Storage error: {}", e));
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

async fn validate_jdbc_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    cache: &Cache,
    use_lax_tls: bool,
) {
    let jdbc_conn = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    if jdbc_conn.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("JDBC connection string not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = jdbc::generate_jdbc_cache_key(&jdbc_conn);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match jdbc::validate_jdbc(&jdbc_conn, use_lax_tls).await {
        Ok(outcome) => {
            m.validation_success = outcome.valid;
            m.validation_response_body = validation_body::from_string(outcome.message);
            m.validation_response_status = outcome.status;
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("JDBC validation error: {}", e));
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

async fn validate_postgres_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    cache: &Cache,
    use_lax_tls: bool,
) {
    let pg_url = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if pg_url.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Postgres URL not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = postgres::generate_postgres_cache_key(&pg_url);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match postgres::validate_postgres(&pg_url, use_lax_tls).await {
        Ok((ok, meta)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(if ok {
                format!("Postgres connection is valid. Metadata: {:?}", meta)
            } else {
                "Postgres connection failed.".to_string()
            });
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Postgres error: {}", e));
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

async fn validate_jwt_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    let token = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    if token.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("JWT token not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    match jwt::validate_jwt(&token, use_lax_tls, allow_internal_ips).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = validation_body::from_string(msg);
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("JWT validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_REQUEST;
        }
    }
}

async fn validate_aws_rule(
    m: &mut OwnedBlobMatch,
    captured_values: &[(String, String, usize, usize)],
    dependent_variables: &FxHashMap<String, Vec<(String, OffsetSpan)>>,
    cache: &Cache,
) {
    let secret = captured_values
        .iter()
        .find(|(n, ..)| n == "TOKEN")
        .map(|(_, v, ..)| v.clone())
        .unwrap_or_default();

    if secret.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing AWS access-key ID or secret.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let akid_candidates = aws_akid_candidates(
        captured_values,
        dependent_variables.get("AKID"),
        m.matching_input_offset_span,
        &secret,
    );

    if akid_candidates.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing AWS access-key ID or secret.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let mut last_body = None;
    let mut last_status = StatusCode::UNAUTHORIZED;

    for akid in akid_candidates {
        let cache_key = aws::generate_aws_cache_key(&akid, &secret);
        if let Some(cached) = cache.get(&cache_key) {
            let c = cached.value();
            if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
                if c.is_valid {
                    m.validation_success = c.is_valid;
                    m.validation_response_body = c.body.clone();
                    m.validation_response_status = c.status;
                    return;
                }
                last_body = Some(c.body.clone());
                last_status = c.status;
                continue;
            }
        }

        if let Some(account_id) = aws::should_skip_aws_validation(&akid) {
            let body = validation_body::from_string(format!(
                "(skip list entry) AWS validation not attempted for account {}.",
                account_id
            ));
            cache.insert(
                cache_key,
                CachedResponse {
                    body: body.clone(),
                    status: StatusCode::PRECONDITION_REQUIRED,
                    is_valid: false,
                    timestamp: Instant::now(),
                },
            );
            last_body = Some(body);
            last_status = StatusCode::PRECONDITION_REQUIRED;
            continue;
        }

        if let Err(e) = aws::validate_aws_credentials_input(&akid, &secret) {
            let body =
                validation_body::from_string(format!("Invalid AWS credentials ({}): {}", akid, e));
            cache.insert(
                cache_key,
                CachedResponse {
                    body: body.clone(),
                    status: StatusCode::BAD_REQUEST,
                    is_valid: false,
                    timestamp: Instant::now(),
                },
            );
            last_body = Some(body);
            last_status = StatusCode::BAD_REQUEST;
            continue;
        }

        match aws::validate_aws_credentials(&akid, &secret).await {
            Ok((ok, msg)) => {
                if ok {
                    m.validation_success = true;
                    let mut body = format!("{} --- ARN: {}", akid, msg);
                    if let Ok(acct) = aws::aws_key_to_account_number(&akid) {
                        body.push_str(&format!(" --- AWS Account Number: {:012}", acct));
                    }
                    m.validation_response_body = validation_body::from_string(body);
                    m.validation_response_status = StatusCode::OK;
                    cache.insert(
                        cache_key,
                        CachedResponse {
                            body: m.validation_response_body.clone(),
                            status: m.validation_response_status,
                            is_valid: true,
                            timestamp: Instant::now(),
                        },
                    );
                    return;
                }

                let body = validation_body::from_string(format!(
                    "AWS validation error ({}): {}",
                    akid, msg
                ));
                cache.insert(
                    cache_key,
                    CachedResponse {
                        body: body.clone(),
                        status: StatusCode::UNAUTHORIZED,
                        is_valid: false,
                        timestamp: Instant::now(),
                    },
                );
                last_body = Some(body);
                last_status = StatusCode::UNAUTHORIZED;
            }
            Err(e) => {
                last_body = Some(validation_body::from_string(format!(
                    "AWS validation error ({}): {}",
                    akid, e
                )));
                last_status = StatusCode::BAD_GATEWAY;
            }
        }
    }

    m.validation_success = false;
    m.validation_response_body = last_body.unwrap_or_else(|| {
        validation_body::from_string("AWS validation failed for all nearby access-key IDs.")
    });
    m.validation_response_status = last_status;
}

fn aws_akid_candidates(
    captured_values: &[(String, String, usize, usize)],
    dependent_akids: Option<&Vec<(String, OffsetSpan)>>,
    target_span: OffsetSpan,
    secret: &str,
) -> Vec<String> {
    let mut candidates = Vec::new();

    if let Some(closest) = utils::find_closest_variable(captured_values, secret, "TOKEN", "AKID") {
        candidates.push((0usize, closest));
    }

    if let Some(values) = dependent_akids {
        candidates.extend(
            values
                .iter()
                .map(|(value, span)| (dependency_distance(*span, target_span), value.clone())),
        );
    }

    candidates.sort_by_key(|(distance, _)| *distance);

    let mut seen = FxHashSet::default();
    candidates
        .into_iter()
        .filter_map(|(_, value)| if seen.insert(value.clone()) { Some(value) } else { None })
        .take(64)
        .collect()
}

fn dependency_distance(span: OffsetSpan, target_span: OffsetSpan) -> usize {
    if span.end <= target_span.start {
        target_span.start - span.end
    } else {
        span.start.saturating_sub(target_span.end)
    }
}

async fn validate_gcp_rule(m: &mut OwnedBlobMatch, globals: &Object, cache: &Cache) {
    let gcp_json = globals
        .get("TOKEN")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if gcp_json.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("GCP JSON not found.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    let cache_key = gcp::generate_gcp_cache_key(&gcp_json);
    if let Some(cached) = cache.get(&cache_key) {
        let c = cached.value();
        if c.timestamp.elapsed() < Duration::from_secs(VALIDATION_CACHE_SECONDS) {
            m.validation_success = c.is_valid;
            m.validation_response_body = c.body.clone();
            m.validation_response_status = c.status;
            return;
        }
    }

    match gcp::GcpValidator::global() {
        Ok(validator) => match validator.validate_gcp_credentials(gcp_json.as_bytes()).await {
            Ok((ok, meta)) => {
                m.validation_success = ok;
                m.validation_response_body = validation_body::from_string(meta.join("\n"));
                m.validation_response_status =
                    if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
            }
            Err(e) => {
                m.validation_success = false;
                m.validation_response_body =
                    validation_body::from_string(format!("GCP validation error: {}", e));
                m.validation_response_status = StatusCode::BAD_GATEWAY;
            }
        },
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Failed to create GCP validator: {}", e));
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

async fn validate_coinbase_rule(
    m: &mut OwnedBlobMatch,
    globals: &Object,
    client: &Client,
    parser: &liquid::Parser,
    cache: &Cache,
) {
    let cred_name = globals
        .get("CRED_NAME")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();
    let private_key = globals
        .get("PRIVATE_KEY")
        .and_then(|v| v.as_scalar())
        .map(|s| s.into_owned().to_kstr().to_string())
        .unwrap_or_default();

    if cred_name.is_empty() || private_key.is_empty() {
        m.validation_success = false;
        m.validation_response_body =
            validation_body::from_string("Missing key name or private key.".to_string());
        m.validation_response_status = StatusCode::BAD_REQUEST;
        return;
    }

    match coinbase::validate_cdp_api_key(&cred_name, &private_key, client, parser, cache).await {
        Ok((ok, msg)) => {
            m.validation_success = ok;
            m.validation_response_body = msg;
            m.validation_response_status =
                if ok { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
        }
        Err(e) => {
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Coinbase validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

async fn validate_raw_rule(
    m: &mut OwnedBlobMatch,
    raw: &str,
    globals: &Object,
    client: &Client,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) {
    match kingfisher_scanner::validation::raw::validate_raw(
        raw,
        globals,
        client,
        use_lax_tls,
        allow_internal_ips,
    )
    .await
    {
        Ok(result) => {
            m.validation_success = result.valid;
            m.validation_response_body = validation_body::from_string(result.body);
            m.validation_response_status = result.status;
        }
        Err(e) => {
            debug!("Raw validation error for {}: {}", raw, e);
            m.validation_success = false;
            m.validation_response_body =
                validation_body::from_string(format!("Raw validation error: {}", e));
            m.validation_response_status = StatusCode::BAD_GATEWAY;
        }
    }
}

fn populate_globals_from_captures(
    globals: &mut Object,
    captured_values: &[(String, String, usize, usize)],
) {
    let mut best_token: Option<&String> = None;

    for (k, v, ..) in captured_values {
        if k.eq_ignore_ascii_case("TOKEN") {
            if best_token.is_none_or(|best| v.len() >= best.len()) {
                best_token = Some(v);
            }
        } else {
            globals.insert(k.to_uppercase().into(), Value::scalar(v.clone()));
        }
    }

    if let Some(token) = best_token {
        globals.insert("TOKEN".into(), Value::scalar(token.clone()));
    }
}

fn select_closest_dependency_value(
    values: &[(String, OffsetSpan)],
    target_span: OffsetSpan,
) -> Option<(String, OffsetSpan)> {
    let mut best_before: Option<(usize, (String, OffsetSpan))> = None;
    let mut best_overlap: Option<(usize, (String, OffsetSpan))> = None;
    let mut best_after: Option<(usize, (String, OffsetSpan))> = None;

    for (value, span) in values {
        if span.end <= target_span.start {
            let distance = target_span.start - span.end;
            match &mut best_before {
                Some((best_distance, best_value)) if distance < *best_distance => {
                    *best_distance = distance;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_before = Some((distance, (value.clone(), *span)));
                }
                _ => {}
            }
        } else if span.start >= target_span.end {
            let distance = span.start - target_span.end;
            match &mut best_after {
                Some((best_distance, best_value)) if distance < *best_distance => {
                    *best_distance = distance;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_after = Some((distance, (value.clone(), *span)));
                }
                _ => {}
            }
        } else {
            match &mut best_overlap {
                Some((best_distance, best_value)) if 0 < *best_distance => {
                    *best_distance = 0;
                    *best_value = (value.clone(), *span);
                }
                None => {
                    best_overlap = Some((0, (value.clone(), *span)));
                }
                _ => {}
            }
        }
    }

    best_before.or(best_overlap).or(best_after).map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn populate_globals_prefers_longest_token() {
        let captured_values = vec![
            ("TOKEN".to_string(), "short".to_string(), 0usize, 5usize),
            ("BODY".to_string(), "body".to_string(), 0usize, 4usize),
            ("TOKEN".to_string(), "longervalue".to_string(), 0usize, 11usize),
        ];

        let mut globals = Object::new();
        populate_globals_from_captures(&mut globals, &captured_values);

        assert_eq!(globals.get("TOKEN"), Some(Value::scalar("longervalue")).as_ref());
        assert_eq!(globals.get("BODY"), Some(Value::scalar("body")).as_ref());
    }

    #[test]
    fn populate_globals_handles_missing_token() {
        let captured_values = vec![("CHECKSUM".to_string(), "123456".to_string(), 0usize, 6usize)];

        let mut globals = Object::new();
        populate_globals_from_captures(&mut globals, &captured_values);

        assert!(globals.get("TOKEN").is_none());
        assert_eq!(globals.get("CHECKSUM"), Some(Value::scalar("123456")).as_ref());
    }

    #[test]
    fn select_closest_dependency_value_prefers_nearest_preceding_dependency() {
        let values = vec![
            ("first".to_string(), OffsetSpan::from_range(10..20)),
            ("second".to_string(), OffsetSpan::from_range(40..50)),
            ("third".to_string(), OffsetSpan::from_range(80..90)),
        ];

        let selected =
            select_closest_dependency_value(&values, OffsetSpan::from_range(55..60)).unwrap();

        assert_eq!(selected.0, "second");
        assert_eq!(selected.1, OffsetSpan::from_range(40..50));
    }

    #[test]
    fn select_closest_dependency_value_falls_back_to_nearest_following_dependency() {
        let values = vec![
            ("first".to_string(), OffsetSpan::from_range(70..80)),
            ("second".to_string(), OffsetSpan::from_range(90..100)),
        ];

        let selected =
            select_closest_dependency_value(&values, OffsetSpan::from_range(55..60)).unwrap();

        assert_eq!(selected.0, "first");
        assert_eq!(selected.1, OffsetSpan::from_range(70..80));
    }

    #[test]
    fn aws_akid_candidates_orders_by_proximity_and_deduplicates() {
        let captured_values = vec![
            ("TOKEN".to_string(), "secret".to_string(), 100usize, 140usize),
            ("AKID".to_string(), "closest_capture".to_string(), 80usize, 90usize),
        ];
        let dependent_akids = vec![
            ("far_before".to_string(), OffsetSpan::from_range(10..20)),
            ("near_after".to_string(), OffsetSpan::from_range(150..160)),
            ("overlap".to_string(), OffsetSpan::from_range(110..120)),
            ("closest_capture".to_string(), OffsetSpan::from_range(80..90)),
        ];

        let candidates = aws_akid_candidates(
            &captured_values,
            Some(&dependent_akids),
            OffsetSpan::from_range(100..140),
            "secret",
        );

        assert_eq!(candidates, vec!["closest_capture", "overlap", "near_after", "far_before"]);
    }

    #[test]
    fn aws_akid_candidates_caps_unique_candidates() {
        let dependent_akids = (0..70)
            .map(|i| (format!("akid{i}"), OffsetSpan::from_range((i * 2)..(i * 2 + 1))))
            .collect::<Vec<_>>();

        let candidates = aws_akid_candidates(
            &[],
            Some(&dependent_akids),
            OffsetSpan::from_range(1_000..1_010),
            "secret",
        );

        assert_eq!(candidates.len(), 64);
        assert_eq!(candidates.first().map(String::as_str), Some("akid69"));
        assert_eq!(candidates.last().map(String::as_str), Some("akid6"));
    }

    #[test]
    fn truncate_to_char_boundary_handles_multibyte_characters() {
        let max_len = 2048;
        let mut body = "a".repeat(max_len);
        body.push('é');

        truncate_to_char_boundary(&mut body, max_len);

        assert_eq!(body.len(), max_len);
        assert!(body.is_char_boundary(body.len()));
        assert!(body.ends_with('a'));
    }

    #[test]
    fn truncate_skipped_when_max_body_len_is_zero() {
        let original_len = 4096;
        let body = "x".repeat(original_len);

        let preview = truncate_preview(&body, 0);

        assert_eq!(preview.len(), original_len);
    }

    #[test]
    fn truncate_applies_custom_max_body_len() {
        let body = "y".repeat(5000);

        let preview = truncate_preview(&body, 1024);

        assert_eq!(preview.len(), 1024);
    }

    mod tls_mode_tests {
        use super::*;

        #[test]
        fn validation_clients_new_creates_both_clients() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();
            assert_eq!(clients.global_mode, TlsMode::Strict);

            let clients_lax = ValidationClients::new(TlsMode::Lax, false).unwrap();
            assert_eq!(clients_lax.global_mode, TlsMode::Lax);

            let clients_off = ValidationClients::new(TlsMode::Off, false).unwrap();
            assert_eq!(clients_off.global_mode, TlsMode::Off);
        }

        #[test]
        fn client_for_rule_strict_mode_always_returns_strict_client() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();

            // With no rule TLS mode
            let client1 = clients.client_for_rule(None);
            // With rule wanting lax
            let client2 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));
            // With rule wanting strict
            let client3 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict));

            // In strict mode, all should return the same strict client
            assert!(std::ptr::eq(client1, client2));
            assert!(std::ptr::eq(client2, client3));
        }

        #[test]
        fn client_for_rule_off_mode_always_returns_lax_client() {
            let clients = ValidationClients::new(TlsMode::Off, false).unwrap();

            // With no rule TLS mode
            let client1 = clients.client_for_rule(None);
            // With rule wanting lax
            let client2 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));
            // With rule wanting strict
            let client3 = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict));

            // In off mode, all should return the same lax client
            assert!(std::ptr::eq(client1, client2));
            assert!(std::ptr::eq(client2, client3));
        }

        #[test]
        fn client_for_rule_lax_mode_respects_rule_preference() {
            let clients = ValidationClients::new(TlsMode::Lax, false).unwrap();

            // Get references to understand which is which
            let strict_client = clients.client_for_rule(None);
            let lax_client = clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax));

            // When rule doesn't specify, should get strict
            assert!(std::ptr::eq(clients.client_for_rule(None), strict_client));

            // When rule wants strict, should get strict
            assert!(std::ptr::eq(
                clients.client_for_rule(Some(kingfisher_rules::TlsMode::Strict)),
                strict_client
            ));

            // When rule wants lax, should get lax
            assert!(std::ptr::eq(
                clients.client_for_rule(Some(kingfisher_rules::TlsMode::Lax)),
                lax_client
            ));

            // Strict and lax clients should be different
            assert!(!std::ptr::eq(strict_client, lax_client));
        }

        #[test]
        fn should_use_lax_off_mode_always_returns_true() {
            let clients = ValidationClients::new(TlsMode::Off, false).unwrap();

            assert!(clients.should_use_lax(None));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }

        #[test]
        fn should_use_lax_strict_mode_always_returns_false() {
            let clients = ValidationClients::new(TlsMode::Strict, false).unwrap();

            assert!(!clients.should_use_lax(None));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }

        #[test]
        fn should_use_lax_lax_mode_respects_rule_preference() {
            let clients = ValidationClients::new(TlsMode::Lax, false).unwrap();

            // Only true when rule explicitly opts in
            assert!(!clients.should_use_lax(None));
            assert!(!clients.should_use_lax(Some(kingfisher_rules::TlsMode::Strict)));
            assert!(clients.should_use_lax(Some(kingfisher_rules::TlsMode::Lax)));
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use std::sync::Arc;

//     use anyhow::Result;
//     use crossbeam_skiplist::SkipMap;
//     use http::StatusCode;
//     use rustc_hash::FxHashMap;
//     use smallvec::smallvec;

//     use crate::{
//         blob::BlobId,
//         liquid_filters::register_all,
//         location::OffsetSpan,
//         matcher::{OwnedBlobMatch, SerializableCapture, SerializableCaptures},
//         rules::{
//             rule::{Confidence, Rule},
//             Rules,
//         },
//         util::intern,
//         validation::{validate_single_match, Cache},
//     };
//     #[tokio::test]
//     async fn test_actual_pypi_token_validation() -> Result<()> {
//         // Minimal PyPI YAML snippet for testing
//         let pypi_yaml = r#"
// rules:
//   - name: PyPI Upload Token
//     id: kingfisher.pypi.1
//     pattern: |
//       (?x)
//       \b
//       (
//         pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}
//       )
//       (?:[^a-zA-Z0-9_-]|$)
//     min_entropy: 4.0
//     confidence: medium
//     examples:
//       - '# password = pypi-AgEIcHlwaS5vcmcCJDkwNzYwNzU1LWMwOTUtNGNkOC1iYjQzLTU3OWNhZjI1NDQ1MwACJXsicGVybWCf99lvbnMiOiAidXNlciIsICJ2ZXJzaW9uIjogMX0AAAYgSpW5PAywXvchMUQnkF5H6-SolJysfUvIWopMsxE4hCM'
//       - 'password: pypi-AgEIcHlwaS5vcmcCJGExMDIxZjRhLTFhZDMtNDc4YS1iOWNmLWQwCf99OTIwZjFjNwACSHsicGVybWlzc2lvbnMiOiB7InByb2plY3RzIjogWyJkamFuZ28tY2hhbm5lbHMtanNvbnJwYyJdfSwgInZlcnNpb24iOiAxfQAABiBZg48cIBQt7HckwM4G3q-462xphsLbm7IZvjqMS4jvQw'
//     validation:
//       type: Http
//       content:
//         request:
//           method: POST
//           url: https://upload.pypi.org/legacy/
//           response_is_html: true
//           response_matcher:
//             - report_response: true
//             - type: WordMatch
//               words:
//                 - "isn't allowed to upload to project"
//           headers:
//             Authorization: 'Basic {{ "__token__:" | append: TOKEN | b64enc }}'
//           multipart:
//             parts:
//               - name: name
//                 type: text
//                 content: "my-package"
//               - name: version
//                 type: text
//                 content: "0.0.1"
//               - name: filetype
//                 type: text
//                 content: "sdist"
//               - name: metadata_version
//                 type: text
//                 content: "2.1"
//               - name: summary
//                 type: text
//                 content: "A simple example package"
//               - name: home_page
//                 type: text
//                 content: "https://github.com/yourusername/my_package"
//               - name: sha256_digest
//                 type: text
//                 content: "0447379dd46c4ca8b8992bda56d07b358d015efb9300e6e16f224f4536e71d64"
//               - name: md5_digest
//                 type: text
//                 content: "9b4036ab91a71124ab9f1d32a518e2bb"
//               - name: :action
//                 type: text
//                 content: "file_upload"
//               - name: protocol_version
//                 type: text
//                 content: "1"
//               - name: content
//                 type: file
//                 content: "path/to/my_package-0.0.1.tar.gz"
//                 content_type: "application/octet-stream"
//         "#;
//         // Use from_paths_and_contents to parse the YAML snippet into a Rules object
//         let data = vec![(std::path::Path::new("pypi_test.yaml"), pypi_yaml.as_bytes())];
//         let rules = Rules::from_paths_and_contents(data, Confidence::Low)?;
//         // Find the PyPI rule we just loaded
//         let pypi_rule_syntax = rules
//             .iter_rules()
//             .find(|r| r.id == "kingfisher.pypi.1")
//             .expect("Failed to find PyPI rule in test YAML")
//             .clone(); // Clone so we can create a `Rule` from it
//                       // Wrap that into a `Rule` object
//         let pypi_rule = Rule::new(pypi_rule_syntax);
//         //////////////////////////////////////////
//         //
//         // Your actual PyPI token to test
//         let token = "<enter_pypi_token_here>";
//         let id = BlobId::new(&pypi_yaml.as_bytes());
//         // Construct an `OwnedBlobMatch` (all fields needed):
//         let mut owned_blob_match = OwnedBlobMatch {
//             rule: pypi_rule.into(),
//             blob_id: id,
//             finding_fingerprint: 0, // dummy value
//             // matching_input: token.as_bytes().to_vec(),
//             matching_input_offset_span: OffsetSpan { start: 0, end: token.len() },
//             captures: SerializableCaptures {
//                 captures: smallvec![SerializableCapture {
//                     name: Some("TOKEN".to_string()),
//                     match_number: -1,
//                     start: 0,
//                     end: token.len(),
//                     value: intern(token),
//                 }],
//             },
//             validation_response_body: String::new(),
//             validation_response_status: StatusCode::OK,
//             validation_success: false,
//             calculated_entropy: 0.0, // or compute your own
//             is_base64: false,
//         };
//         let parser = register_all(liquid::ParserBuilder::with_stdlib()).build()?;
//         let client = reqwest::Client::new();
//         let cache: Cache = Arc::new(SkipMap::new());
//         let dependent_vars = FxHashMap::default();
//         let missing_deps = FxHashMap::default();
//         // Run the validation
//         validate_single_match(
//             &mut owned_blob_match,
//             &parser,
//             &client,
//             &dependent_vars,
//             &missing_deps,
//             &cache,
//         )
//         .await;
//         println!("Success? {:?}", owned_blob_match.validation_success);
//         println!("Status: {:?}", owned_blob_match.validation_response_status);
//         println!("Body: {:?}", owned_blob_match.validation_response_body);
//         Ok(())
//     }
// }
