//! Operator-configured OAuth2 authentication for fixed HTTP verification services.
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
    time::Duration,
};

use kingfisher_rules::OAuth2Config;
use reqwest::{
    Client, Url,
    header::{HeaderName, HeaderValue},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::{sync::Mutex, time::Instant};

use super::{ValidationReason, http_validation::check_url_resolvable, limits::ResourceTimeout};

const DEFAULT_LIFETIME: u64 = 60;
const MAX_TOKEN_RESPONSE: usize = 64 * 1024;
const MAX_CACHED_CONFIGURATIONS: usize = 256;
type TokenEntries = HashMap<[u8; 32], TokenEntry>;

struct TokenEntry {
    state: Arc<Mutex<TokenState>>,
    last_used: Instant,
}

/// In-memory tokens and failure backoff owned by one validation session.
/// Clones share state; credentials, tokens and provider errors never enter Debug or reports.
#[derive(Clone, Default)]
pub struct OAuth2TokenCache {
    entries: Arc<Mutex<TokenEntries>>,
    client: Arc<OnceLock<Client>>,
    loopback_http_client: Arc<OnceLock<Client>>,
}

#[derive(Default)]
struct TokenState {
    token: Option<HeaderValue>,
    expires_at: Option<Instant>,
    retry_at: Option<Instant>,
    failures: u32,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
}

fn credential(
    value: &Option<String>,
    env: &Option<String>,
    required: bool,
) -> Result<Option<String>, ValidationReason> {
    let value = match (value, env) {
        (Some(value), None) => Some(value.clone()),
        (None, Some(name)) => {
            Some(std::env::var(name).map_err(|_| ValidationReason::InvalidConfiguration)?)
        }
        (None, None) if !required => None,
        _ => return Err(ValidationReason::InvalidConfiguration),
    };
    if value.as_ref().is_some_and(|v| v.is_empty() || v.contains("{{") || v == "[REDACTED]") {
        return Err(ValidationReason::InvalidConfiguration);
    }
    Ok(value)
}

/// OAuth credentials may only travel to explicit HTTPS origins. Loopback HTTP
/// is available for local verification services when internal IPs are permitted.
pub(crate) fn fixed_url(raw: &str, allow_internal_ips: bool) -> Result<Url, ValidationReason> {
    let url = Url::parse(raw).map_err(|_| ValidationReason::InvalidConfiguration)?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.host_str().is_none_or(|host| host.contains(['{', '}', '%']))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback && allow_internal_ips))
    {
        return Err(ValidationReason::InvalidConfiguration);
    }
    Ok(url)
}

// Both token and verifier requests use strict TLS and no redirects. The HTTP
// exception is only for explicitly permitted loopback services (see fixed_url):
// never send their plaintext passwords or bearer tokens via an ambient proxy.
// HTTPS keeps the operator's ordinary environment proxy/NO_PROXY policy.
fn transport_builder(
    builder: reqwest::ClientBuilder,
    loopback_http: bool,
) -> reqwest::ClientBuilder {
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    if loopback_http { builder.no_proxy() } else { builder }
}

impl OAuth2TokenCache {
    fn transport(&self, url: &Url) -> Result<Client, ValidationReason> {
        // Callers have already checked fixed_url, so HTTP here is loopback-only.
        let loopback_http = url.scheme() == "http";
        let slot = if loopback_http { &self.loopback_http_client } else { &self.client };
        if slot.get().is_none() {
            let client = transport_builder(Client::builder(), loopback_http)
                .build()
                .map_err(|_| ValidationReason::InvalidConfiguration)?;
            let _ = slot.set(client);
        }
        Ok(slot.get().expect("initialized OAuth2 transport").clone())
    }

    async fn state(&self, key: [u8; 32]) -> Arc<Mutex<TokenState>> {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();
        if entries.len() >= MAX_CACHED_CONFIGURATIONS && !entries.contains_key(&key) {
            // Reclaim expired idle entries before evicting a still-useful token or
            // cooldown. Never remove a state held by an exchange or its waiters:
            // doing so would permit a second exchange for the same credentials.
            entries.retain(|_, entry| {
                Arc::strong_count(&entry.state) > 1
                    || entry.state.try_lock().map_or(true, |state| {
                        state.expires_at.is_some_and(|until| now < until)
                            || state.retry_at.is_some_and(|until| now < until)
                    })
            });
            while entries.len() >= MAX_CACHED_CONFIGURATIONS {
                let oldest = entries
                    .iter()
                    .filter(|(_, entry)| Arc::strong_count(&entry.state) == 1)
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| *key);
                let Some(oldest) = oldest else {
                    // Active configurations may temporarily exceed the retention
                    // bound; a later insertion reclaims them once they are idle.
                    break;
                };
                entries.remove(&oldest);
            }
        }
        let entry = entries
            .entry(key)
            .or_insert_with(|| TokenEntry { state: Arc::default(), last_used: now });
        entry.last_used = now;
        entry.state.clone()
    }

    pub(crate) async fn header(
        &self,
        config: &OAuth2Config,
        verifier_template: &str,
        verifier: &Url,
        timeout: Duration,
        allow_internal_ips: bool,
    ) -> Result<(HeaderName, HeaderValue, Client), ValidationReason> {
        let configured = fixed_url(verifier_template, allow_internal_ips)?;
        if configured.origin() != verifier.origin() {
            return Err(ValidationReason::TargetBlocked);
        }
        let token_url = fixed_url(&config.token_endpoint, allow_internal_ips)?;
        let name = HeaderName::from_bytes(config.token_header.as_bytes())
            .map_err(|_| ValidationReason::InvalidConfiguration)?;
        if matches!(
            name.as_str(),
            "host"
                | "user-agent"
                | "accept"
                | "accept-language"
                | "accept-encoding"
                | "content-length"
                | "content-type"
                | "connection"
                | "transfer-encoding"
                | "cookie"
                | "proxy-authorization"
        ) {
            return Err(ValidationReason::InvalidConfiguration);
        }
        let ropc = &config.ropc;
        let username = credential(&ropc.username, &ropc.username_env, true)?.unwrap();
        let password = credential(&ropc.password, &ropc.password_env, true)?.unwrap();
        let client_secret = credential(&ropc.client_secret, &ropc.client_secret_env, false)?;
        if ropc.client_id.is_empty() || ropc.client_id.contains("{{") {
            return Err(ValidationReason::InvalidConfiguration);
        }
        let mut form = vec![
            ("grant_type", "password".to_string()),
            ("username", username),
            ("password", password),
            ("client_id", ropc.client_id.clone()),
        ];
        if let Some(secret) = client_secret {
            form.push(("client_secret", secret));
        }
        if let Some(scope) = &ropc.scope {
            form.push(("scope", scope.clone()));
        }

        let key: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&(
                token_url.as_str(),
                verifier.origin().ascii_serialization(),
                config.token_header.as_str(),
                &form,
                allow_internal_ips,
            ))
            .map_err(|_| ValidationReason::InvalidConfiguration)?,
        )
        .into();
        let state = self.state(key).await;
        // Hold this lock through the exchange: siblings wait for its result, not
        // the provisional cooldown. Dropping a waiter cannot cancel its owner;
        // dropping the owner releases the lock and retains retry-storm protection.
        let mut state = state.lock().await;
        // Select independently: a local token service may authenticate a remote
        // HTTPS verifier, or vice versa. Injected clients/use_lax_tls do not apply.
        let client = self.transport(verifier)?;
        let token_client = self.transport(&token_url)?;
        let now = Instant::now();
        if state.expires_at.is_some_and(|until| now < until)
            && let Some(token) = &state.token
        {
            return Ok((name, token.clone(), client));
        }
        if state.retry_at.is_some_and(|until| now < until) {
            return Err(ValidationReason::RequestFailed);
        }
        // Set a cooldown before I/O so cancellation also cannot cause a retry storm.
        let backoff = Duration::from_secs(1 << state.failures.min(6));
        state.retry_at = Some(now + backoff);
        state.failures = state.failures.saturating_add(1);
        let started = Instant::now();
        let exchanged = async {
            check_url_resolvable(&token_url, allow_internal_ips)
                .await
                .map_err(|_| ValidationReason::TargetBlocked)?;
            let mut response = token_client
                .post(token_url)
                .form(&form)
                .resource_timeout(timeout)
                .send()
                .await
                .map_err(|_| ValidationReason::RequestFailed)?;
            if !response.status().is_success() {
                return Err(ValidationReason::RequestFailed);
            }
            let mut body = Vec::new();
            while let Some(chunk) =
                response.chunk().await.map_err(|_| ValidationReason::RequestFailed)?
            {
                if body.len().saturating_add(chunk.len()) > MAX_TOKEN_RESPONSE {
                    return Err(ValidationReason::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            let token: TokenResponse =
                serde_json::from_slice(&body).map_err(|_| ValidationReason::RequestFailed)?;
            if !token.token_type.eq_ignore_ascii_case("bearer") || token.access_token.is_empty() {
                return Err(ValidationReason::RequestFailed);
            }
            let mut header = HeaderValue::from_str(&format!("Bearer {}", token.access_token))
                .map_err(|_| ValidationReason::RequestFailed)?;
            header.set_sensitive(true);
            let lifetime = token.expires_in.unwrap_or(DEFAULT_LIFETIME).min(86400);
            Ok::<_, ValidationReason>((header, lifetime))
        }
        .await;
        let (header, lifetime) = match exchanged {
            Ok(token) => token,
            Err(reason) => {
                state.retry_at = Some(Instant::now() + backoff);
                return Err(reason);
            }
        };
        // Refresh a little early; measure from before the exchange, not after it.
        state.expires_at =
            Some(started + Duration::from_secs(lifetime.saturating_sub((lifetime / 10).min(30))));
        state.token = Some(header.clone());
        state.retry_at = None;
        state.failures = 0;
        Ok((name, header, client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn only_loopback_http_transport_bypasses_configured_proxies() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct Server(tokio::task::JoinHandle<()>);
        impl Drop for Server {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        async fn serve(body: &'static str, hits: Arc<AtomicUsize>) -> (String, Server) {
            let app = axum::Router::new().fallback(move || {
                hits.fetch_add(1, Ordering::SeqCst);
                async move { body }
            });
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            (url, Server(task))
        }

        let target_hits = Arc::new(AtomicUsize::new(0));
        let proxy_hits = Arc::new(AtomicUsize::new(0));
        let (target, _target) = serve("direct", target_hits.clone()).await;
        let (proxy, _proxy) = serve("proxied", proxy_hits.clone()).await;
        for loopback_http in [true, false] {
            // Inject a proxy rather than mutate process-wide environment variables.
            // The false branch is the HTTPS transport's ordinary proxy policy;
            // use an HTTP probe so this test does not need TLS certificates.
            let client = transport_builder(
                Client::builder().proxy(reqwest::Proxy::all(&proxy).unwrap()),
                loopback_http,
            )
            .build()
            .unwrap();
            let body = tokio::time::timeout(Duration::from_secs(5), async {
                client.get(&target).send().await.unwrap().text().await.unwrap()
            })
            .await
            .expect("transport probe must finish");
            assert_eq!(body, if loopback_http { "direct" } else { "proxied" });
        }
        assert_eq!(target_hits.load(Ordering::SeqCst), 1);
        assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
    }

    fn key(index: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&(index as u64).to_be_bytes());
        key
    }

    async fn full_cache() -> OAuth2TokenCache {
        let cache = OAuth2TokenCache::default();
        let now = Instant::now();
        for index in 0..MAX_CACHED_CONFIGURATIONS {
            cache.entries.lock().await.insert(
                key(index),
                TokenEntry {
                    state: Arc::new(Mutex::new(TokenState {
                        token: Some(HeaderValue::from_static("Bearer test-token")),
                        expires_at: Some(now + Duration::from_secs(3600)),
                        ..Default::default()
                    })),
                    last_used: now + Duration::from_millis(index as u64),
                },
            );
        }
        cache
    }

    #[tokio::test]
    async fn cache_pressure_reclaims_expired_entries_before_live_tokens_or_cooldowns() {
        let cache = full_cache().await;
        let entries = cache.entries.lock().await;
        entries[&key(1)].state.lock().await.expires_at = Some(Instant::now());
        let mut cooldown = entries[&key(2)].state.lock().await;
        cooldown.token = None;
        cooldown.expires_at = None;
        cooldown.retry_at = Some(Instant::now() + Duration::from_secs(60));
        drop(cooldown);
        drop(entries);

        let _new = cache.state(key(MAX_CACHED_CONFIGURATIONS)).await;
        let entries = cache.entries.lock().await;
        assert_eq!(entries.len(), MAX_CACHED_CONFIGURATIONS);
        assert!(entries.contains_key(&key(0)), "oldest live token should survive");
        assert!(!entries.contains_key(&key(1)));
        assert!(entries.contains_key(&key(2)), "failure cooldown should survive");
    }

    #[tokio::test]
    async fn cache_pressure_evicts_only_the_least_recently_used_idle_entry() {
        let cache = full_cache().await;
        let active = cache.state(key(0)).await;
        cache.entries.lock().await.get_mut(&key(0)).unwrap().last_used =
            Instant::now() - Duration::from_secs(1);
        // An expired state still belongs to the in-flight exchange/waiters.
        active.lock().await.expires_at = None;
        let recently_used = cache.state(key(1)).await;
        cache.entries.lock().await.get_mut(&key(1)).unwrap().last_used =
            Instant::now() + Duration::from_secs(60);
        drop(recently_used);

        let _new = cache.state(key(MAX_CACHED_CONFIGURATIONS)).await;
        assert!(Arc::ptr_eq(&active, &cache.state(key(0)).await));
        let entries = cache.entries.lock().await;
        assert_eq!(entries.len(), MAX_CACHED_CONFIGURATIONS);
        assert!(entries.contains_key(&key(1)), "recently used entry should survive");
        assert!(!entries.contains_key(&key(2)), "oldest idle entry should be evicted");
        assert!(entries.contains_key(&key(3)), "do not clear unrelated live entries");
    }

    #[tokio::test]
    async fn cache_pressure_preserves_all_active_states_and_later_reclaims_idle_overflow() {
        let cache = full_cache().await;
        let mut active = Vec::new();
        for index in 0..MAX_CACHED_CONFIGURATIONS {
            active.push(cache.state(key(index)).await);
        }
        let overflow = cache.state(key(MAX_CACHED_CONFIGURATIONS)).await;
        assert_eq!(cache.entries.lock().await.len(), MAX_CACHED_CONFIGURATIONS + 1);
        for (index, state) in active.iter().enumerate() {
            assert!(Arc::ptr_eq(state, &cache.state(key(index)).await));
        }
        drop(active);
        let _new = cache.state(key(MAX_CACHED_CONFIGURATIONS + 1)).await;
        assert_eq!(cache.entries.lock().await.len(), MAX_CACHED_CONFIGURATIONS);
        assert!(Arc::ptr_eq(&overflow, &cache.state(key(MAX_CACHED_CONFIGURATIONS)).await));
    }
}
