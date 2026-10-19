#![cfg(feature = "validation")]

use axum::{
    Router,
    body::to_bytes,
    extract::Request,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use kingfisher_rules::{Rule, RuleSyntax, Validation};
use kingfisher_scanner::{
    ValidationOutcome, ValidationReason,
    validation::{OAuth2TokenCache, ValidationEngine},
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Server {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn serve(app: Router) -> Server {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server { url, task }
}
fn rule(base: &str, expires: bool) -> Rule {
    let mut syntax = RuleSyntax::new("acme.oauth2", "Internal API key", "(secret)");
    syntax.validation = Some(serde_json::from_value::<Validation>(json!({
        "type": "Http", "content": {
            "auth": {"oauth2": {
                "token_endpoint": format!("{base}/token"),
                "token_header": if expires { "X-Proxy-Authorization" } else { "Authorization" },
                "ropc": {"username": "scanner & operator", "password": "password+=value", "client_id": "scanner", "client_secret": "client-secret", "scope": "verify read"}
            }},
            "request": {
                "method": "GET", "url": format!("{base}/verify"),
                "headers": if expires { json!({"Authorization": "Bearer {{ TOKEN }}"}) } else { json!({}) },
                "response_matcher": [{"type": "StatusMatch", "status": [200]}, {"type": "WordMatch", "words": ["authenticated"]}]
            }
        }
    })).unwrap());
    Rule::new(syntax)
}
fn json_response(value: serde_json::Value) -> String {
    value.to_string()
}

fn parser() -> liquid::Parser {
    liquid::ParserBuilder::with_stdlib().build().unwrap()
}
fn client() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

#[tokio::test]
async fn kingfisher_yaml_http_validation_keeps_candidate_auth_without_oauth2() {
    let requests = Arc::new(AtomicUsize::new(0));
    let server = serve(Router::new().route(
        "/verify",
        get({
            let requests = requests.clone();
            move |request: Request| {
                let requests = requests.clone();
                async move {
                    // Neither the candidate headers nor templated origins require
                    // verifier OAuth2 credentials. There is deliberately no token endpoint.
                    assert!(!request.headers().contains_key("x-proxy-authorization"));
                    match request.headers().get("authorization") {
                        Some(value) => assert_eq!(value, "OAuth candidate"),
                        None => {
                            assert_eq!(request.headers()["x-algolia-api-key"], "candidate");
                            assert_eq!(request.headers()["x-algolia-application-id"], "WRB8YLFW7Y");
                        }
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    json_response(json!({"authenticated": true}))
                }
            }
        }),
    ))
    .await;
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kingfisher-rules/src/fixtures/kingfisher");
    let rules = kingfisher_rules::Rules::from_paths(
        [fixtures.join("algolia.yml"), fixtures.join("twitch.yml")],
        kingfisher_rules::Confidence::Low,
    )
    .unwrap();
    let client = client();
    let parser = parser();
    let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
    let globals = liquid::object!({
        "TOKEN": "candidate", "APPID": "WRB8YLFW7Y", "VERIFIER": server.url.clone()
    });
    for id in ["kingfisher.algolia.1", "kingfisher.twitch.1"] {
        let mut syntax = rules.rules[id].clone();
        let Some(Validation::Http(http)) = &mut syntax.validation else { panic!() };
        assert!(http.auth.is_none());
        // Change only the destination to a local mock; keep the original headers
        // and response matchers. Finding-driven URLs remain valid without auth.
        http.request.url = "{{ VERIFIER }}/verify".into();
        let result = engine.validate(&Rule::new(syntax), &globals).await;
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive, "{id}: {result:?}");
    }
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn password_form_custom_header_and_concurrent_token_reuse() {
    let exchanges = Arc::new(AtomicUsize::new(0));
    let verifications = Arc::new(AtomicUsize::new(0));
    let app = Router::new().route("/token", post({
        let exchanges = exchanges.clone();
        move |request: Request| { let exchanges = exchanges.clone(); async move {
            assert_eq!(request.headers()["content-type"], "application/x-www-form-urlencoded");
            let body = to_bytes(request.into_body(), 65536).await.unwrap();
            let fields: std::collections::BTreeMap<_, _> = url::form_urlencoded::parse(&body).into_owned().collect();
            assert_eq!(fields["grant_type"], "password");
            assert_eq!(fields["username"], "scanner & operator");
            assert_eq!(fields["password"], "password+=value");
            assert_eq!(fields["client_id"], "scanner");
            assert_eq!(fields["client_secret"], "client-secret");
            assert_eq!(fields["scope"], "verify read");
            exchanges.fetch_add(1, Ordering::SeqCst);
            json_response(json!({"access_token":"gateway-token", "token_type":"Bearer", "expires_in":3600}))
        }}
    })).route("/verify", get({
        let verifications = verifications.clone();
        move |request: Request| { let verifications = verifications.clone(); async move {
            assert_eq!(request.headers()["x-proxy-authorization"], "Bearer gateway-token");
            assert_eq!(request.headers()["authorization"], "Bearer candidate");
            verifications.fetch_add(1, Ordering::SeqCst);
            "authenticated"
        }}
    }));
    let server = serve(app).await;
    let rule = rule(&server.url, true);
    let client = client();
    let parser = parser();
    let cache = OAuth2TokenCache::default();
    let engine = ValidationEngine::new(&client, &parser)
        .allow_internal_ips(true)
        .oauth2_token_cache(cache.clone());
    let globals = liquid::object!({"TOKEN": "candidate"});
    let results = futures::future::join_all((0..8).map(|_| engine.validate(&rule, &globals))).await;
    assert!(results.iter().all(|r| r.outcome == ValidationOutcome::VerifiedActive));
    // A separate engine in the same session also reuses the token.
    assert_eq!(
        ValidationEngine::new(&client, &parser)
            .allow_internal_ips(true)
            .oauth2_token_cache(cache)
            .validate(&rule, &globals)
            .await
            .outcome,
        ValidationOutcome::VerifiedActive
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(verifications.load(Ordering::SeqCst), 9);
}

struct GatedServer {
    server: Server,
    exchanges: Arc<AtomicUsize>,
    verifications: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

async fn gated_server(fail_first_verification: bool) -> GatedServer {
    let exchanges = Arc::new(AtomicUsize::new(0));
    let verifications = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let server = serve(
        Router::new()
            .route(
                "/token",
                post({
                    let exchanges = exchanges.clone();
                    let entered = entered.clone();
                    let release = release.clone();
                    move || {
                        let exchanges = exchanges.clone();
                        let entered = entered.clone();
                        let release = release.clone();
                        async move {
                            exchanges.fetch_add(1, Ordering::SeqCst);
                            entered.notify_one();
                            release.acquire().await.unwrap().forget();
                            json!({"access_token":"gateway-token", "token_type":"Bearer", "expires_in":3600}).to_string()
                        }
                    }
                }),
            )
            .route(
                "/verify",
                get({
                    let verifications = verifications.clone();
                    move || {
                        let attempt = verifications.fetch_add(1, Ordering::SeqCst);
                        let failed = fail_first_verification && attempt == 0;
                        async move {
                            if failed {
                                (StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
                            } else {
                                (StatusCode::OK, "authenticated")
                            }
                        }
                    }
                }),
            ),
    )
    .await;
    GatedServer { server, exchanges, verifications, entered, release }
}

#[tokio::test]
async fn delayed_exchange_isolates_credentials_and_shares_failures_only_within_a_batch() {
    let gate = gated_server(true).await;
    let mut syntax = rule(&gate.server.url, false).syntax().clone();
    syntax.pattern = "(secret_[ab])".into();
    let scanner = kingfisher_scanner::Scanner::new(Arc::new(
        kingfisher_rules::RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap(),
    ));
    let validator = kingfisher_scanner::Validator::builder()
        .allow_internal_ips(true)
        .concurrency(2)
        .build()
        .unwrap();
    let findings = scanner.scan_bytes(b"secret_a secret_b secret_a secret_b").unwrap();
    let mut batch = Box::pin(validator.validate_findings(findings.clone()));
    tokio::select! {
        _ = gate.entered.notified() => {},
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("token exchange never reached the gate"),
        _ = &mut batch => panic!("batch completed before token exchange was released"),
    }
    assert!(futures::poll!(batch.as_mut()).is_pending());
    assert_eq!(gate.exchanges.load(Ordering::SeqCst), 1);
    gate.release.add_permits(1);
    let results = tokio::time::timeout(Duration::from_secs(5), batch).await.unwrap();
    assert_eq!(results.len(), 4);
    assert_eq!(
        results.iter().filter(|result| result.outcome == ValidationOutcome::Unavailable).count(),
        2
    );
    let failed =
        results.iter().find(|result| result.outcome == ValidationOutcome::Unavailable).unwrap();
    // One credential's transient verifier failure is shared only with its own
    // duplicate, never with the other credential waiting on the same token.
    for result in &results {
        if result.finding.secret == failed.finding.secret {
            assert_eq!(result.outcome, ValidationOutcome::Unavailable);
            assert_eq!(result.reason, Some(ValidationReason::RequestFailed));
            assert_eq!(result.http_status, Some(StatusCode::SERVICE_UNAVAILABLE.as_u16()));
        } else {
            assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        }
    }
    assert_eq!(
        results.iter().filter(|result| result.outcome == ValidationOutcome::VerifiedActive).count(),
        2
    );
    assert_eq!(gate.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(gate.verifications.load(Ordering::SeqCst), 2);

    // A later batch retries both credentials without retaining the transient
    // failure, but keeps the reusable operator token from this validator.
    let recovered =
        tokio::time::timeout(Duration::from_secs(5), validator.validate_findings(findings))
            .await
            .unwrap();
    assert_eq!(recovered.len(), 4);
    assert!(recovered.iter().all(|result| result.outcome == ValidationOutcome::VerifiedActive));
    assert_eq!(gate.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(gate.verifications.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn cancelling_a_waiter_does_not_cancel_the_exchange_or_poison_the_token() {
    let gate = gated_server(false).await;
    let client = client();
    let parser = parser();
    let rule = rule(&gate.server.url, false);
    let globals = liquid::Object::new();
    let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
    let mut owner = Box::pin(engine.validate(&rule, &globals));
    tokio::select! {
        _ = gate.entered.notified() => {},
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("token exchange never reached the gate"),
        _ = &mut owner => panic!("owner completed before token exchange was released"),
    }
    let mut waiter = Box::pin(engine.validate(&rule, &globals));
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    drop(waiter);
    gate.release.add_permits(1);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), owner).await.unwrap().outcome,
        ValidationOutcome::VerifiedActive
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), engine.validate(&rule, &globals))
            .await
            .unwrap()
            .outcome,
        ValidationOutcome::VerifiedActive
    );
    assert_eq!(gate.exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_the_exchange_owner_releases_waiters_and_preserves_cooldown() {
    let gate = gated_server(false).await;
    let client = client();
    let parser = parser();
    let rule = rule(&gate.server.url, false);
    let globals = liquid::Object::new();
    let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
    let mut owner = Box::pin(engine.validate(&rule, &globals));
    tokio::select! {
        _ = gate.entered.notified() => {},
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("token exchange never reached the gate"),
        _ = &mut owner => panic!("owner completed before token exchange was released"),
    }
    let mut waiter = Box::pin(engine.validate(&rule, &globals));
    assert!(futures::poll!(waiter.as_mut()).is_pending());
    drop(owner);
    let result = tokio::time::timeout(Duration::from_secs(5), waiter).await.unwrap();
    assert_eq!(result.reason, Some(ValidationReason::RequestFailed));
    assert!(result.response_body.is_empty());
    assert_eq!(gate.exchanges.load(Ordering::SeqCst), 1);
    assert_eq!(gate.verifications.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_tokens_refresh_and_missing_expiry_has_a_default_lifetime() {
    for expires in [Some(0), None] {
        let exchanges = Arc::new(AtomicUsize::new(0));
        let server = serve(
            Router::new()
                .route(
                    "/token",
                    post({
                        let exchanges = exchanges.clone();
                        move || {
                            let exchanges = exchanges.clone();
                            async move {
                                exchanges.fetch_add(1, Ordering::SeqCst);
                                let mut response =
                                    json!({"access_token":"gateway-token", "token_type":"bearer"});
                                if let Some(expires) = expires {
                                    response["expires_in"] = json!(expires);
                                }
                                response.to_string()
                            }
                        }
                    }),
                )
                .route(
                    "/verify",
                    get(|request: Request| async move {
                        assert_eq!(request.headers()["authorization"], "Bearer gateway-token");
                        "authenticated"
                    }),
                ),
        )
        .await;
        let client = client();
        let parser = parser();
        let rule = rule(&server.url, false);
        let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
        for _ in 0..2 {
            assert_eq!(
                engine.validate(&rule, &liquid::Object::new()).await.outcome,
                ValidationOutcome::VerifiedActive
            );
        }
        assert_eq!(exchanges.load(Ordering::SeqCst), if expires.is_some() { 2 } else { 1 });
    }
}

#[tokio::test]
async fn failed_or_malformed_token_exchanges_back_off_without_leaking_responses() {
    for status in [StatusCode::UNAUTHORIZED, StatusCode::TOO_MANY_REQUESTS, StatusCode::OK] {
        let exchanges = Arc::new(AtomicUsize::new(0));
        let server = serve(Router::new().route(
            "/token",
            post({
                let exchanges = exchanges.clone();
                move || {
                    let exchanges = exchanges.clone();
                    async move {
                        exchanges.fetch_add(1, Ordering::SeqCst);
                        (status, "password+=value client-secret provider-error")
                    }
                }
            }),
        ))
        .await;
        let rule = rule(&server.url, true);
        let client = client();
        let parser = parser();
        let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
        for _ in 0..4 {
            let result = engine.validate(&rule, &liquid::object!({"TOKEN":"candidate"})).await;
            assert_eq!(result.reason, Some(ValidationReason::RequestFailed));
            assert!(result.response_body.is_empty());
            assert!(!format!("{result:?}").contains("client-secret"));
        }
        assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn token_and_verifier_redirects_never_receive_credentials_at_another_host() {
    let destination_hits = Arc::new(AtomicUsize::new(0));
    let destination = serve(Router::new().fallback({
        let hits = destination_hits.clone();
        move || {
            let hits = hits.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                "authenticated"
            }
        }
    }))
    .await;
    for token_redirect in [true, false] {
        let target = destination.url.clone();
        let server = serve(
            Router::new()
                .route(
                    "/token",
                    post(move || {
                        let target = target.clone();
                        async move {
                            if token_redirect {
                                (StatusCode::TEMPORARY_REDIRECT, [("location", target)], "")
                                    .into_response()
                            } else {
                                json_response(
                                    json!({"access_token":"gateway-token", "token_type":"Bearer"}),
                                )
                                .into_response()
                            }
                        }
                    }),
                )
                .route(
                    "/verify",
                    get({
                        let target = destination.url.clone();
                        move || {
                            let target = target.clone();
                            async move { (StatusCode::FOUND, [("location", target)], "") }
                        }
                    }),
                ),
        )
        .await;
        let client = reqwest::Client::new();
        let parser = parser();
        let result = ValidationEngine::new(&client, &parser)
            .allow_internal_ips(true)
            .validate(&rule(&server.url, false), &liquid::Object::new())
            .await;
        assert_ne!(result.outcome, ValidationOutcome::VerifiedActive);
    }
    assert_eq!(destination_hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn dynamic_verifier_origins_and_remote_cleartext_token_endpoints_are_rejected() {
    let client = client();
    let parser = parser();
    for dynamic_host in [true, false] {
        let mut syntax = rule("http://127.0.0.1:1", false).syntax().clone();
        let Some(Validation::Http(http)) = &mut syntax.validation else { unreachable!() };
        if dynamic_host {
            http.request.url = "{{ ENDPOINT }}/verify".into();
        } else {
            http.auth.as_mut().unwrap().oauth2.token_endpoint =
                "http://idp.example.com/token".into();
        }
        let result = ValidationEngine::new(&client, &parser)
            .allow_internal_ips(true)
            .timeout(Duration::from_secs(1))
            .validate(&Rule::new(syntax), &liquid::object!({"ENDPOINT":"http://127.0.0.1:1"}))
            .await;
        assert_eq!(result.reason, Some(ValidationReason::InvalidConfiguration));
    }
}

#[test]
fn schema_defaults_header_and_redacts_debug_credentials() {
    let auth: kingfisher_rules::HttpValidationAuth = serde_json::from_value(json!({"oauth2": {
        "token_endpoint":"https://idp.example.com/token", "ropc":{"username":"scanner", "password":"password-secret", "client_id":"app", "client_secret":"client-secret"}
    }})).unwrap();
    assert_eq!(auth.oauth2.token_header, "Authorization");
    let debug = format!("{auth:?}");
    for secret in ["password-secret", "client-secret", "idp.example.com"] {
        assert!(!debug.contains(secret));
    }
}

#[tokio::test]
async fn validator_clones_share_auth_and_echoed_tokens_are_redacted() {
    let exchanges = Arc::new(AtomicUsize::new(0));
    let server = serve(Router::new().route("/token", post({
        let exchanges = exchanges.clone(); move || { let exchanges = exchanges.clone(); async move {
            exchanges.fetch_add(1, Ordering::SeqCst);
            json!({"access_token":"gateway-token", "token_type":"Bearer", "expires_in":3600}).to_string()
        }}
    })).route("/verify", get(|| async { "authenticated Bearer gateway-token gateway-token" }))).await;
    let rule = rule(&server.url, false);
    let scanner = kingfisher_scanner::Scanner::new(Arc::new(
        kingfisher_rules::RulesDatabase::from_rules(vec![rule.clone()]).unwrap(),
    ));
    let validator =
        kingfisher_scanner::Validator::builder().allow_internal_ips(true).build().unwrap();
    for validator in [validator.clone(), validator] {
        let results = validator.validate_findings(scanner.scan_bytes(b"secret").unwrap()).await;
        assert_eq!(results[0].outcome, ValidationOutcome::VerifiedActive);
    }
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    let client = client();
    let parser = parser();
    let result = ValidationEngine::new(&client, &parser)
        .allow_internal_ips(true)
        .validate(&rule, &liquid::Object::new())
        .await;
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert!(!result.response_body.contains("gateway-token"));
}

#[tokio::test]
async fn invalid_auth_configuration_and_oversized_token_responses_do_not_call_the_verifier() {
    let exchanges = Arc::new(AtomicUsize::new(0));
    let server = serve(Router::new().route(
        "/token",
        post({
            let exchanges = exchanges.clone();
            move || {
                let exchanges = exchanges.clone();
                async move {
                    exchanges.fetch_add(1, Ordering::SeqCst);
                    "x".repeat(65537)
                }
            }
        }),
    ))
    .await;
    let mut syntax = rule(&server.url, false).syntax().clone();
    let Some(Validation::Http(http)) = &mut syntax.validation else { unreachable!() };
    http.request.headers.insert("authorization".into(), "candidate".into());
    let client = client();
    let parser = parser();
    let engine = ValidationEngine::new(&client, &parser).allow_internal_ips(true);
    assert_eq!(
        engine.validate(&Rule::new(syntax), &liquid::Object::new()).await.reason,
        Some(ValidationReason::InvalidConfiguration)
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    for header in ["User-Agent", "Accept", "Accept-Language", "Accept-Encoding"] {
        let mut syntax = rule(&server.url, false).syntax().clone();
        let Some(Validation::Http(http)) = &mut syntax.validation else { unreachable!() };
        http.auth.as_mut().unwrap().oauth2.token_header = header.into();
        assert_eq!(
            engine.validate(&Rule::new(syntax), &liquid::Object::new()).await.reason,
            Some(ValidationReason::InvalidConfiguration)
        );
    }
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    let result = engine.validate(&rule(&server.url, false), &liquid::Object::new()).await;
    assert_eq!(result.reason, Some(ValidationReason::ResponseTooLarge));
    assert!(result.response_body.is_empty());
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
}
