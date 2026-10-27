#![cfg(feature = "validation")]

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
};
use kingfisher_rules::{HttpRequest, HttpValidation, Revocation, RuleSyntax, Validation};
use kingfisher_scanner::{
    Finding, Revoker, Rule, RulesDatabase, Scanner, ScannerConfig, ValidationOutcome,
    ValidationReason, Validator,
};
use serde_json::json;

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
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server { url, task }
}

fn request(url: serde_json::Value, method: &str) -> HttpRequest {
    serde_json::from_value(json!({
        "method": method,
        "url": url,
        "headers": {"Authorization": "Bearer {{ TOKEN }}"},
        "response_matcher": [
            {"type": "StatusMatch", "status": [200]},
            {"type": "JsonValid"}
        ]
    }))
    .unwrap()
}

fn syntax(url: serde_json::Value) -> RuleSyntax {
    let mut rule = RuleSyntax::new("custom.fallback", "Fallback token", r"(demo_[a-z0-9]{16})");
    rule.validation = Some(Validation::Http(HttpValidation {
        request: request(url, "GET"),
        multipart: None,
        auth: None,
    }));
    rule
}

fn findings(rule: RuleSyntax, input: &[u8]) -> Vec<Finding> {
    Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(vec![Rule::new(rule)]).unwrap()),
        ScannerConfig { redact_secrets: false, ..Default::default() },
    )
    .scan_bytes(input)
    .unwrap()
}

fn validator() -> Validator {
    Validator::builder().allow_internal_ips(true).http_fallbacks(true).build().unwrap()
}

#[tokio::test]
async fn ordered_fallback_stops_on_success_and_memoizes_selected_endpoint() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut app = Router::new();
    for (path, status) in [
        ("/first", StatusCode::UNAUTHORIZED),
        ("/second", StatusCode::OK),
        ("/third", StatusCode::OK),
    ] {
        let calls = calls.clone();
        app = app.route(
            path,
            get(move |headers: HeaderMap| {
                calls.lock().unwrap().push(path);
                assert_eq!(headers["Authorization"], "Bearer demo_abcd1234efgh5678");
                async move { (status, r#"{"authenticated":true}"#) }
            }),
        );
    }
    let server = serve(app).await;
    let rule = syntax(json!([
        format!("{}/first", server.url),
        format!("{}/second", server.url),
        format!("{}/third", server.url)
    ]));
    let input = findings(rule, b"demo_abcd1234efgh5678 demo_abcd1234efgh5678");
    let results = validator().validate_prepared_findings(input.clone(), &input).await;
    assert_eq!(results.len(), 2);
    assert_eq!(*calls.lock().unwrap(), ["/first", "/second"]);
    for result in &results {
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        let variables = &result.credential.as_ref().unwrap().variables;
        assert_eq!(variables["VALIDATION_ENDPOINT_INDEX"], "1");
        assert_eq!(variables["VALIDATION_ENDPOINT_COUNT"], "3");
        assert_eq!(variables["VALIDATION_URL"], format!("{}/second", server.url));
        assert_eq!(variables["VALIDATION_ORIGIN"], server.url);
        assert!(!format!("{result:?}").contains(&server.url));
        assert!(!format!("{result:?}").contains("demo_abcd"));
    }
}

#[tokio::test]
async fn a_success_status_without_matching_evidence_tries_the_next_endpoint() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first_calls = calls.clone();
    let second_calls = calls.clone();
    let server = serve(
        Router::new()
            .route(
                "/bad",
                get(move || {
                    first_calls.lock().unwrap().push("bad");
                    async { "not JSON" }
                }),
            )
            .route(
                "/good",
                get(move || {
                    second_calls.lock().unwrap().push("good");
                    async { "{}" }
                }),
            ),
    )
    .await;
    let input = findings(
        syntax(json!([format!("{}/bad", server.url), format!("{}/good", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = validator().validate_findings(input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(*calls.lock().unwrap(), ["bad", "good"]);
}

#[tokio::test]
async fn every_endpoint_must_reject_before_a_credential_is_inactive() {
    let server = serve(
        Router::new()
            .route("/reject", get(|| async { (StatusCode::UNAUTHORIZED, "{}") }))
            .route("/unavailable", get(|| async { (StatusCode::SERVICE_UNAVAILABLE, "{}") })),
    )
    .await;
    for (paths, expected) in [
        (["reject", "reject"], ValidationOutcome::VerifiedInactive),
        (["reject", "unavailable"], ValidationOutcome::Unavailable),
        (["unavailable", "reject"], ValidationOutcome::Unavailable),
    ] {
        let input = findings(
            syntax(json!(paths.map(|path| format!("{}/{path}", server.url)))),
            b"demo_abcd1234efgh5678",
        );
        let result = validator().validate_findings(input).await.remove(0);
        assert_eq!(result.outcome, expected);
        assert!(!result.credential.as_ref().unwrap().variables.contains_key("VALIDATION_URL"));
    }
}

#[tokio::test]
async fn endpoint_template_failures_do_not_block_a_renderable_fallback_in_preflight() {
    let server = serve(Router::new().route("/identity", get(|| async { "{}" }))).await;
    let input = findings(
        syntax(json!(["{{ UNAVAILABLE_ENDPOINT }}/identity", format!("{}/identity", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let validator = validator();
    assert!(validator.input_diagnostics(&input[0], &input).is_empty());
    let result = validator.validate_prepared_findings(input.clone(), &input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.credential.unwrap().variables["VALIDATION_ENDPOINT_INDEX"], "1");
}

#[tokio::test]
async fn invalid_or_blocked_targets_do_not_prevent_a_later_valid_endpoint() {
    let server = serve(Router::new().route("/identity", get(|| async { "{}" }))).await;
    let input = findings(
        syntax(json!(["not a URL", "file:///private", format!("{}/identity", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = validator().validate_findings(input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.credential.unwrap().variables["VALIDATION_ENDPOINT_INDEX"], "2");
}

#[tokio::test]
async fn private_host_protection_applies_to_every_fallback_endpoint() {
    let calls = Arc::new(Mutex::new(0));
    let server_calls = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            *server_calls.lock().unwrap() += 1;
            async { "{}" }
        }),
    ))
    .await;
    let input = findings(
        syntax(json!([format!("{}/identity", server.url), format!("{}/identity", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = Validator::builder().build().unwrap().validate_findings(input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::Skipped);
    assert_eq!(result.reason, Some(ValidationReason::TargetBlocked));
    assert_eq!(*calls.lock().unwrap(), 0);
    assert!(!result.credential.unwrap().variables.contains_key("VALIDATION_URL"));
}

#[tokio::test]
async fn oversized_responses_cannot_verify_an_endpoint_and_fallback_still_works() {
    let server = serve(
        Router::new()
            .route("/large", get(|| async { "{\"value\":\"larger than the response limit\"}" }))
            .route("/small", get(|| async { "{}" })),
    )
    .await;
    let input = findings(
        syntax(json!([format!("{}/large", server.url), format!("{}/small", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = Validator::builder()
        .http_fallbacks(true)
        .allow_internal_ips(true)
        .max_response_bytes(16)
        .build()
        .unwrap()
        .validate_findings(input)
        .await
        .remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.credential.unwrap().variables["VALIDATION_ENDPOINT_INDEX"], "1");
}

#[tokio::test]
async fn retries_finish_for_one_endpoint_before_the_next_is_attempted() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first_calls = calls.clone();
    let second_calls = calls.clone();
    let server = serve(
        Router::new()
            .route(
                "/first",
                get(move || {
                    first_calls.lock().unwrap().push("first");
                    async { (StatusCode::SERVICE_UNAVAILABLE, "{}") }
                }),
            )
            .route(
                "/second",
                get(move || {
                    second_calls.lock().unwrap().push("second");
                    async { "{}" }
                }),
            ),
    )
    .await;
    let input = findings(
        syntax(json!([format!("{}/first", server.url), format!("{}/second", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = Validator::builder()
        .http_fallbacks(true)
        .allow_internal_ips(true)
        .retries(1)
        .build()
        .unwrap()
        .validate_findings(input)
        .await
        .remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(*calls.lock().unwrap(), ["first", "first", "second"]);
}

#[tokio::test]
async fn fallback_endpoints_share_one_total_deadline() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let first_calls = calls.clone();
    let second_calls = calls.clone();
    let server = serve(
        Router::new()
            .route(
                "/slow",
                get(move || {
                    first_calls.lock().unwrap().push("slow");
                    async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        "{}"
                    }
                }),
            )
            .route(
                "/second",
                get(move || {
                    second_calls.lock().unwrap().push("second");
                    async { "{}" }
                }),
            ),
    )
    .await;
    let input = findings(
        syntax(json!([format!("{}/slow", server.url), format!("{}/second", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let result = Validator::builder()
        .http_fallbacks(true)
        .allow_internal_ips(true)
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap()
        .validate_findings(input)
        .await
        .remove(0);
    assert_eq!(result.outcome, ValidationOutcome::Unavailable);
    assert_eq!(result.reason, Some(ValidationReason::DeadlineExceeded));
    assert!(!calls.lock().unwrap().contains(&"second"));
}

async fn environment(status: StatusCode, mutations: Arc<Mutex<usize>>) -> Server {
    serve(Router::new().route("/identity", get(move || async move { (status, "{}") })).route(
        "/revoke",
        delete(move |headers: HeaderMap| {
            *mutations.lock().unwrap() += 1;
            assert_eq!(headers["Authorization"], "Bearer demo_abcd1234efgh5678");
            async { "{}" }
        }),
    ))
    .await
}

#[tokio::test]
async fn revocation_selects_only_the_environment_that_verified_the_credential() {
    let rejected_mutations = Arc::new(Mutex::new(0));
    let accepted_mutations = Arc::new(Mutex::new(0));
    let rejected = environment(StatusCode::UNAUTHORIZED, rejected_mutations.clone()).await;
    let accepted = environment(StatusCode::OK, accepted_mutations.clone()).await;
    let mut rule =
        syntax(json!([format!("{}/identity", rejected.url), format!("{}/identity", accepted.url)]));
    rule.revocation = Some(Revocation::Http(HttpValidation {
        request: request(
            json!([format!("{}/revoke", rejected.url), format!("{}/revoke", accepted.url)]),
            "DELETE",
        ),
        multipart: None,
        auth: None,
    }));
    let input = findings(rule, b"demo_abcd1234efgh5678 demo_abcd1234efgh5678");
    let results = validator().validate_prepared_findings(input.clone(), &input).await;
    assert_eq!(*accepted_mutations.lock().unwrap(), 0);
    let revoker = Revoker::new().unwrap();
    let outcome = revoker.revoke_validated(&results[1]).await.unwrap();
    assert!(outcome.revoked);
    assert_eq!(*accepted_mutations.lock().unwrap(), 1);
    assert_eq!(*rejected_mutations.lock().unwrap(), 0);

    let rule = results[0].finding.rule();
    assert!(revoker.revoke(rule, "demo_abcd1234efgh5678", &BTreeMap::new()).await.is_err());
    let mut variables = results[0].credential.as_ref().unwrap().variables.clone();
    variables.insert("VALIDATION_ENDPOINT_INDEX".into(), "2".into());
    assert!(revoker.revoke(rule, "demo_abcd1234efgh5678", &variables).await.is_err());
    variables.insert("VALIDATION_ENDPOINT_INDEX".into(), "0".into());
    assert!(revoker.revoke(rule, "demo_abcd1234efgh5678", &variables).await.is_err());
    assert_eq!(*accepted_mutations.lock().unwrap(), 1);
    assert_eq!(*rejected_mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn revocation_origin_template_works_and_a_fixed_rejected_origin_is_refused() {
    let rejected_mutations = Arc::new(Mutex::new(0));
    let accepted_mutations = Arc::new(Mutex::new(0));
    let rejected = environment(StatusCode::UNAUTHORIZED, rejected_mutations.clone()).await;
    let accepted = environment(StatusCode::OK, accepted_mutations.clone()).await;
    for (target, should_revoke) in [
        ("{{ VALIDATION_ORIGIN }}/revoke".to_string(), true),
        (format!("{}/revoke", rejected.url), false),
    ] {
        let mut rule = syntax(json!([
            format!("{}/identity", rejected.url),
            format!("{}/identity", accepted.url)
        ]));
        rule.revocation = Some(Revocation::Http(HttpValidation {
            request: request(json!(target), "DELETE"),
            multipart: None,
            auth: None,
        }));
        let input = findings(rule, b"demo_abcd1234efgh5678");
        let result = validator().validate_prepared_findings(input.clone(), &input).await.remove(0);
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        let revoked = Revoker::new().unwrap().revoke_validated(&result).await;
        if should_revoke {
            assert!(revoked.unwrap().revoked);
        } else {
            assert!(revoked.is_err());
        }
    }
    assert_eq!(*accepted_mutations.lock().unwrap(), 1);
    assert_eq!(*rejected_mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn revocation_readiness_checks_only_the_trusted_selected_url() {
    use kingfisher_rules::{HttpMultiStepRevocation, RevocationStep};

    for (selected, fallbacks) in [(0, false), (0, true), (1, true)] {
        for multi_step in [false, true] {
            for missing_selected in [false, true] {
                let mutations = Arc::new(Mutex::new(0));
                let counted = mutations.clone();
                let first_status =
                    if selected == 0 { StatusCode::OK } else { StatusCode::UNAUTHORIZED };
                let server = serve(
                    Router::new()
                        .route("/first", get(move || async move { (first_status, "{}") }))
                        .route("/second", get(|| async { "{}" }))
                        .route("/lookup", get(|| async { "{}" }))
                        .route(
                            "/revoke",
                            delete(move || {
                                *counted.lock().unwrap() += 1;
                                async { "{}" }
                            }),
                        ),
                )
                .await;
                let mut rule = syntax(json!([
                    format!("{}/first", server.url),
                    format!("{}/second", server.url)
                ]));
                let mut urls = [format!("{}/revoke", server.url), format!("{}/revoke", server.url)];
                let missing = if missing_selected { selected } else { 1 - selected };
                urls[missing] = format!("{}/keys/{{{{ KEY_ID }}}}", server.url);
                let action = request(json!(urls), "DELETE");
                rule.revocation = Some(if multi_step {
                    Revocation::HttpMultiStep(HttpMultiStepRevocation {
                        steps: vec![
                            RevocationStep {
                                name: Some("lookup".into()),
                                request: request(json!(format!("{}/lookup", server.url)), "GET"),
                                multipart: None,
                                extract: None,
                            },
                            RevocationStep {
                                name: Some("revoke".into()),
                                request: action,
                                multipart: None,
                                extract: None,
                            },
                        ],
                    })
                } else {
                    Revocation::Http(HttpValidation {
                        request: action,
                        multipart: None,
                        auth: None,
                    })
                });
                let input = findings(rule, b"demo_abcd1234efgh5678");
                let validator = Validator::builder()
                    .allow_internal_ips(true)
                    .http_fallbacks(fallbacks)
                    // This must not choose the URL inspected after validation.
                    .variable("VALIDATION_ENDPOINT_INDEX", (1 - selected).to_string())
                    .build()
                    .unwrap();
                let result =
                    validator.validate_prepared_findings(input.clone(), &input).await.remove(0);
                assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
                let credential = result.credential.as_ref().unwrap();
                assert_eq!(credential.variables["VALIDATION_ENDPOINT_INDEX"], selected.to_string());
                assert_eq!(credential.revocation.is_none(), missing_selected);
                if missing_selected {
                    assert_eq!(
                        credential.revocation_reason,
                        Some(ValidationReason::MissingDependency)
                    );
                    assert!(result.input_diagnostics.iter().any(|issue| {
                        issue.stage == "revocation"
                            && issue.code == "missing_variable"
                            && issue.variable.as_deref() == Some("KEY_ID")
                    }));
                    assert!(Revoker::new().unwrap().revoke_validated(&result).await.is_err());
                    assert_eq!(*mutations.lock().unwrap(), 0);
                } else {
                    assert!(
                        !result.input_diagnostics.iter().any(|issue| issue.stage == "revocation")
                    );
                    assert!(
                        Revoker::new().unwrap().revoke_validated(&result).await.unwrap().revoked
                    );
                    assert_eq!(*mutations.lock().unwrap(), 1);
                }
            }
        }
    }
}

#[tokio::test]
async fn successful_endpoint_identity_overwrites_untrusted_captured_selection() {
    let server = serve(Router::new().route("/identity", get(|| async { "{}" }))).await;
    let input = findings(
        syntax(json!(["file:///blocked", format!("{}/identity", server.url)])),
        b"demo_abcd1234efgh5678",
    );
    let validator = Validator::builder()
        .http_fallbacks(true)
        .allow_internal_ips(true)
        .variable("VALIDATION_ENDPOINT_INDEX", "0")
        .variable("VALIDATION_ORIGIN", "https://incorrect.example")
        .build()
        .unwrap();
    let result = validator.validate_findings(input).await.remove(0);
    let variables = &result.credential.unwrap().variables;
    assert_eq!(variables["VALIDATION_ENDPOINT_INDEX"], "1");
    assert_eq!(variables["VALIDATION_ORIGIN"], server.url);
}

#[tokio::test]
async fn multi_step_revocation_checks_all_endpoint_bindings_before_any_mutation() {
    use kingfisher_rules::{HttpMultiStepRevocation, ResponseExtractor, RevocationStep};

    let rejected_mutations = Arc::new(Mutex::new(0));
    let accepted_mutations = Arc::new(Mutex::new(0));
    let rejected = environment(StatusCode::UNAUTHORIZED, rejected_mutations.clone()).await;
    let accepted = environment(StatusCode::OK, accepted_mutations.clone()).await;
    let step = || RevocationStep {
        name: None,
        request: request(json!("{{ VALIDATION_ORIGIN }}/revoke"), "DELETE"),
        multipart: None,
        extract: None,
    };
    for scenario in ["wrong_origin", "invalid_index", "reserved_extractor", "valid"] {
        let mut steps = vec![step(), step()];
        match scenario {
            "wrong_origin" => steps[1].request.url = format!("{}/revoke", rejected.url),
            "invalid_index" => {
                // Only one alternate URL exists, but the validated endpoint is index one.
                // A third validation URL below selects index two, outside this list.
                steps[1].request.url = format!("{}/revoke", rejected.url);
                steps[1].request.fallback_urls = vec![format!("{}/revoke", accepted.url)];
            }
            "reserved_extractor" => {
                steps[0].extract =
                    Some(BTreeMap::from([("VALIDATION_ORIGIN".into(), ResponseExtractor::Body)]));
            }
            _ => {}
        }
        let urls = if scenario == "invalid_index" {
            json!([
                "file:///blocked",
                format!("{}/identity", rejected.url),
                format!("{}/identity", accepted.url)
            ])
        } else {
            json!([format!("{}/identity", rejected.url), format!("{}/identity", accepted.url)])
        };
        let mut rule = syntax(urls);
        rule.revocation = Some(Revocation::HttpMultiStep(HttpMultiStepRevocation { steps }));
        let input = findings(rule, b"demo_abcd1234efgh5678");
        let result = validator().validate_prepared_findings(input.clone(), &input).await.remove(0);
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        let revoked = Revoker::new().unwrap().revoke_validated(&result).await;
        if scenario == "valid" {
            assert!(revoked.unwrap().revoked);
            assert_eq!(*accepted_mutations.lock().unwrap(), 2);
        } else {
            assert!(revoked.is_err(), "{scenario}");
            assert_eq!(*accepted_mutations.lock().unwrap(), 0, "{scenario}");
        }
        assert_eq!(*rejected_mutations.lock().unwrap(), 0, "{scenario}");
    }
}

fn profile(id: &str, url: &str) -> kingfisher_rules::HttpFallback {
    serde_json::from_value(json!({"id":id,"reuse_primary_validation_logic":true,"url":url}))
        .unwrap()
}

#[tokio::test]
async fn named_fallbacks_are_off_by_default_and_unused_templates_do_not_block_primary() {
    let calls = Arc::new(Mutex::new(0));
    let count = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            *count.lock().unwrap() += 1;
            async { "{}" }
        }),
    ))
    .await;
    let mut rule = syntax(json!(format!("{}/identity", server.url)));
    rule.fallbacks.push(profile("unused", "{{ MISSING_ENDPOINT }}/identity"));
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let default = Validator::builder().allow_internal_ips(true).build().unwrap();
    assert!(default.input_diagnostics(&input[0], &input).is_empty());
    let result = default.validate_prepared_findings(input.clone(), &input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.credential.unwrap().variables["VALIDATION_ENDPOINT_COUNT"], "1");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn rejected_primary_does_not_contact_a_fallback_without_opt_in() {
    let calls = Arc::new(Mutex::new(0));
    let count = calls.clone();
    let server = serve(
        Router::new().route("/primary", get(|| async { (StatusCode::UNAUTHORIZED, "{}") })).route(
            "/secondary",
            get(move || {
                *count.lock().unwrap() += 1;
                async { "{}" }
            }),
        ),
    )
    .await;
    let mut rule = syntax(json!(format!("{}/primary", server.url)));
    rule.fallbacks.push(profile("secondary", &format!("{}/secondary", server.url)));
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let result = Validator::builder()
        .allow_internal_ips(true)
        .build()
        .unwrap()
        .validate_findings(input.clone())
        .await
        .remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedInactive);
    assert_eq!(*calls.lock().unwrap(), 0);
    let result = validator().validate_findings(input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.credential.unwrap().variables["VALIDATION_FALLBACK_ID"], "secondary");
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn independent_fallback_uses_its_own_method_headers_body_and_matchers() {
    use axum::routing::post;
    let server = serve(
        Router::new().route("/primary", get(|| async { (StatusCode::UNAUTHORIZED, "{}") })).route(
            "/secondary",
            post(|headers: HeaderMap, body: String| async move {
                assert!(!headers.contains_key("Authorization"));
                assert_eq!(headers["X-API-Key"], "demo_abcd1234efgh5678");
                assert_eq!(body, "demo_abcd1234efgh5678");
                (StatusCode::ACCEPTED, "authenticated")
            }),
        ),
    )
    .await;
    let mut rule = syntax(json!(format!("{}/primary", server.url)));
    rule.fallbacks.push(
        serde_json::from_value(json!({
            "id":"independent", "validation":{"type":"Http","content":{"request":{
                "method":"POST", "url":format!("{}/secondary",server.url),
                "headers":{"X-API-Key":"{{ TOKEN }}"}, "body":"{{ TOKEN }}",
                "response_matcher":[{"type":"StatusMatch","status":[202]},
                    {"type":"WordMatch","words":["authenticated"]}]
            }}}
        }))
        .unwrap(),
    );
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let result = validator().validate_prepared_findings(input.clone(), &input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.http_status, Some(202));
    assert!(!result.revocation_supported());
}

#[tokio::test]
async fn named_fallback_never_implicitly_inherits_primary_revocation() {
    let mutations = Arc::new(Mutex::new(0));
    let server = environment(StatusCode::OK, mutations.clone()).await;
    let mut rule = syntax(json!("file:///blocked"));
    rule.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!(format!("{}/revoke", server.url)), "DELETE"),
        auth: None,
        multipart: None,
    }));
    rule.fallbacks.push(profile("secondary", &format!("{}/identity", server.url)));
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let result = validator().validate_findings(input).await.remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert!(!result.revocation_supported());
    assert!(result.credential.as_ref().unwrap().revocation.is_none());
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.is_err());
    assert_eq!(*mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn named_fallback_revokes_only_its_own_action_even_without_primary_revocation() {
    let mutations = Arc::new(Mutex::new(0));
    let server = environment(StatusCode::OK, mutations.clone()).await;
    let mut rule = syntax(json!("file:///blocked"));
    let mut fallback = profile("secondary", &format!("{}/identity", server.url));
    fallback.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!("{{ VALIDATION_ORIGIN }}/revoke"), "DELETE"),
        auth: None,
        multipart: None,
    }));
    rule.fallbacks.push(fallback);
    let input = findings(rule, b"demo_abcd1234efgh5678 demo_abcd1234efgh5678");
    let results = validator().validate_findings(input).await;
    assert!(results[1].revocation_supported());
    assert!(results[0].same_revocation_target(&results[1]));
    assert!(Revoker::new().unwrap().revoke_validated(&results[1]).await.unwrap().revoked);
    assert_eq!(*mutations.lock().unwrap(), 1);
}

#[tokio::test]
async fn missing_fallback_header_inputs_cannot_silently_verify_an_unauthenticated_response() {
    let calls = Arc::new(Mutex::new(0));
    let counted = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            *counted.lock().unwrap() += 1;
            async { "{}" }
        }),
    ))
    .await;
    let mut rule = syntax(json!("file:///blocked"));
    let mut independent = request(json!(format!("{}/identity", server.url)), "GET");
    independent.headers.insert("Authorization".into(), "Bearer {{ MISSING_SECRET }}".into());
    rule.fallbacks.push(kingfisher_rules::HttpFallback {
        id: "missing-input".into(),
        reuse_primary_validation_logic: false,
        url: None,
        validation: Some(Validation::Http(HttpValidation {
            request: independent,
            auth: None,
            multipart: None,
        })),
        reuse_primary_revocation_logic: false,
        revocation_url: None,
        revocation_urls: Vec::new(),
        revocation: None,
    });
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let result = validator().validate_findings(input).await.remove(0);
    assert!(!result.outcome.is_verified_active());
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn explicit_primary_revocation_reuse_targets_only_the_selected_environment() {
    let rejected_mutations = Arc::new(Mutex::new(0));
    let accepted_mutations = Arc::new(Mutex::new(0));
    let rejected = environment(StatusCode::UNAUTHORIZED, rejected_mutations.clone()).await;
    let accepted = environment(StatusCode::OK, accepted_mutations.clone()).await;
    let mut rule = syntax(json!(format!("{}/identity", rejected.url)));
    rule.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!(format!("{}/revoke", rejected.url)), "DELETE"),
        auth: None,
        multipart: None,
    }));
    let mut fallback = profile("secondary", &format!("{}/identity", accepted.url));
    fallback.reuse_primary_revocation_logic = true;
    fallback.revocation_url = Some(format!("{}/revoke", accepted.url));
    rule.fallbacks.push(fallback);
    let input = findings(rule, b"demo_abcd1234efgh5678");
    let result = validator().validate_findings(input).await.remove(0);
    assert!(result.revocation_supported());
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.unwrap().revoked);
    assert_eq!(*accepted_mutations.lock().unwrap(), 1);
    assert_eq!(*rejected_mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn reused_revocation_cannot_target_the_rejected_primary_origin() {
    let rejected_mutations = Arc::new(Mutex::new(0));
    let accepted_mutations = Arc::new(Mutex::new(0));
    let rejected = environment(StatusCode::UNAUTHORIZED, rejected_mutations.clone()).await;
    let accepted = environment(StatusCode::OK, accepted_mutations.clone()).await;
    let mut rule = syntax(json!(format!("{}/identity", rejected.url)));
    rule.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!(format!("{}/revoke", rejected.url)), "DELETE"),
        auth: None,
        multipart: None,
    }));
    let mut fallback = profile("secondary", &format!("{}/identity", accepted.url));
    fallback.reuse_primary_revocation_logic = true;
    fallback.revocation_url = Some(format!("{}/revoke", rejected.url));
    rule.fallbacks.push(fallback);
    let result =
        validator().validate_findings(findings(rule, b"demo_abcd1234efgh5678")).await.remove(0);
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.is_err());
    assert_eq!(*accepted_mutations.lock().unwrap(), 0);
    assert_eq!(*rejected_mutations.lock().unwrap(), 0);
}

#[tokio::test]
async fn reused_multi_step_revocation_retains_extractors_and_never_visits_primary() {
    use kingfisher_rules::{HttpMultiStepRevocation, ResponseExtractor, RevocationStep};
    let mutations = Arc::new(Mutex::new(0));
    let deleted = mutations.clone();
    let server = serve(
        Router::new()
            .route("/identity", get(|| async { "{}" }))
            .route(
                "/keys",
                get(|headers: HeaderMap| async move {
                    assert_eq!(headers["Authorization"], "Bearer demo_abcd1234efgh5678");
                    r#"{"id":"key-7"}"#
                }),
            )
            .route(
                "/keys/key-7",
                delete(move |headers: HeaderMap| {
                    assert_eq!(headers["Authorization"], "Bearer demo_abcd1234efgh5678");
                    *deleted.lock().unwrap() += 1;
                    async { "{}" }
                }),
            ),
    )
    .await;
    let mut rule = syntax(json!("file:///blocked"));
    rule.revocation = Some(Revocation::HttpMultiStep(HttpMultiStepRevocation {
        steps: vec![
            RevocationStep {
                name: Some("lookup".into()),
                request: request(json!("https://primary.example/keys"), "GET"),
                multipart: None,
                extract: Some(BTreeMap::from([(
                    "KEY_ID".into(),
                    ResponseExtractor::JsonPath { path: "$.id".into() },
                )])),
            },
            RevocationStep {
                name: Some("delete".into()),
                request: request(json!("https://primary.example/keys/{{ KEY_ID }}"), "DELETE"),
                multipart: None,
                extract: None,
            },
        ],
    }));
    let mut fallback = profile("secondary", &format!("{}/identity", server.url));
    fallback.reuse_primary_revocation_logic = true;
    fallback.revocation_urls = vec![
        "{{ VALIDATION_ORIGIN }}/keys".into(),
        "{{ VALIDATION_ORIGIN }}/keys/{{ KEY_ID }}".into(),
    ];
    rule.fallbacks.push(fallback);
    let result =
        validator().validate_findings(findings(rule, b"demo_abcd1234efgh5678")).await.remove(0);
    assert!(result.credential.as_ref().unwrap().revocation.is_some());
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.unwrap().revoked);
    assert_eq!(*mutations.lock().unwrap(), 1);
}

#[tokio::test]
async fn selected_fallback_action_takes_precedence_over_primary_betterleaks_revocation() {
    let mutations = Arc::new(Mutex::new(0));
    let server = environment(StatusCode::OK, mutations.clone()).await;
    let mut rule = syntax(json!("file:///blocked"));
    rule.revocation = Some(
        serde_json::from_value(json!({"type":"Betterleaks", "content":{
            "expression":"{\"result\":\"revoked\"}"
        }}))
        .unwrap(),
    );
    let mut fallback = profile("secondary", &format!("{}/identity", server.url));
    fallback.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!("{{ VALIDATION_ORIGIN }}/revoke"), "DELETE"),
        auth: None,
        multipart: None,
    }));
    rule.fallbacks.push(fallback);
    let result =
        validator().validate_findings(findings(rule, b"demo_abcd1234efgh5678")).await.remove(0);
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.unwrap().revoked);
    assert_eq!(*mutations.lock().unwrap(), 1);
}

#[tokio::test]
async fn long_legacy_lists_still_try_primary_and_only_two_alternatives() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let counted = calls.clone();
    let server = serve(Router::new().fallback(get(move |uri: axum::http::Uri| {
        counted.lock().unwrap().push(uri.path().to_owned());
        async { (StatusCode::UNAUTHORIZED, "{}") }
    })))
    .await;
    let urls: Vec<_> = (0..5).map(|index| format!("{}/{index}", server.url)).collect();
    let result = validator()
        .validate_findings(findings(syntax(json!(urls)), b"demo_abcd1234efgh5678"))
        .await
        .remove(0);
    assert_eq!(result.outcome, ValidationOutcome::VerifiedInactive);
    assert_eq!(*calls.lock().unwrap(), ["/0", "/1", "/2"]);
}

#[tokio::test]
async fn unchecked_fallback_keeps_the_result_inconclusive_and_names_the_missing_input() {
    let server =
        serve(Router::new().route("/primary", get(|| async { (StatusCode::UNAUTHORIZED, "{}") })))
            .await;
    for named in [false, true] {
        let mut rule = syntax(json!(format!("{}/primary", server.url)));
        if named {
            rule.fallbacks.push(profile("secondary", "{{ OPTIONAL_FALLBACK_HOST }}/identity"));
        } else if let Some(Validation::Http(http)) = &mut rule.validation {
            http.request.fallback_urls.push("{{ OPTIONAL_FALLBACK_HOST }}/identity".into());
        }
        let result =
            validator().validate_findings(findings(rule, b"demo_abcd1234efgh5678")).await.remove(0);
        assert_eq!(result.outcome, ValidationOutcome::Unavailable);
        assert_eq!(result.reason, Some(ValidationReason::MissingDependency));
        assert!(
            result
                .input_diagnostics
                .iter()
                .any(|issue| issue.variable.as_deref() == Some("OPTIONAL_FALLBACK_HOST"))
        );
    }
}

#[tokio::test]
async fn primary_revocation_retains_its_configured_origin_when_fallbacks_are_enabled() {
    let identity = serve(Router::new().route("/identity", get(|| async { "{}" }))).await;
    let mutations = Arc::new(Mutex::new(0));
    let action = environment(StatusCode::OK, mutations.clone()).await;
    let mut rule = syntax(json!(format!("{}/identity", identity.url)));
    rule.fallbacks.push(profile("unused", "{{ MISSING_HOST }}/identity"));
    rule.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!(format!("{}/revoke", action.url)), "DELETE"),
        auth: None,
        multipart: None,
    }));
    let result =
        validator().validate_findings(findings(rule, b"demo_abcd1234efgh5678")).await.remove(0);
    assert!(Revoker::new().unwrap().revoke_validated(&result).await.unwrap().revoked);
    assert_eq!(*mutations.lock().unwrap(), 1);
}

#[tokio::test]
async fn direct_revocation_cannot_forge_a_validated_endpoint_selection() {
    let mutations = Arc::new(Mutex::new(0));
    let server = environment(StatusCode::OK, mutations.clone()).await;
    let mut rule = syntax(json!(format!("{}/identity", server.url)));
    let mut fallback = profile("secondary", &format!("{}/identity", server.url));
    fallback.revocation = Some(Revocation::Http(HttpValidation {
        request: request(json!("{{ VALIDATION_ORIGIN }}/revoke"), "DELETE"),
        auth: None,
        multipart: None,
    }));
    rule.fallbacks.push(fallback);
    let rule = Rule::new(rule);
    let variables = BTreeMap::from([
        ("VALIDATION_FALLBACK_ID".into(), "secondary".into()),
        ("VALIDATION_ORIGIN".into(), server.url.clone()),
    ]);
    assert!(
        Revoker::new().unwrap().revoke(&rule, "demo_abcd1234efgh5678", &variables).await.is_err()
    );
    assert_eq!(*mutations.lock().unwrap(), 0);
}
