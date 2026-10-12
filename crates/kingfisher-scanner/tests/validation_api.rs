#![cfg(feature = "validation")]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use kingfisher_rules::{DependsOnRule, HttpRequest, HttpValidation, ResponseMatcher, Validation};
use kingfisher_scanner::{
    Finding, Rule, RuleSyntax, RulesDatabase, Scanner, ScannerConfig, ValidationOutcome,
    ValidationReason, Validator,
};

fn syntax() -> RuleSyntax {
    let mut syntax = RuleSyntax::new("acme.demo", "Demo", r"\b(demo_[a-z0-9]{16})\b");
    syntax.validation = Some(Validation::Http(HttpValidation {
        request: HttpRequest {
            method: "GET".into(),
            url: "{{ ENDPOINT }}/identity".into(),
            headers: BTreeMap::from([("Authorization".into(), "Bearer {{ TOKEN }}".into())]),
            body: None,
            multipart: None,
            response_is_html: false,
            response_matcher: Some(vec![
                ResponseMatcher::StatusMatch {
                    r#type: "StatusMatch".into(),
                    status: vec![200],
                    match_all_status: false,
                    negative: false,
                },
                ResponseMatcher::WordMatch {
                    r#type: "WordMatch".into(),
                    words: vec!["authenticated".into()],
                    match_all_words: false,
                    negative: false,
                },
            ]),
        },
        multipart: None,
    }));
    syntax
}

fn scan(rules: Vec<RuleSyntax>, input: &[u8], redact: bool) -> Vec<Finding> {
    Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(rules.into_iter().map(Rule::new).collect()).unwrap()),
        ScannerConfig { redact_secrets: redact, ..Default::default() },
    )
    .scan_bytes(input)
    .unwrap()
}

fn finding(syntax: RuleSyntax) -> Finding {
    scan(vec![syntax], b"demo_abcd1234efgh5678", false).remove(0)
}

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
fn validator(server: &Server) -> Validator {
    Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .client(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn preparation_retains_missing_components_and_inspects_without_provider_work() {
    let mut primary = syntax();
    primary.depends_on_rule = vec![Some(DependsOnRule {
        rule_id: "acme.account".into(),
        variable: "ACCOUNT".into(),
        within: Some("2L".into()),
        optional: false,
        verify_candidates: false,
    })];
    let helper = RuleSyntax::new("acme.account", "Account", r"(account_[a-z]{4})");
    let scanner = Scanner::new(Arc::new(
        RulesDatabase::from_rules(vec![Rule::new(primary), Rule::new(helper)]).unwrap(),
    ));
    let blob = kingfisher_scanner::Blob::from_borrowed(b"demo_abcd1234efgh5678");
    assert!(scanner.scan_blob(&blob).unwrap().is_empty());
    let candidates = scanner
        .scan_blob_for_preparation_with_control(
            &blob,
            "settings.conf",
            &kingfisher_scanner::ScanControl::default(),
        )
        .unwrap();
    let validator = Validator::builder().build().unwrap();
    let diagnostics = validator.input_diagnostics(&candidates[0], &candidates);
    assert!(diagnostics.iter().any(|issue| issue.variable.as_deref() == Some("ACCOUNT")
        && issue.rule_id.as_deref() == Some("acme.account")
        && issue.code == "missing_dependency"));
    assert!(diagnostics.iter().any(|issue| issue.variable.as_deref() == Some("ENDPOINT")));
    assert!(!format!("{diagnostics:?}").contains("demo_abcd"));
    let validated = validator.validate_prepared_findings(candidates.clone(), &candidates).await;
    assert_eq!(validated[0].outcome, ValidationOutcome::Skipped);
    assert!(!validated[0].input_diagnostics.is_empty());
}

#[tokio::test]
async fn missing_revocation_inputs_block_readiness_and_preserve_live_validation() {
    let server = serve(Router::new().route("/identity", get(|| async { "authenticated" }))).await;
    let mut rule = syntax();
    rule.revocation = Some(kingfisher_rules::Revocation::Http(HttpValidation {
        request: HttpRequest {
            method: "DELETE".into(),
            url: "{{ ENDPOINT }}/keys/{{ KEY_ID }}".into(),
            response_matcher: Some(vec![ResponseMatcher::StatusMatch {
                r#type: "StatusMatch".into(),
                status: vec![204],
                match_all_status: false,
                negative: false,
            }]),
            headers: BTreeMap::new(),
            body: None,
            multipart: None,
            response_is_html: false,
        },
        multipart: None,
    }));
    let finding = finding(rule);
    let validator = validator(&server);
    let issues = validator.input_diagnostics(&finding, &[]);
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].stage, "revocation");
    assert_eq!(issues[0].variable.as_deref(), Some("KEY_ID"));
    let result = validator.validate_finding(&finding).await;
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert!(result.credential.as_ref().unwrap().revocation.is_none());
    assert_eq!(result.input_diagnostics, issues);
    let result = validator
        .with_variables(BTreeMap::from([("KEY_ID".into(), "key-example".into())]))
        .validate_finding(&finding)
        .await;
    assert!(result.credential.as_ref().unwrap().revocation.is_some());
    assert!(result.input_diagnostics.is_empty());
}

#[test]
fn multi_step_response_values_are_not_missing_caller_inputs() {
    let mut rule = syntax();
    rule.revocation = Some(
        serde_json::from_value(serde_json::json!({
            "type": "HttpMultiStep", "content": {"steps": [
                {"request": {"method": "GET", "url": "{{ ENDPOINT }}/identity"},
                 "extract": {"KEY_ID": {"type": "JsonPath", "path": "$.id"}}},
                {"request": {"method": "DELETE", "url": "{{ ENDPOINT }}/keys/{{ KEY_ID }}"}}
            ]}
        }))
        .unwrap(),
    );
    let finding = finding(rule);
    let validator =
        Validator::builder().variable("ENDPOINT", "https://provider.invalid").build().unwrap();
    assert!(validator.input_diagnostics(&finding, &[]).is_empty());
    let issues = Validator::builder().build().unwrap().input_diagnostics(&finding, &[]);
    assert!(issues.iter().any(|issue| issue.variable.as_deref() == Some("ENDPOINT")));
    assert!(!issues.iter().any(|issue| issue.variable.as_deref() == Some("KEY_ID")));
}

#[test]
fn revocation_extractor_templates_require_resolved_inputs() {
    for extractor in [
        serde_json::json!({"type": "JsonPath", "path": "$.{{ FIELD }}"}),
        serde_json::json!({"type": "Regex", "pattern": "{{ FIELD }}=(.*)"}),
        serde_json::json!({"type": "Header", "name": "X-{{ FIELD }}"}),
    ] {
        let mut rule = syntax();
        rule.revocation = Some(
            serde_json::from_value(serde_json::json!({
                "type": "HttpMultiStep", "content": {"steps": [
                    {"request": {"method": "GET", "url": "{{ ENDPOINT }}/identity"},
                     "extract": {"key_id": extractor}},
                    {"request": {"method": "DELETE", "url": "{{ ENDPOINT }}/keys/{{ KEY_ID }}"}}
                ]}
            }))
            .unwrap(),
        );
        let finding = finding(rule);
        let validator =
            Validator::builder().variable("ENDPOINT", "https://provider.invalid").build().unwrap();
        let issues = validator.input_diagnostics(&finding, &[]);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].stage, "revocation");
        assert_eq!(issues[0].code, "missing_variable");
        assert_eq!(issues[0].variable.as_deref(), Some("FIELD"));
        assert!(
            validator
                .with_variables(BTreeMap::from([("FIELD".into(), "id".into())]))
                .input_diagnostics(&finding, &[])
                .is_empty()
        );
    }
}

#[tokio::test]
async fn smtp_credential_uri_dispatch_survives_public_api_compatibility() {
    let mut rule = syntax();
    rule.validation = Some(Validation::CredentialUri);
    let finding = finding(rule);
    for (uri, scheme) in [
        ("SMTP://user:fixture-only-password@127.0.0.1:587", ""),
        ("smtps://user:fixture-only-password@127.0.0.1:465", " SMTPS "),
    ] {
        let result = Validator::builder()
            .variable("URI", uri)
            .variable("SCHEME", scheme)
            .build()
            .unwrap()
            .validate_finding(&finding)
            .await;
        assert_eq!(result.outcome, ValidationOutcome::Skipped);
        assert_eq!(result.reason, Some(ValidationReason::TargetBlocked));
    }
}

#[test]
fn inspection_honors_typed_validator_aliases() {
    for (kind, name) in [
        (Validation::AWS, "ACCESS_KEY_ID"),
        (Validation::AzureStorage, "STORAGE_ACCOUNT"),
        (Validation::Coinbase, "KEY_ID"),
    ] {
        let mut rule = syntax();
        rule.validation = Some(kind);
        let candidate = finding(rule);
        let validator = Validator::builder().variable(name, "synthetic-value").build().unwrap();
        assert!(validator.input_diagnostics(&candidate, &[]).is_empty());
        assert!(
            !Validator::builder()
                .variable(name, "")
                .build()
                .unwrap()
                .input_diagnostics(&candidate, &[])
                .is_empty()
        );
    }
}

#[test]
fn invalid_builder_settings_fail_and_validator_is_shareable() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<Validator>();
    send_sync::<kingfisher_scanner::ValidatedFinding>();
    assert!(Validator::builder().concurrency(0).build().is_err());
    assert!(Validator::builder().timeout(Duration::ZERO).build().is_ok());
    assert!(Validator::builder().max_response_bytes(0).build().is_ok());
}

#[tokio::test]
async fn http_classification_requires_evidence_and_does_not_leak_credentials() {
    for (status, body, expected) in [
        (StatusCode::OK, "authenticated", ValidationOutcome::VerifiedActive),
        (StatusCode::UNAUTHORIZED, "rejected", ValidationOutcome::VerifiedInactive),
        (StatusCode::FORBIDDEN, "forbidden", ValidationOutcome::Unavailable),
        (StatusCode::TOO_MANY_REQUESTS, "authenticated", ValidationOutcome::Unavailable),
        (StatusCode::SERVICE_UNAVAILABLE, "authenticated", ValidationOutcome::Unavailable),
        (StatusCode::OK, "welcome", ValidationOutcome::Unavailable),
    ] {
        let server = serve(Router::new().route(
            "/identity",
            get(move |headers: HeaderMap| async move {
                assert_eq!(headers["authorization"], "Bearer demo_abcd1234efgh5678");
                (status, body)
            }),
        ))
        .await;
        let result = validator(&server).validate_finding(&finding(syntax())).await;
        assert_eq!(result.outcome, expected);
        assert_eq!(result.http_status, Some(status.as_u16()));
        assert!(!format!("{result:?}").contains("demo_abcd"));
        let redacted = result.into_redacted();
        assert_eq!(redacted.finding.secret, "[REDACTED]");
        assert!(!serde_json::to_string(&redacted.finding).unwrap().contains("demo_abcd"));
    }
}

#[tokio::test]
async fn non_network_states_do_not_require_an_endpoint() {
    let validator = Validator::builder().build().unwrap();
    let mut rule = syntax();
    rule.validation = None;
    assert_eq!(
        validator.validate_finding(&finding(rule.clone())).await.outcome,
        ValidationOutcome::NotAttempted
    );
    rule.validation = Some(Validation::Assumed);
    assert_eq!(
        validator.validate_finding(&finding(rule.clone())).await.outcome,
        ValidationOutcome::Assumed
    );
    rule.authoritative = false;
    assert_eq!(
        validator.validate_finding(&finding(rule)).await.reason,
        Some(ValidationReason::NonAuthoritative)
    );
    let redacted = scan(vec![syntax()], b"demo_abcd1234efgh5678", true).remove(0);
    assert_eq!(
        validator.validate_finding(&redacted).await.reason,
        Some(ValidationReason::RedactedInput)
    );
}

#[tokio::test]
async fn preparation_preserves_non_network_outcomes_with_invalid_inputs() {
    let validator = Validator::builder().build().unwrap();
    for (validation, authoritative, expected, reason) in [
        (None, true, ValidationOutcome::NotAttempted, None),
        (Some(Validation::Assumed), true, ValidationOutcome::Assumed, None),
        (
            syntax().validation,
            false,
            ValidationOutcome::NotAttempted,
            Some(ValidationReason::NonAuthoritative),
        ),
    ] {
        let mut rule = syntax();
        rule.validation = validation;
        rule.authoritative = authoritative;
        let mut candidate = finding(rule);
        candidate.secret = "[REDACTED]".into();
        let ordinary = validator.validate_findings(vec![candidate.clone()]).await;
        let prepared = validator.validate_prepared_findings(vec![candidate], &[]).await;
        assert_eq!(ordinary[0].outcome, expected);
        assert_eq!(prepared[0].outcome, expected);
        assert_eq!(prepared[0].reason, reason);
    }
}

#[test]
fn preparation_does_not_read_or_commit_scan_dedup_state() {
    let scanner = Scanner::with_config(
        Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax())]).unwrap()),
        ScannerConfig { enable_dedup: true, ..Default::default() },
    );
    let blob = kingfisher_scanner::Blob::from_borrowed(b"demo_abcd1234efgh5678");
    let control = kingfisher_scanner::ScanControl::default();
    assert_eq!(
        scanner.scan_blob_for_preparation_with_control(&blob, "", &control).unwrap().len(),
        1
    );
    assert_eq!(scanner.scan_blob(&blob).unwrap().len(), 1);
    assert!(scanner.scan_blob(&blob).unwrap().is_empty());
    assert_eq!(
        scanner.scan_blob_for_preparation_with_control(&blob, "", &control).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn bad_templates_empty_matchers_and_blocked_targets_are_explicit() {
    let server = serve(Router::new().route(
        "/identity",
        get(|| async {
            panic!("must not send request");
            #[allow(unreachable_code)]
            ""
        }),
    ))
    .await;
    let local = validator(&server);
    let mut rule = syntax();
    let Some(Validation::Http(config)) = &mut rule.validation else { unreachable!() };
    config.request.response_matcher = Some(vec![]);
    assert_eq!(
        local.validate_finding(&finding(rule)).await.reason,
        Some(ValidationReason::InvalidConfiguration)
    );
    let missing_variable =
        Validator::builder().build().unwrap().validate_finding(&finding(syntax())).await;
    assert_eq!(missing_variable.reason, Some(ValidationReason::InvalidConfiguration));
    let blocked = Validator::builder()
        .variable("ENDPOINT", &server.url)
        .build()
        .unwrap()
        .validate_finding(&finding(syntax()))
        .await;
    assert_eq!(blocked.reason, Some(ValidationReason::TargetBlocked));
}

#[tokio::test]
async fn bounded_body_and_deadline_fail_without_claiming_inactive() {
    let server = serve(Router::new().route("/identity", get(|| async { "authenticated" }))).await;
    let bounded = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .max_response_bytes(4)
        .build()
        .unwrap();
    assert_eq!(
        bounded.validate_finding(&finding(syntax())).await.reason,
        Some(ValidationReason::ResponseTooLarge)
    );
    let server = serve(Router::new().route(
        "/identity",
        get(|| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "authenticated"
        }),
    ))
    .await;
    let short = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        // A client with a longer deadline proves the outer deadline applies.
        .client(reqwest::Client::builder().no_proxy().build().unwrap())
        .timeout(Duration::from_millis(30))
        .build()
        .unwrap();
    let result = short.validate_finding(&finding(syntax())).await;
    assert_eq!(result.reason, Some(ValidationReason::DeadlineExceeded));
    assert_eq!(result.outcome, ValidationOutcome::Unavailable);
}

#[tokio::test]
async fn default_client_does_not_follow_redirects() {
    let server = serve(
        Router::new()
            .route(
                "/identity",
                get(|| async { axum::response::Redirect::temporary("/destination") }),
            )
            .route(
                "/destination",
                get(|| async {
                    panic!("redirect followed");
                    #[allow(unreachable_code)]
                    ""
                }),
            ),
    )
    .await;
    let result = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .build()
        .unwrap()
        .validate_finding(&finding(syntax()))
        .await;
    assert_eq!(result.http_status, Some(307));
    assert_eq!(result.outcome, ValidationOutcome::Unavailable);
}

fn component_rules(within: Option<&str>) -> Vec<RuleSyntax> {
    let mut primary = syntax();
    let Some(Validation::Http(config)) = &mut primary.validation else { unreachable!() };
    config.request.headers.insert("X-Account".into(), "{{ ACCOUNT }}".into());
    primary.depends_on_rule = vec![Some(DependsOnRule {
        rule_id: "acme.account".into(),
        variable: "ACCOUNT".into(),
        optional: false,
        verify_candidates: false,
        within: within.map(str::to_string),
    })];
    let mut helper = RuleSyntax::new("acme.account", "Account", r"\b(account_[a-z]{4})\b");
    helper.visible = false;
    vec![primary, helper]
}

#[tokio::test]
async fn batch_binds_hidden_components_and_preserves_order() {
    let server = serve(Router::new().route(
        "/identity",
        get(|headers: HeaderMap| async move {
            assert_eq!(headers["x-account"], "account_abcd");
            "authenticated"
        }),
    ))
    .await;
    let findings = scan(component_rules(Some("2L")), b"account_abcd\ndemo_abcd1234efgh5678", false);
    let ids: Vec<_> = findings.iter().map(|f| f.rule_id.clone()).collect();
    let results = validator(&server).validate_findings(findings).await;
    assert_eq!(results.iter().map(|r| r.finding.rule_id.clone()).collect::<Vec<_>>(), ids);
    assert_eq!(
        results.iter().find(|r| r.finding.rule().visible()).unwrap().outcome,
        ValidationOutcome::VerifiedActive
    );
    assert_eq!(
        results.iter().find(|r| !r.finding.rule().visible()).unwrap().outcome,
        ValidationOutcome::NotAttempted
    );
}

#[tokio::test]
async fn missing_ambiguous_and_foreign_components_never_send_requests() {
    let validator = Validator::builder().build().unwrap();
    let rules = component_rules(None);
    let findings = scan(rules.clone(), b"account_abcd account_efgh demo_abcd1234efgh5678", false);
    let primary = findings.iter().find(|f| f.rule().visible()).unwrap();
    assert_eq!(
        validator.validate_finding(primary).await.reason,
        Some(ValidationReason::MissingDependency)
    );
    assert_eq!(
        validator.validate_finding_with_context(primary, &findings).await.reason,
        Some(ValidationReason::AmbiguousDependency)
    );
    let foreign = scan(rules, b"account_abcd", false);
    assert_eq!(
        validator.validate_finding_with_context(primary, &foreign).await.reason,
        Some(ValidationReason::MissingDependency)
    );
}

#[tokio::test]
async fn dependency_window_excludes_other_accounts() {
    let server = serve(Router::new().route(
        "/identity",
        get(|headers: HeaderMap| async move {
            assert_eq!(headers["x-account"], "account_abcd");
            "authenticated"
        }),
    ))
    .await;
    let findings = scan(
        component_rules(Some("1L")),
        b"account_efgh\naccount_abcd demo_abcd1234efgh5678",
        false,
    );
    let primary = findings.iter().find(|f| f.rule().visible()).unwrap();
    assert_eq!(
        validator(&server).validate_finding_with_context(primary, &findings).await.outcome,
        ValidationOutcome::VerifiedActive
    );
}

#[tokio::test]
async fn cloned_validators_share_concurrency_and_release_permits() {
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let (a, m, c) = (active.clone(), maximum.clone(), calls.clone());
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            let (a, m, c) = (a.clone(), m.clone(), c.clone());
            async move {
                m.fetch_max(a.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(15)).await;
                a.fetch_sub(1, Ordering::SeqCst);
                c.fetch_add(1, Ordering::SeqCst);
                "authenticated"
            }
        }),
    ))
    .await;
    let validator = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .concurrency(2)
        .build()
        .unwrap();
    let other = validator.clone();
    let f = finding(syntax());
    let (a, b) = tokio::join!(
        validator.validate_findings(vec![f.clone(); 5]),
        other.validate_findings(vec![f; 5])
    );
    assert!(a.iter().chain(&b).all(|r| r.outcome == ValidationOutcome::VerifiedActive));
    assert_eq!(calls.load(Ordering::SeqCst), 10);
    assert!(maximum.load(Ordering::SeqCst) <= 2);
}

#[tokio::test]
async fn multipart_renders_captures_as_inline_content() {
    let server = serve(Router::new().route(
        "/identity",
        axum::routing::post(|body: String| async move {
            assert!(body.contains("demo_abcd1234efgh5678"));
            "authenticated".into_response()
        }),
    ))
    .await;
    let mut rule = syntax();
    let Some(Validation::Http(config)) = &mut rule.validation else { unreachable!() };
    config.request.method = "POST".into();
    config.request.multipart = Some(kingfisher_rules::MultipartConfig {
        parts: vec![kingfisher_rules::MultipartPart {
            name: "token".into(),
            part_type: "text".into(),
            content: "{{ TOKEN }}".into(),
            content_type: None,
        }],
    });
    assert_eq!(
        validator(&server).validate_finding(&finding(rule)).await.outcome,
        ValidationOutcome::VerifiedActive
    );
}

#[cfg(not(feature = "validation"))]
#[tokio::test]
async fn disabled_family_is_skipped() {
    let mut rule = syntax();
    rule.validation = Some(Validation::AWS);
    assert_eq!(
        Validator::builder().build().unwrap().validate_finding(&finding(rule)).await.reason,
        Some(ValidationReason::FeatureDisabled)
    );
}

#[cfg(feature = "validation")]
#[tokio::test]
async fn local_family_dispatch_preserves_cryptographic_outcome() {
    let mut rule = syntax();
    rule.validation = Some(Validation::Ethereum(kingfisher_rules::EthereumValidation::PrivateKey));
    assert_eq!(
        Validator::builder().build().unwrap().validate_finding(&finding(rule)).await.outcome,
        ValidationOutcome::InvalidMaterial
    );
}

fn toml_finding(expression: &str) -> Finding {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rules.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[[rules]]
id = "acme.demo"
description = "Demo"
regex = '(demo_[a-z0-9]{{16}})'
validate = '''{expression}'''
"#
        ),
    )
    .unwrap();
    let rules =
        kingfisher_rules::Rules::from_paths([path], kingfisher_rules::Confidence::Low).unwrap();
    Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules).unwrap()))
        .scan_bytes(b"demo_abcd1234efgh5678")
        .unwrap()
        .remove(0)
}

#[tokio::test]
async fn betterleaks_dispatch_runs_multiple_requests_and_uses_previous_response() {
    let server = serve(
        Router::new()
            .route(
                "/first",
                get(|headers: HeaderMap| async move {
                    assert_eq!(headers["authorization"], "Bearer demo_abcd1234efgh5678");
                    r#"{"challenge":"synthetic-nonce"}"#
                }),
            )
            .route(
                "/second",
                get(|headers: HeaderMap| async move {
                    assert_eq!(headers["x-challenge"], "synthetic-nonce");
                    "authenticated"
                }),
            ),
    )
    .await;
    let f = toml_finding(
        r#"
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let first = http.get(endpoint + "/first", {"Authorization": "Bearer " + finding.secret});
let second = http.get(endpoint + "/second", {"X-Challenge": first.json.challenge});
second.status == 200 ? {"result": "valid"} : {"result": "unknown"}
"#,
    );
    let result = validator(&server).validate_finding(&f).await;
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(result.http_status, Some(200));
}

#[cfg(not(feature = "validation"))]
#[tokio::test]
async fn betterleaks_missing_sdk_feature_is_not_a_rejected_credential() {
    let f = toml_finding(r#"aws.validate(finding.secret, "synthetic-secret")"#);
    let result = Validator::builder().build().unwrap().validate_finding(&f).await;
    assert_eq!(result.outcome, ValidationOutcome::Skipped);
    assert_eq!(result.reason, Some(ValidationReason::FeatureDisabled));
}

#[tokio::test]
async fn cancellation_releases_shared_permit_for_next_check() {
    let received = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let notify = received.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            let notify = notify.clone();
            let calls = calls.clone();
            async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    notify.notify_one();
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                "authenticated"
            }
        }),
    ))
    .await;
    let validator = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .concurrency(1)
        .build()
        .unwrap();
    let worker = validator.clone();
    let task = tokio::spawn(async move { worker.validate_finding(&finding(syntax())).await });
    tokio::time::timeout(Duration::from_secs(2), received.notified()).await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        validator.validate_finding(&finding(syntax())),
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
}

#[tokio::test]
async fn http_retries_preserve_final_status_and_rebuild_multipart() {
    use axum::routing::post;
    use kingfisher_rules::{MultipartConfig, MultipartPart};
    for multipart in [false, true] {
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = attempts.clone();
        let server = serve(Router::new().route(
            "/identity",
            post(move |body: String| {
                let seen = seen.clone();
                async move {
                    if multipart {
                        assert!(body.contains("demo_abcd1234efgh5678"));
                    }
                    if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, "retry")
                    } else {
                        (StatusCode::OK, "authenticated")
                    }
                }
            }),
        ))
        .await;
        let mut rule = syntax();
        let Some(Validation::Http(config)) = &mut rule.validation else { unreachable!() };
        config.request.method = "POST".into();
        if multipart {
            config.request.multipart = Some(MultipartConfig {
                parts: vec![MultipartPart {
                    name: "credential".into(),
                    part_type: "text".into(),
                    content: "{{ TOKEN }}".into(),
                    content_type: None,
                }],
            });
        }
        let result = Validator::builder()
            .allow_internal_ips(true)
            .variable("ENDPOINT", &server.url)
            .retries(1)
            .build()
            .unwrap()
            .validate_finding(&finding(rule))
            .await;
        assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
        assert_eq!(result.http_status, Some(200));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn unlimited_validation_reads_late_evidence_past_default_body_limit() {
    let server = serve(Router::new().route(
        "/identity",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            format!("{}authenticated", " ".repeat((1 << 20) + 1))
        }),
    ))
    .await;
    let bounded = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .build()
        .unwrap();
    assert_eq!(
        bounded.validate_finding(&finding(syntax())).await.reason,
        Some(ValidationReason::ResponseTooLarge)
    );
    let unlimited = Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.url)
        .timeout(Duration::ZERO)
        .max_response_bytes(0)
        .build()
        .unwrap();
    assert_eq!(
        unlimited.validate_finding(&finding(syntax())).await.outcome,
        ValidationOutcome::VerifiedActive
    );
}

#[tokio::test]
async fn resolved_components_and_endpoints_survive_until_explicit_revocation() {
    use axum::routing::delete;
    use kingfisher_rules::Revocation;
    use kingfisher_scanner::Revoker;

    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let server = serve(
        Router::new()
            .route(
                "/identity",
                get(|headers: HeaderMap| async move {
                    assert_eq!(headers["authorization"], "Bearer demo_abcd1234efgh5678");
                    assert_eq!(headers["x-account"], "account_abcd");
                    "authenticated"
                }),
            )
            .route(
                "/revoke",
                delete(move |headers: HeaderMap| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert_eq!(headers["authorization"], "Bearer demo_abcd1234efgh5678");
                        assert_eq!(headers["x-account"], "account_abcd");
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
    )
    .await;
    let mut rules = component_rules(Some("2L"));
    let Some(Validation::Http(config)) = rules[0].validation.clone() else { unreachable!() };
    let mut request = config.request;
    request.method = "DELETE".into();
    request.url = "{{ ENDPOINT }}/revoke".into();
    request.response_matcher = Some(vec![ResponseMatcher::StatusMatch {
        r#type: "StatusMatch".into(),
        status: vec![204],
        match_all_status: false,
        negative: false,
    }]);
    rules[0].revocation = Some(Revocation::Http(HttpValidation { request, multipart: None }));
    let findings = scan(rules, b"account_efgh\n\naccount_abcd\ndemo_abcd1234efgh5678", false);
    let mut results = validator(&server).validate_findings(findings).await;
    let result = results.remove(results.iter().position(|r| r.finding.rule().visible()).unwrap());
    assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let credential = result.credential.as_ref().unwrap();
    assert_eq!(credential.components.len(), 1);
    assert_eq!(credential.components[0].secret, "account_abcd");
    assert_eq!(credential.variables["ENDPOINT"], server.url);
    assert!(credential.revocation.is_some());
    let revoker = Revoker::new().unwrap();
    assert!(revoker.revoke_validated(&result).await.unwrap().revoked);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let mut inactive = result.clone();
    inactive.outcome = ValidationOutcome::VerifiedInactive;
    assert!(revoker.revoke_validated(&inactive).await.is_err());
    assert!(revoker.revoke_validated(&result.into_redacted()).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
