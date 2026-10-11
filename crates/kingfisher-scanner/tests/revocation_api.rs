#![cfg(feature = "validation")]

use aws_config::BehaviorVersion;
use aws_credential_types::Credentials;
use aws_types::region::Region;
use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use kingfisher_rules::{
    HttpMultiStepRevocation, HttpRequest, HttpValidation, ResponseExtractor, ResponseMatcher,
    Revocation, RevocationStep,
};
use kingfisher_scanner::validation::{
    AwsRevocationAction, AwsRevocationActor, AwsRevocationCredentials, AwsRevocationOptions,
    AwsRevocationStatus, revoke_aws_access_key_with_options,
};
use kingfisher_scanner::{Revoker, Rule, RuleSyntax};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

fn request(url: String) -> HttpRequest {
    HttpRequest {
        method: "DELETE".into(),
        url,
        headers: BTreeMap::from([("Authorization".into(), "Bearer {{ TOKEN }}".into())]),
        body: None,
        multipart: None,
        response_is_html: false,
        response_matcher: Some(vec![ResponseMatcher::StatusMatch {
            r#type: "StatusMatch".into(),
            status: vec![204],
            match_all_status: false,
            negative: false,
        }]),
    }
}
fn rule(revocation: Option<Revocation>) -> Rule {
    let mut syntax = RuleSyntax::new("acme.revoke", "Revoke test", "(test)");
    syntax.revocation = revocation;
    Rule::new(syntax)
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

#[tokio::test]
async fn http_revocation_matches_response_and_resolves_variables() {
    let server = serve(
        Router::new()
            .route(
                "/keys/selected",
                delete(|headers: HeaderMap| async move {
                    assert_eq!(headers["authorization"], "Bearer test-secret");
                    StatusCode::NO_CONTENT
                }),
            )
            .route("/keys/missing", delete(|| async { StatusCode::NOT_FOUND })),
    )
    .await;
    let rule = rule(Some(Revocation::Http(HttpValidation {
        request: request(format!("{}/keys/{{{{ KEY_ID }}}}", server.url)),
        multipart: None,
    })));
    let revoker = Revoker::new().unwrap();
    for (id, expected) in [("selected", true), ("missing", false)] {
        let result = revoker
            .revoke(&rule, "test-secret", &BTreeMap::from([("KEY_ID".into(), id.into())]))
            .await
            .unwrap();
        assert_eq!(result.revoked, expected);
        assert_eq!(result.rule_id, "acme.revoke");
        assert_eq!(result.rule_name, "Revoke test");
        assert_eq!(result.status_code, Some(if expected { 204 } else { 404 }));
    }
}

#[tokio::test]
async fn multi_step_revocation_extracts_key_id() {
    let server = serve(
        Router::new()
            .route("/identity", get(|| async { r#"{"id":"selected"}"# }))
            .route("/keys/selected", delete(|| async { StatusCode::NO_CONTENT })),
    )
    .await;
    let mut lookup = request(format!("{}/identity", server.url));
    lookup.method = "GET".into();
    lookup.response_matcher = None;
    let rule = rule(Some(Revocation::HttpMultiStep(HttpMultiStepRevocation {
        steps: vec![
            RevocationStep {
                name: None,
                request: lookup,
                multipart: None,
                extract: Some(BTreeMap::from([(
                    "KEY_ID".into(),
                    ResponseExtractor::JsonPath { path: "$.id".into() },
                )])),
            },
            RevocationStep {
                name: None,
                request: request(format!("{}/keys/{{{{ KEY_ID }}}}", server.url)),
                multipart: None,
                extract: None,
            },
        ],
    })));
    assert!(
        Revoker::new()
            .unwrap()
            .revoke(&rule, "test-secret", &BTreeMap::new())
            .await
            .unwrap()
            .revoked
    );
}

#[tokio::test]
async fn preparatory_http_failures_do_not_imply_mutation() {
    use kingfisher_scanner::validation::revocation::RevocationSubmitted;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let mutations = Arc::new(AtomicUsize::new(0));
    let observed = mutations.clone();
    let server = serve(
        Router::new()
            .route("/lookup", axum::routing::any(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .route(
                "/mutate",
                delete(move || {
                    observed.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::NO_CONTENT }
                }),
            ),
    )
    .await;
    for method in ["GET", "HEAD", "OPTIONS", "POST"] {
        let mut lookup = request(format!("{}/lookup", server.url));
        lookup.method = method.into();
        let action = rule(Some(Revocation::HttpMultiStep(HttpMultiStepRevocation {
            steps: vec![
                RevocationStep { name: None, request: lookup, multipart: None, extract: None },
                RevocationStep {
                    name: None,
                    request: request(format!("{}/mutate", server.url)),
                    multipart: None,
                    extract: None,
                },
            ],
        })));
        let error =
            Revoker::new().unwrap().revoke(&action, "secret", &BTreeMap::new()).await.unwrap_err();
        assert_eq!(error.is::<RevocationSubmitted>(), method == "POST", "{method}: {error:#}");
    }
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn extraction_failure_preserves_whether_the_step_mutated() {
    use kingfisher_scanner::validation::revocation::RevocationSubmitted;
    let server = serve(
        Router::new().route("/lookup", axum::routing::any(|| async { r#"{"other":"value"}"# })),
    )
    .await;
    for method in ["GET", "POST"] {
        let mut lookup = request(format!("{}/lookup", server.url));
        lookup.method = method.into();
        let action = rule(Some(Revocation::HttpMultiStep(HttpMultiStepRevocation {
            steps: vec![
                RevocationStep {
                    name: None,
                    request: lookup,
                    multipart: None,
                    extract: Some(BTreeMap::from([(
                        "KEY_ID".into(),
                        ResponseExtractor::JsonPath { path: "$.missing".into() },
                    )])),
                },
                RevocationStep {
                    name: None,
                    request: request("http://unused.invalid".into()),
                    multipart: None,
                    extract: None,
                },
            ],
        })));
        let error =
            Revoker::new().unwrap().revoke(&action, "secret", &BTreeMap::new()).await.unwrap_err();
        assert_eq!(error.is::<RevocationSubmitted>(), method == "POST");
    }
}

#[tokio::test]
async fn unsupported_url_schemes_are_not_submission() {
    use kingfisher_scanner::validation::revocation::RevocationSubmitted;
    let invalid = request("ftp://unused.invalid".into());
    let action = rule(Some(Revocation::Http(HttpValidation { request: invalid, multipart: None })));
    let error =
        Revoker::new().unwrap().revoke(&action, "secret", &BTreeMap::new()).await.unwrap_err();
    assert!(!error.is::<RevocationSubmitted>());
}

#[tokio::test]
async fn invalid_inputs_fail_before_network() {
    let revoker = Revoker::new().unwrap();
    assert!(
        revoker
            .revoke(&rule(None), "secret", &BTreeMap::new())
            .await
            .unwrap_err()
            .to_string()
            .contains("no revocation")
    );
    let http = rule(Some(Revocation::Http(HttpValidation {
        request: request("http://unused.invalid".into()),
        multipart: None,
    })));
    assert!(revoker.revoke(&http, "", &BTreeMap::new()).await.is_err());
    assert!(
        revoker
            .revoke(&http, "secret", &BTreeMap::from([("TOKEN".into(), "override".into())]))
            .await
            .is_err()
    );
    let mut no_matcher = request("http://unused.invalid".into());
    no_matcher.response_matcher = None;
    assert!(
        revoker
            .revoke(
                &rule(Some(Revocation::Http(HttpValidation {
                    request: no_matcher,
                    multipart: None
                }))),
                "secret",
                &BTreeMap::new()
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("response matcher")
    );
}

#[tokio::test]
async fn total_deadline_bounds_revocation() {
    let server = serve(Router::new().route(
        "/slow",
        delete(|| async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            StatusCode::NO_CONTENT
        }),
    ))
    .await;
    let rule = rule(Some(Revocation::Http(HttpValidation {
        request: request(format!("{}/slow", server.url)),
        multipart: None,
    })));
    let revoker = Revoker::new().unwrap().timeout(Duration::from_millis(50)).unwrap();
    assert!(revoker.revoke(&rule, "secret", &BTreeMap::new()).await.is_err());
    assert!(Revoker::new().unwrap().timeout(Duration::ZERO).is_err());
}

#[tokio::test]
async fn default_client_does_not_retry_or_follow_redirects() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let hits = Arc::new(AtomicUsize::new(0));
    let failed_hits = hits.clone();
    let destination_hits = hits.clone();
    let server = serve(
        Router::new()
            .route(
                "/failed",
                delete(move || {
                    failed_hits.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::SERVICE_UNAVAILABLE }
                }),
            )
            .route(
                "/redirect",
                delete(|| async { axum::response::Redirect::temporary("/destination") }),
            )
            .route(
                "/destination",
                delete(move || {
                    destination_hits.fetch_add(100, Ordering::SeqCst);
                    async { StatusCode::NO_CONTENT }
                }),
            ),
    )
    .await;
    let revoker = Revoker::new().unwrap();
    for (path, status) in [("failed", 503), ("redirect", 307)] {
        let rule = rule(Some(Revocation::Http(HttpValidation {
            request: request(format!("{}/{path}", server.url)),
            multipart: None,
        })));
        let result = revoker.revoke(&rule, "secret", &BTreeMap::new()).await;
        if status == 503 {
            // The shared transport treats transient server failures as errors.
            assert!(result.is_err());
        } else {
            let result = result.unwrap();
            assert!(!result.revoked);
            assert_eq!(result.status_code, Some(status));
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[test]
fn detailed_aws_revocation_api_defaults_to_self_deactivation() {
    let options = AwsRevocationOptions::default();

    assert_eq!(options.action, AwsRevocationAction::Deactivate);
    assert!(matches!(options.credentials, AwsRevocationCredentials::SelfCredentials));
    assert!(options.target_user_name.is_none());
    assert!(options.region.is_none());
    assert_eq!(options.attempt_timeout, Duration::from_secs(5));
    assert_eq!(AwsRevocationStatus::Unknown.to_string(), "unknown");
}

#[tokio::test]
async fn aws_responder_revocation_sends_one_explicit_user_mutation() {
    let requests = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let observed = requests.clone();
    let server = serve(Router::new().route(
        "/",
        post(move |headers: HeaderMap, body: Bytes| {
            let observed = observed.clone();
            async move {
                let body = String::from_utf8(body.to_vec()).unwrap();
                let authorization = headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                observed.lock().unwrap().push((body.clone(), authorization));

                if body.contains("Action=GetCallerIdentity") {
                    (
                        StatusCode::OK,
                        [("content-type", "text/xml"), ("x-amzn-requestid", "sts-request-1")],
                        r#"<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/incident-responder</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>sts-request-1</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>"#,
                    )
                        .into_response()
                } else {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        [("content-type", "text/xml"), ("x-amzn-requestid", "iam-request-1")],
                        r#"<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <Error>
    <Type>Receiver</Type>
    <Code>ServiceFailure</Code>
    <Message>Internal service failure</Message>
  </Error>
  <RequestId>iam-request-1</RequestId>
</ErrorResponse>"#,
                    )
                        .into_response()
                }
            }
        }),
    ))
    .await;

    let responder_access_key_id = "AKIARESPONDEREXAMPLE";
    let responder_config = aws_config::defaults(BehaviorVersion::latest())
        .credentials_provider(Credentials::new(
            responder_access_key_id,
            "responderSecretKeyThatIsLongEnoughForSigning12345",
            None,
            None,
            "test-responder",
        ))
        .region(Region::new("us-east-1"))
        .endpoint_url(&server.url)
        .load()
        .await;
    let result = revoke_aws_access_key_with_options(
        "AKIAIOSFODNN7EXAMPLE",
        "unusedTargetSecretThatIsLongEnoughForValidation123",
        AwsRevocationOptions::responder(&responder_config)
            .with_target_user_name("target-user")
            .with_attempt_timeout(Duration::from_secs(2)),
    )
    .await
    .unwrap();

    assert_eq!(result.status, AwsRevocationStatus::Unknown);
    assert_eq!(result.action, AwsRevocationAction::Deactivate);
    assert_eq!(result.actor, AwsRevocationActor::Responder);
    assert_eq!(result.user_name.as_deref(), Some("target-user"));
    assert_eq!(result.error_code.as_deref(), Some("ServiceFailure"));
    assert_eq!(result.request_id.as_deref(), Some("iam-request-1"));

    let requests = requests.lock().unwrap();
    let identity_requests: Vec<_> =
        requests.iter().filter(|(body, _)| body.contains("Action=GetCallerIdentity")).collect();
    let mutation_requests: Vec<_> =
        requests.iter().filter(|(body, _)| body.contains("Action=UpdateAccessKey")).collect();
    assert_eq!(identity_requests.len(), 1, "only responder STS should be called");
    assert_eq!(mutation_requests.len(), 1, "IAM mutation must not be retried");

    let (mutation_body, authorization) = mutation_requests[0];
    assert!(mutation_body.contains("AccessKeyId=AKIAIOSFODNN7EXAMPLE"));
    assert!(mutation_body.contains("Status=Inactive"));
    assert!(mutation_body.contains("UserName=target-user"));
    assert!(authorization.contains(responder_access_key_id));
}

#[tokio::test]
async fn iam_mutations_retry_only_definitive_throttling_and_stop_after_three_attempts() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for action in [AwsRevocationAction::Deactivate, AwsRevocationAction::Delete] {
        for rejected in [2, 10] {
            let mutations = Arc::new(AtomicUsize::new(0));
            let observed = mutations.clone();
            let server = serve(Router::new().route("/", post(move |body: Bytes| {
                let observed = observed.clone();
                async move {
                    let body = String::from_utf8_lossy(&body);
                    let response = if body.contains("Action=GetCallerIdentity") {
                        "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/responder</Arn><Account>123456789012</Account><UserId>AIDAEXAMPLE</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>".to_string()
                    } else if observed.fetch_add(1, Ordering::SeqCst) < rejected {
                        return (StatusCode::TOO_MANY_REQUESTS, [("content-type", "text/xml")],
                            "<ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error></ErrorResponse>".to_string()).into_response();
                    } else {
                        let operation = if action == AwsRevocationAction::Delete { "DeleteAccessKey" } else { "UpdateAccessKey" };
                        format!("<{operation}Response xmlns=\"https://iam.amazonaws.com/doc/2010-05-08/\"><ResponseMetadata><RequestId>iam-success</RequestId></ResponseMetadata></{operation}Response>")
                    };
                    (StatusCode::OK, [("content-type", "text/xml")], response).into_response()
                }
            }))).await;
            let config = aws_config::defaults(BehaviorVersion::latest())
                .credentials_provider(Credentials::new(
                    "AKIARESPONDEREXAMPLE",
                    "fixtureSecretKeyLongEnoughForSigning1234567890",
                    None,
                    None,
                    "test",
                ))
                .region(Region::new("us-east-1"))
                .endpoint_url(&server.url)
                .load()
                .await;
            let result = revoke_aws_access_key_with_options(
                "AKIAIOSFODNN7EXAMPLE",
                "unusedTargetSecret",
                AwsRevocationOptions::responder(&config)
                    .with_action(action)
                    .with_target_user_name("target"),
            )
            .await
            .unwrap();
            assert_eq!(
                result.status,
                if rejected == 2 {
                    AwsRevocationStatus::Succeeded
                } else {
                    AwsRevocationStatus::Failed
                }
            );
            assert_eq!(mutations.load(Ordering::SeqCst), 3);
        }
    }
}

#[tokio::test]
async fn explicit_http_retries_never_repeat_mutations() {
    use kingfisher_scanner::validation::revocation::{
        RevocationSubmitted, execute_http_revocation,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::REQUEST_TIMEOUT,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_GATEWAY,
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::GATEWAY_TIMEOUT,
    ] {
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let server = serve(Router::new().route(
            "/",
            post(move || {
                let attempt = observed.fetch_add(1, Ordering::SeqCst);
                async move { if attempt == 0 { status } else { StatusCode::NO_CONTENT } }
            }),
        ))
        .await;
        let mut request = request(server.url.clone());
        request.method = "POST".into();
        let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
        let result = execute_http_revocation(
            &HttpValidation { request, multipart: None },
            &liquid::Object::from_iter([(
                "TOKEN".into(),
                liquid::model::Value::scalar("fixture-token"),
            )]),
            &reqwest::Client::new(),
            &parser,
            Duration::from_secs(2),
            2,
        )
        .await;
        assert!(result.unwrap_err().is::<RevocationSubmitted>(), "{status}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "{status}");
    }
}

#[tokio::test]
async fn explicit_http_retries_only_repeat_read_only_lookup_steps() {
    use kingfisher_scanner::validation::revocation::{
        RevocationSubmitted, execute_multi_step_revocation,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    for method in ["GET", "HEAD", "OPTIONS", "POST", "DELETE"] {
        for rejected in [2, 10] {
            let lookups = Arc::new(AtomicUsize::new(0));
            let observed_lookups = lookups.clone();
            let mutations = Arc::new(AtomicUsize::new(0));
            let observed_mutations = mutations.clone();
            let server = serve(
                Router::new()
                    .route(
                        "/lookup",
                        axum::routing::any(move || {
                            let attempt = observed_lookups.fetch_add(1, Ordering::SeqCst);
                            async move {
                                if attempt < rejected {
                                    StatusCode::TOO_MANY_REQUESTS
                                } else {
                                    StatusCode::OK
                                }
                            }
                        }),
                    )
                    .route(
                        "/mutate",
                        delete(move || {
                            observed_mutations.fetch_add(1, Ordering::SeqCst);
                            async { StatusCode::NO_CONTENT }
                        }),
                    ),
            )
            .await;
            let mut lookup = request(format!("{}/lookup", server.url));
            lookup.method = method.into();
            lookup.response_matcher = None;
            let steps = HttpMultiStepRevocation {
                steps: vec![
                    RevocationStep { name: None, request: lookup, multipart: None, extract: None },
                    RevocationStep {
                        name: None,
                        request: request(format!("{}/mutate", server.url)),
                        multipart: None,
                        extract: None,
                    },
                ],
            };
            let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
            let mut globals = liquid::Object::from_iter([(
                "TOKEN".into(),
                liquid::model::Value::scalar("fixture-token"),
            )]);
            let result = execute_multi_step_revocation(
                &steps,
                &mut globals,
                &reqwest::Client::new(),
                &parser,
                Duration::from_secs(2),
                2,
            )
            .await;
            let may_mutate = matches!(method, "POST" | "DELETE");
            assert_eq!(lookups.load(Ordering::SeqCst), if may_mutate { 1 } else { 3 }, "{method}");
            if !may_mutate && rejected == 2 {
                assert!(result.unwrap().revoked);
                assert_eq!(mutations.load(Ordering::SeqCst), 1);
            } else {
                assert_eq!(result.unwrap_err().is::<RevocationSubmitted>(), may_mutate, "{method}");
                assert_eq!(mutations.load(Ordering::SeqCst), 0);
            }
        }
    }
}

#[tokio::test]
async fn final_http_step_is_not_retried_even_with_read_only_method() {
    use kingfisher_scanner::validation::revocation::{
        RevocationSubmitted, execute_multi_step_revocation,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    for method in ["GET", "HEAD", "OPTIONS"] {
        let hits = Arc::new(AtomicUsize::new(0));
        let observed = hits.clone();
        let server = serve(Router::new().route(
            "/",
            axum::routing::any(move || {
                observed.fetch_add(1, Ordering::SeqCst);
                async { StatusCode::TOO_MANY_REQUESTS }
            }),
        ))
        .await;
        let mut action = request(server.url.clone());
        action.method = method.into();
        let steps = HttpMultiStepRevocation {
            steps: vec![RevocationStep {
                name: None,
                request: action,
                multipart: None,
                extract: None,
            }],
        };
        let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
        let mut globals = liquid::Object::from_iter([(
            "TOKEN".into(),
            liquid::model::Value::scalar("fixture-token"),
        )]);
        let result = execute_multi_step_revocation(
            &steps,
            &mut globals,
            &reqwest::Client::new(),
            &parser,
            Duration::from_secs(2),
            2,
        )
        .await;
        assert!(result.unwrap_err().is::<RevocationSubmitted>(), "{method}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn later_configuration_failure_preserves_a_submitted_multi_step_mutation() {
    use kingfisher_scanner::validation::revocation::RevocationSubmitted;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = hits.clone();
    let server = serve(Router::new().route(
        "/",
        post(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::NO_CONTENT }
        }),
    ))
    .await;
    let mut first = request(server.url.clone());
    first.method = "POST".into();
    first.response_matcher = None;
    let rule = rule(Some(Revocation::HttpMultiStep(HttpMultiStepRevocation {
        steps: vec![
            RevocationStep { name: None, request: first, multipart: None, extract: None },
            RevocationStep {
                name: None,
                request: request("invalid URL".into()),
                multipart: None,
                extract: None,
            },
        ],
    })));
    let error =
        Revoker::new().unwrap().revoke(&rule, "fixture-token", &BTreeMap::new()).await.unwrap_err();
    assert!(error.is::<RevocationSubmitted>());
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
