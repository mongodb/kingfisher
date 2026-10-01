#![cfg(feature = "validation")]

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
};
use kingfisher_rules::{
    HttpMultiStepRevocation, HttpRequest, HttpValidation, ResponseExtractor, ResponseMatcher,
    Revocation, RevocationStep,
};
use kingfisher_scanner::{Revoker, Rule, RuleSyntax};
use std::{collections::BTreeMap, time::Duration};

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
