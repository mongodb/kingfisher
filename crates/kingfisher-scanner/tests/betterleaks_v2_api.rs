#![cfg(feature = "validation")]

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    http::{HeaderMap, StatusCode},
    routing::{delete, get},
};
use kingfisher_rules::{Confidence, Rules};
use kingfisher_scanner::{Revoker, RulesDatabase, Scanner, ValidationOutcome, Validator};

#[tokio::test]
async fn imported_v2_programs_preserve_snapshots_and_require_explicit_operations() {
    let validations = Arc::new(AtomicUsize::new(0));
    let analyses = Arc::new(AtomicUsize::new(0));
    let revocations = Arc::new(AtomicUsize::new(0));
    let validation_count = validations.clone();
    let analysis_count = analyses.clone();
    let revocation_count = revocations.clone();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route(
                    "/identity",
                    get(move |headers: HeaderMap| {
                        validation_count.fetch_add(1, Ordering::SeqCst);
                        async move {
                            assert_eq!(headers["authorization"], "Bearer token_abcdefgh12345678");
                            assert_eq!(headers["x-account"], "demo");
                            r#"{"id":"user-7","private":"handoff-evidence"}"#
                        }
                    }),
                )
                .route(
                    "/permissions",
                    get(move |headers: HeaderMap| {
                        analysis_count.fetch_add(1, Ordering::SeqCst);
                        async move {
                            assert_eq!(headers["x-handoff"], "handoff-evidence");
                            assert_eq!(headers["x-capture"], "token_");
                            r#"{"permissions":["read","write"]}"#
                        }
                    }),
                )
                .route(
                    "/token",
                    delete(move |headers: HeaderMap| {
                        revocation_count.fetch_add(1, Ordering::SeqCst);
                        async move {
                            assert_eq!(headers["authorization"], "Bearer token_abcdefgh12345678");
                            assert_eq!(headers["x-account"], "demo");
                            StatusCode::NO_CONTENT
                        }
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v2.toml");
    std::fs::write(&path, r#"
minVersion = "v2.0.0"
[[rules]]
id = "account"
regex = '(?P<account>demo)'
[[rules]]
id = "credential"
regex = '((?P<prefix>token_)[a-z0-9]{16})'
secretGroup = 1
components = [{id = "account"}]
validate = '''
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let identity = http.get(endpoint + "/identity", {Authorization: "Bearer " + finding.secret, "X-Account": components["account"].captures.account});
identity.status == 200 ? {result: "valid", metadata: {id: identity.json.id}, analysis: {private: identity.json.private}} : validate.unknown(identity)
'''
analyze = '''
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let permissions = http.get(endpoint + "/permissions", {"X-Handoff": validation.analysis.private, "X-Capture": finding.captures.prefix});
{identity: {id: validation.metadata.id}, capabilities: analysis.capabilities({read: "read" in permissions.json.permissions, write: "write" in permissions.json.permissions})}
'''
revoke = '''
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let response = http.delete(endpoint + "/token", {Authorization: "Bearer " + finding.secret, "X-Account": components["account"].captures.account});
response.status == 204 ? {result: "revoked"} : revoke.unknown(response)
'''
"#).unwrap();
    let rules = Rules::from_paths([path], Confidence::Low).unwrap();
    let scanner = Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules).unwrap()));
    let findings = scanner.scan_bytes(b"demo token_abcdefgh12345678").unwrap();
    assert_eq!(validations.load(Ordering::SeqCst), 0);
    assert_eq!(analyses.load(Ordering::SeqCst), 0);
    assert_eq!(revocations.load(Ordering::SeqCst), 0);
    let validator = Validator::builder()
        .variable("ENDPOINT", endpoint)
        .allow_internal_ips(true)
        .build()
        .unwrap();
    let checked = validator.validate_findings(findings).await;
    let credential =
        checked.iter().find(|finding| finding.finding.rule_id == "custom.credential").unwrap();
    assert_eq!(credential.outcome, ValidationOutcome::VerifiedActive);
    assert_eq!(validations.load(Ordering::SeqCst), 1);
    assert_eq!(analyses.load(Ordering::SeqCst), 0);
    assert_eq!(revocations.load(Ordering::SeqCst), 0);
    let changed = validator
        .with_variables(BTreeMap::from([("ENDPOINT".into(), "https://invalid.example".into())]));
    let analysis = changed.analyze_validated(credential).await.unwrap();
    assert_eq!(analysis["identity"]["id"], "user-7");
    assert_eq!(analysis["capabilities"], serde_json::json!(["read", "write"]));
    assert_eq!(analyses.load(Ordering::SeqCst), 1);
    assert!(!format!("{credential:?}").contains("handoff-evidence"));
    let revoked = Revoker::new().unwrap().revoke_validated(credential).await.unwrap();
    assert!(revoked.revoked);
    assert_eq!(revocations.load(Ordering::SeqCst), 1);
    server.abort();
}

#[tokio::test]
async fn explicit_analysis_obeys_transport_policy_deadline_and_snapshot_redaction() {
    use std::time::Duration;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = format!("http://{}/permissions", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/permissions",
                get(move || {
                    count.fetch_add(1, Ordering::SeqCst);
                    async {
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        "{}"
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let mut syntax =
        kingfisher_scanner::RuleSyntax::new("acme.analysis", "Explicit analysis", "(synthetic)");
    syntax.validation = Some(
        serde_json::from_value(serde_json::json!({"type":"Betterleaks","content":{
            "expression":"{result: \"valid\"}",
            "analyze":format!("let r = http.get(\"{endpoint}\", {{}}); {{capabilities:[\"read\"]}}")
        }}))
        .unwrap(),
    );
    let scanner = Scanner::new(Arc::new(
        RulesDatabase::from_rules(vec![kingfisher_scanner::Rule::new(syntax)]).unwrap(),
    ));
    let finding = scanner.scan_bytes(b"synthetic").unwrap().remove(0);
    let blocked = Validator::builder().build().unwrap();
    let validated = blocked.validate_finding(&finding).await;
    assert_eq!(validated.outcome, ValidationOutcome::VerifiedActive);
    assert!(blocked.analyze_validated(&validated).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let short = Validator::builder()
        .timeout(Duration::from_millis(25))
        .allow_internal_ips(true)
        .build()
        .unwrap();
    assert!(short.analyze_validated(&validated).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let redacted = validated.into_redacted();
    assert!(short.analyze_validated(&redacted).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    server.abort();
}
