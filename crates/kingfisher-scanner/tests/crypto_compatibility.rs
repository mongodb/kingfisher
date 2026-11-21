#![cfg(feature = "validation")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{Router, http::HeaderMap, routing::get};
use kingfisher_rules::{Confidence, Rule, Rules, Validation};
use kingfisher_scanner::{
    Finding, RulesDatabase, Scanner, ValidationOutcome, ValidationReason, Validator,
};

// These use only the YAML/TOML schema and helpers available in 2.19.1 and earlier.
// Keep the sources unchanged when loading: runtime endpoint selection is a variable.
const LEGACY_YAML: &str = r#"
rules:
  - id: acme.legacy-yaml
    name: Legacy YAML compatibility
    pattern: '(demo_[a-z0-9]{16})'
    pattern_requirements:
      checksum:
        actual:
          template: '{{ MATCH | sha256 }}'
        expected: '1efdb41ceb836c393507da3e86167ada43d7670d7da0ab8f12b5b244d9597db0'
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '{{ ENDPOINT }}/identity'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
            X-Proof: '{{ TOKEN | sha256 }}'
            X-Hmac: "{{ TOKEN | hmac_sha256: 'key' }}"
          response_matcher:
            - type: StatusMatch
              status: [200]
"#;

const LEGACY_TOML: &str = r#"
[[rules]]
id = "legacy-toml"
regex = '(demo_[a-z0-9]{16})'
validate = '''
let response = http.get(env.get("ENDPOINT") + "/identity", {
    Authorization: "Bearer " + finding.secret,
    "X-Proof": crypto.sha256(finding.secret),
    "X-Hmac": base64.encode(crypto.hmacSha256("key", finding.secret))
});
response.status == 200 ? {result: "valid"} : validate.unknown(response)
'''
"#;

fn scan(name: &str, source: &str) -> Vec<Finding> {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(name);
    std::fs::write(&path, source).unwrap();
    let rules = Rules::from_paths([path], Confidence::Low).unwrap();
    Scanner::new(Arc::new(RulesDatabase::from_rule_collection(rules).unwrap()))
        .scan_bytes(b"demo_abcdefgh12345678")
        .unwrap()
}

struct Server {
    endpoint: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(app: Router) -> Server {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server { endpoint, task }
}

fn validator(server: &Server) -> Validator {
    Validator::builder()
        .allow_internal_ips(true)
        .variable("ENDPOINT", &server.endpoint)
        .build()
        .unwrap()
}

#[tokio::test]
async fn legacy_yaml_and_toml_keep_hashing_and_validation_contracts() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move |headers: HeaderMap| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move {
                assert_eq!(headers["authorization"], "Bearer demo_abcdefgh12345678");
                assert_eq!(
                    headers["x-proof"],
                    "1efdb41ceb836c393507da3e86167ada43d7670d7da0ab8f12b5b244d9597db0"
                );
                assert_eq!(headers["x-hmac"], "6o8TSQIpN6HZmCDkZQ63MJmfSpCyOMVa9JDEwxGOiro=");
                "authenticated"
            }
        }),
    ))
    .await;
    for (name, source) in [("legacy.yml", LEGACY_YAML), ("legacy.toml", LEGACY_TOML)] {
        let findings = scan(name, source);
        assert_eq!(findings.len(), 1, "{name}");
        let checked =
            validator(&server).validate_prepared_findings(findings.clone(), &findings).await;
        assert_eq!(checked[0].outcome, ValidationOutcome::VerifiedActive, "{name}: {checked:?}");
        assert!(checked[0].input_diagnostics.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn crypto_headers_fail_closed_while_legacy_errors_still_omit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { axum::http::StatusCode::UNAUTHORIZED }
        }),
    ))
    .await;
    for (name, value) in [
        ("Authorization", "{{ TOKEN | ecdsa_sign: TOKEN }}"),
        ("Authorization", "{{ TOKEN | ed25519_sign }}"),
        ("Authorization", "{{ TOKEN | ec_public_key: 'P-256' }}"),
        ("Invalid Header", "{{ TOKEN | sha512 }}"),
        ("Authorization", "{{ TOKEN | sha512 }}\0"),
    ] {
        let mut finding = scan("legacy.yml", LEGACY_YAML).remove(0);
        let mut syntax = finding.rule().syntax().clone();
        let Some(Validation::Http(http)) = syntax.validation.as_mut() else { unreachable!() };
        http.request.headers.insert(name.into(), value.into());
        finding.rule = Arc::new(Rule::new(syntax));
        // Ordinary validation must enforce this too, without a preparation prerequisite.
        let checked = validator(&server).validate_findings(vec![finding]).await;
        assert_eq!(checked[0].outcome, ValidationOutcome::Unavailable, "{value}");
        assert_eq!(checked[0].reason, Some(ValidationReason::InvalidConfiguration));
        assert!(checked[0].http_status.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The same provider must still be contacted when a genuinely legacy header
    // is omitted. Merely mentioning a new filter must not change that contract.
    for value in [
        "{{ TOKEN | unknown_legacy_filter }}",
        "literal | sha512 {{ MISSING }}",
        "{% comment %}{{ TOKEN | sha512 }}{% endcomment %}{{ MISSING }}",
        "{{ '| sha512' }}{{ MISSING }}",
    ] {
        let mut finding = scan("legacy.yml", LEGACY_YAML).remove(0);
        let mut syntax = finding.rule().syntax().clone();
        let Some(Validation::Http(http)) = syntax.validation.as_mut() else { unreachable!() };
        http.request.headers.insert("Authorization".into(), value.into());
        finding.rule = Arc::new(Rule::new(syntax));
        let checked = validator(&server).validate_findings(vec![finding]).await;
        assert_eq!(checked[0].outcome, ValidationOutcome::VerifiedInactive, "{value}");
        assert_eq!(checked[0].http_status, Some(401));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn prepared_crypto_templates_allow_locals_and_unreachable_inputs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let server = serve(Router::new().route(
        "/identity",
        get(move |headers: HeaderMap| {
            counter.fetch_add(1, Ordering::SeqCst);
            async move {
                assert!(headers["x-proof"].to_str().unwrap().starts_with("Proof "));
                "authenticated"
            }
        }),
    ))
    .await;
    let mut findings = scan("legacy.yml", LEGACY_YAML);
    let mut syntax = findings[0].rule().syntax().clone();
    let Some(Validation::Http(http)) = syntax.validation.as_mut() else { unreachable!() };
    http.request.headers.insert(
        "X-Proof".into(),
        "{%- assign digest = TOKEN | sha512 -%}\
         {%- capture proof -%}Proof {{ digest }}{%- endcapture -%}\
         {%- if false -%}{{ UNREACHABLE }}{%- endif -%}{{ proof }}"
            .into(),
    );
    findings[0].rule = Arc::new(Rule::new(syntax));
    let checked = validator(&server).validate_prepared_findings(findings.clone(), &findings).await;
    assert_eq!(checked[0].outcome, ValidationOutcome::VerifiedActive, "{checked:?}");
    assert!(checked[0].input_diagnostics.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
