//! Local SMTP fixtures exercise authentication without any mail transaction.
use std::{path::Path, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use kingfisher_rules::{Confidence, Rule, RuleSyntax, Rules, Validation, get_builtin_rules};
use kingfisher_scanner::validation::{ValidationEngine, ValidationResult, raw::validate_raw};
use kingfisher_scanner::{RulesDatabase, Scanner, ValidationOutcome, ValidationReason, Validator};
use liquid::{Object, model::Value};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
type TestStream = BufStream<Box<dyn Stream>>;

async fn send(stream: &mut TestStream, reply: &str) {
    stream.write_all(reply.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
}

async fn read(stream: &mut TestStream, transcript: &mut Vec<String>) -> String {
    let mut line = String::new();
    match stream.read_line(&mut line).await {
        Ok(_) => {}
        Err(error) if line.is_empty() && error.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(error) => panic!("SMTP fixture read failed: {error}"),
    }
    let line = line.trim_end().to_string();
    transcript.push(line.clone());
    line
}

async fn server(
    implicit: bool,
    starttls: bool,
    mechanism: &'static str,
    auth_reply: &'static str,
) -> (u16, JoinHandle<Vec<String>>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut transcript = Vec::new();
        let mut stream: TestStream = if implicit {
            let Ok(tls) = acceptor.accept(socket).await else { return transcript };
            BufStream::new(Box::new(tls))
        } else {
            BufStream::new(Box::new(socket))
        };
        send(&mut stream, "220-fixture.example\r\n220 SMTP fixture\r\n").await;
        assert_eq!(read(&mut stream, &mut transcript).await, "EHLO kingfisher.invalid");
        if !implicit {
            if !starttls {
                send(&mut stream, "250-fixture.example\r\n250 AUTH PLAIN LOGIN\r\n").await;
                assert!(read(&mut stream, &mut transcript).await.is_empty());
                return transcript;
            }
            // A different pre-TLS AUTH list must be discarded after the upgrade.
            send(&mut stream, "250-fixture.example\r\n250-AUTH CRAM-MD5\r\n250 STARTTLS\r\n").await;
            assert_eq!(read(&mut stream, &mut transcript).await, "STARTTLS");
            send(&mut stream, "220 Ready for TLS\r\n").await;
            let Ok(tls) = acceptor.accept(stream.into_inner()).await else { return transcript };
            stream = BufStream::new(Box::new(tls));
            assert_eq!(read(&mut stream, &mut transcript).await, "EHLO kingfisher.invalid");
        }
        send(&mut stream, &format!("250-fixture.example\r\n250 auth {mechanism}\r\n")).await;
        if mechanism == "PLAIN EARLY" {
            assert_eq!(read(&mut stream, &mut transcript).await, "AUTH PLAIN");
            send(&mut stream, auth_reply).await;
            assert!(read(&mut stream, &mut transcript).await.is_empty());
            return transcript;
        } else if mechanism == "PLAIN" {
            assert_eq!(read(&mut stream, &mut transcript).await, "AUTH PLAIN");
            send(&mut stream, "334 \r\n").await;
            let payload = read(&mut stream, &mut transcript).await;
            assert_eq!(B64.decode(payload).unwrap(), b"\0user@example.com\0fixture:@password");
        } else if mechanism == "LOGIN" {
            assert_eq!(read(&mut stream, &mut transcript).await, "AUTH LOGIN");
            send(&mut stream, "334 VXNlcm5hbWU6\r\n").await;
            assert_eq!(
                B64.decode(read(&mut stream, &mut transcript).await).unwrap(),
                b"user@example.com"
            );
            send(&mut stream, "334 UGFzc3dvcmQ6\r\n").await;
            assert_eq!(
                B64.decode(read(&mut stream, &mut transcript).await).unwrap(),
                b"fixture:@password"
            );
        } else {
            assert!(read(&mut stream, &mut transcript).await.is_empty());
            return transcript;
        }
        send(&mut stream, auth_reply).await;
        assert_eq!(read(&mut stream, &mut transcript).await, "QUIT");
        transcript
    });
    (port, task)
}

async fn check_uri(port: u16, implicit: bool, lax: bool, allow_internal: bool) -> ValidationResult {
    let mut syntax = RuleSyntax::new("custom.smtp.uri", "SMTP URI", "(fixture)");
    syntax.validation = Some(Validation::CredentialUri);
    let uri = format!(
        "{}://user%40example.com:fixture%3A%40password@127.0.0.1:{port}",
        if implicit { "smtps" } else { "smtp" }
    );
    let globals = Object::from_iter([("TOKEN".into(), Value::scalar(uri))]);
    let client = reqwest::Client::new();
    let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
    ValidationEngine::new(&client, &parser)
        .use_lax_tls(lax)
        .allow_internal_ips(allow_internal)
        .validate(&Rule::new(syntax), &globals)
        .await
}

#[tokio::test]
async fn smtp_starttls_and_implicit_tls_authenticate_without_sending_email() {
    for implicit in [false, true] {
        for mechanism in ["PLAIN", "LOGIN"] {
            let (port, task) = server(implicit, true, mechanism, "235 2.7.0 Accepted\r\n").await;
            let result = check_uri(port, implicit, true, true).await;
            assert_eq!(result.outcome, ValidationOutcome::VerifiedActive);
            assert!(!result.response_body.contains("fixture:@password"));
            assert!(!result.response_body.contains("user@example.com"));
            let transcript = task.await.unwrap();
            assert!(!transcript.iter().any(|line| {
                ["MAIL", "RCPT", "DATA", "BDAT"].iter().any(|verb| line.starts_with(verb))
            }));
        }
    }
}

#[tokio::test]
async fn smtp_distinguishes_rejection_from_temporary_and_policy_failures() {
    for (reply, expected) in [
        ("535 5.7.8 Bad credentials\r\n", ValidationOutcome::VerifiedInactive),
        ("454 4.7.0 Try later\r\n", ValidationOutcome::Unavailable),
        ("534 5.7.9 App password required\r\n", ValidationOutcome::Unavailable),
        ("538 5.7.11 Encryption required\r\n", ValidationOutcome::Unavailable),
        ("250 Unrelated success\r\n", ValidationOutcome::Unavailable),
    ] {
        let (port, task) = server(true, true, "PLAIN", reply).await;
        assert_eq!(check_uri(port, true, true, true).await.outcome, expected);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn smtp_refuses_untrusted_tls_plaintext_and_unsupported_auth() {
    for implicit in [false, true] {
        let (port, task) = server(implicit, true, "PLAIN", "235 Accepted\r\n").await;
        assert_eq!(
            check_uri(port, implicit, false, true).await.outcome,
            ValidationOutcome::Unavailable
        );
        let transcript = task.await.unwrap();
        assert!(!transcript.iter().any(|line| line.starts_with("AUTH")));
    }
    for (starttls, mechanism) in [(false, "PLAIN"), (true, "XOAUTH2")] {
        let (port, task) = server(false, starttls, mechanism, "235 Accepted\r\n").await;
        assert_eq!(
            check_uri(port, false, true, true).await.outcome,
            ValidationOutcome::Unavailable
        );
        assert!(!task.await.unwrap().iter().any(|line| line.starts_with("AUTH")));
    }
}

#[tokio::test]
async fn smtp_does_not_classify_replies_before_credentials_are_sent() {
    for reply in ["235 Already authenticated\r\n", "535 AUTH disabled\r\n"] {
        let (port, task) = server(true, true, "PLAIN EARLY", reply).await;
        assert_eq!(check_uri(port, true, true, true).await.outcome, ValidationOutcome::Unavailable);
        task.await.unwrap();
    }
}

#[tokio::test]
async fn smtp_builtin_uri_detection_dispatches_the_full_uri_and_rejects_bad_ports() {
    let syntax = get_builtin_rules(None)
        .unwrap()
        .iter_rules()
        .find(|rule| rule.id == "betterleaks.generic-credential-uri")
        .unwrap()
        .clone();
    let scanner =
        Scanner::new(Arc::new(RulesDatabase::from_rules(vec![Rule::new(syntax)]).unwrap()));
    let findings = scanner
        .scan_bytes(b"MAIL_URL=SMTP://user%40example.com:fixture%3A%40password@127.0.0.1:587\n")
        .unwrap();
    assert_eq!(findings.len(), 1);
    let result = Validator::builder().build().unwrap().validate_findings(findings).await;
    assert_eq!(result[0].outcome, ValidationOutcome::Skipped);
    assert_eq!(result[0].reason, Some(ValidationReason::TargetBlocked));
    assert!(
        scanner.scan_bytes(b"smtp://user:fixture-password@example.com:70000\n").unwrap().is_empty()
    );
}

#[tokio::test]
async fn smtp_cli_scan_validates_detected_uris_without_sending_mail() {
    let (port, server) = server(true, true, "LOGIN", "235 Accepted\r\n").await;
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("smtp.env");
    let report = directory.path().join("report.json");
    std::fs::write(
        &input,
        format!("MAIL_URL=smtps://user%40example.com:fixture%3A%40password@127.0.0.1:{port}\n",),
    )
    .unwrap();
    let report_for_command = report.clone();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .arg("scan")
            .arg(input)
            .args(["--rule", "betterleaks.generic-credential-uri", "--format", "json", "--output"])
            .arg(report_for_command)
            // The fixture has a self-signed certificate; this explicit opt-in
            // exercises the CLI TLS policy without changing production defaults.
            .args(["--tls-mode", "off", "--allow-internal-ips", "--no-update-check"])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert_eq!(output.status.code(), Some(205), "{}", String::from_utf8_lossy(&output.stderr));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(report["findings"][0]["finding"]["validation"]["outcome"], "verified_active");
    assert!(!server.await.unwrap().iter().any(|line| line.starts_with("MAIL")));
}

#[tokio::test]
async fn smtp_blocks_internal_targets_and_handles_closed_connections_and_timeouts() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let result = check_uri(port, false, true, false).await;
    assert_eq!(result.outcome, ValidationOutcome::Skipped);
    assert_eq!(result.reason, Some(ValidationReason::TargetBlocked));
    drop(listener);
    assert_eq!(check_uri(port, false, true, true).await.outcome, ValidationOutcome::Unavailable);

    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut syntax = RuleSyntax::new("custom.smtp.uri", "SMTP URI", "(fixture)");
    syntax.validation = Some(Validation::CredentialUri);
    let globals = Object::from_iter([(
        "TOKEN".into(),
        Value::scalar(format!("smtp://u:p@{}", listener.local_addr().unwrap())),
    )]);
    let client = reqwest::Client::new();
    let parser = liquid::ParserBuilder::with_stdlib().build().unwrap();
    let result = ValidationEngine::new(&client, &parser)
        .allow_internal_ips(true)
        .timeout(Duration::from_millis(20))
        .validate(&Rule::new(syntax), &globals)
        .await;
    assert_eq!(result.outcome, ValidationOutcome::Unavailable);
    assert_eq!(result.reason, Some(ValidationReason::DeadlineExceeded));
}

fn custom_scanner() -> Scanner {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/rules/smtp.yml");
    let rules = Rules::from_yaml_file(path, Confidence::Low).unwrap();
    Scanner::new(Arc::new(
        RulesDatabase::from_rules(rules.iter_rules().cloned().map(Rule::new).collect()).unwrap(),
    ))
}

#[tokio::test]
async fn smtp_custom_rule_associates_environment_and_config_fields() {
    for input in [
        "SMTP_HOST=127.0.0.1\nSMTP_PORT={PORT}\nSMTP_USERNAME=user@example.com\nSMTP_PASSWORD=fixture:@password\n",
        "smtp_host: '127.0.0.1'\r\nsmtp_port: {PORT}\r\nsmtp_username: 'user@example.com'\r\nsmtp_password: 'fixture:@password'\r\n",
    ] {
        let (port, task) = server(false, true, "LOGIN", "235 Accepted\r\n").await;
        let findings = custom_scanner()
            .scan_bytes(input.replace("{PORT}", &port.to_string()).as_bytes())
            .unwrap();
        let result = Validator::builder()
            .allow_internal_ips(true)
            .build()
            .unwrap()
            .validate_findings(findings)
            .await;
        let primary = result.iter().find(|f| f.finding.rule_id == "custom.smtp.password").unwrap();
        // The high-level API deliberately enforces strict TLS; this fixture certificate
        // is untrusted. Association still resolves and retains the correct components.
        assert_eq!(primary.outcome, ValidationOutcome::Unavailable);
        let credential = primary.credential.as_ref().unwrap();
        assert_eq!(credential.secret, "fixture:@password");
        assert_eq!(credential.variables["SMTP_USERNAME"], "user@example.com");
        assert_eq!(credential.variables["SMTP_PORT"], port.to_string());
        task.await.unwrap();
    }
    // Exercise the Raw dispatcher with the same separate-field contract and explicit TLS policy.
    let (port, task) = server(false, true, "PLAIN", "235 Accepted\r\n").await;
    let globals = Object::from_iter([
        ("TOKEN".into(), Value::scalar("fixture:@password")),
        ("SMTP_HOST".into(), Value::scalar("127.0.0.1")),
        ("SMTP_USERNAME".into(), Value::scalar("user@example.com")),
        ("SMTP_PORT".into(), Value::scalar(port.to_string())),
    ]);
    let result = validate_raw("smtp", &globals, &reqwest::Client::new(), true, true).await.unwrap();
    assert!(result.valid);
    task.await.unwrap();
}

#[tokio::test]
async fn smtp_custom_rule_skips_ambiguous_credentials_and_keeps_port_optional() {
    let validator = Validator::builder().build().unwrap();
    let findings = custom_scanner().scan_bytes(
        b"SMTP_HOST=smtp.example.com\nSMTP_USERNAME=user@example.com\nSMTP_PASSWORD=fixture-password\n",
    ).unwrap();
    let primary = findings.iter().find(|f| f.rule_id == "custom.smtp.password").unwrap();
    assert!(validator.input_diagnostics(primary, &findings).is_empty());
    let punctuation = custom_scanner().scan_bytes(
        b"SMTP_HOST=smtp.example.com\nSMTP_USERNAME=user@example.com\nSMTP_PASSWORD=p@ss,#;word\n",
    ).unwrap();
    assert_eq!(
        punctuation.iter().find(|f| f.rule_id == "custom.smtp.password").unwrap().secret,
        "p@ss,#;word"
    );
    let ambiguous = custom_scanner().scan_bytes(
        b"SMTP_HOST=smtp.example.com\nSMTP_HOST=other.example.com\nSMTP_USERNAME=user@example.com\nSMTP_PASSWORD=fixture-password\n",
    ).unwrap();
    let result = validator.validate_findings(ambiguous).await;
    let primary = result.iter().find(|f| f.finding.rule_id == "custom.smtp.password").unwrap();
    assert_eq!(primary.outcome, ValidationOutcome::Skipped);
    assert_eq!(primary.reason, Some(ValidationReason::AmbiguousDependency));
    assert!(
        custom_scanner()
            .scan_bytes(b"PASSWORD=unrelated\nSMTP_PASSWORD=orphan\n")
            .unwrap()
            .is_empty()
    );
}
