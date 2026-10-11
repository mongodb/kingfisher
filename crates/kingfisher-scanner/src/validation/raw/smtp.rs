//! SMTP AUTH only: never create a mail transaction or send message data.
use super::{
    B64, DynStream, RawValidationOutcome, connect_plain, connect_tls, string_var, tls_connector,
};
use crate::validation::{
    http_validation::{SsrfBlockedError, check_host_resolvable},
    limits::timeout,
};
use anyhow::{Result, anyhow, ensure};
use base64::Engine;
use http::StatusCode;
use liquid::Object;
use percent_encoding::percent_decode_str;
use rustls::pki_types::ServerName;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufStream};
use url::Url;

struct Credentials {
    target: Url,
    username: String,
    password: String,
}

fn check_credentials(credentials: &Credentials) -> Result<()> {
    ensure!(credentials.target.host().is_some(), "SMTP host is missing");
    ensure!(!credentials.username.is_empty(), "SMTP username is missing");
    ensure!(!credentials.password.is_empty(), "SMTP password is missing");
    ensure!(credentials.target.port() != Some(0), "Invalid SMTP port");
    ensure!(
        !credentials.username.contains('\0') && !credentials.password.contains('\0'),
        "SMTP credentials contain a NUL byte"
    );
    Ok(())
}

fn uri_credentials(uri: &str) -> Result<Credentials> {
    // Do not include parser errors or server replies in diagnostics: they can echo secrets.
    let mut target = Url::parse(uri).map_err(|_| anyhow!("Invalid SMTP credential URI"))?;
    ensure!(matches!(target.scheme(), "smtp" | "smtps"), "Unsupported SMTP URI scheme");
    let username = percent_decode_str(target.username())
        .decode_utf8()
        .map_err(|_| anyhow!("SMTP username is not UTF-8"))?
        .into_owned();
    let password = percent_decode_str(target.password().unwrap_or_default())
        .decode_utf8()
        .map_err(|_| anyhow!("SMTP password is not UTF-8"))?
        .into_owned();
    target.set_username("").map_err(|_| anyhow!("Invalid SMTP URI"))?;
    target.set_password(None).map_err(|_| anyhow!("Invalid SMTP URI"))?;
    let credentials = Credentials { target, username, password };
    check_credentials(&credentials)?;
    Ok(credentials)
}

pub(crate) fn is_parseable_uri(uri: &str) -> bool {
    uri_credentials(uri).is_ok()
}

pub(crate) async fn validate_uri(
    uri: &str,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<RawValidationOutcome> {
    validate(uri_credentials(uri)?, use_lax_tls, allow_internal_ips).await
}

pub(super) async fn validate_components(
    globals: &Object,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<RawValidationOutcome> {
    let host = string_var(globals, "SMTP_HOST").ok_or_else(|| anyhow!("Missing SMTP_HOST"))?;
    let mut target = Url::parse("smtp://placeholder.invalid").expect("static URL");
    // set_host accepts a hostname or bracketed IPv6, without allowing a supplied URL,
    // userinfo, path, or port to change the intended server.
    ensure!(
        !host.contains(['/', '@', '?', '#', '\\']) && !host.chars().any(char::is_whitespace),
        "Invalid SMTP_HOST"
    );
    ensure!(
        !host.contains(':') || (host.starts_with('[') && host.ends_with(']')),
        "SMTP_HOST must not include a port"
    );
    target.set_host(Some(&host)).map_err(|_| anyhow!("Invalid SMTP_HOST"))?;
    if let Some(port) = string_var(globals, "SMTP_PORT") {
        let port: u16 = port.parse().map_err(|_| anyhow!("Invalid SMTP_PORT"))?;
        ensure!(port != 0, "Invalid SMTP_PORT");
        target.set_port(Some(port)).map_err(|_| anyhow!("Invalid SMTP_PORT"))?;
    }
    let credentials = Credentials {
        target,
        username: string_var(globals, "SMTP_USERNAME")
            .ok_or_else(|| anyhow!("Missing SMTP_USERNAME"))?,
        password: string_var(globals, "TOKEN").ok_or_else(|| anyhow!("Missing TOKEN"))?,
    };
    check_credentials(&credentials)?;
    validate(credentials, use_lax_tls, allow_internal_ips).await
}

fn ports(target: &Url) -> Vec<(u16, bool)> {
    if let Some(port) = target.port() {
        vec![(port, target.scheme() == "smtps" || port == 465)]
    } else if target.scheme() == "smtps" {
        vec![(465, true)]
    } else {
        vec![(587, false), (465, true), (25, false)]
    }
}

async fn validate(
    credentials: Credentials,
    use_lax_tls: bool,
    allow_internal_ips: bool,
) -> Result<RawValidationOutcome> {
    let host = match credentials.target.host().expect("checked SMTP host") {
        // URL display brackets IPv6; socket lookup and TLS server names need the bare address.
        url::Host::Ipv6(address) => address.to_string(),
        host => host.to_string(),
    };
    let probes = ports(&credentials.target);
    if let Err(error) = check_host_resolvable(&host, probes[0].0, allow_internal_ips).await {
        let blocked = error.downcast_ref::<SsrfBlockedError>().is_some();
        return Ok(RawValidationOutcome {
            valid: false,
            status: if blocked {
                StatusCode::PRECONDITION_REQUIRED
            } else {
                StatusCode::BAD_GATEWAY
            },
            body: if blocked {
                "SMTP validation skipped: target blocked".into()
            } else {
                "SMTP authentication inconclusive: host resolution failed".into()
            },
        });
    }
    // Leave time for all common ports within the engine's default ten-second deadline.
    // An explicit port gets a longer budget. The enclosing engine deadline still applies.
    let budget = Duration::from_secs(if probes.len() == 1 { 10 } else { 3 });
    probe(&host, &credentials, probes, budget, use_lax_tls).await
}

async fn probe(
    host: &str,
    credentials: &Credentials,
    probes: Vec<(u16, bool)>,
    budget: Duration,
    use_lax_tls: bool,
) -> Result<RawValidationOutcome> {
    for (port, implicit_tls) in probes {
        if let Ok(Ok(code)) =
            timeout(budget, authenticate(host, port, implicit_tls, credentials, use_lax_tls)).await
        {
            // RFC 4954: only these AUTH replies establish acceptance or rejection.
            // Policy errors (534/538), temporary failures (454), and syntax/mechanism
            // errors are inconclusive. Stop after a definitive reply to avoid retries.
            if matches!(code, 235 | 535) {
                return Ok(RawValidationOutcome {
                    valid: code == 235,
                    status: if code == 235 { StatusCode::OK } else { StatusCode::UNAUTHORIZED },
                    body: format!(
                        "SMTP authentication {} (SMTP {code}, port {port})",
                        if code == 235 { "accepted" } else { "rejected" }
                    ),
                });
            }
        }
    }
    Ok(RawValidationOutcome {
        valid: false,
        status: StatusCode::BAD_GATEWAY,
        body: "SMTP authentication inconclusive: connection, TLS, timeout, or AUTH failure".into(),
    })
}

struct Reply {
    code: u16,
    lines: Vec<String>,
}

async fn reply(stream: &mut BufStream<DynStream>) -> Result<Reply> {
    let mut code = None;
    let mut lines = Vec::new();
    let mut total = 0;
    // Bound both an unterminated line and an endless multiline response, independently
    // of report-body limits. Retain replies only while interpreting this session.
    for _ in 0..64 {
        let mut line = String::new();
        let read = (&mut *stream).take(4097).read_line(&mut line).await?;
        total += read;
        ensure!(read <= 4096 && total <= 16384, "SMTP response too large");
        ensure!(line.ends_with("\r\n"), "Malformed SMTP reply");
        let bytes = line.as_bytes();
        ensure!(
            bytes.len() >= 5 && bytes[..3].iter().all(u8::is_ascii_digit),
            "Malformed SMTP reply"
        );
        let current: u16 = line[..3].parse()?;
        ensure!(code.is_none_or(|code| code == current), "Inconsistent SMTP reply codes");
        code = Some(current);
        let separator = bytes[3];
        ensure!(matches!(separator, b' ' | b'-' | b'\r'), "Malformed SMTP reply");
        lines.push(line[4..].trim_end().to_ascii_uppercase());
        if separator != b'-' {
            return Ok(Reply { code: current, lines });
        }
    }
    Err(anyhow!("Too many SMTP response lines"))
}

async fn command(stream: &mut BufStream<DynStream>, command: &str) -> Result<Reply> {
    stream.write_all(command.as_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    reply(stream).await
}

async fn ehlo(stream: &mut BufStream<DynStream>) -> Result<Reply> {
    let response = command(stream, "EHLO kingfisher.invalid").await?;
    ensure!(response.code == 250, "SMTP EHLO failed");
    Ok(response)
}

async fn authenticate(
    host: &str,
    port: u16,
    implicit_tls: bool,
    credentials: &Credentials,
    use_lax_tls: bool,
) -> Result<u16> {
    let socket = if implicit_tls {
        connect_tls(host, port, use_lax_tls).await?
    } else {
        connect_plain(host, port).await?
    };
    let mut stream = BufStream::new(socket);
    ensure!(reply(&mut stream).await?.code == 220, "SMTP greeting failed");
    let mut capabilities = ehlo(&mut stream).await?;
    if !implicit_tls {
        ensure!(
            capabilities.lines.iter().any(|line| line == "STARTTLS"),
            "SMTP STARTTLS unavailable"
        );
        ensure!(command(&mut stream, "STARTTLS").await?.code == 220, "SMTP STARTTLS rejected");
        // Discard plaintext capabilities and buffered bytes at the TLS boundary.
        let server_name = ServerName::try_from(host.to_string())?;
        let tls = tls_connector(use_lax_tls)?.connect(server_name, stream.into_inner()).await?;
        stream = BufStream::new(Box::new(tls));
        capabilities = ehlo(&mut stream).await?;
    }
    let mechanisms: Vec<_> = capabilities
        .lines
        .iter()
        .filter_map(|line| line.strip_prefix("AUTH ").or_else(|| line.strip_prefix("AUTH=")))
        .flat_map(str::split_ascii_whitespace)
        .collect();
    let code = authenticate_mechanisms(&mut stream, &mechanisms, credentials).await?;
    // Best effort, with no read: a slow/closed QUIT response cannot erase AUTH evidence.
    let _ = timeout(Duration::from_millis(100), async {
        stream.write_all(b"QUIT\r\n").await?;
        stream.flush().await
    })
    .await;
    Ok(code)
}

async fn authenticate_mechanisms(
    stream: &mut BufStream<DynStream>,
    mechanisms: &[&str],
    credentials: &Credentials,
) -> Result<u16> {
    if mechanisms.contains(&"PLAIN") {
        let response = command(stream, "AUTH PLAIN").await?;
        if response.code == 334 {
            let payload =
                B64.encode(format!("\0{}\0{}", credentials.username, credentials.password));
            return Ok(command(stream, &payload).await?.code);
        }
        // These replies reject the mechanism before any credentials were sent.
        if !matches!(response.code, 504 | 534) || !mechanisms.contains(&"LOGIN") {
            return Err(anyhow!("SMTP AUTH PLAIN challenge unavailable"));
        }
    }
    if !mechanisms.contains(&"LOGIN") {
        return Err(anyhow!("SMTP server offers no supported AUTH mechanism"));
    }
    let response = command(stream, "AUTH LOGIN").await?;
    if response.code != 334 {
        return Err(anyhow!("SMTP AUTH LOGIN challenge unavailable"));
    }
    let response = command(stream, &B64.encode(&credentials.username)).await?;
    if response.code == 334 {
        Ok(command(stream, &B64.encode(&credentials.password)).await?.code)
    } else {
        ensure!(response.code != 235, "SMTP accepted AUTH without a password");
        Ok(response.code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plain_mechanism_rejection_falls_back_to_advertised_login() {
        for code in [504, 534] {
            let (client, server) = tokio::io::duplex(1024);
            let server = tokio::spawn(async move {
                let mut server = BufStream::new(server);
                for (expected, reply) in [
                    ("AUTH PLAIN".to_string(), format!("{code} mechanism unavailable")),
                    ("AUTH LOGIN".to_string(), "334 username".to_string()),
                    (B64.encode("user"), "334 password".to_string()),
                    (B64.encode("password"), "235 accepted".to_string()),
                ] {
                    let mut line = String::new();
                    server.read_line(&mut line).await.unwrap();
                    assert_eq!(line.trim_end(), expected);
                    server.write_all(format!("{reply}\r\n").as_bytes()).await.unwrap();
                    server.flush().await.unwrap();
                }
            });
            let mut stream = BufStream::new(Box::new(client) as DynStream);
            let credentials = uri_credentials("smtps://user:password@example.com").unwrap();
            assert_eq!(
                authenticate_mechanisms(&mut stream, &["PLAIN", "LOGIN"], &credentials)
                    .await
                    .unwrap(),
                235
            );
            server.await.unwrap();
        }
    }

    #[test]
    fn smtp_ports_follow_explicit_configuration_and_secure_defaults() {
        for (uri, expected) in [
            ("smtp://u:p@example.com", vec![(587, false), (465, true), (25, false)]),
            ("smtps://u:p@example.com", vec![(465, true)]),
            ("smtp://u:p@example.com:465", vec![(465, true)]),
            ("smtps://u:p@example.com:2465", vec![(2465, true)]),
            ("smtp://u:p@example.com:2525", vec![(2525, false)]),
        ] {
            assert_eq!(ports(&uri_credentials(uri).unwrap().target), expected);
        }
        let credentials = uri_credentials("smtp://user%40example.com:p%3A%40ss@[::1]:587").unwrap();
        assert_eq!(credentials.username, "user@example.com");
        assert_eq!(credentials.password, "p:@ss");
        assert_eq!(credentials.target.host(), Some(url::Host::Ipv6(std::net::Ipv6Addr::LOCALHOST)));
        assert!(credentials.target.username().is_empty());
        assert!(credentials.target.password().is_none());
        assert!(!is_parseable_uri("smtp://:password@example.com"));
        assert!(!is_parseable_uri("smtp://user:p%00ss@example.com"));
    }

    #[tokio::test]
    async fn smtp_fallback_reaches_later_ports_after_connection_failure_and_timeout() {
        use tokio::net::TcpListener;

        let closed = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let stalled = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let stalled_port = stalled.local_addr().unwrap().port();
        let next = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let next_port = next.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = next.accept().await.unwrap();
            let mut stream = BufStream::new(socket);
            stream.write_all(b"220 fixture\r\n").await.unwrap();
            stream.flush().await.unwrap();
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "EHLO kingfisher.invalid\r\n");
            stream.write_all(b"250 No STARTTLS\r\n").await.unwrap();
            stream.flush().await.unwrap();
        });
        let credentials = uri_credentials("smtp://u:p@127.0.0.1").unwrap();
        let result = probe(
            "127.0.0.1",
            &credentials,
            vec![(closed_port, false), (stalled_port, false), (next_port, false)],
            Duration::from_millis(200),
            false,
        )
        .await
        .unwrap();
        assert_eq!(result.status, StatusCode::BAD_GATEWAY);
        tokio::time::timeout(Duration::from_secs(5), task).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn smtp_replies_are_bounded_and_require_consistent_codes() {
        for data in [
            "235-First\r\n535 Second\r\n".to_string(),
            "235xInvalid\r\n".to_string(),
            "235 Missing CRLF\n".to_string(),
            format!("235 {}\r\n", "x".repeat(4096)),
            "235-Still waiting\r\n".repeat(65),
        ] {
            let (reader, mut writer) = tokio::io::duplex(20000);
            writer.write_all(data.as_bytes()).await.unwrap();
            drop(writer);
            let mut stream = BufStream::new(Box::new(reader) as DynStream);
            assert!(reply(&mut stream).await.is_err());
        }
    }
}
