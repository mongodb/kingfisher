use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::Result;
use serde_json::Value;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path_regex},
};

const IMAGE: &str = "local-test:latest";
// kingfisher:ignore (test fixture, not a real token)
const SECRET: &str = "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";

// Dependency-interop check for Bollard's AWS-LC TLS feature selection, not the
// Kingfisher Docker client factory (which rejects TLS environment configuration).
#[tokio::test]
async fn bollard_aws_lc_interop_preserves_client_certificate_authentication() -> Result<()> {
    use std::{sync::Arc, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let server_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
    let client_key = rcgen::generate_simple_self_signed(vec!["docker-client.invalid".into()])?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(client_key.cert.der().clone())?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.signing_key.serialize_der())
                .into(),
        )?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls)).accept(socket).await?;
        assert_eq!(stream.get_ref().1.peer_certificates().unwrap().len(), 1);
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let count = stream.read(&mut buffer).await?;
            anyhow::ensure!(count > 0 && request.len() < 8192, "incomplete Docker ping request");
            request.extend_from_slice(&buffer[..count]);
        }
        assert!(String::from_utf8_lossy(&request).lines().next().unwrap().contains("/_ping"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await?;
        stream.shutdown().await?;
        anyhow::Ok(())
    });
    let work = tempfile::tempdir()?;
    let key = work.path().join("key.pem");
    let cert = work.path().join("cert.pem");
    let ca = work.path().join("ca.pem");
    std::fs::write(&key, client_key.signing_key.serialize_pem())?;
    std::fs::write(&cert, client_key.cert.pem())?;
    std::fs::write(&ca, server_key.cert.pem())?;
    let docker = bollard::Docker::connect_with_ssl(
        &format!("https://{address}"),
        &key,
        &cert,
        &ca,
        5,
        bollard::API_DEFAULT_VERSION,
    )?;
    assert_eq!(docker.ping().await?, "OK");
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    Ok(())
}

fn append_bytes(tar: &mut tar::Builder<impl Write>, path: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, path, data)?;
    Ok(())
}

fn image_archive() -> Result<Vec<u8>> {
    let mut layer = tar::Builder::new(Vec::new());
    append_bytes(&mut layer, "app/secret.txt", format!("token={SECRET}\n").as_bytes())?;
    let mut archive = tar::Builder::new(Vec::new());
    append_bytes(&mut archive, "manifest.json", br#"[{"Layers":["layer.tar"]}]"#)?;
    append_bytes(&mut archive, "layer.tar", &layer.into_inner()?)?;
    Ok(archive.into_inner()?)
}

fn scan_command(work: &Path, host: &str, image: &str) -> Command {
    scan_command_with_binary(assert_cmd::cargo::cargo_bin!("kingfisher"), work, host, image)
}

fn scan_command_with_binary(binary: &Path, work: &Path, host: &str, image: &str) -> Command {
    let mut command = Command::new(binary);
    command
        .args(["-v", "scan", "--git-clone-dir"])
        .arg(work.join("scan output"))
        .args(["docker", image, "--format", "json", "--output"])
        .arg(work.join("report.json"))
        .args([
            "--rule",
            "betterleaks.github-pat",
            "--confidence=low",
            "--no-validate",
            "--no-update-check",
        ])
        .env("DOCKER_CONFIG", work.join("docker config"))
        .env("DOCKER_HOST", host)
        // Keep PATH isolated; Windows CLI fixtures also isolate the application directory.
        .env("PATH", work.join("empty bin"));
    for name in [
        "DOCKER_CONTEXT",
        "DOCKER_API_VERSION",
        "DOCKER_TLS",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "KF_DOCKER_TOKEN",
    ] {
        command.env_remove(name);
    }
    command
}

async fn run_scan(mut command: Command) -> Result<Output> {
    // Keep the mock HTTP server responsive while the scanner subprocess runs.
    Ok(tokio::task::spawn_blocking(move || command.output()).await??)
}

fn assert_no_staging_files(work: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(work) {
        let entry = entry?;
        assert!(!entry.file_name().to_string_lossy().starts_with(".kingfisher-image-"));
    }
    Ok(())
}

fn assert_completed_scan(work: &Path, output: &Output) -> Result<()> {
    assert_eq!(output.status.code(), Some(200), "{}", String::from_utf8_lossy(&output.stderr));
    let report = work.join("report.json");
    assert!(std::fs::read_to_string(&report)?.contains(SECRET));
    let report: Value = serde_json::from_reader(File::open(report)?)?;
    assert_eq!(report["audit"]["summary"]["scan_succeeded"], 1);
    assert_eq!(report["audit"]["summary"]["fetch_failed"], 0);
    assert_no_staging_files(work)
}

async fn failing_api(requests: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/version$"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_json(serde_json::json!({"message": "API unavailable"})),
        )
        .expect(requests)
        .mount(&server)
        .await;
    server
}

fn compile_docker_cli_fixture(work: &Path) -> Result<(PathBuf, PathBuf)> {
    let bin_dir = work.join("fake bin with spaces");
    std::fs::create_dir_all(&bin_dir)?;
    let binary = bin_dir.join(format!("docker{}", std::env::consts::EXE_SUFFIX));
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("docker_cli_stub.rs");
    // Compile a portable executable rather than relying on shell scripts or Unix utilities.
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut command = Command::new(compiler);
    command.args(["--edition=2024", "--target", env!("KINGFISHER_BUILD_TARGET")]);
    // Cargo's target and RUSTFLAGS do not automatically carry over to rustc.
    // Match the scanner's Windows ABI and avoid DLL dependencies in the isolated PATH.
    if cfg!(windows) {
        command
            .args(env!("KINGFISHER_BUILD_RUSTFLAGS").split('\u{1f}').filter(|arg| !arg.is_empty()));
        command.args(["-C", "target-feature=+crt-static"]);
        if cfg!(target_env = "gnu") {
            command.args(["-C", "link-arg=-static"]);
        }
        let linker_name = format!(
            "CARGO_TARGET_{}_LINKER",
            env!("KINGFISHER_BUILD_TARGET").replace('-', "_").to_uppercase()
        );
        if let Some(linker) = std::env::var_os(linker_name) {
            command.arg("-C").arg(format!("linker={}", linker.to_string_lossy()));
        }
    }
    let output = command.arg(source).arg("-o").arg(&binary).output()?;
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    // Windows searches the application directory and system directories before
    // inherited PATH. Run a private scanner copy beside the stub so a system
    // docker.exe cannot take precedence, even when PATH is isolated.
    let scanner = bin_dir.join(format!("kingfisher{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(assert_cmd::cargo::cargo_bin!("kingfisher"), &scanner)?;
    Ok((bin_dir, scanner))
}

#[tokio::test]
async fn scan_through_compatible_api_without_docker_cli() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/version$"))
        // Podman's compatibility service implements the Docker v1.40 API.
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"ApiVersion": "1.40"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/images/local-test:latest/json$"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"Id": "sha256:fixture"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^(/v[0-9.]+)?/images/local-test:latest/get$"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(image_archive()?))
        .expect(2)
        .mount(&server)
        .await;

    for use_context in [false, true] {
        let work = tempfile::tempdir()?;
        let mut command = scan_command(work.path(), &server.uri(), IMAGE);
        command.env("KF_DOCKER_TOKEN", "test-user:test-password");
        if use_context {
            let config = work.path().join("docker config");
            let metadata = config.join("contexts").join("meta").join("fixture-context");
            std::fs::create_dir_all(&metadata)?;
            std::fs::write(config.join("config.json"), br#"{"currentContext":"podman"}"#)?;
            std::fs::write(
                metadata.join("meta.json"),
                serde_json::to_vec(&serde_json::json!({
                    "Name": "podman", "Endpoints": {"docker": {"Host": server.uri()}},
                }))?,
            )?;
            command.env_remove("DOCKER_HOST");
        }
        let output = run_scan(command).await?;
        assert_completed_scan(work.path(), &output)?;
        assert!(!String::from_utf8_lossy(&output.stderr).contains("trying CLI"));
    }
    // Local export must not send private-registry credentials to the daemon.
    for request in server.received_requests().await.unwrap() {
        assert!(!request.headers.contains_key("x-registry-auth"));
        assert!(!request.headers.contains_key("authorization"));
    }
    Ok(())
}

#[tokio::test]
async fn docker_tls_settings_use_cli_without_probing_api() -> Result<()> {
    let work = tempfile::tempdir()?;
    let (bin_dir, scanner) = compile_docker_cli_fixture(work.path())?;
    let archive = work.path().join("fixture.tar");
    std::fs::write(&archive, image_archive()?)?;
    let server = failing_api(0).await;
    for (case, settings) in [
        ("tls", &[("DOCKER_TLS", "1")][..]),
        ("tls-verify", &[("DOCKER_TLS_VERIFY", "1")][..]),
        ("cert-path", &[("DOCKER_CERT_PATH", "certs with spaces")][..]),
        ("tls-empty-verify", &[("DOCKER_TLS", "1"), ("DOCKER_TLS_VERIFY", "")][..]),
        ("empty-verify", &[("DOCKER_TLS_VERIFY", "")][..]),
    ] {
        let scan_dir = work.path().join(case);
        std::fs::create_dir_all(&scan_dir)?;
        let trace = scan_dir.join("cli-trace.txt");
        let mut command = scan_command_with_binary(&scanner, &scan_dir, &server.uri(), IMAGE);
        command
            .envs(settings.iter().copied())
            .env("PATH", &bin_dir)
            .env("KF_TEST_DOCKER_ARCHIVE", &archive)
            .env("KF_TEST_DOCKER_TRACE", &trace);
        let output = run_scan(command).await?;
        assert_completed_scan(&scan_dir, &output)?;
        assert_eq!(std::fs::read_to_string(trace)?, "inspect\nsave\n", "{case}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("Docker environment requires CLI connection configuration"),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn scan_falls_back_to_docker_cli_and_cleans_failed_cli_exports() -> Result<()> {
    let work = tempfile::tempdir()?;
    let (bin_dir, scanner) = compile_docker_cli_fixture(work.path())?;
    let archive = work.path().join("fixture.tar");
    std::fs::write(&archive, image_archive()?)?;
    let server = failing_api(2).await;
    for fail_save in [false, true] {
        let scan_dir = work.path().join(if fail_save { "failed" } else { "completed" });
        std::fs::create_dir_all(&scan_dir)?;
        let trace = scan_dir.join("cli-trace.txt");
        // Also verify a failed local export never reaches registry fallback.
        let image = if fail_save { "invalid image reference" } else { IMAGE };
        let mut command = scan_command_with_binary(&scanner, &scan_dir, &server.uri(), image);
        command
            .env("PATH", &bin_dir)
            .env("KF_TEST_DOCKER_ARCHIVE", &archive)
            .env("KF_TEST_DOCKER_TRACE", &trace)
            .env("KF_TEST_DOCKER_FAIL_SAVE", if fail_save { "1" } else { "0" });
        let output = run_scan(command).await?;
        assert_eq!(std::fs::read_to_string(trace)?, "inspect\nsave\n");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("trying CLI"));
        if fail_save {
            assert!(!output.status.success());
            assert!(stderr.contains("invalid image reference"));
            assert!(stderr.contains("failed to save local image"));
            assert!(!stderr.contains("trying OCI"));
            assert_no_staging_files(&scan_dir)?;
        } else {
            assert_completed_scan(&scan_dir, &output)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn unavailable_api_and_cli_image_absence_reach_oci_fallback() -> Result<()> {
    let work = tempfile::tempdir()?;
    let (bin_dir, scanner) = compile_docker_cli_fixture(work.path())?;
    let trace = work.path().join("cli-trace.txt");
    let server = failing_api(1).await;
    // Invalid registry syntax proves the OCI path is reached without a live registry request.
    let mut command =
        scan_command_with_binary(&scanner, work.path(), &server.uri(), "invalid image reference");
    command
        .env("PATH", bin_dir)
        .env("KF_TEST_DOCKER_TRACE", &trace)
        .env("KF_TEST_DOCKER_IMAGE_ABSENT", "1");
    let output = run_scan(command).await?;
    assert!(!output.status.success());
    assert_eq!(std::fs::read_to_string(trace)?, "inspect\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trying CLI"));
    assert!(stderr.contains("trying OCI"));
    assert!(stderr.contains("invalid image reference"));
    assert_no_staging_files(work.path())?;
    Ok(())
}

#[tokio::test]
async fn unavailable_api_and_missing_cli_report_lookup_failure() -> Result<()> {
    let work = tempfile::tempdir()?;
    let server = failing_api(1).await;
    let output =
        run_scan(scan_command(work.path(), &server.uri(), "invalid image reference")).await?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Neither lookup established absence, so preserve the lookup error.
    assert!(stderr.contains("Docker CLI lookup/export failed"));
    assert!(!stderr.contains("trying OCI"));
    assert!(stderr.contains("invalid image reference"));
    assert_no_staging_files(work.path())?;
    Ok(())
}
