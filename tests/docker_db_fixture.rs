//! Offline contract tests for the opt-in live database fixtures. No Docker required.

#[path = "support/docker_db.rs"]
#[allow(dead_code)] // Platform-specific socket discovery is exercised by opt-in live tests.
mod docker_db;

use std::time::Duration;

use anyhow::Result;
use docker_db::{Connection, DatabaseContainer, MYSQL, Options, POSTGRES, connect};
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, method, path_regex, query_param},
};

fn client(server: &MockServer) -> Connection {
    Connection { host: server.uri(), tls_verify: false, cert_dir: None }
}

fn frame(stream: u8, data: &[u8]) -> Vec<u8> {
    let mut bytes = vec![stream, 0, 0, 0];
    bytes.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(data);
    bytes
}

fn ready_logs(marker: &str) -> Vec<u8> {
    // The first occurrence is split across frames; the second is on stderr.
    let split = marker.len() / 2;
    [
        frame(1, &marker.as_bytes()[..split]),
        frame(1, &marker.as_bytes()[split..]),
        frame(2, format!("\n{marker}\n").as_bytes()),
    ]
    .concat()
}

async fn mock_lifecycle(server: &MockServer, marker: &str, port: u16, removals: u64) {
    Mock::given(method("POST"))
        .and(path_regex(r"/containers/create$"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"Id": "db", "Warnings": []})))
        .with_priority(10)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/containers/db/start$"))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(10)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/containers/db/logs$"))
        .and(query_param("stdout", "true"))
        .and(query_param("stderr", "true"))
        .and(query_param("follow", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(ready_logs(marker)))
        .with_priority(10)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"/containers/db/json$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "NetworkSettings": {"Ports": {format!("{port}/tcp"): [
                {"HostIp": "::", "HostPort": "4567"},
                {"HostIp": "0.0.0.0", "HostPort": "1234"}
            ]}}
        })))
        .with_priority(10)
        .mount(server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"/containers/db$"))
        .and(query_param("force", "true"))
        .and(query_param("v", "true"))
        .respond_with(ResponseTemplate::new(204))
        .expect(removals)
        .with_priority(10)
        .mount(server)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserves_database_images_environment_readiness_and_ipv4_mapping() -> Result<()> {
    for image in [MYSQL, POSTGRES] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, image.ready_message, image.port, 1).await;
        Mock::given(method("POST"))
            .and(path_regex(r"/containers/create$"))
            .and(body_partial_json(json!({
                "Image": image.image,
                "Env": image.environment,
                "ExposedPorts": {format!("{}/tcp", image.port): {}},
                "HostConfig": {"PublishAllPorts": true}
            })))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(json!({"Id": "db", "Warnings": []})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let container =
            DatabaseContainer::start_with(client(&server), image, Options::default()).await?;
        assert_eq!(container.port, 1234);
        container.remove().await?;
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pulls_only_missing_images_and_preserves_platform_and_registry_auth() -> Result<()> {
    let server = MockServer::start().await;
    mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
    Mock::given(method("POST"))
        .and(path_regex(r"/containers/create$"))
        .and(query_param("platform", "linux/arm64"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"message": "No such image"})))
        .up_to_n_times(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(r"/images/create$"))
        .and(query_param("fromImage", "mysql:8.4"))
        .and(query_param("platform", "linux/arm64"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"status\":\"Downloaded\"}\n"))
        .expect(1)
        .mount(&server)
        .await;
    let options = Options {
        platform: Some("linux/arm64".into()),
        credentials: Some(bollard::auth::DockerCredentials {
            username: Some("fixture-user".into()),
            password: Some("fixture-password".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    DatabaseContainer::start_with(client(&server), MYSQL, options).await?.remove().await?;
    let requests = server.received_requests().await.unwrap();
    let pull =
        requests.iter().find(|request| request.url.path().ends_with("/images/create")).unwrap();
    use base64::Engine;
    let credentials: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(pull.headers["x-registry-auth"].as_bytes())?,
    )?;
    assert_eq!(credentials["username"], "fixture-user");
    assert_eq!(credentials["password"], "fixture-password");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_failures_and_incomplete_readiness_remove_the_container() -> Result<()> {
    for (failure, body) in [(true, vec![]), (false, frame(1, MYSQL.ready_message.as_bytes()))] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
        if failure {
            Mock::given(method("POST"))
                .and(path_regex(r"/containers/db/start$"))
                .respond_with(
                    ResponseTemplate::new(500).set_body_json(json!({"message": "cannot start"})),
                )
                .mount(&server)
                .await;
        } else {
            Mock::given(method("GET"))
                .and(path_regex(r"/containers/db/logs$"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                .mount(&server)
                .await;
        }
        let error = DatabaseContainer::start_with(client(&server), MYSQL, Options::default())
            .await
            .err()
            .expect("startup must fail");
        assert!(
            format!("{error:#}").contains(if failure { "cannot start" } else { "ready" }),
            "{error:#}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_deadline_and_bad_port_mapping_remove_the_container() -> Result<()> {
    for delayed in [true, false] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
        if delayed {
            Mock::given(method("GET"))
                .and(path_regex(r"/containers/db/logs$"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_bytes(ready_logs(MYSQL.ready_message))
                        .set_delay(Duration::from_millis(200)),
                )
                .mount(&server)
                .await;
        } else {
            Mock::given(method("GET"))
                .and(path_regex(r"/containers/db/json$"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({"NetworkSettings": {"Ports": {}}})),
                )
                .mount(&server)
                .await;
        }
        let options = Options {
            startup_timeout: if delayed {
                Duration::from_millis(50)
            } else {
                Duration::from_secs(5)
            },
            ..Default::default()
        };
        let error = DatabaseContainer::start_with(client(&server), MYSQL, options)
            .await
            .err()
            .expect("startup must fail");
        assert!(
            error.to_string().contains(if delayed { "timed out" } else { "IPv4" }),
            "{error:#}"
        );
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_cleans_up_during_unwinding_and_after_the_original_runtime_stops() -> Result<()> {
    for panic in [false, true] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
        let docker = client(&server);
        let container = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(DatabaseContainer::start_with(docker, MYSQL, Options::default()))
                .unwrap()
        })
        .join()
        .unwrap();
        let outcome = tokio::task::spawn_blocking(move || {
            if panic {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _container = container;
                    panic!("exercise database fixture cleanup");
                }))
                .is_err()
            } else {
                drop(container);
                false
            }
        })
        .await?;
        assert_eq!(outcome, panic);
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drop_cleans_up_while_current_thread_runtime_is_blocked() -> Result<()> {
    for panic in [false, true] {
        // Keep the mock daemon independent of the client's current-thread runtime.
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
        let connection = client(&server);
        tokio::task::spawn_blocking(move || {
            let runtime =
                tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let container =
                    DatabaseContainer::start_with(connection, MYSQL, Options::default())
                        .await
                        .unwrap();
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _container = container;
                    if panic {
                        panic!("exercise cleanup inside current-thread runtime");
                    }
                }));
                assert_eq!(outcome.is_err(), panic);
            });
        })
        .await?;
        // A timeout swallowed by Drop is not success: DELETE must reach the daemon.
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_mode_preserves_containers_on_explicit_removal_and_drop() -> Result<()> {
    for explicit in [false, true] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 0).await;
        let options = Options { keep: true, ..Default::default() };
        let container = DatabaseContainer::start_with(client(&server), MYSQL, options).await?;
        if explicit {
            container.remove().await?;
        } else {
            drop(container);
        }
        server.verify().await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_helpers_run_only_when_pulling_missing_images() -> Result<()> {
    const CHILD: &str = "KINGFISHER_DOCKER_HELPER_MARKER";
    // A subprocess isolates Docker configuration without mutating a live test runtime's environment.
    if std::env::var_os(CHILD).is_some() {
        DatabaseContainer::start(MYSQL).await?.remove().await?;
        return Ok(());
    }
    let work = tempfile::tempdir()?;
    let binary = work
        .path()
        .join(format!("docker-credential-kingfisher-fixture{}", std::env::consts::EXE_SUFFIX));
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/docker_credential_stub.rs");
    let compiler = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let mut command = std::process::Command::new(compiler);
    command.args(["--edition=2024", "--target", env!("KINGFISHER_BUILD_TARGET")]);
    // Match the existing portable Docker CLI stub's target, linker and Windows CRT setup.
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
    let marker = work.path().join("helper called");
    let mut paths = vec![work.path().to_path_buf()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()));
    let search_path = std::env::join_paths(paths)?;
    for missing in [false, true] {
        let server = MockServer::start().await;
        mock_lifecycle(&server, MYSQL.ready_message, MYSQL.port, 1).await;
        if missing {
            Mock::given(method("POST"))
                .and(path_regex(r"/containers/create$"))
                .respond_with(
                    ResponseTemplate::new(404).set_body_json(json!({"message": "No such image"})),
                )
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path_regex(r"/images/create$"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_string("{\"status\":\"Downloaded\"}\n"),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let output = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "credential_helpers_run_only_when_pulling_missing_images",
                "--nocapture",
            ])
            .env(CHILD, &marker)
            .env("PATH", &search_path)
            .env("DOCKER_HOST", server.uri())
            .env(
                "DOCKER_AUTH_CONFIG",
                r#"{"credHelpers":{"https://index.docker.io/v1/":"kingfisher-fixture"}}"#,
            )
            .env("TESTCONTAINERS_COMMAND", "remove")
            .env_remove("DOCKER_TLS_VERIFY")
            .env_remove("DOCKER_CERT_PATH")
            .env_remove("DOCKER_DEFAULT_PLATFORM")
            .output()
            .await?;
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(marker.exists(), missing, "cached images must not invoke credential helpers");
        if missing {
            use base64::Engine;
            let requests = server.received_requests().await.unwrap();
            let pull = requests
                .iter()
                .find(|request| request.url.path().ends_with("/images/create"))
                .unwrap();
            let credentials: serde_json::Value = serde_json::from_slice(
                &base64::engine::general_purpose::STANDARD
                    .decode(pull.headers["x-registry-auth"].as_bytes())?,
            )?;
            assert_eq!(credentials["username"], "fixture-user");
            assert_eq!(credentials["password"], "fixture-password");
        }
        server.verify().await;
    }
    Ok(())
}

#[test]
fn tls_verify_matches_docker_cli_nonempty_semantics() {
    use std::ffi::OsStr;

    assert!(!docker_db::tls_verify_enabled(None));
    assert!(!docker_db::tls_verify_enabled(Some(OsStr::new(""))));
    for value in ["1", "0", "true", "false", " "] {
        assert!(docker_db::tls_verify_enabled(Some(OsStr::new(value))), "{value:?}");
    }
}

#[test]
fn tls_configuration_never_downgrades_to_plain_http() {
    for host in ["https://127.0.0.1:2376", "tcp://127.0.0.1:2376", "http://127.0.0.1:2376"] {
        let error = connect(host, true, None).unwrap_err();
        assert!(error.to_string().contains("DOCKER_CERT_PATH"), "{error:#}");
    }
    assert!(connect("ssh://example.invalid", false, None).is_err());
}
