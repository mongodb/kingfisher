//! Offline release-check fixtures use a test-only loopback transport. The public
//! updater remains HTTPS-only, including when its API endpoint is overridden.

use super::{UpdateStatus, check_for_update_with, release::Updater};
use crate::cli::global::GlobalArgs;
use sha2::{Digest, Sha256};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

async fn check_against(server: &MockServer, args: GlobalArgs) -> UpdateStatus {
    let uri = server.uri();
    tokio::task::spawn_blocking(move || {
        check_for_update_with(&args, || Updater::for_mock_server(&uri))
    })
    .await
    .expect("blocking task panicked")
}

fn release_body(version: &str) -> serde_json::Value {
    serde_json::json!({
        "tag_name": format!("v{version}"),
        "created_at": "2025-01-01T00:00:00Z",
        "name": format!("Kingfisher {version}"),
        "body": "",
        "assets": []
    })
}

#[tokio::test]
async fn detects_new_release() {
    let server = MockServer::start().await;
    let body = serde_json::json!({
        "tag_name": "v99.999.0",
        "created_at": "2025-01-01T00:00:00Z",
        "name": "Kingfisher 99.999.0",
        "body": "",
        "assets": [{"url": "https://example.com/bin", "name": "bin"}]
    });
    Mock::given(method("GET"))
        .and(path("/repos/mongodb/kingfisher/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .expect(1)
        .mount(&server)
        .await;
    let status = check_against(&server, GlobalArgs::default()).await;
    assert!(status.is_outdated);
    assert!(
        status
            .message
            .as_deref()
            .expect("update check should return a message")
            .contains("99.999.0")
    );
    // Detection alone (without --self-update) must never flip the re-exec signal.
    assert!(!status.was_self_updated);
}

#[tokio::test]
async fn disabled_check_never_requests_or_updates() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let args = GlobalArgs { no_update_check: true, self_update: true, ..Default::default() };
    let status = check_against(&server, args).await;
    assert_eq!(status.check_status.as_str(), "disabled");
    assert!(!status.is_outdated);
    assert!(!status.was_self_updated);
}

#[tokio::test]
async fn current_release_does_not_download_or_replace() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/mongodb/kingfisher/releases/latest"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(release_body(env!("CARGO_PKG_VERSION"))),
        )
        .expect(1)
        .mount(&server)
        .await;
    let status =
        check_against(&server, GlobalArgs { self_update: true, ..Default::default() }).await;
    assert_eq!(status.check_status.as_str(), "ok");
    assert_eq!(status.latest_version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    assert!(!status.is_outdated);
    assert!(!status.was_self_updated);
}

#[tokio::test]
async fn older_release_never_downgrades() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/mongodb/kingfisher/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(release_body("0.0.1")))
        .expect(1)
        .mount(&server)
        .await;
    let status =
        check_against(&server, GlobalArgs { self_update: true, ..Default::default() }).await;
    assert_eq!(status.check_status.as_str(), "ok");
    assert_eq!(status.latest_version.as_deref(), Some("0.0.1"));
    assert!(!status.is_outdated);
    assert!(!status.was_self_updated);
}

#[tokio::test]
async fn invalid_release_responses_fail_without_updating() {
    for response in [
        ResponseTemplate::new(403),
        ResponseTemplate::new(500),
        ResponseTemplate::new(200).set_body_string("not json"),
        ResponseTemplate::new(200).set_body_json(serde_json::json!({})),
        ResponseTemplate::new(200).set_body_json(release_body("not-a-version")),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/mongodb/kingfisher/releases/latest"))
            .respond_with(response)
            .mount(&server)
            .await;
        let status =
            check_against(&server, GlobalArgs { self_update: true, ..Default::default() }).await;
        assert_eq!(status.check_status.as_str(), "failed");
        assert!(status.latest_version.is_none());
        assert!(!status.was_self_updated);
    }
}

/// Download, digest, and archive failures must never trigger the re-exec path. Use
/// real platform asset names and require a download so asset selection cannot satisfy
/// this regression without exercising the failing installation step. The archive case
/// publishes the matching digest so it reaches extraction rather than stopping at the
/// digest check.
#[tokio::test]
async fn self_update_failure_does_not_set_reexec_flag() {
    let not_an_archive = b"not an archive".as_slice();
    let matching_digest = format!("sha256:{}", hex::encode(Sha256::digest(not_an_archive)));
    for (response, digest) in [
        (ResponseTemplate::new(500), Some(matching_digest.clone())),
        (ResponseTemplate::new(200).set_body_bytes(not_an_archive), None),
        (ResponseTemplate::new(200).set_body_bytes(not_an_archive), Some(matching_digest.clone())),
    ] {
        let server = MockServer::start().await;
        let assets = [
            "kingfisher-linux-x64.tgz",
            "kingfisher-linux-arm64.tgz",
            "kingfisher-darwin-x64.tgz",
            "kingfisher-darwin-arm64.tgz",
            "kingfisher-windows-x64.zip",
            "kingfisher-windows-arm64.zip",
        ]
        .map(|name| {
            serde_json::json!({
                "url": format!("{}/download", server.uri()),
                "name": name,
                "digest": digest,
            })
        });
        let mut body = release_body("99.999.0");
        body["assets"] = serde_json::json!(assets);
        Mock::given(method("GET"))
            .and(path("/repos/mongodb/kingfisher/releases/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/download"))
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;

        let status =
            check_against(&server, GlobalArgs { self_update: true, ..Default::default() }).await;
        assert!(status.is_outdated);
        assert!(!status.was_self_updated, "failed installation must not trigger re-execution");
    }
}
