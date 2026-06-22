use kingfisher::{cli::global::GlobalArgs, update::check_for_update};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn no_update_when_flag_set() {
    let args = GlobalArgs { no_update_check: true, ..Default::default() };
    let status = check_for_update(&args, None);
    assert_eq!(status.check_status.as_str(), "disabled");
    assert!(status.latest_version.is_none());
}

#[tokio::test]
async fn detects_new_release() {
    let server = MockServer::start().await;

    let body = serde_json::json!({
        "tag_name": "v99.999.0",
        "created_at": "2025-01-01T00:00:00Z",
        "name": "Kingfisher 99.999.0",
        "body": "",
        "assets": [{"url": "http://example.com/bin", "name": "bin"}]
    });

    // Stub HEAD *and* GET
    for m in ["HEAD", "GET"] {
        Mock::given(method(m))
            .and(path("/repos/mongodb/kingfisher/releases/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;
    }

    // run the update checker on a blocking thread
    let status = tokio::task::spawn_blocking({
        let uri = server.uri(); // move into closure
        let args = GlobalArgs::default();
        move || check_for_update(&args, Some(&uri))
    })
    .await
    .expect("blocking task panicked");

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

/// When --self-update is requested but the actual download/replace step fails (which
/// is what happens with the wiremock since `http://example.com/bin` won't deliver a
/// real archive), `was_self_updated` MUST stay false. This is the guardrail that the
/// re-exec path is never triggered on a failed update.
#[tokio::test]
async fn self_update_failure_does_not_set_reexec_flag() {
    let server = MockServer::start().await;

    let body = serde_json::json!({
        "tag_name": "v99.999.0",
        "created_at": "2025-01-01T00:00:00Z",
        "name": "Kingfisher 99.999.0",
        "body": "",
        "assets": [{"url": "http://example.com/bin", "name": "bin"}]
    });

    for m in ["HEAD", "GET"] {
        Mock::given(method(m))
            .and(path("/repos/mongodb/kingfisher/releases/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&server)
            .await;
    }

    let status = tokio::task::spawn_blocking({
        let uri = server.uri();
        let args = GlobalArgs { self_update: true, ..Default::default() };
        move || check_for_update(&args, Some(&uri))
    })
    .await
    .expect("blocking task panicked");

    assert!(status.is_outdated);
    assert!(
        !status.was_self_updated,
        "self-update download failed against the mock; was_self_updated must remain false"
    );
}
