// Avoid "update" in the test binary name: Windows may otherwise require elevation.
use kingfisher::{cli::global::GlobalArgs, update::check_for_update};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

#[tokio::test]
async fn no_update_when_flag_set() {
    let args = GlobalArgs { no_update_check: true, ..Default::default() };
    let status = check_for_update(&args, None);
    assert_eq!(status.check_status.as_str(), "disabled");
    assert!(status.latest_version.is_none());
}

#[tokio::test]
async fn public_updater_rejects_http_even_for_loopback_api_overrides() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    for self_update in [false, true] {
        let uri = server.uri();
        let status = tokio::task::spawn_blocking(move || {
            let args = GlobalArgs { self_update, ..Default::default() };
            check_for_update(&args, Some(&uri))
        })
        .await
        .expect("blocking task panicked");
        assert_eq!(status.check_status.as_str(), "failed");
        assert!(status.latest_version.is_none());
        assert!(!status.is_outdated);
        assert!(!status.was_self_updated);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}
