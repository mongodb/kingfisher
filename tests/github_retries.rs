use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use kingfisher::{
    findings_store::FindingsStore,
    git_url::GitUrl,
    github::{
        RepoSpecifiers, RepoType, enumerate_contributor_repo_urls, enumerate_public_event_targets,
        enumerate_repo_urls_streaming, fetch_repo_items,
    },
};
use serde_json::{Value, json};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

async fn page(server: &MockServer, endpoint: &str, number: &str, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v3/{endpoint}")))
        .and(query_param("page", number))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(1)
        .with_priority(2)
        .mount(server)
        .await;
}

async fn transient(server: &MockServer, endpoint: &str, number: &str, status: u16) {
    Mock::given(method("GET"))
        .and(path(format!("/api/v3/{endpoint}")))
        .and(query_param("page", number))
        .respond_with(ResponseTemplate::new(status).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(server)
        .await;
}

fn api_base(server: &MockServer) -> Url {
    Url::parse(&format!("{}/api/v3/", server.uri())).unwrap()
}

#[tokio::test]
async fn discovery_retries_pages_without_duplicate_streamed_repositories() {
    let server = MockServer::start().await;
    page(
        &server,
        "users/alice/repos",
        "1",
        json!([
            {"clone_url": "https://github.com/alice/first.git", "fork": false}
        ]),
    )
    .await;
    transient(&server, "users/alice/repos", "2", 500).await;
    page(
        &server,
        "users/alice/repos",
        "2",
        json!([
            {"clone_url": "https://github.com/alice/second.git", "fork": false}
        ]),
    )
    .await;
    page(&server, "users/alice/repos", "3", json!([])).await;
    transient(&server, "orgs/acme/repos", "1", 429).await;
    page(
        &server,
        "orgs/acme/repos",
        "1",
        json!([
            {"clone_url": "https://github.com/acme/repo.git", "fork": false}
        ]),
    )
    .await;
    page(&server, "orgs/acme/repos", "2", json!([])).await;
    for (endpoint, response) in [
        ("organizations", json!([{"login": "acme"}])),
        ("users/alice/gists", json!([{"git_pull_url": "https://gist.github.com/abc.git"}])),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/{endpoint}")))
            .respond_with(ResponseTemplate::new(403).insert_header("retry-after", "0"))
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/{endpoint}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .with_priority(2)
            .mount(&server)
            .await;
    }

    let specifiers = RepoSpecifiers {
        user: vec!["alice".into()],
        organization: vec![],
        all_organizations: true,
        include_gists: true,
        repo_filter: RepoType::Source,
        exclude_repos: vec![],
    };
    let mut streamed = Vec::new();
    let urls =
        enumerate_repo_urls_streaming(&specifiers, api_base(&server), false, None, &mut |url| {
            streamed.push(url.to_owned());
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        streamed,
        [
            "https://github.com/alice/first.git",
            "https://github.com/alice/second.git",
            "https://gist.github.com/abc.git",
            "https://github.com/acme/repo.git",
        ]
    );
    streamed.sort();
    assert_eq!(urls, streamed);
}

#[tokio::test]
async fn contributor_discovery_recovers_from_rate_limits() {
    let server = MockServer::start().await;
    transient(&server, "repos/acme/repo/contributors", "1", 403).await;
    page(&server, "repos/acme/repo/contributors", "1", json!([{"login": "alice"}])).await;
    page(&server, "repos/acme/repo/contributors", "2", json!([])).await;
    transient(&server, "users/alice/repos", "1", 429).await;
    page(
        &server,
        "users/alice/repos",
        "1",
        json!([
            {"clone_url": "https://github.com/alice/repo.git", "fork": false}
        ]),
    )
    .await;
    page(&server, "users/alice/repos", "2", json!([])).await;
    let repos = enumerate_contributor_repo_urls(
        &GitUrl::from_str("https://github.com/acme/repo.git").unwrap(),
        &api_base(&server),
        false,
        &[],
        None,
        false,
        RepoType::Source,
    )
    .await
    .unwrap();
    assert_eq!(repos, ["https://github.com/alice/repo.git"]);
}

#[tokio::test]
async fn event_discovery_recovers_from_server_errors() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v3/users/alice/events/public"))
        .respond_with(ResponseTemplate::new(503).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/users/alice/events/public"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{
            "type": "CreateEvent",
            "repo": {"name": "alice/repo"},
            "payload": {"ref_type": "repository"},
            "created_at": chrono::Utc::now().to_rfc3339()
        }])))
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    let targets = enumerate_public_event_targets(
        &["alice".into()],
        24,
        api_base(&server),
        false,
        &[],
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(targets.len(), 1);
    assert!(matches!(targets[0].selector, kingfisher::github::GitHubEventScanSelector::Repository));
}

#[tokio::test]
async fn repository_artifacts_retry_issue_pages_and_gist_details() {
    let server = MockServer::start().await;
    transient(&server, "repos/acme/repo/issues", "1", 502).await;
    page(
        &server,
        "repos/acme/repo/issues",
        "1",
        json!([
            {"number": 1, "title": "Recovered issue", "body": "issue content"}
        ]),
    )
    .await;
    page(&server, "repos/acme/repo/issues", "2", json!([])).await;
    transient(&server, "users/acme/gists", "1", 500).await;
    page(&server, "users/acme/gists", "1", json!([{"id": "abc"}])).await;
    page(&server, "users/acme/gists", "2", json!([])).await;
    Mock::given(method("GET"))
        .and(path("/api/v3/gists/abc"))
        .respond_with(ResponseTemplate::new(504).insert_header("retry-after", "0"))
        .up_to_n_times(1)
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/gists/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "files": {"secret.txt": {"content": "gist content"}}
        })))
        .expect(1)
        .with_priority(2)
        .mount(&server)
        .await;
    // This optional endpoint is used when the environment supplies a fixed token.
    Mock::given(method("GET"))
        .and(path("/api/v3/gists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let temp = tempfile::tempdir().unwrap();
    let datastore = Arc::new(Mutex::new(FindingsStore::new(temp.path().to_path_buf())));
    let dirs = fetch_repo_items(
        &GitUrl::from_str("https://github.com/acme/repo.git").unwrap(),
        &api_base(&server),
        false,
        temp.path(),
        &datastore,
    )
    .await
    .unwrap();
    assert_eq!(dirs.len(), 2);
    assert_eq!(
        std::fs::read_to_string(
            temp.path().join("github_issues").join("acme").join("repo").join("issue_1.md")
        )
        .unwrap(),
        "# Recovered issue\n\nissue content"
    );
    assert_eq!(
        std::fs::read_to_string(
            temp.path().join("github_gists").join("acme").join("abc").join("secret.txt")
        )
        .unwrap(),
        "gist content"
    );
}

fn list_repositories_command(server: &MockServer) -> assert_cmd::Command {
    let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .args([
            "scan",
            "github",
            "--user",
            "alice",
            "--api-url",
            &format!("{}/api/v3/", server.uri()),
            "--list-only",
            "--no-update-check",
        ])
        .env("KF_GITHUB_TOKEN", "retry-test-token")
        .env_remove("KF_GITHUB_APP_ID")
        .env_remove("KF_GITHUB_APP_INSTALLATION_ID")
        .env_remove("KF_GITHUB_APP_PRIVATE_KEY")
        .env_remove("KF_GITHUB_APP_PRIVATE_KEY_PATH")
        .timeout(std::time::Duration::from_secs(30));
    command
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_retry_wait_budget_controls_whether_discovery_resumes() {
    for (budget, resumes) in [("0", false), ("1", true)] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v3/users/alice/repos"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("retry-after", "1")
                    .set_body_json(json!({"message": "API rate limit exceeded"})),
            )
            .up_to_n_times(1)
            .expect(1)
            .with_priority(1)
            .mount(&server)
            .await;
        if resumes {
            page(
                &server,
                "users/alice/repos",
                "1",
                json!([{"clone_url": "https://github.com/alice/recovered.git", "fork": false}]),
            )
            .await;
            page(&server, "users/alice/repos", "2", json!([])).await;
        }

        let mut command = list_repositories_command(&server);
        command.env("KF_GITHUB_MAX_RETRY_WAIT_SECS", budget);
        if resumes {
            command.assert().success().stdout("https://github.com/alice/recovered.git\n");
        } else {
            command
                .assert()
                .failure()
                .stdout("")
                .stderr(predicates::str::contains("listing user repositories: HTTP 403"));
        }
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), if resumes { 3 } else { 1 });
        for request in requests {
            assert_eq!(request.headers["authorization"], "Bearer retry-test-token");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reports_invalid_retry_wait_budget_before_requesting_repositories() {
    for budget in ["invalid", "-1", "18446744073709551616"] {
        let server = MockServer::start().await;
        list_repositories_command(&server)
            .env("KF_GITHUB_MAX_RETRY_WAIT_SECS", budget)
            .assert()
            .failure()
            .stderr(predicates::str::contains("KF_GITHUB_MAX_RETRY_WAIT_SECS"));
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
