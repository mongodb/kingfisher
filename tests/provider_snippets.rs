use clap::Parser;
use kingfisher::{
    bitbucket,
    cli::{
        commands::{
            github::GitHistoryMode,
            scan::{ListRepositoriesCommand, ScanOperation},
        },
        global::{Command, CommandLineArgs},
    },
    gitlab,
};
use serde_json::{Value, json};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_partial_json, header, method, path, query_param},
};

fn operation(provider: &str, extra: &[&str]) -> ScanOperation {
    let mut argv = vec!["kingfisher", "scan", provider, "--user", "alice"];
    argv.extend_from_slice(extra);
    let args = CommandLineArgs::try_parse_from(argv).unwrap();
    let Command::Scan(command) = args.command else { panic!("expected scan") };
    command.into_operation().unwrap()
}

#[test]
fn snippet_flags_reach_scans_and_listings_and_default_to_off() {
    for provider in ["gitlab", "bitbucket"] {
        for enabled in [false, true] {
            let extra = if enabled { vec!["--include-snippets"] } else { vec![] };
            let ScanOperation::Scan(args) = operation(provider, &extra) else {
                panic!("expected scan")
            };
            let inputs = args.input_specifier_args;
            assert_eq!(
                if provider == "gitlab" {
                    inputs.gitlab_include_snippets
                } else {
                    inputs.bitbucket_include_snippets
                },
                enabled
            );
            assert_eq!(inputs.git_history, GitHistoryMode::Full);
        }
        let specs = operation(provider, &["--include-snippets", "--list-only"]);
        match specs {
            ScanOperation::ListRepositories(ListRepositoriesCommand::Gitlab {
                specifiers, ..
            }) => assert!(specifiers.include_snippets),
            ScanOperation::ListRepositories(ListRepositoriesCommand::Bitbucket {
                specifiers,
                ..
            }) => assert!(specifiers.include_snippets),
            other => panic!("unexpected operation: {other:?}"),
        }
    }
}

fn gitlab_specs(enabled: bool) -> gitlab::RepoSpecifiers {
    gitlab::RepoSpecifiers {
        user: vec!["alice".into()],
        include_snippets: enabled,
        group: vec![],
        all_groups: false,
        include_subgroups: false,
        repo_filter: gitlab::RepoType::All,
        exclude_repos: vec![],
    }
}

fn bitbucket_specs(enabled: bool) -> bitbucket::RepoSpecifiers {
    bitbucket::RepoSpecifiers {
        user: vec![],
        include_snippets: enabled,
        workspace: vec!["alice".into()],
        project: vec![],
        all_workspaces: false,
        repo_filter: bitbucket::RepoType::Source,
        exclude_repos: vec![],
    }
}

fn snippets_page(urls: &[&str], next: Option<&str>) -> Value {
    json!({"data": {"snippets": {
        "nodes": urls.iter().map(|url| json!({"httpUrlToRepo": url})).collect::<Vec<_>>(),
        "pageInfo": {"hasNextPage": next.is_some(), "endCursor": next}
    }}})
}

async fn gitlab_user(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/gitlab/api/v4/users"))
        .and(query_param("username", "alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id": 7}])))
        .mount(server)
        .await;
}

async fn gitlab_projects(server: &MockServer, endpoint: &str, projects: Value) {
    Mock::given(method("GET"))
        .and(path(endpoint))
        .and(query_param("page", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(projects))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(endpoint))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(server)
        .await;
}

#[tokio::test]
async fn gitlab_enumerates_personal_and_project_snippets_with_pagination_and_exclusions() {
    let server = MockServer::start().await;
    gitlab_user(&server).await;
    gitlab_projects(
        &server,
        "/gitlab/api/v4/users/7/projects",
        json!([
            {"id": 10, "http_url_to_repo": "https://gitlab.com/alice/repo.git"},
            {"http_url_to_repo": "https://gitlab.com/alice/no-id.git"},
            {"id": 20, "http_url_to_repo": "https://gitlab.com/alice/excluded.git"}
        ]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/gitlab/api/v4/groups/team"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 9})))
        .mount(&server)
        .await;
    gitlab_projects(
        &server,
        "/gitlab/api/v4/groups/9/projects",
        json!([
            {"id": 10, "http_url_to_repo": "https://gitlab.com/alice/repo.git"},
            {"id": 30, "http_url_to_repo": "https://gitlab.com/team/subgroup/repo.git"}
        ]),
    )
    .await;
    let mut specs = gitlab_specs(false);
    specs.group.push("team".into());
    specs.include_subgroups = true;
    specs.exclude_repos.push("alice/excluded".into());
    let base = Url::parse(&format!("{}/gitlab", server.uri())).unwrap();
    let repos = gitlab::enumerate_repo_urls(&specs, base.clone(), false, None).await.unwrap();
    assert_eq!(repos.len(), 3);
    assert!(server.received_requests().await.unwrap().iter().all(|r| r.method.as_str() == "GET"));
    Mock::given(method("POST")).and(path("/gitlab/api/graphql"))
        .and(body_partial_json(json!({"variables": {"authorId": "gid://gitlab/User/7", "projectId": null, "type": "personal", "after": null}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(snippets_page(&["https://gitlab.com/snippets/1.git"], Some("next"))))
        .expect(1).mount(&server).await;
    Mock::given(method("POST")).and(path("/gitlab/api/graphql"))
        .and(body_partial_json(json!({"variables": {"authorId": "gid://gitlab/User/7", "type": "personal", "after": "next"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(snippets_page(&["https://gitlab.com/snippets/1.git", "https://gitlab.com/snippets/2.git"], None)))
        .expect(1).mount(&server).await;
    for (id, urls) in [(10, vec!["https://gitlab.com/snippets/3.git"]), (30, vec![])] {
        Mock::given(method("POST")).and(path("/gitlab/api/graphql"))
            .and(body_partial_json(json!({"variables": {"authorId": null, "projectId": format!("gid://gitlab/Project/{id}"), "type": "project"}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(snippets_page(&urls, None)))
            .expect(1).mount(&server).await;
    }
    specs.include_snippets = true;
    let urls = gitlab::enumerate_repo_urls(&specs, base, false, None).await.unwrap();
    assert_eq!(
        urls,
        vec![
            "https://gitlab.com/alice/no-id.git",
            "https://gitlab.com/alice/repo.git",
            "https://gitlab.com/snippets/1.git",
            "https://gitlab.com/snippets/2.git",
            "https://gitlab.com/snippets/3.git",
            "https://gitlab.com/team/subgroup/repo.git"
        ]
    );
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .filter(|r| r.url.path().ends_with("groups/9/projects"))
            .all(|r| r.url.query_pairs().any(|(k, v)| k == "include_subgroups" && v == "true"))
    );
}

#[tokio::test]
async fn gitlab_rejects_graphql_errors_and_broken_pagination() {
    for (response, message) in [
        (json!({"errors": [{"message": "denied"}], "data": null}), "denied"),
        (
            json!({"data": {"snippets": {"nodes": [], "pageInfo": {"hasNextPage": true, "endCursor": null}}}}),
            "missing a cursor",
        ),
        (snippets_page(&[], Some("same")), "repeated a cursor"),
    ] {
        let server = MockServer::start().await;
        gitlab_user(&server).await;
        gitlab_projects(&server, "/gitlab/api/v4/users/7/projects", json!([])).await;
        Mock::given(method("POST"))
            .and(path("/gitlab/api/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let err = gitlab::enumerate_repo_urls(
            &gitlab_specs(true),
            Url::parse(&format!("{}/gitlab/", server.uri())).unwrap(),
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(message), "{err:#}");
    }
}

#[tokio::test]
async fn gitlab_snippet_errors_identify_user_and_project_scopes() {
    for project_scope in [false, true] {
        for status in [200, 403, 429] {
            let server = MockServer::start().await;
            gitlab_user(&server).await;
            gitlab_projects(
                &server,
                "/gitlab/api/v4/users/7/projects",
                json!([{"id": 10, "http_url_to_repo": "https://gitlab.com/alice/repo.git"}]),
            )
            .await;
            if project_scope {
                Mock::given(method("POST"))
                    .and(path("/gitlab/api/graphql"))
                    .and(body_partial_json(json!({"variables": {"type": "personal"}})))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(snippets_page(&[], None)),
                    )
                    .mount(&server)
                    .await;
            }
            let snippet_type = if project_scope { "project" } else { "personal" };
            Mock::given(method("POST"))
                .and(path("/gitlab/api/graphql"))
                .and(body_partial_json(json!({"variables": {"type": snippet_type}})))
                .respond_with(ResponseTemplate::new(status).set_body_json(json!({
                    "errors": [{"message": "denied"}], "data": null
                })))
                .expect(1)
                .mount(&server)
                .await;
            let err = gitlab::enumerate_repo_urls(
                &gitlab_specs(true),
                Url::parse(&format!("{}/gitlab/", server.uri())).unwrap(),
                false,
                None,
            )
            .await
            .unwrap_err();
            let scope = if project_scope { "project 10" } else { "user 7" };
            assert!(err.to_string().contains(scope), "{err:#}");
            let detail = if status == 200 { "denied".to_string() } else { status.to_string() };
            assert!(format!("{err:#}").contains(&detail), "{err:#}");
        }
    }
}

#[tokio::test]
async fn bitbucket_project_only_does_not_request_snippets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/PROJ"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    let mut specs = bitbucket_specs(true);
    specs.workspace.clear();
    specs.project.push("PROJ".into());
    let urls = bitbucket::enumerate_repo_urls(
        &specs,
        Url::parse(&format!("{}/2.0/", server.uri())).unwrap(),
        &Default::default(),
        false,
        None,
    )
    .await
    .unwrap();
    assert!(urls.is_empty());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/2.0/repositories/PROJ");
}

fn bitbucket_snippet(url: &str) -> Value {
    json!({"links": {"clone": [{"name": "ssh", "href": "git@bitbucket.org:unused"}, {"name": "https", "href": url}]}})
}

#[tokio::test]
async fn bitbucket_enumerates_workspace_snippets_with_auth_pagination_and_deduplication() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
        .mount(&server)
        .await;
    let base = Url::parse(&format!("{}/2.0", server.uri())).unwrap();
    let auth =
        bitbucket::AuthConfig { bearer_token: Some("test-token".into()), ..Default::default() };
    assert!(
        bitbucket::enumerate_repo_urls(&bitbucket_specs(false), base.clone(), &auth, false, None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    let a = "https://bitbucket.org/snippets/alice/abc/test.git";
    let b = "https://bitbucket.org/snippets/alice/def/test.git";
    Mock::given(method("GET")).and(path("/2.0/snippets/alice"))
        .and(query_param("pagelen", "100")).and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": [bitbucket_snippet(a)], "next": format!("{}/2.0/snippets/alice?page=2", server.uri())})))
        .expect(1).mount(&server).await;
    Mock::given(method("GET"))
        .and(path("/2.0/snippets/alice"))
        .and(query_param("page", "2"))
        .and(header("authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": [
            {"links": {}},
            {"links": {"clone": [{"name": "ssh", "href": "git@bitbucket.org:unused"}]}},
            bitbucket_snippet(a), bitbucket_snippet(b)
        ]})))
        .expect(1)
        .mount(&server)
        .await;
    let mut specs = bitbucket_specs(true);
    specs.user.push("alice".into()); // Same owner should only be enumerated once.
    specs.project.push("PROJ".into()); // Project keys must not become snippet owners.
    specs.project.push("alice".into()); // An explicit workspace still selects this owner.
    specs.all_workspaces = true;
    Mock::given(method("GET"))
        .and(path("/2.0/workspaces"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"values": [{"slug": "alice"}, {"slug": "bob"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    for endpoint in ["/2.0/repositories/bob", "/2.0/snippets/bob"] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/PROJ"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2.0/snippets/PROJ"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0)
        .mount(&server)
        .await;
    specs.repo_filter = bitbucket::RepoType::Fork; // Does not filter snippets.
    let urls = bitbucket::enumerate_repo_urls(&specs, base, &auth, false, None).await.unwrap();
    assert_eq!(urls, vec![a, b]);
}

#[tokio::test]
async fn bitbucket_snippets_reject_server_and_report_api_errors() {
    let server = MockServer::start().await;
    let err = bitbucket::enumerate_repo_urls(
        &bitbucket_specs(true),
        Url::parse(&format!("{}/rest/api/1.0/", server.uri())).unwrap(),
        &Default::default(),
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("only for Bitbucket Cloud"));
    assert!(server.received_requests().await.unwrap().is_empty());
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/2.0/snippets/alice"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let err = bitbucket::enumerate_repo_urls(
        &bitbucket_specs(true),
        Url::parse(&format!("{}/2.0/", server.uri())).unwrap(),
        &Default::default(),
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("403"));
}

#[tokio::test]
async fn bitbucket_rejects_cross_origin_and_repeated_pagination_links() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/2.0/repositories/alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
        .mount(&server)
        .await;
    for (next, message) in [
        ("https://example.invalid/snippets".to_string(), "different origin"),
        (format!("{}/2.0/snippets/alice?pagelen=100", server.uri()), "repeated a page"),
    ] {
        let mock = Mock::given(method("GET"))
            .and(path("/2.0/snippets/alice"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"values": [], "next": next})),
            )
            .expect(1)
            .mount_as_scoped(&server)
            .await;
        let err = bitbucket::enumerate_repo_urls(
            &bitbucket_specs(true),
            Url::parse(&format!("{}/2.0/", server.uri())).unwrap(),
            &Default::default(),
            false,
            None,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(message), "{err:#}");
        drop(mock);
    }
}

async fn scan_deleted_secret(provider: &str) -> anyhow::Result<()> {
    use assert_cmd::prelude::*;
    use git2::{Repository, Signature};
    use predicates::str::contains;
    use std::{fs, path::Path, process::Command};

    let temp = tempfile::tempdir()?;
    let repo_dir = temp.path().join("snippet");
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@example.com")?;
    let secret = "test_snippet_deleted_secret";
    fs::write(repo_dir.join("secret.txt"), secret)?;
    let mut index = repo.index()?;
    index.add_path(Path::new("secret.txt"))?;
    let tree = repo.find_tree(index.write_tree()?)?;
    let first = repo.commit(Some("HEAD"), &sig, &sig, "add secret", &tree, &[])?;
    fs::remove_file(repo_dir.join("secret.txt"))?;
    index.remove_path(Path::new("secret.txt"))?;
    let tree = repo.find_tree(index.write_tree()?)?;
    repo.commit(Some("HEAD"), &sig, &sig, "remove secret", &tree, &[&repo.find_commit(first)?])?;
    let rules = temp.path().join("rules.yml");
    fs::write(
        &rules,
        "rules:\n  - name: Snippet history test\n    id: custom.snippet.history\n    pattern: '(test_snippet_deleted_secret)'\n    min_entropy: 0\n    confidence: high\n",
    )?;
    let server = MockServer::start().await;
    let (api_url, clone_url) = if provider == "gitlab" {
        gitlab_user(&server).await;
        gitlab_projects(&server, "/gitlab/api/v4/users/7/projects", json!([])).await;
        let clone_url = "https://gitlab.com/snippets/508.git";
        Mock::given(method("POST"))
            .and(path("/gitlab/api/graphql"))
            .and(header("authorization", "Bearer snippet-test-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(snippets_page(&[clone_url], None)),
            )
            .mount(&server)
            .await;
        (format!("{}/gitlab/", server.uri()), clone_url)
    } else {
        Mock::given(method("GET"))
            .and(path("/2.0/repositories/alice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"values": []})))
            .mount(&server)
            .await;
        let clone_url = "https://bitbucket.org/snippets/alice/508/history.git";
        Mock::given(method("GET"))
            .and(path("/2.0/snippets/alice"))
            .and(header("authorization", "Bearer snippet-test-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"values": [bitbucket_snippet(clone_url)]})),
            )
            .mount(&server)
            .await;
        (format!("{}/2.0/", server.uri()), clone_url)
    };
    let make_command = || {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .args(["scan", provider, "--user", "alice", "--api-url", &api_url, "--no-update-check"])
            .env("KF_GITLAB_TOKEN", "snippet-test-token")
            .env("KF_BITBUCKET_OAUTH_TOKEN", "snippet-test-token")
            .env_remove("KF_BITBUCKET_TOKEN")
            .env_remove("KF_BITBUCKET_APP_PASSWORD")
            .env_remove("KF_BITBUCKET_USERNAME")
            .env_remove("KF_BITBUCKET_PASSWORD");
        command
    };
    make_command()
        .args(["--include-snippets", "--list-only"])
        .assert()
        .success()
        .stdout(format!("{clone_url}\n"));
    let rewrite = format!("url.{}.insteadOf", Url::from_directory_path(&repo_dir).unwrap());
    // Bitbucket's clone layer embeds its configured OAuth credentials in the URL.
    let clone_argument = if provider == "bitbucket" {
        clone_url.replace("https://", "https://x-token-auth:snippet-test-token@")
    } else {
        clone_url.to_string()
    };
    for (enabled, code) in [(true, 200), (false, 1)] {
        let mut command = make_command();
        command
            .args(["--no-validate", "--load-builtins=false", "--rules-path"])
            .arg(&rules)
            .args(["--format", "json", "--jobs", "2"])
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", &rewrite)
            .env("GIT_CONFIG_VALUE_0", &clone_argument);
        if enabled {
            command.arg("--include-snippets");
        }
        let assertion = command.assert().code(code);
        if enabled {
            assertion.stdout(contains(secret));
        } else {
            assertion.stderr(contains("No inputs to scan"));
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gitlab_snippet_clone_finds_deleted_secret() -> anyhow::Result<()> {
    scan_deleted_secret("gitlab").await
}

#[tokio::test(flavor = "multi_thread")]
async fn bitbucket_snippet_clone_finds_deleted_secret() -> anyhow::Result<()> {
    scan_deleted_secret("bitbucket").await
}
