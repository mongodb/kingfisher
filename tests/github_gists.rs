use clap::Parser;
use kingfisher::{
    cli::{
        commands::{
            github::GitHistoryMode,
            scan::{ListRepositoriesCommand, ScanOperation},
        },
        global::{Command, CommandLineArgs},
    },
    github::{RepoSpecifiers, RepoType, enumerate_repo_urls},
};
use serde_json::json;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

fn operation(extra: &[&str]) -> ScanOperation {
    let mut argv = vec!["kingfisher", "scan", "github", "--user", "alice"];
    argv.extend_from_slice(extra);
    let args = CommandLineArgs::try_parse_from(argv).unwrap();
    let Command::Scan(command) = args.command else { panic!("expected scan command") };
    command.into_operation().unwrap()
}

#[test]
fn gist_flag_reaches_scan_and_listing() {
    let ScanOperation::Scan(args) = operation(&["--include-gists"]) else {
        panic!("expected scan")
    };
    assert!(args.input_specifier_args.github_include_gists);
    assert_eq!(args.input_specifier_args.git_history, GitHistoryMode::Full);
    let ScanOperation::Scan(args) = operation(&[]) else { panic!("expected scan") };
    assert!(!args.input_specifier_args.github_include_gists);
    let ScanOperation::ListRepositories(ListRepositoriesCommand::Github { specifiers, .. }) =
        operation(&["--include-gists", "--list-only"])
    else {
        panic!("expected listing")
    };
    assert!(specifiers.include_gists);
}

#[test]
fn gist_flag_requires_users_and_rejects_public_events() {
    for extra in [vec!["--org", "acme"], vec!["--user", "alice", "--public-events"]] {
        let mut argv = vec!["kingfisher", "scan", "github", "--include-gists"];
        argv.extend(extra);
        assert!(CommandLineArgs::try_parse_from(argv).is_err());
    }
}

fn specifiers(include_gists: bool) -> RepoSpecifiers {
    RepoSpecifiers {
        user: vec!["alice".into(), "bob".into()],
        include_gists,
        organization: vec![],
        all_organizations: false,
        repo_filter: RepoType::Source,
        exclude_repos: vec![],
    }
}

async fn mock_repos(server: &MockServer) {
    for user in ["alice", "bob"] {
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/users/{user}/repos")))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"clone_url": format!("https://github.com/{user}/repo.git"), "fork": false}
            ])))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api/v3/users/{user}/repos")))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(server)
            .await;
    }
}

#[tokio::test]
async fn gists_are_opt_in_paginated_and_deduplicated() {
    let server = MockServer::start().await;
    mock_repos(&server).await;
    let base = Url::parse(&format!("{}/api/v3", server.uri())).unwrap();
    let repos = enumerate_repo_urls(&specifiers(false), base.clone(), false, None).await.unwrap();
    assert_eq!(repos, vec!["https://github.com/alice/repo.git", "https://github.com/bob/repo.git"]);
    assert!(
        server.received_requests().await.unwrap().iter().all(|r| !r.url.path().ends_with("/gists"))
    );

    Mock::given(method("GET"))
        .and(path("/api/v3/users/alice/gists"))
        .and(query_param("per_page", "100"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header(
                    "Link",
                    format!("<{}/api/v3/users/alice/gists?page=2>; rel=\"next\"", server.uri()),
                )
                .set_body_json(json!([{"git_pull_url": "https://gist.github.com/aaa.git"}])),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/users/alice/gists"))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"git_pull_url": "https://gist.github.com/aaa.git"},
            {"git_pull_url": "https://gist.github.com/bbb.git"}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v3/users/bob/gists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;
    let urls = enumerate_repo_urls(&specifiers(true), base, false, None).await.unwrap();
    assert_eq!(
        urls,
        vec![
            "https://gist.github.com/aaa.git",
            "https://gist.github.com/bbb.git",
            "https://github.com/alice/repo.git",
            "https://github.com/bob/repo.git",
        ]
    );
}

#[tokio::test]
async fn gists_reject_cross_origin_and_repeated_pagination() {
    for cross_origin in [false, true] {
        let server = MockServer::start().await;
        mock_repos(&server).await;
        let next = if cross_origin {
            "https://example.invalid/gists".to_string()
        } else {
            format!("{}/api/v3/users/alice/gists?per_page=100", server.uri())
        };
        Mock::given(method("GET"))
            .and(path("/api/v3/users/alice/gists"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Link", format!("<{next}>; rel=\"next\""))
                    .set_body_json(json!([{"git_pull_url": "https://gist.github.com/aaa.git"}])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let err = enumerate_repo_urls(
            &specifiers(true),
            Url::parse(&format!("{}/api/v3/", server.uri())).unwrap(),
            false,
            None,
        )
        .await
        .unwrap_err();
        let message = if cross_origin { "different origin" } else { "repeated a page" };
        assert!(err.to_string().contains(message), "{err:#}");
    }
}

#[tokio::test]
async fn gist_api_failure_is_reported() {
    let server = MockServer::start().await;
    mock_repos(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v3/users/alice/gists"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"message": "rate limit exceeded"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let err = enumerate_repo_urls(
        &specifiers(true),
        Url::parse(&format!("{}/api/v3/", server.uri())).unwrap(),
        false,
        None,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("listing user gists: HTTP 403"));
}

#[tokio::test(flavor = "multi_thread")]
async fn enumerated_gist_is_cloned_and_scanned_for_deleted_secrets() -> anyhow::Result<()> {
    use assert_cmd::prelude::*;
    use git2::{Repository, Signature};
    use predicates::str::contains;
    use std::{fs, path::Path, process::Command};

    let temp = tempfile::tempdir()?;
    let repo_dir = temp.path().join("gist");
    let repo = Repository::init(&repo_dir)?;
    let sig = Signature::now("tester", "tester@example.com")?;
    let secret = "issue508_deleted_secret";
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
        "rules:\n  - name: Gist history test\n    id: custom.issue508.secret\n    pattern: '(issue508_deleted_secret)'\n    min_entropy: 0\n    confidence: high\n",
    )?;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/users/alice/repos"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users/alice/gists"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"git_pull_url": "https://gist.github.com/issue508.git"}
        ])))
        .mount(&server)
        .await;

    Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
        .args([
            "scan",
            "github",
            "--user",
            "alice",
            "--api-url",
            &server.uri(),
            "--include-gists",
            "--list-only",
            "--no-update-check",
        ])
        .assert()
        .success()
        .stdout("https://gist.github.com/issue508.git\n");

    // Redirect only this fixture's clone URL to a local Git repository.
    let rewrite = format!("url.{}.insteadOf", Url::from_directory_path(&repo_dir).unwrap());
    for (extra, expected_code) in [
        (vec!["--include-gists"], 200),
        (vec![], 1),
        (vec!["--include-gists", "--repo-clone-limit", "0"], 1),
    ] {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
        command
            .args([
                "scan",
                "github",
                "--user",
                "alice",
                "--api-url",
                &server.uri(),
                "--no-update-check",
                "--no-validate",
                "--load-builtins=false",
                "--rules-path",
            ])
            .arg(&rules)
            .args(["--format", "json"])
            .args(extra)
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", &rewrite)
            .env("GIT_CONFIG_VALUE_0", "https://gist.github.com/issue508.git");
        let assertion = command.assert().code(expected_code);
        if expected_code == 200 {
            assertion.stdout(contains(secret));
        } else {
            assertion.stderr(contains("No inputs to scan"));
        }
    }
    Ok(())
}
