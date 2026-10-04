use clap::Parser;
use kingfisher::{
    cli::{
        commands::scan::{ListRepositoriesCommand, ScanOperation},
        global::{Command, CommandLineArgs},
    },
    github, gitlab,
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

#[test]
fn gitlab_user_files_reject_invalid_username_boundaries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("users.txt");
    for user in [".", "..", "...", "-alice", ".alice", "_alice", "alice."] {
        std::fs::write(&path, user).unwrap();
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            "gitlab",
            "--user-file",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let Command::Scan(command) = args.command else { panic!() };
        let error = command.into_operation().expect_err("invalid username accepted");
        assert!(error.to_string().contains("Invalid GitLab username"), "{error}");
    }
}

#[test]
fn gitlab_users_accept_trailing_underscores_and_hyphens() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users.txt");
    std::fs::write(&users, "alice_\nalice-\n").unwrap();
    for listing in [false, true] {
        let mut argv = vec![
            "kingfisher",
            "scan",
            "gitlab",
            "--user",
            "alice-",
            "--user",
            "alice_",
            "--user-file",
            users.to_str().unwrap(),
        ];
        if listing {
            argv.push("--list-only");
        }
        let args = CommandLineArgs::try_parse_from(argv).unwrap();
        let Command::Scan(command) = args.command else { panic!() };
        let actual = match command.into_operation().unwrap() {
            ScanOperation::Scan(args) => args.input_specifier_args.gitlab_user,
            ScanOperation::ListRepositories(ListRepositoriesCommand::Gitlab {
                specifiers, ..
            }) => specifiers.user,
            other => panic!("unexpected operation: {other:?}"),
        };
        assert_eq!(actual, ["alice-", "alice_"]);
    }
}

#[test]
fn user_files_merge_with_flags_for_scanning_and_listing() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users.txt");
    for provider in ["github", "gitlab"] {
        let extra_user = if provider == "github" { "bob-smith_acme" } else { "bob_smith.dev" };
        std::fs::write(&users, format!("# users\r\n\r\n @Alice \r\n{extra_user}\r\nALICE\r\n"))
            .unwrap();
        for listing in [false, true] {
            let mut argv = vec![
                "kingfisher",
                "scan",
                provider,
                "--user-file",
                users.to_str().unwrap(),
                "--user",
                "alice",
            ];
            if listing {
                argv.push("--list-only");
            }
            // A file alone must also satisfy --include-gists' user requirement.
            if provider == "github" {
                argv.push("--include-gists");
            }
            let args = CommandLineArgs::try_parse_from(argv).unwrap();
            let Command::Scan(command) = args.command else { panic!("expected scan") };
            let actual = match command.into_operation().unwrap() {
                ScanOperation::Scan(args) => {
                    if provider == "github" {
                        args.input_specifier_args.github_user
                    } else {
                        args.input_specifier_args.gitlab_user
                    }
                }
                ScanOperation::ListRepositories(ListRepositoriesCommand::Github {
                    specifiers,
                    ..
                }) => specifiers.user,
                ScanOperation::ListRepositories(ListRepositoriesCommand::Gitlab {
                    specifiers,
                    ..
                }) => specifiers.user,
                other => panic!("unexpected operation: {other:?}"),
            };
            assert_eq!(actual, ["alice", extra_user]);
        }
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            provider,
            "--user-file",
            users.to_str().unwrap(),
            if provider == "github" { "--include-gists" } else { "--include-snippets" },
        ])
        .unwrap();
        let Command::Scan(command) = args.command else { panic!("expected scan") };
        assert!(matches!(command.into_operation().unwrap(), ScanOperation::Scan(_)));
    }
}

#[test]
fn user_file_errors_identify_provider_and_line_and_protect_input() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users.txt");
    for provider in ["github", "gitlab"] {
        std::fs::write(&users, "alice\nbad/user\n").unwrap();
        let parse = |extra: &[&str]| {
            let args = CommandLineArgs::try_parse_from(
                ["kingfisher", "scan", provider, "--user-file", users.to_str().unwrap()]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .unwrap();
            let Command::Scan(command) = args.command else { panic!("expected scan") };
            command.into_operation()
        };
        let err = parse(&[]).unwrap_err().to_string();
        assert!(err.contains("users.txt:2"), "{err}");
        assert!(
            parse(&["--audit-log", users.to_str().unwrap()])
                .unwrap_err()
                .to_string()
                .contains("must not overwrite")
        );
        std::fs::remove_file(&users).unwrap();
        assert!(parse(&[]).unwrap_err().to_string().contains("Failed to read"));
    }
}

// Page two fails deliberately: the first page must have reached the consumer
// already, and the later API failure must still reach the caller.
#[tokio::test]
async fn github_streams_users_and_organizations_before_later_page_failure() {
    for organization in [false, true] {
        let server = MockServer::start().await;
        let endpoint = if organization { "/orgs/acme/repos" } else { "/users/alice/repos" };
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"clone_url":"https://github.com/acme/keep.git","fork":false},
                {"clone_url":"https://github.com/acme/skip.git","fork":false}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let emitted = Arc::new(AtomicBool::new(false));
        let observed = emitted.clone();
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(move |_: &wiremock::Request| {
                assert!(
                    observed.load(Ordering::SeqCst),
                    "page one was buffered until discovery ended"
                );
                ResponseTemplate::new(503)
            })
            .expect(1)
            .mount(&server)
            .await;
        let specs = github::RepoSpecifiers {
            user: if organization { vec![] } else { vec!["alice".into()] },
            organization: if organization { vec!["acme".into()] } else { vec![] },
            all_organizations: false,
            include_gists: false,
            repo_filter: github::RepoType::Source,
            exclude_repos: vec!["acme/skip".into()],
        };
        let mut urls = Vec::new();
        let result = github::enumerate_repo_urls_streaming(
            &specs,
            Url::parse(&server.uri()).unwrap(),
            false,
            None,
            &mut |url| {
                urls.push(url.to_owned());
                emitted.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(urls, ["https://github.com/acme/keep.git"]);
    }
}

#[tokio::test]
async fn gitlab_streams_users_and_groups_before_later_page_failure() {
    for group in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(if group { "/api/v4/groups/acme" } else { "/api/v4/users" }))
            .respond_with(ResponseTemplate::new(200).set_body_json(if group {
                json!({"id":1})
            } else {
                json!([{"id":1}])
            }))
            .expect(1)
            .mount(&server)
            .await;
        let endpoint = if group { "/api/v4/groups/1/projects" } else { "/api/v4/users/1/projects" };
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id":10,"http_url_to_repo":"https://gitlab.example.com/acme/keep.git"},
                {"id":11,"http_url_to_repo":"https://gitlab.example.com/acme/skip.git"}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        let emitted = Arc::new(AtomicBool::new(false));
        let observed = emitted.clone();
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(move |_: &wiremock::Request| {
                assert!(
                    observed.load(Ordering::SeqCst),
                    "page one was buffered until discovery ended"
                );
                ResponseTemplate::new(503)
            })
            .expect(1)
            .mount(&server)
            .await;
        let specs = gitlab::RepoSpecifiers {
            user: if group { vec![] } else { vec!["alice".into()] },
            group: if group { vec!["acme".into()] } else { vec![] },
            all_groups: false,
            include_subgroups: true,
            include_snippets: false,
            repo_filter: gitlab::RepoType::All,
            exclude_repos: vec!["acme/skip".into()],
        };
        let mut urls = Vec::new();
        let result = gitlab::enumerate_repo_urls_streaming(
            &specs,
            Url::parse(&server.uri()).unwrap(),
            false,
            None,
            &mut |url| {
                urls.push(url.to_owned());
                emitted.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(urls, ["https://gitlab.example.com/acme/keep.git"]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn scanning_completes_while_later_discovery_is_waiting() -> anyhow::Result<()> {
    use assert_cmd::Command as ProcessCommand;
    use git2::{Repository, Signature};
    use std::{
        fs,
        path::Path,
        time::{Duration, Instant},
    };

    let temp = tempfile::tempdir()?;
    let repo_dir = temp.path().join("fixture");
    {
        let repo = Repository::init(&repo_dir)?;
        let sig = Signature::now("tester", "tester@example.com")?;
        fs::write(repo_dir.join("secret.txt"), "issue525_streamed_secret")?;
        let mut index = repo.index()?;
        index.add_path(Path::new("secret.txt"))?;
        let tree = repo.find_tree(index.write_tree()?)?;
        repo.commit(Some("HEAD"), &sig, &sig, "fixture", &tree, &[])?;
    }
    let rules = temp.path().join("rules.yml");
    fs::write(
        &rules,
        "rules:\n  - name: Streaming fixture\n    id: custom.issue525.secret\n    pattern: '(issue525_streamed_secret)'\n    min_entropy: 0\n",
    )?;
    let users = temp.path().join("users.txt");
    fs::write(&users, "alice\nbob\n")?;
    let local_repo = repo_dir.to_string_lossy();
    #[cfg(windows)]
    let local_repo = local_repo.replace('\\', "/");

    for (provider, selector, later_status) in [
        ("github", "--user-file", 200),
        ("github", "--org", 200),
        ("gitlab", "--user-file", 200),
        ("gitlab", "--group", 200),
        ("github", "--user-file", 503),
        ("gitlab", "--user-file", 503),
    ] {
        let server = MockServer::start().await;
        let is_user = selector == "--user-file";
        let audit = temp.path().join(format!("{provider}-{is_user}-{later_status}.jsonl"));
        let clone_url = format!("https://{provider}.com/acme/first.git");
        let endpoint = match (provider, is_user) {
            ("github", true) => "/users/alice/repos",
            ("github", false) => "/orgs/acme/repos",
            ("gitlab", true) => "/api/v4/users/1/projects",
            _ => "/api/v4/groups/1/projects",
        };
        if provider == "gitlab" {
            Mock::given(method("GET"))
                .and(path(if is_user { "/api/v4/users" } else { "/api/v4/groups/acme" }))
                .respond_with(ResponseTemplate::new(200).set_body_json(if is_user {
                    json!([{"id":1}])
                } else {
                    json!({"id":1})
                }))
                .mount(&server)
                .await;
        }
        let first = if provider == "github" {
            json!({"clone_url":clone_url,"fork":false})
        } else {
            json!({"id":10,"http_url_to_repo":clone_url})
        };
        let second = if provider == "github" {
            json!({"clone_url":"https://github.com/acme/second.git","fork":false})
        } else {
            json!({"id":11,"http_url_to_repo":"https://gitlab.com/acme/second.git"})
        };
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([first, first, second])))
            .mount(&server)
            .await;
        let completed = Arc::new(AtomicBool::new(false));
        let observed = completed.clone();
        let audit_path = audit.clone();
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(move |_: &wiremock::Request| {
                let deadline = Instant::now() + Duration::from_secs(20);
                while Instant::now() < deadline {
                    if fs::read_to_string(&audit_path)
                        .unwrap_or_default()
                        .contains("repository_scan_completed")
                    {
                        observed.store(true, Ordering::SeqCst);
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                ResponseTemplate::new(later_status).set_body_json(json!([]))
            })
            .mount(&server)
            .await;
        if provider == "github" && is_user {
            Mock::given(method("GET"))
                .and(path("/users/bob/repos"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&server)
                .await;
        }
        let output = ProcessCommand::new(assert_cmd::cargo::cargo_bin!("kingfisher"))
            .timeout(Duration::from_secs(60))
            .args(["scan", provider, selector])
            .arg(if is_user { users.as_os_str() } else { std::ffi::OsStr::new("acme") })
            .args([
                "--api-url",
                &server.uri(),
                "--no-update-check",
                "--no-validate",
                "--load-builtins=false",
                "--rules-path",
            ])
            .arg(&rules)
            .arg("--audit-log")
            .arg(&audit)
            .args([
                "--format",
                "toon",
                "--repo-clone-limit",
                "1",
                "--jobs",
                if is_user { "1" } else { "2" },
            ])
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", format!("url.{local_repo}.insteadOf"))
            .env("GIT_CONFIG_VALUE_0", &clone_url)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(if later_status == 200 { 200 } else { 1 }),
            "{provider} {selector}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            completed.load(Ordering::SeqCst),
            "scan waited for discovery to finish: {provider} {selector}"
        );
        if later_status == 200 {
            assert!(String::from_utf8_lossy(&output.stdout).contains("issue525_streamed_secret"));
        } else {
            assert!(String::from_utf8_lossy(&output.stderr).contains("Failed to enumerate"));
        }
        let log = fs::read_to_string(&audit)?;
        if later_status != 200 {
            assert!(
                log.contains("\"event\":\"run_failed\""),
                "missing incomplete-run marker: {log}"
            );
            assert!(
                !log.contains("\"event\":\"run_completed\""),
                "failed run reported completion: {log}"
            );
        }
        assert_eq!(log.matches("repository_scan_completed").count(), 1, "duplicate scan: {log}");
        assert!(!log.contains("second.git"), "clone limit was not applied: {log}");
    }
    Ok(())
}

#[test]
fn user_files_accept_thousands_of_users_without_repeated_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users.txt");
    let expected: Vec<String> = (0..3000).map(|i| format!("user-{i}")).collect();
    let contents = expected
        .iter()
        .map(|user| format!("{user}\n@{}\n", user.to_uppercase()))
        .collect::<String>();
    std::fs::write(&users, contents).unwrap();
    for provider in ["github", "gitlab"] {
        let args = CommandLineArgs::try_parse_from([
            "kingfisher",
            "scan",
            provider,
            "--user-file",
            users.to_str().unwrap(),
            "--list-only",
        ])
        .unwrap();
        let Command::Scan(command) = args.command else { panic!("expected scan") };
        let actual = match command.into_operation().unwrap() {
            ScanOperation::ListRepositories(ListRepositoriesCommand::Github {
                specifiers, ..
            }) => specifiers.user,
            ScanOperation::ListRepositories(ListRepositoriesCommand::Gitlab {
                specifiers, ..
            }) => specifiers.user,
            other => panic!("unexpected operation: {other:?}"),
        };
        assert_eq!(actual, expected);
    }
}

#[test]
fn empty_user_files_require_another_source() {
    let dir = tempfile::tempdir().unwrap();
    let users = dir.path().join("users.txt");
    std::fs::write(&users, "\r\n # no users yet\r\n \r\n").unwrap();
    for provider in ["github", "gitlab"] {
        for extra in [
            vec![],
            vec!["--user", "alice"],
            vec![if provider == "github" { "--org" } else { "--group" }, "acme"],
        ] {
            let args = CommandLineArgs::try_parse_from(
                ["kingfisher", "scan", provider, "--user-file", users.to_str().unwrap()]
                    .into_iter()
                    .chain(extra.iter().copied()),
            )
            .unwrap();
            let Command::Scan(command) = args.command else { panic!("expected scan") };
            let operation = command.into_operation();
            if extra.is_empty() {
                assert!(operation.unwrap_err().to_string().contains("must specify"));
            } else {
                assert!(matches!(operation.unwrap(), ScanOperation::Scan(_)));
            }
        }
    }
}

#[tokio::test]
async fn disconnected_consumers_stop_discovery_before_the_next_page() {
    for provider in ["github", "gitlab"] {
        let server = MockServer::start().await;
        if provider == "gitlab" {
            Mock::given(method("GET"))
                .and(path("/api/v4/users"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([{"id":1}])))
                .expect(1)
                .mount(&server)
                .await;
        }
        let endpoint =
            if provider == "github" { "/users/alice/repos" } else { "/api/v4/users/1/projects" };
        let body = if provider == "github" {
            json!([{"clone_url":"https://github.com/acme/first.git","fork":false}])
        } else {
            json!([{"id":10,"http_url_to_repo":"https://gitlab.com/acme/first.git"}])
        };
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(0)
            .mount(&server)
            .await;
        let mut stop = |_: &str| anyhow::bail!("scan consumer disconnected");
        let result = if provider == "github" {
            let specs = github::RepoSpecifiers {
                user: vec!["alice".into()],
                organization: vec![],
                all_organizations: false,
                include_gists: false,
                repo_filter: github::RepoType::Source,
                exclude_repos: vec![],
            };
            github::enumerate_repo_urls_streaming(
                &specs,
                Url::parse(&server.uri()).unwrap(),
                false,
                None,
                &mut stop,
            )
            .await
        } else {
            let specs = gitlab::RepoSpecifiers {
                user: vec!["alice".into()],
                group: vec![],
                all_groups: false,
                include_subgroups: false,
                include_snippets: false,
                repo_filter: gitlab::RepoType::All,
                exclude_repos: vec![],
            };
            gitlab::enumerate_repo_urls_streaming(
                &specs,
                Url::parse(&server.uri()).unwrap(),
                false,
                None,
                &mut stop,
            )
            .await
        };
        assert_eq!(result.unwrap_err().to_string(), "scan consumer disconnected");
    }
}
