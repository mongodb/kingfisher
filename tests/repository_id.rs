use std::{fs, path::Path, time::Duration};

use anyhow::Result;
use git2::{Repository, Signature};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path, query_param},
};

const REPOSITORIES: [(&str, &str); 3] = [
    ("original", "issue564_original_secret"),
    ("fork", "issue564_fork_secret"),
    ("unknown", "issue564_unknown_secret"),
];
const ORIGINAL_ID: u64 = 9_007_199_254_740_993;

fn fixtures(root: &Path) -> Result<()> {
    fixtures_with_secrets(root, REPOSITORIES)
}

fn fixtures_with_secrets(root: &Path, repositories: [(&str, &str); 3]) -> Result<()> {
    for (name, secret) in repositories {
        // Bare repositories avoid working-tree line endings and leave no open
        // handles when the subprocess clones them, including on Windows.
        let repo = Repository::init_bare(root.join(name))?;
        let blob = repo.blob(secret.as_bytes())?;
        let mut tree = repo.treebuilder(None)?;
        tree.insert("secret.txt", blob, 0o100644)?;
        let tree = repo.find_tree(tree.write()?)?;
        let signature = Signature::now("Scanner test", "scanner@example.com")?;
        repo.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])?;
    }
    fs::write(
        root.join("rules.yml"),
        "rules:\n  - id: acme.repository-id\n    name: Repository identity fixture\n    pattern: '(issue564_[a-z]+_secret)'\n    min_entropy: 0\n",
    )?;
    Ok(())
}

fn scan(root: &Path, clones: &Path, jobs: &str) -> assert_cmd::Command {
    fs::create_dir_all(clones).unwrap();
    let mut command = assert_cmd::Command::new(assert_cmd::cargo::cargo_bin!("kingfisher"));
    command
        .current_dir(root)
        .timeout(Duration::from_secs(60))
        .arg("scan")
        .arg("--rules-path")
        .arg(root.join("rules.yml"))
        // An explicit --git-clone-dir intentionally retains clones. Use the
        // subprocess's temporary directory instead to exercise automatic cleanup.
        .env("TMPDIR", clones)
        .env("TMP", clones)
        .env("TEMP", clones)
        // All clone targets are rewritten to local fixtures. Never let a bad
        // rewrite make a test contact a real source host, even with fake tokens.
        .env("GIT_ALLOW_PROTOCOL", "file")
        .args(["--load-builtins=false", "--no-validate", "--no-update-check", "--jobs", jobs])
        .env_remove("KF_GITHUB_TOKEN")
        .env_remove("KF_GITHUB_APP_ID")
        .env_remove("KF_GITHUB_APP_INSTALLATION_ID")
        .env_remove("KF_GITHUB_APP_PRIVATE_KEY")
        .env_remove("KF_GITHUB_APP_PRIVATE_KEY_PATH")
        .env("GIT_CONFIG_COUNT", REPOSITORIES.len().to_string());
    for name in [
        "KF_GITLAB_TOKEN",
        "KF_GITEA_TOKEN",
        "KF_BITBUCKET_USERNAME",
        "KF_BITBUCKET_APP_PASSWORD",
        "KF_BITBUCKET_TOKEN",
        "KF_BITBUCKET_PASSWORD",
        "KF_BITBUCKET_OAUTH_TOKEN",
        "KF_AZURE_USERNAME",
        "KF_AZURE_TOKEN",
        "KF_AZURE_PAT",
        "KF_HUGGINGFACE_TOKEN",
    ] {
        command.env_remove(name);
    }
    for (index, (name, _)) in REPOSITORIES.iter().enumerate() {
        // Git accepts absolute local paths on all platforms. In particular,
        // MSYS2 Git does not reliably support file:///C:/... clone rewrites.
        let local_repo = root.join(name).to_string_lossy().replace('\\', "/");
        command.env(format!("GIT_CONFIG_KEY_{index}"), format!("url.{local_repo}.insteadOf")).env(
            format!("GIT_CONFIG_VALUE_{index}"),
            format!("https://github.com/acme/{name}.git"),
        );
    }
    command
}

fn findings(command: &mut assert_cmd::Command, clones: &Path, format: &str) -> Result<Vec<Value>> {
    command.args(["--format", format]);
    let report_path = clones.with_extension("toon");
    if format == "toon" {
        // Stdout streams per-repository envelopes and a final scan summary.
        // A report file is one combined envelope and exercises post-cleanup reporting.
        command.arg("--output").arg(&report_path);
    }
    let assertion = command.assert().code(200);
    assert!(fs::read_dir(clones)?.next().is_none(), "clones must be removed after scanning");
    if format == "toon" {
        let report: Value = toon_format::decode_default(&fs::read_to_string(report_path)?)?;
        return Ok(report["findings"].as_array().unwrap().clone());
    }
    let mut findings = Vec::new();
    // JSON stdout also contains a separate scan summary.
    for report in
        serde_json::Deserializer::from_slice(&assertion.get_output().stdout).into_iter::<Value>()
    {
        let report = report?;
        if let Some(records) = report["findings"].as_array() {
            findings.extend(records.iter().map(|record| record["finding"].clone()));
        }
    }
    Ok(findings)
}

#[tokio::test(flavor = "multi_thread")]
async fn discovered_repository_ids_survive_per_repository_scanning_and_cleanup() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures(temp.path())?;
    // Exercise both discovery endpoints and both scanner scheduling paths.
    for (selector, endpoint, jobs) in
        [("--user", "/users/acme/repos", "1"), ("--org", "/orgs/acme/repos", "2")]
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": ORIGINAL_ID, "clone_url": "https://github.com/acme/original.git", "fork": false},
                {"id": 42, "clone_url": "https://github.com/acme/fork.git", "fork": true,
                 "parent": {"id": ORIGINAL_ID}},
                {"clone_url": "https://github.com/acme/unknown.git", "fork": false}
            ])))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(endpoint))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&server)
            .await;
        let clones = temp.path().join(format!("clones-{jobs}"));
        let mut command = scan(temp.path(), &clones, jobs);
        command.args([
            "github",
            selector,
            "acme",
            "--repo-type",
            "all",
            "--api-url",
            &server.uri(),
        ]);
        let findings = findings(&mut command, &clones, "json")?;
        assert_eq!(findings.len(), REPOSITORIES.len());
        for ((name, secret), id) in
            REPOSITORIES.into_iter().zip([Some(ORIGINAL_ID), Some(42), None])
        {
            let finding = findings.iter().find(|finding| finding["snippet"] == secret).unwrap();
            let git = &finding["git_metadata"];
            assert_eq!(git["repository_url"], format!("https://github.com/acme/{name}"));
            match id {
                Some(id) => assert_eq!(git["repository_id"].as_u64(), Some(id)),
                None => assert!(git.get("repository_id").is_none()),
            }
        }
        // Listing already supplies IDs; scanning must not perform per-repo
        // lookups, including when an older response omits the optional ID.
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_github_repository_id_lookup_is_best_effort() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures(temp.path())?;
    for (status, jobs, format, mismatched_host) in [
        (200, "1", "json", false),
        (200, "2", "toon", false),
        (404, "2", "json", false),
        (403, "2", "json", false),
        (200, "1", "json", true),
    ] {
        let server = MockServer::start().await;
        let response = if status == 200 {
            json!({"id": ORIGINAL_ID})
        } else {
            json!({"message": "Repository metadata is unavailable"})
        };
        Mock::given(method("GET"))
            .and(path("/repos/acme/original"))
            .respond_with(ResponseTemplate::new(status).set_body_json(response))
            .expect(if mismatched_host { 0 } else { 1 })
            .mount(&server)
            .await;
        let clones =
            temp.path().join(format!("explicit-clones-{status}-{format}-{mismatched_host}"));
        let mut command = scan(temp.path(), &clones, jobs);
        let repository_url = if mismatched_host {
            "https://github.com/acme/original.git".to_owned()
        } else {
            format!("{}/acme/original.git", server.uri())
        };
        // The metadata API and clone host belong to the same enterprise instance.
        // Retain the absolute local Git rewrite for portability on Windows.
        command
            .env("GIT_CONFIG_VALUE_0", &repository_url)
            .env("KF_GITHUB_TOKEN", "synthetic-metadata-token");
        command.args([
            "--git-url",
            &repository_url,
            "--github-api-url",
            &server.uri(),
            "--commit-metadata=false",
        ]);
        let findings = findings(&mut command, &clones, format)?;
        assert_eq!(findings.len(), 1);
        let (git, url_key, id_key) = if format == "toon" {
            (&findings[0], "git_repository_url", "git_repository_id")
        } else {
            (&findings[0]["git_metadata"], "repository_url", "repository_id")
        };
        assert_eq!(git[url_key], repository_url.trim_end_matches(".git"));
        if status == 200 && !mismatched_host {
            assert_eq!(git[id_key].as_u64(), Some(ORIGINAL_ID));
        } else {
            assert!(git.get(id_key).is_none());
        }
        assert_eq!(server.received_requests().await.unwrap().len(), usize::from(!mismatched_host));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn discovered_repository_ids_cover_other_scm_providers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures(temp.path())?;
    for (provider, variant, format) in [
        ("gitlab", "user", "json"),
        ("gitlab", "group", "toon"),
        ("gitea", "user", "json"),
        ("gitea", "org", "toon"),
        ("bitbucket", "cloud", "toon"),
        ("bitbucket", "server", "json"),
        ("azure", "org", "toon"),
    ] {
        let server = MockServer::start().await;
        let host = match provider {
            "gitlab" => "gitlab.example.com",
            "gitea" => "gitea.example.com",
            "azure" => "dev.azure.com",
            "bitbucket" if variant == "cloud" => "bitbucket.org",
            _ => "bitbucket.example.com",
        };
        let urls: Vec<_> = REPOSITORIES
            .iter()
            .map(|(name, _)| match (provider, variant) {
                ("azure", _) => format!("https://{host}/acme/project/_git/{name}"),
                ("bitbucket", "server") => format!("https://{host}/scm/acme/{name}.git"),
                _ => format!("https://{host}/acme/{name}.git"),
            })
            .collect();
        let ids = if provider == "azure" || variant == "cloud" {
            [
                json!("{a1b2c3d4-1234-5678-9abc-0123456789ab}"),
                json!("{b2c3d4e5-1234-5678-9abc-0123456789ab}"),
                Value::Null,
            ]
        } else {
            [json!(ORIGINAL_ID), json!(42), Value::Null]
        };
        let records: Vec<_> = urls.iter().zip(&ids).zip(REPOSITORIES).map(|((url, id), (name, _))| {
            let fork = name == "fork";
            match provider {
                "gitlab" => json!({"id": id, "http_url_to_repo": url}),
                "gitea" => json!({"id": id, "clone_url": url, "full_name": format!("acme/{name}"), "fork": fork}),
                "azure" => json!({"id": id, "remoteUrl": url, "isFork": fork, "project": {"name": "project"}}),
                _ => {
                    let mut repo = json!({"links": {"clone": [{"name": "http", "href": url}]}});
                    repo[if variant == "cloud" { "uuid" } else { "id" }] = id.clone();
                    if fork {
                        repo[if variant == "cloud" { "parent" } else { "origin" }] = json!({"id": ids[0]});
                    }
                    repo
                }
            }
        }).collect();
        let (api_path, endpoint, selector) = match (provider, variant) {
            ("gitlab", "user") => ("", "/api/v4/users/1/projects", "--user"),
            ("gitlab", _) => ("", "/api/v4/groups/1/projects", "--group"),
            ("gitea", "user") => ("/api/v1/", "/api/v1/users/acme/repos", "--user"),
            ("gitea", _) => ("/api/v1/", "/api/v1/orgs/acme/repos", "--org"),
            ("bitbucket", "cloud") => ("/2.0/", "/2.0/repositories/acme", "--workspace"),
            ("bitbucket", _) => {
                ("/rest/api/1.0/", "/rest/api/1.0/projects/acme/repos", "--project")
            }
            _ => ("", "/acme/_apis/git/repositories", "--organization"),
        };
        if provider == "gitlab" {
            Mock::given(method("GET"))
                .and(path(if variant == "user" { "/api/v4/users" } else { "/api/v4/groups/acme" }))
                .respond_with(ResponseTemplate::new(200).set_body_json(if variant == "user" {
                    json!([{"id": 1}])
                } else {
                    json!({"id": 1})
                }))
                .expect(1)
                .mount(&server)
                .await;
        }
        let body = match provider {
            "gitlab" | "gitea" => json!(records),
            "azure" => json!({"value": records}),
            _ => json!({"values": records, "isLastPage": true}),
        };
        let paginated = provider == "gitlab" || provider == "gitea";
        let mut listing = Mock::given(method("GET")).and(path(endpoint));
        if paginated {
            listing = listing.and(query_param("page", "1"));
            Mock::given(method("GET"))
                .and(path(endpoint))
                .and(query_param("page", "2"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .expect(1)
                .mount(&server)
                .await;
        }
        listing
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let clones = temp.path().join(format!("{provider}-{variant}"));
        let mut command = scan(temp.path(), &clones, "2");
        for (index, url) in urls.iter().enumerate() {
            command.env(format!("GIT_CONFIG_VALUE_{index}"), url);
        }
        command.args([
            provider,
            selector,
            "acme",
            "--repo-type",
            "all",
            if provider == "azure" { "--base-url" } else { "--api-url" },
            &format!("{}{api_path}", server.uri()),
        ]);
        let findings = findings(&mut command, &clones, format)?;
        assert_eq!(findings.len(), 3, "{provider}-{variant}");
        for ((name, secret), id) in REPOSITORIES.into_iter().zip(&ids) {
            let finding = findings.iter().find(|f| f["snippet"] == secret).unwrap();
            let (git, key) = if format == "toon" {
                (finding, "git_repository_id")
            } else {
                (&finding["git_metadata"], "repository_id")
            };
            if id.is_null() {
                assert!(git.get(key).is_none(), "{provider}-{name}: {git}");
            } else {
                assert_eq!(&git[key], id, "{provider}-{name}");
            }
        }
        let expected_requests = if provider == "gitlab" {
            3
        } else if paginated {
            2
        } else {
            1
        };
        assert_eq!(server.received_requests().await.unwrap().len(), expected_requests);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn explicit_repository_ids_cover_other_scm_providers() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures(temp.path())?;
    for (provider, api_path, repo_path, lookup_path, field, id) in [
        (
            "gitlab",
            "",
            "/acme/subgroup/original.git",
            "/api/v4/projects/acme%2Fsubgroup%2Foriginal",
            "id",
            json!(ORIGINAL_ID),
        ),
        (
            "gitlab",
            "",
            "/acme/sub%2Egroup/original.git",
            "/api/v4/projects/acme%2Fsub%2Egroup%2Foriginal",
            "id",
            json!(ORIGINAL_ID),
        ),
        ("gitea", "/api/v1/", "/acme/original.git", "/api/v1/repos/acme/original", "id", json!(42)),
        (
            "bitbucket-cloud",
            "/2.0/",
            "/acme/original.git",
            "/2.0/repositories/acme/original",
            "uuid",
            json!("{stable-cloud-uuid}"),
        ),
        (
            "bitbucket-server",
            "/rest/api/1.0/",
            "/scm/acme/original.git",
            "/rest/api/1.0/projects/acme/repos/original",
            "id",
            json!(42),
        ),
        (
            "azure",
            "",
            "/acme/project/_git/original",
            "/acme/project/_apis/git/repositories/original",
            "id",
            json!("stable-azure-guid"),
        ),
    ] {
        for status in [200, 403, 404, 429, 503] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path(lookup_path))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("retry-after", "600")
                        .set_body_json(json!({field: id})),
                )
                .expect(1)
                .mount(&server)
                .await;
            let clones = temp.path().join(format!("explicit-{provider}-{status}"));
            let mut command = scan(temp.path(), &clones, "1");
            let repo_url = format!("{}{repo_path}", server.uri());
            let provider_flag =
                if provider.starts_with("bitbucket") { "bitbucket" } else { provider };
            command.env("GIT_CONFIG_VALUE_0", &repo_url).args([
                "--git-url",
                &repo_url,
                &format!(
                    "--{provider_flag}-{}",
                    if provider == "azure" { "base-url" } else { "api-url" }
                ),
                &format!("{}{api_path}", server.uri()),
            ]);
            let findings = findings(&mut command, &clones, "json")?;
            assert_eq!(findings.len(), 1);
            let git = &findings[0]["git_metadata"];
            if status == 200 {
                assert_eq!(git["repository_id"], id, "{provider}");
            } else {
                assert!(git.get("repository_id").is_none(), "{provider}-{status}");
            }
            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn public_repositories_are_not_looked_up_on_other_provider_instances() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures(temp.path())?;
    for (provider, repo_url, flag, token) in [
        ("gitlab", "https://gitlab.com/acme/original.git", "--gitlab-api-url", "KF_GITLAB_TOKEN"),
        ("gitea", "https://gitea.com/acme/original.git", "--gitea-api-url", "KF_GITEA_TOKEN"),
        (
            "bitbucket",
            "https://bitbucket.org/acme/original.git",
            "--bitbucket-api-url",
            "KF_BITBUCKET_TOKEN",
        ),
        (
            "azure",
            "https://dev.azure.com/acme/project/_git/original",
            "--azure-base-url",
            "KF_AZURE_TOKEN",
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": 42})))
            .expect(0)
            .mount(&server)
            .await;
        let clones = temp.path().join(format!("public-mismatch-{provider}"));
        let mut command = scan(temp.path(), &clones, "2");
        let api_url = if provider == "bitbucket" {
            // Exercise the cloud API shape on a different configured host.
            format!("{}/2.0/", server.uri())
        } else {
            server.uri()
        };
        command.env("GIT_CONFIG_VALUE_0", repo_url).env(token, "synthetic-instance-token").args([
            "--git-url",
            repo_url,
            flag,
            &api_url,
        ]);
        if provider == "bitbucket" {
            // The Bitbucket Git transport embeds basic credentials before Git
            // applies insteadOf. Match that actual URL, not the clean input.
            command.env(
                "GIT_CONFIG_VALUE_0",
                "https://x-token-auth:synthetic-instance-token@bitbucket.org/acme/original.git",
            );
        }
        let findings = findings(&mut command, &clones, "json")?;
        assert_eq!(findings.len(), 1);
        assert!(findings[0]["git_metadata"].get("repository_id").is_none());
        assert!(server.received_requests().await.unwrap().is_empty());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn identical_findings_in_forks_keep_both_repository_ids_in_combined_reports() -> Result<()> {
    let temp = tempfile::tempdir()?;
    fixtures_with_secrets(
        temp.path(),
        [
            ("original", "issue564_shared_secret"),
            ("fork", "issue564_shared_secret"),
            REPOSITORIES[2],
        ],
    )?;
    for jobs in ["1", "2"] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path("/orgs/acme/repos")).and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {"id": ORIGINAL_ID, "clone_url": "https://github.com/acme/original.git", "fork": false},
                {"id": 42, "clone_url": "https://github.com/acme/fork.git", "fork": true, "parent": {"id": ORIGINAL_ID}}
            ]))).expect(1).mount(&server).await;
        Mock::given(method("GET"))
            .and(path("/orgs/acme/repos"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&server)
            .await;
        let clones = temp.path().join(format!("identical-{jobs}"));
        let mut command = scan(temp.path(), &clones, jobs);
        command.args(["github", "--org", "acme", "--repo-type", "all", "--api-url", &server.uri()]);
        if jobs == "2" {
            command.arg("--disk-offload");
        }
        let findings = findings(&mut command, &clones, "toon")?;
        assert_eq!(findings.len(), 2, "a fork must not lose its repository identity");
        let mut ids: Vec<_> = findings
            .iter()
            .map(|finding| {
                assert_eq!(finding["snippet"], "issue564_shared_secret");
                finding["git_repository_id"].as_u64().unwrap()
            })
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, [42, ORIGINAL_ID]);
    }
    Ok(())
}
