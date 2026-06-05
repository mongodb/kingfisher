use std::sync::{Arc, Mutex};

use anyhow::Result;
use kingfisher::{
    cli::{
        GlobalArgs,
        commands::{
            azure::AzureRepoType,
            bitbucket::{BitbucketAuthArgs, BitbucketRepoType},
            gitea::GiteaRepoType,
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
            scan::{ConfidenceLevel, ScanArgs},
        },
        global::{Mode, TlsMode},
    },
    findings_store::FindingsStore,
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::run_async_scan,
    update::UpdateStatus,
};
use tempfile::TempDir;
use url::Url;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn test_scan_postman_all() -> Result<()> {
    use std::env;

    let server = MockServer::start().await;

    // Workspace listing
    let workspaces_response = serde_json::json!({
        "workspaces": [
            { "id": "ws-uid-1", "name": "demo", "type": "team", "visibility": "private" }
        ]
    });
    Mock::given(method("GET"))
        .and(path("/workspaces"))
        .respond_with(ResponseTemplate::new(200).set_body_json(workspaces_response))
        .mount(&server)
        .await;

    // Workspace detail (collections + environments embedded)
    let workspace_detail = serde_json::json!({
        "workspace": {
            "id": "ws-uid-1",
            "name": "demo",
            "type": "team",
            "collections": [
                { "id": "col-uid-1", "uid": "col-uid-1", "name": "demo collection" }
            ],
            "environments": [
                { "id": "env-uid-1", "uid": "env-uid-1", "name": "prod" }
            ],
            "mocks": [],
            "monitors": []
        }
    });
    Mock::given(method("GET"))
        .and(path("/workspaces/ws-uid-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(workspace_detail))
        .mount(&server)
        .await;

    // Collection detail — plant a GitHub PAT in a request bearer token
    let collection_response = serde_json::json!({
        "collection": {
            "info": { "name": "demo collection" },
            "item": [{
                "name": "auth call",
                "request": {
                    "method": "GET",
                    "header": [],
                    "url": { "raw": "https://api.example.com/v1/me" },
                    "auth": {
                        "type": "bearer",
                        "bearer": [{
                            "key": "token",
                            "value": "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",
                            "type": "string"
                        }]
                    }
                }
            }]
        }
    });
    Mock::given(method("GET"))
        .and(path("/collections/col-uid-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(collection_response))
        .mount(&server)
        .await;

    // Environment detail — plant a second GitHub PAT in a "secret"-typed variable
    // (this exercises the headline finding: the API returns plaintext for "secret"
    // env vars, so Kingfisher can detect what the UI would otherwise mask).
    let environment_response = serde_json::json!({
        "environment": {
            "id": "env-uid-1",
            "name": "prod",
            "values": [
                {
                    "key": "API_TOKEN",
                    "value": "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",
                    "type": "secret",
                    "enabled": true
                }
            ]
        }
    });
    Mock::given(method("GET"))
        .and(path("/environments/env-uid-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(environment_response))
        .mount(&server)
        .await;

    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { env::set_var("KF_POSTMAN_TOKEN", "test-key") };

    let temp_dir = TempDir::new()?;
    let clone_dir = temp_dir.path().to_path_buf();

    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            git_clone_dir: None,
            keep_clones: false,
            repo_clone_limit: None,
            include_contributors: false,
            github_user: Vec::new(),
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::Owner,
            gitlab_include_subgroups: false,
            huggingface_user: Vec::new(),
            huggingface_organization: Vec::new(),
            huggingface_model: Vec::new(),
            huggingface_dataset: Vec::new(),
            huggingface_space: Vec::new(),
            huggingface_exclude: Vec::new(),
            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,
            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/").unwrap(),
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),
            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/").unwrap(),
            azure_repo_type: AzureRepoType::Source,
            jira_url: None,
            jql: None,
            jira_include_comments: false,
            jira_include_changelog: false,
            confluence_url: None,
            cql: None,
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            teams_query: None,
            teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),
            postman_workspaces: Vec::new(),
            postman_collections: Vec::new(),
            postman_environments: Vec::new(),
            postman_all: true,
            postman_include_mocks_monitors: false,
            postman_api_url: Url::parse(&format!("{}/", server.uri()))?,
            max_results: 10,
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            docker_image: Vec::new(),
            docker_archive: Vec::new(),
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
            branch_root: false,
            branch_root_commit: None,
            staged: false,
        },
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            extraction_depth: 2,
            no_binary: true,
            no_extract_archives: false,
            exclude: Vec::new(),
        },
        confidence: ConfidenceLevel::Low,
        no_validate: true,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: Some(0.0),
        redact: false,
        git_repo_timeout: 1800,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true,
        baseline_file: None,
        manage_baseline: false,
        skip_regex: Vec::new(),
        skip_word: Vec::new(),
        skip_aws_account: Vec::new(),
        skip_aws_account_file: None,
        no_base64: false,
        turbo: false,
        extra_ignore_comments: Vec::new(),
        no_inline_ignore: false,
        no_ignore_if_contains: false,
        view_report: false,
        view_report_port: 7890,
        view_report_address: "127.0.0.1".to_string(),
        validation_retries: 1,
        validation_rps: None,
        validation_rps_rule: Vec::new(),
        validation_timeout: 10,
        full_validation_response: false,
        max_validation_response_length: 2048,
        alert_webhook: Vec::new(),
        alert_format: None,
        alert_on: kingfisher::alerts::AlertOn::Findings,
        alert_min_confidence: ConfidenceLevel::Medium,
        alert_include_secret: false,
        alert_report_url: None,
        alert_detail: kingfisher::alerts::AlertDetail::Auto,
        config_webhook_overrides: Vec::new(),
    };

    let global_args = GlobalArgs {
        verbose: 0,
        quiet: true,
        color: Mode::Auto,
        no_update_check: false,
        self_update: false,
        progress: Mode::Never,
        ignore_certs: false,
        user_agent_suffix: None,
        tls_mode: TlsMode::Strict,
        allow_internal_ips: false,
        endpoint: Vec::new(),
        endpoint_config: None,
        config: None,
    };

    let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = Arc::new(RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?);

    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    let update_status = UpdateStatus::default();

    run_async_scan(
        &global_args,
        &scan_args,
        Arc::clone(&datastore),
        &rules_db,
        &update_status,
        false,
    )
    .await?;

    let ds = datastore.lock().unwrap();
    let findings = ds.get_matches().len();
    assert!(
        findings >= 2,
        "expected at least two findings (collection bearer + secret env value), got {}",
        findings
    );

    // Both findings should resolve to a Postman web URL via the link map.
    let postman_link_count = ds.postman_links().len();
    assert!(
        postman_link_count >= 2,
        "expected postman_links registered for collection + environment (got {})",
        postman_link_count
    );
    Ok(())
}
