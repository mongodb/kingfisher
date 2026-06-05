//! Proves that run_async_scan collapses identical findings when
//!               ── no_dedup == false ──
//! while keeping them separate when       no_dedup == true.

use std::{
    fs,
    sync::{Arc, Mutex},
};

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
use tokio::runtime::Runtime;
use url::Url;

/// Helper: run a scan with the supplied `no_dedup` flag and return how many
/// findings the `FindingsStore` ends up containing.
fn run_scan(count_rt: &Runtime, no_dedup: bool) -> Result<usize> {
    // ── temp workspace ──────────────────────────────────────────────
    let work = TempDir::new()?;
    let rules_dir = work.path().join("rules");
    fs::create_dir_all(&rules_dir)?;
    let inputs_dir = work.path().join("in");
    fs::create_dir_all(&inputs_dir)?;

    // 1. Tiny custom rule that matches `secret_1234`
    fs::write(
        rules_dir.join("demo.yml"),
        r#"
rules:
  - id: demo.secret
    name: Demo secret
    pattern: "secret_[0-9]{4}"
    confidence: low
"#,
    )?;

    // 2. Two different blobs that both contain the SAME secret
    fs::write(inputs_dir.join("a.txt"), "secret_1234\n")?;
    fs::write(inputs_dir.join("b.txt"), "secret_1234\n")?;

    // ── build ScanArgs ──────────────────────────────────────────────
    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: vec![rules_dir.clone()],
            rule: vec!["all".into()],
            load_builtins: false,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: vec![inputs_dir.join("a.txt"), inputs_dir.join("b.txt")],
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
            // new GitLab defaults
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
            max_results: 100,
            slack_query: None,
            slack_api_url: Url::parse("https://slack.com/api/").unwrap(),
            teams_query: None,
            teams_api_url: Url::parse("https://graph.microsoft.com/").unwrap(),
            postman_workspaces: Vec::new(),
            postman_collections: Vec::new(),
            postman_environments: Vec::new(),
            postman_all: false,
            postman_include_mocks_monitors: false,
            postman_api_url: Url::parse("https://api.getpostman.com/").unwrap(),
            // s3
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            // Docker image scanning
            docker_image: Vec::new(),
            docker_archive: Vec::new(),
            // git clone / history options
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
            max_file_size_mb: 5.0,
            extraction_depth: 1,
            no_binary: true,
            no_extract_archives: false,
            exclude: Vec::new(), // Exclude patterns
        },
        confidence: ConfidenceLevel::Low,
        no_validate: true,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: Some(0.0),
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup,
        view_report: false,
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
        color: Mode::Never,
        progress: Mode::Never,
        no_update_check: false,
        self_update: false,
        ignore_certs: false,
        user_agent_suffix: None,
        tls_mode: TlsMode::Strict,
        allow_internal_ips: false,
        endpoint: Vec::new(),
        endpoint_config: None,
        config: None,
    };

    // ── load rules once ─────────────────────────────────────────────
    let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = Arc::new(RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?);
    let update_status = UpdateStatus::default();

    // Fresh FindingsStore for this run
    let store_path = work.path().join("store");
    fs::create_dir_all(&store_path)?;
    let datastore = Arc::new(Mutex::new(FindingsStore::new(store_path)));

    // run_async_scan is async – use the supplied Tokio runtime
    count_rt.block_on(run_async_scan(
        &global_args,
        &scan_args,
        Arc::clone(&datastore),
        &rules_db,
        &update_status,
        false,
    ))?;

    let x = Ok(datastore.lock().unwrap().get_matches().len());
    x
}

#[test]
fn test_dedup_branch() -> Result<()> {
    // A *single* runtime reused for both scans keeps the test fast
    let rt = Runtime::new().unwrap();

    let findings_with_dups = run_scan(&rt, true)?; // keep duplicates
    let findings_deduped = run_scan(&rt, false)?; // collapse duplicates

    assert!(
        findings_with_dups > findings_deduped,
        "expected deduplication to reduce finding count ({} -- {})",
        findings_with_dups,
        findings_deduped
    );
    assert_eq!(findings_deduped, 1, "exactly one unique finding should remain after dedup");

    Ok(())
}
