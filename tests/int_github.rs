// tests/int_github.rs
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
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
    git_url::GitUrl,
    scanner::{load_and_record_rules, run_scan},
    update::UpdateStatus,
};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use url::Url;
/// Helper function to determine exit code based on findings
fn determine_exit_code(total_findings: usize, validated_findings: usize) -> i32 {
    if total_findings == 0 {
        0 // No findings discovered
    } else if validated_findings > 0 {
        205 // Validated findings discovered
    } else {
        200 // Findings discovered but none validated
    }
}
#[test]
fn test_github_remote_scan() -> Result<()> {
    // Create a temporary directory for the scan
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let clone_dir = temp_dir.path().to_path_buf();
    // Create test repository URL
    let test_repo_url = "https://github.com/micksmix/SecretsTest.git";
    let git_url = GitUrl::from_str(test_repo_url).expect("Failed to parse Git URL");
    // Create scan arguments
    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: vec![git_url],
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
            max_file_size_mb: 25.0,
            no_extract_archives: false,
            extraction_depth: 2,
            no_binary: true,
            exclude: Vec::new(), // Exclude patterns
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: false,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true,
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
    // Create global arguments
    let global_args = GlobalArgs {
        verbose: 0,
        quiet: false,
        color: Mode::Auto,
        progress: Mode::Auto,
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
    // Create in-memory datastore
    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    // Create the runtime first
    let runtime = Runtime::new().expect("Failed to create Tokio runtime");
    // Load rules
    let rules_db =
        Arc::new(load_and_record_rules(&scan_args, &datastore, global_args.use_progress())?);
    let update_status = UpdateStatus::default();
    // Run the scan using runtime.block_on
    runtime.block_on(async {
        run_scan(&global_args, &scan_args, &rules_db, Arc::clone(&datastore), &update_status, false)
            .await
    })?;
    // Get scan results
    let ds = datastore.lock().unwrap();
    let matches = ds.get_matches();
    let total_findings = matches.len();
    let validated_findings = matches.iter().filter(|arc| arc.as_ref().2.validation_success).count();

    // Print validation statistics
    println!("Total findings: {}, Validated findings: {}", total_findings, validated_findings);
    // Check total number of findings
    assert!(total_findings >= 10, "Expected at least 10 findings, but got {}", total_findings);
    // Determine exit code
    let exit_code = determine_exit_code(total_findings, validated_findings);
    // Test passes if we found some kind of findings (exit code >= 200)
    assert!(
        exit_code >= 200,
        "Test failed: Expected to find vulnerabilities (exit code >= 200), got exit code {}",
        exit_code
    );
    // Drop the runtime explicitly here, outside of async context
    drop(runtime);
    Ok(())
}
