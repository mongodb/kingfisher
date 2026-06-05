// tests/int_gitlab.rs
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

/// Derive process exit-codes from findings
fn determine_exit_code(total: usize, validated: usize) -> i32 {
    match (total, validated) {
        (0, _) => 0,
        (_, v) if v > 0 => 205,
        _ => 200,
    }
}

#[test]
fn test_gitlab_remote_scan() -> Result<()> {
    let temp_dir = TempDir::new().context("tmp dir")?;
    let clone_dir = temp_dir.path().to_path_buf();

    // Public GitLab repo seeded with test secrets
    let test_repo_url = "https://gitlab.com/micksmix/SecretsTest.git";
    let git_url = GitUrl::from_str(test_repo_url).expect("parse GitLab URL");

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
            github_api_url: Url::parse("https://api.github.com/")?,
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/")?,
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
            gitea_api_url: Url::parse("https://gitea.com/api/v1/")?,
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/")?,
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),

            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/")?,
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
        extra_ignore_comments: Vec::new(),
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

    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    let rt = Runtime::new()?;

    let rules_db =
        Arc::new(load_and_record_rules(&scan_args, &datastore, global_args.use_progress())?);
    let update_status = UpdateStatus::default();

    rt.block_on(async {
        run_scan(&global_args, &scan_args, &rules_db, Arc::clone(&datastore), &update_status, false)
            .await
    })?;

    let ds = datastore.lock().unwrap();
    let findings = ds.get_matches();
    let total = findings.len();
    let validated = findings.iter().filter(|m| m.as_ref().2.validation_success).count();

    assert!(total >= 10, "expected at least 10 findings from GitLab repo, got {total}");

    let exit_code = determine_exit_code(total, validated);
    assert!(
        exit_code >= 200,
        "expected kingfisher to report findings (exit_code >= 200), got {exit_code}"
    );

    drop(rt);
    Ok(())
}

#[test]
fn test_gitlab_remote_scan_no_history() -> Result<()> {
    let temp_dir = TempDir::new().context("tmp dir")?;
    let clone_dir = temp_dir.path().to_path_buf();

    let test_repo_url = "https://gitlab.com/micksmix/SecretsTest.git";
    let git_url = GitUrl::from_str(test_repo_url).expect("parse GitLab URL");

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
            github_api_url: Url::parse("https://api.github.com/")?,
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            gitlab_exclude: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/")?,
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
            gitea_api_url: Url::parse("https://gitea.com/api/v1/")?,
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_workspace: Vec::new(),
            bitbucket_project: Vec::new(),
            bitbucket_exclude: Vec::new(),
            all_bitbucket_workspaces: false,
            bitbucket_api_url: Url::parse("https://api.bitbucket.org/2.0/")?,
            bitbucket_repo_type: BitbucketRepoType::Source,
            bitbucket_auth: BitbucketAuthArgs::default(),

            azure_organization: Vec::new(),
            azure_project: Vec::new(),
            azure_exclude: Vec::new(),
            all_azure_projects: false,
            azure_base_url: Url::parse("https://dev.azure.com/")?,
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
            s3_bucket: None,
            s3_prefix: None,
            role_arn: None,
            aws_local_profile: None,
            docker_image: Vec::new(),
            docker_archive: Vec::new(),
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::None,
            commit_metadata: true,
            repo_artifacts: false,
            scan_nested_repos: true,
            since_commit: None,
            branch: None,
            branch_root: false,
            branch_root_commit: None,
            gcs_bucket: None,
            gcs_prefix: None,
            gcs_service_account: None,
            staged: false,
        },
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: false,
            extraction_depth: 2,
            no_binary: true,
            exclude: Vec::new(),
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: false,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
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

    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    let rt = Runtime::new()?;

    let rules_db =
        Arc::new(load_and_record_rules(&scan_args, &datastore, global_args.use_progress())?);
    let update_status = UpdateStatus::default();

    rt.block_on(async {
        run_scan(&global_args, &scan_args, &rules_db, Arc::clone(&datastore), &update_status, false)
            .await
    })?;

    let ds = datastore.lock().unwrap();
    let findings = ds.get_matches();
    let total = findings.len();
    let validated = findings.iter().filter(|m| m.as_ref().2.validation_success).count();

    assert!(total >= 10, "expected at least 10 findings from GitLab repo, got {total}");

    let exit_code = determine_exit_code(total, validated);
    assert!(
        exit_code >= 200,
        "expected kingfisher to report findings (exit_code >= 200), got {exit_code}"
    );

    drop(rt);
    Ok(())
}
