// tests/int_validation_cache.rs
use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
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
            rules::{RuleCacheArgs, RuleSpecifierArgs},
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
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test]
async fn test_validation_cache_and_depvars() -> Result<()> {
    check_validation_cache_and_depvars(false, false, false).await?;
    check_validation_cache_and_depvars(true, false, false).await?;
    check_validation_cache_and_depvars(true, true, false).await?;
    check_validation_cache_and_depvars(false, false, true).await
}

async fn check_validation_cache_and_depvars(
    different_dependencies: bool,
    named_context: bool,
    spill_across_chunks: bool,
) -> Result<()> {
    /* --------------------------------------------------------- *
     * 1. Spin-up Wiremock and count incoming validation calls  *
     * --------------------------------------------------------- */
    let server = MockServer::start().await;
    let hit_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&hit_counter);

    Mock::given(method("GET"))
        .and(path("/validate"))
        .respond_with(move |req: &Request| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            let rejected = req.url.query_pairs().any(|(_, value)| value == "component_rejected");
            ResponseTemplate::new(200).set_body_string(if rejected {
                "{\"error_code\":\"403003\"}"
            } else {
                "ok"
            })
        })
        .mount(&server)
        .await;

    /* --------------------------------------------------------- *
     * 2. Synthetic rules exercising depends_on_rule + HTTP val *
     * --------------------------------------------------------- */
    let helper_pattern =
        if different_dependencies { "(component_[a-z]+)" } else { "(demokey_[a-z0-9]{8})" };
    let validation_variable =
        if different_dependencies { "{{ COMPONENT }}" } else { "{{ TOKEN }}" };
    let dependencies = if named_context {
        ""
    } else {
        "        depends_on_rule:\n          - rule_id: demo.key.1\n            variable: COMPONENT\n"
    };
    let primary_pattern = if named_context {
        r"(demokey_[a-z0-9]{8})\s+(?P<COMPONENT>component_[a-z]+)"
    } else {
        r"(demokey_[a-z0-9]{8})"
    };
    let rules_yaml = format!(
        r#"
    rules:
      - name: Demo API Key
        id: demo.key.1
        pattern: '{helper_pattern}'
        confidence: low
        min_entropy: 0.0
    
      - name: Demo API Key Validation
        id: demo.key.validation.1
{dependencies}        pattern: '{primary_pattern}'
        confidence: low
        validation:
          type: Http
          content:
            request:
              method: GET
              url: '{base}/validate?token={validation_variable}'
              response_matcher:
                  - report_response: true
                  - type: WordMatch
                    words:
                      - '"error_code":"403003"'
                    negative: true
    "#,
        base = server.uri()
    );

    /* --------------------------------------------------------- *
     * 3. Temp workspace:  rules file + input with 2 duplicates *
     * --------------------------------------------------------- */
    let work_dir = TempDir::new()?;
    let rules_file = work_dir.path().join("demo.yml");
    fs::write(&rules_file, rules_yaml)?;

    let secret_file = work_dir.path().join("secrets.txt");
    let mut input_files = vec![secret_file.clone()];
    if different_dependencies {
        fs::write(&secret_file, "demokey_abcdefgh\ncomponent_accepted")?;
        let other_file = work_dir.path().join("other.txt");
        fs::write(&other_file, "demokey_abcdefgh\ncomponent_rejected")?;
        input_files.push(other_file);
    } else {
        fs::write(&secret_file, "demokey_abcdefgh\ndemokey_abcdefgh")?;
    }

    if spill_across_chunks {
        // num_jobs=2 uses validation chunks of 200 blobs. Cross the boundary
        // with duplicates and dependency helpers in every blob.
        for index in 1..205 {
            let file = work_dir.path().join(format!("chunk-{index}.txt"));
            fs::write(&file, format!("# fixture {index}\ndemokey_abcdefgh\ndemokey_abcdefgh"))?;
            input_files.push(file);
        }
    }

    /* --------------------------------------------------------- *
     * 4. Build Scan / Global args (no_dedup=true to keep dups) *
     * --------------------------------------------------------- */
    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: vec![work_dir.path().to_path_buf()],
            rule: vec!["all".into()],
            exclude_rule: Vec::new(),
            load_builtins: false,
        },
        rule_cache: RuleCacheArgs::default(),
        input_specifier_args: InputSpecifierArgs {
            path_inputs: input_files,
            git_url: Vec::new(),
            git_clone_dir: None,
            keep_clones: false,
            repo_clone_limit: None,
            include_contributors: false,
            github_user: Vec::new(),
            github_include_gists: false,
            github_organization: Vec::new(),
            github_exclude: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            github_event_user: Vec::new(),
            github_event_lookback_hours: 24,

            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_include_snippets: false,
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
            huggingface_bucket: Vec::new(),
            huggingface_exclude: Vec::new(),

            gitea_user: Vec::new(),
            gitea_organization: Vec::new(),
            gitea_exclude: Vec::new(),
            all_gitea_organizations: false,
            gitea_api_url: Url::parse("https://gitea.com/api/v1/").unwrap(),
            gitea_repo_type: GiteaRepoType::Source,

            bitbucket_user: Vec::new(),
            bitbucket_include_snippets: false,
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
            extraction_depth: 2,
            no_binary: true,
            no_extract_archives: false,
            exclude: Vec::new(), // Exclude patterns
        },
        confidence: ConfidenceLevel::Low,
        disk_offload: spill_across_chunks,
        no_validate: false,
        access_map: false,
        rule_stats: false,
        only_valid: false,
        validation_filter: None,
        include_hidden_findings: false,
        min_entropy: Some(0.0),
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        audit_log: None,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true, // keep duplicates so the cache is stressed
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
        alert_finding_filter: kingfisher::alerts::AlertFindingFilter::All,
        alert_prevent_empty: false,
        alert_dry_run: false,
        config_webhook_overrides: Vec::new(),
    };

    /* --------------------------------------------------------- *
     * 5. Load rules, run scan                                  *
     * --------------------------------------------------------- */
    // ---------------------------------------------------------
    // 5. Load rules, record them, run scan
    // ---------------------------------------------------------
    let loaded = RuleLoader::from_rule_specifiers(&scan_args.rules).load(&scan_args)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = Arc::new(RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?);

    let datastore = Arc::new(Mutex::new(FindingsStore::new(work_dir.path().to_path_buf())));

    // NEW: make the datastore aware of every rule
    {
        let mut ds = datastore.lock().unwrap();
        ds.record_rules(rules_db.rules()); // <-- **add this line**
    }

    let global_args = GlobalArgs {
        verbose: 0,
        quiet: true,
        color: Mode::Auto,
        progress: Mode::Never,
        no_update_check: false,
        self_update: false,
        ignore_certs: false,
        user_agent_suffix: None,
        tls_mode: TlsMode::Strict,
        allow_internal_ips: true,
        endpoint: Vec::new(),
        endpoint_config: None,
        config: None,
    };
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

    /* --------------------------------------------------------- *
     * 6. Assertions                                             *
     * --------------------------------------------------------- */
    // Repeated credentials share a request only when their dependencies also match.
    assert_eq!(
        hit_counter.load(Ordering::SeqCst),
        if different_dependencies { 2 } else { 1 },
        "each distinct credential and dependency pair should be validated once"
    );

    let ds = datastore.lock().unwrap();
    for entry in ds.get_matches() {
        if entry.2.rule.syntax().id == "demo.key.validation.1" {
            if different_dependencies {
                let accepted_blob =
                    kingfisher::blob::BlobId::new(b"demokey_abcdefgh\ncomponent_accepted");
                let accepted = entry.2.blob_id == accepted_blob;
                assert_eq!(entry.2.validation_success, accepted);
                assert_eq!(
                    if named_context {
                        entry
                            .2
                            .groups
                            .captures
                            .iter()
                            .find(|capture| capture.name == Some("COMPONENT"))
                            .map(|capture| capture.raw_value())
                    } else {
                        entry.2.dependent_captures.get("COMPONENT").map(String::as_str)
                    },
                    Some(if accepted { "component_accepted" } else { "component_rejected" }),
                );
                continue;
            }
            assert_eq!(
                entry.2.dependent_captures.get("COMPONENT").map(String::as_str),
                Some("demokey_abcdefgh"),
                "every dependent occurrence must retain its selected token"
            );
        }
    }
    let total_matches = ds.get_matches().len();
    assert_eq!(
        total_matches,
        if spill_across_chunks { 4 * 205 } else { 4 },
        "expected 2 matches per rule per blob (dup secrets)"
    ); // 2 for each rule

    Ok(())
}
