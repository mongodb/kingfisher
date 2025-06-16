// tests/int_github.rs
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use kingfisher::{
    cli::{
        commands::{
            github::{GitCloneMode, GitHistoryMode, GitHubRepoType},
            gitlab::GitLabRepoType,
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::RuleSpecifierArgs,
            scan::{ConfidenceLevel, ScanArgs},
        },
        global::{AdvancedArgs, Mode},
        GlobalArgs,
    },
    findings_store::FindingsStore,
    git_url::GitUrl,
    scanner::{load_and_record_rules, run_scan},
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
            github_user: Vec::new(),
            github_organization: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/").unwrap(),
            github_repo_type: GitHubRepoType::Source,
            // new GitLab defaults
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/").unwrap(),
            gitlab_repo_type: GitLabRepoType::Owner,

            // git clone / history options
            git_clone: GitCloneMode::Bare,
            git_history: GitHistoryMode::Full,
            scan_nested_repos: true,
            commit_metadata: true,
        },
        content_filtering_args: ContentFilteringArgs {
            max_file_size_mb: 25.0,
            no_extract_archives: false,
            extraction_depth: 2,
            no_binary: true,
            ignore: Vec::new(),
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true,
        snippet_length: 256,
    };
    // Create global arguments
    let global_args = GlobalArgs {
        verbose: 0,
        quiet: false,
        color: Mode::Auto,
        progress: Mode::Auto,
        ignore_certs: false,
        advanced: AdvancedArgs { rlimit_nofile: 16384 },
    };
    // Create in-memory datastore
    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    // Create the runtime first
    let runtime = Runtime::new().expect("Failed to create Tokio runtime");
    // Load rules
    let rules_db = Arc::new(load_and_record_rules(&scan_args, &datastore)?);
    // Run the scan using runtime.block_on
    runtime.block_on(async {
        run_scan(&global_args, &scan_args, &rules_db, Arc::clone(&datastore)).await
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
