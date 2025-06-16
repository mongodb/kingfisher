// tests/int_gitlab.rs
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
            github_user: Vec::new(),
            github_organization: Vec::new(),
            all_github_organizations: false,
            github_api_url: Url::parse("https://api.github.com/")?,
            github_repo_type: GitHubRepoType::Source,
            gitlab_user: Vec::new(),
            gitlab_group: Vec::new(),
            all_gitlab_groups: false,
            gitlab_api_url: Url::parse("https://gitlab.com/")?,
            gitlab_repo_type: GitLabRepoType::Owner,
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

    let global_args = GlobalArgs {
        verbose: 0,
        quiet: false,
        color: Mode::Auto,
        progress: Mode::Auto,
        ignore_certs: false,
        advanced: AdvancedArgs { rlimit_nofile: 16_384 },
    };

    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    let rt = Runtime::new()?;

    let rules_db = Arc::new(load_and_record_rules(&scan_args, &datastore)?);

    rt.block_on(async {
        run_scan(&global_args, &scan_args, &rules_db, Arc::clone(&datastore)).await
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
