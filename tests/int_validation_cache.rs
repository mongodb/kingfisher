// tests/int_validation_cache.rs
use std::{
    fs,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
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
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::run_async_scan,
};
use tempfile::TempDir;
use url::Url;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, Request, ResponseTemplate,
};

#[tokio::test]
async fn test_validation_cache_and_depvars() -> Result<()> {
    /* --------------------------------------------------------- *
     * 1. Spin-up Wiremock and count incoming validation calls  *
     * --------------------------------------------------------- */
    let server = MockServer::start().await;
    let hit_counter = Arc::new(AtomicUsize::new(0));
    let counter_clone = Arc::clone(&hit_counter);

    Mock::given(method("GET"))
        .and(path("/validate"))
        .respond_with(move |_req: &Request| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(200).set_body_string("ok")
        })
        .mount(&server)
        .await;

    /* --------------------------------------------------------- *
     * 2. Synthetic rules exercising depends_on_rule + HTTP val *
     * --------------------------------------------------------- */
    let rules_yaml = format!(
        r#"
    rules:
      - name: Demo API Key
        id: demo.key.1
        pattern: '(demokey_[a-z0-9]{{8}})'
        confidence: low
        min_entropy: 0.0
    
      - name: Demo API Key Validation
        id: demo.key.validation.1
        depends_on_rule:
          - rule_id: demo.key.1
            variable: TOKEN
        pattern: '(demokey_[a-z0-9]{{8}})'
        confidence: low
        validation:
          type: Http
          content:
            request:
              method: GET
              url: '{base}/validate?token={{ {{ TOKEN }} }}'
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
    fs::write(&secret_file, "demokey_abcdefgh\ndemokey_abcdefgh")?;

    /* --------------------------------------------------------- *
     * 4. Build Scan / Global args (no_dedup=true to keep dups) *
     * --------------------------------------------------------- */
    let scan_args = ScanArgs {
        num_jobs: 2,
        rules: RuleSpecifierArgs {
            rules_path: vec![work_dir.path().to_path_buf()],
            rule: vec!["all".into()],
            load_builtins: false,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: vec![secret_file.clone()],
            git_url: Vec::new(),
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
            extraction_depth: 2,
            no_binary: true,
            no_extract_archives: false,
            ignore: Vec::new(),
        },
        confidence: ConfidenceLevel::Low,
        no_validate: false,
        rule_stats: false,
        only_valid: false,
        min_entropy: Some(0.0),
        redact: false,
        git_repo_timeout: 1800, // 30 minutes
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
        no_dedup: true, // keep duplicates so the cache is stressed
        snippet_length: 128,
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
        ignore_certs: false,
        advanced: AdvancedArgs { rlimit_nofile: 8192 },
    };

    run_async_scan(&global_args, &scan_args, Arc::clone(&datastore), &rules_db).await?;

    /* --------------------------------------------------------- *
     * 6. Assertions                                             *
     * --------------------------------------------------------- */
    // There are two matches for demo.key.validation.1, but the validator
    // should have been called only once thanks to SkipMap caching.
    assert_eq!(
        hit_counter.load(Ordering::SeqCst),
        1,
        "validator endpoint should be hit exactly once"
    );

    let ds = datastore.lock().unwrap();
    let total_matches = ds.get_matches().len();
    assert_eq!(total_matches, 4, "expected 2 matches per rule (dup secrets)"); // 2 for each rule

    Ok(())
}
