// ────────────────────────────────────────────────────────────
// Global allocator setup
//   * Default  - mimalloc             (no feature flags)
//   * Debug    - jemalloc (`use-jemalloc` feature)
//   * Fallback - system allocator     (`system-alloc` feature)
// ────────────────────────────────────────────────────────────

// --- jemalloc (opt-in) ---
#[cfg(feature = "use-jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// --- mimalloc (default) ---
#[cfg(all(not(feature = "use-jemalloc"), not(feature = "system-alloc")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// --- system allocator (explicit opt-out) ---
#[cfg(feature = "system-alloc")]
use std::alloc::System;
#[cfg(feature = "system-alloc")]
#[global_allocator]
static GLOBAL: System = System;

use std::{
    io::Read,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use kingfisher::{
    cli::{
        self,
        commands::{
            github::{
                GitCloneMode, GitHistoryMode, GitHubCommand, GitHubRepoType, GitHubReposCommand,
            },
            inputs::{ContentFilteringArgs, InputSpecifierArgs},
            output::{OutputArgs, ReportOutputFormat},
            rules::{
                RuleSpecifierArgs, RulesCheckArgs, RulesCommand, RulesListArgs,
                RulesListOutputFormat,
            },
        },
        global::Command,
        CommandLineArgs, GlobalArgs,
    },
    findings_store,
    findings_store::FindingsStore,
    github,
    rule_loader::RuleLoader,
    rules_database::RulesDatabase,
    scanner::{load_and_record_rules, run_scan},
};
use serde_json::json;
use tempfile::TempDir;
use term_size;
use tokio::runtime::Builder;
use tracing::{debug, error, warn};
use tracing_core::metadata::LevelFilter;
use tracing_subscriber::{
    self, fmt, prelude::__tracing_subscriber_SubscriberExt, registry, util::SubscriberInitExt,
};
use url::Url;

use crate::cli::commands::gitlab::{GitLabCommand, GitLabRepoType, GitLabReposCommand};

fn main() -> anyhow::Result<()> {
    color_backtrace::install();
    // Parse command-line arguments
    let args = CommandLineArgs::parse_args();

    // Determine the number of jobs, defaulting to the number of CPUs
    let num_jobs = match args.command {
        Command::Scan(ref scan_args) => scan_args.num_jobs,
        Command::GitHub(_) => num_cpus::get(), // Default for GitHub commands
        Command::GitLab(_) => num_cpus::get(), // Default for GitLab commands
        Command::Rules(_) => num_cpus::get(),  // Default for Rules commands
    };
    debug!("Running with {} worker threads.", num_jobs);
    // Set up the Tokio runtime with the specified number of threads
    let runtime = Builder::new_multi_thread()
        .worker_threads(num_jobs)
        .enable_all()
        .build()
        .context("Failed to create Tokio runtime")?;
    runtime.block_on(async_main(args))
}
fn setup_logging(global_args: &GlobalArgs) {
    // Determine log level based on global verbosity
    let (level, all_targets) = if global_args.quiet {
        (LevelFilter::ERROR, false)
    } else {
        let level = match global_args.verbose {
            0 => LevelFilter::INFO,  // Default level if no `-v` is provided
            1 => LevelFilter::DEBUG, // `-v`
            2 => LevelFilter::TRACE, // `-vv`
            _ => LevelFilter::TRACE, // `-vvv` or more
        };
        let all_targets = global_args.verbose > 2; // Enable all targets for `-vvv` or more
        (level, all_targets)
    };
    // Create a filter for logging
    let filter = if all_targets {
        // Enable TRACE for all modules
        tracing_subscriber::filter::Targets::new().with_default(LevelFilter::TRACE)
    } else {
        // Per-target filtering, only TRACE for `kingfisher`
        tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::ERROR) // Default for all modules
            .with_target("kingfisher", level) // Replace `kingfisher` with your
                                              // crate's name
    };
    // Configure the formatter layer
    let fmt_layer = fmt::layer()
        .with_writer(std::io::stderr) // Write logs to stderr
        .with_target(true) // Enable target filtering
        .with_ansi(false) // Disable colors
        .without_time(); // Remove timestamps
                         // Build and initialize the registry
    registry()
        .with(fmt_layer) // Attach the formatter layer
        .with(filter) // Attach the filter
        .init();
}

pub fn determine_exit_code(datastore: &Arc<Mutex<findings_store::FindingsStore>>) -> i32 {
    // exit with code 200 if _any_ findings are discovered
    // exit with code 205 if VALIDATED findings are discovered
    // exit with code 0 if there are NO findings discovered
    let ds = datastore.lock().unwrap();
    // Get all matches
    let all_matches = ds.get_matches();
    if all_matches.is_empty() {
        // No findings discovered
        0
    } else {
        // Check if there are any validated findings
        let validated_matches = all_matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = &***msg;
                match_item.validation_success
            })
            .count();
        if validated_matches > 0 {
            // Validated findings discovered
            205
        } else {
            // Findings discovered, but not validated
            200
        }
    }
}

async fn async_main(args: CommandLineArgs) -> Result<()> {
    // Create a temporary directory
    let temp_dir = TempDir::new().context("Failed to create temporary directory")?;
    let clone_dir = temp_dir.path().to_path_buf();

    // Create the in-memory datastore
    let datastore = Arc::new(Mutex::new(FindingsStore::new(clone_dir)));
    setup_logging(&args.global_args);
    match args.command {
        Command::Scan(mut scan_args) => {
            // —————————————————————————————————————————
            // If no paths or a single "-", slurp stdin into a temp file
            // —————————————————————————————————————————
            let paths = &scan_args.input_specifier_args.path_inputs;
            let is_dash = paths.iter().any(|p| p.as_os_str() == "-");
            if (paths.is_empty() || is_dash) && !atty::is(atty::Stream::Stdin) {
                // read all stdin
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                // write into temp_dir
                let stdin_file = temp_dir.path().join("stdin_input");
                std::fs::write(&stdin_file, buf)?;
                // replace inputs
                scan_args.input_specifier_args.path_inputs = vec![stdin_file.into()];
            }

            // now proceed exactly as before
            let rules_db = Arc::new(load_and_record_rules(&scan_args, &datastore)?);
            run_scan(&args.global_args, &scan_args, &rules_db, Arc::clone(&datastore)).await?;
            let exit_code = determine_exit_code(&datastore);
            std::process::exit(exit_code);
        }
        Command::Rules(ref rule_args) => match &rule_args.command {
            RulesCommand::Check(check_args) => {
                run_rules_check(&check_args)?;
            }
            RulesCommand::List(list_args) => {
                run_rules_list(&list_args)?;
            }
        },
        Command::GitHub(github_args) => match github_args.command {
            GitHubCommand::Repos(repos_command) => match repos_command {
                GitHubReposCommand::List(list_args) => {
                    github::list_repositories(
                        github_args.github_api_url,
                        args.global_args.ignore_certs,
                        args.global_args.use_progress(),
                        &list_args.repo_specifiers.user,
                        &list_args.repo_specifiers.organization,
                        list_args.repo_specifiers.all_organizations,
                        list_args.repo_specifiers.repo_type.into(),
                    )
                    .await?;
                }
            },
        },
        Command::GitLab(gitlab_args) => match gitlab_args.command {
            GitLabCommand::Repos(repos_command) => match repos_command {
                GitLabReposCommand::List(list_args) => {
                    kingfisher::gitlab::list_repositories(
                        gitlab_args.gitlab_api_url,
                        args.global_args.ignore_certs,
                        args.global_args.use_progress(),
                        &list_args.repo_specifiers.user,
                        &list_args.repo_specifiers.group,
                        list_args.repo_specifiers.all_groups,
                        list_args.repo_specifiers.repo_type.into(),
                    )
                    .await?;
                }
            },
        },
    }
    Ok(())
}

/// Create a default ScanArgs instance for rule loading
fn create_default_scan_args() -> cli::commands::scan::ScanArgs {
    use cli::commands::scan::*;
    ScanArgs {
        num_jobs: 1,
        rules: RuleSpecifierArgs {
            rules_path: Vec::new(),
            rule: vec!["all".into()],
            load_builtins: true,
        },
        input_specifier_args: InputSpecifierArgs {
            path_inputs: Vec::new(),
            git_url: Vec::new(),
            github_user: Vec::new(),
            github_organization: Vec::new(),
            all_github_organizations: false,
            github_api_url: url::Url::parse("https://api.github.com/").unwrap(),
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
            no_extract_archives: true,
            extraction_depth: 2,
            ignore: Vec::new(),
            no_binary: true,
        },
        confidence: ConfidenceLevel::Medium,
        no_validate: true,
        rule_stats: false,
        only_valid: false,
        min_entropy: None,
        redact: false,
        git_repo_timeout: 1800,
        no_dedup: false,
        snippet_length: 256,
        output_args: OutputArgs { output: None, format: ReportOutputFormat::Pretty },
    }
}
/// Run the rules check command
pub fn run_rules_check(args: &RulesCheckArgs) -> Result<()> {
    let mut num_errors = 0;
    let mut num_warnings = 0;
    // Load and check rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let rules_db = RulesDatabase::from_rules(resolved.into_iter().cloned().collect())?;

    // Check each rule
    for (rule_index, rule) in rules_db.rules().iter().enumerate() {
        let rule_syntax = rule.syntax();
        // Basic rule validation checks
        if rule.name().len() < 3 {
            warn!("Rule '{}' has a very short name", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().pattern.len() < 5 {
            warn!("Rule '{}' has a very short pattern", rule.name());
            num_warnings += 1;
        }
        if rule.syntax().examples.is_empty() {
            warn!("Rule '{}' has no examples", rule.name());
            num_warnings += 1;
            continue;
        }
        // Check regex compilation
        if let Err(e) = rule.syntax().as_regex() {
            error!("Rule '{}' has invalid regex: {}", rule.name(), e);
            num_errors += 1;
            continue;
        }
        // Test each example against both vectorscan and regex
        for (example_index, example) in rule_syntax.examples.iter().enumerate() {
            // Create a test blob from the example
            // let blob = Blob::new(BlobId::new(example.as_bytes()),
            // example.as_bytes().to_vec()); let origin = OriginSet::new(
            //     Origin::from_file(PathBuf::from("test_example")),
            //     Vec::new(),
            // );
            // // Check vectorscan match
            // let vectorscan_matched = match matcher.scan_blob(&blob, &origin, None)? {
            //     ScanResult::New(matches) => !matches.is_empty(),
            //     _ => false,
            // };
            // Check regex match
            // Get the regex using the public method
            let re =
                rules_db.get_regex_by_rule_id(rule.id()).expect("Failed to get regex for rule");
            let regex_matched = re.is_match(example.as_bytes());
            if !regex_matched {
                // ||!vectorscan_matched  {
                println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                println!("  Processing example {}", example_index + 1);
                println!("    [!] Mismatch detected for example: {}", example);
                // if !vectorscan_matched {
                //     println!("    Vectorscan match: {}", vectorscan_matched);
                //     num_errors += 1;
                // }
                if !regex_matched {
                    println!("    Regex match: {}", regex_matched);
                    num_errors += 1;
                }
            }

            // // Report any mismatches
            // if !vectorscan_matched || !regex_matched {
            //     error!("Rule '{}' example {} failed validation:",
            // rule.name(), example_index + 1);     println!("
            // Example text: {}", example);

            //     if !vectorscan_matched {
            //         error!("  - Vectorscan pattern did not match example");
            //         num_errors += 1;
            //     }

            //     if !regex_matched {
            //         error!("  - Regex pattern did not match example");
            //         num_errors += 1;
            //     }
            // }
        }
    }
    // Print summary
    if num_errors > 0 || num_warnings > 0 {
        println!("\nCheck Summary:");
        println!("  Errors: {}", num_errors);
        println!("  Warnings: {}", num_warnings);
        println!("\nError types include:");
        println!("  - Invalid regex patterns");
        println!("  - Examples that don't match their patterns");
        println!("\nWarning types include:");
        println!("  - Rules with very short names");
        println!("  - Rules with very short patterns");
        println!("  - Rules without examples");
    } else {
        println!("\nAll rules passed validation successfully!");
    }
    // Exit with error if there are errors or if warnings are treated as errors
    if num_errors > 0 || (args.warnings_as_errors && num_warnings > 0) {
        std::process::exit(1);
    }
    Ok(())
}
/// Run the rules list command
pub fn run_rules_list(args: &RulesListArgs) -> Result<()> {
    // Load rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args())?;
    let resolved = loaded.resolve_enabled_rules()?;
    let mut writer = args.output_args.get_writer()?;
    match args.output_args.format {
        RulesListOutputFormat::Pretty => {
            // Determine terminal width if possible, otherwise use default
            let term_width = term_size::dimensions().map(|(w, _)| w).unwrap_or(120);
            // First pass: calculate column widths
            let max_name_width = resolved.iter().map(|r| r.name().len()).max().unwrap_or(0).max(4); // "Rule" header
            let max_id_width = resolved.iter().map(|r| r.id().len()).max().unwrap_or(0).max(2); // "ID" header
            let max_conf_width = resolved
                .iter()
                .map(|r| format!("{:?}", r.confidence()).len())
                .max()
                .unwrap_or(0)
                .max(10); // "Confidence" header
                          // Calculate pattern width based on terminal width
            let reserved_width = max_name_width + max_id_width + max_conf_width + 10;
            let pattern_width = term_width.saturating_sub(reserved_width);
            // Format pattern on a single line
            let format_pattern = |pattern: &str| {
                let single_line = pattern
                    .replace('\n', " ")
                    .replace('\r', " ")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if single_line.len() > pattern_width {
                    format!("{}...", &single_line[..pattern_width.saturating_sub(3)])
                } else {
                    single_line
                }
            };
            // Print header
            writeln!(
                writer,
                "\n{:name_width$} │ {:id_width$} │ {:conf_width$} │ Pattern",
                "Rule",
                "ID",
                "Confidence",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width
            )?;
            // Print separator
            writeln!(
                writer,
                "{0:─<name_width$} ┼ {0:─<id_width$} ┼ {0:─<conf_width$} ┼ {0:─<pattern_width$}",
                "",
                name_width = max_name_width,
                id_width = max_id_width,
                conf_width = max_conf_width,
                pattern_width = pattern_width
            )?;
            // Print each rule
            for rule in resolved {
                let formatted_pattern = format_pattern(&rule.syntax().pattern);
                writeln!(
                    writer,
                    "{:name_width$} │ {:id_width$} │ {:conf_width$} │ {}",
                    rule.name(),
                    rule.id(),
                    format!("{:?}", rule.confidence()),
                    formatted_pattern,
                    name_width = max_name_width,
                    id_width = max_id_width,
                    conf_width = max_conf_width
                )?;
            }
            writeln!(writer)?;
        }
        RulesListOutputFormat::Json => {
            // Create JSON format
            let rules_json: Vec<_> = resolved
                .iter()
                .map(|rule| {
                    json!({
                        "name": rule.name(),
                        "id": rule.id(),
                        "pattern": rule.syntax().pattern,
                        "confidence": rule.confidence(),
                        "examples": rule.syntax().examples,
                        "visible": rule.visible(),
                    })
                })
                .collect();
            serde_json::to_writer_pretty(&mut writer, &rules_json)?;
            writeln!(writer)?;
        }
    }
    Ok(())
}
