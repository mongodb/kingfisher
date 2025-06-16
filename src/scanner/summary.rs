use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use http::StatusCode;
use indicatif::HumanBytes;
use serde_json::json;
use thousands::Separable;
use tokio::time::Instant;
use tracing::debug;

use crate::{
    cli::{
        commands::{output::ReportOutputFormat, scan},
        global,
    },
    findings_store,
    matcher::MatcherStats,
    rules_database::RulesDatabase,
};

macro_rules! safe_println {
    ($($arg:tt)*) => {
        if let Err(e) = writeln!(io::stdout(), $($arg)*) {
            if e.kind() == io::ErrorKind::BrokenPipe {
                // Silently exit: the consumer went away
                std::process::exit(0);
            } else {
                // Unexpected I/O error – keep the old behaviour
                panic!("stdout error: {}", e);
            }
        }
    };
}

pub fn print_scan_summary(
    start_time: Instant,
    datastore: &Arc<Mutex<findings_store::FindingsStore>>,
    _global_args: &global::GlobalArgs,
    args: &scan::ScanArgs,
    // inputs: &FilesystemEnumeratorResult,
    rules_db: &RulesDatabase,
    matcher_stats: &Mutex<MatcherStats>,
) {
    // let duration = start_time.elapsed();
    let ds = datastore.lock().unwrap();

    let num_rules = rules_db.num_rules();
    let findings_by_rule = ds.get_summary();
    let mut sorted_findings: Vec<_> = findings_by_rule.into_iter().collect();
    sorted_findings.sort_by(|a, b| b.1.cmp(&a.1));
    let duration = start_time.elapsed();
    // let ds = datastore.lock().unwrap();

    // Get all matches
    let all_matches = ds.get_matches();

    // Count total findings
    let total_findings = if args.no_dedup {
        // When no_dedup is true, count each origin of validated matches as a separate finding
        all_matches.iter().fold(0, |count, msg| {
            let (origin_set, _, match_item) = &**msg;
            // If this is a validated match, count each origin as a separate finding
            if match_item.validation_success {
                count + origin_set.len()
            } else {
                count + 1
            }
        })
    } else {
        ds.get_num_matches()
    };
    // Count successful and failed validations
    let (successful_validations, failed_validations) =
        all_matches.iter().fold((0, 0), |(success, fail), msg| {
            let (origin_set, _, match_item) = &**msg;
            if match_item.validation_success {
                if match_item.validation_response_status != StatusCode::CONTINUE.as_u16() {
                    if args.no_dedup {
                        // Count each origin of a successful validation as a separate success
                        (success + origin_set.len(), fail)
                    } else {
                        (success + 1, fail)
                    }
                } else {
                    (success, fail)
                }
            } else {
                if match_item.validation_response_status != StatusCode::CONTINUE.as_u16() {
                    (success, fail + 1)
                } else {
                    (success, fail)
                }
            }
        });
    let matcher_stats = matcher_stats.lock().unwrap();

    // Generate JSON or JSONL output
    if args.output_args.format == ReportOutputFormat::Json
        || args.output_args.format == ReportOutputFormat::Jsonl
    {
        let summary = json!({
            "findings": total_findings,
            "successful_validations": successful_validations,
            "failed_validations": failed_validations,
            "rules_applied": num_rules,
            // "git_repositories": num_git_repos,
            // "commits": num_commits,
            "blobs_scanned": matcher_stats.blobs_scanned,
            // "files_read": num_files,
            "bytes_scanned": matcher_stats.bytes_scanned,
            "scan_duration": duration.as_secs_f64(),
            "findings_by_rule": sorted_findings
        });
        // only printing to stdout, not to the file itself
        safe_println!("{}", summary.to_string());
    } else if args.output_args.format == ReportOutputFormat::Pretty
        || args.output_args.output.is_some()
    {
        safe_println!("\n==========================================");
        safe_println!("Scan Summary:");
        safe_println!("==========================================");
        safe_println!(" |Findings....................: {}", total_findings.separate_with_commas());
        safe_println!(
            " |__Successful Validations....: {}",
            successful_validations.separate_with_commas()
        );
        safe_println!(
            " |__Failed Validations........: {}",
            failed_validations.separate_with_commas()
        );
        safe_println!(" |Rules Applied...............: {}", num_rules.separate_with_commas());
        // safe_println!(" |Git Repositories............: {}",
        // num_git_repos.separate_with_commas()); safe_println!(
        //     "|__Commits...................: {}",
        //     num_commits.separate_with_commas()
        // );
        safe_println!(
            " |__Blobs Scanned.............: {}",
            matcher_stats.blobs_scanned.separate_with_commas()
        );
        // safe_println!(" |Files Read..................: {}",
        // num_files.separate_with_commas());
        safe_println!(
            " |Bytes Scanned...............: {}",
            HumanBytes(matcher_stats.bytes_scanned)
        );
        safe_println!(
            " |Scan Duration...............: {}",
            // HumanDuration(duration),
            humantime::format_duration(duration)
        );
    }
    debug!("\nAll Rules with Matches:");
    debug!("=======================");
    let max_rule_length = sorted_findings.iter().map(|(rule, _)| rule.len()).max().unwrap_or(0);
    for (rule, count) in sorted_findings {
        debug!("{: <width$}: {}", rule, count, width = max_rule_length);
    }
}
