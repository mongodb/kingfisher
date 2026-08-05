use clap::Parser;

use kingfisher::cli::{
    commands::scan::{ScanOperation, UNLIMITED_RESULTS},
    global::{Command, CommandLineArgs},
};

fn scan_args_from(argv: &[&str]) -> anyhow::Result<kingfisher::cli::commands::scan::ScanArgs> {
    let args = CommandLineArgs::try_parse_from(argv)?;

    let command = match args.command {
        Command::Scan(scan_args) => scan_args,
        other => panic!("unexpected command parsed: {:?}", other),
    };

    match command.into_operation()? {
        ScanOperation::Scan(scan_args) => Ok(scan_args),
        op => panic!("expected scan operation, got {:?}", op),
    }
}

#[test]
fn jira_all_lifts_the_result_limit() -> anyhow::Result<()> {
    let scan_args = scan_args_from(&[
        "kingfisher",
        "scan",
        "jira",
        "--url",
        "https://example.atlassian.net",
        "--jql",
        "project = TEST",
        "--all",
        "--no-update-check",
    ])?;

    assert_eq!(scan_args.input_specifier_args.max_results, UNLIMITED_RESULTS);

    Ok(())
}

#[test]
fn confluence_all_lifts_the_result_limit() -> anyhow::Result<()> {
    let scan_args = scan_args_from(&[
        "kingfisher",
        "scan",
        "confluence",
        "--url",
        "https://example.atlassian.net/wiki",
        "--cql",
        "label = secret",
        "--all",
        "--no-update-check",
    ])?;

    assert_eq!(scan_args.input_specifier_args.max_results, UNLIMITED_RESULTS);

    Ok(())
}

#[test]
fn jira_defaults_to_a_bounded_result_limit() -> anyhow::Result<()> {
    let scan_args = scan_args_from(&[
        "kingfisher",
        "scan",
        "jira",
        "--url",
        "https://example.atlassian.net",
        "--jql",
        "project = TEST",
        "--no-update-check",
    ])?;

    assert_eq!(scan_args.input_specifier_args.max_results, 100);

    Ok(())
}

#[test]
fn jira_all_conflicts_with_an_explicit_max_results() {
    // The default value of `--max-results` must not trigger the conflict, but
    // passing both explicitly is contradictory and should be rejected.
    let err = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "jira",
        "--url",
        "https://example.atlassian.net",
        "--jql",
        "project = TEST",
        "--all",
        "--max-results",
        "5",
        "--no-update-check",
    ])
    .expect_err("--all and --max-results must conflict");

    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn confluence_all_conflicts_with_an_explicit_max_results() {
    let err = CommandLineArgs::try_parse_from([
        "kingfisher",
        "scan",
        "confluence",
        "--url",
        "https://example.atlassian.net/wiki",
        "--cql",
        "label = secret",
        "--all",
        "--max-results",
        "5",
        "--no-update-check",
    ])
    .expect_err("--all and --max-results must conflict");

    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}
