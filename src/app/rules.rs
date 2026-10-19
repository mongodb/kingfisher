//! Rule catalog inspection, checking, and compiled-cache commands.

use std::io::Write;

use anyhow::{Context, Result, bail};
use clap::Parser;
use console::Term;
use kingfisher::{
    cli::{
        self,
        commands::rules::{
            RuleCachePruneArgs, RulesCheckArgs, RulesCompileCacheArgs, RulesListArgs,
            RulesListOutputFormat,
        },
    },
    matcher::{rule_matches_example, rule_matches_example_ignoring_substrings},
    rule_loader::RuleLoader,
    rules_database::{
        RuleCacheConfig, RuleCachePruneConfig, RuleCacheStatus, RulesDatabase, prune_rule_cache,
    },
};
use serde_json::json;
use tracing::{info, warn};

/// Explain rejected examples and preserve the legacy warning for ignored substrings.
/// The matcher is authoritative; this is called only after all matches in an example are rejected.
/// Returns true when every regex match reaches substring rejection; the caller must still
/// check the other scan-time filters before treating the example as a warning.
fn print_pattern_requirement_failures(
    rule: &kingfisher::rules::rule::Rule,
    re: &regex::bytes::Regex,
    example: &str,
) -> bool {
    use kingfisher_rules::{PatternRequirementContext, PatternValidationResult};
    use kingfisher_scanner::primitives::find_secret_capture_with_group;

    let Some(requirements) = rule.pattern_requirements() else {
        return false;
    };
    // Mirror the shared primitive's input choice for diagnostics: named/multiple captures use
    // the full match, while a single unnamed capture uses the selected secret.
    let use_full_match = re.capture_names().any(|name| name.is_some()) || re.captures_len() > 2;
    let mut saw_ignored_match = false;
    let mut only_ignored_matches = true;
    for captures in re.captures_iter(example.as_bytes()) {
        let full_match = captures.get(0).expect("a regex match has group 0").as_bytes();
        let secret = find_secret_capture_with_group(re, &captures, rule.betterleaks_secret_group());
        let input = if use_full_match { full_match } else { secret.as_bytes() };
        let context = PatternRequirementContext { regex: re, captures: &captures, full_match };
        match requirements.validate(input, Some(context), true) {
            PatternValidationResult::Passed => only_ignored_matches = false,
            PatternValidationResult::Failed => {
                only_ignored_matches = false;
                println!("    [!] Pattern requirements not met for example: {}", example);
                println!(
                    "    The match does not satisfy the character requirements (min_digits, min_uppercase, etc.)"
                );
            }
            PatternValidationResult::FailedChecksum { actual_len, expected_len } => {
                only_ignored_matches = false;
                println!("    [!] Checksum validation failed for example: {}", example);
                println!(
                    "    Actual checksum length: {}, Expected checksum length: {}",
                    actual_len, expected_len
                );
            }
            PatternValidationResult::IgnoredBySubstring { matched_term } => {
                saw_ignored_match = true;
                println!(
                    "    [!] Example would be ignored due to containing term: {}",
                    matched_term
                );
            }
        }
    }
    saw_ignored_match && only_ignored_matches
}

/// Use the scan CLI defaults so rule commands stay in sync with scans.
fn create_default_scan_args() -> Result<cli::commands::scan::ScanArgs> {
    let cli::global::Command::Scan(command) =
        cli::CommandLineArgs::try_parse_from(["kingfisher", "scan"])?.command
    else {
        unreachable!("the scan subcommand was explicitly selected");
    };
    let mut args = command.scan_args;
    // Rule inspection does not scan inputs or validate credentials.
    args.num_jobs = 1;
    args.no_validate = true;
    Ok(args)
}
/// Run the rules compile-cache command
pub(crate) fn run_rules_compile_cache(args: &RulesCompileCacheArgs) -> Result<()> {
    let mut scan_args = create_default_scan_args()?;
    scan_args.confidence = args.confidence;

    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&scan_args).context("Failed to load rules")?;
    let resolved = loaded.resolve_enabled_rules_owned().context("Failed to resolve rules")?;
    let betterleaks_prefilter = loaded.betterleaks_prefilter_for(&resolved);
    let cache = RuleCacheConfig::from_dir_or_env(args.cache.rule_cache_dir.clone());
    if !cache.is_enabled() {
        bail!("No per-user rule cache directory is available; provide --rule-cache-dir");
    }
    info!(cache_dir = %cache.cache_dir().display(), "Using Vectorscan rule cache");
    let rules_db = RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
        resolved,
        &cache,
        betterleaks_prefilter,
    )
    .context("Failed to compile rules with Vectorscan cache")?;

    if rules_db.cache_status() == RuleCacheStatus::Bypassed {
        bail!(
            "Rules compiled, but the cache could not be persisted in {}. Check directory ownership, permissions, and available disk space",
            cache.cache_dir().display()
        );
    }

    println!("Rule cache ready: {} rules in {}", rules_db.num_rules(), cache.cache_dir().display());
    Ok(())
}

/// Run the rules prune-cache command
pub(crate) fn run_rules_prune_cache(args: &RuleCachePruneArgs) -> Result<()> {
    let cache = RuleCacheConfig::from_dir_or_env(args.cache.rule_cache_dir.clone());
    let summary = prune_rule_cache(
        &cache,
        &RuleCachePruneConfig {
            max_entries: args.max_entries,
            max_age: args.max_age,
            protected_cache_key: None,
            dry_run: args.dry_run,
        },
    );

    let action = if args.dry_run { "would remove" } else { "removed" };
    println!(
        "Rule cache prune {action} {} entries ({} bytes) from {}; scanned {} entries, {} valid, {} invalid, {} protected, {} removal errors",
        if args.dry_run { summary.candidate_entries } else { summary.removed_entries },
        if args.dry_run { summary.candidate_bytes } else { summary.removed_bytes },
        cache.cache_dir().display(),
        summary.scanned_entries,
        summary.valid_entries,
        summary.invalid_entries,
        summary.protected_entries,
        summary.removal_errors
    );
    Ok(())
}

/// Run the rules check command
pub(crate) fn run_rules_check(args: &RulesCheckArgs) -> Result<()> {
    let mut num_errors = 0;
    let mut num_warnings = 0;
    // Load and check rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args()?)?;
    let resolved = loaded.resolve_enabled_rules_owned()?;
    let betterleaks_prefilter = loaded.betterleaks_prefilter_for(&resolved);
    let rules_db =
        RulesDatabase::from_rules_with_betterleaks_prefilter(resolved, betterleaks_prefilter)?;

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
            // Betterleaks' generated catalog does not carry example strings. The upstream
            // configuration is parsed and operation-checked by our build adapter, so retain this
            // legacy-authoring warning only for custom Kingfisher YAML rules.
            if !rule.id().starts_with("betterleaks.") {
                warn!("Rule '{}' has no examples", rule.name());
                num_warnings += 1;
            }
        }
        // The database has already compiled every regex. Test both kinds of examples against
        // the scan-time content filters instead of duplicating capture and requirement logic.
        let re = &rules_db.anchored_regexes()[rule_index];
        for (negative, examples) in
            [(false, &rule_syntax.examples), (true, &rule_syntax.negative_examples)]
        {
            for (example_index, example) in examples.iter().enumerate() {
                let matched = rule_matches_example(&rules_db, rule_index, example.as_bytes());
                if matched != negative {
                    continue;
                }
                let kind = if negative { "negative example" } else { "example" };
                println!(
                    "\nTesting rule {} - {} ({})",
                    rule_index + 1,
                    rule_syntax.name,
                    rule.id()
                );
                println!("  Processing {} {}", kind, example_index + 1);
                if negative {
                    println!("    [!] Negative example unexpectedly matched: {}", example);
                } else if !re.is_match(example.as_bytes()) {
                    println!("    [!] Pattern mismatch detected for example: {}", example);
                    println!("    Regex match: false");
                } else {
                    if print_pattern_requirement_failures(rule, re, example)
                        && rule_matches_example_ignoring_substrings(
                            &rules_db,
                            rule_index,
                            example.as_bytes(),
                        )
                    {
                        num_warnings += 1;
                        continue;
                    }
                    println!("    [!] Example rejected by scan-time filters: {}", example);
                    println!(
                        "    Check entropy, safe-list, pattern requirements, and rule filters; use --verbose for details"
                    );
                }
                num_errors += 1;
            }
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
        println!("  - Examples rejected by scan-time filters");
        println!("  - Negative examples that match after scan-time filtering");
        println!("\nWarning types include:");
        println!("  - Rules with very short names");
        println!("  - Rules with very short patterns");
        println!("  - Rules without examples");
        println!("  - Examples ignored by ignore_if_contains");
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
pub(crate) fn run_rules_list(args: &RulesListArgs) -> Result<()> {
    // Load rules
    let loader = RuleLoader::from_rule_specifiers(&args.rules);
    let loaded = loader.load(&create_default_scan_args()?)?;
    let resolved = loaded.resolve_enabled_rules()?;
    let mut writer = args.output_args.get_writer()?;
    #[cfg(debug_assertions)]
    let show_validation = args.show_validation;
    #[cfg(not(debug_assertions))]
    let show_validation = false;
    match args.output_args.format {
        RulesListOutputFormat::Pretty => {
            // Determine terminal width if possible, otherwise use default
            let term_width = usize::from(Term::stdout().size().1);
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
                    .replace(['\n', '\r'], " ")
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
                if show_validation && let Some(validation) = &rule.syntax().validation {
                    match validation {
                        kingfisher::rules::Validation::Betterleaks(validation) => {
                            #[cfg(debug_assertions)]
                            writeln!(writer, "  Validation: {}", validation.source)?;
                            writeln!(writer, "  Validation AST: {:?}", validation.expression)?;
                        }
                        validation => writeln!(writer, "  Validation: {validation:?}")?,
                    }
                }
            }
            writeln!(writer)?;
        }
        RulesListOutputFormat::Json => {
            // Create JSON format
            let rules_json: Vec<_> = resolved
                .iter()
                .map(|rule| {
                    let mut value = json!({
                        "name": rule.name(),
                        "id": rule.id(),
                        "pattern": rule.syntax().pattern,
                        "confidence": rule.confidence(),
                        "examples": rule.syntax().examples,
                        "visible": rule.visible(),
                    });
                    if show_validation {
                        value["validation"] = serde_json::to_value(
                            rule.syntax()
                                .validation
                                .as_ref()
                                .map(kingfisher::rules::Validation::redacted_for_inspection),
                        )
                        .expect("validation serialization should succeed");
                    }
                    value
                })
                .collect();
            serde_json::to_writer_pretty(&mut writer, &rules_json)?;
            writeln!(writer)?;
        }
    }
    Ok(())
}
