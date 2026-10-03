//! Rule catalog inspection, checking, and compiled-cache commands.

use std::io::Write;

use anyhow::{Context, Result};
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
    rule_loader::RuleLoader,
    rules_database::{RuleCacheConfig, RuleCachePruneConfig, RulesDatabase, prune_rule_cache},
};
use serde_json::json;
use tracing::{error, info, warn};

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
    info!(cache_dir = %cache.cache_dir().display(), "Using Vectorscan rule cache");
    let rules_db = RulesDatabase::from_rules_with_cache_and_betterleaks_prefilter(
        resolved,
        &cache,
        betterleaks_prefilter,
    )
    .context("Failed to compile rules with Vectorscan cache")?;

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
            continue;
        }
        // Check regex compilation
        if let Err(e) = rule.syntax().as_regex() {
            error!("Rule '{}' has invalid regex: {}", rule.name(), e);
            num_errors += 1;
            continue;
        }
        // Test each example against regex and pattern_requirements
        for (example_index, example) in rule_syntax.examples.iter().enumerate() {
            // Get the regex using the public method
            let re =
                rules_db.get_regex_by_rule_id(rule.id()).expect("Failed to get regex for rule");

            // Check if the example matches the pattern
            let example_bytes = example.as_bytes();
            let regex_matched = re.is_match(example_bytes);

            if !regex_matched {
                println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                println!("  Processing example {}", example_index + 1);
                println!("    [!] Pattern mismatch detected for example: {}", example);
                println!("    Regex match: {}", regex_matched);
                num_errors += 1;
                continue;
            }

            // If the rule has pattern_requirements, validate them against the match
            if let Some(pattern_reqs) = rule.pattern_requirements() {
                // Get the captures from the match
                if let Some(captures) = re.captures(example_bytes) {
                    // Get the full match (group 0)
                    let full_capture = captures.get(0).expect("Group 0 should always exist");
                    let full_bytes = full_capture.as_bytes();

                    // Determine which bytes to validate (same logic as in matcher.rs)
                    // Find the primary capture group for validation
                    let matching_input_for_validation = 'block: {
                        // 1. Look for a named capture "secret" (case-insensitive).
                        if let Some(secret_cap) =
                            captures.name("secret").or_else(|| captures.name("SECRET"))
                        {
                            break 'block secret_cap;
                        }

                        // 2. Look for any other named capture.
                        if let Some(named_cap) = (1..captures.len()).find_map(|i| {
                            let name_opt = re.capture_names().nth(i).and_then(|n| n);
                            name_opt.and_then(|_| captures.get(i))
                        }) {
                            break 'block named_cap;
                        }

                        // 3. Fall back to first positional capture (group 1) if it exists.
                        if let Some(pos_cap) = captures.get(1) {
                            break 'block pos_cap;
                        }

                        // 4. Finally, fall back to the full match (group 0).
                        break 'block full_capture;
                    };

                    let validation_bytes = matching_input_for_validation.as_bytes();

                    // Create context for pattern requirements validation
                    use kingfisher_rules::PatternRequirementContext;
                    let context = PatternRequirementContext {
                        regex: re,
                        captures: &captures,
                        full_match: full_bytes,
                    };

                    // Validate pattern requirements (without respect_ignore_if_contains for examples)
                    use kingfisher_rules::PatternValidationResult;
                    match pattern_reqs.validate(validation_bytes, Some(context), false) {
                        PatternValidationResult::Passed => {
                            // All requirements met
                        }
                        PatternValidationResult::Failed => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Pattern requirements not met for example: {}",
                                example
                            );
                            println!(
                                "    The match does not satisfy the character requirements (min_digits, min_uppercase, etc.)"
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::FailedChecksum { actual_len, expected_len } => {
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!("    [!] Checksum validation failed for example: {}", example);
                            println!(
                                "    Actual checksum length: {}, Expected checksum length: {}",
                                actual_len, expected_len
                            );
                            num_errors += 1;
                        }
                        PatternValidationResult::IgnoredBySubstring { matched_term } => {
                            // For examples, we don't want to treat this as an error in check mode
                            // since ignore_if_contains is meant for runtime filtering
                            // But we can warn about it
                            println!("\nTesting rule {} - {}", rule_index + 1, rule_syntax.name);
                            println!("  Processing example {}", example_index + 1);
                            println!(
                                "    [!] Example would be ignored due to containing term: {}",
                                matched_term
                            );
                            println!("    Example: {}", example);
                            num_warnings += 1;
                        }
                    }
                }
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
                        value["validation"] = serde_json::to_value(&rule.syntax().validation)
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
