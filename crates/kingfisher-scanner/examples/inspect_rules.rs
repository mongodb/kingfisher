//! Inspect loaded rule definitions offline, using only public embedding APIs.
//!
//! cargo run -p kingfisher-scanner --example inspect_rules -- --with-revocation
//! cargo run -p kingfisher-scanner --example inspect_rules -- betterleaks.aws-access-token
//! No `validation` feature is needed to inspect configured actions.
use std::{ffi::OsString, path::PathBuf};

use anyhow::{Context, bail, ensure};
use kingfisher_rules::Rules;
use kingfisher_scanner::{Confidence, RulesDatabase, get_builtin_rules};
use serde_json::json;

const USAGE: &str = "inspect_rules [EXACT_RULE_ID] [--rules-path PATH] [--no-builtins]
    [--id-prefix PREFIX] [--with-validation] [--with-revocation] [--field NAME]
Omit the ID to list catalog summaries. Repeat --rules-path or --field.
Fields: pattern, detection_regex, validation, revocation, depends_on_rule,
        betterleaks_filter, pattern_requirements, examples, references.";

fn text(value: OsString) -> anyhow::Result<String> {
    value.into_string().map_err(|_| anyhow::anyhow!("rule IDs/options must be valid Unicode"))
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let mut rule_id = None;
    let mut paths = Vec::new();
    let mut builtins = true;
    let mut prefix = String::new();
    let mut with_validation = false;
    let mut with_revocation = false;
    let mut fields = Vec::new();
    while let Some(arg) = args.next() {
        let arg = text(arg)?;
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--rules-path" => {
                paths.push(PathBuf::from(args.next().context("--rules-path requires a path")?));
            }
            "--no-builtins" => builtins = false,
            "--id-prefix" => prefix = text(args.next().context("--id-prefix requires a prefix")?)?,
            "--with-validation" => with_validation = true,
            "--with-revocation" => with_revocation = true,
            "--field" => {
                let field = text(args.next().context("--field requires a name")?)?;
                ensure!(
                    matches!(
                        field.as_str(),
                        "pattern"
                            | "detection_regex"
                            | "validation"
                            | "revocation"
                            | "depends_on_rule"
                            | "betterleaks_filter"
                            | "pattern_requirements"
                            | "examples"
                            | "references"
                    ),
                    "unknown field: {field}\n{USAGE}"
                );
                fields.push(field);
            }
            _ if arg.starts_with('-') => bail!("unknown option: {arg}\n{USAGE}"),
            _ => {
                ensure!(rule_id.is_none(), "supply only one exact rule ID\n{USAGE}");
                rule_id = Some(arg);
            }
        }
    }
    ensure!(fields.is_empty() || rule_id.is_some(), "--field requires an exact rule ID");
    ensure!(
        rule_id.is_none() || (prefix.is_empty() && !with_validation && !with_revocation),
        "catalog filters apply when the rule ID is omitted"
    );

    // Low confidence includes the complete catalog, including component helpers.
    // Use a higher minimum when loading a deliberately restricted catalog.
    let mut rules = if builtins { get_builtin_rules(Some(Confidence::Low))? } else { Rules::new() };
    if !paths.is_empty() {
        rules.update(Rules::from_paths(paths, Confidence::Low)?);
    }
    // Preserve collection-level metadata and compile once for exact regex inspection.
    let database = RulesDatabase::from_rule_collection(rules)?;

    if let Some(id) = rule_id {
        let (index, rule) = database
            .rules()
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.id() == id)
            .with_context(|| format!("unknown exact rule ID: {id}"))?;
        // RuleSyntax is serializable: inspect all loaded configuration directly.
        // pattern retains source comments; detection_regex is the already-compiled
        // Rust confirmation pattern, excluding the internal endpoint wrapper.
        // The historical anchored_regexes() name does not imply end anchoring.
        let mut detail = serde_json::to_value(rule.syntax())?;
        detail["detection_regex"] = json!(database.anchored_regexes()[index].as_str());
        // Http/Grpc expose requests/matchers; Betterleaks exposes a portable AST.
        // Typed/raw handlers expose dispatch type/name, not their Rust source.
        // Missing actions are null. None of this executes validation/revocation.
        if !fields.is_empty() {
            let mut selected = json!({"id": rule.id()});
            for field in fields {
                selected[&field] = detail[&field].clone();
            }
            detail = selected;
        }
        println!("{}", serde_json::to_string_pretty(&detail)?);
    } else {
        for rule in database.rules() {
            let syntax = rule.syntax();
            // Combine predicates with AND. You can also filter confidence,
            // visibility, entropy, dependencies, or pattern requirements here.
            if !rule.id().starts_with(&prefix)
                || (with_validation && syntax.validation.is_none())
                || (with_revocation && syntax.revocation.is_none())
            {
                continue;
            }
            println!(
                "{}",
                json!({
                    "id": rule.id(), "name": rule.name(), "visible": syntax.visible,
                    "validation": syntax.validation.is_some(),
                    "revocation": syntax.revocation.is_some(),
                })
            );
        }
    }
    Ok(())
}
