use std::io::Write;

use anyhow::Result;
use kingfisher_rules::Validation;

use crate::{
    cli::commands::scan::ScanArgs,
    validation::internal_ip_policy::{RuleInternalIpAccess, RuleInternalIpPolicy},
};

use super::rule_loading::resolve_scan_rules;

pub(super) fn write_rules(
    out: &mut impl Write,
    args: &ScanArgs,
    policy: &RuleInternalIpPolicy,
) -> Result<()> {
    let (rules, _) = resolve_scan_rules(args)?;
    writeln!(out, "\nSelected rules ({})", rules.len())?;
    if args.no_validate {
        writeln!(out, "Credential validation: disabled (--no-validate)")?;
    }
    for rule in &rules {
        let role = if rule.is_runtime_dependency_helper() { " [dependency helper]" } else { "" };
        let access = match rule.syntax().validation.as_ref() {
            None => "n/a (detection only)",
            Some(_) if !rule.syntax().is_authoritative() => "n/a (non-authoritative rule)",
            Some(Validation::Assumed) => "n/a (assumed validation)",
            Some(Validation::Ethereum(_)) => "n/a (local validation)",
            Some(Validation::AzureStorage) => "n/a (account-specific provider endpoint)",
            // These validators call fixed provider endpoints and never apply the internal-IP gate.
            Some(Validation::AWS | Validation::Coinbase | Validation::GCP) => {
                "n/a (fixed provider endpoint)"
            }
            Some(_) => match policy.access(rule) {
                RuleInternalIpAccess::Blocked => "blocked",
                RuleInternalIpAccess::AllRules => "allowed (--allow-internal-ips)",
                RuleInternalIpAccess::RuleOptIn => "allowed (YAML opt-in)",
                RuleInternalIpAccess::RuleIdGlob => "allowed (rule ID glob)",
            },
        };
        writeln!(out, "  {}{role} | internal-IP access: {access}", rule.id().escape_debug())?;
    }
    Ok(())
}
