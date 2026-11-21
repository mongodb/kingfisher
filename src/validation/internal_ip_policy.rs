use anyhow::{Context, Result};
use globset::GlobBuilder;
use kingfisher_rules::Rule;
use regex::bytes::RegexSet;

use crate::cli::GlobalArgs;

/// Decides which validators may reach internal/private IP addresses.
#[derive(Clone, Default)]
pub(crate) struct RuleInternalIpPolicy {
    allow_all: bool,
    enable_marked_rules: bool,
    rule_ids: Option<RegexSet>,
}

pub(crate) enum RuleInternalIpAccess {
    Blocked,
    AllRules,
    RuleOptIn,
    RuleIdGlob,
}

impl RuleInternalIpPolicy {
    pub(crate) fn from_global_args(args: &GlobalArgs) -> Result<Self> {
        let patterns = args
            .enable_internal_ips_for
            .iter()
            .map(|pattern| {
                GlobBuilder::new(pattern)
                    .backslash_escape(true)
                    .build()
                    .with_context(|| {
                        format!("Invalid rule ID glob {pattern:?} for --enable-internal-ips-for")
                    })
                    .map(|glob| glob.regex().to_owned())
            })
            .collect::<Result<Vec<_>>>()?;

        // Match IDs as text. GlobSet's path matching normalizes backslashes on Windows.
        let rule_ids = if patterns.is_empty() {
            None
        } else {
            Some(RegexSet::new(patterns).context("Compile --enable-internal-ips-for rule globs")?)
        };
        Ok(Self {
            allow_all: args.allow_internal_ips,
            enable_marked_rules: args.enable_rule_internal_ips,
            rule_ids,
        })
    }

    /// Whether every rule is granted internal IP access (`--allow-internal-ips`).
    pub(crate) fn allows_all(&self) -> bool {
        self.allow_all
    }

    pub(crate) fn allows(&self, rule: &Rule) -> bool {
        !matches!(self.access(rule), RuleInternalIpAccess::Blocked)
    }

    pub(crate) fn access(&self, rule: &Rule) -> RuleInternalIpAccess {
        if self.allow_all {
            return RuleInternalIpAccess::AllRules;
        }
        self.rule_grant(rule)
    }

    pub(crate) fn allows_rule_grant(&self, rule: &Rule) -> bool {
        !matches!(self.rule_grant(rule), RuleInternalIpAccess::Blocked)
    }

    fn rule_grant(&self, rule: &Rule) -> RuleInternalIpAccess {
        if self.enable_marked_rules && rule.allow_internal_ips() {
            RuleInternalIpAccess::RuleOptIn
        } else if self.rule_ids.as_ref().is_some_and(|ids| ids.is_match(rule.id().as_bytes())) {
            RuleInternalIpAccess::RuleIdGlob
        } else {
            RuleInternalIpAccess::Blocked
        }
    }
}
