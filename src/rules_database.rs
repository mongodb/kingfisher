use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use regex::bytes::Regex;
use tracing::{debug, debug_span, error};
use vectorscan_rs::{BlockDatabase, Flag, Pattern};

use crate::rules::rule::{Rule, RULE_COMMENTS_PATTERN};

pub struct RulesDatabase {
    // pub(crate) rules: Vec<Rule,>,
    pub(crate) rules: Vec<Arc<Rule>>,
    pub(crate) anchored_regexes: Vec<Regex>,
    pub(crate) vsdb: BlockDatabase,
}

pub fn format_regex_pattern(pattern: &str) -> String {
    // Remove comments and whitespace while preserving the regex pattern
    let no_comment_pattern = RULE_COMMENTS_PATTERN.replace_all(pattern, "");
    // flattens multi-line regex into a single line
    no_comment_pattern
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join("")
}

impl RulesDatabase {
    pub fn get_regex_by_rule_id(&self, rule_id: &str) -> Option<&Regex> {
        self.rules
            .iter()
            .position(|r| r.syntax().id == rule_id)
            .and_then(|index| self.anchored_regexes.get(index))
    }

    pub fn get_rule_by_finding_fingerprint(&self, finding_fingerprint: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.finding_sha1_fingerprint() == finding_fingerprint).cloned()
    }

    pub fn get_rule_by_text_id(&self, text_id: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.id() == text_id).cloned()
    }

    pub fn get_rule_by_name(&self, name: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.name() == name).cloned()
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let _span = debug_span!("RulesDatabase::from_rules").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }
        let patterns: Vec<Pattern> = rules
            .iter()
            .enumerate()
            .map(|(id, rule)| {
                Pattern::new(
                    rule.syntax().pattern.clone().into_bytes(),
                    Flag::default(),
                    Some(id.try_into().unwrap()),
                )
            })
            .collect();
        let t1 = Instant::now();
        match BlockDatabase::new(patterns) {
            Ok(vsdb) => {
                let d1 = t1.elapsed().as_secs_f64();
                let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
                debug!("Compiled {} rules: vectorscan {}s; regex {}s", rules.len(), d1, d2);
                Ok(RulesDatabase { rules, vsdb, anchored_regexes })
            }
            Err(e) => {
                error!(
                    "Failed to create BlockDatabase: {}. Attempting to compile rules individually.",
                    e
                );
                Self::compile_rules_individually(rules)
                    .map_err(|err| anyhow!("Failed to compile rules: {}\n{}", e, err))
            }
        }
    }

    fn compile_rules_individually(rules: Vec<Arc<Rule>>) -> Result<Self> {
        // NOTE: This function only used when attempting to determine which rule failed
        // to compile
        let mut compiled_rules = Vec::new();
        let mut compiled_patterns = Vec::new();
        let mut compiled_regexes = Vec::new();
        let mut error_messages = Vec::new();
        for (id, rule) in rules.into_iter().enumerate() {
            let pattern = Pattern::new(
                rule.syntax().pattern.clone().into_bytes(),
                Flag::default(),
                Some(id.try_into().unwrap()),
            );
            match BlockDatabase::new(vec![pattern]) {
                Ok(_) => {
                    // Recreate the pattern for the final compilation
                    let final_pattern = Pattern::new(
                        rule.syntax().pattern.clone().into_bytes(),
                        Flag::default(),
                        Some(id.try_into().unwrap()),
                    );
                    compiled_patterns.push(final_pattern);
                    match rule.syntax().as_regex() {
                        Ok(regex) => {
                            compiled_regexes.push(regex);
                            compiled_rules.push(rule);
                        }
                        Err(e) => {
                            error_messages.push(format!(
                                "Failed to compile Regex for rule '{}' (ID: {}): {}",
                                rule.name(),
                                rule.id(),
                                e
                            ));
                        }
                    }
                }
                Err(e) => {
                    error_messages.push(format!(
                        "Failed to compile vectorscan pattern for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        if !error_messages.is_empty() {
            error!(
                "Errors occurred while compiling rules individually:\n{}",
                error_messages.join("\n")
            );
            bail!("Failed to compile the following rules:\n{}", error_messages.join("\n"));
        }
        let vsdb = BlockDatabase::new(compiled_patterns)?;
        Ok(RulesDatabase { rules: compiled_rules, vsdb, anchored_regexes: compiled_regexes })
    }

    fn compile_regexes(rules: &[Arc<Rule>]) -> Result<(Vec<Regex>, f64)> {
        // fn compile_regexes(rules: &[Rule],) -> Result<(Vec<Regex,>, f64,),> {
        let t2 = Instant::now();
        let mut anchored_regexes = Vec::with_capacity(rules.len());
        for rule in rules {
            match rule.syntax().as_regex() {
                Ok(regex) => anchored_regexes.push(regex),
                Err(e) => {
                    error!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    );
                    return Err(anyhow!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        let d2 = t2.elapsed().as_secs_f64();
        Ok((anchored_regexes, d2))
    }

    #[inline]
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    #[inline]
    pub fn get_rule(&self, index: usize) -> Option<Arc<Rule>> {
        self.rules.get(index).cloned()
    }

    pub fn rules(&self) -> &[Arc<Rule>] {
        &self.rules
    }
}
#[cfg(test)]
mod test_vectorscan {
    use pretty_assertions::assert_eq;

    use super::*;
    #[test]
    pub fn test_vectorscan_sanity() -> Result<()> {
        use vectorscan_rs::{BlockDatabase, BlockScanner, Pattern, Scan};
        let input = b"some test data for vectorscan";
        let pattern = Pattern::new(b"test".to_vec(), Flag::CASELESS | Flag::SOM_LEFTMOST, None);
        let db: BlockDatabase = BlockDatabase::new(vec![pattern])?;
        let mut scanner = BlockScanner::new(&db)?;
        let mut matches: Vec<(u64, u64)> = vec![];
        scanner.scan(input, |id: u32, from: u64, to: u64, _flags: u32| {
            println!("found pattern #{} @ [{}, {})", id, from, to);
            matches.push((from, to));
            Scan::Continue
        })?;
        assert_eq!(matches, vec![(5, 9)]);
        Ok(())
    }
}
#[cfg(test)]
#[cfg(test)]
mod test_regex_cleaning {
    use super::*;
    #[test]
    fn test_format_regex_pattern() {
        let input = r#"(?x)
            (?i)
            (?:
              \\b
              (?:AWS|AMAZON|AMZN|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
              (?:\\.|[\\n\\r]){0,32}?  (?# THIS IS A COMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENT)
              (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN) # THIS IS A COMMENT THAT SHOULD NOT BE USED BUT MIGHT BE
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            |
              \\b
              (?:SECRET|PRIVATE|ACCESS)
              (?:\\.|[\\n\\r]){0,16}?
              (?:KEY|TOKEN)
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            )"#;
        let data = format_regex_pattern(input);
        println!("{}", data);
    }
}
