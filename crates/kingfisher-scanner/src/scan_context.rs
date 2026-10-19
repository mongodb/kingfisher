//! Optional compact association metadata; retains no input payload or secret values.
use crate::{Finding, FindingLocation, ScanControl, scanner::ScanFinding};
use kingfisher_core::{LocationMapping, OffsetSpan};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Findings plus source context for exact component windows and candidate ranking.
/// Public finding locations and serialization retain their existing meaning.
pub struct ScanOutput {
    pub findings: Vec<Finding>,
    pub context: Arc<ScanContext>,
}

/// Compact full-match spans and assignment/object context for one scan input.
/// Keep this with its findings and pass it to `Validator::with_scan_context`.
#[derive(Default)]
pub struct ScanContext {
    matches: BTreeMap<String, BTreeMap<(u64, usize), MatchContext>>,
    needed_rules: BTreeSet<String>,
}

pub(crate) struct MatchContext {
    pub location: FindingLocation,
    #[cfg(feature = "validation")]
    pub secret_start: usize,
    pub buffer: usize,
    #[cfg(feature = "validation")]
    pub family: Option<String>,
    #[cfg(feature = "validation")]
    pub scope: usize,
}

impl ScanContext {
    pub(crate) fn new(rules: &kingfisher_rules::RulesDatabase) -> Self {
        let mut needed_rules = BTreeSet::new();
        for rule in rules.rules() {
            for dependency in rule.syntax().depends_on_rule.iter().flatten() {
                needed_rules.insert(rule.id().to_string());
                needed_rules.insert(dependency.rule_id.clone());
            }
        }
        Self { matches: BTreeMap::new(), needed_rules }
    }

    pub(crate) fn get(&self, finding: &Finding) -> Option<&MatchContext> {
        self.matches
            .get(&finding.rule_id)?
            .get(&(finding.fingerprint, Arc::as_ptr(&finding.rule) as usize))
    }

    pub(crate) fn record(
        &mut self,
        bytes: &[u8],
        findings: &mut [ScanFinding],
        base: usize,
        control: &ScanControl,
    ) -> anyhow::Result<()> {
        if !findings.iter().any(|finding| self.needed_rules.contains(&finding.rule_id)) {
            return Ok(());
        }
        let mapping = LocationMapping::new(bytes);
        #[cfg(feature = "validation")]
        let scopes = crate::candidate_context::scopes(
            bytes,
            findings
                .iter()
                .filter(|f| self.needed_rules.contains(&f.rule_id))
                .map(|f| f.secret_span.start - base),
        );
        for finding in findings {
            control.check()?;
            if !self.needed_rules.contains(&finding.rule_id) {
                continue;
            }
            let full = OffsetSpan::from_range(
                (finding.association_span.start - base)..(finding.association_span.end - base),
            );
            #[cfg(feature = "validation")]
            let secret = OffsetSpan::from_range(
                (finding.secret_span.start - base)..(finding.secret_span.end - base),
            );
            // Component windows use the exclusive regex endpoint, including a
            // trailing newline. Public finding locations keep their usual span.
            let start = mapping.get_source_point(full.start);
            let end = mapping.get_source_point(full.end);
            let matches = self.matches.entry(finding.rule_id.clone()).or_default();
            // Decoded occurrences can share public offsets and fingerprints. Give
            // collisions a distinct rule Arc so cloning/moving a Finding preserves
            // its context identity without adding fields or changing serialization.
            let key = (finding.fingerprint, Arc::as_ptr(&finding.rule) as usize);
            if matches.contains_key(&key) {
                finding.finding.rule = Arc::new(finding.rule.as_ref().clone());
            }
            matches.insert(
                (finding.fingerprint, Arc::as_ptr(&finding.rule) as usize),
                MatchContext {
                    location: FindingLocation::new(
                        full.start,
                        full.end,
                        start.line,
                        start.column,
                        end.line,
                        end.column,
                    ),
                    #[cfg(feature = "validation")]
                    secret_start: secret.start,
                    buffer: finding.buffer_id,
                    #[cfg(feature = "validation")]
                    family: crate::candidate_context::assignment_family(bytes, secret),
                    #[cfg(feature = "validation")]
                    scope: scopes.get(&secret.start).copied().unwrap_or_default(),
                },
            );
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "validation"))]
mod tests {
    use super::*;

    #[test]
    fn full_match_windows_agree_with_cli_proximity_at_newlines_and_column_edges() {
        let bytes = b"prefix\r\nalpha beta\nlast line\n";
        let mapping = LocationMapping::new(bytes);
        let mut lines = vec![0];
        lines.extend(
            bytes.iter().enumerate().filter_map(|(i, &byte)| (byte == b'\n').then_some(i + 1)),
        );
        let location = |span: OffsetSpan| {
            let start = mapping.get_source_point(span.start);
            let end = mapping.get_source_point(span.end);
            FindingLocation::new(
                span.start,
                span.end,
                start.line,
                start.column,
                end.line,
                end.column,
            )
        };
        for range in [0..1, 0..8, 8..13, 8..19, 19..bytes.len()] {
            let primary = OffsetSpan::from_range(range);
            for start in 0..bytes.len() {
                let component = OffsetSpan::from_range(start..start + 1);
                for within in ["0", "1L", "+2L", "-2L", "4C", "+4C", "-4C", "2L,4C"] {
                    assert_eq!(
                        crate::scanner::locations_are_within(
                            &location(primary),
                            &location(component),
                            within
                        ),
                        crate::postprocess::component_is_within(
                            bytes, &lines, primary, component, within
                        ),
                        "primary={primary:?}, component={component:?}, within={within}"
                    );
                }
            }
        }
    }
}
