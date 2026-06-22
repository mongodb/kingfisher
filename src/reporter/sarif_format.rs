use std::collections::{BTreeMap, HashSet};

use rayon::prelude::*;
use serde_sarif::sarif;

use super::*;
use crate::defaults::get_builtin_rules;

impl DetailsReporter {
    fn sarif_level_for_confidence(confidence: &str) -> sarif::ResultLevel {
        // println!("Mapping confidence '{}' to SARIF level", confidence);
        match confidence.to_ascii_lowercase().as_str() {
            "low" => sarif::ResultLevel::Note,
            "medium" => sarif::ResultLevel::Warning,
            "high" => sarif::ResultLevel::Error,
            _ => sarif::ResultLevel::Warning,
        }
    }

    fn record_to_sarif_result(&self, record: &FindingReporterRecord) -> Result<sarif::Result> {
        let finding = &record.finding;
        let artifact_location =
            sarif::ArtifactLocation::builder().uri(finding.path.clone()).build();
        let region = sarif::Region::builder()
            .start_line(finding.line as i64)
            .start_column(finding.column_start as i64)
            .end_line(finding.line as i64)
            .end_column(finding.column_end as i64)
            .snippet(sarif::ArtifactContent::builder().text(finding.snippet.clone()).build())
            .build();

        let mut props = BTreeMap::new();
        props.insert("validation_status".to_string(), serde_json::json!(finding.validation.status));
        props.insert("entropy".to_string(), serde_json::json!(finding.entropy));
        if let Some(git) = &finding.git_metadata {
            props.insert("git_metadata".to_string(), git.clone());
        }
        if let Some(validate_cmd) = &finding.validate_command {
            props.insert("validate_command".to_string(), serde_json::json!(validate_cmd));
        }
        if let Some(revoke_cmd) = &finding.revoke_command {
            props.insert("revoke_command".to_string(), serde_json::json!(revoke_cmd));
        }
        let properties = sarif::PropertyBag::builder().additional_properties(props).build();

        let location = sarif::Location::builder()
            .physical_location(
                sarif::PhysicalLocation::builder()
                    .artifact_location(artifact_location)
                    .region(region)
                    .build(),
            )
            .properties(properties)
            .build();

        let message = sarif::Message::builder()
            .text(format!("Rule {} matched {}", record.rule.name, finding.path))
            .build();

        let result = sarif::Result::builder()
            .rule_id(&record.rule.name)
            .message(message)
            .kind(sarif::ResultKind::Review)
            .locations(vec![location])
            .level(Self::sarif_level_for_confidence(&finding.confidence))
            .partial_fingerprints([("fingerprint".to_string(), finding.fingerprint.clone())])
            .build();
        Ok(result)
    }

    pub fn sarif_format<W: std::io::Write>(
        &self,
        mut writer: W,
        _no_dedup: bool,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        let finding_rule_ids: HashSet<_> =
            envelope.findings.iter().map(|r| r.rule.name.clone()).collect();
        let rules: Vec<sarif::ReportingDescriptor> = get_builtin_rules(None)?
            .iter_rules()
            .par_bridge()
            .filter_map(|rule| {
                if finding_rule_ids.contains(&rule.name) {
                    let help = sarif::MultiformatMessageString::builder()
                        .text(rule.references.join("\n"))
                        .build();
                    let description =
                        sarif::MultiformatMessageString::builder().text(&rule.name).build();
                    Some(
                        sarif::ReportingDescriptor::builder()
                            .id(&rule.name)
                            .short_description(description)
                            .help(help)
                            .build(),
                    )
                } else {
                    None
                }
            })
            .collect();
        let tool = sarif::Tool::builder()
            .driver(
                sarif::ToolComponent::builder()
                    .name(env!("CARGO_PKG_NAME").to_string())
                    .semantic_version(env!("CARGO_PKG_VERSION").to_string())
                    .full_name(format!("Kingfisher {}", env!("CARGO_PKG_VERSION")))
                    .information_uri(env!("CARGO_PKG_HOMEPAGE").to_string())
                    .download_uri(env!("CARGO_PKG_REPOSITORY").to_string())
                    .short_description(
                        sarif::MultiformatMessageString::builder()
                            .text(env!("CARGO_PKG_DESCRIPTION"))
                            .build(),
                    )
                    .rules(rules)
                    .build(),
            )
            .build();

        let sarif_results: Vec<sarif::Result> =
            envelope.findings.iter().filter_map(|r| self.record_to_sarif_result(r).ok()).collect();

        let run_builder = sarif::Run::builder().tool(tool).results(sarif_results);
        let run = if let Some(access_map) = envelope.access_map {
            let mut props = BTreeMap::new();
            props.insert("access_map".to_string(), serde_json::to_value(access_map)?);
            let property_bag = sarif::PropertyBag::builder().additional_properties(props).build();
            run_builder.properties(property_bag).build()
        } else {
            run_builder.build()
        };
        let sarif = sarif::Sarif::builder()
            .version(sarif::Version::V2_1_0.to_string())
            .schema(sarif::SCHEMA_URL)
            .runs(vec![run])
            .build();
        serde_json::to_writer_pretty(&mut writer, &sarif)?;
        writeln!(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{findings_store::FindingsStore, reporter::styles::Styles};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn test_reporter() -> DetailsReporter {
        let tmp = tempdir().expect("tempdir");
        let store = FindingsStore::new(tmp.path().to_path_buf());
        DetailsReporter {
            datastore: Arc::new(Mutex::new(store)),
            styles: Styles::new(false),
            only_valid: false,
            audit_context: None,
        }
    }

    fn sample_record(confidence: &str) -> FindingReporterRecord {
        FindingReporterRecord {
            rule: RuleMetadata { name: "test-rule".to_string(), id: "rule-1".to_string() },
            finding: FindingRecordData {
                snippet: "secret".to_string(),
                fingerprint: "fingerprint".to_string(),
                confidence: confidence.to_string(),
                entropy: "0.0".to_string(),
                validation: ValidationInfo {
                    status: "unknown".to_string(),
                    response: "n/a".to_string(),
                },
                language: "Rust".to_string(),
                line: 1,
                column_start: 1,
                column_end: 5,
                path: "src/lib.rs".to_string(),
                encoding: None,
                git_metadata: None,
                validate_command: None,
                revoke_command: None,
            },
        }
    }

    #[test]
    fn sarif_level_maps_from_confidence() {
        let reporter = test_reporter();
        let low = reporter.record_to_sarif_result(&sample_record("low")).unwrap();
        let medium = reporter.record_to_sarif_result(&sample_record("medium")).unwrap();
        let high = reporter.record_to_sarif_result(&sample_record("high")).unwrap();

        let expected_low = sarif::ResultLevel::Note.to_string();
        let expected_medium = sarif::ResultLevel::Warning.to_string();
        let expected_high = sarif::ResultLevel::Error.to_string();

        assert_eq!(low.level.map(|level| level.to_string()), Some(expected_low));
        assert_eq!(medium.level.map(|level| level.to_string()), Some(expected_medium));
        assert_eq!(high.level.map(|level| level.to_string()), Some(expected_high));
    }
}
