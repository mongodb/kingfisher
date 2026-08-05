use serde::Serialize;

use super::*;

#[derive(Serialize)]
struct ToonReportEnvelope {
    schema: &'static str,
    scan: ToonScanMetadata,
    findings: Vec<ToonFindingRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_map: Option<Vec<AccessMapEntry>>,
}

#[derive(Serialize)]
struct ToonScanMetadata {
    generated_at: String,
    scan_timestamp: String,
    target: Option<String>,
    kingfisher_version: String,
    latest_version_available: Option<String>,
    update_check_status: Option<String>,
    summary: ScanReportSummary,
}

#[derive(Serialize)]
struct ToonFindingRecord {
    rule_id: String,
    rule_name: String,
    validation_status: String,
    validation_outcome: kingfisher_core::ValidationOutcome,
    path: String,
    line: u32,
    column_start: u32,
    column_end: u32,
    confidence: String,
    entropy: f32,
    language: String,
    fingerprint: String,
    snippet: String,
    validation_response: Option<String>,
    encoding: Option<String>,
    validate_command: Option<String>,
    revoke_command: Option<String>,
    git_repository_url: Option<String>,
    git_commit_id: Option<String>,
    git_commit_url: Option<String>,
    git_file_url: Option<String>,
}

impl ToonFindingRecord {
    fn from_record(record: &FindingReporterRecord) -> Self {
        let git = record.finding.git_metadata.as_ref();

        Self {
            rule_id: record.rule.id.clone(),
            rule_name: record.rule.name.clone(),
            validation_status: record.finding.validation.status.clone(),
            validation_outcome: record.finding.validation.outcome,
            path: record.finding.path.clone(),
            line: record.finding.line,
            column_start: record.finding.column_start,
            column_end: record.finding.column_end,
            confidence: record.finding.confidence.clone(),
            entropy: record.finding.entropy.parse().unwrap_or_default(),
            language: record.finding.language.clone(),
            fingerprint: record.finding.fingerprint.clone(),
            snippet: record.finding.snippet.clone(),
            validation_response: non_empty(record.finding.validation.response.clone()),
            encoding: record.finding.encoding.clone(),
            validate_command: record.finding.validate_command.clone(),
            revoke_command: record.finding.revoke_command.clone(),
            git_repository_url: json_string(git, &["repository_url"]),
            git_commit_id: json_string(git, &["commit", "id"]),
            git_commit_url: json_string(git, &["commit", "url"]),
            git_file_url: json_string(git, &["file", "url"]),
        }
    }
}

fn json_string(value: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_string)
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_string()) }
}

impl DetailsReporter {
    pub fn toon_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        let payload = ToonReportEnvelope {
            schema: "kingfisher.toon.v1",
            scan: ToonScanMetadata {
                generated_at: envelope
                    .metadata
                    .as_ref()
                    .map(|metadata| metadata.generated_at.clone())
                    .unwrap_or_default(),
                scan_timestamp: envelope
                    .metadata
                    .as_ref()
                    .map(|metadata| metadata.scan_timestamp.clone())
                    .unwrap_or_default(),
                target: envelope.metadata.as_ref().and_then(|metadata| metadata.target.clone()),
                kingfisher_version: envelope
                    .metadata
                    .as_ref()
                    .map(|metadata| metadata.kingfisher_version.clone())
                    .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
                latest_version_available: envelope
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.latest_version_available.clone()),
                update_check_status: envelope
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.update_check_status.clone()),
                summary: envelope.metadata.map(|metadata| metadata.summary).unwrap_or(
                    ScanReportSummary {
                        findings: envelope.findings.len(),
                        active_findings: 0,
                        inactive_findings: 0,
                        unknown_validation_findings: 0,
                        access_map_identities: envelope.access_map.as_ref().map_or(0, Vec::len),
                        rules_applied: None,
                        confidence_level: args.confidence.to_string(),
                        custom_rules_used: !args.rules.rules_path.is_empty()
                            || !args.rules.load_builtins,
                        successful_validations: None,
                        failed_validations: None,
                        skipped_validations: None,
                        unavailable_validations: None,
                        blobs_scanned: None,
                        bytes_scanned: None,
                        scan_duration_seconds: None,
                    },
                ),
            },
            findings: envelope.findings.iter().map(ToonFindingRecord::from_record).collect(),
            access_map: envelope.access_map,
        };

        write!(writer, "{}", crate::toon::encode_llm_friendly(&payload)?)?;
        writeln!(writer)?;
        Ok(())
    }
}
