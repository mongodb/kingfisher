use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

// Emit the small SARIF 2.1.0 subset used by Kingfisher directly. Using the
// existing JSON serializer avoids a generated model of the entire SARIF schema.
const SARIF_SCHEMA_URL: &str =
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json";

use super::*;
use crate::defaults::get_builtin_rules;

/// Files larger than this are not re-read to convert columns; byte columns are kept.
const MAX_SOURCE_REREAD_BYTES: u64 = 64 * 1024 * 1024;

struct SarifRegion {
    start_line: i64,
    start_column: i64,
    end_line: i64,
    end_column: i64,
}

/// Holds the most recently read source file. Findings are grouped by path, so a
/// single entry avoids re-reading a file without keeping many files in memory.
#[derive(Default)]
struct SourceFileCache {
    path: Option<PathBuf>,
    contents: Option<Vec<u8>>,
    line_starts: Vec<usize>,
}

impl SourceFileCache {
    fn load(&mut self, path: &Path) -> Option<(&[u8], &[usize])> {
        if self.path.as_deref() != Some(path) {
            self.path = Some(path.to_path_buf());
            self.contents = std::fs::metadata(path)
                .ok()
                .filter(|meta| meta.is_file() && meta.len() <= MAX_SOURCE_REREAD_BYTES)
                .and_then(|_| std::fs::read(path).ok());
            self.line_starts = match &self.contents {
                Some(bytes) => std::iter::once(0)
                    .chain(memchr::memchr_iter(b'\n', bytes).map(|nl| nl + 1))
                    .collect(),
                None => Vec::new(),
            };
        }
        self.contents.as_deref().map(|bytes| (bytes, self.line_starts.as_slice()))
    }
}

/// Builds a SARIF 2.1.0 region. Findings carry 1-based lines and 0-based byte columns
/// with an inclusive end; SARIF wants 1-based UTF-16 columns with an exclusive end.
fn sarif_region(finding: &FindingRecordData, cache: &mut SourceFileCache) -> SarifRegion {
    let start_line = finding.line;
    let end_line = match finding.source_region.line_end {
        0 => start_line,
        line => line.max(start_line),
    };
    let start_byte = finding.column_start as usize;
    let end_byte_exclusive = finding.column_end as usize + 1;
    let (start_column, end_column) =
        utf16_columns(finding, cache, start_line, end_line, start_byte, end_byte_exclusive)
            .unwrap_or((start_byte, end_byte_exclusive));
    SarifRegion {
        start_line: i64::from(start_line),
        start_column: start_column as i64 + 1,
        end_line: i64::from(end_line),
        end_column: end_column as i64 + 1,
    }
}

/// Converts byte columns to UTF-16 code units by re-reading the source line. Returns
/// `None` (keep byte columns, identical for ASCII) unless the file still holds the
/// reported value at that location.
fn utf16_columns(
    finding: &FindingRecordData,
    cache: &mut SourceFileCache,
    start_line: u32,
    end_line: u32,
    start_byte: usize,
    end_byte_exclusive: usize,
) -> Option<(usize, usize)> {
    let hint = &finding.source_region;
    let path = hint.local_file.as_deref()?;
    if hint.matched_value.is_empty() || start_line == 0 {
        return None;
    }
    let (bytes, line_starts) = cache.load(path)?;
    let line_bytes = |line: u32| -> Option<&[u8]> {
        let index = usize::try_from(line).ok()?.checked_sub(1)?;
        let start = *line_starts.get(index)?;
        let end = line_starts.get(index + 1).map_or(bytes.len(), |next| next - 1);
        bytes.get(start..end)
    };
    let start_text = line_bytes(start_line)?;
    let end_text = line_bytes(end_line)?;
    // The inclusive end may sit on the line's newline byte, one past the text.
    if start_byte > start_text.len() || end_byte_exclusive > end_text.len() + 1 {
        return None;
    }
    let region_start = line_starts[start_line as usize - 1] + start_byte;
    let region_end = line_starts[end_line as usize - 1] + end_byte_exclusive;
    let region = bytes.get(region_start..region_end.min(bytes.len()))?;
    // Confirm the file still holds the reported value at this location.
    memchr::memmem::find(region, hint.matched_value.as_bytes())?;
    let units = |text: &[u8], byte: usize| -> Option<usize> {
        let within = byte.min(text.len());
        let prefix = std::str::from_utf8(text.get(..within)?).ok()?;
        Some(prefix.encode_utf16().count() + (byte - within))
    };
    Some((units(start_text, start_byte)?, units(end_text, end_byte_exclusive)?))
}

impl DetailsReporter {
    fn sarif_level_for_confidence(confidence: &str) -> &'static str {
        match confidence.to_ascii_lowercase().as_str() {
            "low" => "note",
            "high" => "error",
            _ => "warning",
        }
    }

    fn record_to_sarif_result(
        &self,
        record: &FindingReporterRecord,
        source_cache: &mut SourceFileCache,
    ) -> Value {
        let finding = &record.finding;

        let mut props = BTreeMap::new();
        props.insert("validation_status".to_string(), serde_json::json!(finding.validation.status));
        props.insert(
            "validation_outcome".to_string(),
            serde_json::json!(finding.validation.outcome),
        );
        props.insert("entropy".to_string(), serde_json::json!(finding.entropy));
        props.insert("description".to_string(), serde_json::json!(record.rule.description));
        if let Some(git) = &finding.git_metadata {
            props.insert("git_metadata".to_string(), git.clone());
        }
        if let Some(validate_cmd) = &finding.validate_command {
            props.insert("validate_command".to_string(), serde_json::json!(validate_cmd));
        }
        if let Some(revoke_cmd) = &finding.revoke_command {
            props.insert("revoke_command".to_string(), serde_json::json!(revoke_cmd));
        }
        if let Some(blast_radius_cmd) = &finding.blast_radius_command {
            props.insert("blast_radius_command".to_string(), serde_json::json!(blast_radius_cmd));
        }
        let region = sarif_region(finding, source_cache);
        json!({
            "ruleId": record.rule.id,
            "message": {"text": format!("{} matched {}", record.rule.title, finding.path)},
            "kind": "review",
            "level": Self::sarif_level_for_confidence(&finding.confidence),
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {
                        "startLine": region.start_line,
                        "startColumn": region.start_column,
                        "endLine": region.end_line,
                        "endColumn": region.end_column,
                        "snippet": {"text": finding.snippet}
                    }
                },
                "properties": props
            }],
            "partialFingerprints": {"fingerprint": finding.fingerprint}
        })
    }

    pub fn sarif_format<W: std::io::Write>(
        &self,
        mut writer: W,
        _no_dedup: bool,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        let finding_rule_ids: HashSet<_> =
            envelope.findings.iter().map(|r| r.rule.id.clone()).collect();
        let rules: Vec<Value> = get_builtin_rules(None)?
            .iter_rules()
            .filter(|rule| finding_rule_ids.contains(&rule.id))
            .map(|rule| {
                json!({
                    "id": rule.id,
                    "shortDescription": {"text": finding_title(&rule.id)},
                    "fullDescription": {"text": rule.name},
                    "help": {"text": rule.references.join("\n")}
                })
            })
            .collect();
        let tool = json!({
            "driver": {
                // Keep the tool identity stable despite the kingfisher-bin crate name.
                "name": "kingfisher",
                "semanticVersion": env!("CARGO_PKG_VERSION"),
                "fullName": format!("Kingfisher {}", env!("CARGO_PKG_VERSION")),
                "informationUri": env!("CARGO_PKG_HOMEPAGE"),
                "downloadUri": env!("CARGO_PKG_REPOSITORY"),
                "shortDescription": {"text": env!("CARGO_PKG_DESCRIPTION")},
                "rules": rules
            }
        });

        let mut source_cache = SourceFileCache::default();
        let sarif_results: Vec<Value> = envelope
            .findings
            .iter()
            .map(|r| self.record_to_sarif_result(r, &mut source_cache))
            .collect();

        // Columns are UTF-16 code units, the SARIF default, so `columnKind` is omitted.
        let mut run = json!({"tool": tool, "results": sarif_results});
        let mut props = BTreeMap::new();
        if let Some(access_map) = envelope.access_map {
            props.insert("access_map".to_string(), serde_json::to_value(access_map)?);
        }
        if let Some(audit) = envelope.audit {
            props.insert("repository_audit".to_string(), serde_json::to_value(audit)?);
        }
        if !props.is_empty() {
            run["properties"] = serde_json::to_value(props)?;
        }
        let sarif = json!({
            "version": "2.1.0",
            "$schema": SARIF_SCHEMA_URL,
            "runs": [run]
        });
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
            validation_filter: cli::commands::scan::ValidationFilter::All,
            audit_context: None,
        }
    }

    fn sample_record(confidence: &str) -> FindingReporterRecord {
        FindingReporterRecord {
            rule: RuleMetadata {
                title: "TEST-RULE => [RULE-1]".to_string(),
                name: "test-rule".to_string(),
                id: "rule-1".to_string(),
                description: "Test rule description".to_string(),
            },
            finding: FindingRecordData {
                dependent_captures: Default::default(),
                ambiguous_dependencies: Default::default(),
                snippet: "secret".to_string(),
                fingerprint: "fingerprint".to_string(),
                confidence: confidence.to_string(),
                entropy: "0.0".to_string(),
                validation: ValidationInfo {
                    outcome: kingfisher_core::ValidationOutcome::NotAttempted,
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
                blast_radius_command: None,
                source_region: Default::default(),
            },
        }
    }

    #[test]
    fn sarif_regions_are_one_based_with_exclusive_end() {
        let reporter = test_reporter();
        let mut record = sample_record("medium");
        // A six-byte secret at the very start of a line: 0-based inclusive [0, 5].
        record.finding.column_start = 0;
        record.finding.column_end = 5;
        let result = serde_json::to_value(
            reporter.record_to_sarif_result(&record, &mut SourceFileCache::default()),
        )
        .unwrap();
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 1);
        assert_eq!(region["endColumn"], 7);
    }

    #[test]
    fn sarif_regions_span_lines_for_multi_line_findings() {
        let reporter = test_reporter();
        let mut record = sample_record("medium");
        // A PEM key starting at byte 19 of line 10 and ending at byte 4 of line 40.
        record.finding.line = 10;
        record.finding.column_start = 19;
        record.finding.column_end = 4;
        record.finding.source_region.line_end = 40;
        let result = reporter.record_to_sarif_result(&record, &mut SourceFileCache::default());
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 10);
        assert_eq!(region["startColumn"], 20);
        assert_eq!(region["endLine"], 40);
        assert_eq!(region["endColumn"], 6);
    }

    #[test]
    fn sarif_columns_are_utf16_code_units_for_local_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.env");
        // "秘密=" is 7 bytes but 3 UTF-16 code units; the emoji is 4 bytes / 2 units.
        std::fs::write(&path, "first line\n秘密=🔑abc123\n").unwrap();
        let reporter = test_reporter();
        let mut record = sample_record("medium");
        record.finding.line = 2;
        record.finding.column_start = 11; // byte offset of "abc123"
        record.finding.column_end = 16;
        record.finding.source_region.local_file = Some(path.clone());
        record.finding.source_region.matched_value = "abc123".into();
        let mut cache = SourceFileCache::default();
        let result = reporter.record_to_sarif_result(&record, &mut cache);
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 6);
        assert_eq!(region["endColumn"], 12);

        // When the file no longer holds the reported value, byte columns are kept.
        record.finding.source_region.matched_value = "different".into();
        let result = reporter.record_to_sarif_result(&record, &mut cache);
        let region = &result["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startColumn"], 12);
        assert_eq!(region["endColumn"], 18);
    }

    #[test]
    fn sarif_result_preserves_wire_format() {
        let reporter = test_reporter();
        let result = reporter
            .record_to_sarif_result(&sample_record("medium"), &mut SourceFileCache::default());
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            serde_json::json!({
                "ruleId": "rule-1",
                "message": {"text": "TEST-RULE => [RULE-1] matched src/lib.rs"},
                "kind": "review",
                "level": "warning",
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/lib.rs"},
                        "region": {
                            "startLine": 1, "startColumn": 2, "endLine": 1, "endColumn": 7,
                            "snippet": {"text": "secret"}
                        }
                    },
                    "properties": {
                        "validation_status": "unknown",
                        "validation_outcome": "not_attempted",
                        "entropy": "0.0",
                        "description": "Test rule description"
                    }
                }],
                "partialFingerprints": {"fingerprint": "fingerprint"}
            })
        );
    }

    #[test]
    fn sarif_result_preserves_optional_properties_and_escaping() {
        let reporter = test_reporter();
        let mut record = sample_record("HIGH");
        record.finding.path = "directory/\"unicode-秘密\".rs".into();
        record.finding.snippet = "secret\n\"quoted\"\\".into();
        record.finding.git_metadata = Some(serde_json::json!({"commit": "abc123"}));
        record.finding.validate_command = Some("kingfisher validate example".into());
        record.finding.revoke_command = Some("kingfisher revoke example".into());
        record.finding.blast_radius_command = Some("kingfisher access-map example".into());
        let result = reporter.record_to_sarif_result(&record, &mut SourceFileCache::default());
        let encoded = serde_json::to_string(&result).unwrap();
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        let location = &value["locations"][0];
        assert_eq!(value["level"], "error");
        assert_eq!(location["physicalLocation"]["artifactLocation"]["uri"], record.finding.path);
        assert_eq!(
            location["physicalLocation"]["region"]["snippet"]["text"],
            record.finding.snippet
        );
        let properties = &location["properties"];
        assert_eq!(properties["git_metadata"]["commit"], "abc123");
        assert_eq!(properties["validate_command"], "kingfisher validate example");
        assert_eq!(properties["revoke_command"], "kingfisher revoke example");
        assert_eq!(properties["blast_radius_command"], "kingfisher access-map example");
        let unknown = reporter
            .record_to_sarif_result(&sample_record("unexpected"), &mut SourceFileCache::default());
        assert_eq!(serde_json::to_value(unknown).unwrap()["level"], "warning");
    }

    #[test]
    fn sarif_level_maps_from_confidence() {
        let reporter = test_reporter();
        let low =
            reporter.record_to_sarif_result(&sample_record("low"), &mut SourceFileCache::default());
        let medium = reporter
            .record_to_sarif_result(&sample_record("medium"), &mut SourceFileCache::default());
        let high = reporter
            .record_to_sarif_result(&sample_record("high"), &mut SourceFileCache::default());

        assert_eq!(low["level"], "note");
        assert_eq!(medium["level"], "warning");
        assert_eq!(high["level"], "error");
    }
}
