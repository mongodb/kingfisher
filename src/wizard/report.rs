//! Native report model. Preserve the complete source records for inspection and export.
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

/// Group display quantities without changing stored values, identifiers, or commands.
pub fn number(value: impl ToString) -> String {
    let value = value.to_string();
    let (integer, fraction) = value.split_once('.').unwrap_or((&value, ""));
    let digits = integer.strip_prefix('-').unwrap_or(integer);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return value;
    }
    let mut result = String::new();
    if integer.starts_with('-') {
        result.push('-');
    }
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(digit);
    }
    if value.contains('.') {
        result.push('.');
        result.push_str(fraction);
    }
    result
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub rule: String,
    pub path: String,
    pub line: u64,
    pub status: String,
    pub confidence: String,
    pub snippet: String,
    pub fingerprint: String,
    pub raw: Value,
}

impl Finding {
    /// Use the reporter's provider-specific permalinks, allowing only web navigation.
    pub fn source_links(&self) -> Vec<(&'static str, String)> {
        let git = &self.raw["finding"]["git_metadata"];
        let repository = git["repository_url"]
            .as_str()
            .or_else(|| git["repository"]["url"].as_str())
            .unwrap_or("");
        let commit = git["commit"]["id"].as_str().unwrap_or("");
        let fallback = if !repository.is_empty()
            && !commit.is_empty()
            && commit.bytes().all(|c| c.is_ascii_hexdigit())
        {
            let (_, url, _) = crate::reporter::build_git_urls(
                repository.trim_end_matches('/').trim_end_matches(".git"),
                commit,
                "",
                0,
            );
            Value::String(url)
        } else {
            Value::Null
        };
        let repository = Value::String(repository.to_owned());
        let commit_url = git["commit"]["url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_owned()))
            .unwrap_or(fallback);
        [
            ("Open repository", &repository),
            ("Open file at line", &git["file"]["url"]),
            ("Open commit", &commit_url),
        ]
        .into_iter()
        .filter_map(|(label, value)| {
            let url = url::Url::parse(value.as_str()?).ok()?;
            (matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none())
            .then(|| (label, url.to_string()))
        })
        .collect()
    }
    pub fn field(&self, key: &str) -> String {
        let f = &self.raw["finding"];
        let git = &f["git_metadata"];
        match key {
            "Status" => self.status.clone(),
            "Confidence" => self.confidence.clone(),
            "Rule" => format!("{} {}", self.rule, text(&self.raw["rule"], &["id"])),
            "Path" => self.path.clone(),
            "Repository" => text(git, &["repository_url"]),
            "Author / committer" => format!(
                "{} {} {} {}",
                text(&git["commit"]["author"], &["name"]),
                text(&git["commit"]["author"], &["email"]),
                text(&git["commit"]["committer"], &["name"]),
                text(&git["commit"]["committer"], &["email"])
            ),
            "Commit" => text(&git["commit"], &["id"]),
            "From date" | "To date" | "Commit date" => text(&git["commit"], &["date"]),
            _ => text(f, &[key]),
        }
    }
    pub fn matches_filters(&self, filters: &[(String, String)]) -> bool {
        filters.iter().all(|(key, value)| {
            let value = value.trim().to_lowercase();
            if value.is_empty() {
                return true;
            }
            let field = self.field(key).to_lowercase();
            match key.as_str() {
                "From date" | "To date" => {
                    let Some(date) = field
                        .get(..10)
                        .and_then(|v| chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").ok())
                    else {
                        return false;
                    };
                    let Ok(bound) = chrono::NaiveDate::parse_from_str(&value, "%Y-%m-%d") else {
                        return false;
                    };
                    if key == "From date" { date >= bound } else { date <= bound }
                }
                "Status" | "Confidence" => field == value,
                _ => field.contains(&value),
            }
        })
    }
    pub fn active(&self) -> bool {
        matches!(
            self.status.to_ascii_lowercase().as_str(),
            "active credential" | "verified_active" | "active"
        )
    }
    pub fn from_record(raw: Value) -> Self {
        let finding = &raw["finding"];
        Self {
            rule: text(&raw["rule"], &["name", "title", "id"]),
            path: text(finding, &["path"]),
            line: finding["line"].as_u64().unwrap_or(0),
            status: text(&finding["validation"], &["status", "outcome"]),
            confidence: text(finding, &["confidence"]),
            snippet: text(finding, &["snippet"]),
            fingerprint: text(finding, &["fingerprint"]),
            raw,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingColumn {
    Rule,
    Path,
    Line,
    Status,
    Repository,
    Commit,
    Author,
}
impl FindingColumn {
    pub const ALL: [Self; 7] = [
        Self::Rule,
        Self::Path,
        Self::Line,
        Self::Status,
        Self::Repository,
        Self::Commit,
        Self::Author,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::Rule => "Rule",
            Self::Path => "Path",
            Self::Line => "Line",
            Self::Status => "Status",
            Self::Repository => "Repository",
            Self::Commit => "Commit",
            Self::Author => "Author / committer",
        }
    }
    pub fn width(self) -> f32 {
        match self {
            Self::Rule => 220.,
            Self::Path => 300.,
            Self::Line => 80.,
            Self::Status => 200.,
            _ => 240.,
        }
    }
    pub fn value(self, finding: &Finding) -> String {
        match self {
            Self::Rule => finding.rule.clone(),
            Self::Path => finding.path.clone(),
            Self::Line => number(finding.line),
            Self::Status => finding.status.clone(),
            _ => finding.field(self.label()),
        }
    }
}
pub fn sort_findings(
    indices: &mut [usize],
    findings: &[Finding],
    column: FindingColumn,
    descending: bool,
) {
    let key = |index: &usize| {
        let finding = &findings[*index];
        let number = match column {
            FindingColumn::Line => finding.line,
            _ => 0,
        };
        (number, column.value(finding).to_lowercase())
    };
    if descending {
        indices.sort_by_cached_key(|index| std::cmp::Reverse(key(index)));
    } else {
        indices.sort_by_cached_key(key);
    }
}

#[derive(Clone, Default)]
pub struct ReportData {
    pub findings: Vec<Finding>,
    pub coverage: Vec<Value>,
    pub identities: Vec<Value>,
    pub metadata: Vec<Value>,
    pub audits: Vec<Value>,
    pub sources: Vec<PathBuf>,
}

pub fn text(value: &Value, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| match &value[*key] {
            Value::String(s) if !s.is_empty() => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        })
        .unwrap_or_default()
}

impl ReportData {
    pub fn load(paths: &[PathBuf]) -> Result<Self> {
        let mut report = Self::default();
        for path in paths {
            let path = crate::util::expand_tilde(path);
            let bytes = std::fs::read(&path)
                .with_context(|| format!("Could not read {}", path.display()))?;
            report
                .read_bytes(&bytes)
                .with_context(|| format!("Invalid report: {}", path.display()))?;
            report.sources.push(path);
        }
        Ok(report)
    }

    pub fn read_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        let mut count = 0;
        for document in serde_json::Deserializer::from_slice(bytes).into_iter::<Value>() {
            self.ingest(document?)?;
            count += 1;
        }
        if count == 0 {
            bail!("The report is empty.");
        }
        Ok(())
    }

    fn ingest(&mut self, value: Value) -> Result<()> {
        if let Some(values) = value.as_array() {
            for item in values {
                self.ingest(item.clone())?;
            }
        } else if let Some(runs) = value["runs"].as_array() {
            for run in runs {
                for result in run["results"].as_array().into_iter().flatten() {
                    let locations =
                        result["locations"].as_array().cloned().unwrap_or_else(|| vec![json!({})]);
                    for location in locations {
                        let physical = &location["physicalLocation"];
                        let properties = if location["properties"].is_object() {
                            &location["properties"]
                        } else {
                            &result["properties"]
                        };
                        let record = json!({
                            "rule": {"id": result["ruleId"], "name": result["ruleId"]},
                            "finding": {
                                "path": physical["artifactLocation"]["uri"], "line": physical["region"]["startLine"],
                                "snippet": physical["region"]["snippet"]["text"],
                                "fingerprint": result["partialFingerprints"]["fingerprint"],
                                "confidence": match result["level"].as_str() {Some("error")=>"high",Some("warning")=>"medium",_=>"low"},
                                "validation": {"status": properties["validation_status"], "outcome": properties["validation_outcome"]},
                                "git_metadata": properties["git_metadata"],
                                "validate_command": properties["validate_command"],
                                "revoke_command": properties["revoke_command"],
                                "blast_radius_command": properties["blast_radius_command"],
                                "entropy": properties["entropy"],
                                "column_start": physical["region"]["startColumn"],
                                "column_end": physical["region"]["endColumn"],
                            },
                            "sarif": result,
                        });
                        self.findings.push(Finding::from_record(record));
                    }
                }
                // Kingfisher stores envelope context in SARIF run properties.
                if run["properties"].is_object() {
                    self.context(&run["properties"]);
                }
            }
        } else if value["findings"].is_array() {
            for finding in value["findings"].as_array().unwrap() {
                if !finding["finding"].is_object() {
                    bail!("A finding record is missing its finding data.");
                }
                self.findings.push(Finding::from_record(finding.clone()));
            }
            self.context(&value);
        } else if value["finding"].is_object() && value["rule"].is_object() {
            self.findings.push(Finding::from_record(value));
        } else if value["access_map"].is_array() || value["audit"].is_object() {
            self.context(&value);
        } else if value["repositories"].is_array() {
            self.coverage.extend(value["repositories"].as_array().unwrap().iter().cloned());
        } else {
            bail!("Expected a Kingfisher JSON/JSONL report or a SARIF report.");
        }
        Ok(())
    }

    fn context(&mut self, value: &Value) {
        self.identities.extend(value["access_map"].as_array().into_iter().flatten().cloned());
        let audit = if value["repository_audit"].is_object() {
            &value["repository_audit"]
        } else {
            &value["audit"]
        };
        self.coverage.extend(audit["repositories"].as_array().into_iter().flatten().cloned());
        if let Some(audits) = value["source_audits"].as_array() {
            self.audits.extend(audits.iter().cloned());
        } else if audit.is_object() {
            self.audits.push(audit.clone());
        }
        if let Some(metadata) = value["source_metadata"].as_array() {
            self.metadata.extend(metadata.iter().cloned());
        } else if value["metadata"].is_object() {
            self.metadata.push(value["metadata"].clone());
        } else if value["stats"].is_object() {
            self.metadata.push(value["stats"].clone());
        }
    }

    #[cfg(test)]
    pub fn filtered(&self, query: &str, active: bool, unique: bool) -> Vec<usize> {
        self.filtered_by(query, active, unique, &[])
    }

    pub fn filtered_by(
        &self,
        query: &str,
        active: bool,
        unique: bool,
        filters: &[(String, String)],
    ) -> Vec<usize> {
        let query = query.to_lowercase();
        let mut seen = HashSet::new();
        self.findings
            .iter()
            .enumerate()
            .filter_map(|(index, finding)| {
                if !finding.matches_filters(filters) || (active && !finding.active()) {
                    return None;
                }
                if !query.is_empty()
                    && !format!(
                        "{} {} {} {} {} {} {} {}",
                        finding.rule,
                        text(&finding.raw["rule"], &["id"]),
                        finding.path,
                        finding.status,
                        finding.snippet,
                        finding.field("Repository"),
                        finding.field("Author / committer"),
                        finding.field("Commit")
                    )
                    .to_lowercase()
                    .contains(&query)
                {
                    return None;
                }
                if unique && !finding.fingerprint.is_empty() && !seen.insert(&finding.fingerprint) {
                    return None;
                }
                Some(index)
            })
            .collect()
    }

    pub fn families(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for finding in &self.findings {
            *counts.entry(finding.rule.clone()).or_default() += 1;
        }
        counts
    }

    pub fn export(&self, path: &Path, indices: Option<&[usize]>) -> Result<()> {
        let findings: Vec<_> = match indices {
            Some(indices) => {
                indices.iter().filter_map(|i| self.findings.get(*i)).map(|f| &f.raw).collect()
            }
            None => self.findings.iter().map(|f| &f.raw).collect(),
        };
        let mut audit = if self.audits.len() == 1 { self.audits[0].clone() } else { json!({}) };
        audit["repositories"] = json!(self.coverage);
        let value = json!({"findings": findings, "access_map": self.identities,
            "audit": audit, "metadata": self.metadata.first(), "stats": self.metadata.first(),
            "source_metadata": self.metadata, "source_audits": self.audits});
        // Replace only after a complete write; a failed export must not truncate a saved report.
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(file.as_file_mut(), &value)?;
        file.persist(path).map_err(|error| error.error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_numbers_group_only_quantities() {
        for (value, expected) in [
            ("0", "0"),
            ("999", "999"),
            ("39204", "39,204"),
            ("1234567.890", "1,234,567.890"),
            ("-1234", "-1,234"),
            ("abc1234", "abc1234"),
        ] {
            assert_eq!(number(value), expected);
        }
    }

    #[test]
    fn commit_link_supports_older_report_metadata() {
        let finding = Finding::from_record(json!({"finding":{"git_metadata":{
            "repository_url":"https://github.com/team/repo.git",
            "commit":{"id":"abc123"}
        }}}));
        assert!(
            finding
                .source_links()
                .contains(&("Open commit", "https://github.com/team/repo/commit/abc123".into()))
        );
    }

    #[test]
    fn source_links_preserve_reporter_line_anchors_and_reject_non_web_urls() {
        let finding = Finding::from_record(json!({"finding":{"git_metadata":{
            "repository_url":"https://git.example/team/repo",
            "file":{"url":"https://git.example/team/repo/blob/abc/config.rs#L42"},
            "commit":{"url":"javascript:alert(1)"}
        }}}));
        let links = finding.source_links();
        assert_eq!(links.len(), 2);
        assert_eq!(links[1].1, "https://git.example/team/repo/blob/abc/config.rs#L42");
        assert!(Finding::from_record(json!({})).source_links().is_empty());
        for url in ["file:///tmp/test", "https://user:password@example.com/repo", "invalid"] {
            let finding =
                Finding::from_record(json!({"finding":{"git_metadata":{"repository_url":url}}}));
            assert!(finding.source_links().is_empty());
        }
    }
    #[test]
    fn column_sorting_is_numeric_case_insensitive_and_stable() {
        let findings: Vec<_> = [("Zulu", 10, "high"), ("alpha", 2, "low"), ("Alpha", 2, "medium")]
            .into_iter()
            .map(|(rule, line, confidence)| {
                Finding::from_record(
                    json!({"rule":{"name":rule},"finding":{"line":line,"confidence":confidence}}),
                )
            })
            .collect();
        let mut indices = vec![0, 1, 2];
        sort_findings(&mut indices, &findings, FindingColumn::Line, false);
        assert_eq!(indices, vec![1, 2, 0]);
        sort_findings(&mut indices, &findings, FindingColumn::Rule, false);
        assert_eq!(indices, vec![1, 2, 0]);
        sort_findings(&mut indices, &findings, FindingColumn::Rule, true);
        assert_eq!(indices, vec![0, 1, 2]);
        sort_findings(&mut indices, &findings, FindingColumn::Line, true);
        assert_eq!(indices, vec![0, 1, 2]);
    }
    #[test]
    fn structured_filters_apply_before_dedup_and_keep_metadata_and_commands() {
        let mut data = ReportData::default();
        for (author, status, date) in [
            ("Alice", "Inactive Credential", "2026-01-01"),
            ("Bob", "Active Credential", "2026-09-26"),
        ] {
            data.ingest(json!({"rule":{"id":"test.key", "name":"API key"}, "finding":{
                "path":"src/config.rs", "fingerprint":"same", "confidence":"high", "validation":{"status":status},
                "validate_command":"kingfisher validate fixture", "revoke_command":"kingfisher revoke fixture",
                "git_metadata":{"repository_url":"https://example.invalid/project", "commit":{"id":"abc123", "date":date, "author":{"name":author,"email":"test@example.invalid"}}}
            }})).unwrap();
        }
        let filters = vec![
            ("Author / committer".into(), "bob".into()),
            ("Status".into(), "Active Credential".into()),
            ("From date".into(), "2026-09-26".into()),
            ("To date".into(), "2026-09-26".into()),
            ("Confidence".into(), "high".into()),
        ];
        assert_eq!(data.filtered_by("example.invalid", false, true, &filters), vec![1]);
        assert_eq!(data.findings[1].field("revoke_command"), "kingfisher revoke fixture");
        assert!(
            data.filtered_by("", false, false, &[("Status".into(), "active".into())]).is_empty()
        );
        assert!(
            data.filtered_by("", false, false, &[("To date".into(), "2025-01-01".into())])
                .is_empty()
        );
    }
    #[test]
    fn imports_sample_and_filters_active_without_matching_inactive() {
        let mut data = ReportData::default();
        data.read_bytes(include_bytes!("../../docs/viewer/sample-report.json")).unwrap();
        assert_eq!(data.findings.len(), 3);
        assert_eq!(data.filtered("", true, true).len(), 1);
        assert!(!data.identities.is_empty());
        assert_eq!(data.filtered("utf8", false, false).len(), 1);
    }
    #[test]
    fn export_preserves_audit_evidence_and_merged_source_context() {
        let sample = include_bytes!("../../docs/viewer/sample-report.json");
        let mut data = ReportData::default();
        data.read_bytes(sample).unwrap();
        data.read_bytes(sample).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("merged.json");
        data.export(&path, Some(&[0])).unwrap();
        let imported = ReportData::load(&[path]).unwrap();
        assert_eq!(imported.findings.len(), 1);
        assert_eq!(imported.findings[0].raw, data.findings[0].raw);
        assert_eq!(imported.identities, data.identities);
        assert_eq!(imported.audits, data.audits);
        assert_eq!(imported.metadata, data.metadata);
        assert_eq!(imported.coverage, data.coverage);
    }

    #[test]
    fn jsonl_multiline_records_and_dedup_preserve_locations() {
        let record =
            json!({"rule":{"id":"example"},"finding":{"fingerprint":"abc","path":"a","line":1}});
        let bytes = format!("{}\n{}\n", serde_json::to_string_pretty(&record).unwrap(), record);
        let mut data = ReportData::default();
        data.read_bytes(bytes.as_bytes()).unwrap();
        assert_eq!(data.findings.len(), 2);
        assert_eq!(data.filtered("", false, true).len(), 1);
        assert_eq!(data.filtered("", false, false).len(), 2);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        data.export(&path, None).unwrap();
        assert_eq!(ReportData::load(&[path]).unwrap().findings.len(), 2);
    }
    #[test]
    fn sarif_location_properties_and_empty_reports_are_supported() {
        let mut data = ReportData::default();
        data.read_bytes(br#"{"runs":[{"results":[{"ruleId":"test","level":"error","locations":[{"physicalLocation":{"artifactLocation":{"uri":"file.rs"},"region":{"startLine":7}},"properties":{"validation_status":"Active Credential"}}]}]}]}"#).unwrap();
        assert!(data.findings[0].active());
        assert_eq!(data.findings[0].line, 7);
        assert_eq!(data.findings[0].path, "file.rs");
        data.read_bytes(br#"{"runs":[{"results":[],"properties":{"repository_audit":{"repositories":[{"repository":"project","scan":{"status":"failed"}}]}}}]}"#).unwrap();
        assert_eq!(data.coverage[0]["scan"]["status"], "failed");
        assert!(ReportData::default().read_bytes(b"{\"findings\":[]}").is_ok());
        assert!(ReportData::default().read_bytes(b"{}").is_err());
        assert!(ReportData::default().read_bytes(b"").is_err());
    }
}
