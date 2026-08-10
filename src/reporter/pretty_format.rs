use std::fmt::{Display, Formatter, Result as FmtResult};

use indenter::indented;

use super::*;

impl DetailsReporter {
    pub fn pretty_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        let num_findings = envelope.findings.len();
        for (index, record) in envelope.findings.iter().enumerate() {
            self.write_finding_record(&mut writer, record, index + 1, num_findings)?;
            if index + 1 != num_findings {
                writeln!(writer)?;
            }
        }

        if let Some(access_map) = envelope.access_map {
            self.write_access_map(&mut writer, &access_map)?;
        }
        Ok(())
    }

    fn write_finding_record<W: std::io::Write>(
        &self,
        writer: &mut W,
        record: &FindingReporterRecord,
        _finding_num: usize,
        _num_findings: usize,
    ) -> Result<()> {
        let validation_outcome = record.finding.validation.outcome;
        let is_active = validation_outcome.is_verified_active();
        let is_high_confidence = validation_outcome == kingfisher_core::ValidationOutcome::Assumed;
        let lock_icon = if is_active {
            "🔓 "
        } else if is_high_confidence {
            "🔒 "
        } else {
            ""
        };
        let formatted_heading = format!(
            "{}{} => [{}]",
            lock_icon,
            record.rule.name.to_uppercase(),
            record.rule.id.to_uppercase()
        );
        if is_active {
            writeln!(writer, "{}", self.style_finding_active_heading(formatted_heading))?;
        } else if is_high_confidence {
            writeln!(writer, "{}", self.style_finding_active_heading(formatted_heading))?;
        } else {
            writeln!(writer, "{}", self.style_finding_heading(formatted_heading))?;
        }
        writeln!(writer, "{}", PrettyFindingRecord(self, record))?;
        Ok(())
    }

    fn write_access_map<W: std::io::Write>(
        &self,
        writer: &mut W,
        entries: &[AccessMapEntry],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }

        writeln!(writer, " |{}", self.style_heading("BLAST RADIUS"))?;
        for entry in entries {
            // A failed mapping resolved nothing; its groups are placeholders.
            if let Some(error) = &entry.mapping_error {
                writeln!(writer, " |_service.......: {}", entry.provider.to_uppercase())?;
                writeln!(writer, " |__unmapped....: {}", error)?;
                writeln!(writer)?;
                continue;
            }
            for group in &entry.groups {
                writeln!(writer, " |_service.......: {}", entry.provider.to_uppercase())?;
                if let Some(account) = &entry.account {
                    writeln!(writer, " |__account.....: {}", account)?;
                }
                for resource in &group.resources {
                    writeln!(writer, " |____resource....: {}", resource)?;
                }
                if !group.permissions.is_empty() {
                    writeln!(writer, " |____permission..: {}", group.permissions.join(","))?;
                }
            }

            writeln!(writer)?;
        }

        Ok(())
    }

    fn write_git_metadata_value(
        &self,
        f: &mut Formatter<'_>,
        git: &serde_json::Value,
    ) -> FmtResult {
        let repo_url = git["repository_url"].as_str().unwrap_or("");
        writeln!(f, " |Git Repo......: {}", self.style_metadata(repo_url))?;
        if let Some(commit) = git.get("commit") {
            if let Some(url) = commit.get("url").and_then(|v| v.as_str()) {
                writeln!(f, " |__Commit......: {}", self.style_metadata(url))?;
            }
            if let Some(committer) = commit.get("committer") {
                let name = committer.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let email = committer.get("email").and_then(|v| v.as_str()).unwrap_or("");
                writeln!(indented(f).with_str(" |__"), "Committer...: {} <{}>", name, email)?;
            }
            if let Some(date) = commit.get("date").and_then(|v| v.as_str()) {
                writeln!(indented(f).with_str(" |__"), "Date........: {}", date)?;
            }
        }
        if let Some(file) = git.get("file") {
            if let Some(path) = file.get("path").and_then(|v| v.as_str()) {
                writeln!(indented(f).with_str(" |__"), "Path........: {}", path)?;
            }
            if let Some(url) = file.get("url").and_then(|v| v.as_str()) {
                writeln!(
                    indented(f).with_str(" |__"),
                    "Git Link....: {}",
                    self.style_metadata(url)
                )?;
            }
            if let Some(cmd) = file.get("git_command").and_then(|v| v.as_str()) {
                writeln!(
                    indented(f).with_str(" |__"),
                    "Git Command.: {}",
                    self.style_metadata(cmd)
                )?;
            }
        }
        Ok(())
    }
}

pub struct PrettyFindingRecord<'a>(&'a DetailsReporter, &'a FindingReporterRecord);

impl<'a> Display for PrettyFindingRecord<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let reporter = self.0;
        let record = self.1;
        let validation_outcome = record.finding.validation.outcome;
        let is_active = validation_outcome.is_verified_active();
        let is_high_confidence = validation_outcome == kingfisher_core::ValidationOutcome::Assumed;
        let style_fn: Box<dyn Fn(&str) -> String> = if is_active {
            Box::new(|s| reporter.style_active_creds(s).to_string())
        } else if is_high_confidence {
            Box::new(|s| reporter.style_active_creds(s).to_string())
        } else {
            Box::new(|s| reporter.style_match(s).to_string())
        };
        let finding = &record.finding;
        writeln!(f, " |Finding.......: {}", style_fn(&finding.snippet))?;
        if let Some(enc) = &finding.encoding {
            writeln!(f, " |Encoding......: {}", enc)?;
        }
        writeln!(f, " |Fingerprint...: {}", finding.fingerprint)?;
        writeln!(f, " |Confidence....: {}", finding.confidence)?;
        writeln!(f, " |Entropy.......: {}", finding.entropy)?;
        if is_active {
            writeln!(
                f,
                " |Validation....: {}",
                reporter.style_finding_active_heading(&finding.validation.status)
            )?;
        } else if is_high_confidence {
            writeln!(
                f,
                " |Validation....: {}",
                reporter.style_finding_active_heading(&finding.validation.status)
            )?;
        } else {
            writeln!(f, " |Validation....: {}", finding.validation.status)?;
        }
        if !finding.validation.response.is_empty() {
            writeln!(f, " |__Response....: {}", style_fn(&finding.validation.response))?;
        }
        if let Some(validate_cmd) = &finding.validate_command {
            writeln!(f, " |Validate Cmd..: {}", reporter.style_metadata(validate_cmd))?;
        }
        if let Some(revoke_cmd) = &finding.revoke_command {
            writeln!(f, " |Revoke Cmd....: {}", reporter.style_active_creds(revoke_cmd))?;
        }
        writeln!(f, " |Language......: {}", finding.language)?;
        writeln!(f, " |Line Num......: {}", finding.line)?;
        writeln!(f, " |Path..........: {}", style_fn(&finding.path))?;
        if let Some(git) = &finding.git_metadata {
            reporter.write_git_metadata_value(f, git)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn high_confidence_findings_use_active_color_with_locked_icon() {
        let reporter = DetailsReporter {
            datastore: Arc::new(Mutex::new(findings_store::FindingsStore::new(
                std::path::PathBuf::new(),
            ))),
            styles: Styles::new(true),
            validation_filter: cli::commands::scan::ValidationFilter::All,
            audit_context: None,
        };
        let record = FindingReporterRecord {
            rule: RuleMetadata {
                name: "PEM-encoded private key".to_string(),
                id: "kingfisher.pem.1".to_string(),
            },
            finding: FindingRecordData {
                snippet: "secret".to_string(),
                fingerprint: "123".to_string(),
                confidence: "high".to_string(),
                entropy: "6.00".to_string(),
                validation: ValidationInfo {
                    outcome: kingfisher_core::ValidationOutcome::Assumed,
                    status: "Assumed Valid (Not Live-Validated)".to_string(),
                    response: String::new(),
                },
                language: "Unknown".to_string(),
                line: 2,
                column_start: 1,
                column_end: 7,
                path: "/tmp/private.pem".to_string(),
                encoding: None,
                git_metadata: None,
                validate_command: None,
                revoke_command: None,
            },
        };
        let expected_heading = reporter
            .style_finding_active_heading(
                "🔒 PEM-ENCODED PRIVATE KEY => [KINGFISHER.PEM.1]".to_string(),
            )
            .to_string();
        let expected_snippet = reporter.style_active_creds("secret").to_string();
        let expected_status =
            reporter.style_finding_active_heading("Assumed Valid (Not Live-Validated)").to_string();

        let mut output = Vec::new();
        reporter.write_finding_record(&mut output, &record, 1, 1).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains(&expected_heading));
        assert!(output.contains(&format!(" |Finding.......: {expected_snippet}")));
        assert!(output.contains(&format!(" |Validation....: {expected_status}")));
    }
}
