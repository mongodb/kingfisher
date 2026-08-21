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
        let is_local = validation_outcome == kingfisher_core::ValidationOutcome::LocallyDerived;
        let is_actionable = is_active || is_high_confidence || is_local;
        let lock_icon = if is_active {
            "🔓 "
        } else if is_high_confidence {
            "🔒 "
        } else if is_local {
            "◇ "
        } else {
            ""
        };
        let formatted_heading = format!("{}{}", lock_icon, record.rule.title);
        if is_actionable {
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
            if let Some(evidence) = entry
                .provider_metadata
                .as_ref()
                .and_then(|metadata| metadata.authorization_evidence.as_ref())
            {
                writeln!(writer, " |__policies....: {}", evidence.policies.len())?;
                writeln!(writer, " |__paths.......: {}", evidence.paths.len())?;
                for path in evidence.paths.iter().take(25) {
                    let hops = path
                        .hops
                        .iter()
                        .map(|hop| format!("{} --{}--> {}", hop.from, hop.relationship, hop.to))
                        .collect::<Vec<_>>()
                        .join("; ");
                    writeln!(
                        writer,
                        " |____path.......: [{} {}] {}",
                        path.direction.as_deref().unwrap_or("unknown"),
                        path.status,
                        hops
                    )?;
                }
                if evidence.paths.len() > 25 {
                    writeln!(
                        writer,
                        " |____path.......: {} additional paths in structured output",
                        evidence.paths.len() - 25
                    )?;
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
        let is_local = validation_outcome == kingfisher_core::ValidationOutcome::LocallyDerived;
        let is_actionable = is_active || is_high_confidence || is_local;
        let style_fn: Box<dyn Fn(&str) -> String> = if is_actionable {
            Box::new(|s| reporter.style_active_creds(s).to_string())
        } else {
            Box::new(|s| reporter.style_match(s).to_string())
        };
        let finding = &record.finding;
        writeln!(f, " |Finding.......: {}", style_fn(&finding.snippet))?;
        writeln!(f, " |Description...: {}", record.rule.description)?;
        if let Some(enc) = &finding.encoding {
            writeln!(f, " |Encoding......: {}", enc)?;
        }
        writeln!(f, " |Fingerprint...: {}", finding.fingerprint)?;
        writeln!(f, " |Confidence....: {}", finding.confidence)?;
        writeln!(f, " |Entropy.......: {}", finding.entropy)?;
        if is_actionable {
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
                title: "PEM => [CUSTOM.PEM]".to_string(),
                name: "pem".to_string(),
                id: "custom.pem".to_string(),
                description: "PEM private key".to_string(),
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
        let expected_heading =
            reporter.style_finding_active_heading("🔒 PEM => [CUSTOM.PEM]".to_string()).to_string();
        let expected_snippet = reporter.style_active_creds("secret").to_string();
        let expected_status =
            reporter.style_finding_active_heading("Assumed Valid (Not Live-Validated)").to_string();

        let mut output = Vec::new();
        reporter.write_finding_record(&mut output, &record, 1, 1).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains(&expected_heading));
        assert!(output.contains(&format!(" |Finding.......: {expected_snippet}")));
        assert!(output.contains(" |Description...: PEM private key"));
        assert!(output.contains(&format!(" |Validation....: {expected_status}")));
    }
}
