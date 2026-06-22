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
        let is_active = record.finding.validation.status == "Active Credential";
        let lock_icon = if is_active { "🔓 " } else { "" };
        let formatted_heading = format!(
            "{}{} => [{}]",
            lock_icon,
            record.rule.name.to_uppercase(),
            record.rule.id.to_uppercase()
        );
        if is_active {
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

        writeln!(writer, " |{}", self.style_heading("ACCESS MAP"))?;
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
        let is_active = record.finding.validation.status == "Active Credential";
        let style_fn: Box<dyn Fn(&str) -> String> = if is_active {
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
