use super::*;

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_timestamp(input: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(input)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_else(|_| input.to_string())
}

fn summary_line(label: &str, value: &str) -> String {
    format!(
        "<div class=\"summary-line\"><span class=\"label\">{}</span><span class=\"dots\"></span><span class=\"value\">{}</span></div>",
        escape_html(label),
        escape_html(value)
    )
}

fn render_metadata(metadata: &ScanReportMetadata) -> String {
    let mut lines = Vec::new();
    lines.push(summary_line("Findings", &metadata.summary.findings.to_string()));
    if let Some(successful) = metadata.summary.successful_validations {
        lines.push(summary_line(" |__Successful Validations", &successful.to_string()));
    }
    if let Some(failed) = metadata.summary.failed_validations {
        lines.push(summary_line(" |__Failed Validations", &failed.to_string()));
    }
    if let Some(skipped) = metadata.summary.skipped_validations {
        lines.push(summary_line(" |__Skipped Validations", &skipped.to_string()));
    }
    if let Some(rules_applied) = metadata.summary.rules_applied {
        lines.push(summary_line("Rules Applied", &rules_applied.to_string()));
    }
    if let Some(blobs) = metadata.summary.blobs_scanned {
        lines.push(summary_line(" |__Blobs Scanned", &blobs.to_string()));
    }
    if let Some(bytes) = metadata.summary.bytes_scanned {
        lines.push(summary_line("Bytes Scanned", &bytes.to_string()));
    }
    if let Some(duration) = metadata.summary.scan_duration_seconds {
        lines.push(summary_line("Scan Duration", &format!("{duration:.3}s")));
    }
    lines.push(summary_line("Scan Date", &format_timestamp(&metadata.scan_timestamp)));
    lines.push(summary_line("Report Generated", &format_timestamp(&metadata.generated_at)));
    lines.push(summary_line("Kingfisher Version", &metadata.kingfisher_version));
    if let Some(latest) = &metadata.latest_version_available {
        lines.push(summary_line(" |__Latest Version", latest));
    }
    if let Some(target) = &metadata.target {
        lines.push(summary_line("Target", target));
    }
    lines.push(summary_line(
        "Confidence Level",
        &metadata.summary.confidence_level.to_ascii_lowercase(),
    ));
    lines.push(summary_line(
        "Custom Rules Used",
        if metadata.summary.custom_rules_used { "yes" } else { "no" },
    ));
    lines.push(summary_line(
        "Validation Split",
        &format!(
            "Active {} | Inactive {} | Unknown {}",
            metadata.summary.active_findings,
            metadata.summary.inactive_findings,
            metadata.summary.unknown_validation_findings
        ),
    ));
    lines.push(summary_line(
        "Blast Radius Identities",
        &metadata.summary.access_map_identities.to_string(),
    ));

    let cli_cmdline =
        metadata.command_line_args.iter().map(|arg| escape_html(arg)).collect::<Vec<_>>().join(" ");

    format!(
        "<section class=\"panel\">
          <h2>Scan Summary</h2>
          <div class=\"meta summary\">{}</div>
          <h3>Sanitized command-line arguments</h3>
          <pre class=\"cmdline\"><code>{}</code></pre>
        </section>",
        lines.join(""),
        cli_cmdline
    )
}

fn validation_rank(status: &str) -> usize {
    if status.eq_ignore_ascii_case("Active Credential") {
        0
    } else if status.eq_ignore_ascii_case("Assumed Valid (Not Live-Validated)") {
        1
    } else if status.eq_ignore_ascii_case("Inconclusive Validation") {
        2
    } else if status.eq_ignore_ascii_case("Inactive Credential") {
        3
    } else if status.eq_ignore_ascii_case("Canary Token (Skipped)")
        || status.eq_ignore_ascii_case("Validation Skipped")
    {
        4
    } else if status.eq_ignore_ascii_case("Not Attempted") {
        5
    } else {
        6
    }
}

fn validation_status_class(outcome: kingfisher_core::ValidationOutcome) -> &'static str {
    match outcome {
        kingfisher_core::ValidationOutcome::VerifiedActive => "status-active",
        kingfisher_core::ValidationOutcome::Assumed => "status-assumed",
        kingfisher_core::ValidationOutcome::VerifiedInactive => "status-inactive",
        kingfisher_core::ValidationOutcome::Unavailable => "status-unavailable",
        kingfisher_core::ValidationOutcome::Skipped => "status-canary",
        kingfisher_core::ValidationOutcome::NotAttempted => "status-unknown",
    }
}

fn finding_git_url(record: &FindingReporterRecord) -> Option<String> {
    record
        .finding
        .git_metadata
        .as_ref()
        .and_then(|meta| {
            meta.get("file").and_then(|file| file.get("url")).or_else(|| meta.get("repository_url"))
        })
        .and_then(|url| url.as_str())
        .map(|url| url.to_string())
}

fn render_findings_table(findings: &[FindingReporterRecord]) -> String {
    if findings.is_empty() {
        return "<p>No findings detected.</p>".to_string();
    }

    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        validation_rank(&a.finding.validation.status)
            .cmp(&validation_rank(&b.finding.validation.status))
            .then_with(|| a.finding.path.cmp(&b.finding.path))
            .then_with(|| a.finding.line.cmp(&b.finding.line))
    });

    let mut rows = String::new();
    for record in &sorted {
        let status_class = validation_status_class(record.finding.validation.outcome);
        let git_url_html = finding_git_url(record)
            .map(|url| {
                format!(
                    "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>",
                    escape_html(&url),
                    escape_html(&url)
                )
            })
            .unwrap_or_default();

        rows.push_str(&format!(
            "<tr>\
                <td>{}</td>\
                <td>{}</td>\
                <td><code>{}</code></td>\
                <td>{}</td>\
                <td><span class=\"status {}\">{}</span></td>\
                <td>{}</td>\
                <td>{}</td>\
             </tr>",
            escape_html(&record.rule.name),
            escape_html(&record.rule.id),
            escape_html(&record.finding.path),
            git_url_html,
            status_class,
            escape_html(&record.finding.validation.status),
            escape_html(&record.finding.confidence),
            record.finding.line
        ));
    }

    format!(
        "<table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Rule ID</th>
              <th>Path</th>
              <th>Git URL</th>
              <th>Validation</th>
              <th>Confidence</th>
              <th>Line</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"
    )
}

fn render_access_map(access_map: Option<&Vec<AccessMapEntry>>) -> String {
    let Some(entries) = access_map else {
        return String::new();
    };
    if entries.is_empty() {
        return String::new();
    }

    let mut items = String::new();
    for entry in entries {
        let account = entry.account.clone().unwrap_or_else(|| "(identity)".to_string());
        items.push_str(&format!(
            "<li><strong>{}</strong> <span>{}</span> ({} groups)</li>",
            escape_html(&account),
            escape_html(&entry.provider.to_uppercase()),
            entry.groups.len()
        ));
    }
    format!(
        "<section class=\"panel\">
            <h2>Blast Radius Summary</h2>
            <ul>{items}</ul>
        </section>"
    )
}

fn build_html(envelope: &ReportEnvelope) -> String {
    let metadata_html = envelope.metadata.as_ref().map(render_metadata).unwrap_or_default();
    let findings_html = render_findings_table(&envelope.findings);
    let access_map_html = render_access_map(envelope.access_map.as_ref());

    format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Kingfisher Audit Report</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", monospace; margin: 0; padding: 24px; color: #111827; background: #f8fafc; }}
    h1 {{ margin: 0 0 6px; color: #0f766e; }}
    h2 {{ margin: 0 0 10px; }}
    h3 {{ margin: 16px 0 8px; font-size: 14px; }}
    .subtitle {{ color: #475569; margin-bottom: 18px; line-height: 1.45; }}
    .subtitle a {{ color: #0f766e; text-decoration: none; font-weight: 600; }}
    .subtitle a:hover {{ text-decoration: underline; }}
    .panel {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    .summary {{ display: grid; gap: 4px; }}
    .summary-line {{ display: flex; align-items: baseline; gap: 8px; color: #111827; }}
    .summary-line .label {{ color: #0f766e; white-space: nowrap; }}
    .summary-line .dots {{ flex: 1; border-bottom: 1px dotted #cbd5e1; transform: translateY(-3px); }}
    .summary-line .value {{ color: #0f172a; }}
    .cmdline {{ margin: 0; padding: 12px; background: #f1f5f9; border-radius: 8px; overflow-x: auto; }}
    .cmdline code {{ color: #0f172a; white-space: pre-wrap; word-break: break-word; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 8px; font-size: 12px; text-align: left; word-break: break-word; }}
    th {{ background: #e2e8f0; color: #0f172a; }}
    .status {{ padding: 2px 8px; border-radius: 999px; font-weight: 700; }}
    .status-active {{ background: #14532d; color: #86efac; }}
    .status-assumed {{ background: #1e3a8a; color: #bfdbfe; }}
    .status-inactive {{ background: #7f1d1d; color: #fecaca; }}
    .status-canary {{ background: #581c87; color: #e9d5ff; }}
    .status-unavailable {{ background: #7f1d1d; color: #fecaca; }}
    .status-unknown {{ background: #78350f; color: #fde68a; }}
  </style>
</head>
<body>
  <h1>Kingfisher Audit Report</h1>
  <div class=\"subtitle\">Secret scanning report generated by <a href=\"https://github.com/mongodb/kingfisher\" target=\"_blank\" rel=\"noopener noreferrer\">MongoDB Kingfisher</a>.</div>
  {metadata_html}
  <section class=\"panel\">
    <h2>Detailed Findings</h2>
    {findings_html}
  </section>
  {access_map_html}
</body>
</html>"
    )
}

impl DetailsReporter {
    pub fn html_format<W: std::io::Write>(
        &self,
        mut writer: W,
        args: &cli::commands::scan::ScanArgs,
    ) -> Result<()> {
        let envelope = self.build_report_envelope(args)?;
        write!(writer, "{}", build_html(&envelope))?;
        writeln!(writer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skipped_validations_have_a_stable_rank_and_style() {
        assert_eq!(validation_rank("Canary Token (Skipped)"), 4);
        assert_eq!(validation_rank("Validation Skipped"), 4);
        assert_eq!(
            validation_status_class(kingfisher_core::ValidationOutcome::Skipped),
            "status-canary"
        );
    }

    #[test]
    fn build_html_includes_audit_title_and_cli_args() {
        let envelope = ReportEnvelope {
            findings: Vec::new(),
            access_map: None,
            metadata: Some(ScanReportMetadata {
                generated_at: "2026-01-01T00:00:00Z".to_string(),
                scan_timestamp: "2026-01-01T00:00:00Z".to_string(),
                target: Some("/tmp/repo".to_string()),
                command_line_args: vec![
                    "kingfisher".to_string(),
                    "scan".to_string(),
                    "--token".to_string(),
                    "***REDACTED***".to_string(),
                ],
                kingfisher_version: "1.2.3".to_string(),
                latest_version_available: Some("1.2.4".to_string()),
                update_check_status: Some("ok".to_string()),
                summary: ScanReportSummary {
                    findings: 0,
                    active_findings: 0,
                    inactive_findings: 0,
                    unknown_validation_findings: 0,
                    access_map_identities: 0,
                    rules_applied: Some(10),
                    confidence_level: "medium".to_string(),
                    custom_rules_used: false,
                    successful_validations: Some(0),
                    failed_validations: Some(0),
                    skipped_validations: Some(0),
                    blobs_scanned: Some(1),
                    bytes_scanned: Some(10),
                    scan_duration_seconds: Some(0.1),
                },
            }),
        };

        let html = build_html(&envelope);
        assert!(html.contains("Kingfisher Audit Report"));
        assert!(html.contains("Sanitized command-line arguments"));
        assert!(html.contains("***REDACTED***"));
        assert!(html.contains("/tmp/repo"));
    }
}
