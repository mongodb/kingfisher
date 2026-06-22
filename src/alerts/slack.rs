//! Slack incoming-webhook payload (Block Kit).

use serde_json::{Value, json};

use crate::alerts::{AlertDetail, AlertSummary};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let header_text = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        format!(
            "Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            summary.total,
            if summary.total == 1 { "" } else { "s" },
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let mut blocks: Vec<Value> = vec![json!({
        "type": "header",
        "text": { "type": "plain_text", "text": header_text }
    })];

    if let Some(target) = &summary.target {
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Target:* `{}`", escape_for_code_span(target))
            }
        }));
    }

    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule_id, count)| format!("• `{}` — {}", escape_for_code_span(rule_id), count))
            .collect();
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!("*Top rules*\n{}", lines.join("\n"))
            }
        }));
    }

    if !findings.is_empty() && summary.detail == AlertDetail::Detail {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut detail_lines: Vec<String> = Vec::with_capacity(take);
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                escape_for_code_span(&truncate(&f.finding.snippet, 32))
            } else {
                "redacted".to_string()
            };
            detail_lines.push(format!(
                "• `{}` at `{}:{}` — `{}` (validation: {}) — fp:`{}`",
                escape_for_code_span(&f.rule.id),
                escape_for_code_span(&f.finding.path),
                f.finding.line,
                snippet,
                escape_mrkdwn(&f.finding.validation.status),
                escape_for_code_span(&f.finding.fingerprint),
            ));
        }
        if findings.len() > take {
            detail_lines.push(format!("_…{} more findings omitted_", findings.len() - take));
        }
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": detail_lines.join("\n") }
        }));
    } else if summary.detail == AlertDetail::Summary && summary.filtered_total > 0 {
        // Summary-mode: explicitly tell the operator the per-finding block was
        // dropped on purpose, so they pivot to the report instead of assuming
        // the alert is incomplete.
        blocks.push(json!({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": format!(
                    "_{} findings — per-finding detail suppressed (summary mode). See full report for specifics._",
                    summary.filtered_total
                )
            }
        }));
    }

    if let Some(url) = &summary.report_url {
        // Render as a Block Kit `actions` block with a `button` element. The
        // button takes the URL via a separate JSON field, so we sidestep the
        // mrkdwn `<url|text>` link syntax entirely — a URL containing `|` or
        // `>` cannot inject markup or break the link the way it could in
        // `<{}|Full report →>`.
        blocks.push(json!({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": { "type": "plain_text", "text": "Full report" },
                "url": url,
            }]
        }));
    }

    blocks.push(json!({
        "type": "context",
        "elements": [{
            "type": "mrkdwn",
            "text": format!("kingfisher v{}", summary.kingfisher_version)
        }]
    }));

    json!({ "text": header_text, "blocks": blocks })
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

/// Slack mrkdwn requires `<>&` escaping; backticks are fine inside code spans.
fn escape_mrkdwn(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Sanitize a value before it goes inside a backtick code span. We escape
/// the same `<>&` mrkdwn metacharacters and replace embedded backticks with
/// a similar-looking U+02CB (modifier letter grave accent) so a user-controlled
/// value cannot break out of the span and inject Slack markup or `<url|text>`
/// links. Newlines are normalized to spaces so a single finding does not
/// fragment the bullet list.
fn escape_for_code_span(s: &str) -> String {
    escape_mrkdwn(s).replace('`', "\u{02CB}").replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_summary() -> AlertSummary {
        AlertSummary {
            total: 0,
            active: 0,
            inactive: 0,
            unknown: 0,
            by_rule: vec![],
            kingfisher_version: "test".to_string(),
            target: None,
            report_url: None,
            detail: crate::alerts::AlertDetail::Detail,
            filtered_total: 0,
        }
    }

    #[test]
    fn empty_payload_has_no_finding_block() {
        let p = build_payload(&empty_summary(), &[], false);
        let blocks = p["blocks"].as_array().unwrap();
        let header = &blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header.contains("no findings"));
    }

    #[test]
    fn header_pluralization() {
        let summary = AlertSummary {
            total: 1,
            active: 1,
            inactive: 0,
            unknown: 0,
            by_rule: vec![("kingfisher.aws.1".into(), 1)],
            kingfisher_version: "test".to_string(),
            target: None,
            report_url: None,
            detail: crate::alerts::AlertDetail::Detail,
            filtered_total: 1,
        };
        let p = build_payload(&summary, &[], false);
        let header = p["blocks"][0]["text"]["text"].as_str().unwrap();
        assert!(header.contains("1 finding"));
        assert!(!header.contains("findings"), "should be singular");
    }

    #[test]
    fn report_url_renders_link_block() {
        let mut s = empty_summary();
        s.report_url = Some("https://ci.example/run/42".to_string());
        let p = build_payload(&s, &[], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("https://ci.example/run/42"));
        assert!(serialized.contains("Full report"));
    }

    #[test]
    fn summary_mode_suppresses_findings_with_notice() {
        let mut s = empty_summary();
        s.detail = crate::alerts::AlertDetail::Summary;
        s.filtered_total = 50;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-123");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        // Per-finding rule id must NOT appear in summary mode.
        assert!(
            !serialized.contains("kingfisher.aws.1"),
            "summary mode must not render the per-finding rule id"
        );
        // The suppression notice must appear so the operator knows why.
        assert!(serialized.contains("per-finding detail suppressed"));
        assert!(serialized.contains("50 findings"));
    }

    #[test]
    fn detail_mode_includes_fingerprint() {
        let mut s = empty_summary();
        s.total = 1;
        s.filtered_total = 1;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-abc-123");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("fp:`fp-abc-123`"), "fingerprint must appear in detail block");
    }
}
