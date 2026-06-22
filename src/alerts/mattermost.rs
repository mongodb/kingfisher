//! Mattermost incoming-webhook payload (Slack-compatible `attachments`).
//!
//! Mattermost has no canonical hostname (it is always self-hosted), so the
//! `infer_from_url` heuristic cannot distinguish a Mattermost URL from any
//! other generic webhook. Users must pass `--alert-format mattermost`
//! explicitly.
//!
//! The legacy Slack `attachments` schema renders identically across Mattermost
//! server versions ≥ 5.x and gives us the same red/amber/green sidebar that
//! Teams/Discord use. We deliberately do **not** reuse `slack::build_payload`
//! because Slack's Block Kit support in Mattermost is partial — older clients
//! only render the top-level `text` and silently drop blocks.

use serde_json::{Value, json};

use crate::alerts::{AlertDetail, AlertSummary};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

const COLOR_RED: &str = "#C0392B";
const COLOR_AMBER: &str = "#F39C12";
const COLOR_GREEN: &str = "#27AE60";

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let header = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        format!(
            "Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            summary.total,
            plural(summary.total),
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let color = if summary.active > 0 {
        COLOR_RED
    } else if summary.total > 0 {
        COLOR_AMBER
    } else {
        COLOR_GREEN
    };

    let mut fields: Vec<Value> = vec![
        json!({ "short": true, "title": "Active",   "value": summary.active.to_string() }),
        json!({ "short": true, "title": "Inactive", "value": summary.inactive.to_string() }),
        json!({ "short": true, "title": "Unknown",  "value": summary.unknown.to_string() }),
    ];
    if let Some(t) = &summary.target {
        fields.push(json!({
            "short": false,
            "title": "Target",
            "value": format!("`{}`", escape_for_code_span(t)),
        }));
    }
    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule, count)| format!("• `{}` — {count}", escape_for_code_span(rule)))
            .collect();
        fields.push(json!({
            "short": false,
            "title": "Top rules",
            "value": lines.join("\n"),
        }));
    }

    let mut attachment = json!({
        "color": color,
        "title": header,
        "fields": fields,
        "footer": format!("kingfisher v{}", summary.kingfisher_version),
    });

    if !findings.is_empty() && summary.detail == AlertDetail::Detail {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut details = String::new();
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                escape_for_code_span(&truncate(&f.finding.snippet, 32))
            } else {
                "redacted".to_string()
            };
            details.push_str(&format!(
                "- **{}** at `{}:{}` — `{}` (validation: {}) — fp:`{}`\n",
                escape_bold(&f.rule.id),
                escape_for_code_span(&f.finding.path),
                f.finding.line,
                snippet,
                escape_bold(&f.finding.validation.status),
                escape_for_code_span(&f.finding.fingerprint),
            ));
        }
        if findings.len() > take {
            details.push_str(&format!("_…{} more findings omitted_\n", findings.len() - take));
        }
        attachment["text"] = Value::String(details);
    } else if summary.detail == AlertDetail::Summary && summary.filtered_total > 0 {
        attachment["text"] = Value::String(format!(
            "_{} findings — per-finding detail suppressed (summary mode). See full report for specifics._",
            summary.filtered_total
        ));
    }

    if let Some(url) = &summary.report_url {
        // Mattermost renders `attachments[].title_link` as a clickable title.
        // Setting both `title_link` and a fallback field makes the link
        // visible regardless of how a given client/version renders.
        attachment["title_link"] = Value::String(url.clone());
        if let Some(fields_arr) = attachment["fields"].as_array_mut() {
            fields_arr.push(json!({
                "short": false,
                "title": "Full report",
                "value": format!("[Open]({})", url),
            }));
        }
    }

    json!({
        "text": header,
        "attachments": [attachment],
    })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Escape a value before embedding it in a backtick code span. Replace
/// backticks with U+02CB so a user-controlled value cannot terminate the
/// span and inject markdown, and collapse newlines so a single finding
/// does not fragment the bullet list.
fn escape_for_code_span(s: &str) -> String {
    s.replace('`', "\u{02CB}").replace(['\n', '\r'], " ")
}

/// Escape values rendered inside a `**bold**` span — strip embedded `**`
/// and `_` so a user-controlled value cannot end the bold or start a link.
fn escape_bold(s: &str) -> String {
    s.replace("**", "\u{02CB}\u{02CB}")
        .replace('_', "\\_")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(total: usize, active: usize) -> AlertSummary {
        AlertSummary {
            total,
            active,
            inactive: 0,
            unknown: 0,
            by_rule: vec![],
            kingfisher_version: "test".to_string(),
            target: None,
            report_url: None,
            detail: crate::alerts::AlertDetail::Detail,
            filtered_total: total,
        }
    }

    #[test]
    fn color_red_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        assert_eq!(p["attachments"][0]["color"], COLOR_RED);
    }

    #[test]
    fn color_amber_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        assert_eq!(p["attachments"][0]["color"], COLOR_AMBER);
    }

    #[test]
    fn color_green_when_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["attachments"][0]["color"], COLOR_GREEN);
    }

    #[test]
    fn fallback_text_carries_header() {
        let p = build_payload(&summary(0, 0), &[], false);
        let text = p["text"].as_str().unwrap();
        assert!(text.contains("no findings"));
    }

    #[test]
    fn footer_carries_version() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["attachments"][0]["footer"], "kingfisher vtest");
    }

    #[test]
    fn report_url_renders_as_title_link() {
        let mut s = summary(0, 0);
        s.report_url = Some("https://ci.example/run/3".to_string());
        let p = build_payload(&s, &[], false);
        assert_eq!(p["attachments"][0]["title_link"], "https://ci.example/run/3");
    }

    #[test]
    fn summary_mode_emits_suppression_notice() {
        let mut s = summary(40, 0);
        s.detail = crate::alerts::AlertDetail::Summary;
        s.filtered_total = 40;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-y");
        let p = build_payload(&s, &[&rec], false);
        let text = p["attachments"][0]["text"].as_str().unwrap();
        assert!(text.contains("per-finding detail suppressed"));
        assert!(!text.contains("kingfisher.aws.1"));
    }

    #[test]
    fn detail_mode_includes_fingerprint() {
        let mut s = summary(1, 1);
        s.filtered_total = 1;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-mm-7");
        let p = build_payload(&s, &[&rec], false);
        let text = p["attachments"][0]["text"].as_str().unwrap();
        assert!(text.contains("fp:`fp-mm-7`"));
    }
}
