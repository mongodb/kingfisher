//! Google Chat incoming-webhook payload (`cardsV2`).
//!
//! Google Chat does not expose a card-color knob in the public webhook API the
//! way Discord/Teams/Mattermost do, so severity is encoded textually in the
//! header title. The card uses two sections: a "Summary" with `decoratedText`
//! widgets for the active/inactive/unknown counts, and a "Findings" section
//! with a `textParagraph` widget. `textParagraph.text` accepts a small
//! markdown subset (`*bold*`, `_italic_`, backtick code spans).

use serde_json::{Value, json};

use crate::alerts::{AlertDetail, AlertSummary};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let title = if summary.total == 0 {
        "Kingfisher: scan complete — no findings".to_string()
    } else {
        let prefix = if summary.active > 0 { "🚨 " } else { "" };
        format!(
            "{}Kingfisher: {} finding{} ({} active, {} inactive, {} unknown)",
            prefix,
            summary.total,
            plural(summary.total),
            summary.active,
            summary.inactive,
            summary.unknown
        )
    };

    let mut summary_widgets: Vec<Value> = vec![
        json!({ "decoratedText": { "topLabel": "Active",   "text": summary.active.to_string() } }),
        json!({ "decoratedText": { "topLabel": "Inactive", "text": summary.inactive.to_string() } }),
        json!({ "decoratedText": { "topLabel": "Unknown",  "text": summary.unknown.to_string() } }),
    ];
    if let Some(t) = &summary.target {
        summary_widgets.push(json!({
            "decoratedText": { "topLabel": "Target", "text": escape_html(t) }
        }));
    }
    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule, count)| format!("• <code>{}</code> — {count}", escape_html(rule)))
            .collect();
        summary_widgets.push(json!({
            "textParagraph": { "text": format!("<b>Top rules</b><br>{}", lines.join("<br>")) }
        }));
    }

    let mut sections: Vec<Value> = vec![json!({
        "header": "Summary",
        "widgets": summary_widgets,
    })];

    if !findings.is_empty() && summary.detail == AlertDetail::Detail {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut detail = String::new();
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                escape_html(&truncate(&f.finding.snippet, 32))
            } else {
                "redacted".to_string()
            };
            detail.push_str(&format!(
                "• <b>{}</b> at <code>{}:{}</code> — <code>{}</code> (validation: {}) — fp:<code>{}</code><br>",
                escape_html(&f.rule.id),
                escape_html(&f.finding.path),
                f.finding.line,
                snippet,
                escape_html(&f.finding.validation.status),
                escape_html(&f.finding.fingerprint),
            ));
        }
        if findings.len() > take {
            detail.push_str(&format!("<i>…{} more findings omitted</i>", findings.len() - take));
        }
        sections.push(json!({
            "header": "Findings",
            "widgets": [{ "textParagraph": { "text": detail } }],
        }));
    } else if summary.detail == AlertDetail::Summary && summary.filtered_total > 0 {
        sections.push(json!({
            "header": "Findings",
            "widgets": [{ "textParagraph": { "text": format!(
                "<i>{} findings — per-finding detail suppressed (summary mode). See full report for specifics.</i>",
                summary.filtered_total
            ) }}],
        }));
    }

    if let Some(url) = &summary.report_url {
        // `buttonList` widget gives a tappable "Full report" button below the
        // card body — Google Chat's idiomatic way to render a pivot link.
        sections.push(json!({
            "widgets": [{
                "buttonList": {
                    "buttons": [{
                        "text": "Full report",
                        "onClick": { "openLink": { "url": url } }
                    }]
                }
            }]
        }));
    }

    json!({
        "cardsV2": [{
            "cardId": "kingfisher-alert",
            "card": {
                "header": {
                    "title": title,
                    "subtitle": format!("kingfisher v{}", summary.kingfisher_version),
                },
                "sections": sections,
            }
        }]
    })
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

/// Google Chat `textParagraph.text` is HTML-ish — `<b>`, `<code>`, `<br>`, etc.
/// are rendered as markup. Any user-controlled value (rule id, path, snippet,
/// fingerprint, validation status) must be HTML-escaped before interpolation,
/// otherwise an unescaped `<` could break out of a `<code>` span and inject
/// arbitrary chat markup. Newlines are normalized to spaces so a single
/// finding does not fragment the bullet list.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
        .replace(['\n', '\r'], " ")
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
    fn empty_payload_has_no_findings_section() {
        let p = build_payload(&summary(0, 0), &[], false);
        let sections = p["cardsV2"][0]["card"]["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 1, "expected only the Summary section");
        assert_eq!(sections[0]["header"], "Summary");
    }

    #[test]
    fn title_prefixes_emoji_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        let title = p["cardsV2"][0]["card"]["header"]["title"].as_str().unwrap();
        assert!(title.starts_with("🚨"), "active findings should prefix the title with 🚨");
    }

    #[test]
    fn title_no_emoji_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        let title = p["cardsV2"][0]["card"]["header"]["title"].as_str().unwrap();
        assert!(!title.starts_with("🚨"), "no active findings → no emoji prefix");
    }

    #[test]
    fn subtitle_carries_version() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["cardsV2"][0]["card"]["header"]["subtitle"], "kingfisher vtest");
    }

    #[test]
    fn report_url_renders_as_button() {
        let mut s = summary(0, 0);
        s.report_url = Some("https://ci.example/run/11".to_string());
        let p = build_payload(&s, &[], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("https://ci.example/run/11"));
        assert!(serialized.contains("Full report"));
        assert!(serialized.contains("buttonList"));
    }

    #[test]
    fn summary_mode_emits_suppression_notice() {
        let mut s = summary(60, 0);
        s.detail = crate::alerts::AlertDetail::Summary;
        s.filtered_total = 60;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-z");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("per-finding detail suppressed"));
        // Rule id present in HTML-encoded form like <b>kingfisher.aws.1</b>
        // would mean detail mode leaked through; assert absence.
        assert!(!serialized.contains("kingfisher.aws.1"));
    }

    #[test]
    fn detail_mode_includes_fingerprint() {
        let mut s = summary(1, 1);
        s.filtered_total = 1;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-gc-13");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("fp-gc-13"));
    }
}
