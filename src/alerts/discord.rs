//! Discord incoming-webhook payload (`embeds`).
//!
//! A single embed carries the summary as `fields`, the per-finding detail in
//! the embed `description`, and a footer with the Kingfisher version. The
//! sidebar is color-coded the same way the Teams card is: red on any active
//! credential, amber for unverified findings, green for a clean run.

use serde_json::{Value, json};

use crate::alerts::{
    AlertDetail, AlertSummary, SNIPPET_LIMIT, headline, markdown_link_target, plural,
    suppression_notice, truncate,
};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

// Discord embed `description` is capped at 4096 chars and each `fields[].value`
// at 1024. We keep the per-finding block well under both — 1900 chars — so
// servers running older Discord clients render the embed without truncation.
const DESCRIPTION_SOFT_LIMIT: usize = 1900;

// Reserve enough of the limit for the trailing omitted-count line.
const DESCRIPTION_LINE_BUDGET: usize = DESCRIPTION_SOFT_LIMIT - 64;

const COLOR_RED: u32 = 0xC0_39_2B; // active live secrets
const COLOR_AMBER: u32 = 0xF3_9C_12; // findings present, none verified active
const COLOR_GREEN: u32 = 0x27_AE_60; // clean

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    let title = headline(summary);

    let color = if summary.active > 0 {
        COLOR_RED
    } else if summary.total > 0 {
        COLOR_AMBER
    } else {
        COLOR_GREEN
    };

    let mut fields: Vec<Value> = vec![
        json!({ "name": "Active",   "value": summary.active.to_string(),   "inline": true }),
        json!({ "name": "Inactive", "value": summary.inactive.to_string(), "inline": true }),
        json!({ "name": "Unknown",  "value": summary.unknown.to_string(),  "inline": true }),
    ];
    if summary.impacted_resources > 0 {
        fields.push(json!({
            "name": "Impacted resources",
            "value": summary.impacted_resources.to_string(),
            "inline": true,
        }));
    }
    if let Some(t) = &summary.target {
        fields.push(json!({
            "name": "Target",
            "value": format!("`{}`", escape_for_code_span(&truncate(t, 1000))),
            "inline": false,
        }));
    }
    if !summary.by_rule.is_empty() {
        let lines: Vec<String> = summary
            .by_rule
            .iter()
            .map(|(rule, count)| format!("• `{}` — {count}", escape_for_code_span(rule)))
            .collect();
        fields.push(json!({
            "name": "Top rules",
            "value": truncate(&lines.join("\n"), 1000),
            "inline": false,
        }));
    }

    let mut embed = json!({
        "title": title,
        "color": color,
        "fields": fields,
        "footer": { "text": format!("kingfisher v{}", summary.kingfisher_version) },
    });

    if !findings.is_empty() && summary.detail == AlertDetail::Detail {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut detail = String::new();
        let mut rendered = 0usize;
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                escape_for_code_span(&truncate(&f.finding.snippet, SNIPPET_LIMIT))
            } else {
                "redacted".to_string()
            };
            let line = format!(
                "• `{}` at `{}:{}` — `{}` (validation: {}) — fp:`{}`\n",
                escape_for_code_span(&f.rule.id),
                escape_for_code_span(&f.finding.path),
                f.finding.line,
                snippet,
                escape_md(&f.finding.validation.status),
                escape_for_code_span(&f.finding.fingerprint),
            );
            // Truncating instead would cut the omitted-count line below.
            if detail.chars().count() + line.chars().count() > DESCRIPTION_LINE_BUDGET {
                // Keep a truncated first line rather than rendering no detail
                // at all when one line already fills the budget.
                if rendered == 0 {
                    detail.push_str(&truncate(&line, DESCRIPTION_LINE_BUDGET));
                    rendered += 1;
                }
                break;
            }
            detail.push_str(&line);
            rendered += 1;
        }
        let omitted = findings.len() - rendered;
        if omitted > 0 {
            detail.push_str(&format!("…{} finding{} omitted", omitted, plural(omitted)));
        }
        embed["description"] = Value::String(truncate(&detail, DESCRIPTION_SOFT_LIMIT));
    } else if summary.detail == AlertDetail::Summary && summary.total > 0 {
        embed["description"] = Value::String(format!("_{}_", suppression_notice(summary.total)));
    }

    // Render the report URL as a clickable embed link in the title (Discord
    // does not have a dedicated "actions" surface on webhook embeds).
    if let Some(url) = &summary.report_url {
        embed["url"] = Value::String(url.clone());
        // Append a fields entry too — embed `url` only renders if the title
        // is short enough; the field guarantees the link is visible.
        if let Some(fields_arr) = embed["fields"].as_array_mut() {
            fields_arr.push(json!({
                "name": "Full report",
                "value": format!("[Open]({})", markdown_link_target(url)),
                "inline": false,
            }));
        }
    }

    json!({ "embeds": [embed] })
}

/// Escape a value before embedding it in a backtick code span. Replace
/// backticks with U+02CB so a user-controlled value cannot terminate the
/// span and inject Discord markup, and normalize newlines so a single
/// finding does not fragment the bullet list.
fn escape_for_code_span(s: &str) -> String {
    s.replace('`', "\u{02CB}").replace(['\n', '\r'], " ")
}

/// Escape Discord markdown metacharacters in fields rendered outside a code
/// span (e.g. validation status). Backslash-escapes the common formatters.
fn escape_md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '<' | '[' | ']' | '(' | ')' => {
                out.push('\\');
                out.push(ch);
            }
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
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
            impacted_resources: 0,
            unfiltered_total: 0,
        }
    }

    #[test]
    fn color_red_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_RED);
    }

    #[test]
    fn color_amber_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_AMBER);
    }

    #[test]
    fn color_green_when_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["embeds"][0]["color"], COLOR_GREEN);
        assert_eq!(p["embeds"][0]["title"], "Kingfisher: scan complete — no findings");
    }

    #[test]
    fn title_distinguishes_clean_scan_from_filtered_to_empty() {
        let mut s = summary(0, 0);
        s.unfiltered_total = 5;
        let p = build_payload(&s, &[], false);
        let title = p["embeds"][0]["title"].as_str().unwrap();
        assert!(!title.contains("no findings"), "got: {title}");
        assert!(title.contains("matched this alert's filters"), "got: {title}");
    }

    #[test]
    fn footer_carries_version() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["embeds"][0]["footer"]["text"], "kingfisher vtest");
    }

    #[test]
    fn empty_findings_has_no_description() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert!(p["embeds"][0].get("description").is_none());
    }

    #[test]
    fn report_url_renders_as_field_and_embed_url() {
        let mut s = summary(0, 0);
        s.report_url = Some("https://ci.example/run/9".to_string());
        let p = build_payload(&s, &[], false);
        assert_eq!(p["embeds"][0]["url"], "https://ci.example/run/9");
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("Full report"));
    }

    #[test]
    fn summary_mode_emits_suppression_notice() {
        let mut s = summary(50, 5);
        s.detail = crate::alerts::AlertDetail::Summary;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-x");
        let p = build_payload(&s, &[&rec], false);
        let desc = p["embeds"][0]["description"].as_str().unwrap();
        assert!(desc.contains("per-finding detail suppressed"));
        assert!(!desc.contains("kingfisher.aws.1"));
    }

    #[test]
    fn detail_mode_includes_fingerprint() {
        let s = summary(1, 1);
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-d-99");
        let p = build_payload(&s, &[&rec], false);
        let desc = p["embeds"][0]["description"].as_str().unwrap();
        assert!(desc.contains("fp:`fp-d-99`"));
    }

    #[test]
    fn report_url_cannot_break_out_of_the_markdown_link() {
        let mut s = summary(1, 0);
        s.report_url = Some("https://ci.example/run(7)?x=1 2".to_string());
        let p = build_payload(&s, &[], false);
        let fields = serde_json::to_string(&p["embeds"][0]["fields"]).unwrap();
        assert!(fields.contains("%28") && fields.contains("%29") && fields.contains("%20"));
        // The structured link keeps the URL verbatim.
        assert_eq!(p["embeds"][0]["url"], "https://ci.example/run(7)?x=1 2");
    }

    #[test]
    fn one_oversized_finding_still_renders_truncated() {
        let s = summary(3, 3);
        let mut rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-huge");
        rec.finding.path = "x".repeat(4000);
        let refs: Vec<&crate::reporter::FindingReporterRecord> = (0..3).map(|_| &rec).collect();

        let p = build_payload(&s, &refs, false);
        let desc = p["embeds"][0]["description"].as_str().unwrap();
        assert!(desc.contains("kingfisher.aws.1"), "no detail rendered at all: {desc}");
        assert!(desc.contains("…2 findings omitted"), "got: {desc}");
        assert!(desc.chars().count() <= DESCRIPTION_SOFT_LIMIT);
    }

    #[test]
    fn omitted_count_survives_long_findings_and_stays_within_the_limit() {
        // Long paths blow past the soft limit before the per-finding cap does.
        let s = summary(40, 40);
        let mut rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-long");
        rec.finding.path = format!("services/{}/src/config.rs", "nested-module/".repeat(20));
        let refs: Vec<&crate::reporter::FindingReporterRecord> = (0..40).map(|_| &rec).collect();

        let p = build_payload(&s, &refs, false);
        let desc = p["embeds"][0]["description"].as_str().unwrap();

        assert!(desc.contains("findings omitted"), "omitted-count line was cut: {desc}");
        assert!(desc.chars().count() <= DESCRIPTION_SOFT_LIMIT);
        let rendered = desc.matches("fp:`fp-long`").count();
        assert!(rendered > 0 && rendered < 40);
        assert!(desc.contains(&format!("…{} findings omitted", 40 - rendered)));
    }
}
