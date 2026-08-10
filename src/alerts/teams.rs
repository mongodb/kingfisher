//! Microsoft Teams incoming-webhook payload (legacy MessageCard schema).
//!
//! Teams' `IncomingWebhook` connector still accepts the simpler MessageCard
//! schema in addition to Adaptive Cards. We use MessageCard for broader
//! compatibility with both classic O365 connectors and newer Power Automate
//! webhooks.

use serde_json::{Value, json};

use crate::alerts::{
    AlertDetail, AlertSummary, SNIPPET_LIMIT, empty_headline, plural, suppression_notice, truncate,
};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 10;

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    // Teams keeps a short card title; the counts render as facts below.
    let title = empty_headline(summary).unwrap_or_else(|| {
        format!("Kingfisher: {} finding{}", summary.total, plural(summary.total))
    });

    let theme_color = if summary.active > 0 {
        "C0392B" // red — active live secrets
    } else if summary.total > 0 {
        "F39C12" // amber — findings present but unverified
    } else {
        "27AE60" // green — clean
    };

    let mut facts: Vec<Value> = vec![
        json!({ "name": "Active",   "value": summary.active.to_string() }),
        json!({ "name": "Inactive", "value": summary.inactive.to_string() }),
        json!({ "name": "Unknown",  "value": summary.unknown.to_string() }),
    ];
    if summary.impacted_resources > 0 {
        facts.push(json!({ "name": "Impacted resources", "value": summary.impacted_resources.to_string() }));
    }
    // The section sets `markdown: true`, so facts render as markup too.
    if let Some(t) = &summary.target {
        facts.push(json!({ "name": "Target", "value": escape_bold(t) }));
    }
    for (rule, count) in &summary.by_rule {
        facts.push(json!({ "name": escape_bold(rule), "value": count.to_string() }));
    }

    let mut sections: Vec<Value> = vec![json!({
        "activityTitle": title,
        "activitySubtitle": format!("kingfisher v{}", summary.kingfisher_version),
        "facts": facts,
        "markdown": true,
    })];

    if !findings.is_empty() && summary.detail == AlertDetail::Detail {
        let take = findings.len().min(PER_FINDING_LIMIT);
        let mut details = String::new();
        for f in findings.iter().take(take) {
            let snippet = if include_secret {
                escape_for_code_span(&truncate(&f.finding.snippet, SNIPPET_LIMIT))
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
        sections.push(json!({
            "title": "Findings",
            "text": details,
        }));
    } else if summary.detail == AlertDetail::Summary && summary.total > 0 {
        sections.push(json!({
            "title": "Findings",
            "text": format!(
                "_{}_", suppression_notice(summary.total)
            ),
        }));
    }

    let mut card = json!({
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": theme_color,
        "title": title,
        "sections": sections,
    });

    if let Some(url) = &summary.report_url {
        // Teams renders an `OpenUri` action as a button on the card.
        card["potentialAction"] = json!([{
            "@type": "OpenUri",
            "name": "Full report",
            "targets": [{ "os": "default", "uri": url }],
        }]);
    }

    card
}

/// Escape a value before embedding it in a backtick code span. Replace
/// backticks with U+02CB so a user-controlled value cannot terminate the
/// span and inject Teams markdown, and collapse newlines so a single
/// finding does not fragment the bullet list.
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
    fn theme_color_red_when_active() {
        let p = build_payload(&summary(3, 1), &[], false);
        assert_eq!(p["themeColor"], "C0392B");
    }

    #[test]
    fn theme_color_green_when_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["themeColor"], "27AE60");
    }

    #[test]
    fn theme_color_amber_when_findings_no_active() {
        let p = build_payload(&summary(2, 0), &[], false);
        assert_eq!(p["themeColor"], "F39C12");
    }

    #[test]
    fn title_distinguishes_clean_scan_from_filtered_to_empty() {
        let p = build_payload(&summary(0, 0), &[], false);
        assert_eq!(p["title"], "Kingfisher: scan complete — no findings");

        let mut s = summary(0, 0);
        s.unfiltered_total = 5;
        let p2 = build_payload(&s, &[], false);
        let title = p2["title"].as_str().unwrap();
        assert!(!title.contains("no findings"), "got: {title}");
        assert!(title.contains("matched this alert's filters"), "got: {title}");
    }

    #[test]
    fn report_url_adds_open_uri_action() {
        let mut s = summary(1, 0);
        s.report_url = Some("https://ci.example/run/77".to_string());
        let p = build_payload(&s, &[], false);
        assert_eq!(p["potentialAction"][0]["@type"], "OpenUri");
        assert_eq!(p["potentialAction"][0]["targets"][0]["uri"], "https://ci.example/run/77");
    }

    #[test]
    fn summary_mode_emits_suppression_notice() {
        let mut s = summary(40, 0);
        s.detail = crate::alerts::AlertDetail::Summary;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-t");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("per-finding detail suppressed"));
        assert!(!serialized.contains("kingfisher.aws.1"));
    }

    #[test]
    fn target_fact_is_escaped_like_the_detail_block() {
        let mut s = summary(1, 0);
        s.target = Some("repo_with_**bold**_name".to_string());
        let p = build_payload(&s, &[], false);
        let facts = serde_json::to_string(&p["sections"][0]["facts"]).unwrap();
        assert!(!facts.contains("**bold**"), "got: {facts}");
    }

    #[test]
    fn detail_mode_includes_fingerprint() {
        let s = summary(1, 1);
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-teams-5");
        let p = build_payload(&s, &[&rec], false);
        let serialized = serde_json::to_string(&p).unwrap();
        assert!(serialized.contains("fp:`fp-teams-5`"));
    }
}
