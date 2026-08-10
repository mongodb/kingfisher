//! Generic JSON webhook payload — `{ summary, findings }`.
//!
//! This is the most-flexible sink: drop in any HTTPS endpoint that accepts a
//! JSON POST and you get the same shape Kingfisher's reporter produces, wrapped
//! in a stable envelope so consumers can version against `schema_version`.

use serde_json::{Value, json};

use crate::alerts::{AlertDetail, AlertSummary};
use crate::reporter::FindingReporterRecord;

const PER_FINDING_LIMIT: usize = 200;
const SCHEMA_VERSION: &str = "1";

pub fn build_payload(
    summary: &AlertSummary,
    findings: &[&FindingReporterRecord],
    include_secret: bool,
) -> Value {
    // In Summary mode the operator wants summary stats only — useful for
    // SIEMs that just want to count events but don't ingest per-finding
    // detail from the alert pipe (they pull the SARIF/JSON report directly).
    let take = if summary.detail == AlertDetail::Summary {
        0
    } else {
        findings.len().min(PER_FINDING_LIMIT)
    };
    let included: Vec<Value> = findings
        .iter()
        .take(take)
        .map(|f| {
            let mut record = serde_json::to_value(f).unwrap_or(Value::Null);
            if !include_secret
                && let Some(obj) = record.get_mut("finding").and_then(|v| v.as_object_mut())
            {
                obj.insert("snippet".into(), Value::String("<redacted>".to_string()));
                // The commands quote the raw secret, and a response body can
                // carry it in a rendered request URL.
                obj.remove("validate_command");
                obj.remove("revoke_command");
                if let Some(validation) = obj.get_mut("validation").and_then(|v| v.as_object_mut())
                {
                    validation.insert("response".into(), Value::String(String::new()));
                }
            }
            record
        })
        .collect();

    let mut summary_obj = json!({
        "total": summary.total,
        "active": summary.active,
        "inactive": summary.inactive,
        "unknown": summary.unknown,
        "impacted_resources": summary.impacted_resources,
        "unfiltered_total": summary.unfiltered_total,
        "by_rule": summary.by_rule.iter().map(|(r, c)| json!({"rule_id": r, "count": c})).collect::<Vec<_>>(),
        "target": summary.target,
    });
    if let Some(url) = &summary.report_url {
        summary_obj["report_url"] = Value::String(url.clone());
    }

    json!({
        "schema_version": SCHEMA_VERSION,
        "kingfisher_version": summary.kingfisher_version,
        "summary": summary_obj,
        "findings": included,
        "findings_omitted": findings.len().saturating_sub(take),
    })
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
            impacted_resources: 0,
            unfiltered_total: 0,
        }
    }

    #[test]
    fn schema_version_present() {
        let p = build_payload(&empty_summary(), &[], false);
        assert_eq!(p["schema_version"], "1");
    }

    #[test]
    fn empty_findings_array() {
        let p = build_payload(&empty_summary(), &[], false);
        assert_eq!(p["findings"].as_array().unwrap().len(), 0);
        assert_eq!(p["findings_omitted"], 0);
    }

    #[test]
    fn report_url_appears_in_summary_block() {
        let mut s = empty_summary();
        s.report_url = Some("https://ci.example/run/7".to_string());
        let p = build_payload(&s, &[], false);
        assert_eq!(p["summary"]["report_url"], "https://ci.example/run/7");
    }

    #[test]
    fn summary_mode_drops_findings_array() {
        let mut s = empty_summary();
        s.detail = crate::alerts::AlertDetail::Summary;
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-abc");
        let p = build_payload(&s, &[&rec, &rec, &rec], false);
        // In summary mode the findings array is empty, but findings_omitted
        // accurately reflects what was dropped so SIEMs still see the count.
        assert_eq!(p["findings"].as_array().unwrap().len(), 0);
        assert_eq!(p["findings_omitted"], 3);
    }

    #[test]
    fn fingerprint_round_trips_in_detail_mode() {
        let s = empty_summary();
        let rec = crate::alerts::make_test_record("kingfisher.aws.1", "fp-roundtrip");
        let p = build_payload(&s, &[&rec], false);
        assert_eq!(p["findings"][0]["finding"]["fingerprint"], "fp-roundtrip");
    }

    /// Regression: this sink serializes the whole record, and `snippet` is not
    /// the only field that carries the secret.
    #[test]
    fn redaction_covers_every_field_carrying_the_secret() {
        let s = empty_summary();
        let mut rec = crate::alerts::make_test_record("kingfisher.slack.2", "fp-leak");
        rec.finding.validate_command =
            Some("kingfisher validate --rule kingfisher.slack.2 'xoxb-REAL-SECRET'".to_string());
        rec.finding.revoke_command =
            Some("kingfisher revoke --rule kingfisher.slack.2 'xoxb-REAL-SECRET'".to_string());
        rec.finding.validation.response =
            "GET https://slack.com/api/auth.test?token=xoxb-REAL-SECRET".to_string();

        let redacted = build_payload(&s, &[&rec], false).to_string();
        assert!(!redacted.contains("xoxb-REAL-SECRET"), "payload leaked the secret: {redacted}");

        // `--alert-include-secret` still opts in to the full record.
        let with_secret = build_payload(&s, &[&rec], true).to_string();
        assert!(with_secret.contains("xoxb-REAL-SECRET"));
    }

    #[test]
    fn impacted_resources_present_in_summary_block() {
        let mut s = empty_summary();
        s.impacted_resources = 7;
        let p = build_payload(&s, &[], false);
        assert_eq!(p["summary"]["impacted_resources"], 7);
    }

    #[test]
    fn unfiltered_total_present_in_summary_block() {
        let mut s = empty_summary();
        s.unfiltered_total = 12;
        let p = build_payload(&s, &[], false);
        assert_eq!(p["summary"]["unfiltered_total"], 12);
    }
}
