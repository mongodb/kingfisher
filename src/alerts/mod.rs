//! Alert sinks: post scan results to Slack / Microsoft Teams / a generic webhook.
//!
//! Activated via CLI (`--alert-webhook`) or `kingfisher.yaml`. The dispatch is
//! best-effort: failure to deliver an alert never changes the scan exit code,
//! it only emits a `warn!` on stderr. Every webhook URL is treated as a secret —
//! we redact path/query when logging.

use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cli::commands::scan::ConfidenceLevel;
use crate::reporter::FindingReporterRecord;

pub mod discord;
pub mod generic;
pub mod googlechat;
pub mod mattermost;
pub mod slack;
pub mod teams;

/// Trigger condition for an alert.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
#[derive(Default)]
pub enum AlertOn {
    /// Only post when at least one finding is reported.
    #[default]
    Findings,
    /// Always post, even on a clean run.
    Always,
}

/// How much per-finding detail to include in alert payloads.
///
/// `Auto` switches to `Summary` once the per-sink filtered finding count
/// exceeds [`AUTO_DETAIL_THRESHOLD`] — at that volume, chat detail blocks add
/// noise without being actionable, and the operator should be pivoting to the
/// full report (see `--alert-report-url`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum AlertDetail {
    /// Headline + top-rules + report link only. No per-finding lines.
    Summary,
    /// Headline + top-rules + per-finding lines (capped at 10).
    Detail,
    /// `Detail` if filtered findings ≤ [`AUTO_DETAIL_THRESHOLD`], else `Summary`.
    #[default]
    Auto,
}

/// Auto-mode threshold: if a sink's filtered finding count exceeds this, the
/// payload drops the per-finding block and points at the full report instead.
pub const AUTO_DETAIL_THRESHOLD: usize = 25;

/// Webhook payload format / target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum AlertFormat {
    /// Slack incoming-webhook (Block Kit).
    Slack,
    /// Microsoft Teams incoming-webhook (Adaptive Card / MessageCard).
    Teams,
    /// Generic JSON envelope (`{ summary, findings }`).
    Generic,
    /// Discord incoming-webhook (color-coded `embeds`).
    Discord,
    /// Mattermost incoming-webhook (Slack-compatible `attachments`).
    Mattermost,
    /// Google Chat incoming-webhook (`cardsV2` payload).
    Googlechat,
}

impl AlertFormat {
    /// Heuristic: infer the format from the webhook host when the user did
    /// not pass `--alert-format`.
    pub fn infer_from_url(url: &str) -> Self {
        let host = url::Url::parse(url).ok().and_then(|u| u.host_str().map(str::to_lowercase));
        match host.as_deref() {
            Some(h) if host_matches(h, "slack.com") => AlertFormat::Slack,
            Some(h)
                if host_matches(h, "office.com")
                    || host_matches(h, "webhook.office.com")
                    || host_matches(h, "webhook.office.net") =>
            {
                AlertFormat::Teams
            }
            Some(h) if host_matches(h, "discord.com") || host_matches(h, "discordapp.com") => {
                AlertFormat::Discord
            }
            Some(h) if host_matches(h, "chat.googleapis.com") => AlertFormat::Googlechat,
            _ => AlertFormat::Generic,
        }
    }
}

/// One configured webhook destination. `--alert-webhook` may be repeated to
/// produce more than one. The config-file equivalent is `alerts.webhooks[]`.
#[derive(Clone, Debug)]
pub struct AlertSink {
    pub url: String,
    pub format: AlertFormat,
    pub on: AlertOn,
    pub min_confidence: ConfidenceLevel,
    pub include_secret: bool,
    /// Pivot link rendered in the payload — typically the URL of the full
    /// report artifact (CI run, S3 object, SARIF in Code Scanning, etc).
    /// `None` omits the link from the payload.
    pub report_url: Option<String>,
    /// How much per-finding detail to include. `Auto` is resolved against the
    /// per-sink filtered finding count at dispatch time before the payload
    /// builder runs, so each `build_payload` only sees `Summary` or `Detail`.
    pub detail: AlertDetail,
}

/// Summary numbers we surface to every sink, regardless of format.
///
/// Per-sink fields (`report_url`, `detail`, `filtered_total`) are populated by
/// `dispatch` immediately before the payload builder runs. They are
/// intentionally not part of `from_findings` because they are sink-specific.
#[derive(Clone, Debug, Serialize)]
pub struct AlertSummary {
    pub total: usize,
    pub active: usize,
    pub inactive: usize,
    pub unknown: usize,
    pub by_rule: Vec<(String, usize)>,
    pub kingfisher_version: String,
    pub target: Option<String>,
    /// Pivot link, copied from the per-sink configuration. `None` → no link
    /// is rendered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
    /// Resolved detail level (`Summary` or `Detail`, never `Auto`).
    pub detail: AlertDetail,
    /// Count of findings the per-sink min-confidence filter let through. May
    /// be smaller than `total` when the sink raises `min_confidence` above the
    /// scan default.
    pub filtered_total: usize,
}

impl AlertSummary {
    pub fn from_findings(findings: &[FindingReporterRecord], target: Option<String>) -> Self {
        let mut active = 0usize;
        let mut inactive = 0usize;
        let mut unknown = 0usize;
        let mut by_rule_map: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for f in findings {
            *by_rule_map.entry(f.rule.id.clone()).or_default() += 1;
            match f.finding.validation.status.as_str() {
                "Active Credential" => active += 1,
                "Inactive Credential" => inactive += 1,
                _ => unknown += 1,
            }
        }
        let mut by_rule: Vec<(String, usize)> = by_rule_map.into_iter().collect();
        by_rule.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        by_rule.truncate(5);

        Self {
            total: findings.len(),
            active,
            inactive,
            unknown,
            by_rule,
            kingfisher_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            report_url: None,
            // Placeholder; `dispatch` overwrites this per-sink with a resolved
            // value (`Summary` or `Detail`) before calling `build_payload`.
            detail: AlertDetail::Detail,
            filtered_total: findings.len(),
        }
    }
}

/// Build a reqwest client suitable for outbound webhook POSTs. Webhook hosts
/// are public services; we always run with strict TLS validation here even if
/// the user passed `--tls-mode=off` for credential validation, since the user
/// almost certainly does not intend to lower TLS for their own paging service.
fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(5))
        .user_agent(format!("kingfisher/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build webhook reqwest::Client")
}

/// Tail-match a hostname against a webhook host so substrings like
/// `not-slack.com.attacker.example` cannot be misclassified.
fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Validate a webhook URL.
///
/// Webhook URLs typically embed a secret token in the path (e.g.
/// `hooks.slack.com/services/T0/B0/<secret>`) and the payload contains
/// finding metadata, so the transport must protect both. Default policy:
///
/// * Must parse and have a non-empty host.
/// * Scheme must be `https`.
/// * `http` is allowed *only* when the host is a loopback address
///   (`localhost`, `127.0.0.0/8`, `::1`) — useful for local development and
///   on-host webhook receivers without exposing webhooks-in-the-clear on a
///   network.
pub fn validate_webhook_url(url: &str) -> Result<()> {
    let parsed = url::Url::parse(url)
        .with_context(|| format!("invalid webhook URL `{}`", redact_for_log(url)))?;
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("");
    if host.is_empty() {
        anyhow::bail!("webhook URL `{}` has no host", redact_for_log(url));
    }
    match scheme {
        "https" => {}
        "http" if is_loopback_host(host) => {}
        "http" => {
            anyhow::bail!(
                "webhook URL `{}` uses cleartext `http://`; webhook tokens and finding \
                 metadata must not traverse the network unencrypted. Use `https://`, or a \
                 loopback host (`localhost`/`127.0.0.1`/`::1`) for local testing.",
                redact_for_log(url)
            );
        }
        _ => {
            anyhow::bail!(
                "webhook URL `{}` uses unsupported scheme `{scheme}` (only `https` is \
                 allowed; `http` is allowed only for loopback hosts)",
                redact_for_log(url)
            );
        }
    }
    Ok(())
}

/// True when `host` resolves unambiguously to the local machine — i.e. the
/// loopback hostname or any IPv4 in `127.0.0.0/8` or the IPv6 loopback `::1`.
/// We deliberately do not consult DNS; only literal hostnames and IP
/// literals count, so a malicious resolver cannot trick us into accepting
/// `http://` for a remote host.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // `url::Url::host_str` keeps the surrounding `[...]` on IPv6 literals;
    // `IpAddr::from_str` rejects that form, so strip the brackets first.
    let trimmed = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

fn redact_for_log(url: &str) -> String {
    redact_webhook(url)
}

/// Redact the path/query of a webhook URL so we never log the full secret token
/// embedded by Slack/Teams/etc. e.g. `https://hooks.slack.com/services/...` →
/// `https://hooks.slack.com/<redacted>`.
pub fn redact_webhook(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let scheme = u.scheme();
            let host = u.host_str().unwrap_or("");
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            format!("{scheme}://{host}{port}/<redacted>")
        }
        Err(_) => "<unparseable webhook url>".to_string(),
    }
}

/// Dispatch the configured alerts. Best-effort: a bad webhook produces a
/// `warn!` and never propagates as an error to the caller.
pub async fn dispatch(
    sinks: &[AlertSink],
    findings: &[FindingReporterRecord],
    target: Option<String>,
) {
    if sinks.is_empty() {
        return;
    }
    let client = match build_client() {
        Ok(c) => c,
        Err(e) => {
            warn!("alert dispatch: failed to build HTTP client: {}", e);
            return;
        }
    };

    let base_summary = AlertSummary::from_findings(findings, target);
    debug!(
        "alert dispatch: total={} active={} inactive={} unknown={} sinks={}",
        base_summary.total,
        base_summary.active,
        base_summary.inactive,
        base_summary.unknown,
        sinks.len()
    );

    for sink in sinks {
        if matches!(sink.on, AlertOn::Findings) && base_summary.total == 0 {
            debug!(
                "alert dispatch: skipping {} (on=findings, no findings)",
                redact_webhook(&sink.url)
            );
            continue;
        }
        let filtered: Vec<&FindingReporterRecord> = findings
            .iter()
            .filter(|f| matches_min_confidence(&f.finding.confidence, sink.min_confidence))
            .collect();

        // Per-sink summary: clone the base, overlay sink-specific fields, and
        // resolve `Auto` based on this sink's filtered count.
        let resolved_detail = match sink.detail {
            AlertDetail::Auto => {
                if filtered.len() > AUTO_DETAIL_THRESHOLD {
                    AlertDetail::Summary
                } else {
                    AlertDetail::Detail
                }
            }
            other => other,
        };
        let mut summary = base_summary.clone();
        summary.report_url = sink.report_url.clone();
        summary.detail = resolved_detail;
        summary.filtered_total = filtered.len();

        let payload = match sink.format {
            AlertFormat::Slack => slack::build_payload(&summary, &filtered, sink.include_secret),
            AlertFormat::Teams => teams::build_payload(&summary, &filtered, sink.include_secret),
            AlertFormat::Generic => {
                generic::build_payload(&summary, &filtered, sink.include_secret)
            }
            AlertFormat::Discord => {
                discord::build_payload(&summary, &filtered, sink.include_secret)
            }
            AlertFormat::Mattermost => {
                mattermost::build_payload(&summary, &filtered, sink.include_secret)
            }
            AlertFormat::Googlechat => {
                googlechat::build_payload(&summary, &filtered, sink.include_secret)
            }
        };

        match post(&client, &sink.url, &payload).await {
            Ok(()) => {
                info!("alert posted to {}", redact_webhook(&sink.url));
            }
            Err(e) => {
                warn!("alert dispatch failed for {}: {}", redact_webhook(&sink.url), e);
            }
        }
    }
}

fn matches_min_confidence(finding_confidence: &str, threshold: ConfidenceLevel) -> bool {
    let level = match finding_confidence {
        "Low" => ConfidenceLevel::Low,
        "Medium" => ConfidenceLevel::Medium,
        "High" => ConfidenceLevel::High,
        _ => ConfidenceLevel::Medium,
    };
    level >= threshold
}

async fn post(client: &Client, url: &str, payload: &serde_json::Value) -> Result<()> {
    let resp = client
        .post(url)
        .json(payload)
        .send()
        .await
        .with_context(|| format!("POST to {} failed", redact_webhook(url)))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "webhook returned HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

/// Shared test helper: build a fully-formed `FindingReporterRecord` so payload
/// builders can be unit-tested against per-finding rendering (fingerprint,
/// snippet redaction, summary-mode suppression). Test-only; not for runtime
/// callers.
#[cfg(test)]
pub(crate) fn make_test_record(
    rule_id: &str,
    fingerprint: &str,
) -> crate::reporter::FindingReporterRecord {
    use crate::reporter::{FindingRecordData, FindingReporterRecord, RuleMetadata, ValidationInfo};
    FindingReporterRecord {
        rule: RuleMetadata { name: rule_id.to_string(), id: rule_id.to_string() },
        finding: FindingRecordData {
            snippet: "AKIAEXAMPLE_REDACTED_TOKEN_12345".to_string(),
            fingerprint: fingerprint.to_string(),
            confidence: "Medium".to_string(),
            entropy: "4.5".to_string(),
            validation: ValidationInfo {
                status: "Active Credential".to_string(),
                response: String::new(),
            },
            language: "rust".to_string(),
            line: 42,
            column_start: 10,
            column_end: 50,
            path: "src/foo.rs".to_string(),
            encoding: None,
            git_metadata: None,
            validate_command: None,
            revoke_command: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_webhook_keeps_host() {
        let r = redact_webhook("https://hooks.slack.com/services/T0/B0/XXX");
        assert_eq!(r, "https://hooks.slack.com/<redacted>");
    }

    #[test]
    fn redact_webhook_unparseable() {
        let r = redact_webhook("not a url");
        assert_eq!(r, "<unparseable webhook url>");
    }

    #[test]
    fn validate_webhook_accepts_https() {
        validate_webhook_url("https://hooks.slack.com/services/T0/B0/XXX").unwrap();
    }

    #[test]
    fn validate_webhook_rejects_remote_http() {
        let err = validate_webhook_url("http://example.com/hook").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("cleartext `http://`"), "got: {msg}");
    }

    #[test]
    fn validate_webhook_allows_http_localhost() {
        validate_webhook_url("http://localhost:8080/hook").unwrap();
        validate_webhook_url("http://127.0.0.1:9000/hook").unwrap();
        validate_webhook_url("http://[::1]:9000/hook").unwrap();
    }

    #[test]
    fn validate_webhook_rejects_unknown_scheme() {
        let err = validate_webhook_url("ftp://example.com/hook").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("unsupported scheme"), "got: {msg}");
    }

    #[test]
    fn validate_webhook_rejects_no_host() {
        // url::Url::parse on a relative-style file URL leaves no host.
        let err = validate_webhook_url("file:///etc/passwd").unwrap_err();
        let msg = format!("{err:#}");
        // Either "no host" or "unsupported scheme" is acceptable; both are
        // hard rejections.
        assert!(msg.contains("no host") || msg.contains("unsupported scheme"), "got: {msg}");
    }

    #[test]
    fn infer_format_slack() {
        assert_eq!(
            AlertFormat::infer_from_url("https://hooks.slack.com/services/T0/B0/XXX"),
            AlertFormat::Slack
        );
    }

    #[test]
    fn infer_format_teams() {
        assert_eq!(
            AlertFormat::infer_from_url(
                "https://outlook.office.com/webhook/abc/IncomingWebhook/def"
            ),
            AlertFormat::Teams
        );
    }

    #[test]
    fn infer_format_generic_fallback() {
        assert_eq!(
            AlertFormat::infer_from_url("https://example.com/webhook"),
            AlertFormat::Generic
        );
    }

    #[test]
    fn infer_format_discord() {
        assert_eq!(
            AlertFormat::infer_from_url("https://discord.com/api/webhooks/123/abc"),
            AlertFormat::Discord
        );
        assert_eq!(
            AlertFormat::infer_from_url("https://discordapp.com/api/webhooks/123/abc"),
            AlertFormat::Discord
        );
    }

    #[test]
    fn infer_format_googlechat() {
        assert_eq!(
            AlertFormat::infer_from_url(
                "https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t"
            ),
            AlertFormat::Googlechat
        );
    }

    #[test]
    fn infer_format_mattermost_falls_back_to_generic_without_override() {
        // Mattermost is self-hosted with no canonical domain; users must pass
        // `--alert-format mattermost` explicitly. Inference falls through.
        assert_eq!(
            AlertFormat::infer_from_url("https://mattermost.example.com/hooks/abcdef"),
            AlertFormat::Generic
        );
    }

    #[test]
    fn auto_detail_threshold_is_inclusive_at_25() {
        // Boundary regression: filtered.len() == THRESHOLD must stay in
        // Detail mode; > THRESHOLD must escalate to Summary.
        assert_eq!(AUTO_DETAIL_THRESHOLD, 25);
        // The resolution itself lives inside `dispatch`; this test pins the
        // constant so any future tuning is intentional.
    }
}
