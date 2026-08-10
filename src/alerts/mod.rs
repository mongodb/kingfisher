//! Alert sinks: post scan results to Slack / Microsoft Teams / a generic webhook.
//!
//! Activated via CLI (`--alert-webhook`) or `kingfisher.yaml`. The dispatch is
//! best-effort: failure to deliver an alert never changes the scan exit code,
//! it only emits a `warn!` on stderr. Every webhook URL is treated as a secret —
//! we redact path/query when logging.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use kingfisher_core::ValidationOutcome;

use crate::cli::commands::scan::ConfidenceLevel;
use crate::reporter::{AccessMapEntry, FindingReporterRecord};
use crate::rules::rule::Confidence;

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

/// Which findings a sink is allowed to report, independent of `min_confidence`.
///
/// Each variant is a strict subset of the previous one: `AccessMapOnly` only
/// ever matches findings that are also `OnlyActive` (access-mapping requires a
/// validated, active credential), which is itself a subset of `Actionable`, of
/// `ExcludeInactive`, of `All`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[clap(rename_all = "kebab-case")]
pub enum AlertFindingFilter {
    /// No filtering by validation status or access-map result.
    #[default]
    All,
    /// Drop `VerifiedInactive` findings; keep active + unknown/not-attempted.
    ExcludeInactive,
    /// Keep active and assumed-valid findings — the same tier
    /// `--validation-filter actionable` reports. Private keys and other
    /// unvalidatable high-signal secrets page; unverifiable noise does not.
    Actionable,
    /// Keep only `VerifiedActive` findings. Note this excludes `Assumed`, which
    /// was never live-validated.
    OnlyActive,
    /// Keep only findings with a matching `--access-map` result (implies
    /// active, since access-mapping only runs on validated credentials).
    AccessMapOnly,
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
    /// Which findings this sink is allowed to report, on top of `min_confidence`.
    pub finding_filter: AlertFindingFilter,
    /// When `true`, skip this sink entirely if filtering (min-confidence +
    /// finding_filter) leaves nothing to report — except for the deliberate
    /// `on: Always` clean-scan heartbeat (zero findings scan-wide). Defaults
    /// to `false` to preserve pre-existing behavior on upgrade.
    pub prevent_empty: bool,
}

/// Summary numbers we surface to every sink, regardless of format.
///
/// Built per-sink in `dispatch` from that sink's own filtered finding list, so
/// every count here (including `total`) always matches what's actually
/// rendered in the payload below it — never the whole-scan numbers — with one
/// deliberate exception: `unfiltered_total`, which exists precisely so a
/// payload can tell a genuinely clean scan apart from a sink whose filters
/// excluded everything.
///
/// Per-sink fields (`report_url`, `detail`, `unfiltered_total`) are overlaid
/// by `dispatch` immediately after construction. They are intentionally not
/// parameters of `from_findings` because they don't derive from the (already
/// filtered) finding list passed to it.
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
    /// Sum of impacted-resource counts (from `--access-map`) across findings
    /// in this summary. `0` when access-map wasn't run or none of this sink's
    /// findings have a matching access-map result.
    pub impacted_resources: usize,
    /// Whole-scan finding count, before this sink's `min_confidence` /
    /// `finding_filter` were applied. Used only to distinguish "the scan
    /// found nothing" (`unfiltered_total == 0`) from "this sink's filters
    /// excluded everything the scan found" (`unfiltered_total > 0 && total
    /// == 0`) — payload builders must not otherwise use this in place of
    /// `total`.
    pub unfiltered_total: usize,
}

/// `--access-map` results indexed for alert dispatch. Impact is keyed per
/// credential, not per finding, since one mapping covers every occurrence.
#[derive(Clone, Debug, Default)]
struct AccessMapImpact {
    credential_by_fingerprint: HashMap<String, usize>,
    resources_per_credential: Vec<usize>,
}

impl AccessMapImpact {
    /// Entries whose identity mapping failed are skipped: their placeholder
    /// resource would report impact that was never established.
    fn from_entries(entries: &[AccessMapEntry]) -> Self {
        let mut credential_by_fingerprint: HashMap<String, usize> = HashMap::new();
        let mut resources_per_credential = Vec::new();
        for entry in entries.iter().filter(|e| e.mapping_error.is_none()) {
            // A resource split across two permission groups is counted twice —
            // acceptable for a rough "impacted resources" indicator.
            let resources: usize = entry.groups.iter().map(|g| g.resources.len()).sum();
            let credential = resources_per_credential.len();
            let mut mapped = false;
            for fingerprint in entry.fingerprint.iter().chain(entry.fingerprints.iter()) {
                credential_by_fingerprint.insert(fingerprint.clone(), credential);
                mapped = true;
            }
            if mapped {
                resources_per_credential.push(resources);
            }
        }
        Self { credential_by_fingerprint, resources_per_credential }
    }

    /// True when this finding's credential was successfully access-mapped.
    fn is_mapped(&self, fingerprint: &str) -> bool {
        self.credential_by_fingerprint.contains_key(fingerprint)
    }

    /// Resources exposed by the distinct credentials behind `findings`. A
    /// credential found at several offsets contributes its resources once.
    fn impacted_resources(&self, findings: &[&FindingReporterRecord]) -> usize {
        let mut counted = std::collections::HashSet::new();
        findings
            .iter()
            .filter_map(|f| self.credential_by_fingerprint.get(&f.finding.fingerprint))
            .filter(|credential| counted.insert(**credential))
            .map(|credential| self.resources_per_credential[*credential])
            .sum()
    }
}

impl AlertSummary {
    pub fn from_findings(findings: &[&FindingReporterRecord], target: Option<String>) -> Self {
        let mut active = 0usize;
        let mut inactive = 0usize;
        let mut unknown = 0usize;
        // Borrow the rule ids while counting; this runs once per sink, so only
        // the five that survive the truncation are worth allocating.
        let mut by_rule_map: HashMap<&str, usize> = HashMap::new();
        for f in findings {
            *by_rule_map.entry(f.rule.id.as_str()).or_default() += 1;
            match f.finding.validation.outcome {
                ValidationOutcome::VerifiedActive => active += 1,
                ValidationOutcome::VerifiedInactive => inactive += 1,
                _ => unknown += 1,
            }
        }
        let mut counted: Vec<(&str, usize)> = by_rule_map.into_iter().collect();
        counted.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        counted.truncate(5);
        let by_rule: Vec<(String, usize)> =
            counted.into_iter().map(|(id, count)| (id.to_string(), count)).collect();

        Self {
            total: findings.len(),
            active,
            inactive,
            unknown,
            by_rule,
            kingfisher_version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            report_url: None,
            // `dispatch` overlays these three per-sink, before any builder runs.
            detail: AlertDetail::Detail,
            impacted_resources: 0,
            unfiltered_total: 0,
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

/// How much of a secret a payload shows under `--alert-include-secret`.
pub(crate) const SNIPPET_LIMIT: usize = 32;

pub(crate) fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

pub(crate) fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let prefix: String = s.chars().take(n).collect();
    format!("{prefix}…")
}

/// Headline for a sink with nothing to report, which has to tell a clean scan
/// apart from filters that excluded everything. `None` when there are findings.
pub(crate) fn empty_headline(summary: &AlertSummary) -> Option<String> {
    if summary.total > 0 {
        return None;
    }
    Some(if summary.unfiltered_total > 0 {
        format!(
            "Kingfisher: scan complete — 0 of {} finding{} matched this alert's filters",
            summary.unfiltered_total,
            plural(summary.unfiltered_total)
        )
    } else {
        "Kingfisher: scan complete — no findings".to_string()
    })
}

/// Headline carrying the per-outcome counts. Sinks that prefix an emoji or want
/// a shorter title build on [`empty_headline`] instead.
pub(crate) fn headline(summary: &AlertSummary) -> String {
    if let Some(empty) = empty_headline(summary) {
        return empty;
    }
    let counts = format!(
        "{} active, {} inactive, {} unknown",
        summary.active, summary.inactive, summary.unknown
    );
    let impact = if summary.impacted_resources > 0 {
        format!(
            ", {} impacted resource{}",
            summary.impacted_resources,
            plural(summary.impacted_resources)
        )
    } else {
        String::new()
    };
    format!("Kingfisher: {} finding{} ({counts}{impact})", summary.total, plural(summary.total))
}

/// Body text for `AlertDetail::Summary`, where per-finding lines are dropped.
/// Callers wrap it in their own emphasis markup.
pub(crate) fn suppression_notice(total: usize) -> String {
    format!(
        "{total} findings — per-finding detail suppressed (summary mode). See full report for \
         specifics."
    )
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
///
/// `access_map` is the (possibly empty) set of `--access-map` results for
/// this scan; used both for `AlertFindingFilter::AccessMapOnly` filtering and
/// to populate `AlertSummary::impacted_resources`. `dry_run` builds and logs
/// each sink's resolved payload instead of POSTing it — always redacted, since
/// a logged payload outlives the run.
pub async fn dispatch(
    sinks: &[AlertSink],
    findings: &[FindingReporterRecord],
    access_map: &[AccessMapEntry],
    target: Option<String>,
    dry_run: bool,
) {
    if sinks.is_empty() {
        return;
    }
    // A dry run never POSTs, so it must not depend on client construction
    // succeeding.
    let client = if dry_run {
        None
    } else {
        match build_client() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("alert dispatch: failed to build HTTP client: {}", e);
                return;
            }
        }
    };

    let unfiltered_total = findings.len();
    let access_map_impact = AccessMapImpact::from_entries(access_map);
    debug!("alert dispatch: total={} sinks={}", unfiltered_total, sinks.len());

    for sink in sinks {
        if matches!(sink.on, AlertOn::Findings) && unfiltered_total == 0 {
            debug!(
                "alert dispatch: skipping {} (on=findings, no findings)",
                redact_webhook(&sink.url)
            );
            continue;
        }
        let filtered: Vec<&FindingReporterRecord> = findings
            .iter()
            .filter(|f| matches_min_confidence(&f.finding.confidence, sink.min_confidence))
            .filter(|f| {
                matches_finding_filter(
                    f.finding.validation.outcome,
                    &f.finding.fingerprint,
                    sink.finding_filter,
                    &access_map_impact,
                )
            })
            .collect();

        let is_clean_heartbeat = matches!(sink.on, AlertOn::Always) && unfiltered_total == 0;
        if sink.prevent_empty && filtered.is_empty() && !is_clean_heartbeat {
            debug!(
                "alert dispatch: skipping {} (filters left nothing to report)",
                redact_webhook(&sink.url)
            );
            continue;
        }

        // Per-sink summary, built from this sink's own filtered set, and
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
        let mut summary = AlertSummary::from_findings(&filtered, target.clone());
        summary.report_url = sink.report_url.clone();
        summary.detail = resolved_detail;
        summary.unfiltered_total = unfiltered_total;
        summary.impacted_resources = access_map_impact.impacted_resources(&filtered);

        // The dry-run payload is logged, and logs persist — never copy a
        // secret there, even for a sink that includes secrets in real POSTs.
        let include_secret = sink.include_secret && !dry_run;
        if dry_run && sink.include_secret {
            warn!(
                "alert dry-run: secrets are redacted in the logged payload for {}; \
                 --alert-include-secret only applies to real POSTs",
                redact_webhook(&sink.url)
            );
        }

        let payload = match sink.format {
            AlertFormat::Slack => slack::build_payload(&summary, &filtered, include_secret),
            AlertFormat::Teams => teams::build_payload(&summary, &filtered, include_secret),
            AlertFormat::Generic => generic::build_payload(&summary, &filtered, include_secret),
            AlertFormat::Discord => discord::build_payload(&summary, &filtered, include_secret),
            AlertFormat::Mattermost => {
                mattermost::build_payload(&summary, &filtered, include_secret)
            }
            AlertFormat::Googlechat => {
                googlechat::build_payload(&summary, &filtered, include_secret)
            }
        };

        if dry_run {
            info!(
                "alert dry-run: would POST to {} ({} finding(s)):\n{}",
                redact_webhook(&sink.url),
                filtered.len(),
                serde_json::to_string_pretty(&payload).unwrap_or_default()
            );
            continue;
        }

        // Always `Some` here: only `dry_run` leaves it `None`, and that
        // `continue`d above.
        if let Some(client) = &client {
            match post(client, &sink.url, &payload).await {
                Ok(()) => {
                    info!("alert posted to {}", redact_webhook(&sink.url));
                }
                Err(e) => {
                    warn!("alert dispatch failed for {}: {}", redact_webhook(&sink.url), e);
                }
            }
        }
    }
}

fn matches_min_confidence(finding_confidence: &str, threshold: ConfidenceLevel) -> bool {
    // The reporter renders confidence through `Confidence: Display`, which is
    // lowercase; parsing is case-insensitive so either spelling works.
    let level = finding_confidence.parse::<Confidence>().unwrap_or(Confidence::Medium);
    level.is_at_least(&Confidence::from(threshold))
}

fn matches_finding_filter(
    outcome: ValidationOutcome,
    fingerprint: &str,
    filter: AlertFindingFilter,
    access_map_impact: &AccessMapImpact,
) -> bool {
    match filter {
        AlertFindingFilter::All => true,
        AlertFindingFilter::ExcludeInactive => outcome != ValidationOutcome::VerifiedInactive,
        AlertFindingFilter::Actionable => outcome.is_actionable(),
        AlertFindingFilter::OnlyActive => outcome.is_verified_active(),
        AlertFindingFilter::AccessMapOnly => {
            outcome.is_verified_active() && access_map_impact.is_mapped(fingerprint)
        }
    }
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
            confidence: "medium".to_string(),
            entropy: "4.5".to_string(),
            validation: ValidationInfo {
                outcome: ValidationOutcome::VerifiedActive,
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
    use kingfisher_core::ValidationOutcome as VO;

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

    /// Pins the wording every chat sink renders, including the impact clause
    /// and the distinction between a clean scan and filters that matched
    /// nothing.
    #[test]
    fn headline_covers_every_branch() {
        let mut s = AlertSummary::from_findings(&[], None);
        assert_eq!(headline(&s), "Kingfisher: scan complete — no findings");

        s.unfiltered_total = 1;
        assert_eq!(
            headline(&s),
            "Kingfisher: scan complete — 0 of 1 finding matched this alert's filters"
        );
        s.unfiltered_total = 4;
        assert_eq!(
            headline(&s),
            "Kingfisher: scan complete — 0 of 4 findings matched this alert's filters"
        );

        s.total = 1;
        s.active = 1;
        assert_eq!(headline(&s), "Kingfisher: 1 finding (1 active, 0 inactive, 0 unknown)");

        s.total = 3;
        s.inactive = 1;
        s.unknown = 1;
        s.impacted_resources = 1;
        assert_eq!(
            headline(&s),
            "Kingfisher: 3 findings (1 active, 1 inactive, 1 unknown, 1 impacted resource)"
        );
        s.impacted_resources = 2;
        assert_eq!(
            headline(&s),
            "Kingfisher: 3 findings (1 active, 1 inactive, 1 unknown, 2 impacted resources)"
        );

        // A sink with findings never renders the empty-headline variants.
        assert!(empty_headline(&s).is_none());
    }

    #[test]
    fn finding_filter_all_matches_everything() {
        let map = AccessMapImpact::default();
        for outcome in [VO::VerifiedActive, VO::VerifiedInactive, VO::NotAttempted, VO::Assumed] {
            assert!(matches_finding_filter(outcome, "fp1", AlertFindingFilter::All, &map));
        }
    }

    #[test]
    fn finding_filter_exclude_inactive_drops_only_inactive() {
        let map = AccessMapImpact::default();
        assert!(matches_finding_filter(
            VO::VerifiedActive,
            "fp1",
            AlertFindingFilter::ExcludeInactive,
            &map
        ));
        assert!(matches_finding_filter(
            VO::NotAttempted,
            "fp1",
            AlertFindingFilter::ExcludeInactive,
            &map
        ));
        assert!(!matches_finding_filter(
            VO::VerifiedInactive,
            "fp1",
            AlertFindingFilter::ExcludeInactive,
            &map
        ));
    }

    #[test]
    fn finding_filter_only_active_keeps_only_verified_active() {
        let map = AccessMapImpact::default();
        assert!(matches_finding_filter(
            VO::VerifiedActive,
            "fp1",
            AlertFindingFilter::OnlyActive,
            &map
        ));
        // `Assumed` was never live-validated, so it is not "active" here even
        // though `is_actionable()` accepts it for --validation-filter.
        for outcome in [VO::VerifiedInactive, VO::NotAttempted, VO::Assumed, VO::Unavailable] {
            assert!(!matches_finding_filter(outcome, "fp1", AlertFindingFilter::OnlyActive, &map));
        }
    }

    /// `actionable` exists for secrets no provider API can confirm — a private
    /// key is `Assumed`, never `VerifiedActive` — while still excluding the
    /// outcomes that mean "we could not check".
    #[test]
    fn finding_filter_actionable_keeps_assumed_but_not_unchecked() {
        let map = AccessMapImpact::default();
        for outcome in [VO::VerifiedActive, VO::Assumed] {
            assert!(matches_finding_filter(outcome, "fp1", AlertFindingFilter::Actionable, &map));
        }
        for outcome in [VO::VerifiedInactive, VO::NotAttempted, VO::Unavailable, VO::Skipped] {
            assert!(!matches_finding_filter(outcome, "fp1", AlertFindingFilter::Actionable, &map));
        }
    }

    #[test]
    fn finding_filter_access_map_only_requires_fingerprint_match() {
        let map = AccessMapImpact::from_entries(&[access_map_entry(
            "aws",
            "fp-mapped",
            &["bucket-a", "bucket-b", "bucket-c"],
        )]);
        assert!(matches_finding_filter(
            VO::VerifiedActive,
            "fp-mapped",
            AlertFindingFilter::AccessMapOnly,
            &map
        ));
        assert!(!matches_finding_filter(
            VO::VerifiedActive,
            "fp-other",
            AlertFindingFilter::AccessMapOnly,
            &map
        ));
    }

    #[test]
    fn finding_filter_access_map_only_still_requires_active_outcome() {
        // Regression: an access-map entry can exist for a fingerprint whose
        // finding did NOT validate as active (e.g. a GitLab-rule finding
        // recorded on a bare 2xx response per maybe_record_access_map in
        // scanner/validation.rs). AccessMapOnly must not let that through —
        // its doc comment promises it's a subset of OnlyActive.
        let map =
            AccessMapImpact::from_entries(&[access_map_entry("gitlab", "fp-gitlab", &["group/p"])]);
        assert!(!matches_finding_filter(
            VO::VerifiedInactive,
            "fp-gitlab",
            AlertFindingFilter::AccessMapOnly,
            &map
        ));
    }

    /// Like `make_test_record`, but with a configurable confidence/validation
    /// outcome so dispatch-level tests can exercise `min_confidence` /
    /// `finding_filter`. `status` is derived from `outcome` so the record stays
    /// internally consistent, matching what the reporter produces.
    fn record_with(
        rule_id: &str,
        fingerprint: &str,
        confidence: &str,
        outcome: ValidationOutcome,
    ) -> crate::reporter::FindingReporterRecord {
        use crate::reporter::{
            FindingRecordData, FindingReporterRecord, RuleMetadata, ValidationInfo,
        };
        FindingReporterRecord {
            rule: RuleMetadata { name: rule_id.to_string(), id: rule_id.to_string() },
            finding: FindingRecordData {
                snippet: "AKIAEXAMPLE_REDACTED_TOKEN_12345".to_string(),
                fingerprint: fingerprint.to_string(),
                confidence: confidence.to_string(),
                entropy: "4.5".to_string(),
                validation: ValidationInfo {
                    outcome,
                    status: outcome.display_name().to_string(),
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

    /// A successfully-mapped entry for `fingerprint`, with one permission group
    /// covering `resources`.
    fn access_map_entry(
        provider: &str,
        fingerprint: &str,
        resources: &[&str],
    ) -> crate::reporter::AccessMapEntry {
        use crate::reporter::{AccessMapEntry, AccessMapResourceGroup};
        AccessMapEntry {
            provider: provider.to_string(),
            account: None,
            groups: vec![AccessMapResourceGroup {
                resources: resources.iter().map(|r| r.to_string()).collect(),
                permissions: vec![],
            }],
            token_details: None,
            provider_metadata: None,
            fingerprint: Some(fingerprint.to_string()),
            fingerprints: Vec::new(),
            mapping_error: None,
            permissions_by_severity: None,
            context: None,
        }
    }

    fn test_sink(url: &str) -> AlertSink {
        AlertSink {
            url: url.to_string(),
            format: AlertFormat::Generic,
            on: AlertOn::Findings,
            min_confidence: ConfidenceLevel::Low,
            include_secret: false,
            report_url: None,
            detail: AlertDetail::Detail,
            finding_filter: AlertFindingFilter::All,
            prevent_empty: false,
        }
    }

    mod dispatch_tests {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        use super::*;

        #[tokio::test]
        async fn prevent_empty_skips_sink_when_filters_leave_nothing() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.min_confidence = ConfidenceLevel::High;
            sink.prevent_empty = true;

            let findings =
                vec![record_with("kingfisher.aws.1", "fp1", "medium", VO::VerifiedActive)];
            dispatch(&[sink], &findings, &[], None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        #[tokio::test]
        async fn prevent_empty_false_still_posts_when_filters_leave_nothing() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.min_confidence = ConfidenceLevel::High;
            sink.prevent_empty = false;

            let findings =
                vec![record_with("kingfisher.aws.1", "fp1", "medium", VO::VerifiedActive)];
            dispatch(&[sink], &findings, &[], None, false).await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            // The scan wasn't clean — one finding existed, it just didn't
            // pass this sink's min_confidence — so the posted summary must
            // say so via unfiltered_total, not just report total == 0.
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(body["summary"]["total"], 0);
            assert_eq!(body["summary"]["unfiltered_total"], 1);
        }

        #[tokio::test]
        async fn always_heartbeat_posts_despite_prevent_empty_on_zero_total() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.on = AlertOn::Always;
            sink.prevent_empty = true;

            dispatch(&[sink], &[], &[], None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 1);
        }

        #[tokio::test]
        async fn access_map_only_filters_to_matching_fingerprint_and_reports_impact() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::AccessMapOnly;
            sink.min_confidence = ConfidenceLevel::Low;

            let mapped = record_with("kingfisher.aws.1", "fp-mapped", "high", VO::VerifiedActive);
            let unmapped = record_with("kingfisher.aws.2", "fp-other", "high", VO::VerifiedActive);
            let access_map = vec![access_map_entry(
                "aws",
                "fp-mapped",
                &["arn:aws:s3:::bucket-a", "arn:aws:s3:::bucket-b"],
            )];

            dispatch(&[sink], &[mapped, unmapped], &access_map, None, false).await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(body["findings"].as_array().unwrap().len(), 1);
            assert_eq!(body["findings"][0]["finding"]["fingerprint"], "fp-mapped");
            assert_eq!(body["summary"]["impacted_resources"], 2);
        }

        #[tokio::test]
        async fn access_map_only_excludes_finding_with_access_map_entry_but_inactive_status() {
            // Regression: an access-map entry can be recorded for a finding
            // that never validated as active (e.g. a GitLab-rule finding
            // recorded on a bare 2xx response). AccessMapOnly must still
            // exclude it, since it's documented as a subset of OnlyActive.
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::AccessMapOnly;
            sink.min_confidence = ConfidenceLevel::Low;
            sink.prevent_empty = true;

            let inactive_but_mapped =
                record_with("kingfisher.gitlab.1", "fp-gitlab", "high", VO::VerifiedInactive);
            let access_map = vec![access_map_entry("gitlab", "fp-gitlab", &["group/project"])];

            dispatch(&[sink], &[inactive_but_mapped], &access_map, None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        /// Regression: `map_requests` assigns a fingerprint even to the
        /// `build_failed_result` placeholder, whose synthetic resource must not
        /// be read as confirmed impact.
        #[tokio::test]
        async fn access_map_only_excludes_findings_whose_mapping_failed() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::AccessMapOnly;
            sink.prevent_empty = true;

            let mut failed = access_map_entry("aws", "fp-failed", &[""]);
            failed.mapping_error = Some("sts:GetCallerIdentity returned 403".to_string());

            let findings =
                vec![record_with("kingfisher.aws.1", "fp-failed", "high", VO::VerifiedActive)];
            dispatch(&[sink], &findings, &[failed], None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        /// Regression: the collector maps a credential once and keeps only the
        /// first occurrence's fingerprint, but every occurrence it covers must
        /// still be reported — with its resources counted once.
        #[tokio::test]
        async fn access_map_only_keeps_every_occurrence_of_a_mapped_credential() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::AccessMapOnly;

            let mut entry = access_map_entry("aws", "fp-first", &["arn:aws:s3:::bucket-a"]);
            entry.fingerprints = vec!["fp-first".to_string(), "fp-second".to_string()];

            let findings = vec![
                record_with("kingfisher.aws.1", "fp-first", "high", VO::VerifiedActive),
                record_with("kingfisher.aws.1", "fp-second", "high", VO::VerifiedActive),
            ];
            dispatch(&[sink], &findings, &[entry], None, false).await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(body["findings"].as_array().unwrap().len(), 2);
            assert_eq!(body["summary"]["impacted_resources"], 1);
        }

        #[tokio::test]
        async fn failed_mapping_is_not_counted_in_impacted_resources() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            // `all` still reports both findings; only the impact count changes.
            let sink = test_sink(&server.uri());

            let mut failed = access_map_entry("aws", "fp-failed", &[""]);
            failed.mapping_error = Some("sts:GetCallerIdentity returned 403".to_string());
            let mapped = access_map_entry("aws", "fp-mapped", &["arn:aws:s3:::bucket-a"]);

            let findings = vec![
                record_with("kingfisher.aws.1", "fp-failed", "high", VO::VerifiedActive),
                record_with("kingfisher.aws.2", "fp-mapped", "high", VO::VerifiedActive),
            ];
            dispatch(&[sink], &findings, &[failed, mapped], None, false).await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(body["findings"].as_array().unwrap().len(), 2);
            assert_eq!(body["summary"]["impacted_resources"], 1);
        }

        /// `prevent_empty` only spares the clean-scan heartbeat, which keys on
        /// the whole-scan total. With `on: always` and findings that this
        /// sink's filters all reject, the sink stays silent.
        #[tokio::test]
        async fn prevent_empty_silences_an_always_sink_when_filters_reject_everything() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.on = AlertOn::Always;
            sink.prevent_empty = true;
            sink.finding_filter = AlertFindingFilter::OnlyActive;

            let findings =
                vec![record_with("kingfisher.aws.1", "fp1", "high", VO::VerifiedInactive)];
            dispatch(&[sink], &findings, &[], None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        #[tokio::test]
        async fn access_map_only_filters_everything_when_access_map_is_empty() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::AccessMapOnly;
            sink.prevent_empty = true;

            let findings = vec![record_with("kingfisher.aws.1", "fp1", "high", VO::VerifiedActive)];
            dispatch(&[sink], &findings, &[], None, false).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        #[tokio::test]
        async fn dry_run_makes_no_http_calls() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let sink = test_sink(&server.uri());
            let findings = vec![record_with("kingfisher.aws.1", "fp1", "high", VO::VerifiedActive)];
            dispatch(&[sink], &findings, &[], None, true).await;

            assert_eq!(server.received_requests().await.unwrap().len(), 0);
        }

        /// The dry-run payload is logged, and logs persist, so
        /// `--alert-include-secret` must not leak the secret into it.
        #[tokio::test]
        async fn dry_run_redacts_secrets_even_when_the_sink_includes_them() {
            let logs = CaptureWriter::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(logs.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .finish();
            // `#[tokio::test]` is single-threaded, so this thread-local
            // subscriber stays installed across the `.await` below.
            let _guard = tracing::subscriber::set_default(subscriber);

            let mut finding = record_with("kingfisher.aws.1", "fp1", "high", VO::VerifiedActive);
            finding.finding.snippet = "AKIAIOSFODNN7EXAMPLE-live-value".to_string();
            finding.finding.validate_command =
                Some("kingfisher validate --rule kingfisher.aws.1 'AKIAIOSFODNN7EXAMPLE'".into());

            // Every format, so a builder added later cannot opt out of this.
            for format in [
                AlertFormat::Slack,
                AlertFormat::Teams,
                AlertFormat::Generic,
                AlertFormat::Discord,
                AlertFormat::Mattermost,
                AlertFormat::Googlechat,
            ] {
                let mut sink = test_sink("https://hooks.example.com/services/T0/B0/XXX");
                sink.include_secret = true;
                sink.format = format;

                dispatch(&[sink], &[finding.clone()], &[], None, true).await;
            }

            let logged = logs.contents();
            assert!(
                !logged.contains("AKIAIOSFODNN7EXAMPLE"),
                "dry-run log leaked the secret: {logged}"
            );
            assert!(logged.contains("<redacted>"), "dry-run log has no payload: {logged}");
        }

        /// In-memory `MakeWriter` to assert on what `dispatch` logged.
        #[derive(Clone, Default)]
        struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

        impl CaptureWriter {
            fn contents(&self) -> String {
                String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
            }
        }

        impl std::io::Write for CaptureWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CaptureWriter {
            type Writer = Self;

            fn make_writer(&'a self) -> Self::Writer {
                self.clone()
            }
        }

        #[tokio::test]
        async fn header_counts_reflect_only_active_filter_not_whole_scan() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200))
                .mount(&server)
                .await;

            let mut sink = test_sink(&server.uri());
            sink.finding_filter = AlertFindingFilter::OnlyActive;

            let findings = vec![
                record_with("kingfisher.aws.1", "fp-active", "high", VO::VerifiedActive),
                record_with("kingfisher.aws.2", "fp-inactive", "high", VO::VerifiedInactive),
            ];
            dispatch(&[sink], &findings, &[], None, false).await;

            let requests = server.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1);
            let body: serde_json::Value = requests[0].body_json().unwrap();
            assert_eq!(body["summary"]["total"], 1);
            assert_eq!(body["summary"]["active"], 1);
            assert_eq!(body["summary"]["inactive"], 0);
            assert_eq!(body["findings"].as_array().unwrap().len(), 1);
        }
    }
}
