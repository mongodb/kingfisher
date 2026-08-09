# Alert Webhooks

Kingfisher can POST a scan summary (and optionally per-finding details) to one
or more webhooks when a scan completes — Slack, Microsoft Teams, Discord,
Mattermost, Google Chat, or any HTTPS endpoint that accepts a JSON POST.

Alerting is **best-effort**. A bad webhook produces a `WARN` line on stderr and
*never* changes the scan exit code; this avoids breaking CI when paging
infrastructure is having a bad day.

## Quick start

```bash
# Slack incoming webhook (format inferred from the URL host).
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK"

# Teams + a generic webhook in one run.
kingfisher scan ./repo \
  --alert-webhook "$TEAMS_WEBHOOK" \
  --alert-webhook "https://siem.example.com/ingest" \
  --alert-format generic

# Discord webhook (auto-detected from discord.com).
kingfisher scan ./repo --alert-webhook "$DISCORD_SECURITY_WEBHOOK"

# Mattermost (self-hosted — format must be specified explicitly).
kingfisher scan ./repo \
  --alert-webhook "https://mattermost.example.com/hooks/abc123" \
  --alert-format mattermost
```

The format is inferred from the URL host:

| Host pattern                          | Inferred format |
|---------------------------------------|-----------------|
| `*.slack.com`                         | `slack`         |
| `*.office.com` / `webhook.office.*`   | `teams`         |
| `discord.com` / `discordapp.com`      | `discord`       |
| `chat.googleapis.com`                 | `googlechat`    |
| anything else                         | `generic`       |

Set `--alert-format` to override. Mattermost has no canonical hostname (it is
always self-hosted), so it is **never** inferred — pass
`--alert-format mattermost` whenever you target a Mattermost server.

## Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--alert-webhook URL` | *(none, repeatable)* | Destination URL; pass once per webhook. |
| `--alert-format slack\|teams\|generic\|discord\|mattermost\|googlechat` | inferred | Payload shape. |
| `--alert-on findings\|always` | `findings` | `always` posts even on a clean run. |
| `--alert-min-confidence low\|medium\|high` | `medium` | Findings below this are dropped from the payload. |
| `--alert-include-secret` | off | Include the (truncated to ~32 chars) secret value in the payload. Ignored under `--alert-dry-run`, which always redacts. |
| `--alert-report-url URL` | *(none)* | Pivot link rendered in every payload — typically a CI run URL or report-artifact URL. Reads `KINGFISHER_ALERT_REPORT_URL` env var as a fallback. |
| `--alert-detail summary\|detail\|auto` | `auto` | How much per-finding detail to render. `auto` switches to `summary` once the per-sink filtered finding count exceeds 25. |
| `--alert-finding-filter all\|exclude-inactive\|only-active\|access-map-only` | `all` | Restrict which findings a sink reports, on top of `--alert-min-confidence`. See [Finding filters](#finding-filters) below. |
| `--alert-prevent-empty` | off | Skip a sink entirely when `--alert-min-confidence` / `--alert-finding-filter` leave nothing to report, instead of posting an alert with an empty findings list. Does **not** suppress the deliberate `--alert-on always` clean-scan heartbeat. Off by default to preserve existing behavior on upgrade. |
| `--alert-dry-run` | off | Build and log each sink's resolved payload instead of POSTing it — use to validate filter configuration before wiring a real webhook URL. A URL is still required and still validated, so pass a placeholder such as `https://example.invalid/hook`. Secrets are always redacted in the logged payload (a log outlives the run), so `--alert-include-secret` has no effect here; a `WARN` is emitted when both are set. |

Webhook URLs are sensitive: the host/path/query are redacted in logs. Pass them
via environment variables (`$SLACK_SECURITY_WEBHOOK`) or CI secrets, never
inline in committed files.

## Finding filters

`--alert-finding-filter` narrows which findings a sink is allowed to report,
independent of confidence:

- **`all`** (default) — no filtering by validation status or access-map result.
- **`exclude-inactive`** — drop findings a validator authoritatively rejected
  (`Inactive Credential`); keep active findings plus every inconclusive
  outcome (assumed-valid, inconclusive, skipped, not attempted).
- **`only-active`** — keep only live-validated `Active Credential` findings.
  This deliberately excludes `Assumed Valid (Not Live-Validated)`, which was
  never confirmed against the provider — use `exclude-inactive` if you want
  assumed-valid findings to page you too.
- **`access-map-only`** — keep only findings that have a matching
  `--access-map` result. This requires `--access-map` to also be passed;
  without it, the filter matches nothing and the sink never reports (a
  `WARN` is logged when alerts are dispatched, i.e. after the scan). Since
  access-mapping only ever runs on validated, active credentials, this is
  the strictest tier — a subset of `only-active`. Credentials whose identity
  mapping *failed* (the provider refused the lookup, the network was
  unavailable, …) do not count: the report records the mapping error, and the
  finding is treated as unmapped rather than as confirmed impact. A credential
  found in several places is mapped once, and every occurrence is reported;
  `impacted_resources` counts that credential's resources once.

Every summary count in a payload (total/active/inactive/unknown, and
`impacted_resources` when access-map data is available) reflects that sink's
own filtered results, not the whole scan — a sink with `--alert-finding-filter
only-active` never shows a header count that includes inactive findings it
didn't list. **This changed:** these counts previously came from the whole
scan, so a sink already using `--alert-min-confidence` will see them drop to
its own filtered numbers. `unfiltered_total` carries the whole-scan count.

```bash
# Page only on findings with confirmed cloud impact.
kingfisher scan ./repo --access-map \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-finding-filter access-map-only \
  --alert-prevent-empty

# Preview what a filter change would send, without touching the real webhook.
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-finding-filter only-active \
  --alert-dry-run
```

## Detail modes

Chat is a notification surface, not a report viewer. `--alert-detail` controls
how much per-finding detail Kingfisher tries to cram into a single message:

- **`detail`** — header + summary stats + up to 10 findings inline + report link.
  Best for low-volume runs where the reviewer wants triage info in chat.
- **`summary`** — header + summary stats + report link, *no* per-finding lines.
  Best for high-volume runs and SOC/SIEM ingestion where chat just needs to
  page someone with a count.
- **`auto`** (default) — `detail` when filtered findings ≤ 25, otherwise
  `summary`. Avoids the "10 shown, 190 omitted" anti-pattern on large repos.

Pair `summary` (or `auto` at scale) with `--alert-report-url` so the operator
has a one-click pivot to the full report:

```bash
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-report-url "$GITHUB_RUN_URL" \
  --alert-detail auto \
  --format json --output ./kingfisher-report.json
```

## Per-finding fingerprints

Every finding line in `detail` mode (and every record in the Generic JSON
payload) carries a stable `fingerprint`. Downstream automation (SIEM/SOAR,
Jira webhooks, custom dedupe) can use it to:

- Suppress repeat alerts when the same secret reappears in subsequent runs.
- Correlate the chat alert with the matching `kingfisher.fingerprint` in the
  baseline file or the SARIF report.
- Build per-finding triage threads / tickets keyed by fingerprint.

## Payload shapes

### Slack (Block Kit)

A header line, a "Top rules" section, an optional findings block (capped at 10
entries), and a context line with the Kingfisher version. Theme colour cues are
applied via the message structure itself.

### Microsoft Teams (MessageCard)

A coloured card — green if clean, amber if findings without active validation,
red if any active. Facts list active/inactive/unknown counts and the top rules.

### Generic JSON

```json
{
  "schema_version": "1",
  "kingfisher_version": "1.99.0",
  "summary": {
    "total": 3,
    "active": 1,
    "inactive": 1,
    "unknown": 1,
    "impacted_resources": 0,
    "unfiltered_total": 3,
    "by_rule": [{"rule_id": "kingfisher.aws.1", "count": 2}],
    "target": "./repo"
  },
  "findings": [ /* array of FindingReporterRecord, capped at 200 */ ],
  "findings_omitted": 0
}
```

Findings are the same shape as `kingfisher scan --format json` produces, so
existing JSON consumers work unchanged.

`summary.target` describes the scan target requested on the command line. It supports local paths,
Git URLs, repository hosts, cloud buckets, container images, and collaboration-platform scans; a
non-path scan running with redirected stdin is not mislabeled as an internal temporary file.

### Discord (Embed)

A single embed with a color-coded sidebar — red on any verified-active credential,
amber when findings exist but none are verified active, green on a clean run.
Inline `Active`/`Inactive`/`Unknown` fields, a `Top rules` field, the
per-finding detail in the embed `description` (capped at 10 entries), and a
footer with the Kingfisher version.

### Mattermost (Slack-compatible attachments)

Renders as a single attachment with the same red/amber/green sidebar (via the
legacy Slack `attachments[].color` field). Mattermost ≥ 5.x renders this
identically; we deliberately use legacy attachments instead of Block Kit
because Block Kit support in Mattermost is partial. Findings are listed in
the attachment `text` body, capped at 10 entries.

### Google Chat (cardsV2)

A modern `cardsV2` card with a "Summary" section (`decoratedText` widgets for
active/inactive/unknown counts and a top-rules paragraph) and a "Findings"
section (capped at 10 entries). Google Chat does not expose a card-color knob
in its public webhook API, so severity is conveyed textually — the title is
prefixed with 🚨 when any verified-active credential is detected.

## Configuring via `kingfisher.yaml`

CLI flags and config-file webhooks are concatenated. Per-webhook overrides live
in the config so you can mix one Slack channel for active findings with a
broader Teams channel that paged on every run:

```yaml
alerts:
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA
      format: slack
      on: findings
      min_confidence: high
    - url: https://outlook.office.com/webhook/XXX
      format: teams
      on: always
      min_confidence: medium
      include_secret: false
    - url: https://discord.com/api/webhooks/123/abcdef
      format: discord
      on: findings
    - url: https://mattermost.example.com/hooks/xxx
      format: mattermost      # required — never auto-inferred
      on: findings
    - url: https://chat.googleapis.com/v1/spaces/AAA/messages?key=k&token=t
      format: googlechat
      on: always
      report_url: https://github.com/org/repo/actions/runs/4242    # per-webhook pivot link
      detail: summary                                              # blue-team mode for this sink
    - url: https://hooks.slack.com/services/T0/B0/CCC
      format: slack
      on: findings
      finding_filter: access-map-only   # requires --access-map on the scan
      prevent_empty: true               # skip this sink when the filter leaves nothing to report
```

`report_url` and `detail` can be set globally via `--alert-report-url` and
`--alert-detail`, or overridden per-webhook in YAML. Per-webhook overrides
let you, for example, send a *summary* card with a CI link to a busy team
channel while still sending *detail* + per-finding fingerprints to a quieter
SOC channel.

See [`docs/CONFIG.md`](CONFIG.md) for the full config schema.
