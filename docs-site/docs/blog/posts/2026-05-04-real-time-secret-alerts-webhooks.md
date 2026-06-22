---
date: 2026-05-04
title: "Real-time Secret Alerts: Webhooks for Slack, Teams, Discord, Mattermost, and Google Chat"
description: >
  Kingfisher now POSTs scan results straight to your team's chat the moment a
  scan completes — Slack, Microsoft Teams, Discord, Mattermost, Google Chat,
  or any HTTPS endpoint. With per-finding fingerprints, a pivot link to the
  full report, and an auto-summary mode that keeps high-volume scans from
  spamming the channel.
categories:
  - Features
tags:
  - alerts
  - webhooks
  - slack
  - teams
  - discord
  - mattermost
  - google-chat
  - integrations
---

# Real-time Secret Alerts: Webhooks for Slack, Teams, Discord, Mattermost, and Google Chat

A scanner that finds secrets in CI is only useful if a human sees the result
in time to act on it. The default outcome — a JSON file in an artifact bucket
that nobody opens until the next incident — is roughly the same as not
running the scanner at all.

Kingfisher now closes that gap with **first-class webhook alerting** for the
five major team chat platforms plus a generic JSON sink, all configurable from
a single CLI flag or a project-local `kingfisher.yaml`.

<!-- more -->

## What's new

- **Five chat targets**: Slack (Block Kit), Microsoft Teams (MessageCard),
  Discord (color-coded embeds), Mattermost (Slack-compatible attachments),
  and Google Chat (cardsV2). Plus a generic JSON envelope for SIEM ingestion.
- **Auto-detail mode**: when a scan finds more than 25 secrets, the chat
  payload automatically drops the per-finding block and points the operator
  at the full report instead.
- **Report URL pivot**: every payload can carry a "Full report →" link to
  the canonical artifact (CI run, S3 object, SARIF in Code Scanning).
- **Fingerprints in every finding**: stable per-finding IDs round-trip into
  chat payloads so SIEM/SOAR tooling can dedupe across runs.
- **Secret redaction by default**: snippets are replaced with `<redacted>`
  unless you explicitly opt in. Chat retention is uneven and screenshots are
  forever — secrets do not belong in a chat audit trail.
- **YAML configuration**: declare your webhooks once in `kingfisher.yaml`
  and check it into the repo. Per-webhook overrides for format, severity
  filter, detail mode, and report URL.

## The 30-second quick start

If your webhook URL points at a recognizable host (`hooks.slack.com`,
`outlook.office.com`, `discord.com`, `chat.googleapis.com`), you don't need
to specify a format — Kingfisher infers it:

```bash
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK"
```

That's it. Run a scan, get a card in `#security-alerts` with the count, the
top rules, the first ten findings, and the Kingfisher version. URLs are
treated as secrets — they're redacted in any log line Kingfisher emits.

## Mix and match destinations in one run

`--alert-webhook` is repeatable, and each destination can have its own
format. A common pattern is a quiet SOC channel paired with a SIEM ingest
endpoint:

```bash
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SOC_WEBHOOK" \
  --alert-webhook "$TEAMS_AUDIT_WEBHOOK" \
  --alert-webhook "https://siem.example.com/ingest" \
  --alert-format generic   # only applies to the third one; first two are inferred
```

Mattermost is the one exception to auto-inference: because it's always
self-hosted, there is no canonical hostname to detect. Pass the format
explicitly:

```bash
kingfisher scan ./repo \
  --alert-webhook "https://mattermost.example.com/hooks/abc123" \
  --alert-format mattermost
```

## Auto-detail keeps high-volume scans readable

The biggest UX failure of "send everything to chat" is what happens when the
scan finds 200 secrets in a freshly-onboarded legacy repo. Truncating to ten
is worse than useless — the operator has no idea what they're missing.

`--alert-detail auto` (the default) handles this gracefully:

- 0–25 filtered findings → render the per-finding block inline.
- 26+ findings → drop the per-finding block, surface the count, and point
  the operator at the full report.

You can force the mode if you want consistent behavior:

```bash
# SOC-style summary card every time, regardless of count
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SOC_WEBHOOK" \
  --alert-detail summary \
  --alert-report-url "$GITHUB_RUN_URL"

# Bug-bounty-style raw detail, even on big runs
kingfisher scan ./repo \
  --alert-webhook "$DISCORD_RECON_WEBHOOK" \
  --alert-detail detail
```

## A pivot link is the missing link

Pair `--alert-report-url` with whatever produces the full artifact and the
chat alert becomes a one-click triage handoff. In GitHub Actions:

```yaml
- name: Run Kingfisher
  env:
    KINGFISHER_ALERT_REPORT_URL: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
  run: |
    kingfisher scan ./ \
      --alert-webhook "${{ secrets.SLACK_SECURITY_WEBHOOK }}" \
      --format sarif --output kingfisher.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: kingfisher.sarif
```

Now your Slack alert reads "**16 secrets found in repo X — Full report →**"
and one click drops the responder into the SARIF view in GitHub Code
Scanning, scoped to that exact run.

`KINGFISHER_ALERT_REPORT_URL` works as an env-var fallback if the flag isn't
passed, which is convenient for orchestrators that already export run URLs
into the environment.

## Fingerprints make dedupe trivial

Every finding in chat-detail mode and every record in the Generic JSON
payload carries a stable `fingerprint` — the same one Kingfisher emits in
its baseline file and SARIF report. Concretely:

```
• kingfisher.aws.1 at src/foo.rs:42 — <redacted> (validation: Active Credential) — fp:1635470773610661884
```

That ID is deterministic across runs. Hook it up to your dedupe layer of
choice:

- A SOAR playbook can suppress repeats during the lifetime of an open ticket.
- A SIEM rule can correlate the chat alert with the matching record in the
  scheduled SARIF ingest.
- A Slack workflow can thread alerts by fingerprint so a single offending
  secret gets one thread, not 50 separate pings.

## Declarative setup with `kingfisher.yaml`

Long CLI invocations get awkward in CI. Drop a `kingfisher.yaml` next to
the repo root and pass `--config ./kingfisher.yaml` so Kingfisher loads
it (the file is never auto-discovered — the path must be explicit):

```yaml
alerts:
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA
      format: slack
      on: findings
      min_confidence: high
      detail: detail
    - url: https://outlook.office.com/webhook/XXX
      format: teams
      on: always
      min_confidence: medium
      detail: summary
      report_url: https://github.com/org/repo/actions/runs/4242
    - url: https://siem.example.com/ingest
      format: generic
      on: always
      min_confidence: low

filters:
  skip_words: ["EXAMPLE", "PLACEHOLDER"]
  exclude:    ["vendor/", "**/node_modules/**"]
```

CLI flags and config-file webhooks are concatenated, and per-webhook
overrides let you split delivery: a *detail* card to the on-call channel for
high-confidence findings, a *summary* card to a broader channel that pages
on every run, and a generic JSON feed to your SIEM with no confidence floor
at all.

## Why this matters

Three audiences win here, and they want different things from the same tool.

**Blue teams** want a low-noise notification — "something fired, look at the
report" — with enough metadata to triage without leaving chat. Auto-summary
mode plus a report-URL pivot is exactly that workflow.

**SOC and detection-engineering teams** want machine-readable events keyed
by fingerprint so their SIEM can dedupe across runs and correlate with
existing incident tickets. The Generic JSON envelope plus stable
fingerprints handles that without you needing a separate exporter.

**Bug bounty researchers and red teamers** want raw per-finding output in
real time, often into a personal Discord channel. Default `auto` mode plus
explicit `--alert-detail detail` covers that with the same flag surface.

The combined result is that **Kingfisher's output now reaches the human who
needs to see it, in the format they expect, on the platform they already
live in** — without you having to write a single line of glue code or stand
up a notification microservice.

And because URLs are redacted in every log line and secrets are redacted in
every payload by default, you get all of that without making your chat the
next leak vector.

## Get started

```bash
# Install — see the README for other platforms
brew install kingfisher

# Scan and alert
kingfisher scan ./repo \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-report-url "$GITHUB_RUN_URL"
```

For the full schema and per-platform payload examples, see
[`docs/ALERTS.md`](https://github.com/mongodb/kingfisher/blob/main/docs/ALERTS.md)
and [`docs/CONFIG.md`](https://github.com/mongodb/kingfisher/blob/main/docs/CONFIG.md).
If a destination you'd like to alert to isn't on the list, open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
