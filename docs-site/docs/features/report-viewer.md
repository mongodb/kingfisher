---
title: "Report Viewer & Triager (Kingfisher, SARIF, Gitleaks, TruffleHog)"
description: "Triage Kingfisher, SARIF, Gitleaks, and TruffleHog findings in one browser-based viewer. Use the bundled local viewer via `kingfisher view` or the hosted static viewer on GitHub Pages."
---

# Report Viewer & Triager

Kingfisher ships a browser-based **report viewer and triager** for four report families:

- **Kingfisher** JSON / JSONL / SARIF — with full `access_map` blast-radius data when available
- **SARIF** 2.1.0 — normalized into the same triage workflow
- **Gitleaks** JSON
- **TruffleHog** JSON / JSONL — verified findings are surfaced as active credentials

The same UI is available two ways:

- **Locally**, bundled into every Kingfisher binary: `kingfisher view ./report.json`
- **Hosted**, as a static upload-based copy on GitHub Pages: **[Open the hosted report viewer](../viewer/index.html)** ([https://mongodb.github.io/kingfisher/viewer/](https://mongodb.github.io/kingfisher/viewer/))

Both render reports entirely client-side. Nothing about the uploaded report leaves the browser.

## Why a visual viewer/triager matters

Gitleaks and TruffleHog are great at emitting candidate matches; Kingfisher goes further by live-validating and mapping blast radius. But raw JSON and SARIF are not how a human decides which finding to rotate first. The viewer turns that output into a triage workflow:

- **Skim at a glance** — findings are grouped by detector, rule, file, and repository with counts and validation state, instead of one JSON object per line in a terminal.
- **Cross-tool triage in one place** — import a Gitleaks scan, a TruffleHog scan, and a Kingfisher scan of the same codebase and look at them side-by-side with deduplication, rather than reconciling three different schemas by hand.
- **Rotate real secrets first** — validated Kingfisher findings and TruffleHog-verified findings are surfaced as active credentials; unverified/static matches are marked as not attempted.
- **Dedup automatically** — the same secret appearing across multiple reports, directories, or scan runs collapses to one entry by fingerprint / secret identity.
- **See blast radius** — when a Kingfisher report was generated with `--access-map`, the viewer opens an interactive blast-radius graph with a side inspector and details view, so you can trace the identity, resources, and permissions without digging through nested JSON.
- **Share and archive** — export filtered subsets for tickets, rotation runbooks, or audit reviewers.

Tools like Gitleaks and TruffleHog surface candidates. Kingfisher's viewer helps you decide which ones matter — and it works with their output, not just its own.

## Using the local viewer via the `kingfisher` CLI

The local viewer is part of the `kingfisher` binary — no separate install, no network calls.

```bash
# Open a Kingfisher scan report
kingfisher view kingfisher.json

# Open Kingfisher SARIF output
kingfisher view kingfisher.sarif

# Import a Gitleaks JSON report
kingfisher view gitleaks-report.json

# Import a TruffleHog JSON or JSONL report
kingfisher view trufflehog-report.jsonl

# Combine multiple reports — deduplicated by fingerprint / secret identity
kingfisher view kingfisher.json kingfisher.sarif gitleaks.json trufflehog.jsonl

# Or load every JSON/JSONL/SARIF report in a directory (non-recursive)
kingfisher view ./reports/
```

`kingfisher view` starts a tiny local web server on `127.0.0.1:7890` and opens the browser automatically. Use `--port` to pick another port and `--address 0.0.0.0` to expose the viewer from a container or remote host.

You can also chain scanning and viewing in a single step:

```bash
# Scan and open the report in the browser when it finishes
kingfisher scan /path/to/code --view-report

# Same, but bind to all interfaces and a specific port (useful in Docker)
kingfisher scan /path/to/code \
  --view-report \
  --view-report-address 0.0.0.0 \
  --view-report-port 7891
```

## Using the hosted viewer

The docs site publishes a static, upload-based copy of the viewer at:

**[https://mongodb.github.io/kingfisher/viewer/](https://mongodb.github.io/kingfisher/viewer/)**

Drag a Kingfisher, SARIF, Gitleaks, or TruffleHog report into the page (or use the file picker) to triage it in your browser. You can also merge multiple reports in one session by uploading them one after another — duplicates collapse automatically. It's useful when you want to:

- Triage a report on a machine that doesn't have Kingfisher installed
- Show a finding with its blast-radius context without shipping the raw JSON around

## Sample data

You can test the hosted page with a bundled sample report:

- [Open sample report JSON](../viewer/sample-report.json)

## Caveats for imported SARIF / Gitleaks / TruffleHog reports

- Generic imported reports are display-oriented. They do not carry Kingfisher-native `access_map` data or drive `kingfisher validate` / `kingfisher revoke`.
- Kingfisher-produced SARIF can restore compatible validation status, command, fingerprint, and `access_map` properties when present.
- Fingerprints on imported findings use the report's native fingerprint when available; otherwise the viewer synthesizes one from rule, location, and snippet data.
- TruffleHog findings marked as verified are shown as active credentials; all other imported findings are treated as not attempted rather than inactive.
- For full validation and blast-radius mapping, re-scan the source with Kingfisher and (when authorized) add `--access-map`.

Gitleaks and TruffleHog are both widely used open-source secret scanners with their own strengths; Kingfisher's viewer reads their standard JSON output plus SARIF so teams that already run other tooling can pull those findings into the same triage workflow. Kingfisher is not affiliated with or endorsed by the Gitleaks project or Truffle Security Co.; TruffleHog and Gitleaks are trademarks of their respective owners.
