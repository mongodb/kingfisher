---
title: "Repository Scan Audit Log"
description: "Record repository discovery, fetch and scan outcomes, timing, Git snapshot coverage, and incremental JSONL lifecycle events."
---

# Repository Scan Audit Log

Kingfisher records repository coverage for Git and source-host scans. The audit data answers four
operational questions for every eligible repository:

- Was the repository discovered, fetched, and scanned?
- When did fetch and scan work start, and how long did each phase take?
- Which Git tip SHA was resolved when scanning began?
- What history or diff scope was eligible for scanning?

Repository audit data is included in every report produced by a repository scan. For long-running multi-repository scans,
`--audit-log` also writes each lifecycle transition immediately as JSON Lines so partial evidence
survives interruption.

## Quick start

```bash
KF_GITHUB_TOKEN="..." kingfisher scan github \
  --organization acme \
  --audit-log kingfisher-repository-events.jsonl \
  --format html \
  --output kingfisher-scan.html
```

The HTML report contains a Repository Coverage section. The same data appears in the interactive
viewer when you open a native Kingfisher JSON, JSONL, or SARIF report:

```bash
kingfisher scan github --organization acme \
  --format json --output kingfisher.json \
  --audit-log kingfisher-repository-events.jsonl

kingfisher view kingfisher.json
```

Use different paths for `--audit-log` and `--output`. The former is an incremental operational
event stream; the latter is the completed findings report.

## What is recorded

The final manifest uses schema `kingfisher.repository-audit.v1` and contains:

| Field | Meaning |
|---|---|
| `run_id` | UUID shared by the manifest and all incremental events for one scan |
| `started_at`, `completed_at` | UTC RFC 3339 timestamps for the overall run |
| `duration_seconds` | Overall elapsed time measured with a monotonic clock |
| `summary` | Discovered, successful, failed, partial, and pending repository counts |
| `repositories[]` | One lifecycle record per eligible repository |

Each repository record contains its canonical URL or local path, source type, discovery timestamp,
fetch and scan phases, Git snapshot, and per-repository finding/blob/byte counts. A phase includes
`status`, timestamps, elapsed duration, method, and a bounded error message when relevant.

When one repository is selected by multiple GitHub event targets, `git.scope` is
`multiple_targets` and `git.target_snapshots[]` retains the selector and Git boundary for every
target. The aggregate record does not claim that one target's tip describes the other selectors.

Repositories are recorded after provider selectors, exclusions, and `--repo-clone-limit` have been
applied. A failed clone remains in the manifest with `fetch.status: failed` and
`scan.status: not_run`; it is not silently omitted. Non-Git assets such as S3 objects are not
repository records.

## What “Tip SHA” means

A Git commit has a unique hash called its SHA. The **tip SHA** is the commit Kingfisher pinned as
the starting point when it began scanning a repository. It is the scan's precise version bookmark:
if the branch moves later, the SHA still identifies the exact commit that was inspected. Reports
usually show the first 12 characters; the full value remains in `git.tip_sha`. `tip_ref` is the
branch or tag name that resolved to that commit, when one was available.

The tip is not necessarily the only commit or file that was scanned. The `git.scope` field says
whether Kingfisher scanned the tip's tree, a diff, the working tree, or all Git objects that were
fetched locally. For a diff, the older endpoint is recorded separately as `base_sha` or
`inclusive_root_sha`.

## Git coverage semantics

Git history is not one straight line: branches and merges make a single “last commit scanned”
ambiguous. Kingfisher records three easier-to-audit facts instead: the tip SHA (the starting
bookmark), an optional boundary SHA (the older edge of a diff), and the scan scope (what data was
eligible). The available scopes are:

| `git.scope` | Meaning |
|---|---|
| `all_fetched_git_objects` | Every eligible file-content object (Git blob) available in the fetched object database, including history objects—not only the tip's files |
| `git_tree` | The tree resolved from `--branch` |
| `working_tree` | The checked-out files used with `--git-history none` |
| `tree_diff` | The change set between `--since-commit` and the resolved tip |
| `inclusive_root_tree_diff` | Changes beginning at `--branch-root-commit` or the computed branch root |
| `staged_tree_diff` | The staged index changes selected by `--staged` |

`tip_ref` and `tip_sha` identify the starting tip. Range scans also record `base_ref`/`base_sha` or
`inclusive_root_ref`/`inclusive_root_sha`. Full-history scans include `fetched_commit_count` when
Git can compute it, plus the clone mode and whether the repository is shallow. These fields
describe what was locally available and eligible; they do not pretend that a Git graph has one
chronological “last” commit.

## Incremental JSONL events

`--audit-log FILE` emits and flushes these events as work progresses:

- `run_started`
- `repository_discovered`
- `repository_fetch_started`
- `repository_fetch_completed` or `repository_fetch_failed`
- `repository_scan_started`
- `repository_scan_completed`, `repository_scan_partial`, or `repository_scan_failed`
- `run_completed`

Every line is independent JSON and includes the schema, event name, run ID, event timestamp, and
the current repository record when applicable. `run_completed` also includes the final summary.
If the process is interrupted, the file ends at the last flushed transition, making unfinished
repositories visible as `pending` or `running`.

```bash
# Failed fetches
jq -c 'select(.event == "repository_fetch_failed") | .repository' \
  kingfisher-repository-events.jsonl

# Repositories whose scan started but did not emit a terminal scan event
jq -r 'select(.event == "repository_scan_started") | .repository.key' \
  kingfisher-repository-events.jsonl
```

Audit errors are whitespace-normalized, truncated to 2,048 characters, and redact HTTP URL
userinfo and Authorization header values. Treat audit files as security records anyway: repository
names, local paths, commit identifiers, and operational failures may be sensitive.

## Report format locations

| Format | Audit location |
|---|---|
| JSON | Top-level `audit` object |
| JSONL | A final `{"audit": {...}}` record |
| TOON | Top-level `audit` object |
| BSON | A trailing document containing `audit` |
| SARIF | `runs[].properties.repository_audit` |
| Pretty | `REPOSITORY COVERAGE` section |
| HTML | Self-contained Repository Coverage and findings tables with search, filters, and sortable columns |

The standalone HTML report embeds its styles and JavaScript; it does not load a table library or
send report data elsewhere. Click any column heading to toggle ascending/descending order. The
Repository Coverage table has repository and status filters, while Detailed Findings adds
validation and confidence filters. Long commands are collapsed until opened and Git URLs use a
compact source link so large reports remain readable. The report is also print-friendly: browser
printing switches to landscape, removes the scrolling frame, repeats table headers across pages,
and expands command details. If you filter before printing, only the visible rows are printed.

The browser viewer merges repository manifests from multiple native Kingfisher reports and exposes
them in its Coverage workspace. It supports repository/status search, pagination, lifecycle timing,
tip and boundary SHAs, scan scope, per-repository volume, and failure messages. Imported generic
SARIF, Gitleaks, and TruffleHog reports do not gain repository coverage unless the source report
contains Kingfisher audit data.

## CI guidance

Keep the incremental event log even when a completed JSON, SARIF, or HTML report is also retained.
The report is the concise final artifact; the event log is the recovery and troubleshooting trail
for timeouts, cancellation, worker failures, or access changes during a large organization scan.

For an auditable CI run, archive both files with the same retention and access controls:

```bash
kingfisher scan github --organization acme \
  --audit-log artifacts/repository-events.jsonl \
  --format sarif --output artifacts/kingfisher.sarif
```
