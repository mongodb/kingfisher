# Benchmark

A Go-based benchmarking tool that clones a set of repositories, runs secret-scanning
tools (Kingfisher, TruffleHog, and Gitleaks), and reports execution times,
findings, and network-request counts. An intercepting HTTP proxy (without TLS
decryption) counts plain HTTP requests and HTTPS CONNECT tunnels. Requests inside
a TLS tunnel and traffic that bypasses the proxy are not observed.

## Features

- **Repository cloning** — clones a predefined list of repositories (skips ones already present).
- **Tool execution** — runs each enabled scanner and collects timing, findings, and validation metrics.
- **Network-request counting** — an HTTP proxy on `127.0.0.1:9191` counts plain HTTP requests and HTTPS CONNECT tunnels sent through it.
- **Tool versions** — records `kingfisher`/`trufflehog`/`gitleaks` versions in the report.
- **Timestamped results folder** — every run writes a `benchmark-<timestamp>/` directory (see below).
- **Markdown report** — environment, tool versions, runtime, findings, validated/verified, and
  network-request tables. The report is printed to stdout *and* saved as `comparison_<timestamp>.md`.
- **Runtime chart** — renders `runtime-comparison-<timestamp>.png` via QuickChart.io, matching
  [the reference chart](../runtime-comparison.png): 1360×966 pixels, green/blue/amber bars,
  outlined Kingfisher bars, and straight downward arrows labeled with the runtime reduction
  relative to the fastest successful competitor, or labeled "slower" when another
  scanner wins.
  Versions are shown beneath tool names, and the analysis month/year appears
  directly beneath the title. The filename carries a timestamp, so existing charts
  are never overwritten.
- **Failure reporting** — saves stderr logs, marks failed scans as `ERROR`, and excludes them
  from the chart. Saves a progress report after each repository.

## Latest local results

The [current three-tool comparison](benchmark-session-20261020-comparisons/three-tools/comparison_20261020-184315.md)
contains Kingfisher, TruffleHog, and Gitleaks measurements for all nine repositories.
Completed detection-only measurements are reused with explicit source provenance;
no rescan is needed for chart-only presentation changes. Charts include program
versions beneath tool names and the analysis month beneath the title. Successful
TruffleHog timings remain included despite localized diagnostics.

Automation supports only these three scanners. Historical results, logs, source
snapshots, and archived notes are retained as evidence, not supported run commands.

The [redundant partial rerun](benchmark-session-20261020-three-tools/README.md)
was stopped under the reuse instruction. The
[earlier complete baseline](benchmark-session-20261020/README.md) and
[performance investigation](benchmark-session-20261020/investigation-20261020/README.md)
remain preserved with explicit source links; partial rerun measurements are not
merged into the completed comparison.

### Audit before publishing

A zero exit status does not guarantee complete input processing. Inspect stderr
and Kingfisher audit metadata before publishing, and trace diagnostics against
the executed tool version before deciding their impact. Preserve measured runtime
cells for scans that complete successfully with localized diagnostics; annotate
the affected metadata, file, or decoder-stream coverage rather than calling the
whole run a fatal failure or its timing invalid. Omit only fatal or missing
measurements from the runtime chart, never plot them as zero. Keep original
reports, exact command timings, and coverage caveats alongside any corrected
report/chart. Finding and network counts remain observations, not complete-history
recall claims. Neither exit success nor the absence of logged errors establishes
complete or equivalent cross-tool coverage. See the local session's
[TruffleHog investigation](benchmark-session-20261020/investigation-20261020/trufflehog-findings.md).

## How it works

The whole tool lives in a single [main.go](main.go), organized into sections: configuration
and types, orchestration, tool-version capture, the request-counting proxy, the
per-tool scanners and parsers, the Markdown report, and the QuickChart.io chart
generation. For each repository it clones the repo (skipping any already on disk),
runs every enabled scanner through the proxy, then writes the report and renders
the chart. Chart rendering requires network access to `quickchart.io`.

### Output layout

Each run creates a `benchmark-<timestamp>/` directory (under `-out`) containing:

```text
benchmark-20260529-193512/
├── comparison_20260529-193512.md      # the full Markdown report
├── runtime-comparison-20260529-193512.png
├── croc-kingfisher.json               # raw tool output, per repo + tool
├── croc-trufflehog.json
├── croc-gitleaks.json
├── croc-gitleaks.json.stderr          # scanner diagnostics, per repo + tool
└── ...
```

### Finding counts

Counts come from Kingfisher's report metadata (or finding records when metadata is
absent), TruffleHog's `verified + unverified` summary, and the length of Gitleaks'
JSON report array.
Validated/verified counts use successful live checks only; Kingfisher findings
labelled **Assumed Valid (Not Live-Validated)** are not counted as live-validation
successes.

Run two separate comparisons against the same unchanged repository revisions and
refs:

- **Detection-only** (`-validate=false`, the default): Kingfisher, TruffleHog,
  and Gitleaks, with Kingfisher validation and TruffleHog verification explicitly
  disabled. Only this run supplies **Runtime Comparison** and the runtime chart.
- **Validation-enabled** (`-validate=true -gitleaks=false`):
  Kingfisher and TruffleHog only. This separate run supplies **Network Requests
  Comparison** and **Validated / Verified Findings**, not the runtime chart.

Each tool runs once per repository with full available Git history and its default
detection settings. Update checks are disabled where supported, and Kingfisher's
repository timeout is disabled. TruffleHog's automatic private clone preparation is
included in its runtime. Worker counts use tool defaults; on the measured 16-core
host, Kingfisher uses 16 scanning threads. No repetitions or cache flushing are
performed. Different rules, file-size limits, archive handling, filters, provenance
collection, and deduplication mean finding counts do not measure equivalent recall.
Kingfisher may also enumerate working-tree files, unlike the Git-diff-oriented
scanners; existing working-tree changes must be recorded rather than discarded.

Proxy counts are **not total API requests**: each HTTPS CONNECT tunnel is counted
once regardless of how many requests it carries, and direct/non-HTTP traffic can
bypass the proxy. Zero observed traffic is not proof that no validation occurred.
Raw reports can contain credentials; keep them local and share aggregate results
rather than secret values.

## Prerequisites

- **Go 1.24 or newer** — [install Go](https://go.dev/doc/install)
- **Git** — must be installed and on your `PATH`.
- **Scanning tools** on your `PATH`:
  - `kingfisher`
  - `trufflehog`
  - `gitleaks` *(unless `-gitleaks=false` is passed)*

Use the latest published binaries from the official
[TruffleHog releases](https://github.com/trufflesecurity/trufflehog/releases/latest) and
[Gitleaks releases](https://github.com/gitleaks/gitleaks/releases/latest).
The installed binaries used on October 20, 2026 were Kingfisher 2.14.0,
TruffleHog 3.99.2, and Gitleaks 8.30.1. The runner uses the
executables on `PATH` and records their actual versions; it does not install or
upgrade scanners.

## Build

From this directory:

```bash
go build -o benchmark main.go
```

## Usage

```bash
# Detection-only: Kingfisher, TruffleHog, and Gitleaks:
./benchmark -basedir "$HOME/dev/bench-repos" -validate=false -out detection-only

# Separate validation-enabled run: only Kingfisher and TruffleHog, no chart:
./benchmark -basedir "$HOME/dev/bench-repos" -validate=true \
  -gitleaks=false -chart=false -out validation-enabled

# Smoke-test the three selected scanners without rendering a chart:
./benchmark -basedir "$HOME/dev/bench-repos" -repos croc -validate=false -chart=false

# Regenerate only the chart from a detection-only report (no scanning):
go run main.go -chart-from "detection-only/benchmark-<timestamp>"
```

Each mode creates its own timestamped directory and preserves separate JSON and
stderr files. `commands.jsonl` records exact subprocess argument arrays, durations,
and exit errors. Reports record repository HEADs, refs fingerprints, shallow
status, and working-tree changes alongside tool versions and environment. Do not
update, fetch, checkout, edit, or run garbage collection on the corpus between runs.
Validation-enabled runs contact credential providers; they do not request
revocation or access-map enumeration.

### Scanner command lines

The harness invokes subprocesses directly (not through a shell). Equivalent shell
commands below define `$REPO` as an absolute repository path, `$RAW` as that scan's
JSON output path.
`$REPO_URI` is the URL-escaped `file://` URI for `$REPO` (for example,
`file:///Users/me/dev/bench-repos/croc`). Paths vary per repository; flags do not.
All scanner subprocesses inherit these proxy settings:

```bash
export HTTP_PROXY=http://127.0.0.1:9191 HTTPS_PROXY=http://127.0.0.1:9191
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY"
```

The harness starts that counting proxy itself; the command snippets assume it is
running. Stdout/stderr are redirected to the raw output and diagnostic files.

**Detection-only runtime run:**

```bash
kingfisher scan "$REPO" --format json --no-update-check \
  --git-repo-timeout 0 --git-history full --no-validate > "$RAW"
trufflehog git "$REPO_URI" --json --no-update --fail-on-scan-errors --no-verification > "$RAW"
gitleaks git "$REPO" --report-format json --report-path "$RAW" \
  --exit-code 0 --log-opts="--all --full-history"
```

**Separate validation-enabled run:**

```bash
kingfisher scan "$REPO" --format json --no-update-check \
  --git-repo-timeout 0 --git-history full > "$RAW"
trufflehog git "$REPO_URI" --json --no-update --fail-on-scan-errors > "$RAW"
```

Omitting the disabling flags enables Kingfisher validation and TruffleHog
verification by default. Gitleaks is excluded from this mode. No concurrency
overrides, branch/depth bounds, custom rules, revocation, or access-map flags are
passed. TruffleHog additional refs are not skipped. Full-history flags select all
**available** local history;
they do not repair shallow clones or missing refs. Kingfisher's unbounded Git scope
is `all_fetched_git_objects`, while Gitleaks processes diffs reachable from all
refs. Unreachable objects and other tool-specific enumeration differences can
therefore affect coverage even with identical repository state. Nonzero scan errors are
reported as `ERROR`, not charted as successful fast runs. Inspect saved stderr
for additional input-processing warnings even when the process exits zero.

### Regenerating just the chart

`go run main.go -chart-from <results-directory>` rebuilds the chart from a previous
run's `comparison_*.md` report (it reads runtimes and tool versions), writing a
fresh `runtime-comparison-<timestamp>.png` into the same directory and exiting
without cloning or scanning. The report must explicitly identify **detection-only**
mode; validation-enabled and legacy unlabelled reports are rejected. Runtime
columns may contain only Kingfisher, TruffleHog, and GitLeaks; unsupported scanner
columns are rejected rather than rendered. Derive a supported-tool-only report
from historical measurements before regenerating an archived mixed-tool chart.
Rerun the benchmark rather than relabelling older validation-enabled measurements.

Charts display the saved tool versions beneath their legend names. A report line
such as `Analysis month: October 2026` displays **October 2026** beneath the title;
the month value must use the `January 2006` format. If that line is absent, the
month is derived from the dated report heading; it is never inferred from the
regeneration clock. Invalid,
repeated, or missing analysis dates are rejected. This lets saved data be replotted
without changing the reported analysis period or running scanners again.

### Flags

| Flag        | Default            | Description                                              |
|-------------|--------------------|----------------------------------------------------------|
| `-basedir`  | `$TMPDIR/benchmark`| Directory to clone repositories into.                    |
| `-validate` | `false`            | Enable live validation; requires `-gitleaks=false`. Runtime chart generation is skipped. |
| `-gitleaks` | `true`             | Include Gitleaks (requires `gitleaks` in `PATH`).         |
| `-repos`    | `""`               | Comma-separated repository names; defaults to all nine.   |
| `-chart`    | `true`             | Render the runtime-comparison PNG chart.                 |
| `-out`      | `.`                | Directory under which the `benchmark-<timestamp>/` folder is created. |
| `-chart-from` | `""`             | Regenerate only the chart from an existing results directory, then exit. |
