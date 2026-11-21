# Benchmark

A Go-based benchmarking tool that clones a set of repositories, runs secret-scanning
tools (Kingfisher, TruffleHog, and Gitleaks), and reports execution times,
findings, and network-request counts. An intercepting HTTP proxy (without TLS
decryption) counts plain HTTP requests and HTTPS CONNECT tunnels. Requests inside
a TLS tunnel and traffic that bypasses the proxy are not observed.

## Features

- **Repository cloning** — clones a predefined list of repositories (skips ones already present).
- **Tool execution** — runs each enabled scanner five times per repository and reports the median for each metric.
- **Network-request counting** — an HTTP proxy on `127.0.0.1:9191` counts plain HTTP requests and HTTPS CONNECT tunnels sent through it.
- **Tool versions** — records `kingfisher`/`trufflehog`/`gitleaks` versions in the report.
- **Timestamped results folder** — every run writes a `benchmark-<timestamp>/` directory (see below).
- **Markdown report** — environment, tool versions, runtime, findings, validated/verified, and
  network-request tables. The report is printed to stdout *and* saved as `comparison_<timestamp>.md`.
- **Runtime chart** — renders `runtime-comparison-<timestamp>.png` via QuickChart.io, matching
  [the original chart](../runtime-comparison-original.png): 1360×966 pixels, green/blue/amber bars,
  outlined Kingfisher bars, and straight downward arrows labeled with the runtime reduction
  relative to the fastest successful competitor, or labeled "slower" when another
  scanner wins.
  Versions appear beneath tool names. The scan month and trials per median
  appear beneath the title. The filename carries a timestamp, so existing
  charts are never overwritten.
- **Failure reporting** — saves stderr logs, marks failed scans as `ERROR`, and excludes them
  from the chart. Saves a progress report after each repository.

## Published results

The November 20, 2026 benchmark used Kingfisher 2.20.0, TruffleHog 3.100.0,
and Gitleaks 8.30.1 across nine repositories. See the [runtime results](../COMPARISON.md#runtime-comparison-seconds)
and the [three-tool chart](../runtime-comparison.png).
Use the saved detection-only report to regenerate a chart without running the
scanners again.

### Audit before publishing

A zero exit status does not guarantee complete input processing. Inspect stderr
and Kingfisher audit metadata before publishing, and trace diagnostics against
the executed tool version before deciding their impact. Preserve measured runtime
cells for scans that complete successfully with localized diagnostics; annotate
the affected metadata, file, or decoder-stream coverage rather than calling the
whole run a fatal failure or its timing invalid. Omit only fatal or missing
measurements from the runtime chart, never plot them as zero. Keep original
reports, exact command timings, and coverage caveats alongside any corrected
report or chart. Finding and network counts reflect each scanner's coverage and
settings.

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
├── commands.jsonl                    # exact commands, timings, and exit status
├── croc-kingfisher-trial-1.json        # raw output, per repo, tool, and trial
├── croc-trufflehog-trial-1.json
├── croc-gitleaks-trial-1.json
├── croc-gitleaks-trial-1.json.stderr  # scanner diagnostics, one file per trial
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

Each tool runs five times per repository with full available Git history and its
default detection settings. Trials run sequentially and the starting scanner
rotates each round. Each cell is the median of the five values for that metric.
A tool and repository need five successful trials to report a median. The harness
keeps the system's normal caches in place. Update checks are disabled where
supported, and Kingfisher's repository timeout is disabled. Worker counts use
tool defaults. TruffleHog normally prepares a private clone within its timed run.
For a corpus with trusted local Git configuration, `-trufflehog-in-place` makes
TruffleHog use the existing local clone directly. Different rules, file-size
limits, archive handling, filters, provenance
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
stderr files for each trial. `commands.jsonl` records exact subprocess argument arrays, durations,
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
verification by default. Gitleaks is excluded from this mode. With
`-trufflehog-in-place`, the harness also passes `--trust-local-git-config`
to TruffleHog in either mode. No concurrency
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

`go run main.go -chart-from <results-directory>` rebuilds the chart from a saved
detection-only `comparison_*.md` report. It writes
`runtime-comparison-<timestamp>.png` in the same directory without scanning.
The report must include `Validation mode: detection-only` and a runtime table.
Use Kingfisher, TruffleHog, and GitLeaks as the scanner names in that table.

Add `-nosey-parker-chart` to render the green-and-blue Kingfisher vs. NoseyParker
chart. The report needs `Kingfisher Runtime` and `NoseyParker Runtime` columns,
the NoseyParker version, and a successful NoseyParker median for every plotted
repository. Use five-trial medians measured on the same inputs, with archive
extraction and Base64 decoding enabled for Kingfisher. The output is
`runtime-comparison-<timestamp>-with-nosey-parker.png`.

Charts display tool versions below the legend names, dropping a zero patch
number for Kingfisher. Arrow labels bold **faster** when Kingfisher wins.
The saved scan month appears below the title. Reports can supply `Scan date` in
`January 2, 2006` format, `Analysis month` in `January 2006` format, or a dated
report heading. For median runtimes, a line such as
`Trials per tool per repository: 5` adds the trial count to the subtitle.
Reports without a count show the scan month alone.

### Flags

| Flag        | Default            | Description                                              |
|-------------|--------------------|----------------------------------------------------------|
| `-basedir`  | `$TMPDIR/benchmark`| Directory to clone repositories into.                    |
| `-validate` | `false`            | Enable live validation; requires `-gitleaks=false`. Runtime chart generation is skipped. |
| `-gitleaks` | `true`             | Include Gitleaks (requires `gitleaks` in `PATH`).         |
| `-trufflehog-in-place` | `false` | Have TruffleHog scan the existing local clone directly. Use for repositories with trusted local Git configuration. |
| `-repos`    | `""`               | Comma-separated repository names; defaults to all nine.   |
| `-chart`    | `true`             | Render the runtime-comparison PNG chart.                 |
| `-out`      | `.`                | Directory under which the `benchmark-<timestamp>/` folder is created. |
| `-chart-from` | `""`             | Regenerate only the chart from an existing results directory, then exit. |
| `-nosey-parker-chart` | `false`  | Render the Kingfisher vs. NoseyParker chart from the saved report. Requires `-chart-from`. |
