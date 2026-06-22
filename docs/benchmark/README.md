# Benchmark

A Go-based benchmarking tool that clones a set of repositories, runs secret-scanning
tools (Kingfisher, TruffleHog, and optionally GitLeaks), and reports execution times,
findings, and network-request counts. An intercepting HTTP proxy (without TLS
decryption) counts the network requests each tool makes.

## Features

- **Repository cloning** — clones a predefined list of repositories (skips ones already present).
- **Tool execution** — runs each enabled scanner and collects timing, findings, and validation metrics.
- **Network-request counting** — an HTTP proxy on `127.0.0.1:9191` counts every request a tool makes.
- **Tool versions** — records `kingfisher`/`trufflehog`/`gitleaks` versions and includes them in the report and chart.
- **Timestamped results folder** — every run writes a `benchmark-<timestamp>/` directory (see below).
- **Markdown report** — environment, tool versions, runtime, findings, validated/verified, and
  network-request tables. The report is printed to stdout *and* saved as `comparison_<timestamp>.md`.
- **Runtime chart** — renders `runtime-comparison-<timestamp>.png` via QuickChart.io, matching
  `../runtime-comparison.png`: green/blue/amber bars, a "↓ X% faster" arrow over each Kingfisher
  bar, and a "lower is better" note. The filename carries a timestamp, so existing charts are never overwritten.

## How it works

The whole tool lives in a single `main.go`, organized into sections: configuration
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
└── ...
```

### Finding counts

Counts come from each tool's own summary, so they match what you'd see running the
tool directly: Kingfisher's deduplicated `findings` total, TruffleHog's
`verified + unverified` secrets, and the length of GitLeaks' JSON report.

## Prerequisites

- **Go** — [install Go](https://golang.org/doc/install)
- **Git** — must be installed and on your `PATH`.
- **Scanning tools** on your `PATH`:
  - `kingfisher`
  - `trufflehog`
  - `gitleaks` *(only when `-gitleaks` is passed)*

## Build

```bash
go build -o benchmark .
```

## Usage

```bash
# Kingfisher vs TruffleHog; results folder created in the current directory:
./benchmark

# Include GitLeaks as well:
./benchmark -gitleaks

# Put the results folder under docs/ (alongside the reference chart):
./benchmark -out ..

# Use a persistent clone directory and skip chart rendering:
./benchmark -basedir ~/bench-repos -chart=false

# Regenerate only the chart from a previous run (no cloning/scanning):
./benchmark -chart-from benchmark-20260529-193512
```

### Regenerating just the chart

`-chart-from <dir>` rebuilds the chart from a previous run's `comparison_*.md`
report (it reads the runtimes and tool versions from that file), writing a fresh
`runtime-comparison-<timestamp>.png` into the same directory and exiting without
cloning or scanning. Useful for tweaking the chart's appearance without re-running
the whole benchmark.

### Flags

| Flag        | Default            | Description                                              |
|-------------|--------------------|----------------------------------------------------------|
| `-basedir`  | `$TMPDIR/benchmark`| Directory to clone repositories into.                    |
| `-gitleaks` | `false`            | Include GitLeaks (requires `gitleaks` in `PATH`).        |
| `-chart`    | `true`             | Render the runtime-comparison PNG chart.                 |
| `-out`      | `.`                | Directory under which the `benchmark-<timestamp>/` folder is created. |
| `-chart-from` | `""`             | Regenerate only the chart from an existing results directory, then exit. |
