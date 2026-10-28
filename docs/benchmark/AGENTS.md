# Benchmark Agent Guidance

Applies to this directory, including [main.go](main.go), generated reports, and
[README.md](README.md).

## Single Go Source File

- Keep [main.go](main.go) as the only Go source file in this directory. It
  contains the executable benchmark harness and chart generation. Do not add
  a separate `main_test.go` or alternate Go implementation.
- Build from this directory with `go build -o benchmark main.go`, and run the
  resulting executable with the required benchmark options. Check compilation
  and use targeted benchmark runs to validate changes.

## Separate Comparison Runs

- Use a detection-only run of **Kingfisher, TruffleHog, and Gitleaks** for
  **Runtime Comparison**. These are the only supported comparison tools.
  Explicitly disable credential validation in Kingfisher and verification in
  TruffleHog. Gitleaks runs as a detection-only scanner. Generate the runtime
  chart from this run's data.
- Perform a separate run of **only TruffleHog and Kingfisher**, with credential
  verification/validation enabled, for **Network Requests Comparison** and
  **Validated / Verified Findings**. Use this run's network counts and verified
  findings for those sections.
- Use the same repository revisions and history for both runs. Keep other scan
  settings comparable, and document any differences that affect interpretation.
- Preserve separate raw outputs and identify each report's validation mode and
  data source. Do not mix results between modes or relabel existing
  validation-enabled timings as detection-only results; rerun the affected
  comparisons when changing methodology.

## Chart Generation

- Use [the reference image](../runtime-comparison.png) as the visual specification
  for the runtime chart. Match its layout, typography, spacing, legend, axes,
  grid, bar outlines, arrow annotations, and footer while plotting the newly
  measured results. Inspect the reference and generated image visually.
- Generate charts deterministically from benchmark results through the chart
  renderer in [main.go](main.go) (QuickChart, Chart.js v4). Do not fabricate
  measurements or use an AI-generated image for the data chart.
- Render a white-background PNG at **1360 × 966 pixels**, with a 52 px Georgia
  title, “Runtime comparison”. Use Kingfisher green `#01ec64`, TruffleHog blue
  `#4a85e8`, and Gitleaks amber `#fabd05`, with dark text and Kingfisher bar
  outlines in `#011e2a`. Show each program's version beneath its legend name and
  the analysis month/year directly beneath the title. Read the analysis date
  from the saved report, not the chart-regeneration clock.
- Plot grouped bars by repository, with runtime in seconds. Point downward
  arrows at Kingfisher's bars and calculate faster/slower annotations against
  the fastest successful competing tool for each repository. Omit failed or
  missing measurements rather than plotting them as zero. Keep labels legible
  and free of clipping or overlap.
- Save the chart as `runtime-comparison-<timestamp>.png` alongside its source
  `comparison_*.md` report. Use only detection-only runtime data; keep the
  validation-enabled comparison data separate.
- To regenerate a chart without rescanning, run from this directory:
  `go run main.go -chart-from <results-directory>`. This reads the saved report and
  writes a new timestamped PNG. Confirm the report uses the required validation
  mode before regenerating, and document this command in the README.

## Commands and Reproducibility

- The README must show the command line used to run each tool, including the
  distinct detection-only and validation-enabled commands where applicable.
- Generalize repository and output paths with defined placeholders
  so each command is printed once per tool and mode, rather than repeated for
  every repository.
- Include all flags used, especially those controlling validation, verification,
  history, concurrency, output, and update checks. Keep run commands limited to
  the supported scanners; do not restore retired flags or tool integrations from
  archived reports or source snapshots.
- Keep README commands aligned with the harness and actual execution logs.
  Record tool versions, repository revisions, measurement environment, and scan
  failures or input-processing diagnostics alongside the results.
