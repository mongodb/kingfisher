# Kingfisher wizard

Build the CLI with `cargo build --release --features gui --bin kingfisher`, then launch
`kingfisher wizard` (or `kingfisher gui`). Pass a local path or Git repository URL to
prefill the target. `kingfisher wizard --report report.json` opens a report directly.
See [installation](INSTALLATION.md#native-scan-wizard) for source-build instructions.

The workspace uses GPUI, with Kingfisher branding and native controls.
Use **Theme** to choose **System** (the default), **Light**, or **Dark**. System mode follows
appearance changes while the wizard is open. Theme and column choices last for this session.
The wizard uses the Kingfisher icon in the macOS Dock, Windows taskbar, and Linux desktop.
GUI builds embed the Windows executable icon. On Linux, launching the wizard installs its
user-local desktop entry and icon under `$XDG_DATA_HOME` (default `~/.local/share`), allowing
Wayland desktops to match the window to its icon. No system-wide installation is required.
The optional `gui` feature requires [GPUI Kit's native prerequisites](https://gpui-kit.com/docs/)
in addition to Kingfisher's scanner prerequisites. Linux requires a graphical desktop and
supported graphics drivers. GUI builds must be verified on Windows x64/arm64 and Linux
before distribution; the current local verification is on macOS.

## Run a scan

Choose a file/folder or enter a repository URL. Configure Git history, detector rules,
path exclusions, live validation, redaction, and blast-radius mapping. Validation is enabled by default;
redaction is off by default, matching the CLI. Blast-radius mapping requires live validation.

**Command preview** displays a multiline command with **Copy**. The shell defaults to Bash/zsh
on macOS/Linux and PowerShell 7.3+ on Windows; use the shell buttons to change it. PowerShell
commands explicitly select standard native argument passing and use backtick continuations;
Unix commands use backslashes. Arguments containing shell syntax are quoted. The preview
uses `kingfisher-report.json` in the terminal's current directory. No Git clone directory
is required. The app launches scans directly with argument arrays, without invoking a shell.

**Rules** stays on the main form. Keep the built-in catalog enabled, add custom YAML/TOML
files with **Rule files…**, or add a recursively loaded directory with **Rules folder…**.
Remove individual sources with their remove buttons. Turn off the built-in catalog for a
custom-only scan; at least one custom source is then required. **Limit to detector** accepts
a detector ID or family; leave it empty to use all selected rule sources.

**Scan settings…** opens a separate pane with categories for scanning, detection, validation,
Git/files, reporting, and network/global settings. Search finds settings across every
category. Choice menus include **Default**; blank fields retain CLI/config defaults.
Hover over an information icon for a setting's explanation and CLI flag. Repeated settings
have **Add value**. **Done** returns to the command preview without discarding settings.
Explicit global options passed to `kingfisher wizard` populate these controls.

**Activity** shows GB scanned, blob counts, average throughput, scan phase, validation counts,
live diagnostics, elapsed time, and errors. A phase banner highlights the transition to validation,
with credential counts and a progress bar. Scan throughput excludes preparation and freezes
when scanning ends; validation does not lower the final scan rate. Failures select this tab
automatically. Use **Copy log** to copy diagnostics, or **Cancel scan** to stop the process
group including Git children. Exit codes 200/205 are completed scans with findings.
The visible log retains its latest 512 KB. Provider credentials and other CLI environment variables are
inherited from the environment in which you launched the wizard.

Use a **release build** for normal scans. Debug builds run the same scanner without compiler
optimizations and can be much slower; the scan form labels debug builds. The wizard uses the
same worker-count and Git-history defaults as the CLI. Validation time depends on provider
latency and retries, visible separately from matching progress.

## Inspect reports natively

Completed scans open the native **Overview**. **Open report** also imports one or more
Kingfisher JSON/JSONL or SARIF reports without starting a web server. Each file and completed
scan opens in a separate report tab. Switch tabs above the section navigation; each retains
its search, filters, columns, sorting, scroll position, and selected record. Export and
**Local Web Viewer** apply to the active report. Close a tab with its **×** button.
The scan form and Activity log are shared, so you can inspect other reports during a scan.

- **Overview:** finding and credential totals, detector distribution, and repository coverage.
- **Findings:** click a column header to sort; click
  again to reverse direction. Selection stays attached to the same finding. Includes text search plus combined status, rule, path, repository, author/committer,
  commit, and inclusive date-range filters. Fingerprint deduplication applies after filtering.
  Use **Add filter** to add only the conditions you need, and remove conditions individually.
  The status menu uses values present in the report. Click a row, then use Up/Down
  to move through findings. **Unique secrets** groups duplicate fingerprints.
  Use **Columns** to add/remove Rule, Path, Line, Status, Repository, Commit, and Author/committer
  columns; at least one stays visible. Drag a header’s right edge to resize it. Horizontal and
  vertical scrollbars appear when content overflows. Confidence is omitted from the normal UI.
  Select inspector text and use the usual Copy shortcut to copy any portion. Repository, commit,
  and file-at-line buttons appear when the report contains web links.
  The inspector groups Git provenance and evidence, and displays copyable validate, revoke,
  and blast-radius commands when present. Redacted/unsupported commands are marked unavailable.
  **Raw evidence** expands the full record; **Copy JSON** always copies it.
  Older reports may contain only committer metadata; new scans also retain the original author.
- **Coverage:** repository fetch/scan outcomes and full repository audit details.
- **Blast radius:** identity records with permissions, resources, and evidence in the inspector.
- **Export JSON:** save all records, or use **Export filtered** in Findings to save the current
  result set. Filtering applies to findings; audit and identity context remain attached.
  Complete source finding records are retained, including metadata.

Git fields depend on provenance retained in the report. Enable **Keep duplicate occurrences** in **Scan settings…** to retain every occurrence; the Findings deduplication control is independent
and applies after its filters.

Use **Local Web Viewer** for the existing `kingfisher view` experience, including its interactive
graph. Native views do not yet implement the web viewer's graph canvas or other scanners'
report formats. Reports remain local. GUI scan reports are temporary: export reports you
want to keep before closing their tab or the app. User-opened report files are never deleted.

## Verification

```sh
cargo test --features gui --lib wizard::
cargo test --features gui --test wizard_cli
cargo test --features gui-tests --lib wizard::ui::tests
cargo clippy --no-deps --features gui-tests --lib --bin kingfisher --test wizard_cli -- -D warnings
```
