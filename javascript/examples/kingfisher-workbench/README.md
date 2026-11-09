# Kingfisher Workbench — runnable Node SDK application

A complete local application built with the stable **Kingfisher Node SDK 1.0.0**:
scan a directory and its Git history, inspect a searchable HTML report, optionally
validate findings, and explicitly revoke an authorized credential from the live
report. Detection uses Rust **in process through Node-API**, not a scanner CLI,
Python service, browser SDK, or shell wrapper.

**Defaults: offline detection, redacted output, revocation disabled.** Reading an
HTML snapshot cannot perform a mutation. Provider validation requires
`--validate`; live revocation additionally requires `--enable-revoke` and an
individual browser confirmation.

## Try the entirely local demo

Requires a supported Node version (**22 (>=22.13.0), 24, or 26**) and Git to create the
synthetic demo repository. See the [SDK platform/build guide](<https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md>)
for the exact supported Node/native-platform combinations. Git is **not** needed
as a subprocess for the application's native SDK history scanner.

### From a repository checkout

From the repository's `javascript` directory, build the local SDK once:

```sh
npm ci
npm run build:debug
node examples/kingfisher-workbench/scripts/checkout.mjs demo
```

The explicit checkout runner selects the local SDK facade using an absolute file
URL. It does not install anything, bypass the facade/native version gate, or
silently fall back from a broken installed package. No environment-variable setup
is needed. Append `--open` to launch a browser, or open the printed loopback URL.

Run a normal offline scan from that same directory:

```sh
node examples/kingfisher-workbench/scripts/checkout.mjs scan --root /path/to/project
node examples/kingfisher-workbench/scripts/checkout.mjs scan --root /path/to/project --no-serve --json scan.json
```

Alternatively, from this example's directory:

```sh
npm run demo:checkout
npm run start:checkout -- --root /path/to/project
npm run test:checkout
```

### With the installed npm SDK

Copy this example into a directory outside the checkout (or use the example
included in the npm package), then install its exact stable dependency:

```sh
npm install
npm run demo
npm start -- --root /path/to/project
npm test
```

The [private example manifest](<package.json>) pins
`"kingfisher-secret-scanner": "1.0.0"`. Normal commands import that installed
package; they never auto-discover a source-tree addon. Only the explicit checkout
runner overrides SDK selection. Installation and native build details are in the
[SDK guide](<https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md#build-and-test-from-a-checkout>).

### What the demo does

- Starts a mock provider bound to **127.0.0.1 on an assigned port**, then waits for
  readiness. No fixed ports or third-party services are used.
- Creates a private temporary repository with two deterministic commits: an
  invented current token and an invented retired token present only in history.
  The [source fixture](<demo/fixture/config.env>) contains no real credentials.
- Loads only the [custom demo rules](<demo/acme-rule.yml>), with built-ins disabled
  and URLs rewritten to that mock's assigned port. An invisible username helper
  demonstrates native multi-part credential resolution.
- Explicitly enables validation and revocation for **these synthetic rules only**.
  The report shows one active and one inactive credential after deduplication.
- Keeps the mock and native results alive while you open **Revoke**, check the
  irreversible-action acknowledgement, and confirm. The mock merely flips an
  in-memory Boolean; no external credential is affected.
- On Ctrl+C, drains already-submitted mutations, closes the server and native
  owners, closes the mock, then removes only its private temporary directory.
  It does not modify the source fixture or your Git configuration/repository.

The demo accepts only `--open`. Use the normal scan command for real input/options.
Do not adapt it to real credentials without reviewing the safety boundaries below.

## Browser screenshots

These are headless-Chrome captures of `npm run demo` with the current renderer
(1440×1100). The confirmation screenshot shows the unchecked consent box and
disabled destructive button; nothing was revoked.

![Redacted report with active and historical inactive findings](<screenshots/report-overview.png>)

![Per-credential revocation confirmation](<screenshots/report-revocation.png>)

## Scan options

```sh
# Default: offline, redacted, loopback live report + inert HTML snapshot.
npm start -- --root /path/to/project

# No listener; optional JSON is also redacted.
npm start -- --root /path/to/project --no-serve --out report.html --json scan.json

# Explicit provider traffic, but still no mutation capability.
npm start -- --root /path/to/project --validate

# Separate mutation opt-in; the browser still requires confirmation each time.
npm start -- --root /path/to/project --validate --enable-revoke

# Organization-specific YAML/TOML rules; custom-only offline detection.
npm start -- --root /path/to/project --rules /path/to/rules --no-builtins --no-serve

npm start -- --help
```

Choose one positional directory or `--root`, not both. Paths are resolved from
the calling directory; quote paths with spaces. Options support `--name=value`.

| Option | Default / behavior |
| --- | --- |
| `--out`, `--json` | HTML defaults to `report.html`; JSON is opt-in. Private, atomic output files. |
| `--audit <new-file>` | Live revocation only; rejected without `--validate --enable-revoke` or with `--no-serve`. Defaults to a new `revocations-<session-id>.jsonl` beside HTML; prints the path. An explicit path must not exist, including links. |
| `--port`, `--open`, `--no-serve` | Assigned loopback port; no automatic browser launch; serving enabled. |
| `--rules`, `--no-builtins` | Built-ins plus optional YAML/TOML path; custom-only requires a rules path. Load only trusted rules. |
| `--confidence low\|medium\|high` / `-c` | `medium`; detection roots plus required helpers; only visible findings at this threshold are validated and reported. |
| `--validate`, `--no-validate` | Off; validation can send credential material to rule-defined providers. |
| `--enable-revoke`, `--no-revoke` | Off; enabling requires explicit validation. |
| `--allow-internal-ips` | Off; explicit permission for private provider destinations in trusted rules (used by the demo). |
| `--show-secrets`, `--redact` | Redaction on. Raw output is an independent, dangerous opt-in. |
| `--jobs` / `-j`, `--concurrency` | 4 detection tasks / 4 validation groups; each 1–32. |
| `--timeout` | 10,000 ms per validation/revocation operation; range 1–600,000. Not a whole-scan deadline. |
| `--no-git-history` | History is enabled only when the selected directory contains a Git metadata entry. |
| `--git-history-max-commits`, `--git-history-max-inputs` | 100,000 / 1,000,000 native history **failure budgets**, not truncation; 0 explicitly removes that budget. |
| `--include-ignored`, `--exclude-hidden` | Respect Git ignore rules; include hidden files. These filesystem filters do not limit history. |
| `--exclude <text>` | Repeatable, case-sensitive substring exclusion on root-relative, slash-normalized tree/history paths. Not a glob; ancestors of the root are not matched. |
| `--max-file-size` | 64 MiB; size units `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB`; 0 explicitly means unlimited. |
| `--no-extract`, `--extraction-depth` | Archive/content transforms enabled; archive depth 2 (0–8); 0 skips archive expansion, not content conversion. |
| `--max-extracted-size` | 64 MiB archive expansion/content-operation budget; positive size required. Archive entries also capped at 10,000 per expansion. |
| `--no-dedup` | Default reports one occurrence per rule + secret, preferring a verified-active context. |
| `--quiet`, `--no-progress` | Suppress chatter / animated progress; final URL or snapshot path is always printed. |

The tree excludes Git internals, dependency directories, selected report outputs,
and the selected session's revocation audit path. Native history scans **all refs
and their reachable history**, with no timestamp sharding or “last N commits” approximation.
Nested repositories are not implicitly discovered; select each repository root.
Unreachable objects, staged changes as a separate source, remote acquisition,
and Git LFS fetching are outside this application's scope. Oversized/missing
history blobs can be skipped with visible warnings; budgets fail the scan.
The report counts Workbench-excluded inputs separately from native iterator
filters, and shows the total warning count with at most 200 warning details.

## Architecture and source map

```text
filesystem() / gitInputs(history, refs: null)
  → explicit expandArchives() → explicit expandContent()
  → DetectionScanner.scanInput()                         [offline]
  → retain complete original findings per ScanInput
  → optional Validator.validate(group, { candidates })  [selected provider traffic]
  → report selected findings + cross-source deduplication
  → redacted HTML / JSON

original native ValidationResult → retained in live owner
  → session token + explicit per-entry confirmation
  → Revoker.revoke(originalResult, { confirm: true })     [separate mutation]
```

| Source | Responsibility |
| --- | --- |
| [Coordinator](<src/main.mjs>) | Source-agent lifecycle, cancellation, exports, live listener, orderly cleanup. |
| [Native agent](<src/agent.mjs>) | Bounded enumeration/transforms/detection/validation; original native snapshot ownership. |
| [Argument parser](<src/args.mjs>) | Offline/redacted defaults and independent permission switches. |
| [SDK selection](<src/sdk.mjs>) | Normal package import or explicit checkout facade URL; no hidden fallback. |
| [Safety helpers](<src/safety.mjs>) | Safe error projection, private report replacement, non-exported deduplication digest. |
| [Loopback server](<src/server.mjs>) | Host/Origin/token/body guards, one-shot mutation, private audit/snapshot updates. |
| [Report UI](<src/report.mjs>) | Escaped HTML, responsive styling, filtering, details, accessible confirmation dialog. |
| [Progress](<src/progress.mjs>) | Optional bounded terminal progress; no scanning logic. |
| [Demo runner](<demo/run.mjs>), [fixture setup](<demo/fixture.mjs>), [mock provider](<demo/mock-provider.mjs>) | Deterministic private Git fixture and entirely local provider lifecycle. |
| [Checkout runner](<scripts/checkout.mjs>), [syntax checker](<scripts/check.mjs>) | Portable development commands using Node subprocess argument arrays. |
| [Regression tests](<test/report.test.mjs>) | Offline/native pipeline, helpers, provenance, extraction/budgets, redaction and HTTP mutation boundaries. |

Working tree and history each have one in-process agent. Pending operations are
bounded, but findings and their native analysis context remain in memory until
validation (and eligible revocation snapshots until shutdown). This is a local
reference application, not an unbounded repository-streaming service.

The scanner compiles the selected confidence roots plus their transitive declared
dependencies, so a low-confidence or visible helper can support a higher-confidence
primary without loading unrelated low-confidence detectors. Default `medium`
therefore excludes `generic-api-key`. It preserves **every original finding in each
selected input group** as validation context, but only visible findings meeting
`--confidence` are validation candidates. Helpers do not authorize extra provider
requests, even when they define validation of their own. Candidates are preflighted:
a finding with a missing, ambiguous or unrenderable input is reported as `skipped`
instead of being sent to its provider.
Deduplication occurs **after** validation, so repeated credentials can cause
multiple provider checks, bounded by concurrency. Never rebuild a `Finding` or
`ValidationResult` from exported JSON to resolve components or authorize a revoke.

Reports retain SDK source paths, repository/blob/commit identity, origin IDs,
lossless base64 Git filename bytes, extraction paths, and string fingerprints.
Locations are UTF-8 **byte offsets**, not JavaScript string indices; extracted
content offsets refer to the transformed source, not the outer compressed file.
One representative matching commit is shown, not an invented complete history.

## Safety and operational limits

- **Offline means no provider calls from detection.** Installing npm dependencies
  is separate. Validation is explicit and may use the network; rule definitions
  choose destinations. Review custom rules before opting in. HTTP fallback
  environments remain disabled. `--allow-internal-ips` is a separate opt-in for
  private destinations in trusted rules; the custom-only demo needs it.
- **Redaction is not anonymization.** Credentials/captures are SDK-redacted;
  free-form provider messages, diagnostics and commit author/message fields are
  omitted by default. Paths, filenames, repository names, object IDs, timestamps
  and fingerprints can still be sensitive. Do not publish real reports casually.
- **The listener trusts local processes.** It binds only to IPv4 loopback, rejects
  unexpected Hosts and cross-origin mutations, requires a random per-session
  header token plus `confirm:true`, and only accepts a currently retained,
  verified-active native result. The root page serves that token to any local
  client: it is a request/CSRF guard, not authentication against other local users
  or processes. No CORS is enabled. Do not proxy/expose the listener or share its
  live HTML/token; this is not a multi-user auth system.
- **Disk snapshots are inert.** They have no live session token and no working
  revoke buttons. JSON is a scan-time export, not an operational restore format;
  HTML snapshots update after live actions. Each mutation-enabled live session
  exclusively creates a new `revocations-<session-id>.jsonl` beside HTML (or the
  explicit `--audit` path) before listening. No audit is created for detection-only
  or `--no-serve` runs. The printed audit path records action metadata, never
  credentials or session tokens; it is not an append target for prior sessions.
  A startup collision or failed pre-action audit write prevents provider mutation.
- **Revocation is one shot.** The native result is consumed before awaiting the
  provider. Failed, unconfirmed, cancelled or unknown outcomes do not enable a
  blind retry. A timeout can mean the provider received a destructive request;
  verify out of band before rescanning. No mutation fallback/retry is attempted.
- **Errors are not empty success.** Fixed application input errors remain actionable
  in redacted mode; arbitrary provider/transport messages remain suppressed. Fatal
  source/transform/native errors, history budgets and cancelled scans abort export
  and produce a nonzero CLI exit.
  Recoverable native input warnings/extraction diagnostics remain visible; a
  failed input is never silently substituted with a successful raw-byte scan by
  this application. Existing output files from earlier scans remain untouched
  if scanning fails, so do not mistake an old snapshot for a new successful run.
- **Cancellation is cooperative.** Ctrl+C stops acquisition, drains pending
  work, and closes native owners. A server already processing a mutation waits
  for its bounded provider outcome before releasing the original snapshot.
- **Output files contain sensitive metadata.** HTML/JSON are atomically replaced
  with POSIX mode 0600 and reject existing non-regular targets. Audits use exclusive
  creation with mode 0600 and retain that owned append descriptor until shutdown;
  existing files, hardlinks and symlinks are never appended to or chmod'ed.
  Use a private output directory and appropriate Windows ACLs; POSIX permission
  bits are not Windows ACLs.

## Verification

From this directory, with the checkout addon built:

```sh
npm run check
npm run test:checkout
npm run demo:checkout
```

The deterministic tests use private temporary inputs and loopback mocks only.
They cover defaults/parser controls, native tree/history provenance, redacted
versus explicit raw exports, complete helper groups (including visible
low-confidence helpers) without helper-only provider requests, root-relative
exclusions, bounded warning previews with full totals, original-snapshot revocation,
extraction/history budget failures, actionable redacted input errors,
cancellation/error identity, HTML escaping, tokenless snapshots,
Host/Origin/token/confirmation guards, concurrent one-shot mutations, unknown
outcomes, and private output handling.

Verified locally on **macOS arm64 / Node 26.13.0** with native SDK 1.0.0.
The screenshots were regenerated from the synthetic demo in headless Chrome on macOS.
**Windows x64 and Windows arm64 execution remain pending**; local success is not
cross-platform verification. The application's subprocess calls use argument
arrays and portable path APIs; Git fixture hooks/config/signing are isolated.
No real credentials, live provider requests, publication, generated report, or
dependency directory is included in this example.
