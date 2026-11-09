<p align="center">
  <img src="https://raw.githubusercontent.com/mongodb/kingfisher/main/docs/kingfisher_logo.png" alt="Kingfisher logo" width="105" height="144" />
</p>

<h1 align="center">Kingfisher for Node.js</h1>

<p align="center">
  <strong>Detect secrets. Validate credentials. Build your own response workflow.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/kingfisher-secret-scanner"><img src="https://img.shields.io/npm/v/kingfisher-secret-scanner.svg" alt="npm version" /></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/Node.js-22%20%7C%2024%20%7C%2026-43853d" alt="Node.js 22, 24 and 26" /></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
</p>

<p align="center">
  <a href="https://mongodb.github.io/kingfisher/reference/javascript-bindings/">Documentation</a> ·
  <a href="https://github.com/mongodb/kingfisher/tree/main/javascript/examples/kingfisher-workbench">Showcase app</a> ·
  <a href="https://github.com/mongodb/kingfisher/blob/main/javascript/examples/README.md">Runnable examples</a> ·
  <a href="https://github.com/mongodb/kingfisher/blob/main/javascript/index.d.ts">API reference</a>
</p>

`kingfisher-secret-scanner` is the **native JavaScript and TypeScript SDK** for
[Kingfisher](https://github.com/mongodb/kingfisher). Scan text, buffers, files and
Git history with the same Rust engine and rule catalog used by Kingfisher's CLI
and Python SDK—directly inside your Node.js process.

**Stable SDK: 1.0.0.** No CLI subprocess, Python interpreter, or separate Kingfisher
installation. ESM, CommonJS and TypeScript declarations are included.

## Why Kingfisher?

- **Native detection, async APIs.** Rust and Vectorscan/Hyperscan do the matching;
  native operations run off the Node.js event loop.
- **Hundreds of built-in rules.** Detect cloud keys, AI tokens, developer-platform
  credentials, database connection strings and more. Add your own YAML or
  Betterleaks TOML rules without replacing the built-in catalog.
- **More than a regex match.** The engine applies secret capture selection,
  entropy checks, rejection filters, checksums and nearby credential components.
- **Compose the pipeline you need.** Enumerate files or Git inputs, optionally
  expand archives/content, detect, then explicitly validate or analyze findings.
- **Response without implicit mutation.** Validate live credentials and revoke
  supported types through separate APIs with explicit confirmation.
- **Safer reporting and execution controls.** Redacted JSON by default, retained
  provenance, input budgets, operation deadlines and cooperative cancellation.

## Install

```sh
npm install kingfisher-secret-scanner
```

Use **Node.js 22 (≥22.13.0), 24 or 26** on a [supported platform](#platforms).
Prebuilt native packages are selected by npm; consumers do **not** need Rust or a
local compiler. Keep optional dependencies enabled: they contain the native addon.
Installation works with `--ignore-scripts`.

> This is the **npm SDK**, not a CLI distribution. The identically named package
> on PyPI is the independently versioned Python SDK (`import kingfisher_sdk`).

## Quick start: detect offline

Save as `scan.mjs` and run `node scan.mjs`:

```js
import { Scanner } from 'kingfisher-secret-scanner';

// Load/compile once, then reuse the scanner across inputs.
const scanner = await Scanner.create();
try {
  // Synthetic GitHub-shaped token. Detection only: no provider is contacted.
  const text = 'GITHUB_TOKEN=ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6\n';
  const findings = await scanner.scan(text, {
    path: 'config.env',
    timeoutMs: 5000,
  });

  for (const finding of findings) {
    if (finding.visible) console.log(finding.toJSON()); // secret: '[REDACTED]'
  }
  // For an actual file: await scanner.scanFile('./config.env');
} finally {
  await scanner.close(); // Release native resources even when a scan fails.
}
```

`scan()` accepts a string, `Buffer`, or `Uint8Array`. `scanFile()` reads one regular
file; it does not recurse, unpack archives, validate, or modify it. Finding reports
include the rule, confidence, fingerprint, blob ID, byte offsets and line/column.
Fingerprints are lossless strings; byte offsets are not JavaScript string indices.

**CommonJS:** `const { Scanner } = require('kingfisher-secret-scanner')` exposes the
same async API. ESM named/default imports and typed subpaths share class identity.

## Showcase: a complete secret-response application

[**Kingfisher Workbench**](https://github.com/mongodb/kingfisher/tree/main/javascript/examples/kingfisher-workbench)
turns the SDK into a local, live-updating reporting app. It scans a working tree
and Git history, groups repeated occurrences for triage, shows scan/validation
progress, and serves an interactive HTML report with explicitly enabled revocation.
The implementation is commented so you can adapt the orchestration, not just copy
a scanning snippet.

![Kingfisher Workbench showing synthetic findings, Git provenance and validation results](https://raw.githubusercontent.com/mongodb/kingfisher/main/javascript/examples/kingfisher-workbench/screenshots/report-overview.png)

![Kingfisher Workbench showing the explicit revocation workflow for a synthetic credential](https://raw.githubusercontent.com/mongodb/kingfisher/main/javascript/examples/kingfisher-workbench/screenshots/report-revocation.png)

*Both screenshots use synthetic credentials and a loopback mock provider—not real
scan results or live provider accounts.*

Try it from a [built checkout](https://github.com/mongodb/kingfisher/blob/main/CONTRIBUTING.md#javascripttypescript-sdk-development):

```sh
cd javascript
node examples/kingfisher-workbench/scripts/checkout.mjs demo
```

Open the local URL printed by the demo. It creates a temporary Git repository,
scans it with the native SDK, and validates against its own loopback mock.
Revocation requires an explicit browser confirmation and changes mock state only.
For real repositories, the app defaults to **offline detection and redacted
reports**; provider validation and revocation require separate opt-ins.

Read the [app walkthrough, architecture and safety notes](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/kingfisher-workbench/README.md)
for standalone/installed-package setup, CLI options, resource limits, screenshots
and tests. File and history scanning use the native SDK, **not** the Kingfisher
CLI; the demo uses Git only to create its synthetic repository.

## Scan a project with a composable pipeline

Enumeration, extraction and detection are deliberately separate. This example
recurses over a local project and writes redacted JSONL, with explicit archive
budgets and no provider traffic:

```js
import { Scanner, filesystem, expandArchives } from 'kingfisher-secret-scanner';

const scanner = await Scanner.create({ maxInputBytes: 16 * 1024 * 1024 });
const controls = { signal: AbortSignal.timeout(60_000) };
try {
  const files = filesystem(['./src'], {
    ...controls,
    gitignore: false, // Include ignored secret configuration deliberately.
    hidden: true,    // Include dotfiles such as .env.
    maxFileSize: 16 * 1024 * 1024,
    onWarning(warning) {
      console.error(JSON.stringify(warning));
      process.exitCode = 1; // Incomplete coverage is not a clean scan.
    },
  });
  const inputs = expandArchives(files, {
    ...controls, depth: 2, maxBytes: 16 * 1024 * 1024, maxEntries: 1000,
  });

  for await (const result of scanner.scanInputs(inputs, controls)) {
    // Keeps source/extraction provenance alongside the redacted findings.
    console.log(JSON.stringify(result.toJSON()));
  }
} finally {
  await scanner.close();
}
```

Use `gitInputs(repo, { mode: 'history' })` instead of `filesystem()` for Git
history; `snapshot`, `diff` and `staged` scopes are also available. Add
`expandContent()` explicitly for SQLite, Python bytecode or PDF text extraction.
See the [project recipe](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/scan-project.mjs)
for signal handling, output backpressure and error propagation, and the
[Git recipe](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/git-scopes.mjs)
for bounded history and provenance.

## Validate explicitly; revoke only when authorized

Detection is offline. `Validator.validate()` can send credentials to their
configured providers; run it only with authorization and trusted rules.
Keep **all original findings from each input**, including invisible component
helpers, until validation finishes:

```js
import { Rules, Scanner, Validator } from 'kingfisher-secret-scanner';

// Compile high-confidence roots and their declared helpers, not unrelated low rules.
const rules = await Rules.load({ confidence: 'high', includeDependencies: true });
const scanner = await Scanner.create({ rules });
const validator = new Validator({ concurrency: 4, retries: 0 });
try {
  const findings = await scanner.scanFile('./authorized-config.env');
  const candidates = findings.filter(f => f.visible && f.confidence === 'high');
  const results = await validator.validate(findings, { candidates, timeoutMs: 30_000 });
  for (const result of results) {
    if (result.finding.visible) console.log(result.toJSON()); // Redacted.
  }
  // Retain original ValidationResult objects for later authorized operations.
} finally {
  await Promise.all([scanner.close(), validator.close()]);
}
```

`candidates` must contain unique original findings from the full same-input batch;
helpers remain available without becoming validation targets. An empty array sends no
validation requests. Omitting `candidates` preserves the existing whole-batch behavior.
Candidates are preflighted like `RevocationPlan.validate()`: one with a missing,
ambiguous or unrenderable input is `skipped` before any provider request, whereas
whole-batch validation may still send it. Pass findings, not `RevocationPlan.candidates`
records.

`Revoker.revoke(originalResult, { confirm: true })` is a **separate mutation** for
supported credential types, not an automatic consequence of validation. Retain
the original native validation result; redacted JSON cannot reconstruct its
private credential/action snapshot. Review the target and impact before acting.
Interrupted revocations may have an unknown outcome: do not assume rollback or
retry blindly.

Learn the full flow without a real credential in the
[loopback-only mock recipe](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/local-workflow.mjs)
or the showcase app. See the [validation and revocation guide](https://mongodb.github.io/kingfisher/reference/javascript-bindings/#validate-and-revoke-explicitly).

## Rules, controls and API map

```js
import { Rules, Scanner } from 'kingfisher-secret-scanner';

const rules = await Rules.load({ paths: ['./company-rules.yml'] }); // Also loads built-ins.
const scanner = await Scanner.create({ rules });
try {
  console.log(rules.metadata()); // IDs, visibility, validation/revocation support.
  // Scan using both the built-in catalog and your trusted custom rules.
} finally {
  await scanner.close();
}
```

YAML and Betterleaks TOML are supported. The default minimum confidence is
**medium**; opt into low-confidence rules with `Rules.load({ confidence: 'low' })`.
`betterleaks.generic-api-key` is low confidence; `generic-credential-uri` remains
medium. `generic-password` and `generic-username` are not bundled. Confidence is
configured per rule, not dynamically upgraded or downgraded by filters.
`includeDependencies: true` additionally retains transitive `depends_on_rule` helpers
below the threshold before compilation; it defaults to `false`.

**Do not treat the rule catalog as JavaScript `RegExp` patterns.** Native syntax
and matching semantics differ; regex alone omits the rest of Kingfisher's
detection pipeline. Rule inspection also requires the native addon.

| Need | API / typed subpath |
| --- | --- |
| Load, inspect and resolve rules | `Rules` · `/rules` |
| Scan text, bytes, files or input streams | `Scanner`, `DetectionScanner` · `/scanner` |
| Enumerate files; expand archives and content | `filesystem`, `expandArchives`, `expandContent` · `/inputs` |
| Scan Git snapshots, history, diffs or staged blobs | `gitInputs`, `gitHistory` · `/git` |
| Inspect prerequisites, validate or analyze | `Validator` · `/validation` |
| Prepare and explicitly revoke credentials | `Revoker` · `/revocation` |
| Findings, inputs, cancellation and typed errors | `Finding`, `ScanInput`, `CancellationToken` · `/core` |

All APIs are also exported at the package root. Pass `timeoutMs`, an `AbortSignal`,
or a `CancellationToken` to supported operations. Cancellation is cooperative,
not hard preemption. The scanner's default per-input cap is **64 MiB**; tune
`maxInputBytes` and enumeration/extraction budgets for your workload. Deduplication
is opt-in (`Scanner.create({ dedup: true })`); keep it off when every occurrence
must be retained.

Errors reject rather than silently returning a clean result. Handle
`AbortError` / `ERR_KINGFISHER_CANCELLED` and
`TimeoutError` / `ERR_KINGFISHER_TIMEOUT`, and always close native resources.
See [execution controls](https://mongodb.github.io/kingfisher/reference/javascript-bindings/#detection-controls-and-safe-reporting)
and the [public TypeScript declarations](https://github.com/mongodb/kingfisher/blob/main/javascript/index.d.ts)
for exact options and result shapes.

## Platforms

Supported Node majors: **22, 24 and 26 only**, minimum **22.13.0**
(`^22.13.0 || ^24.0.0 || ^26.0.0`).

| Operating system | Architectures | Runtime requirement |
| --- | --- | --- |
| macOS | x64, ARM64 | Native macOS package |
| Linux (glibc) | x64, ARM64 | glibc **2.35+**; GCC 11-compatible libstdc++ (GLIBCXX 3.4.29 / CXXABI 1.3.13+) |
| Windows (MSVC) | x64, ARM64 | Architecture-matched **VC++ v14 Redistributable 14.44+** |

This is a Node.js SDK, including supported VS Code workspace-extension runtimes.
Browsers/WASM, edge isolates, Bun, Deno, Alpine/musl and other Node majors are not
supported targets. If the addon cannot load, check your Node version, CPU/libc,
runtime prerequisites, and whether your package manager omitted optional native
dependencies. The JS and native packages must have the **same SDK version**.

## More examples and contributing

The [runnable recipe walkthrough](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/README.md)
covers text/bytes/files, custom rules, cancellation, project JSONL, archive/content
extraction, Git scopes, TypeScript and the local validation/revocation mock. Each
recipe explains its inputs, side effects and expected output.

- [Complete Node SDK guide](https://mongodb.github.io/kingfisher/reference/javascript-bindings/)
- [Source build and test instructions](https://github.com/mongodb/kingfisher/blob/main/CONTRIBUTING.md#javascripttypescript-sdk-development)
- [Report a bug or request a feature](https://github.com/mongodb/kingfisher/issues)
- [Maintainer release guide](https://github.com/mongodb/kingfisher/blob/main/docs/PUBLISHING.md#npm-publishing-with-github-actions)

## License

**Apache 2.0.** See [LICENSE](https://github.com/mongodb/kingfisher/blob/main/LICENSE).
Bundled dependencies and rule data retain their accompanying license and notice files.
