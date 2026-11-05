# kingfisher-secret-scanner

Native, in-process Kingfisher secret detection, validation and explicit revocation
for JavaScript and TypeScript on Node.js. Uses the same Rust crates and rule catalog
as the Rust and Python embedding APIs, with no Python or CLI runtime dependency.

**SDK version: 0.1.0 (preview of npm support).** Install from npm and import/require
`kingfisher-secret-scanner` in JavaScript. The separate PyPI distribution has the
same name, but Python installs with pip and imports `kingfisher_sdk`. These
independent in-process SDKs are not CLI distributions.

```js
import { Scanner } from 'kingfisher-secret-scanner';

const scanner = await Scanner.create();
try {
  const findings = await scanner.scan('application content', { path: 'config.env' });
  for (const finding of findings) {
    if (finding.visible) console.log(finding.toJSON()); // Redacted.
  }
} finally {
  await scanner.close();
}
```

Use the [JavaScript/TypeScript guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md)
for APIs, controls, input pipelines, validation, revocation and VS Code integration.
The [public declarations](https://github.com/mongodb/kingfisher/blob/main/javascript/index.d.ts)
are the API reference. CJS and ESM named/default imports at the root and subpaths
share one addon and class identity; `import sdk from 'kingfisher-secret-scanner'`
provides the same `sdk.Scanner` class as a named import or `require()`.

## Rules and JavaScript RegExp compatibility

Import `Rules` from `kingfisher-secret-scanner/rules` and call
`await Rules.load()` to inspect the bundled catalog with `metadata()` and
`detail(exactId)`. Loading and inspection are offline, but still require the
native addon; the rules subpath is not a native-free JavaScript/JSON catalog.

**Rule patterns are not guaranteed to work with JavaScript `RegExp`.** They target
Kingfisher's native matching pipeline (including Vectorscan/Hyperscan), whose
syntax and matching semantics differ from JavaScript's. Even if a pattern
compiles, regex alone omits secret capture selection, entropy checks, filters,
checksums and nearby credential components. Use `Scanner` or `DetectionScanner`
for Kingfisher detection behavior; a JavaScript-only engine needs compatibility
work and per-rule tests. See the
[rule import and compatibility guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md#importing-rules-and-javascript-regexp-compatibility).

## Learn by running a recipe

Start with the [step-by-step example guide](https://github.com/mongodb/kingfisher/blob/main/javascript/examples/README.md).
It covers synthetic text/bytes/files, YAML + TOML, bounded cancellation, project
JSONL, archive/content transforms, four Git scopes, TypeScript, and a loopback-only
validation/revocation mock. Recipes state inputs, side effects and expected output;
no real provider account is needed.

From a built checkout's `javascript/` directory:

```sh
node examples/quickstart.mjs
node examples/local-workflow.mjs
```

The second command validates only a synthetic credential and performs **no
revocation** by default. Installed-package consumers should follow the guide's
separate adaptation instructions, not run checkout-relative imports unchanged.

## Platforms and local development

Supported Node majors: **22, 24 and 26 only**, tested minimum **22.13.0**
(`^22.13.0 || ^24.0.0 || ^26.0.0`). Native packages target macOS x64/ARM64,
Linux glibc x64/ARM64, and Windows MSVC x64/ARM64. Linux requires
glibc **2.35+** and GCC 11-compatible libstdc++ (GLIBCXX 3.4.29 / CXXABI 1.3.13+).
Windows requires the architecture-matched **VC++ v14 Redistributable 14.44+**.
Browsers/WASM, edge isolates, Bun, Deno, musl and other Node majors are not claimed
supported. See the [platform guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md#nodejs-and-vs-code-support).

For a source checkout, follow the canonical
[build/test steps](https://github.com/mongodb/kingfisher/blob/main/CONTRIBUTING.md#javascripttypescript-sdk-development)
or the [SDK build guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md#build-and-test-from-a-checkout).

Production source builds use `npm run build`. Installed consumers receive native
binaries and need no Rust toolchain. Vectorscan **0.1.4** archives are checksum
verified; normal MSVC builds need no local `HYPERSCAN_ROOT` override.

## Safety and distribution

Detection is offline; provider validation, analysis and revocation are explicit.
Keep complete same-input findings, including invisible helpers, through validation.
Default JSON/inspection redacts secrets, captures and payloads; raw access is
explicit. Byte offsets are not JS string indices; fingerprints are strings.
Cancellation is cooperative, not a hard execution limit. `AbortError` uses
`ERR_KINGFISHER_CANCELLED`; `TimeoutError` uses `ERR_KINGFISHER_TIMEOUT`.
Interrupted revocations can also carry `outcomeUnknown: true`; do not assume rollback
or retry automatically. Close active objects before terminating workers.
See the [input guide](https://github.com/mongodb/kingfisher/blob/main/docs/JAVASCRIPT.md#compose-local-inputs)
for filename and provenance guarantees.

Maintainers: follow the [npm publishing guidance](https://github.com/mongodb/kingfisher/blob/main/docs/PUBLISHING.md#npm-publishing-with-github-actions).
Development manifests are private; native builds produce six platform artifacts.
A separate verification job tests all seven sealed tarballs across supported runtimes;
the pinned Node 24.22.2/npm 11.21.1 publisher uploads those same bytes. Building
locally never publishes anything. After dependency changes, follow the
[notices workflow](https://github.com/mongodb/kingfisher/blob/main/CONTRIBUTING.md#third-party-license-notices):
root `make notices` updates attribution; `npm run check:notices` checks it.

SDK source: Apache-2.0. Distributed native binaries and rule data also include MIT,
BSD-3-Clause and CC-BY-SA-4.0 components; preserve all packaged license and notice files.
