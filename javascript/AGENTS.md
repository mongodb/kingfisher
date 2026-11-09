# AGENTS.md

Guidance for extending and maintaining the JavaScript/TypeScript SDK.

## Scope and Architecture

- Applies to `javascript/`. Follow the [repository guidance](../AGENTS.md) and
  consult this guide for Node-facing changes in the [Node-API bridge](../crates/kingfisher-node)
  or shared Rust crates; those crates retain their own applicable instructions.
- The npm package is `kingfisher-secret-scanner`. It calls the shared
  `kingfisher-core`, `kingfisher-rules`, and `kingfisher-scanner` crates in process
  through napi-rs/Node-API, not through Python or a CLI subprocess.
- Keep the pipeline composable:

  ```text
  enumeration -> content transforms -> detection -> validation -> reporting
  ```

  Rule loading configures these stages. Revocation is a separate, explicitly
  authorized action; detection stays offline. Do not add implicit acquisition,
  extraction, provider calls, or mutation to scanning convenience APIs.
- Put JS argument checks, async-iterator adapters, and composition in the facade.
  Keep the native bridge focused on conversion, ownership, and execution controls.
  Implement reusable engine behavior in the shared Rust crates with one rule catalog.
  Keep input acquisition, extraction, detection policy, and report filtering independent.

## Public Contracts and Sensitive Data

- Preserve public exports, CJS/ESM and subpath class identity, [TypeScript declarations](index.d.ts),
  defaults, serialization shapes, byte-offset semantics, and lossless string fingerprints.
  Add capabilities through explicit options or composable APIs, not silent scope expansion.
- Preserve original per-input raw findings and scan context, including invisible
  component helpers, until dependent validation completes. Keep original native
  `ValidationResult` snapshots for analysis and revocation; never rebuild operational
  state from redacted reports or caller-supplied endpoint variables.
- Default JSON and inspection output must redact credentials, captures, payloads,
  and potentially sensitive provider messages. Raw access remains explicit. Filter
  visibility at reporting time, not before component resolution or validation.
- Retain source paths, Git filename bytes, repository/object identity, and extraction
  provenance through transforms. Document offset coordinates and limits; do not invent
  origin history. Snapshot mutable caller buffers before asynchronous native work.
- Existing YAML/TOML rules must work unchanged. HTTP fallbacks default off; both
  primary-reuse flags default false. Validation reuse does not imply revocation
  reuse. Preserve confirmation, selected-target snapshots, and no mutation failover.

## Controls, Errors, and Portability

- Preserve `KingfisherError.code`, `AbortError`/`ERR_KINGFISHER_CANCELLED`, and
  `TimeoutError`/`ERR_KINGFISHER_TIMEOUT`, including causes and revocation outcome-unknown
  signals. Do not turn cancellation, timeouts, or budget failures into empty successes,
  raw-content fallback, or partial findings for a failed input.
- Cancellation is cooperative, not hard preemption. Keep native work off the Node
  event loop, carry deadlines across stages, bound pending work, and release native
  resources with `close()` before worker termination. Failed scans must not poison
  reusable scanner resources or commit successful-scan deduplication state.
- Support **Node 22, 24 and 26 only**, tested minimum **22.13.0**. Keep npm engines
  at `^22.13.0 || ^24.0.0 || ^26.0.0`; CI tests pinned **22.13.0, 22.23.4, 24.0.0,
  24.22.2, 26.0.0 and 26.13.0**, including each major's supported floor.
  Keep support claims aligned with the [SDK platform guide](../docs/JAVASCRIPT.md)
  and [native build guide](../docs/LIBRARY.md#build-and-deployment); do not infer
  browser/WASM, Bun, Deno, musl, or other Node-major support from Node-API compatibility.
- Use Node path/URL APIs and subprocess argument arrays, not shell interpolation or
  Unix-only utilities. Account for Windows x64/ARM64 locking, separators, and line
  endings. Read sources without modifying caller files or executing untrusted content;
  clean up only private temporary storage after closing handles.

## Verification and Releases

- Follow the [checkout build/test steps](../CONTRIBUTING.md#javascripttypescript-sdk-development)
  or the [SDK build guide](../docs/JAVASCRIPT.md#build-and-test-from-a-checkout).
  Rebuild the addon before testing native changes. Documentation-only edits do not
  require a native build. Run focused shared Rust/CLI regressions where semantics move;
  report skipped checks and pending Windows verification explicitly.
- Use deterministic local fixtures and mock provider services, not live credentials.
  Cover grouping/provenance, raw snapshots versus redacted reports, controls/errors,
  scanner reuse, native/JS parity, and CJS/ESM/types for changed public behavior.
- For packaging/loader changes, test staged **packed tarballs** with
  `npm run test:package`: a clean unrelated consumer must install offline with
  `--ignore-scripts`, without source-tree addon fallback, Rust, or registry publication.
  Preserve packaged examples, exact native-package versions, licenses, and notices;
  passing checkout tests alone is not package verification. After native dependency
  changes, follow the [notices workflow](../CONTRIBUTING.md#third-party-license-notices):
  root `make notices` updates attribution; `npm run check:notices` verifies coverage.
- Add commented runnable [examples](examples) and update the [SDK guide](../docs/JAVASCRIPT.md)
  and [package README](README.md) for public changes. Keep sample output redacted.
- **1.0.1 is the stable npm SDK release**, versioned independently of the CLI, Python
  SDK, and Rust crates. Follow semantic versioning for SDK changes; do not bump it
  just for a CLI release. Follow the [npm publishing guidance](../docs/PUBLISHING.md#npm-publishing-with-github-actions); account
  changes, tags, and uploads require separate authorization. Never publish the
  private development manifest.
