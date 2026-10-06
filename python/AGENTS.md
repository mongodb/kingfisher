# AGENTS.md

Guidance for extending and maintaining the Python SDK.

## Scope and Purpose

- Applies to `python/`, including the public package, tests, and examples. Follow
  the [repository guidance](../AGENTS.md) and any deeper instructions as well.
- The [native bindings guidance](../crates/kingfisher-python/AGENTS.md) incorporates
  these principles for the Rust bridge. Consult this guide when shared Rust
  changes affect Python behavior; shared crates retain their own instructions.
- Keep the SDK composable, predictable, and suitable for embedding. Users should
  be able to supply their own inputs and choose capabilities independently.
- The distribution is `kingfisher-secret-scanner`; the public import is
  `kingfisher_sdk`. Treat `_native` as the implementation bridge.

## Architecture and Ownership

Keep responsibilities separate:

```text
enumeration -> content transforms -> detection -> validation -> reporting
```

Rule loading and inspection configure these stages. Revocation is a separate,
explicit action; enumeration, detection, and validation must not invoke it.

| Responsibility | Extension point |
| --- | --- |
| Rules and capability inspection | Public rule APIs backed by the shared rule catalog and loader |
| Input enumeration | Iterators yielding `ScanInput` or compatible provenance-bearing inputs |
| Content extraction or normalization | Explicit transforms consuming and yielding inputs |
| Detection and detection policies | The shared native scanner and narrowly scoped policy configuration |
| Validation and revocation | Dedicated APIs backed by shared native implementations |
| Reporting | Consumers of finding/result objects and their serialization APIs |

- Put Python ergonomics, argument checks, iterator adapters, and composition in
  the Python package. Keep the PyO3 bridge focused on conversion, ownership,
  execution controls, and exposing native capabilities.
- Implement reusable detection, rule loading, extraction, validation, and
  revocation behavior in the shared Rust crates. Reuse the CLI implementation
  when the interfaces promise equivalent semantics; keep one canonical engine
  and catalog rather than independent Python implementations.
- New sources should feed the existing input contract. New transforms should
  compose with existing enumerators and scanners. Keep acquisition policy,
  extraction policy, detection policy, and report filtering independently usable.
- Prefer small typed functions and configuration objects. Introduce builders,
  protocols, registries, or plugin discovery when a concrete extension requires
  them; do not build a framework around hypothetical providers.
- Keep convenience classes as thin facades over the same engine and policy
  configuration. Avoid a scanner subclass for every source, format, or capability
  combination. As policy options grow, consolidate them in a policy object through
  an additive entry point, preserving existing convenience APIs.

## Compatibility and Public Contracts

- Preserve existing public signatures, import paths, positional/keyword behavior,
  defaults, return types, serialization shapes, and documented exception behavior.
  Constructor and dataclass fields are part of the public contract.
- Keep existing behavior as the default. Expose new behavior through explicit
  transforms, methods, configuration entry points, or opt-in facades. An additive
  feature must not silently widen a source scope or add extraction/network work.
- Treat exports in `kingfisher_sdk.__all__`, result objects, iterator behavior,
  redaction, deduplication state, and reset behavior as user-facing APIs.
- Define ordering, grouping, laziness, ownership, and lifetime guarantees. Preserve
  documented unspecified ordering rather than accidentally promising a new order.
- Preserve the distinction between detection policy and report filtering. Explain
  whether an option changes native work, removes candidate findings, or filters
  already-produced results; do not give these operations interchangeable names.
- Keep scanning offline. Source acquisition and provider operations must remain
  explicit. Preserve the existing revocation confirmation contract and retry
  semantics; do not add automatic revocation or infer authorization from findings.

## Inputs, Results, and Provenance

- Preserve logical source paths for path-aware rules. Keep source metadata with
  each result group; `Finding` alone does not identify its filename.
- Transforms must retain original repository, object, commit, and other provenance
  while assigning meaningful member paths. Preserve specialized input metadata
  when replacing or expanding an input; do not reconstruct only base fields.
- Distinguish original container/object identity from scanned content identity.
  Document the coordinate system for offsets after extraction or normalization.
- Describe the meaning of metadata precisely: a selected occurrence, a target
  snapshot, or an unknown origin must not imply first introduction or complete
  history. Use explicit absence/unknown values instead of invented provenance.
- Keep complete per-input findings, including invisible component helpers,
  together until dependent operations finish. Apply visibility filtering when
  reporting. Context filters must run before component resolution, catalog
  deduplication, and redaction when they affect which candidates can participate.
- Exclude payloads, secrets, captures, and potentially secret-bearing messages
  from default representations. Preserve redaction by default in reporting APIs
  and examples; opt-in raw serialization must remain explicit.

## Resources, Errors, and Concurrency

- Specify the scope of each limit: per operation, per input, per archive root,
  across nested layers, or over an iterator's lifetime. State when work is eager
  and when payloads are read lazily.
- Preserve timeout and cancellation behavior across stages. Check controls around
  expensive native work, release the GIL for native work where appropriate, and
  document operations that cannot be preempted.
- Propagate cancellation, timeouts, and budget errors. Do not convert them into
  empty successes or raw-content fallback. Preserve completed groups already
  yielded, and do not return partial findings for a failed scan.
- Distinguish malformed-input fallback, unsupported formats, best-effort
  extraction, and strict error propagation. Document internal truncation or
  skipped entries; a successful extraction is not necessarily complete coverage.
- Preserve scanner reuse and thread safety. Failed/interrupted work must not
  poison scanner pools or commit successful-scan deduplication state.
- Reuse compiled rules and native execution resources. Avoid repeated payload
  copies and whole-source materialization unless a capability requires it; bound
  memory growth and document unavoidable descriptor/metadata preparation.
- Keep reusable optional capabilities feature-gated in the shared Rust crates.
  The Python distribution may enable them without changing byte-only Rust defaults.
- Source reads and extraction should not mutate caller repositories or files.
  Use private temporary storage and close handles before cleanup. Parse bytecode
  and content without executing untrusted source code or archive members.

## Tests and Verification

- Test externally observable contracts and failure boundaries, including preserved
  defaults and signatures when relevant. Start with the narrowest affected tests;
  documentation-only edits do not require rebuilding native code.
- Add focused coverage for new scope semantics, provenance through composition,
  controls, errors/fallback, grouping, redaction, and state reuse as applicable.
  Where parity is promised, compare equivalent inputs and configuration against
  the shared implementation; do not rely on total finding counts alone.
- Keep tests deterministic and portable across supported Python versions,
  Windows x64/ARM64, macOS, and Linux. Use local fixtures and mock provider services
  rather than live credentials, accounts, or network services.
- Use `Path`/`PathBuf` and subprocess argument arrays. Account for file locking,
  separators, line endings, bare/shallow repositories, and Git availability in
  caller-owned adapters. Native Git APIs should not acquire a Git subprocess
  dependency implicitly.
- For binding changes, rebuild the extension before running Python tests. Relevant
  commands from the repository root include:

  ```bash
  uv run maturin develop --locked --profile dev
  uv run --no-sync pytest python/tests
  cargo check --locked -p kingfisher-python
  cargo clippy --locked -p kingfisher-python --all-targets -- -D warnings
  ```

- Run affected shared Rust and CLI regressions when canonical behavior moves or
  changes. Check shared-crate default and relevant optional-feature builds.
- Follow the repository's Windows verification policy for filesystem, Git, and
  subprocess changes. Report unavailable checks and pending platforms explicitly.

## Documentation, Examples, and Releases

- Every new public capability needs a commented runnable example showing how it
  composes with existing APIs. Explain source selection, controls, provenance,
  limits, and result handling where relevant; keep sample output redacted.
- Update the [SDK guide](../docs/PYPI.md), [package README](README.md), capability
  comparisons, and [changelog](../CHANGELOG.md) for user-facing changes. Document
  differences from CLI behavior and existing APIs, including fallback semantics.
- Synchronize affected documentation-site sources using
  [prepare-docs.py](../docs-site/scripts/prepare-docs.py), verify local links, and
  rebuild MkDocs when practical. Update shared-crate/library documentation for
  exposed Rust APIs as required by their own instructions.
- Verify that new modules, native sources, and runnable examples are included in
  the relevant wheel/source distribution when packaging changes.
- Follow [publishing guidance](../docs/PUBLISHING.md) for independent SDK/crate
  versions and compatibility checks. Follow the root provenance-regeneration
  requirements if dependency or manifest changes affect catalog provenance.

