# AGENTS.md

Guidance for the native Python bindings in this subtree.

- Follow the [repository instructions](../../AGENTS.md) and read the
  [Python SDK architecture and compatibility guidance](../../python/AGENTS.md).
  Its principles apply to this bridge as well as the Python package.
- Keep this crate focused on PyO3 conversions, native object ownership, execution
  controls, and exposing shared capabilities. Put reusable engine behavior in the
  appropriate shared crate and Python composition/ergonomics in `python/`.
- Preserve public Python contracts when changing bindings, including exception
  mapping, result grouping, redaction, deduplication, cancellation, and lifetime
  behavior. Rebuild the extension before testing Python-visible changes.
- Preserve the configured Python compatibility and wheel targets. Keep GIL
  release, thread safety, shared runtime ownership, and optional shared-crate
  features explicit; do not introduce implicit CLI or Git subprocess dependencies.
- Run affected Python tests and native/shared-crate checks. Update Python examples
  and documentation for exposed capabilities, even when implementation changes
  occur entirely in Rust.

