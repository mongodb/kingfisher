# AGENTS.md

Guidance for working in `crates/kingfisher-scanner/`.

## Scope

- Applies to `crates/kingfisher-scanner/` and all files under it.
- This file overrides broader repository guidance for this subtree.

## Purpose

- Preserve `kingfisher-scanner` as a focused, embeddable Rust API for secret scanning.

## Design Expectations

- Keep the public API centered on `Scanner`, `ScannerConfig`, `Finding`, and `ScannerPool`.
- Prefer small, composable changes over broad API reshaping.
- Avoid pulling binary-crate concerns into this crate unless they are truly reusable.
- Re-export shared types from `kingfisher-core` and `kingfisher-rules` only when it materially improves embedding ergonomics.

## Feature Flags

- Validation code must remain feature-gated.
- Validation is all-or-nothing: gate every validator and revoker behind `validation`. Provider-specific feature names are compatibility aliases only.
- Do not make optional validation dependencies unconditional unless there is a strong compatibility reason.

## API Stability

- Preserve unmodified legacy YAML/TOML rule loading and primary validation/revocation behavior.
  New fallback endpoints require explicit execution opt-in in every CLI/SDK path. Unused
  fallbacks must not trigger requests, DNS lookups, or input requirements for primary validation.
  Validation and revocation reuse are separate booleans, both defaulting to false; reuse
  replaces only explicit URL(s). `--fallbacks` enables CLI environments, never automatic
  revocation or mutation failover. Result-based revocation retains the validated selection.
  CLI fallback revocation validates first; do not add implicit revalidation to SDK result-based
  revocation or change legacy direct-primary CLI behavior.

- Treat changes to exported structs, methods, and re-exports as user-facing changes.
- Update `docs/LIBRARY.md` and crate-level docs when the public API or recommended usage changes.
- Keep examples in the crate README and `docs/LIBRARY.md` consistent with the current API.

## Performance

- Preserve the crate's focus on efficient multi-pattern scanning.
- Be cautious with allocations, duplicate conversions, and cross-thread contention in hot paths.
- Keep scanner-pool and primitive changes benchmark-minded, even when benchmarks are not run in the current task.

## Validation

- Run the narrowest relevant tests first for scanner changes.
- If public API behavior changes, prefer adding or updating focused tests in this crate or the external-consumer integration coverage.
