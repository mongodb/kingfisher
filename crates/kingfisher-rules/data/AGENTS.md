# AGENTS.md

Guidance for agents working on Kingfisher's built-in rule import configuration.

## Scope

- Applies to files in `crates/kingfisher-rules/data/`.
- The repository-root `AGENTS.md` still applies unless this file provides more specific guidance.
- Related implementation lives in `../build_support/betterleaks.rs`; runtime behavior is defined by
  the rule schema and validator dispatch outside this directory.
- Veles import implementation lives in `../build_support/veles.rs`.

## Purpose

`imported-rules-capabilities.yml` is the operational overlay for imported rules. Its `betterleaks`
and `veles` sections augment pinned upstream detectors with Kingfisher-specific validation,
access-map, revocation, confidence, authority, and narrow filter behavior. It is not a second rule
catalog.

`veles-rules.yml` pins an OSV-SCALIBR commit and allowlists Veles plugin IDs for build-time import.
Veles is Go source rather than a declarative catalog, so every selected ID must have an explicit,
fail-closed adapter in `build_support/veles.rs`.

## Ownership Boundaries

- Keep detection regexes, components, descriptions, and general validation expressions in
  Betterleaks. Contribute generally useful detector changes upstream first.
- Do not copy or redefine Betterleaks detectors in the overlay.
- Use exact, unqualified upstream IDs such as `mongodb-connection-string`; the importer adds the
  `betterleaks.` namespace.
- Every overlay entry must exist in the pinned Betterleaks release. Do not target `main` or an
  unreleased rule.
- Keep `imported-rules-capabilities.md` synchronized with supported overlay fields and syntax.
- Keep Veles revisions pinned to a full commit hash. Never import from `main`.
- Add only Veles detector families whose live-validated coverage Betterleaks lacks at the pinned
  release, including detector-only Betterleaks equivalents.
- Do not add Veles custom-rule loading or expose the Veles config at runtime.

## Validation Policy

- Preserve an upstream Betterleaks validation expression when it already models the credential
  correctly. Do not replace it merely because a similarly named Kingfisher validator exists.
- Add typed validation only when the detector's reported secret and components exactly match the
  validator's input contract and the typed family adds reusable semantics.
- The overlay currently accepts scalar `Assumed`, `JWT`, and `MongoDB` validation plus configured
  `Ethereum` validation with `private_key`, `public_key`, or `mnemonic` content.
- Typed validation cannot be combined with an upstream `validate` expression or
  `validation_override`. The importer rejects this combination.
- Access-map and `revocation_bindings` metadata currently require Betterleaks expression
  validation. Do not convert such a rule to typed validation without first preserving that
  capability path in the importer and runtime.
- Keep AWS, GCP, and Azure Storage rules on their Betterleaks helper expressions unless their input
  adaptation, result classification, and operational metadata are demonstrably preserved.
- Do not expose provider-specific `Raw`, generic `Http`, or `Grpc` validation through this overlay
  without a concrete pinned detector need and corresponding importer, documentation, and tests.
- Offline validation such as `Ethereum` establishes valid key material or derives an identifier; it
  must not claim that an account or credential is active.

## Operational Fields

- Use `authoritative: false` when successful validation cannot establish that a broad detector is
  an active credential.
- Use `confidence` only for a deliberate Kingfisher classification correction.
- Keep `filter_override` narrow and operational. General false-positive improvements belong in
  Betterleaks.
- Use `validation_override` only to replace an unsafe or incompatible pinned upstream expression,
  and preserve equivalent valid, invalid, and unknown classifications.
- Add access mapping only when validated evidence can be safely translated to an existing handler.
  Map component inputs explicitly and set `reachable_2xx` only when reachability is meaningful.
- Add revocation only when the provider offers a safe, reliable credential-specific operation.
  Bind every required secret and variable explicitly.
- Put Veles operational metadata in the `veles` overlay section, not in its Rust source adapter.
- Never include live credentials, private keys, tokens, or sensitive response bodies in fixtures,
  comments, documentation, or generated evidence.

## Implementation Changes

- Extend source-specific overlay deserialization and generated serialization in
  `../build_support/betterleaks.rs` or `../build_support/veles.rs` when adding syntax.
- Keep generated types aligned with `../src/rule.rs`; the emitted YAML must deserialize into the
  production rule schema.
- Check runtime input names and semantics in `../../kingfisher-scanner/src/validation/` and
  `../../../src/validation.rs` before binding a typed validator.
- Add a focused importer test and an end-to-end generated-catalog assertion in
  `../src/defaults.rs` for new capability kinds or bindings.
- Avoid broad schema expansion for a single provider. Prefer Betterleaks expressions, then an
  existing typed family; reserve new typed families for stable reusable protocols.

## Verification

- Run `cargo fmt --all` after Rust changes.
- Run `cargo test -p kingfisher-rules` for every overlay or importer change. This verifies that
  overlay IDs exist in the pinned catalog and that generated rules deserialize.
- Run the narrowest relevant validator or scan integration test when a binding changes runtime
  behavior.
- Run `git diff --check` before finishing.
