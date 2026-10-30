# Rules compatibility

Follow the repository `AGENTS.md`. Existing Kingfisher YAML and Betterleaks TOML rules must
continue to load and work without edits. New fields need backward-compatible defaults and
must not silently change legacy validation/revocation behavior. Test unmodified legacy inputs.

HTTP fallback profiles are optional, limited to two, and require runtime opt-in. Their
`reuse_primary_validation_logic` and `reuse_primary_revocation_logic` booleans default to false. Validation
reuse replaces only the primary HTTP URL; otherwise a complete HTTP validation is required.
Revocation reuse requires explicit replacement URL(s), preserving the original HTTP action
or multi-step program. Otherwise use an independent action or leave revocation unavailable.
Never implicitly inherit revocation or try alternative mutation targets. The CLI opt-in is `--fallbacks`.
Describe reuse as sharing logic while explicitly replacing the target URL(s), never copying
the primary destination.
Keep legacy scalar/list HTTP URL inputs readable; do not migrate the bundled detection catalog
just to enable optional fallback behavior.

## Built-in catalog

- Exclude all filename-only/path-only detectors from built-in imports, including upstream rules
  with a path but no content regex. Do not add them to the bundle or rely on runtime exclusions.
- Preserve content detectors that also restrict matching by path. Keep filename-only support
  available for explicit custom Kingfisher YAML and Betterleaks TOML rules, including their
  native callback-budget safeguards.
- Generally useful detectors and validation improvements must go upstream to Betterleaks.
  Direct first-party rules in `data/kingfisher-rules.yml` are rare exceptions requiring a
  specific reason that requires shipping in Kingfisher itself, source/license provenance,
  tests, and a retirement condition in `data/kingfisher-rules.md`. Convenience or an
  unsubmitted upstream change is not sufficient. Replace temporary exceptions when a
  compatible upstream detector becomes available.
- First-party exceptions feed the same maintainer-generated bundle, readable catalogs,
  provenance, notices, and verification pipeline as imported detectors. Do not add another
  catalog or runtime loader. Preserve the three broad Betterleaks generic-rule exclusions.
