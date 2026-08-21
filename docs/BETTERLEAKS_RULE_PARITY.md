# Betterleaks Rule Parity Notes

This file records intentional differences and remaining parity work between Betterleaks and
Kingfisher's Rust execution of the Betterleaks catalog. It is internal engineering guidance, not a
second rule source.

## Source and reproducibility

- Kingfisher does not check in or distribute the upstream rule source. Clean builds intentionally
  require outbound HTTPS access and download Betterleaks `v1.8.0` plus selected Veles files from a
  pinned OSV-SCALIBR commit before converting and embedding them.
- The source pins keep normal builds on released/committed upstream content rather than `main`.
  Release build provenance should record the fetched source digests when reproducibility is needed.
- `KINGFISHER_BETTERLEAKS_CONFIG` may supply a local TOML file for controlled importer development;
  normal builds fetch the pinned upstream sources.

## Detection and filtering

- Regex, Betterleaks `secretGroup` selection (including its first-non-empty default), global
  prefilter/filter expressions, per-rule filters, path constraints, component dependencies, and
  `setConfidence` are translated and executed. Upstream named captures are preserved for filters
  and validation. The source prefilter is stored once on the rule database, compiled into a
  separate Vectorscan database, and runs before content matching; only the global finding filter
  and per-rule finding filter are combined.
- Betterleaks keyword lists are not imported as a pre-scan optimization. This should affect
  performance only, not detection semantics; Vectorscan performs Kingfisher's content candidate
  detection.
- When a deduplicated blob has multiple origins, Kingfisher scans it if any source path survives
  the Betterleaks prefilter and uses the first surviving path for path/filter evaluation. This is a
  Kingfisher-specific extension of Betterleaks' one-fragment/one-path model.
- The prefilter gates a mixed Betterleaks/custom compiled database as a whole, so an additive custom
  rule does not run on a Betterleaks-excluded path. `--load-builtins=false` removes that gate. A
  future partitioned matcher could avoid this coupling, but would no longer be a single pre-engine
  database gate.
- Every rule is compiled into the exact Vectorscan content database. Kingfisher's Rust regex then
  confirms each resulting candidate and extracts captures, which Vectorscan does not expose. No
  rule bypasses Vectorscan or runs an unconditional whole-blob regex scan.
- A path-only rule cannot be represented by Kingfisher's match-first engine and is skipped. At the
  time of the migration this affected the PKCS#12 path-only rule. Regex rules with `path` constraints
  are supported.
- `failsTokenEfficiency` implements the tokenizer-ratio threshold with `cl100k_base`, but not
  Betterleaks' internal known-word-list rejection. This can retain findings Betterleaks rejects.
- Kingfisher omits Betterleaks' `generic-api-key`, `generic-password`, and `generic-username` rules.
  Their broad patterns provide low-value findings and impose disproportionate cost on repository
  history scans. Custom Betterleaks TOML can still define organization-specific generic rules.
- Betterleaks uses Go regular-expression behavior for filter helpers; Kingfisher compiles those
  helper patterns into shared Vectorscan databases. Current upstream expressions are compatible,
  but edge-case syntax or Unicode behavior may differ.
- Filter offsets and line context are derived from Kingfisher's byte-oriented matcher. Lossy UTF-8
  conversion can make offsets differ for non-UTF-8 blobs, so `finding["line"]` is not a
  byte-for-byte reconstruction of Betterleaks' scanner line in every input mode.
- Component dependencies use Betterleaks' directional line/byte `within` windows. Kingfisher
  associates the nearest in-range value, leaves optional components absent when none is nearby, and
  suppresses a primary finding when a required component is missing. Legacy Kingfisher YAML
  dependencies without `within` retain their existing validation-only behavior.

## Reporting and output

- All output formats use a title of `<DISPLAY-ID> => [<FULL-ID>]`, omitting the `betterleaks.` or
  `veles.` namespace prefix from the display ID. The shared `FindingReporterRecord`
  (`src/reporter.rs`) retains this title in `rule.title`, the full id in `rule.id`, the display id
  in `rule.name`, and the human-readable rule description in `rule.description`.
- Pretty prefixes the title with its validation icon and writes `Description` immediately after
  `Finding`.
- JSON / JSONL / BSON / TOON / HTML expose the combined title, display id, description, and full
  rule id.
- SARIF keeps the full id in `ruleId` and the reporting-descriptor `id`, while its short description
  is the combined title and its full description is the human-readable rule description.

## Validation

- Current Betterleaks validation expressions are parsed at build time into a portable AST and run
  by Kingfisher's Rust HTTP/cloud clients. Component credentials and endpoint environment overrides
  are supported.
- Import validation is deliberately strict: new upstream expression/filter operations fail the
  build rather than being silently ignored. The Rust evaluator still needs an implementation update
  whenever Betterleaks adds a new supported operation.
- Request retry and response-size behavior is not identical to Betterleaks or to every Kingfisher 1.x
  HTTP validator path. Treat future retry/body-limit unification as runtime work, not a rule
  conversion.
- Access-map collection is available only when a Betterleaks rule has a successful validation and
  `imported-rules-capabilities.yml` declares a compatible typed handler. GitLab mappings may accept a
  reachable 2xx response by explicit metadata. Standalone access-map providers that lack a
  compatible validated Betterleaks credential remain available only through `kingfisher
  access-map`; they are not automatically fed by scans.

## Revocation and checksums

- Betterleaks' current schema contains neither revocation metadata nor Kingfisher-style checksum
  templates. Kingfisher joins selected safe revocation actions through
  `imported-rules-capabilities.yml`; checksum behavior cannot be recovered generically and remains an
  upstream-format gap.
- Composite revocation bindings can map `finding.secret` and `components.<id>` values. This restores
  AWS revocation even though Betterleaks reports the access-key ID as the primary finding and the
  secret access key as a component.
- Revocation is intentionally not mapped when a Betterleaks rule merges token types with different
  revocation endpoints (for example `github-app-token` covers both `ghu_` and `ghs_`), when the
  exact credential cannot be identified safely, or when required provider context is unavailable.
- The Kingfisher 1.x custom YAML format remains supported for `Http`, `HttpMultiStep`, `AWS`, and `GCP`
  revocation and for `pattern_requirements.checksum`. Tests cover both direct custom-rule revocation
  and BIP-39 checksum gating.
- The capability overlay contains operational metadata only and is build-validated against
  upstream IDs/components. Do not add regexes, finding filters, confidence, or validation programs
  to it. Prefer an upstream Betterleaks schema/contribution, followed by importer/runtime support.
