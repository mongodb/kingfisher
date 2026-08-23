# Betterleaks Rule Parity Notes

This file records intentional differences and remaining parity work between Betterleaks and
Kingfisher's Rust execution of the Betterleaks catalog. It is internal engineering guidance, not a
second rule source.

## Source and reproducibility

- Kingfisher does not check in or distribute the upstream rule source. Clean builds intentionally
  require outbound HTTPS access and download the pinned Betterleaks catalog snapshot from its
  [source permalink](https://github.com/betterleaks/betterleaks/blob/3d798ac55d89f14a60c8df65d4d2bda6fccb1ea1/config/betterleaks.toml),
  plus selected Veles files from a pinned OSV-SCALIBR commit, before converting and embedding them.
- A Betterleaks release is preferred. The current pinned commit is a full immutable post-release
  revision because the latest release predates detectors that Kingfisher ships; the build verifies
  the expected SHA-256 digest for the default snapshot. Release provenance should retain the source
  revision and digest.
- `KINGFISHER_BETTERLEAKS_CONFIG` may supply a local TOML file for controlled importer development;
  normal builds fetch the configured upstream sources.

## Rule-level provenance review

- The Fly.io detector is Gitleaks lineage: the Kingfisher 1.x rule explicitly cited the
  [Gitleaks Fly rule](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/flyio.go), and Betterleaks carries the same `FlyV1` format with updated upstream validation. The
  Betterleaks source also contains a TruffleHog pull-request URL as a reference; that citation is
  not evidence that Kingfisher copied TruffleHog.
- The Tableau secret regex (`[A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32}`) is present in both the
  [Betterleaks Tableau commit](https://github.com/betterleaks/betterleaks/commit/f64b922294260c390e4d20442c239b52275247cb) and the
  [TruffleHog Tableau detector](https://github.com/trufflesecurity/trufflehog/commit/05e2328da28ec37eee95008abdbbfd66d8dd4ec7). A search of the local Betterleaks,
  Gitleaks, and TruffleHog sources plus an exact web search found no second indexed copy;
  [Tableau's API documentation](https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_concepts_auth.htm)
  independently shows the same token shape. Because the Betterleaks commit is later than the
  TruffleHog detector, treat this as an unresolved provenance item and obtain legal/source
  confirmation or replace the detector with an independently documented implementation if a strict
  no-TruffleHog-overlap policy is required.

## Detection and filtering

- This migration is not a byte-for-byte catalog replacement. At the default Medium confidence
  threshold, the pinned snapshot currently embeds 483 Betterleaks/Veles rules versus 1,061 bundled
  rules in Kingfisher 1.113.0; families without a 2.x replacement remain available only when the
  1.x YAML catalog is supplied through `--rules-path`. Do not describe the v2 built-in catalog as
  functionally equivalent to every 1.x detector.

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
