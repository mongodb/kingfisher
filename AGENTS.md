# AGENTS.md

Guidance for coding agents working in this repository.

## Scope

- Applies to the entire repository rooted at this file.
- If a deeper `AGENTS.md` exists, that file takes precedence for its subtree.

## Project

Kingfisher is a Rust secret scanner, live credential validator, revocation helper, and access-map tool. It scans repositories, git history, local files, archives, cloud storage, source-host artifacts, Docker images, and collaboration-platform exports.

## Key Paths

- `src/`: main CLI binary and application code.
- `src/cli/commands/`: CLI command definitions and wiring.
- `src/scanner/`: scan orchestration, input enumeration, repository/artifact fetching, validation phase.
- `src/matcher/`: pattern matching, captures, filtering, deduplication.
- `src/reporter/`: TOON, JSON, JSONL, SARIF, BSON, HTML, and pretty output.
- `src/access_map/`: blast-radius and permission mapping.
- `crates/kingfisher-core/`: shared core types.
- `crates/kingfisher-rules/`: rule schema, rule loading, and bundled rule data.
- `crates/kingfisher-rules/build_support/`: Betterleaks TOML import and expression parsing.
- `crates/kingfisher-scanner/`: embeddable scanning API and shared validators.
- `tests/` and `testdata/`: integration tests and fixtures.
- `docs/`, `docs/viewer/`, `docs-site/`: docs, report viewer assets, and generated MkDocs site.
- `vendor/vectorscan-rs/`: vendored Vectorscan bindings.

## Toolchain

- Workspace minimum Rust version is `1.96` in `Cargo.toml`; `make check-rust` enforces `>= 1.96.0` for build targets.
- Rust formatting is defined by `rustfmt.toml` (`max_width = 100`, 4 spaces, Unix newlines, reordered imports).
- Build scripts assume `bash` with `set -eu -o pipefail`.
- Windows Makefile targets expect MSYS2 with `pacman`.

## Common Commands

- Build: `cargo build`
- Release build: `cargo build --release`
- Preferred test wrapper: `make tests`
- Direct tests: `cargo test --workspace --all-targets`
- Nextest: `cargo nextest run --workspace --all-targets`
- Format: `cargo fmt --all`
- Lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Clean: `make clean`

## Workflow Expectations

- Keep edits minimal, targeted, and consistent with touched code.
- Do not revert user-authored or unrelated in-progress changes.
- Prefer clear fixes over broad refactors unless requested.
- Run the narrowest relevant tests first; run broader checks when practical.
- If a validation/build command cannot be run, state exactly what was skipped and why.
- Prefer `kingfisher scan --format toon` for agent/LLM workflows; use `pretty` only when human-interactive output is explicitly desired.
- After markdown/doc changes, verify local documentation links when practical.
- After `docs-site/` source changes, rebuild with `docs-site/.venv/bin/mkdocs build -f docs-site/mkdocs.yml` when practical so generated output stays in sync.

## Architecture Notes

- Built-in detection rules are generated at build time from pinned upstream Betterleaks and Veles
  sources. Keep `crates/kingfisher-rules/build.rs` pinned to a Betterleaks release rather than
  `main`, keep the Veles commit pinned, and update matching documentation and release-dependent
  tests when either source changes. Clean builds intentionally require network access.
- Betterleaks TOML is supported both for the built-in catalog and for custom rules passed through
  `--rules-path`. Custom Betterleaks rules are imported under the `custom.` namespace.
- Kingfisher 1.x YAML rules remain supported for custom, typically private rules.
- Allocator feature flags live in root `Cargo.toml`: `use-mimalloc` default, `use-jemalloc`, and `system-alloc`.
- Optional validator feature sets live in `crates/kingfisher-scanner/Cargo.toml`.
- Validation modules live primarily in `crates/kingfisher-scanner/src/validation/` and `src/validation.rs`.

## Validation And Revocation Policy

- Default to YAML validation (`validation:`), especially `Http` or `Grpc`; do not add Rust validation unless YAML cannot express the flow reliably.
- Typed validators are schema-level reusable families: `AWS`, `AzureStorage`, `Coinbase`, `GCP`, `MongoDB`, `MySQL`, `Postgres`, `Jdbc`, and `JWT`.
- Raw validators use `validation: { type: Raw, content: <name> }` and are implemented in `crates/kingfisher-scanner/src/validation/raw.rs` for provider-specific exceptions.
- If Rust validation is unavoidable, prefer a raw validator before introducing a new typed validator.
- Do not convert existing typed validators to `Raw` for consistency alone.
- For rules with validation, add `revocation:` when the third-party API safely supports revocation.

## Rule Authoring

New generally useful rules should be contributed to the Betterleaks repository first. Use
Betterleaks TOML for shared/custom rules; use the Kingfisher 1.x YAML format for private
organization-specific rules and the fixtures that exercise that format.

1. Read `docs/RULES.md` before non-trivial rule/schema work.
2. Use Betterleaks TOML for shared rules and custom TOML rules; use the Kingfisher 1.x YAML schema for private organization-specific rules.
3. Use an organization-specific custom rule ID; custom Betterleaks TOML IDs are automatically imported under `custom.`.
4. Write a valid Hyperscan/Vectorscan regex. Lookahead and lookbehind are not supported.
5. Put the reported secret in one unnamed capture for `{{ TOKEN }}` and use non-capturing groups for structure.
6. Prefer specific token formats and provider context; avoid broad generic patterns.
7. Use entropy, pattern requirements, filters, and checksum requirements when format constraints are known.
8. Include examples that must match and negative examples when nearby formats are false positives.
9. Use components/`depends_on_rule` for multi-part credentials; mark helper rules invisible.
10. Add HTTP/gRPC validation and revocation only when the provider response is a reliable and safe signal.

## Rule Pipeline

- The default catalog is downloaded from pinned upstream sources during the `kingfisher-rules`
  build, converted, and embedded in the binary. The upstream rule source is not checked in.
- `--rules-path` accepts Betterleaks `.toml` and Kingfisher 1.x `.yml`/`.yaml` files. Betterleaks TOML is translated through the same importer used for built-ins, while custom TOML gets the `custom.` namespace.
- A rule's regex produces candidate matches. The selected capture becomes the reported secret; entropy, pattern requirements, and filters remove candidates before reporting.
- Components attach nearby supporting values to a primary rule. They can be required or optional and are made available to validation as named variables.
- Validation checks credentials live through Betterleaks expressions, Kingfisher 1.x YAML HTTP/gRPC definitions, or Kingfisher's typed/raw validator families. A successful response is not proof unless the provider-specific matcher or expression makes it so.
- Revocation, access-map metadata, and narrow false-positive filters are operational capabilities kept separate from the Betterleaks detection catalog.

## Rule Verification

- Rule crate: `cargo test -p kingfisher-rules`
- Rule syntax/check path: `kingfisher rules check --rules-path <custom-rule.yml> --load-builtins=false --no-update-check`
- Scan fixture/corpus: `kingfisher scan ./testdata --rule <rule-family-or-id> --rule-stats`
- Validator check: `kingfisher validate --rule <rule-id> <token-or-secret>`
- Broad regression when practical: `cargo test --workspace --all-targets`

## Common Tasks

- Add a detection rule: contribute it to Betterleaks first; use Betterleaks TOML for shared rules and the Kingfisher 1.x YAML format only for private custom rules.
- Add a CLI command: implement under `src/cli/commands/` and register it in CLI wiring.
- Add a validator: prefer YAML first; if Rust is required, use `raw.rs` and the narrowest feature/dependency wiring.
- Update Betterleaks import behavior in `crates/kingfisher-rules/build_support/`; do not add a second
  generated or hand-authored built-in catalog.

## Docs Pointers

- Usage: `docs/USAGE.md`, `docs/ADVANCED.md`, `docs/INTEGRATIONS.md`
- Rules: `docs/RULES.md`
- Architecture: `docs/ARCHITECTURE.md`, `docs/ACCESS_MAP.md`
- Deployment/install: `docs/INSTALLATION.md`, `docs/DEPLOYMENT.md`, `docs/PYPI.md`
- Library API: `docs/LIBRARY.md`
