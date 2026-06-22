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
- `crates/kingfisher-rules/data/rules/`: YAML detection rules.
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

- Detection rules are YAML-driven and loaded from `crates/kingfisher-rules/data/rules/`.
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

Use this when creating or updating rules in `crates/kingfisher-rules/data/rules/`.

1. Read `docs/RULES.md` before non-trivial rule/schema work.
2. Start from a nearby provider-family rule and preserve the existing YAML style.
3. Use a stable `kingfisher.<provider>...` rule id and set `confidence: medium`.
4. Write a valid Hyperscan/Vectorscan regex. Lookahead and lookbehind are not supported.
5. Start `pattern` with `(?x)`, use one unnamed capture around the secret for `{{ TOKEN }}`, and use non-capturing groups for structure.
6. Prefer specific token formats and provider context; avoid broad generic patterns.
7. Use `min_entropy`, `pattern_requirements`, `ignore_if_contains`, and checksum requirements when format constraints are known.
8. Include `examples` that must match.
9. Use `depends_on_rule` for multi-part credentials; consider `visible: false` for helper rules.
10. Add YAML validation and revocation only when reliable and safe.

## Rule Verification

- Rule crate: `cargo test -p kingfisher-rules`
- Rule syntax/check path: `kingfisher rules check --rules-path crates/kingfisher-rules/data/rules/<file>.yml --load-builtins=false --no-update-check`
- Scan fixture/corpus: `kingfisher scan ./testdata --rule <rule-family-or-id> --rule-stats`
- Validator check: `kingfisher validate --rule <rule-id> <token-or-secret>`
- Broad regression when practical: `cargo test --workspace --all-targets`

## Common Tasks

- Add a detection rule: follow the rule authoring and verification sections above.
- Add a CLI command: implement under `src/cli/commands/` and register it in CLI wiring.
- Add a validator: prefer YAML first; if Rust is required, use `raw.rs` and the narrowest feature/dependency wiring.
- Update docs-site rule counts: run `uv run '/Users/mickg/src/kingfisher/data/default/rule_cleanup/count_rules.py'`, update `docs-site/overrides/` and `docs-site/mkdocs.yml`, then rebuild the docs site when practical.

## Docs Pointers

- Usage: `docs/USAGE.md`, `docs/ADVANCED.md`, `docs/INTEGRATIONS.md`
- Rules: `docs/RULES.md`
- Architecture: `docs/ARCHITECTURE.md`, `docs/ACCESS_MAP.md`
- Deployment/install: `docs/INSTALLATION.md`, `docs/DEPLOYMENT.md`, `docs/PYPI.md`
- Library API: `docs/LIBRARY.md`
