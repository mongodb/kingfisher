# kingfisher-rules

Rule definitions and compiled rule database support for Kingfisher.

The `1.x` public Rust API follows semantic versioning and requires Rust 1.96+.
Breaking API changes require a new major version; catalog updates may change which
secrets are detected without changing the Rust API.

```toml
[dependencies]
kingfisher-rules = "1.0.0"
anyhow = "1"
```

```rust
use kingfisher_rules::{get_builtin_rules, RulesDatabase};

let rules = get_builtin_rules(None)?;
let database = RulesDatabase::from_rule_collection(rules)?;
assert!(database.num_rules() > 0);
# Ok::<(), anyhow::Error>(())
```

Preserve collection metadata with `from_rule_collection`; converting a loaded
collection to a bare vector discards its database-level source prefilter.
For custom files use `Rules::from_paths`, `Rules::from_toml_file`, or
`Rules::from_yaml_file`. Programmatic private rules can start with
`RuleSyntax::new(id, name, pattern)` and compile via `RulesDatabase::from_rules`.
Construction and compilation do not run validation or contact providers.
Compilation is fallible and relatively expensive: compile once, share with `Arc`,
and reuse. Vectorscan is a native build dependency.

This crate provides:

- rule syntax and rule model types
- Kingfisher YAML and Betterleaks TOML loading for custom rules
- an embedded database generated from pinned Betterleaks and selected Veles detectors
- `RulesDatabase` compilation for scanning engines

Normal builds embed `generated/builtin-rules.gz` without fetching rule sources or
writing documentation. Betterleaks takes precedence when its catalog covers a Veles detector.
The existing importers apply Kingfisher matching, filtering, validation, access-map, and
revocation behavior to the upstream candidates.

`generated/provenance.json` records upstream revisions, source hashes, generated rule IDs,
generator input hashes, and artifact hashes. `generated/upstream-sources.json.gz` is a gzip
compressed JSON map from immutable source URLs to exact UTF-8 file contents (including licenses
and source headers); null records an absent upstream NOTICE. `generated/NOTICES.txt` contains
readable attribution and license text preserved in the repository.
These records document what was imported; they do not establish upstream authorship.

## Readable rule catalogs

The generated [rules directory](generated/rules/) contains two files in the Kingfisher rule
format: [betterleaks.yml](generated/rules/betterleaks.yml) and
[veles.yml](generated/rules/veles.yml). They preserve all imported rules, credential helpers,
and collection-level metadata such as Betterleaks source filtering. These files ship in the
crate and are generated from the same imported documents as the compressed bundle. The runtime
bundle, its entry names, and public loading APIs remain unchanged.

Each file identifies its upstream sources and links to the provenance manifest and notices.
The manifest maps each rule ID to its `generated_file`, records immutable source revisions,
and hashes both YAML files. Kingfisher-authored helpers are explicitly attributed to Kingfisher.
These are modified derivatives, not verbatim upstream rules: Betterleaks sources carry MIT
licensing and Veles / OSV-SCALIBR sources carry Apache-2.0 licensing; retain the
[notices](generated/NOTICES.txt), [provenance](generated/provenance.json), and source archive
when redistributing the catalog.

To load both readable catalogs without also loading the embedded catalog:

```sh
kingfisher rules check --rules-path crates/kingfisher-rules/generated/rules --load-builtins=false --no-update-check
```

Files preserve built-in rule IDs. When adapting them into private rules, assign your own IDs
and update dependency references consistently.

Do not edit `generated/rules/`; regeneration replaces its contents and removes obsolete files.
New imported rules automatically appear in the corresponding source's YAML file; no service
assignment is required. Rule definitions come from pinned upstream inputs and Kingfisher
importers and overlays. `--check` verifies both YAML files alongside the bundle and provenance.

From the repository workspace, maintainers run:

```sh
# Complete regenerate/check/test workflow (also rebuilds docs when MkDocs is installed).
python3 scripts/update-rule-bundle.py
# Use --refresh for new pins/selections; --check verifies without rewriting artifacts.
```

The wrapper uses Python 3.9+ and delegates to the existing Rust importer. It does not change
pins automatically. See `docs/PUBLISHING.md` and the root `AGENTS.md` for the update checklist.
The lower-level commands remain available:

```sh
# Fetch pinned upstream sources, archive evidence, and regenerate artifacts.
cargo run --locked -p kingfisher-rule-bundle -- --refresh
# Regenerate after importer/overlay changes using only archived sources.
cargo run --locked -p kingfisher-rule-bundle
# Verify all generated artifacts without changing files or fetching sources.
cargo run --locked -p kingfisher-rule-bundle -- --check
```

A Betterleaks release is preferred; the current post-release commit retains detectors absent
from the latest release. Its revision and expected digest live in `tools/rule-bundle/src/main.rs`;
Veles selections and revision live in `data/veles-rules.yml`. Update the pins, run `--refresh`,
review the provenance and license changes, and commit the generated artifacts together.
The old `KINGFISHER_BETTERLEAKS_CONFIG` and `KINGFISHER_BETTERLEAKS_CONFIG_URL` build overrides
are no longer used. Custom rules remain supported through `--rules-path`.

The tool also generates `docs-site/docs/rules/builtin-rules.md`. Kingfisher-only operational
metadata lives in `data/imported-rules-capabilities.yml`.

## Runnable examples

From the repository checkout:

```sh
cargo run --locked -p kingfisher-rules --example load_rules
```

The packaged [`load_rules` example](https://github.com/mongodb/kingfisher/blob/main/crates/kingfisher-rules/examples/load_rules.rs) is also available
in the crate source.

To load a custom rule file instead of the embedded catalog:

```sh
cargo run --locked -p kingfisher-rules --example load_rules -- path/to/rules.toml
```
