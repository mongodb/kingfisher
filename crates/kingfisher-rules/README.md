# kingfisher-rules

Rule definitions and compiled rule database support for Kingfisher.

The `1.x` public Rust API follows semantic versioning and requires Rust 1.99+.
Breaking API changes require a new major version; catalog updates may change which
secrets are detected without changing the Rust API.

```toml
[dependencies]
kingfisher-rules = "1.2.0"
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

To persist the main Vectorscan database across processes, use
`RulesDatabase::from_rule_collection_with_cache(rules, &RuleCacheConfig::from_dir_or_env(None))`.
This honors `KF_RULE_CACHE_DIR` or a per-user OS cache directory;
`RuleCacheConfig::new(path)` selects an explicit directory. If no user directory is
available, caching is disabled; it never falls back to a shared temporary directory.
Cache failures fall back to compilation and writes are best effort. Confirmation
regexes and path/finding filters still initialize per database. Ordinary uncached
constructors retain their behavior.

`database.cache_status()` distinguishes `RuleCacheStatus::Loaded`, `Stored`, and
`Bypassed`. Use it when explicitly prewarming an image must persist the database;
the CLI's `rules compile-cache` fails if compilation succeeded without a usable
cache entry. Ordinary scan commands continue when caching is unavailable.

Treat the cache as trusted native bytecode. New Unix cache directories and entries
use modes `0700` and `0600`. Existing locations must be owned by the current user,
with no group/other write access, and their ancestors must prevent substitution.
Symlink entries are rejected. On Windows, the cache directory and files must be
owned by the current user; DACLs permit writes by that user, Administrators and
SYSTEM. New Windows directories and entries receive the process user SID as owner
at creation, including when running as SYSTEM. Existing paths must satisfy the
same ownership and DACL checks. Protected ancestors may also be owned or maintained
by TrustedInstaller; other accounts must not be able to replace the cache.
Reparse points are rejected.
Unsafe or unverifiable directories are ignored and rules compile without using disk caching.
Read permission alone does not invalidate an otherwise protected cache.
Ownership is a check of the deployed filesystem, not part of the cache key or
serialized database. A container may compile as root during image construction,
then copy the directory and all entries with `COPY --chown=<runtime-uid>:<runtime-gid>`.
The same image can run on another host as that UID, including with a read-only
filesystem when the entry is compatible. See the
[Python container example](../../python/examples/rule_cache.Dockerfile).

Each entry includes a SHA-256 of the serialized database, checked before native
deserialization. This detects corruption; it does not authenticate data written by
the same user or a privileged administrator. Protect that account and its cache
directory as you would the executable or installed SDK itself.

Entries are keyed by ordered rule patterns, cache format, exact binding/native crate
versions, full engine build version, architecture, pointer width, and endianness.
Reuse entries from the same deployed CLI binary or SDK wheel. Compatibility across
different native builds or operating systems is not guaranteed. Native CPU/version
rejection falls back to compilation, so an incompatible cache cannot prevent scanning.
Externally supplied or patched engines that preserve the same runtime version string
cannot be distinguished by that identity. Give each such engine build a separate
cache directory, or use the uncached constructors.

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

A Betterleaks release is preferred. The current bundle pins v2.0.0-rc.1 at
`b3b4cbb586c964701f78bbfb6bc2129ced99bed3`, because stable v1.9.0 lacks the Cloudflare
`cfut_`/`cfat_` detectors. The exact `config/betterleaks.toml` SHA-256 is
`b8627cfd4b12beb833f0b7e1173157b1a2988ceb87cf3e2e2882182d7229adf7`.
Its revision and expected digest live in `tools/rule-bundle/src/main.rs`;
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

The `__scanner-internals` feature exposes implementation details used by
`kingfisher-scanner`. It is unstable, unsupported, and has no semantic-versioning
guarantee; its APIs may change in any release. Applications should use the supported
rule-loading and database APIs above.
