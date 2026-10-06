# Publishing Cargo packages

[← Back to README](../README.md)

The root package is `kingfisher-bin`; its executable and Rust library retain the name
`kingfisher`. The `kingfisher` crates.io name belongs to another project. The reusable library packages
are `kingfisher-core`, `kingfisher-rules`, and `kingfisher-scanner`. The maintainer-only
`kingfisher-rule-bundle` package is never published. The `kingfisher-python` binding
crate is packaged by Maturin for the separate Python SDK release, not crates.io.

## Package versions and consumers

The manifests currently prepare these releases; a Git tag does not override Cargo versions:

| Package | Version | Published targets |
| ------- | ------- | ----------------- |
| `kingfisher-core` | `1.0.3` | `kingfisher_core` library |
| `kingfisher-rules` | `1.2.0` | `kingfisher_rules` library |
| `kingfisher-scanner` | `1.3.0` | `kingfisher_scanner` library |
| `kingfisher-bin` | `2.11.0` | `kingfisher` executable and library |

The Python SDK (`kingfisher-secret-scanner`) is independently versioned at
`1.3.0` in `crates/kingfisher-python/Cargo.toml`; Python modules share that version.

The libraries establish their stable `1.x` API at `1.0.0`; they do not inherit the CLI
version. See the [compatibility contract](LIBRARY.md#api-stability).
`kingfisher-rule-bundle` is `0.1.0` with `publish = false`. The external
`kingfisher-vectorscan` dependency is versioned separately.

After publishing, consumers can install the CLI with:

```sh
cargo install --locked kingfisher-bin --version 2.11.0
```

This installs the `kingfisher` command. See [library usage](LIBRARY.md#quick-start)
for registry dependency examples. All four packages require Rust 1.99 or newer.
The [release workflow](../.github/workflows/release.yml) publishes missing crate versions
after its cross-platform tests, builds, and GitHub release succeed. It is restricted
to `mongodb/kingfisher`; forks and the private development mirror do not publish crates.

## Prepare the rule bundle

Normal compilation embeds the prepared bundle and performs no rule downloads. Use the
[Python wrapper](../scripts/update-rule-bundle.py) for the complete update workflow:

```sh
# After importer or operational-overlay edits: use archived sources.
python3 scripts/update-rule-bundle.py
# After changing an upstream pin, Veles selection, or required upstream files:
python3 scripts/update-rule-bundle.py --refresh
# Final verification without rewriting generated artifacts:
python3 scripts/update-rule-bundle.py --check
```

The wrapper requires Python 3.9+ and Cargo on PATH. On Windows, `py -3` can replace `python3`.
It finds the workspace relative to its own location, so an absolute script path works from
any directory. It checks Rust formatting, invokes the existing Rust generator, verifies all
artifacts, and runs the rules and generator tests. Update modes also rebuild the site when
the docs-site virtual environment contains MkDocs; otherwise they report the skipped render.
Every failing command stops the workflow. Fix formatting with `cargo fmt --all` before retrying.
`--check` leaves generated files alone; Cargo still writes build/test outputs. Cargo dependencies
and native prerequisites may require network access even when rule sources come from the archive.

`--refresh` fetches the exact pinned sources and licenses; it does not choose versions for you.
The Betterleaks revision and expected SHA-256 are in
[`tools/rule-bundle/src/main.rs`](../tools/rule-bundle/src/main.rs); the Veles revision and
selected IDs are in [`veles-rules.yml`](../crates/kingfisher-rules/data/veles-rules.yml).
Neither command accepts floating refs or unverified Betterleaks source overrides.

For a new Betterleaks release, resolve the release to its full commit, review the source, and
set both `BETTERLEAKS_REVISION` and the SHA-256 of that commit's exact
`config/betterleaks.toml` bytes. For Veles additions, select the plugin ID and implement an
adapter in `build_support/veles.rs` if needed. Add focused importer/runtime tests and operational
overlays before refreshing. See the [catalog-update checklist](../AGENTS.md#updating-the-bundled-catalog).

Review added/removed IDs in `provenance.json` and the generated rule listing, then update any
documented counts and release-dependent assertions. Importer changes that request additional
upstream files require `--refresh` even at the same commit. Changes to root `Cargo.toml`,
`Cargo.lock`, or `LICENSE` also require regeneration because their hashes are recorded.

Commit the generated bundle, archived sources, provenance, notices, and generated rule docs
together. Review upstream input and license changes; hashes record what was imported, not
whether upstream contributors owned every contribution. Preserve relevant upstream history
and legal review records separately when investigating disputed rules.

The [generated directory](../crates/kingfisher-rules/generated/) contains:

- `builtin-rules.gz`: the existing portable KFRULES v1 container of converted YAML.
- `upstream-sources.json.gz`: gzip-compressed JSON mapping immutable URLs to exact UTF-8
  source/license contents. A null value records an optional NOTICE absent at that revision.
- `provenance.json`: upstream revisions, source hashes, generator input hashes, artifact hashes,
  and a source mapping for every generated rule, including helper rules.
- `NOTICES.txt`: readable rule-source license and attribution text.

CI verifies regeneration with networking disabled. The release workflow includes these files
in `kingfisher-rule-bundle.tgz` and covers that archive with the existing release attestation.
This attests to the release artifact and workflow, not upstream authorship.

## Package and verify

Update package versions and internal dependency version requirements together. The `path`
fields support workspace development; published manifests use the version requirements.
Cargo can package the selected workspace members together before they exist in the registry:

```sh
cargo package --locked -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner -p kingfisher-bin
cargo test --locked -p kingfisher-bin --test licenses --test smoke_check_rules
```

Use `--allow-dirty` only for local pre-commit verification. Inspect the `.crate` archives in
`target/package/`, especially the rules bundle, provenance, licenses, and viewer assets.
The root package's explicit file list avoids shipping fixtures and generated documentation.
`cargo package` verifies extracted packages; a `--no-verify` run alone is insufficient.

For a network-denied build check, first cache Cargo dependencies and native prerequisites,
then build extracted packages in an OS network sandbox. Cargo's `--offline` flag alone does
not prevent arbitrary build scripts from accessing the network. Vectorscan's default native
backend can download its release archive independently of rule generation. For an offline
build, set `VECTORSCAN_PREBUILT_DIR` to a directory containing the verified archive for the
selected target, or use `HYPERSCAN_ROOT` for an installed native library; set
`VECTORSCAN_OFFLINE=1` to reject a missing native archive.

## Stable API release gate

Run README doctests and consumer contract tests in addition to packaging:

```sh
cargo test --locked -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner
cargo test --locked -p kingfisher-scanner --all-features
```

Before subsequent `1.x` releases, compare each library against its last published
compatible version, both without optional features and with all features. For example,
after `1.0.0` is published:

```sh
cargo semver-checks -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner --baseline-version 1.0.0 --only-explicit-features
cargo semver-checks -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner --baseline-version 1.0.0 --all-features
```

Use an installed `cargo-semver-checks` release compatible with the Rust toolchain.
The first stable release deliberately changes the pre-1.0 scanner API; review the
[migration notes](LIBRARY.md#migrating-from-the-01-api) before publishing.
CI compares PRs against their base revision so later changes cannot silently break
unchanged major versions. A passing static check does not replace behavior tests,
Windows x64/arm64 verification, or review of public dependency types and MSRV.

## Independent library releases

Do not bump every library just because the CLI is releasing. Keep an unchanged
library's version and dependency requirements unchanged. A crate version is immutable;
changed crates need a new version, rather than overwriting a previous release.

Examples:

- CLI-only implementation change: bump `kingfisher-bin`; keep all library versions.
- Scanner fix: bump `kingfisher-scanner`'s patch version and update the CLI's minimum
  scanner requirement so its published build receives the fix.
- Rule catalog or rules API change: bump `kingfisher-rules`. Update its dependents'
  requirements where they need the new behavior, and bump those packages too.
- Core API change: update core and any dependents requiring it; incompatible changes
  require a major version, according to the [stable API contract](LIBRARY.md#api-stability).

The [publication planner](../scripts/publish-crates.py) compares each locally packaged
version to the same crates.io version. Identical releases are skipped. Changed
packaged files with an already-published version stop the entire plan **before any
uploads** and identify the files requiring a version bump. New versions are explicit
maintainer decisions; the workflow never chooses or edits version numbers.

Comparison ignores Cargo's checkout metadata and original, unnormalized manifest.
For libraries, it also ignores `Cargo.lock`, since embedding projects resolve their
own dependencies. Normalized manifests, dependency requirements, examples, source,
README, licenses, and the embedded catalog are compared.

For `kingfisher-rules`, only the provenance hashes of the workspace root `Cargo.toml`
and `Cargo.lock` are ignored: a CLI-only version bump changes those hashes without
changing the published library or catalog. All other provenance and catalog content
is checked. A skipped rules release retains its original published provenance;
the GitHub release archive records the current workspace provenance. This avoids
forcing a new rules release for every CLI release.

## GitHub Actions setup

Publishing runs in the `publish-crates` job of
[`.github/workflows/release.yml`](../.github/workflows/release.yml), in the
`mongodb/kingfisher` repository, using the `crates-io` GitHub environment.
It follows the existing release triggers (main pushes, published releases, and manual
dispatch). The release tag must be `v<kingfisher-bin version>` and point to the exact
commit tested by the parent workflow. A stale tag pointing elsewhere stops publication.
Concurrent publish jobs are serialized and never canceled halfway through an upload.

### First publication

crates.io currently requires an API token for the first publication of a crate;
Trusted Publishing applies once the crate exists. See the
[crates.io Trusted Publishing guide](https://crates.io/docs/trusted-publishing).

1. An authorized publisher creates a crates.io API token with permission to publish
   `kingfisher-core`, `kingfisher-rules`, `kingfisher-scanner`, and `kingfisher-bin`,
   including creation of crate names that do not exist yet.
2. Add it to the public repository's `crates-io` environment (or repository secrets)
   as **`CARGO_REGISTRY_TOKEN`**. Do not put it in a workflow file or commit it.
3. Run the normal release workflow after the changes and intended versions are committed.
   The job prefers this token when present. It packages/verifies and computes the
   release plan before using publishing credentials.

### Subsequent publications using OIDC

For **each of the four crates**, an owner configures crates.io Settings → Trusted
Publishing with:

| Setting | Value |
| ------- | ----- |
| Repository owner | `mongodb` |
| Repository name | `kingfisher` |
| Workflow filename | `release.yml` |
| Environment | `crates-io` |

Then remove the bootstrap `CARGO_REGISTRY_TOKEN` secret. The job uses the pinned
[`crates-io-auth-action`](https://github.com/rust-lang/crates-io-auth-action) to obtain
a short-lived token. The job has `id-token: write`; unrelated jobs do not receive its
authentication token. No token is requested when every version is already published.
Authentication still requires this crates.io-side configuration; committing workflow
YAML cannot grant ownership of crate names or configure their trusted publishers.

### Publication sequence and recovery

The job verifies extracted packages, checks all four versions for conflicts, and then
publishes missing versions in this order:

1. `kingfisher-core`
2. `kingfisher-rules`
3. `kingfisher-scanner`
4. `kingfisher-bin`

Each upload uses `cargo publish --locked --registry crates-io` with package verification
enabled. The script waits for the exact dependency version to become visible in the
sparse registry index before advancing. Registry errors and yanked versions fail the
job rather than being mistaken for unpublished versions. Downloaded comparison archives
are checked against the registry's SHA-256 checksum.

If an upload or index wait fails, rerun the workflow: matching versions already uploaded
are skipped, and publication resumes with the missing ones. The job cannot roll back
versions already published to crates.io. A failed publication is never silently accepted.

## Local verification and manual publishing

Python 3.11+ is required for the publishing helper. To inspect the release plan without
publishing, first create fresh archives:

```sh
cargo package --locked --workspace --exclude kingfisher-rule-bundle
python3 scripts/publish-crates.py --tag v2.9.0
python3 -m unittest discover -s scripts/tests -v
```

Use `--allow-dirty` on the packaging command only for local pre-commit verification;
the CI publishing job requires a clean checkout. The planner reads the archives in
Cargo's configured target directory; always rebuild them after source changes.

An authorized publisher can use the same script with `--publish` and a securely supplied
`CARGO_REGISTRY_TOKEN`, or run the four `cargo publish -p <package>` commands manually
in dependency order. Finally, verify
`cargo install --locked kingfisher-bin --version <published-version>` in a fresh environment.
Repository changes and local planning do not themselves publish anything.
