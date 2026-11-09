# Publishing Cargo and npm packages

[← Back to README](../README.md)

The root Cargo package is `kingfisher-bin`; its executable and Rust library retain the name
`kingfisher`. The `kingfisher` crates.io name belongs to another project. The reusable library packages
are `kingfisher-core`, `kingfisher-rules`, and `kingfisher-scanner`. The maintainer-only
`kingfisher-rule-bundle` package is never published. The `kingfisher-python` binding
crate is packaged by Maturin for the separate Python SDK release, not crates.io.
The `kingfisher-node` binding crate is also private to its independently versioned
JavaScript/TypeScript npm SDK; see [npm publishing with GitHub Actions](#npm-publishing-with-github-actions).

Native Linux RPM and DEB packages use the system package name `kingfisher`; do not derive
it from the Cargo or PyPI package name. Keep the RPM compatibility metadata for previously
misnamed packages. See
[Linux package installation](INSTALLATION.md#linux-packages-rpm-and-deb)
and the [maintainer package checks](../.github/RELEASING.md#finish-and-recover).

## Package versions and consumers

The manifests currently prepare these releases; a Git tag does not override Cargo versions:

| Package | Version | Published targets |
| ------- | ------- | ----------------- |
| `kingfisher-core` | `1.0.6` | `kingfisher_core` library |
| `kingfisher-rules` | `3.2.0` | `kingfisher_rules` library |
| `kingfisher-scanner` | `3.0.3` | `kingfisher_scanner` library |
| `kingfisher-bin` | `2.18.1` | `kingfisher` executable and library |

The Python SDK (`kingfisher-secret-scanner`) is independently versioned at
`1.6.3` in `crates/kingfisher-python/Cargo.toml`; Python modules share that version.
The stable npm SDK uses **1.0.0** in `crates/kingfisher-node/Cargo.toml` and
`javascript/package.json`, with six same-version native packages. Its `npm-v*`
release tags do not publish the CLI or Python SDK.

The libraries follow semantic versioning and do not inherit the CLI version.
Rules/scanner 3.0.0 add public Rust schema fields and Expr variants; upgrade both
crates together. Existing YAML/TOML files remain compatible. Core 1.0.6 refreshes
dependency minimums without changing its public API. Python SDK 1.6.0 adds
compatible APIs for explicit analysis and source attributes. Rules/scanner 3.0.1
and Python SDK 1.6.1 include the private-key detection fixes. Rules 3.1.0 adds public
literal expression-input discovery and credential-specific revocation overlays without changing
existing YAML/TOML or primary-action behavior. Rules 3.2.0 and scanner 3.0.3 optimize
fallback matching and filter evaluation, and include the static-low generic API-key detector.
Rules 3.2.0 also deprecates the legacy effective-confidence helpers; new compiler deprecation
warnings require a minor release. Scanner 3.0.3 and Python SDK 1.6.3 remain compatible
patch releases with those shared-engine fixes; core 1.0.6 is unchanged.
Scanner 3.0.2 and Python SDK 1.6.2 include the shared identity-response reporting fix;
high-level SDK results still omit provider responses. Public signatures are unchanged,
but strict budgeted TAR/ZIP/ASAR expansion now rejects malformed/unsafe members or
staging errors for the whole root. Legacy best-effort CLI defaults are unchanged.
See the [3.0 migration guide](LIBRARY.md#migrating-to-rules-and-scanner-30).
`kingfisher-rule-bundle` is `0.1.0` with `publish = false`. The external
`kingfisher-vectorscan` dependency is versioned separately.
The binding and sys crate are now pinned to published **0.1.4**, including
MSVC x64/ARM64 archives with a VS 2022 / MSVC 14.44 STL/CRT baseline. The compiled-rule
cache identity includes both exact versions, so older engine-build entries cannot be
reused silently.

Native CI jobs stage the same pinned archive through GitHub's release asset API,
which remains usable when browser download URLs return gateway errors. The fetcher
reads SHA-256 pins from the immutable Cargo registry sys crate, not mutable release
metadata; the sys build script verifies them again. To use the same path locally:

```sh
python3 scripts/fetch-vectorscan.py
export VECTORSCAN_PREBUILT_DIR="$PWD/target/vectorscan-prebuilt"
```

Pass `--target <Rust-target-triple>` for cross builds. The Docker-based Linux
Makefile targets mount this directory read-only; source builds remain explicit.

After publishing, consumers can install the CLI with:

```sh
cargo install --locked kingfisher-bin --version 2.18.1
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
  source/license contents; binary sources use a `base64:` prefix. A null value records an optional NOTICE absent at that revision.
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
cargo test --locked -p kingfisher-bin --test smoke_check_rules
make check-notices
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

Before compatible releases, compare each library against its last published version
in the same major, both without optional features and with all features. Baselines
are independent: after the releases above are published, for example:

```sh
for feature_set in --only-explicit-features --all-features; do
  cargo semver-checks -p kingfisher-core --baseline-version 1.0.3 "$feature_set"
  cargo semver-checks -p kingfisher-rules --baseline-version 2.0.0 "$feature_set"
  cargo semver-checks -p kingfisher-scanner --baseline-version 2.0.0 "$feature_set"
done
```

Use an installed `cargo-semver-checks` release compatible with the Rust toolchain.
For the rules/scanner 3.0.0 release, review the intentional break against
the published 2.0.0 releases and the [3.0 migration notes](LIBRARY.md#migrating-to-rules-and-scanner-30);
do not treat a major bump as permission for unrelated breaks. The historical
[pre-1.0 migration](LIBRARY.md#migrating-from-the-01-api) remains documented.
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
It follows version-tag pushes and manual dispatch on a tag. The workflow builds and tests,
uploads assets to a draft GitHub release, and publishes it before starting downstream
package publication. See the [maintainer release checklist](../.github/RELEASING.md).
The release tag must be `v<kingfisher-bin version>` and point to the exact
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

If an upload or index wait fails, rerun the failed publishing job in the original run:
matching versions already uploaded are skipped, and publication resumes with the missing
ones. The job cannot roll back versions already published to crates.io. A failed
publication is never silently accepted.

### Metadata-only correction after a successful binary release

An already-published crate version cannot be reused after its packaged source changes.
Bump the affected crate and its dependent minimum requirements; do not disable the
publication planner or move the existing public release tag.

When the GitHub release, binaries, Docker image and Python wheels already succeeded,
a crates-only recovery does not rebuild or replace those artifacts. Merge the version,
lockfile, provenance and documentation corrections into `main`, then dispatch:

```sh
gh workflow run release.yml --repo mongodb/kingfisher --ref main \
  -f crates_only=true -f release_run_id=40610865292 \
  -f expected_sha="$(git rev-parse HEAD)"
```

Use the original binary release's run ID. The recovery gate requires its successful
build/test/release jobs, verifies the public tag, and rejects runtime source, dependency,
feature or catalog changes. Only the core patch version and corresponding dependency,
lockfile and provenance metadata may change. Regenerated root manifest, lockfile and
rules-manifest hashes must match their committed files; all other provenance stays
unchanged. The independent SDK version correction
from 1.4.0 to 1.5.0 and its matching lockfile entry are also allowed. Library tests and all four extracted-crate
build checks still run before authentication and publication. The ordinary release
path retains its exact tag/commit guards. A runtime change needs a new binary release.

The Python SDK preflight reuses the same strict metadata check, so a verified core
version/dependency-metadata correction does not require another SDK release. Actual
SDK/shared runtime or unrelated dependency changes still require a new SDK version.

The original failed run uses its original commit and remains historical; rerunning it
cannot pick up a later metadata correction. The new recovery run publishes the missing
crate versions without retagging `v2.15.0` or republishing its assets.

## npm publishing with GitHub Actions

The npm SDK publishes through [`.github/workflows/node-sdk.yml`](../.github/workflows/node-sdk.yml),
not the Cargo release workflow. It uses **Trusted Publishing (OIDC)**: GitHub supplies
a short-lived identity, so no `NPM_TOKEN` or `NODE_AUTH_TOKEN` publishing secret is needed.
Account ownership, GitHub environment protection and npm trust must be configured by
an authorized maintainer; committing workflow YAML does not configure them.

### One-time setup

1. Review and merge the SDK and workflow into public **`mongodb/kingfisher` `main`**.
   The npm manifests' `repository.url` must match `https://github.com/mongodb/kingfisher.git`.
2. In GitHub **Settings → Environments**, create an environment named exactly **`npm`**.
   Add required reviewers (and **Prevent self-review** if required). Under deployment
   branches/tags, allow the **tag** pattern `npm-v*`; a `main`-only branch rule blocks
   tag releases. Do not add an npm write-token secret.
3. In **Actions → Node SDK → Run workflow**, select `main`. This is a non-publishing
   dry run. Require all six native artifact builds, package staging and the separate
   sealed-tarball verification matrix to pass before configuring npm trust or creating a release tag.
4. Sign into the intended npm owner account, verify its email, enable **account-level
   2FA**, and confirm write access to all seven packages below. npm trust requires an
   existing package entry. Handle absent names in a separately authorized npm
   ownership/bootstrap setup, not an SDK release. Any dummy bootstrap stages must
   remain unapproved and must not publish SDK `1.0.0`.
   **Never approve the dummy bootstrap stages**; skip names already owned.
5. For **each package**, open npmjs.com → package → **Settings → Trusted publishing**,
   select **GitHub Actions**, and save these exact values:

   | npm setting | Value |
   | ----------- | ----- |
   | Organization or user | `mongodb` |
   | Repository | `kingfisher` |
   | Workflow filename | `node-sdk.yml` (filename only, not `.github/workflows/node-sdk.yml`) |
   | Environment name | `npm` |
   | Allowed actions | Explicitly enable **Allow npm publish** |

   New connections default to staging permission; this workflow uses direct
   `npm publish`, so staging-only permission is insufficient. Complete the first
   successful OIDC publication within **48 hours** of creating each connection.
   If it expires, delete only that expired connection and recreate it.

Configure trust on **all seven packages**, not only the main SDK:

- `kingfisher-secret-scanner`
- `kingfisher-secret-scanner-darwin-x64`
- `kingfisher-secret-scanner-darwin-arm64`
- `kingfisher-secret-scanner-linux-x64-gnu`
- `kingfisher-secret-scanner-linux-arm64-gnu`
- `kingfisher-secret-scanner-win32-x64-msvc`
- `kingfisher-secret-scanner-win32-arm64-msvc`

The `core`, `rules`, `scanner`, `inputs`, `git`, `validation` and `revocation` imports
are subpaths of the main package, not separate package names. The npm owning account
is independent of the GitHub organization name.

### Publish and verify

The publication job runs on a **GitHub-hosted runner**, uses Node **24.22.2**
and npm **11.21.1**, and grants `id-token: write` only to that job. Use those
exact publisher pins for local publishing setup as well; consumer runtime support
is separate. Self-hosted publishers are unsupported.

For the initial SDK release, use a clean, current, reviewed upstream `main` checkout.
Confirm `origin` points to `mongodb/kingfisher`, not a private development remote,
the SDK version is `1.0.0`, and `npm-v1.0.0` does not already exist before explicitly
authorizing publication:

```sh
make release npm
```

The six native build jobs produce platform artifacts; staging then seals seven
packages. A **separate verification matrix** tests those tarballs on all six hosts
under Node **22.13.0, 22.23.4, 24.0.0, 24.22.2, 26.0.0 and 26.13.0**. Support is
limited to majors **22/24/26** (`^22.13.0 || ^24.0.0 || ^26.0.0`), including a
tested Node 22.13.0 minimum. Wait for all checks before approving the protected
**`npm`** deployment. `npm run pack:release` creates the tarballs and a SHA-512
integrity manifest once, before verification. The publisher uploads those exact tested
`javascript/release/archives/*.tgz` files, native packages first and the main SDK last;
consumer checks and publication never repack. Branch/PR/manual dry runs do not publish;
CLI `v*` and Python `python-v*` tags are unrelated. Never upload the private development
manifests or move an existing public tag.

Verify all seven exact versions, npm provenance, and a fresh consumer installation
with `npm audit signatures`.
After OIDC succeeds, set **Settings → Publishing access → Require two-factor
authentication and disallow tokens** on every package, revoke obsolete automation
tokens, and reject only the unused dummy bootstrap stages. OIDC remains allowed.

Later releases use `npm-v<SDK-version>` after synchronizing the Node/npm manifests
and lockfiles. Stable releases use `latest`; if any package already has a newer
`latest`, the release instead uses `backport-<major>.<minor>` without downgrading
that tag. Prereleases use `next`. For partial failures, rerun only the failed
publishing job in the original run to reuse the **same tested artifact**, including
its archive manifest; identical published packages are skipped, conflicting bytes fail.
See the [maintainer release procedure](../.github/RELEASING.md) and
[npm Trusted Publishing guide](https://docs.npmjs.com/trusted-publishers/).

## Independent terminal commands

```sh
make release crates
make release kingfisher-secret-scanner
make release npm
```

The first command infers all four crates.io versions, checks the complete publication
plan, and discovers the original passing CLI release run for a failed-job retry or
metadata-only recovery. The second infers the Python SDK version from
`crates/kingfisher-python/Cargo.toml` and starts its tested publishing workflow.
The third infers the independent Node SDK version from `javascript/package.json`,
validates the matching native manifests/lockfiles, and pushes an annotated
`npm-v<SDK-version>` tag. CI builds/verifies all packages before the protected `npm`
deployment approval permits publication. Existing remote npm tags are rejected;
retry the original run's failed job instead. A failed tag push can reuse an annotated
local tag at the same commit.
None changes versions or accepts `VERSION`; commit and merge the intended version
correction first. The full binary-release command remains `make release VERSION=X.Y.Z`.
Use `RELEASE_REMOTE=upstream` when that named remote points to public `mongodb/kingfisher`.

The launcher requires a clean reviewed upstream checkout, authenticated GitHub access,
current merged `main`, and a supported active workflow. It pins the expected SHA.
Python/crates check registries before dispatch; npm registry/integrity checks remain
in CI, not the local tag command. A published Python SDK version, a conflicting crate payload,
an all-published crates plan, invalid source history, or a registry lookup error stops the
command instead of starting a doomed build. Identical unchanged crate dependencies can
still be skipped. Full extracted-package checks and the original protected publication
guards remain enabled in CI. External Trusted Publisher/token configuration and future
network availability cannot be proven by read-only preflight; publish jobs still enforce
them. See the [terminal release runbook](../.github/RELEASING.md#independent-package-releases).

## Local verification and manual publishing

Python 3.11+ is required for the publishing helper. To inspect the release plan without
publishing, first create fresh archives:

```sh
cargo package --locked -p kingfisher-core -p kingfisher-rules -p kingfisher-scanner -p kingfisher-bin
python3 scripts/publish-crates.py --tag v2.18.1
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
