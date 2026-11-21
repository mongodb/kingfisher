# Publishing Cargo, PyPI and npm packages

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
| `kingfisher-core` | `2.1.0` | `kingfisher_core` library |
| `kingfisher-rules` | `3.3.0` | `kingfisher_rules` library |
| `kingfisher-scanner` | `4.1.0` | `kingfisher_scanner` library |
| `kingfisher-bin` | `2.20.0` | `kingfisher` executable and library |

The Python SDK (`kingfisher-secret-scanner`) is independently versioned at
`1.6.4` in `crates/kingfisher-python/Cargo.toml`; Python modules share that version.
The stable npm SDK uses **1.0.2** in `crates/kingfisher-node/Cargo.toml` and
`javascript/package.json`, with six same-version native packages. Versions remain
independent, but release triggers share the coordinated build gate below.

The libraries follow semantic versioning and do not inherit the CLI version.
Rules 3.3.0 and scanner 4.1.0 add opt-in cryptographic custom-rule helpers,
including ECDH, ECDSA, AES-GCM, key derivation, and Ed25519; CLI 2.20.0 embeds
them. Existing YAML/TOML rules and SDK call signatures remain compatible. Core
is unchanged and remains at 2.0.0.

Core 2.0.0 and scanner 4.0.0 migrate public Git types to `gix` 0.90;
scanner 4.0.0 also exposes `jsonwebtoken` 12 decoding keys under `validation`. The root
package follows CLI version 2.19.1 and also replaces the public `gouqi` Jira models
with local DTOs. Consumers of its application library must migrate those types. These
are Rust source/type migrations: existing Kingfisher YAML, Betterleaks TOML, CLI
behavior, and Python/npm runtime APIs remain compatible. Rules 3.2.1 updates
private dependencies without a public Rust API break; its generic YAML loader
still returns `anyhow::Result`. See the
[dependency modernization migration](LIBRARY.md#dependency-modernization-migration),
including the parser-source note for callers that explicitly downcast errors.

Earlier releases established these separate contracts:
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
cargo install --locked kingfisher-bin --version 2.19.1
```

This installs the `kingfisher` command. See [library usage](LIBRARY.md#quick-start)
for registry dependency examples. All four packages require Rust 1.99 or newer.
The [release workflow](../.github/workflows/release.yml) publishes missing crate versions
only in `mongodb/kingfisher`; forks and the private development mirror do not publish.

## Coordinated release gate

Upstream main pushes and matching CLI/Python/npm version tags run a single cohort at
one pinned SHA. **Every** normal platform test and binary build, all four extracted
Cargo package checks and the read-only registry plan, Python SDK wheels/sdist/cache
tests, npm native builds and sealed-package tests, and six CLI PyPI wheel builds must
succeed before any registry upload. Already-published unchanged SDKs still run their
build/test matrices; their uploads are skipped. Failure, cancellation, or a skipped
required build closes the gate for every publisher. Preparation jobs do not authenticate
to registries. Reusable Python SDK and CLI-wheel workflows are build-only with no
OIDC permission; their actual post-gate PyPI upload jobs run directly in `release.yml`
and explicitly enable attestations. PyPI's `id-token: write` permission is confined
to those direct upload jobs.

Main and SDK-tag runs publish pending crates and Python SDK versions, not just the
package named by the tag. **npm remains tag-only:** its handoff requires an existing
`npm-v<committed SDK version>` tag pointing to the producer's exact SHA. If that tag is
missing or points elsewhere, main/CLI/Python runs skip npm without blocking other
registries; the npm tag's own coordinator cohort can publish it. CI never creates or
moves tags. Only CLI `v*` runs also publish a GitHub release, Docker image and CLI PyPI
distribution; these wait for the shared gate and successful GitHub asset uploads.
Manual CLI-tag dispatch retains the same gates. A manual main publication requires
`publish=true`, a full pinned `expected_sha`, and the Python SDK `expected_version`.
Ordinary standalone SDK, CLI-wheel and Docker dispatches build/test only; the internal
Node publish dispatch must validate its authorizing coordinator run and artifacts.

npm and PyPI upload their staged, tested archives without rebuilding them. Cargo
rechecks the staged archive plan, then `cargo publish --locked` packages and verifies
the same pinned source in dependency order. Cross-registry uploads are **not atomic**:
a registry outage or authorization failure after the gate can leave a partial release.
Retry transient publisher failures with the original tested artifacts, following the
[npm handoff recovery rules](#npm-handoff-recovery) or
[artifact-only SDK recovery rules](PYPI.md#artifact-only-sdk-recovery) as applicable.
A later workflow fix does not update an old run's snapshot. Immutable-version checks
remain enabled. When crates are already published but the CLI/npm release tags are
still absent, follow the [prepared-release, no-version-bump sequence](../.github/RELEASING.md#complete-the-prepared-releases-without-version-bumps):
finish the normal CLI cohort first, then the npm cohort at the same reviewed main SHA,
not crates-only recovery.

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
From a clean checkout of the selected commit, build verified archives and inspect the
read-only registry plan:

```sh
python3 scripts/publish-crates.py --package
cargo test --locked -p kingfisher-bin --test smoke_check_rules
make check-notices
```

The helper runs `cargo package --locked` with verification enabled: published members
are packaged individually against real registry dependencies; unpublished members are
packaged together. A batch containing already-published members would substitute fresh
archive checksums into the CLI lockfile, even when only Git bookkeeping changed.
The strict published CLI lockfile comparison remains enabled.

Use `--allow-dirty` only for direct Cargo pre-commit checks, never in CI. Inspect the `.crate` archives in
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
  cargo semver-checks -p kingfisher-core --baseline-version 2.0.0 "$feature_set"
  cargo semver-checks -p kingfisher-rules --baseline-version 3.2.1 "$feature_set"
  cargo semver-checks -p kingfisher-scanner --baseline-version 4.0.0 "$feature_set"
done
```

Use an installed `cargo-semver-checks` release compatible with the Rust toolchain.
Before the releases above are published, compare core against 1.0.6, rules against
3.2.0, and scanner against 3.0.3. Review the intentional core/scanner dependency-type
breaks and the root library's changes against `kingfisher-bin` 2.18.1 using the
[dependency migration notes](LIBRARY.md#dependency-modernization-migration).
Rules 3.2.1 must remain compatible with its published 3.2.0 baseline.
For the earlier rules/scanner 3.0.0 release, the intentional break was against
the published 2.0.0 releases; retain the [3.0 migration notes](LIBRARY.md#migrating-to-rules-and-scanner-30).
Do not treat a major bump as permission for unrelated breaks. The historical
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
It follows main pushes, matching CLI/SDK tag pushes, and guarded manual dispatch,
always after the complete coordinated gate. CLI-tag runs upload assets to a draft
GitHub release and publish it before starting downstream package publication.
See the [maintainer release checklist](../.github/RELEASING.md).
A CLI release tag must be `v<kingfisher-bin version>` and point to the exact
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
a crates-only recovery keeps those public artifacts unchanged. It reruns the current
complete binary/SDK/package build gate before uploading only crates. Merge the version,
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

## PyPI publishing and artifact-only SDK recovery

Both PyPI publishers are ordinary upload jobs directly in the
[release coordinator](../.github/workflows/release.yml), with explicit
`attestations: true`. Reusable `python-sdk.yml` and `pypi.yml` workflows only
build/test/prepare artifacts and receive no OIDC permission. Normal publication
retains the complete cohort gate, pinned source checks, tested artifact handoff,
publication concurrency, and the SDK's protected `pypi-sdk` environment.
PyPI [does not support reusable workflows as Trusted Publishers](https://docs.pypi.org/trusted-publishers/troubleshooting/#reusable-workflows-on-github);
same-repository/same-ref calls do not remove that limitation.

An authorized PyPI project owner must **add** matching GitHub Trusted Publishers:

| PyPI project | Owner / repository | Workflow filename | Environment |
| --- | --- | --- | --- |
| `kingfisher-secret-scanner` | `mongodb` / `kingfisher` | `release.yml` | `pypi-sdk` |
| `kingfisher-bin` | `mongodb` / `kingfisher` | `release.yml` | **None — leave empty** |

Keep the old `python-sdk.yml` / `pypi-sdk` and `pypi.yml` / no-environment records
until the new flow is verified; later removal is optional. Keep existing GitHub
environment rules/reviewers unchanged. YAML changes cannot configure PyPI accounts,
and read-only validation cannot prove successful live publication. See the
[complete PyPI setup](PYPI.md#configure-pypi-trusted-publishers).

When an old SDK upload failed because its reusable-workflow OIDC identity differed
from its attestation identity, neither PyPI-only configuration changes nor rerunning
that old workflow snapshot repairs it. After the fix is merged and matching trust is
added, `release.yml` offers manually opted-in `sdk_only=true` recovery with
`publish=true`. It verifies the original complete passing cohort and SDK
wheel/sdist/portability tests and plan, then publishes only the retained original
SDK artifact. Recovery itself does not rebuild Rust, wheels or binaries or publish
other packages; merging the repair still triggers ordinary automatic full-cohort CI
on `main`. SDK-only dispatch shares main-run concurrency and waits behind that run.
For original-artifact recovery, stop **only the new automatic main run before it
builds/publishes**, then dispatch `sdk_only`. Never cancel/rerun the pinned original
failed producer or let a new ordinary build publish different bytes under the same
SDK version first. Do not disable Actions, change account/branch policies or weaken
gates.

The operator pins **both** the original producer (`release_run_id`, verified
`release_run_attempt`, immutable pending `artifact_id`, `producer_sha` and original
`expected_version`) **and** the current reviewed recovery workflow (`expected_sha`
on clean current upstream `main`). Both explicit pins are required: their roles
are distinct, but their values may match when current `main` is unchanged.
The producer must be an ancestor of current reviewed `main` with the same SDK
manifest version. Allowed drift is limited to the three publication workflows,
maintainer release runbook, recovery validator,
[release-source authorization guard](../scripts/check-release-source.py),
[crate publication/staging helper](../scripts/publish-crates.py), allowlisted CI test
scripts and Markdown docs/generated docs; SDK/runtime/manifests/locks/rules/other build inputs
cannot change. The validator requires latest-effective successful gates/tests/plan
(no older success behind a newer failure), artifact API proof of the upstream
repository/run/SHA and creation within the selected successful SDK plan job, digest,
retention/expiry and exact distributions. It rechecks after protected approval and
does not check out the producer under the new workflow identity. After upload, every
staged filename and exact SHA-256 must match PyPI, with bounded read-only visibility
retries; `skip-existing` cannot conceal a concurrent different-byte upload. Missing or
expired artifacts fail closed; never substitute a new build under an immutable
version. No SDK bump is needed solely for CI-only changes if no files were published;
a partial upload must recover the exact original artifacts. Follow the
[artifact-only SDK recovery procedure and pinned dispatch example](PYPI.md#artifact-only-sdk-recovery),
not a new ordinary full-build publication.

## npm publishing with GitHub Actions

The [release coordinator](../.github/workflows/release.yml) reuses the build/test phase
of [the Node SDK workflow](../.github/workflows/node-sdk.yml), but npm uploads run only
in the **original top-level `node-sdk.yml`** workflow. After the complete shared gate,
the coordinator dispatches that workflow at an **existing `npm-v<committed SDK version>`
tag at the same SHA** and waits for its exact returned run ID. No CI job creates or
moves tags. Missing/different-SHA npm tags skip the npm handoff on main/CLI/Python
triggers; other registries proceed, and the npm tag's own coordinator cohort can publish it.

**Trusted Publishing (OIDC)** retains the existing `node-sdk.yml` / `npm` identity,
`npm-v*`-only environment and reviewer. **No existing npmjs account, Trusted Publisher
connection, or publishing-access changes are needed.** Do not add a `release.yml` npm
connection or widen `npm` to `main`, `v*`, or `python-v*`. No `NPM_TOKEN` or
`NODE_AUTH_TOKEN` publishing secret is needed. PRs, development/fork pushes and ordinary
manual SDK runs only test; only the validated internal coordinator handoff can publish.

### One-time setup (new installations only)

1. Review and merge the SDK and workflow into public **`mongodb/kingfisher` `main`**.
   The npm manifests' `repository.url` must match `https://github.com/mongodb/kingfisher.git`.
2. In GitHub **Settings → Environments**, create an environment named exactly **`npm`**.
   Add required reviewers (and **Prevent self-review** if required). Under deployment
   branches/tags, allow the **tag pattern `npm-v*` only**, not `main`, `v*` or `python-v*`.
   Existing installations keep their current tag-only rule and reviewer unchanged.
   Do not add an npm write-token secret.
3. In **Actions → Node SDK → Run workflow**, select `main`. This is a non-publishing
   dry run. Require all six native artifact builds, package staging and the separate
   sealed-tarball verification matrix to pass before configuring npm trust or creating a release tag.
4. Sign into the intended npm owner account, verify its email, enable **account-level
   2FA**, and confirm write access to all seven packages below. npm trust requires an
   existing package entry. Handle absent names in a separately authorized npm
   ownership/bootstrap setup, not an SDK release. Any dummy bootstrap stages must
   remain unapproved and must not publish SDK `1.0.0` or any later SDK release.
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

The npm publisher is a separate top-level run, not a reusable publish call from
`release.yml`, preserving npm's original OIDC identity. PyPI uploads instead run
directly in `release.yml`: SDK with `pypi-sdk`, CLI wheels with **no environment**.
Their [new PyPI publisher records](#pypi-publishing-and-artifact-only-sdk-recovery)
must be added manually. Crates retain `release.yml` / `crates-io`.

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
and npm **11.21.1**, and receives `id-token: write` only in the original Node SDK
publisher. The parent dispatcher uses `contents: read` / `actions: write`, not npm
OIDC or tag-write permission. Build runners remain read-only. Use those exact
publisher pins for local publishing setup as well; consumer runtime support is
separate. Self-hosted publishers are unsupported.

The prepared SDK version is **1.0.2**. Synchronize the Node crate, all seven npm
manifests, `Cargo.lock` and `javascript/package-lock.json`, then regenerate rule
provenance after lockfile changes. Merge the reviewed version bump into upstream
`main`. **An npm release tag is required**; merging alone does not authorize npm
publication. From a clean, reviewed current upstream `main` checkout, and only
after separate authorization to create and push the new annotated tag, run:

```sh
make release npm
```

The command validates the matching manifests/lockfiles and pushes
`npm-v<SDK-version>` as before. Its tag-triggered coordinator run tests the full
same-SHA cohort before dispatching the protected Node publisher. A main/CLI/Python
producer can hand off only when that exact npm tag already exists at its SHA. Confirm
`origin` points to `mongodb/kingfisher`, not a private development remote; use
`RELEASE_REMOTE=upstream` when that is the public remote's name.

Before native builds, a read-only preflight validates committed manifests/locks,
checks npm, and verifies publication source ancestry against fresh upstream `main`.
Changed packaged/shared-runtime inputs cannot reuse an already-published SDK
version: bump the SDK before merging, including for shared engine changes. An
unchanged version already on npm skips upload, but its full native and sealed-tarball
test matrix still gates the other coordinated releases, even without a matching npm
tag. Unchanged means comparison against the exact source recorded in npm's published
provenance, not just the previous push, so successful-release reruns skip uploads and
later unrelated pushes cannot hide unreleased changes. Missing/invalid source
provenance and registry lookup failures fail closed; prepare a new SDK version rather
than guessing a baseline. Publication is serialized across versions with GitHub's
[`queue: max` concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
(up to 100 pending jobs), preventing `latest` races without replacing an earlier
pending release.

Keep existing `npm-v1.0.0` and `npm-v1.0.1` tags unchanged: rerunning an old workflow
uses its original commit, not updated `main`. Changed release inputs require a new
SDK version; never rebuild different bytes under an already-published version.

The six native build jobs produce platform artifacts; staging then seals seven
packages. A **separate verification matrix** tests those tarballs on all six hosts
under Node **22.13.0, 22.23.4, 24.0.0, 24.22.2, 26.0.0 and 26.13.0**. Support is
limited to majors **22/24/26** (`^22.13.0 || ^24.0.0 || ^26.0.0`), including a
tested Node 22.13.0 minimum. `npm run pack:release` creates the tarballs and a SHA-512
integrity manifest once, before verification.

After **Release build gate** and **Authorize the complete release cohort** succeed,
the parent uses [`scripts/dispatch-node-sdk.py`](../scripts/dispatch-node-sdk.py)
to dispatch the original Node SDK workflow at the existing same-SHA npm tag and
wait for the **exact returned run ID**, not a latest/name-matched run. The internal
handoff supplies the producer run ID/`run_attempt`, full expected SHA and immutable
staging artifact ID. Before entering the `npm` environment, and **again after its
protected approval**, the Node child verifies:

- The producer is the original upstream `release.yml` workflow/repository/run/attempt
  at this SHA, with successful **Release build gate** and **Authorize the complete
  release cohort** jobs.
- The intended npm dispatcher is running or successful and its parent run has not
  failed, been cancelled, or timed out.
- The exact staging artifact ID and metadata belong to that producer run/SHA and
  identify the unexpired `node-sdk-registry-staging` artifact.
- The original top-level Node workflow runs at `npm-v<committed SDK version>` with
  matching manifests, the remote tag still points to that same SHA, and the source
  is an ancestor of freshly fetched upstream `main`.

Only then does it download the sealed archives **cross-run by validated artifact
ID**. Wait for all checks before approving the protected **`npm`** deployment. The
publisher uploads the exact tested `javascript/release/archives/*.tgz` files,
native packages first and the main SDK last; no child rebuild, repack or alternate
artifact lookup is allowed. Ordinary standalone manual/build runs and
PR/development/fork runs do not publish. Never upload the private development
manifests or move an existing public tag.

Verify all seven exact versions, npm provenance, and a fresh consumer installation
with `npm audit signatures`. Existing npmjs connections and publishing-access settings
stay unchanged. Stable releases use `latest`; if any package already has a newer
`latest`, the release instead uses `backport-<major>.<minor>` without downgrading that
tag. Prereleases use `next`.

### npm handoff recovery

Recover partial uploads with the **same producer artifacts**, including their archive
manifest; identical published packages are skipped and conflicting bytes fail. A failed
Node child can be retried only while its authorizing parent run and intended npm
dispatcher remain active or successful. Failed, cancelled, or timed-out parents reject
stale children, including children waiting for protected approval.

If that authorization no longer holds, rerun the **original central release run's failed
npm handoff job**. It may dispatch a new Node child using the same tested producer
artifacts and current producer-attempt authorization. Gates omitted from a
[failed-job rerun](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs)
retain their most recent result: that result must be successful, and the dispatcher must
be running/successful in the current attempt. A newer failed/skipped/pending gate cannot
fall back to an older success. Do not assume rerunning an old npm child after its parent
failed will work. Keep the existing tag/SHA; do not create or
move a tag, rebuild/repack an existing version, or start an independent manual publish.
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
The third retains the required npm tag flow: it infers the independent Node SDK version
from `javascript/package.json`, validates the matching native manifests/lockfiles, and
pushes an annotated `npm-v<SDK-version>` tag. CI builds/verifies the complete cohort
before the validated Node handoff and protected `npm` deployment permit publication.
Existing remote npm tags are rejected; follow the [handoff recovery rules](#npm-handoff-recovery)
instead. A failed tag push can reuse an annotated local tag at the same commit.
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

Python 3.11+ is required for the publishing helper. From a clean checkout containing
only tracked inputs, build fresh verified archives and inspect the plan without publishing:

```sh
python3 scripts/publish-crates.py --package --tag v2.19.1
python3 -m unittest discover -s scripts/tests -v
```

`--package` cannot be combined with `--publish`; it preserves Cargo verification and
strict immutable-package checks. Ignored files covered by Cargo's explicit include
globs can contaminate packages even when Git reports a clean checkout; use a fresh
checkout, not existing local caches. Without `--package`, the planner reads existing
archives in Cargo's configured target directory; rebuild them after source changes.

An authorized publisher can use the same script with `--publish` and a securely supplied
`CARGO_REGISTRY_TOKEN`, or run the four `cargo publish -p <package>` commands manually
in dependency order. Finally, verify
`cargo install --locked kingfisher-bin --version <published-version>` in a fresh environment.
Repository changes and local planning do not themselves publish anything.
