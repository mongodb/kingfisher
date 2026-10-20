# Maintainer release checklist

This is an internal maintainer runbook for publishing GitHub release assets and the downstream
Docker, PyPI, and crates.io packages. End users should follow
[release verification](../docs/INSTALLATION.md#verifying-release-artifacts).

## Release workflow

The workflow runs on pushes of `v*` tags and `workflow_dispatch`. Every run must use a tag
ref matching the root Cargo version, including the `v` prefix; this is checked before tests
or builds start. Release assets are attested from that tag ref so consumers can verify the
version-specific signing identity. Pushes to `main` do not publish releases.

After all tests and builds pass, the workflow creates or updates a draft release, uploads
all assets, and publishes it only after the uploads succeed. A build or upload failure leaves
the release unpublished. Docker, PyPI, and crates.io publication follows the GitHub release.

Manual rebuilds select the tag with `--ref`; there is no separate tag input.

## Before publishing

1. Prepare and merge the release PR into `main`: update the root Cargo version and changelog,
   and update any library versions and dependencies being released. Follow the
   [package preparation checks](../docs/PUBLISHING.md).
2. Include regenerated rule-bundle provenance when required, including after root `Cargo.toml`
   or `Cargo.lock` changes. Run `python3 scripts/update-rule-bundle.py --check`.
3. Confirm CI passed and identify the merged commit you intend to release. Ensure that commit
   includes the tag-triggered release workflow before creating the tag.
4. Use a new tag matching the root Cargo version exactly, including the `v` prefix.
   Do not move an existing release tag to a different commit.

Push the release tag to start the workflow. No separate release creation or Actions dispatch
is needed for a new tag.

## Publish through the terminal

From a clean checkout of the intended merged commit, run with Python 3.11+ and authenticated
Git access to `mongodb/kingfisher`:

```bash
make release VERSION=X.Y.Z
```

The version may include a leading `v`. The command checks it against the committed root
Cargo version, verifies the commit is on the remote's `main`, creates an annotated tag,
and pushes only that tag. It rejects existing remote tags, lightweight local tags, and local
tags on another commit. If a push fails, retrying can reuse the annotated local tag on the
same commit.

The remote defaults to `origin`; confirm it points to `mongodb/kingfisher`, or specify it:

```bash
make release VERSION=X.Y.Z RELEASE_REMOTE=git@github.com:mongodb/kingfisher.git
```

Follow **build-and-release** under **Actions** until all publishing jobs finish.
The workflow uses the latest changelog section for the release notes.

Unchanged libraries keep their existing versions: the crates.io planner verifies their
packaged contents and skips their uploads. `make release` pushes only the CLI's `v*` tag;
it does not trigger the independently versioned Python SDK workflow. On main merges and
`python-v*` SDK tags, that workflow checks the SDK version on PyPI and skips the
protected publish job entirely if that version already exists.

Do not start a release with `gh release create` or the GitHub **Publish release** button:
those publish immediately, before the build. Adding `--draft` prevents immediate publication
but does not trigger this workflow; push the tag or dispatch on an existing tag instead.

## Independent package releases

From a clean checkout of the reviewed commit on the public repository's current `main`:

```bash
make release crates
make release kingfisher-secret-scanner
```

These commands infer the committed manifest versions; do not pass `VERSION`. They do not
edit version numbers, commit changes, move tags, or publish from an unmerged working tree.
Prepare any needed version bump first, update the lockfile/provenance, commit, and merge it.
`make release VERSION=X.Y.Z` remains the separate full CLI release command.

Both package commands check GitHub authentication, the public upstream/merged commit,
workflow availability and supported inputs, and registry state before starting release work.
They pin the expected commit so an advancing `main` cannot silently publish different code.
Registry lookup failures are errors, not evidence that a version is available. Existing PyPI
SDK versions and an all-already-published crates plan are errors; unchanged published crate
dependencies can still be skipped, but changed contents at the same version are rejected.

- **Crates:** discovers the existing CLI release and its passing build/test run. It retries
  only the original failed crates job when using that exact tested commit, or selects the
  guarded metadata-only recovery below. It does not rebuild the platform release archives,
  Docker image, or CLI PyPI package. Crate extraction/build verification still runs.
- **Python SDK:** dispatches the existing SDK workflow's explicit publish mode. The six wheel
  builds, source-distribution tests, and cache-portability checks must pass before publication
  through the protected `pypi-sdk` environment. An existing version fails before those builds;
  missing-artifact staging and `skip-existing` remain final race/retry safeguards, not permission
  to replace an existing release. Ordinary versioned main merges still publish automatically.

The `crates-io` and `pypi-sdk` environments and registry Trusted Publishers/API-token permissions
must already be configured. Read-only local checks cannot prove external registry authorization
or prevent a later outage/race; the protected publish jobs remain authoritative. See the
[crate publishing guide](../docs/PUBLISHING.md) and [SDK publishing guide](../docs/PYPI.md).

## Run through GitHub Actions

For an existing tag, open **Actions → build-and-release → Run workflow**, select the tag,
and run the workflow. Saving or publishing a release in the **Releases** UI is not the build
trigger. Manual dispatch requires the workflow to exist on the default branch as well.

## Finish and recover

Confirm all expected platform archives, Linux packages, `kingfisher-rule-bundle.tgz`, and
`multiple.intoto.jsonl` are attached. Verify an artifact using the end-user instructions with
the new version, and check the Docker, PyPI, and crates.io publishing jobs separately.

For both Linux architectures, inspect the package headers, not just filenames: RPM `Name`
and DEB `Package` must be `kingfisher`. Corrected RPMs must include
`Obsoletes: kingfisher-bin <= 2.11.0-1`. Test upgrades from both historical RPM names
in disposable Linux environments; only
`kingfisher` should remain installed and own `/usr/bin/kingfisher`. The Cargo and PyPI
package names intentionally remain `kingfisher-bin`. See the
[Linux package installation guidance](../docs/INSTALLATION.md#linux-packages-rpm-and-deb).

If a job fails, inspect its logs and rerun the failed jobs from the original Actions run where
appropriate. Keep the original tag and commit. A code fix needs a new release version.
An upload failure leaves a draft that the next attempt can update. Published releases are
skipped by the upload step so reruns do not replace their assets; rerun failed downstream
jobs to recover package publication. To restart an unpublished release on an existing tag:

```bash
gh workflow run release.yml --repo mongodb/kingfisher --ref vX.Y.Z
```

Normal release dispatch on `main` must fail. A free-form tag input or checking out a tag
inside a run on `main` does not provide the tag-based signing identity consumers verify.

### Registry-only metadata recovery

If crates.io planning rejects a missing library version bump **after the GitHub release is
public**, do not move its tag, replace its assets, or bypass the planner. A rerun of the
original failed job uses its original commit and cannot pick up a version fix.

Prepare and merge a metadata-only recovery into `main`: increment the core patch version,
raise its direct minimum requirements in the CLI, rules, and scanner manifests, update the
matching workspace lockfile entry, and regenerate rule-bundle provenance. An independent SDK
version correction from 1.4.0 to 1.5.0 and its matching lockfile entry may accompany this metadata fix. Keep the released CLI
version and all runtime/build/catalog inputs unchanged. Update the associated version docs.
The recovery validator permits only these exact manifest fields, the two workspace provenance
hashes, and its explicit maintenance/documentation file list; it rejects other source or
dependency changes. Unpublished rules, scanner, and CLI versions can retain their versions.
See [package preparation and publication checks](../docs/PUBLISHING.md).

After reviewing the recovery and its CI, dispatch the **same** workflow on `main`, explicitly
selecting crates-only mode and the original tag-based run that published the GitHub release.
For the v2.14.0 recovery:

```bash
gh workflow run release.yml --repo mongodb/kingfisher --ref main \
  -f crates_only=true -f release_run_id=39339690046 \
  -f expected_sha="$(git rev-parse HEAD)"
```

This is not a new binary release. The validator requires the public `mongodb/kingfisher`
repository, a clean checkout of the pinned merged commit, an existing public stable release
at the unchanged tag, and a successful **Public GitHub Release** job at that tag's commit in
the supplied run. It also requires successful release validation, all six platform builds,
all six platform test jobs, and every other test job present in that run. An overall failed
run is acceptable when downstream package publication failed. Missing releases or prerequisite
jobs, lookup failures, and mismatched commits fail closed.

Normal tests, platform builds, public release uploads, Docker, and PyPI are skipped. The
crates job runs the library tests, verifies the rule bundle and all four extracted packages,
rechecks recovery eligibility, then runs the unchanged full publication planner **before
registry authentication**. It uses the same `crates-io` environment, OIDC workflow identity,
and publication concurrency lock. Matching already-published packages remain immutable and
are skipped; conflicting contents still stop publication. No GitHub assets or attestations
are created or replaced, and the original run can remain red after a successful recovery.

A runtime, build, feature, dependency-graph, or catalog change is not eligible: use a new
normal release and its full verification instead. Do not broaden the recovery allowlist to
turn it into a general-purpose release bypass.

See the [release workflow](workflows/release.yml) and
[recovery validator](../scripts/check-crates-recovery.py) for the implementation.
