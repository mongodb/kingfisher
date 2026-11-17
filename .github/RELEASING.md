# Maintainer release checklist

This is an internal maintainer runbook for publishing GitHub release assets and the downstream
Docker, PyPI, npm, and crates.io packages. End users should follow
[release verification](../docs/INSTALLATION.md#verifying-release-artifacts).

## Release workflow

The [coordinator](workflows/release.yml) runs on upstream `main` pushes, `v*`,
`python-v*`, and `npm-v*` tag pushes, and manual dispatch. Tags must match the corresponding
committed manifest and identify a commit merged into upstream `main`.

Every normal release first passes one **Release build gate** for the same pinned SHA: all normal
cross-platform tests and binary builds, four verified Cargo packages and their read-only
registry plan, all Python SDK wheel/sdist/cache-portability tests, all npm native builds and
sealed-tarball tests, and six CLI PyPI wheels built from this run's binary artifacts. Failure,
cancellation, or a skipped required build prevents **every** registry publisher from starting.
SDKs are tested even when their unchanged version is already published.
[Artifact-only SDK recovery](#artifact-only-sdk-recovery) verifies an original complete
passing cohort and retained artifacts instead of rebuilding it.

Both PyPI upload jobs run directly in `release.yml`, with explicit `attestations: true`.
Reusable `python-sdk.yml` and `pypi.yml` are build-only and have no OIDC permission.
Normal source checks, cohort gates, artifact handoff and publication locks remain in
place, as does the SDK's protected `pypi-sdk` environment.

A `v<CLI-version>` tag also creates/updates a draft GitHub release, uploads and attests all
assets, and publishes the release only after uploads succeed. Its downstream registry jobs
wait for that public release too. Main and SDK-tag runs publish pending crates and Python SDK
versions without creating a CLI GitHub release, Docker image, or CLI PyPI release.

**npm remains tag-only:** uploads require an existing `npm-v<committed SDK version>` tag
pointing to the producer's exact SHA. Main/CLI/Python runs skip the npm handoff if that tag
is missing or points elsewhere; other registries proceed. The npm tag's own coordinator
cohort can publish it. CI never creates or moves tags. Publication retains the original
top-level `node-sdk.yml` / `npm` identity, existing `npm-v*`-only environment and reviewer;
no existing npmjs account or trust changes are needed.

Registry uploads are serialized per registry but are not a distributed transaction: an outage
or authentication error can leave a partial release after the build gate. Recover with the
original tested artifacts, following the npm handoff retry rules below; do not move tags or
reuse versions for changed bytes.

Manual CLI rebuilds select the existing tag with `--ref`; there is no separate tag input.
A manual main run is test-only unless `publish=true`, the full `expected_sha`, and the Python
SDK `expected_version` are supplied. Ordinary standalone SDK, CLI-wheel and Docker manual
workflows are build/test-only. The Node SDK's internal publish dispatch must validate the
coordinator's completed gates and exact artifacts; it is not an independent publication route.

## Before publishing

1. Prepare and merge the release PR into `main`: update the root Cargo version and changelog,
   and update any library versions and dependencies being released. Follow the
   [package preparation checks](../docs/PUBLISHING.md).
2. Include regenerated rule-bundle provenance when required, including after root `Cargo.toml`
   or `Cargo.lock` changes. Run `python3 scripts/update-rule-bundle.py --check`.
3. Confirm CI passed and that **Release build gate** and **Authorize the complete release
   cohort** both succeeded on the intended merged `main` commit; an overall green run with
   those jobs skipped is not release-ready. The **Public GitHub Release** job is expected to
   skip on `main`, not the two gates. Ensure that commit includes the tag-triggered release
   workflow before creating the tag.
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
the coordinator nevertheless tests every SDK and releases pending crate/Python SDK versions.
A pending npm upload additionally requires the same-SHA npm tag described above.
Already-published unchanged SDK versions are tested but skip upload.

Do not start a release with `gh release create` or the GitHub **Publish release** button:
those publish immediately, before the build. Adding `--draft` prevents immediate publication
but does not trigger this workflow; push the tag or dispatch on an existing tag instead.

## Independent package releases

From a clean checkout of the reviewed commit on the public repository's current `main`:

```bash
make release crates
make release kingfisher-secret-scanner
make release npm
```

These commands infer the committed manifest versions; do not pass `VERSION`. They do not
edit version numbers, commit changes, move tags, or publish from an unmerged working tree.
Prepare any needed version bump first, update the lockfile/provenance, commit, and merge it.
`make release VERSION=X.Y.Z` remains the separate full CLI release command.

All package commands check GitHub authentication, the public upstream/current `main`
commit, and workflow availability. They pin the expected commit so an advancing `main`
cannot silently publish different code. Python/crates additionally check supported dispatch
inputs and registry state before starting release work; npm registry/artifact checks stay in CI.
Registry lookup failures are errors, not evidence that a version is available. Existing PyPI
SDK versions and an all-already-published crates plan are errors; unchanged published crate
dependencies can still be skipped, but changed contents at the same version are rejected.

Crates preflight runs Cargo metadata and packaging in a temporary, detached checkout of
that exact commit. Ignored virtualenvs, caches, Finder files and local Cargo overrides in
the development checkout are not release inputs, even when Cargo's include globs would
otherwise match them. No `--allow-dirty` bypass or cleanup of development environments is
needed. A packaging failure reports Cargo's first error summary with credentials redacted;
verbose tool/authentication logs remain private. No release is dispatched after a failure.

- **Crates:** discovers the existing CLI release and its passing build/test run. It retries
  only the original failed crates job at that exact tested commit, or selects the guarded
  metadata-only recovery below. Recovery reruns the complete current build cohort but does
  not replace public assets or publish Docker/PyPI/npm releases.
- **Python SDK:** dispatches the coordinator's pinned main publish mode. All normal binary,
  Cargo and npm checks, six wheels, source-distribution tests, and cache-portability checks
  must pass before publication through `pypi-sdk`. Pending crates release too; npm uploads
  only with a matching existing npm tag at the same SHA. An existing Python version fails
  before those builds; missing-artifact staging and `skip-existing` remain race/retry
  safeguards, not permission to replace an existing release.
- **npm SDK:** `make release npm` infers the version from `javascript/package.json`, checks
  matching Node/native manifests and lockfiles, and pushes an annotated
  `npm-v<SDK-version>` tag. It never runs local `npm publish`. That tag's coordinator run
  must pass the complete shared gate before handing the exact tested tarballs to the
  original top-level Node SDK workflow at that same tag/SHA. Keep the `npm` environment
  limited to **`npm-v*` tags only**, with its existing reviewer unchanged. PRs,
  development/fork pushes and ordinary manual SDK runs only test. The source preflight
  rejects changed packaged/shared-runtime inputs at a published SDK version; unchanged
  published versions still pass their full test matrix but skip upload. Existing remote
  tags are rejected; use the handoff retry procedure below with the original artifacts,
  not a new tag. A failed push may reuse a same-commit annotated local tag. To select a
  public remote named `upstream`, use `make release npm RELEASE_REMOTE=upstream`.

The `crates-io`, `pypi-sdk`, and `npm` environments and registry Trusted Publishers/API-token
permissions must already be configured. For direct PyPI publishing, an authorized PyPI
project owner must manually **add**, not assume YAML has configured, these records:

| PyPI project | GitHub owner / repository | Workflow filename | Environment |
| --- | --- | --- | --- |
| `kingfisher-secret-scanner` | `mongodb` / `kingfisher` | `release.yml` | `pypi-sdk` |
| `kingfisher-bin` | `mongodb` / `kingfisher` | `release.yml` | **None — leave empty** |

Keep old `python-sdk.yml` / `pypi-sdk` and `pypi.yml` / no-environment PyPI records
until the new flow is verified; cleanup afterward is optional. Keep the approved SDK
`main`, `v*`, `python-v*`, `npm-v*` environment policies/reviewers unchanged, and do
not add an environment to the CLI uploader. PyPI
[does not support reusable workflows as Trusted Publishers](https://docs.pypi.org/trusted-publishers/troubleshooting/#reusable-workflows-on-github),
even for same-repository/same-ref calls. Read-only local checks cannot prove external
registry authorization or a successful live upload, or prevent a later outage/race;
the publish jobs remain authoritative.
See the [crate publishing guide](../docs/PUBLISHING.md),
[Python SDK publishing guide](../docs/PYPI.md), and
[npm publishing guide](../docs/PUBLISHING.md#npm-publishing-with-github-actions).

## Run through GitHub Actions

For an existing tag, open **Actions → build-and-release → Run workflow**, select the tag,
and run the workflow. Saving or publishing a release in the **Releases** UI is not the build
trigger. Manual dispatch requires the workflow to exist on the default branch as well.

## Finish and recover

Confirm all expected platform archives, Linux packages, `kingfisher-rule-bundle.tgz`, and
`multiple.intoto.jsonl` are attached. Verify an artifact using the end-user instructions with
the new version, and check the Docker, PyPI, npm handoff/child, and crates.io jobs separately.

For both Linux architectures, inspect the package headers, not just filenames: RPM `Name`
and DEB `Package` must be `kingfisher`. Corrected RPMs must include
`Obsoletes: kingfisher-bin <= 2.11.0-1`. Test upgrades from both historical RPM names
in disposable Linux environments; only
`kingfisher` should remain installed and own `/usr/bin/kingfisher`. The Cargo and PyPI
package names intentionally remain `kingfisher-bin`. See the
[Linux package installation guidance](../docs/INSTALLATION.md#linux-packages-rpm-and-deb).

If a job fails, inspect its logs and rerun the failed jobs from the original Actions run where
appropriate. Keep the original tag and commit. Runtime changes need a new release version;
a CI-only SDK publishing fix may use [artifact-only recovery](#artifact-only-sdk-recovery)
without rebuilding the original tested distributions.
An upload failure leaves a draft that the next attempt can update. Published releases are
skipped by the upload step so reruns do not replace their assets; rerun failed downstream
jobs to recover package publication, following the npm handoff rules below. To restart an
unpublished release on an existing tag:

```bash
gh workflow run release.yml --repo mongodb/kingfisher --ref vX.Y.Z
```

Main dispatch without `publish=true` is build/test-only. Guarded main publication releases
pending crates/Python SDKs, plus npm only when its existing tag matches the same SHA, not
CLI assets. A free-form tag input or checking out a tag inside a main run does not provide
the CLI tag-based signing identity consumers verify.

### Complete the prepared releases without version bumps

For CLI **2.19.1**, Python SDK **1.6.4** and npm SDK **1.0.2**, incident checks found
crates.io already published, including `kingfisher-bin 2.19.1`, but no `v2.19.1`,
`npm-v1.0.2` or `python-v1.6.4` tags and no GitHub CLI `2.19.1` release. SDK PyPI
`1.6.4`, CLI PyPI `2.19.1` and all seven unscoped npm `1.0.2` versions were also
absent at that check. A main run is **not** a CLI release; its successful npm handoff
can be a no-op without the npm tag. Recheck current registry/release/tag state before
proceeding; these observations are not a guarantee that versions remain unpublished.

1. **Before merging**, have an authorized owner add both matching
   [PyPI publisher records](../docs/PYPI.md#configure-pypi-trusted-publishers).
   Keep legacy records, approved environments, reviewers and gates unchanged.
2. Merge the reviewed CI-only repair **without changing versions**. Let the ordinary
   automatic main cohort finish: publish pending SDK `1.6.4`, verify unchanged
   already-published crates are skipped, and require both release gates to pass.
   Record this reviewed current-main SHA as **R**.

   If retaining the exact original SDK artifacts is preferred, use
   [artifact-only SDK recovery](#artifact-only-sdk-recovery) **instead of** the normal
   main SDK upload: stop only the **new** automatic main run before builds/publication,
   complete SDK recovery before normal publishing, then rerun **only that cancelled
   new main run** for a fresh green cohort at R. Never cancel/rerun the original
   pinned failed producer.
3. From a clean checkout whose `HEAD` and current upstream `main` still equal R,
   confirm the CLI tag is still absent and use the normal helper with the public
   repository remote:

   ```bash
   make release VERSION=2.19.1
   ```

   **Wait for the entire CLI cohort to finish**, including public GitHub assets and
   CLI PyPI `kingfisher-bin 2.19.1`. Its npm handoff is expected to be a no-op because
   the npm tag is still absent. Do not create the npm tag concurrently.
4. Only after that completion, recheck that the same clean checkout and current
   upstream `main` still equal R and that `npm-v1.0.2` remains absent, then run:

   ```bash
   make release npm
   ```

   This infers `1.0.2` and creates its npm tag at R. Wait for that tag's **own full
   cohort** and protected npm publication to finish; do not race independently rebuilt
   npm archives between cohorts.

These CLI/npm tag releases retain normal full builds/tests: **no bump does not mean
zero rebuilds**. Both tags must resolve to the same R; no `python-v1.6.4` tag is needed.
Do not run `make release crates` or `gh release create`, manually publish a GitHub
release, or change already-published bytes. If main advances or a proposed tag appears, stop and
re-evaluate; never move a tag.

### npm handoff recovery

After **Release build gate** and **Authorize the complete release cohort** succeed, the
coordinator's npm dispatcher uses `contents: read` / `actions: write` and
[`scripts/dispatch-node-sdk.py`](../scripts/dispatch-node-sdk.py) to dispatch the original
Node SDK workflow at the existing npm tag and wait for the exact returned run ID. The
child validates the producer workflow/repository/SHA/`run_attempt`, both successful gates,
the intended running/successful dispatcher, the exact immutable staging artifact ID and
metadata, and the same-SHA npm tag/manifest/fresh upstream ancestry. These checks run both
before entering `npm` and again after protected approval, before downloading the tested
archives by validated artifact ID; there is no rebuild or repack.

Rerun a failed npm child only while its authorizing parent run and npm dispatcher remain
active or successful. A failed, cancelled, or timed-out parent rejects stale children.
Otherwise rerun the **original coordinator's failed npm handoff job**: it can dispatch a
new Node child with the same producer artifacts and current attempt authorization. Gates
not rerun retain their most recent successful result; newer failed/skipped/pending gates
cannot fall back to an older success, and the dispatcher must belong to the current attempt.
Do not create/move tags, dispatch an independent manual publish, or rebuild an existing version.
See the [npm recovery details](../docs/PUBLISHING.md#npm-handoff-recovery).

### Artifact-only SDK recovery

Use this opt-in path for a failed SDK upload whose original distributions and
complete passing cohort can still be verified. It is integrated into the **same
`release.yml`** to keep the direct PyPI publisher identity, protected `pypi-sdk`
environment, explicit attestations and SDK publication lock. It runs no Rust, wheel
or binary builds and publishes no crates, npm, CLI wheels, Docker images or GitHub
assets; original cohort evidence is verified, not replaced.

[Run 43954600383](https://github.com/mongodb/kingfisher/actions/runs/43954600383)
built SDK `1.6.4` at `84b8733639e20ff0469186f73a011d1f84f7196f`. Its coordinated
gates, six SDK wheels, sdist and portability tests passed and crates published.
The first SDK upload then failed HTTP 400: OIDC identified `python-sdk.yml`, but
the attestation certificate's Build Config URI identified `release.yml`. The old
CLI uploader used `attestations: false` and did not have this specific SDK failure.
PyPI configuration alone cannot repair that failed run. Never rerun its broken
workflow snapshot expecting it to execute a later workflow fix.

1. Merge and review the direct publisher/recovery code on upstream `main`. Have an
   authorized project owner add the matching SDK PyPI publisher above; keep old
   records and approved GitHub environment policies unchanged. Merging still starts
   ordinary automatic full-cohort CI on `main`; SDK-only dispatch shares main-run
   concurrency and waits behind it. For original-artifact recovery, stop **only that
   new automatic main run before it builds/publishes**, then dispatch `sdk_only`.
   Never cancel/rerun the pinned original failed producer or let a new ordinary
   build publish different bytes under the same SDK version first. Do not disable
   Actions, change account/branch policies or weaken gates; only recovery itself is
   build-free.
2. From a **clean checkout of current reviewed upstream `main`**, inspect the exact
   original producer run and verify its attempt and retained `python-sdk-pending`
   artifact ID. Do not infer them from a latest-run or artifact-name search.
3. Pin the original run with `release_run_id`, `release_run_attempt`, `artifact_id`,
   `producer_sha` and `expected_version`. Separately pin the **current recovery
   workflow SHA** with `expected_sha`. Both explicit pins are required; they differ
   for this CI fix but may match when current `main` is unchanged.
4. Dispatch with both `sdk_only=true` and `publish=true` (`sdk_only` defaults to
   `false`); leave `crates_only` false. Read-only inspection identified producer
   attempt **`1`**, pending artifact **`14273355973`**, size **110898976 bytes**,
   digest `sha256:1752a6dea7eb8900c03e42ac2246c6917f93b674f12e744dfeb9ad4feca735e2`,
   expiring **2027-02-14 20:54:34 UTC**. Recheck those pins before using this example:

   ```bash
   gh workflow run release.yml --repo mongodb/kingfisher --ref main \
     -f publish=true -f sdk_only=true \
     -f release_run_id=43954600383 \
     -f release_run_attempt=1 \
     -f artifact_id=14273355973 \
     -f producer_sha=84b8733639e20ff0469186f73a011d1f84f7196f \
     -f expected_sha="$(git rev-parse HEAD)" \
     -f expected_version=1.6.4
   ```

5. Review the read-only validator's evidence before approving `pypi-sdk`. It checks
   the upstream producer workflow/ref/SHA/attempt, successful latest-effective
   complete-cohort gates and SDK builds/tests/publication plan, immutable artifact
   ID/digest/retention/expiry, and exact distributions. Newer failed/skipped/pending
   prerequisite results cannot fall back to an older success. Artifact API metadata
   must prove the upstream repository/run/SHA and creation within the selected
   successful SDK plan job.
6. Confirm the producer is an ancestor of current reviewed `main` with an unchanged
   SDK manifest version. Source drift permits only the three publication workflows,
   this runbook, the recovery validator,
   [release-source authorization guard](../scripts/check-release-source.py), allowlisted
   CI test scripts, and Markdown docs/generated docs. Runtime, SDK, manifest, lockfile, rules and other build inputs
   are forbidden. Do not slip unrelated changes into recovery, expand the policy, or
   check out the old producer under the new workflow identity. Validation runs again
   **after protected approval**, before authentication and upload.
7. Require recovery's post-upload check of **every staged filename and exact SHA-256
   against PyPI**, with bounded read-only visibility retries; `skip-existing` cannot
   hide a concurrent different-byte upload. Verify the version/attestations and perform
   a fresh consumer installation. Merged workflow code and passing read-only checks
   are not evidence of a successful live publication or changed PyPI configuration.

Missing, expired or mismatched evidence fails closed. Recovery requires the retained
original artifact; never substitute a different run, rebuild or repackage it. No SDK
version bump is required solely for CI changes if no files were ever published.
Partial uploads must recover the exact original tested artifacts, never replace
immutable published bytes. SDK/runtime changes need a normal new-version release.
See the [SDK recovery details](../docs/PYPI.md#artifact-only-sdk-recovery).

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

Recovery reruns all current platform tests/builds, SDK matrices, CLI wheel builds, library
tests, rule-bundle checks and all four extracted packages through the same shared build gate.
Public release uploads and Docker/PyPI/npm publication remain skipped. The crates publisher
rechecks recovery eligibility and the unchanged full publication plan **before registry
authentication**. It uses the same `crates-io` environment, OIDC workflow identity,
and publication concurrency lock. Matching already-published packages remain immutable and
are skipped; conflicting contents still stop publication. No GitHub assets or attestations
are created or replaced, and the original run can remain red after a successful recovery.

A runtime, build, feature, dependency-graph, or catalog change is not eligible: use a new
normal release and its full verification instead. Do not broaden the recovery allowlist to
turn it into a general-purpose release bypass.

See the [release workflow](workflows/release.yml) and
[recovery validator](../scripts/check-crates-recovery.py) for the implementation.
