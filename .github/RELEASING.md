# Maintainer release checklist

This is an internal maintainer runbook for publishing GitHub release assets and the downstream
Docker, PyPI, and crates.io packages. End users should follow
[release verification](../docs/INSTALLATION.md#verifying-release-artifacts).

## Workflow migration required

This runbook describes the agreed tag-based release process. The current workflow still
publishes on pushes to `main` and accepts a separate tag input; migrate it before adopting
this process:

- Remove the `push: main` release trigger; keep `release: published` and `workflow_dispatch`.
- Require a tag ref for every release run, derive the version from `github.ref_name`, and
  reject a mismatch with the root Cargo version before starting builds.
- Remove the separate `tag` dispatch input. Manual rebuilds must select the tag with `--ref`.

Merge the workflow migration before creating the next release tag, so that tag contains the
updated workflow. Until then, a push to `main` can publish assets signed from `main`; these
cannot pass the end-user version-specific check.

## Before publishing

1. Prepare and merge the release PR into `main`: update the root Cargo version and changelog,
   and update any library versions and dependencies being released. Follow the
   [package preparation checks](../docs/PUBLISHING.md).
2. Include regenerated rule-bundle provenance when required, including after root `Cargo.toml`
   or `Cargo.lock` changes. Run `python3 scripts/update-rule-bundle.py --check`.
3. Confirm CI passed and identify the merged commit you intend to release. The commands below
   target the current tip of `main`; if newer changes have landed, use the intended commit SHA
   with `--target`, or create the tag on that commit before selecting it in the UI.
4. Use a new tag matching the root Cargo version exactly, including the `v` prefix.
   Do not move an existing release tag to a different commit.

Choose one of the following publishing methods. Both publish a GitHub release and trigger the
same tag-based build workflow. No separate Actions dispatch is needed.

## Publish through GitHub

1. Open the repository's **Releases** page and click **Draft a new release**.
2. In **Choose a tag**, enter `vX.Y.Z` and select **Create new tag**.
3. Set **Target** to `main` (or select an existing tag on the intended release commit).
4. Enter the title `Kingfisher vX.Y.Z` and release notes, then click **Publish release**.
5. Follow **build-and-release** under **Actions** until all publishing jobs finish.

Saving a draft does not trigger the build. The published release initially has no compiled
assets; the workflow uploads them after the cross-platform tests and builds succeed.
This process requires mutable releases because assets are attached after publication.

## Publish through the terminal

With an authenticated GitHub CLI, replace `vX.Y.Z` with the release version:

```bash
gh release create vX.Y.Z \
  --repo mongodb/kingfisher \
  --target main \
  --title "Kingfisher vX.Y.Z" \
  --generate-notes
```

This creates the tag if it does not exist, publishes the release, and triggers the build.
There is no need to run `git tag`, `git push`, or `gh workflow run` as well.
The workflow uses the latest changelog section for the final release notes.

## Finish and recover

Confirm all expected platform archives, Linux packages, `kingfisher-rule-bundle.tgz`, and
`multiple.intoto.jsonl` are attached. Verify an artifact using the end-user instructions with
the new version, and check the Docker, PyPI, and crates.io publishing jobs separately.

If a job fails, inspect its logs and rerun the failed jobs from the original Actions run where
appropriate. Keep the original tag and commit. A code fix needs a new release version.
For a deliberate rebuild of an existing tag, dispatch the workflow on that tag:

```bash
gh workflow run release.yml --repo mongodb/kingfisher --ref vX.Y.Z
```

Dispatching on `main` must fail. A free-form tag input or checking out a tag inside a run on
`main` does not provide the tag-based signing identity consumers verify.

See the [release workflow](workflows/release.yml) for the implementation.
