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

Do not start a release with `gh release create` or the GitHub **Publish release** button:
those publish immediately, before the build. Adding `--draft` prevents immediate publication
but does not trigger this workflow; push the tag or dispatch on an existing tag instead.

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

Dispatching on `main` must fail. A free-form tag input or checking out a tag inside a run on
`main` does not provide the tag-based signing identity consumers verify.

See the [release workflow](workflows/release.yml) for the implementation.
