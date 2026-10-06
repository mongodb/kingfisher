#!/usr/bin/env python3
"""Push a release tag; GitHub Actions builds assets before publishing. Requires Python 3.11+."""
import argparse
from pathlib import Path
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def git(*args, root, check=True):
    return subprocess.run(
        ["git", *args], cwd=root, check=check, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def release(version, remote="origin", *, root=ROOT):
    if not version:
        raise ValueError("Specify the version: make release VERSION=X.Y.Z")
    if not remote or remote.startswith("-"):
        raise ValueError("RELEASE_REMOTE must be a Git remote name, URL, or repository path")
    if git("status", "--porcelain", root=root).stdout:
        raise ValueError("Commit or stash local changes before releasing")

    commit = git("rev-parse", "HEAD", root=root).stdout.strip()
    manifest = tomllib.loads(git("show", f"{commit}:Cargo.toml", root=root).stdout)
    expected = manifest["package"]["version"]
    if version.removeprefix("v") != expected:
        raise ValueError(f"Requested version {version!r} does not match Cargo.toml ({expected})")
    tag = f"v{expected}"
    tag_ref = f"refs/tags/{tag}"
    git("check-ref-format", tag_ref, root=root)

    local_tag = git("rev-parse", "--verify", "--quiet", f"{tag_ref}^{{commit}}", root=root, check=False)
    if local_tag.returncode not in (0, 1):
        local_tag.check_returncode()
    if local_tag.returncode == 0 and local_tag.stdout.strip() != commit:
        raise ValueError(f"Local tag {tag} already points to another commit; do not move it")

    git("fetch", "--no-tags", remote, "refs/heads/main", root=root)
    on_main = git("merge-base", "--is-ancestor", commit, "FETCH_HEAD", root=root, check=False)
    if on_main.returncode == 1:
        raise ValueError("The release commit must be merged into the remote's main branch")
    on_main.check_returncode()
    if git("ls-remote", "--tags", remote, tag_ref, root=root).stdout.strip():
        raise ValueError(f"Remote tag {tag} already exists; rerun its Actions jobs instead")

    if local_tag.returncode != 0:
        git("tag", "-a", tag, commit, "-m", f"Kingfisher {tag}", root=root)
    # A failed push leaves the local tag available for a retry. Never force-push tags.
    git("push", remote, f"{tag_ref}:{tag_ref}", root=root)
    print(f"Pushed {tag} ({commit}) to {remote}. Follow build-and-release in GitHub Actions.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Cargo version, with or without a leading v")
    parser.add_argument("--remote", default="origin", help="Git remote to fetch main from and push the tag to")
    args = parser.parse_args()
    try:
        release(args.version, args.remote)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"Release failed: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
