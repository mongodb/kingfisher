#!/usr/bin/env python3
"""Validate a metadata-only crates.io recovery against an existing public release.

Requires Python 3.11+. Reads GitHub state and Git objects; never changes tags,
releases, package versions, or registry state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mongodb/kingfisher"
CORE = "crates/kingfisher-core/Cargo.toml"
SDK = "crates/kingfisher-python/Cargo.toml"
DEPENDENTS = ("Cargo.toml", "crates/kingfisher-rules/Cargo.toml",
              "crates/kingfisher-scanner/Cargo.toml")
PROVENANCE = "crates/kingfisher-rules/generated/provenance.json"
PROVENANCE_INPUTS = ("Cargo.toml", "Cargo.lock")
PLATFORMS = ("Linux x64", "Linux arm64", "macOS x64", "macOS arm64", "Windows x64", "Windows arm64")
REQUIRED_JOBS = {"Verify release ref and version", "Public GitHub Release", *PLATFORMS} | {
    f"tests / {platform}" for platform in PLATFORMS
}
MAINTENANCE_FILES = {
    "README.md", "CHANGELOG.md", "docs/LIBRARY.md", "docs/PUBLISHING.md",
    "crates/kingfisher-core/README.md", "crates/kingfisher-rules/README.md",
    "crates/kingfisher-scanner/README.md", "docs-site/docs/changelog.md",
    "docs-site/docs/reference/library.md", ".github/RELEASING.md",
    ".github/workflows/release.yml", "scripts/check-crates-recovery.py",
    "scripts/tests/test_crates_recovery.py", "Makefile",
    "scripts/release-packages.py", "scripts/tests/test_release_packages.py",
    "scripts/check-sdk-release.py", "scripts/tests/test_sdk_preflight.py",
    "scripts/tests/test_python_sdk_release.py", "scripts/tests/test_release_makefile.py",
    ".github/workflows/python-sdk.yml", "docs/PYPI.md", "python/README.md",
    "docs-site/docs/reference/python-bindings.md",
}


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def blob(root, commit, path):
    return git(root, "show", f"{commit}:{path}")


def check_metadata(root, base, head="HEAD"):
    """Allow one core patch bump, its minimum requirements, and no build drift."""
    allowed = MAINTENANCE_FILES | {CORE, SDK, *DEPENDENTS, "Cargo.lock", PROVENANCE}
    changed = git(root, "diff", "--name-only", "--no-renames", "-z", base, head).decode().split("\0")
    for path in filter(None, changed):
        if path not in allowed:
            raise ValueError(f"Recovery changes a runtime or unapproved file: {path}")
        entry = git(root, "ls-tree", head, "--", path).decode()
        if not entry.startswith(("100644 blob ", "100755 blob ")):
            raise ValueError(f"Recovery must retain a regular file: {path}")
        previous = git(root, "ls-tree", base, "--", path).decode()
        if previous and previous.split()[0] != entry.split()[0]:
            raise ValueError(f"Recovery changes a file mode: {path}")

    def toml(commit, path):
        return tomllib.loads(blob(root, commit, path).decode())

    old_core, new_core = toml(base, CORE), toml(head, CORE)
    old_version, new_version = old_core["package"]["version"], new_core["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", old_version) or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+", new_version):
        raise ValueError("Recovery requires stable core patch versions")
    old_parts, new_parts = tuple(map(int, old_version.split("."))), tuple(map(int, new_version.split(".")))
    if new_parts != (*old_parts[:2], old_parts[2] + 1):
        raise ValueError("Recovery must increment only the core patch version by one")
    new_core["package"]["version"] = old_version
    if new_core != old_core:
        raise ValueError(f"Recovery changes more than the core version: {CORE}")
    for path in DEPENDENTS:
        before, after = toml(base, path), toml(head, path)
        old_dependency = before["dependencies"]["kingfisher-core"]
        new_dependency = after["dependencies"]["kingfisher-core"]
        if old_dependency["version"] != old_version or new_dependency["version"] != new_version:
            raise ValueError(f"Recovery must update the core minimum requirement: {path}")
        new_dependency["version"] = old_version
        if before != after:
            raise ValueError(f"Recovery changes unrelated manifest fields: {path}")

    old_sdk, new_sdk = toml(base, SDK), toml(head, SDK)
    old_sdk_version = old_sdk["package"]["version"]
    new_sdk_version = new_sdk["package"]["version"]
    if old_sdk_version != new_sdk_version and (old_sdk_version, new_sdk_version) != ("1.4.0", "1.5.0"):
        raise ValueError("Recovery allows only the SDK metadata version correction 1.4.0 to 1.5.0")
    new_sdk["package"]["version"] = old_sdk_version
    if old_sdk != new_sdk:
        raise ValueError("Recovery changes SDK manifest fields beyond its package version")

    before, after = toml(base, "Cargo.lock"), toml(head, "Cargo.lock")
    for lock, version, sdk_version in ((before, old_version, old_sdk_version),
                                       (after, new_version, new_sdk_version)):
        core = [p for p in lock["package"] if p["name"] == "kingfisher-core" and "source" not in p]
        if len(core) != 1 or core[0]["version"] != version:
            raise ValueError("Recovery lockfile must contain the matching workspace core version")
        core[0]["version"] = old_version
        sdk = [p for p in lock["package"] if p["name"] == "kingfisher-python" and "source" not in p]
        if len(sdk) != 1 or sdk[0]["version"] != sdk_version:
            raise ValueError("Recovery lockfile must contain the matching workspace SDK version")
        sdk[0]["version"] = old_sdk_version
    if before != after:
        raise ValueError("Recovery changes unrelated lockfile dependencies or checksums")

    before = json.loads(blob(root, base, PROVENANCE))
    after = json.loads(blob(root, head, PROVENANCE))
    for path in PROVENANCE_INPUTS:
        for provenance, commit in ((before, base), (after, head)):
            actual = provenance["generator_input_sha256"][path]
            if actual != hashlib.sha256(blob(root, commit, path)).hexdigest():
                raise ValueError(f"Recovery provenance does not match {path}; regenerate the bundle")
        after["generator_input_sha256"][path] = before["generator_input_sha256"][path]
    if before != after:
        raise ValueError("Recovery changes rule-bundle provenance beyond workspace manifest/lock hashes")


def github_json(path, token):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "kingfisher-crates-recovery"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"https://api.github.com{path}", headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def check_github(repository, tag, base, run_id, token, api=github_json):
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("--release-run-id must identify the original release run")
    repo = api(f"/repos/{repository}", token)
    if repo["full_name"] != REPOSITORY or repo["private"]:
        raise ValueError("Registry recovery requires the public mongodb/kingfisher repository")
    release = api(f"/repos/{repository}/releases/tags/{tag}", token)
    if (release["tag_name"] != tag or release["target_commitish"] != base
            or release["draft"] or release["prerelease"] or not release["published_at"]):
        raise ValueError("Recovery requires an existing public stable release at the unchanged tag commit")
    run = api(f"/repos/{repository}/actions/runs/{run_id}", token)
    if (run["repository"]["full_name"] != REPOSITORY
            or run["path"] != ".github/workflows/release.yml" or run["head_sha"] != base
            or run["head_branch"] != tag or run["status"] != "completed"
            or run["event"] not in {"push", "workflow_dispatch"}):
        raise ValueError("Original release run does not match the public release tag and workflow")
    # Overall run failure is expected when downstream crates publication failed.
    # Check the actual prerequisites, not just the release job's conclusion.
    jobs = []
    page = 1
    while True:
        batch = api(f"/repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100&page={page}", token)["jobs"]
        jobs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    gates = [job for job in jobs if job["name"] in REQUIRED_JOBS or job["name"].startswith("tests / ")]
    if (any(sum(job["name"] == name for job in gates) != 1 for name in REQUIRED_JOBS)
            or any(job["status"] != "completed" or job["conclusion"] != "success" for job in gates)):
        raise ValueError("Original release validation, all platform builds/tests, and Public GitHub Release must have succeeded")
    return jobs


def validate_recovery(root, repository, ref, event, sha, run_id, token, api=github_json,
                      expected_sha=""):
    if repository != REPOSITORY or ref != "refs/heads/main" or event != "workflow_dispatch":
        raise ValueError("Registry-only recovery requires manual dispatch on public mongodb/kingfisher main")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha) or expected_sha != sha:
        raise ValueError("Recovery expected_sha must match the immutable workflow main commit")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or git(root, "rev-parse", "HEAD").decode().strip() != sha:
        raise ValueError("Recovery checkout must match the immutable workflow commit")
    if git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("Recovery requires a clean checkout")
    git(root, "merge-base", "--is-ancestor", sha, "origin/main")
    manifest = tomllib.loads(blob(root, "HEAD", "Cargo.toml").decode())
    version = manifest["package"]["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Recovery requires a stable CLI release version")
    tag = f"v{version}"
    base = git(root, "rev-parse", f"refs/tags/{tag}^{{commit}}").decode().strip()
    git(root, "merge-base", "--is-ancestor", base, sha)
    check_metadata(root, base)
    check_github(repository, tag, base, run_id, token, api=api)
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-run-id", required=True, help="original tag-based release run ID")
    parser.add_argument("--expected-sha", default=os.environ.get("EXPECTED_SHA", ""),
                        help="reviewed main commit SHA; defaults to EXPECTED_SHA")
    args = parser.parse_args()
    tag = validate_recovery(ROOT, os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_REF"],
                            os.environ["GITHUB_EVENT_NAME"], os.environ["GITHUB_SHA"],
                            args.release_run_id, os.environ.get("GH_TOKEN", ""),
                            expected_sha=args.expected_sha)
    print(f"Validated registry-only recovery for {tag}; public tag and assets remain unchanged")
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"tag={tag}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        print(f"Crates.io recovery stopped: {error}", file=sys.stderr)
        sys.exit(1)
