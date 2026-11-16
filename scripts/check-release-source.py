#!/usr/bin/env python3
"""Authorize a pinned central release source without builds or remote writes.

Run with --github-event (or no arguments) in the checked-out GitHub event. Emits
``tag``, ``cli-release`` and ``publish`` to GITHUB_OUTPUT only after validation.
The only remote operation is a read-only fetch of the upstream main history.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "mongodb/kingfisher"
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
NPM_PRERELEASE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
NPM_VERSION = re.compile(VERSION.pattern.removesuffix(r"\Z")
                         + rf"(?:-{NPM_PRERELEASE}(?:\.{NPM_PRERELEASE})*)?"
                         + r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")
MANIFESTS = {
    "cli": ("Cargo.toml", "kingfisher-bin"),
    "python": ("crates/kingfisher-python/Cargo.toml", "kingfisher-python"),
    "npm": ("javascript/package.json", "kingfisher-secret-scanner"),
}
PREFIXES = {"cli": "refs/tags/v", "python": "refs/tags/python-v", "npm": "refs/tags/npm-v"}


def enabled(value):
    return value is True or value == "true"


def full_sha(value):
    return isinstance(value, str) and SHA.fullmatch(value) is not None and value != "0" * 40


def git(root, *arguments):
    return subprocess.run(["git", *arguments], cwd=root, check=True, capture_output=True,
                          text=True, encoding="utf-8").stdout.strip()


def manifest_version(root, kind, revision="HEAD", *, git_fn=None):
    """Read the selected commit, never editable worktree version bytes."""
    path, name = MANIFESTS[kind]
    text = (git_fn or git)(root, "show", f"{revision}:{path}")
    package = json.loads(text) if kind == "npm" else tomllib.loads(text)["package"]
    version = package.get("version")
    pattern = NPM_VERSION if kind == "npm" else VERSION
    if (package.get("name") != name or not isinstance(version, str)
            or pattern.fullmatch(version) is None):
        raise ValueError(f"{kind} release manifest must name {name} with a valid release version")
    return version


def supported_ref(ref):
    return isinstance(ref, str) and (ref == "refs/heads/main" or any(
        ref.startswith(prefix) for prefix in PREFIXES.values()))


def validate_release_ref(root, ref, revision="HEAD", *, versions=None, git_fn=None):
    """Validate stable CLI/Python and SemVer npm tags at that exact commit."""
    if ref == "refs/heads/main":
        return True
    versions = versions or {}
    for kind, prefix in PREFIXES.items():
        if isinstance(ref, str) and ref.startswith(prefix):
            suffix = ref.removeprefix(prefix)
            pattern = NPM_VERSION if kind == "npm" else VERSION
            if pattern.fullmatch(suffix) is None:
                raise ValueError("Release tag must use a supported version")
            version = versions.get(kind)
            if version is None:
                version = manifest_version(root, kind, revision, git_fn=git_fn)
            if suffix != version:
                raise ValueError(f"{kind} release tag must match the {kind} manifest version")
            return True
    return False


def publication_source(root, env, event, *, versions=None, git_fn=None):
    """Return (publish, manual); unrelated/fork events never authorize writes."""
    run_git = git_fn or git
    event_name = env.get("GITHUB_EVENT_NAME")
    ref = env.get("GITHUB_REF", "")
    inputs = event.get("inputs") or {}
    if not isinstance(inputs, dict):
        raise ValueError("Release event inputs must be an object")
    # Recovery still pins current upstream main, but has a separate stricter
    # metadata gate and must never authorize sibling SDK publication.
    recovery = event_name == "workflow_dispatch" and enabled(inputs.get("crates_only"))
    manual = event_name == "workflow_dispatch" and enabled(inputs.get("publish"))
    automatic = event_name == "push" and supported_ref(ref) and not enabled(inputs.get("crates_only"))
    # Preserve the established CLI-tag retry/completion entry point. Unlike a
    # manual main publication, an immutable CLI tag needs no current-main pin.
    publish_input = inputs.get("publish")
    default_publish = publish_input is None or publish_input is False or publish_input == "false"
    cli_tag_dispatch = (event_name == "workflow_dispatch" and default_publish and not recovery
                        and isinstance(ref, str) and ref.startswith(PREFIXES["cli"]))
    if not (manual or recovery or automatic or cli_tag_dispatch):
        return False, False
    if env.get("GITHUB_REPOSITORY") != UPSTREAM:
        if manual or recovery:
            raise ValueError("Release publication requires the upstream mongodb/kingfisher repository")
        return False, False
    head = run_git(root, "rev-parse", "HEAD")
    if not full_sha(env.get("GITHUB_SHA")) or head != env["GITHUB_SHA"]:
        raise ValueError("Release checkout must match the pinned GITHUB_SHA")
    if manual or recovery:
        if ref != "refs/heads/main":
            raise ValueError("Manual release publication requires refs/heads/main")
        if not full_sha(inputs.get("expected_sha")) or inputs["expected_sha"] != head:
            raise ValueError("expected_sha must be the full pinned main checkout SHA")
        if not recovery:
            python_version = (versions or {}).get("python")
            if python_version is None:
                python_version = manifest_version(root, "python", head, git_fn=run_git)
            if inputs.get("expected_version") != python_version:
                raise ValueError("expected_version must match the Python SDK manifest version")
    if not validate_release_ref(root, ref, head, versions=versions, git_fn=run_git):
        return False, False
    # actions/checkout supplies origin for the verified upstream repository. Do
    # not trust a stale local main ref or assume that a tag was merged to main.
    run_git(root, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main")
    main = run_git(root, "rev-parse", "refs/remotes/origin/main")
    if not full_sha(main):
        raise ValueError("Cannot resolve the current upstream main SHA")
    run_git(root, "merge-base", "--is-ancestor", head, main)
    if (manual or recovery) and main != head:
        raise ValueError("expected_sha is no longer the current upstream main SHA")
    return not recovery, manual and not recovery


def source_plan(root, env, event):
    head = git(root, "rev-parse", "HEAD")
    if not full_sha(env.get("GITHUB_SHA")) or env["GITHUB_SHA"] != head:
        raise ValueError("Release checkout must match the pinned GITHUB_SHA")
    cli = manifest_version(root, "cli", head)
    ref = env.get("GITHUB_REF", "")
    # Reject malformed/mismatched supported tags even in a build-only dispatch.
    validate_release_ref(root, ref, head, versions={"cli": cli})
    publish, _ = publication_source(root, env, event, versions={"cli": cli})
    return {"tag": f"v{cli}", "cli-release": publish and ref == f"refs/tags/v{cli}",
            "publish": publish}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-event", action="store_true", help="validate the current GitHub event (default)")
    parser.parse_args(argv)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    plan = source_plan(ROOT, os.environ, event)
    print(json.dumps(plan, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in plan.items():
                stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Release source preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
