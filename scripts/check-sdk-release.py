#!/usr/bin/env python3
"""Read-only SDK release preflight (Python 3.11+; no builds or registry writes).

Local/orchestrator interface:
    python3 scripts/check-sdk-release.py --require-new --expected-version VERSION

With --github-event, validate the event/source and emit build/publish outputs for
an inexpensive workflow job that gates all native builds. Only PyPI HTTP 404
means an unused version; an existing empty or yanked release is still reserved.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "crates/kingfisher-python/Cargo.toml"
PACKAGE = "kingfisher-secret-scanner"
UPSTREAM = "mongodb/kingfisher"
SHA = re.compile(r"[0-9a-f]{40}\Z")
SHARED_CRATES = ("kingfisher-python", "kingfisher-core", "kingfisher-rules", "kingfisher-scanner")

_recovery_spec = importlib.util.spec_from_file_location(
    "crates_recovery", ROOT / "scripts/check-crates-recovery.py")
crates_recovery = importlib.util.module_from_spec(_recovery_spec)
_recovery_spec.loader.exec_module(crates_recovery)


def sdk_version(root=ROOT):
    with (root / MANIFEST).open("rb") as stream:
        package = tomllib.load(stream)["package"]
    if package.get("name") != "kingfisher-python":
        raise ValueError("SDK Rust package must be named kingfisher-python")
    version = package.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version):
        raise ValueError("SDK version must be a prepared stable x.y.z version")
    with (root / "Cargo.lock").open("rb") as stream:
        locked = [item["version"] for item in tomllib.load(stream)["package"]
                  if item["name"] == "kingfisher-python"]
    if locked != [version]:
        raise ValueError("Cargo.lock SDK entry must match the SDK manifest version")
    return version


def version_exists(version):
    """Fail closed on registry errors, with at most three bounded GET attempts."""
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{PACKAGE}/{urllib.parse.quote(version, safe='')}/json",
        headers={"User-Agent": "kingfisher-release (https://github.com/mongodb/kingfisher)"},
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                # The endpoint's existence is the signal, not its urls/file list.
                if response.status != 200:
                    raise ValueError(f"Unexpected PyPI HTTP status {response.status}")
                return True
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return False
            if (error.code not in {408, 429} and not 500 <= error.code < 600
                    or attempt == 2):
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)


def git(root, *arguments):
    return subprocess.run(
        ["git", *arguments], cwd=root, check=True, capture_output=True, text=True, encoding="utf-8",
    ).stdout.strip()


def committed_toml(root, revision, path):
    return tomllib.loads(git(root, "show", f"{revision}:{path}"))


def lock_dependencies(lock):
    """Ignore CLI-only lock churn by comparing only the SDK dependency closure."""
    packages = lock["package"]
    by_name = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
    pending = [item for item in packages if item["name"] == "kingfisher-python"]
    if len(pending) != 1:
        raise ValueError("Cargo.lock must contain exactly one kingfisher-python package")
    selected = {}
    while pending:
        package = pending.pop()
        identity = (package["name"], package["version"], package.get("source", ""))
        if identity in selected:
            continue
        selected[identity] = package
        for dependency in package.get("dependencies", []):
            parts = dependency.split()
            candidates = by_name.get(parts[0], [])
            if len(parts) > 1:
                candidates = [item for item in candidates if item["version"] == parts[1]]
            if len(parts) > 2:
                candidates = [item for item in candidates
                              if item.get("source") == parts[2].strip("()")]
            if len(candidates) != 1:
                raise ValueError(f"Cannot resolve SDK lock dependency: {dependency}")
            pending.extend(candidates)
    return selected


def runtime_path(path):
    if path.startswith(("python/kingfisher_sdk/", "python/src/")):
        return not path.endswith((".pyc", ".md")) and "/__pycache__/" not in path
    if path in {"rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"}:
        return True
    for crate in SHARED_CRATES:
        prefix = f"crates/{crate}/"
        if path in {prefix + "Cargo.toml", prefix + "build.rs"}:
            return True
        if path.startswith((prefix + "src/", prefix + "build_support/")):
            return not path.endswith(".md")
    return (path.startswith(("crates/kingfisher-rules/data/", "crates/kingfisher-rules/generated/rules/"))
            and not path.endswith(".md")
            or path == "crates/kingfisher-rules/generated/builtin-rules.gz")


def runtime_changed(root, base, head):
    paths = git(root, "diff", "--name-only", "-z", "--no-renames", base, head, "--").split("\0")
    if "crates/kingfisher-core/Cargo.toml" in paths:
        # Reuse the strict recovery gate, not a blanket exception for manifest or
        # version edits. Source/dependency drift or unverified provenance falls
        # back to the normal SDK runtime checks and still requires a new release.
        try:
            crates_recovery.check_metadata(root, base, head)
        except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError):
            pass
        else:
            return False
    if any(runtime_path(path) for path in paths):
        return True
    if "Cargo.lock" in paths:
        if lock_dependencies(committed_toml(root, base, "Cargo.lock")) != lock_dependencies(
                committed_toml(root, head, "Cargo.lock")):
            return True
    if "Cargo.toml" in paths:
        before = committed_toml(root, base, "Cargo.toml")
        after = committed_toml(root, head, "Cargo.toml")
        # Root package/CLI dependency/docs edits do not change the SDK build.
        for key in ("package", "dependencies", "resolver"):
            if before.get("workspace", {}).get(key) != after.get("workspace", {}).get(key):
                return True
        for key in ("patch", "replace"):
            if before.get(key) != after.get(key):
                return True
        for profile in ("release", "python-release"):
            if before.get("profile", {}).get(profile) != after.get("profile", {}).get(profile):
                return True
    if "pyproject.toml" in paths:
        before = committed_toml(root, base, "pyproject.toml")
        after = committed_toml(root, head, "pyproject.toml")
        if before.get("build-system") != after.get("build-system"):
            return True
        if before.get("tool", {}).get("maturin") != after.get("tool", {}).get("maturin"):
            return True
        for key in ("requires-python", "dependencies", "optional-dependencies"):
            if before.get("project", {}).get(key) != after.get("project", {}).get(key):
                return True
    return False


def compare_source(root, event_name, event, head, version):
    if event_name == "push":
        base = event.get("before", "")
    elif event_name == "pull_request":
        base = event.get("pull_request", {}).get("base", {}).get("sha", "")
    else:
        return False, False
    if not SHA.fullmatch(base) or base == "0" * 40:
        raise ValueError("A committed push.before / PR base SHA is required for SDK source comparison")
    previous = committed_toml(root, base, MANIFEST)["package"]["version"]
    current = committed_toml(root, head, MANIFEST)["package"]["version"]
    if current != version:
        raise ValueError("SDK manifest version must match the pinned committed source")
    return runtime_changed(root, base, head), previous == current


def publication_source(root, env, event, version):
    """Authorize publishing from the upstream main history, never a mutable ref."""
    event_name = env.get("GITHUB_EVENT_NAME")
    ref = env.get("GITHUB_REF", "")
    manual = event_name == "workflow_dispatch" and event.get("inputs", {}).get("publish") in (True, "true")
    automatic = event_name == "push" and (ref == "refs/heads/main" or ref.startswith("refs/tags/python-v"))
    if not (manual or automatic):
        return False, False
    if env.get("GITHUB_REPOSITORY") != UPSTREAM:
        if manual:
            raise ValueError("SDK publication requires the upstream mongodb/kingfisher repository")
        return False, False
    head = git(root, "rev-parse", "HEAD")
    if not SHA.fullmatch(env.get("GITHUB_SHA", "")) or head != env["GITHUB_SHA"]:
        raise ValueError("SDK publication checkout must match the pinned GITHUB_SHA")
    inputs = event.get("inputs", {})
    if manual:
        if ref != "refs/heads/main":
            raise ValueError("Manual SDK publication requires refs/heads/main")
        if not SHA.fullmatch(inputs.get("expected_sha", "")) or inputs["expected_sha"] != head:
            raise ValueError("expected_sha must be the full pinned main checkout SHA")
        if inputs.get("expected_version") != version:
            raise ValueError("expected_version must match the SDK manifest version")
    if ref.startswith("refs/tags/python-v") and ref != "refs/tags/python-v" + version:
        raise ValueError("SDK release tag must match the SDK manifest version")
    # Read-only fetch: the checkout's origin is created by actions/checkout for
    # this verified upstream repository. Do not trust a stale local main ref.
    git(root, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main")
    main = git(root, "rev-parse", "refs/remotes/origin/main")
    git(root, "merge-base", "--is-ancestor", head, main)
    if manual and main != head:
        raise ValueError("expected_sha is no longer the current upstream main SHA")
    return True, manual


def workflow_plan(root, env, event, version):
    publish, manual = publication_source(root, env, event, version)
    event_name = env.get("GITHUB_EVENT_NAME")
    if not publish:
        # PRs remain test-only, even on forks. Runtime changes must not silently
        # reuse a published version; docs/tests-only changes retain all tests.
        if event_name == "pull_request":
            changed, same = compare_source(root, event_name, event, git(root, "rev-parse", "HEAD"), version)
            if changed and version_exists(version):
                raise ValueError(f"SDK runtime/shared inputs changed but {version} already exists on PyPI; bump SDK version")
        return {"build": True, "publish": False, "version": version}
    changed = same = False
    if event_name == "push" and env.get("GITHUB_REF") == "refs/heads/main":
        changed, same = compare_source(root, event_name, event, env["GITHUB_SHA"], version)
    exists = version_exists(version)
    if exists and manual:
        raise ValueError(f"SDK {version} already exists on PyPI; bump SDK version before publishing")
    if exists and changed:
        raise ValueError(f"SDK runtime/shared inputs changed but {version} already exists on PyPI; bump SDK version")
    if exists:
        print(f"SDK {version} already exists on PyPI; unchanged publication is a no-op before native builds.")
    return {"build": not exists, "publish": not exists, "version": version}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-new", action="store_true", help="fail if the PyPI version exists")
    parser.add_argument("--expected-version", help="require this exact SDK manifest version")
    parser.add_argument("--github-event", action="store_true", help="validate GitHub source and plan the build DAG")
    args = parser.parse_args(argv)
    version = sdk_version(ROOT)
    if args.expected_version is not None and args.expected_version != version:
        raise ValueError(f"Expected SDK version {args.expected_version}, manifest has {version}")
    if args.github_event:
        with Path(os.environ["GITHUB_EVENT_PATH"]).open(encoding="utf-8") as stream:
            event = json.load(stream)
        plan = workflow_plan(ROOT, os.environ, event, version)
    else:
        exists = version_exists(version)
        if exists and args.require_new:
            raise ValueError(f"SDK {version} already exists on PyPI; bump SDK version")
        print(f"SDK {version}: {'already exists on' if exists else 'not yet on'} PyPI (read-only check)")
        plan = {"build": not exists, "publish": not exists, "version": version}
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in plan.items():
                stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print(f"SDK release preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
