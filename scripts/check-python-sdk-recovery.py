#!/usr/bin/env python3
"""Authorize artifact-only SDK publication without rebuilding or registry writes.

Run from release.yml's pinned current-main checkout. The original producer SHA,
run/attempt and immutable pending artifact must be explicitly reviewed and pinned.
With --dist, also verify the downloaded distributions before requesting PyPI OIDC.
Requires Python 3.11+; never installs or executes recovered package contents.
"""
import argparse
from datetime import datetime, timezone
from email.parser import BytesParser
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "mongodb/kingfisher"
WORKFLOW = ".github/workflows/release.yml"
PACKAGE = "kingfisher-secret-scanner"
DIST_NAME = "kingfisher_secret_scanner"
ARTIFACT_NAME = "python-sdk-pending"
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "x86_64-apple-darwin", "aarch64-apple-darwin",
           "x86_64-pc-windows-gnu", "aarch64-pc-windows-gnullvm")
PREFLIGHT = "python-sdk / Read-only SDK release preflight"
PLAN = "python-sdk / plan-publish"
BUILD_GATE = "Release build gate"
PUBLISH_GATE = "Authorize the complete release cohort"
SDK_BUILDS = ("python-sdk / source",) + tuple(f"python-sdk / Wheel ({target})" for target in TARGETS)
SDK_CACHES = tuple(f"python-sdk / Cache portability ({target})" for target in TARGETS)
REQUIRED_JOBS = ("Verify release ref and version", PREFLIGHT, *SDK_BUILDS,
                 *SDK_CACHES, PLAN, BUILD_GATE, PUBLISH_GATE)
PUBLISH_JOBS = {"publish-python-sdk / publish", "Publish Python SDK to PyPI"}
RECOVERY_FILES = {".github/workflows/release.yml", ".github/workflows/python-sdk.yml",
                  ".github/workflows/pypi.yml", ".github/RELEASING.md",
                  "scripts/check-python-sdk-recovery.py", "scripts/check-release-source.py",
                  "scripts/publish-crates.py"}
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAX_METADATA = 2 * 1024 * 1024
MAX_ARTIFACT = 1024 * 1024 * 1024
MAX_ATTEMPTS = 20

_spec = importlib.util.spec_from_file_location("python_recovery_source", ROOT / "scripts/check-release-source.py")
source = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(source)


def positive_id(value, label):
    if isinstance(value, bool) or not isinstance(value, (str, int)) or re.fullmatch(
            r"[1-9][0-9]{0,19}", str(value)) is None:
        raise ValueError(f"{label} must be a positive numeric ID")
    return str(value)


def github_json(path, token):
    if not path.startswith(f"/repos/{UPSTREAM}/"):
        raise ValueError("GitHub requests must stay within the upstream repository")
    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
        "User-Agent": "kingfisher-python-sdk-recovery", "X-GitHub-Api-Version": "2026-03-10"})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(8 * 1024 * 1024 + 1)
    if len(payload) > 8 * 1024 * 1024:
        raise ValueError("GitHub metadata exceeds the response size limit")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("GitHub metadata must be an object")
    return result


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Missing GitHub timestamp")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("GitHub timestamps must include a timezone")
    return result


def job_interval(job):
    start, end = timestamp(job.get("started_at")), timestamp(job.get("completed_at"))
    if start > end:
        raise ValueError("Producer job timestamps are out of order")
    return start, end


def attempt_jobs(run_id, attempt, token, *, api):
    jobs, seen = [], set()
    for page in range(1, 21):
        batch = api(f"/repos/{UPSTREAM}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}", token).get("jobs")
        if not isinstance(batch, list) or len(batch) > 100:
            raise ValueError("Producer metadata must contain an attempt-scoped jobs list")
        for job in batch:
            if (not isinstance(job, dict) or str(job.get("run_id")) != run_id
                    or str(job.get("run_attempt")) != str(attempt)):
                raise ValueError("Producer job belongs to a different run or attempt")
            job_id = positive_id(job.get("id"), "job ID")
            if job_id in seen:
                raise ValueError("Duplicate producer job ID")
            seen.add(job_id)
        jobs.extend(batch)
        if len(batch) < 100:
            return jobs
    raise ValueError("Producer job pagination exceeds the safety limit")


def validate_producer(run_id, attempt, sha, artifact_id, token, *, api=github_json, now=None):
    """Check effective gates, never falling back past a newer unsuccessful job."""
    run_id = positive_id(run_id, "release_run_id")
    attempt = positive_id(attempt, "release_run_attempt")
    artifact_id = positive_id(artifact_id, "artifact_id")
    if not source.full_sha(sha) or int(attempt) > MAX_ATTEMPTS:
        raise ValueError("Producer requires a full SHA and at most 20 run attempts")
    now = now or datetime.now(timezone.utc)
    prefix = f"/repos/{UPSTREAM}/actions"
    workflow, run = api(f"{prefix}/workflows/release.yml", token), api(f"{prefix}/runs/{run_id}", token)
    repository, head_repository = run.get("repository") or {}, run.get("head_repository") or {}
    repo_id = positive_id(repository.get("id"), "upstream repository ID")
    if (workflow.get("path") != WORKFLOW or not workflow.get("id")
            or run.get("workflow_id") != workflow["id"] or run.get("path") != WORKFLOW
            or str(run.get("id")) != run_id or str(run.get("run_attempt")) != attempt
            or run.get("head_sha") != sha or repository.get("full_name") != UPSTREAM
            or head_repository.get("full_name") != UPSTREAM or str(head_repository.get("id")) != repo_id
            or run.get("event") not in {"push", "workflow_dispatch"}
            or run.get("status") != "completed" or run.get("conclusion") not in {"success", "failure"}):
        raise ValueError("Producer must be the exact completed upstream release workflow run/attempt and SHA")
    branch = run.get("head_branch")
    ref = "refs/heads/main" if branch == "main" else f"refs/tags/{branch}"
    if not source.supported_ref(ref):
        raise ValueError("Producer must use main or a supported release tag")
    attempts = {}

    def effective(names, *, upload=False):
        for number in range(int(attempt), 0, -1):
            if number not in attempts:
                attempts[number] = attempt_jobs(run_id, number, token, api=api)
            matches = [job for job in attempts[number] if job.get("name") in names]
            if matches:
                break
        if (len(matches) != 1 or matches[0].get("status") != "completed"
                or matches[0].get("conclusion") not in ({"success", "failure"} if upload else {"success"})):
            raise ValueError(f"Producer requires one completed {'authorized upload' if upload else 'successful gate'}: {sorted(names)}")
        if job_interval(matches[0])[1] > now:
            raise ValueError("Producer job completed in the future")
        return matches[0]

    selected = {name: effective({name}) for name in REQUIRED_JOBS}
    publisher = effective(PUBLISH_JOBS, upload=True)
    plan_start, plan_end = job_interval(selected[PLAN])
    if (any(job_interval(selected[name])[1] > plan_start for name in (PREFLIGHT, *SDK_BUILDS, *SDK_CACHES))
            or plan_end > job_interval(selected[BUILD_GATE])[0]
            or job_interval(selected[BUILD_GATE])[1] > job_interval(selected[PUBLISH_GATE])[0]
            or job_interval(selected[PUBLISH_GATE])[1] > job_interval(publisher)[0]):
        raise ValueError("Producer SDK tests, staging, build gate and authorization are out of order")
    artifact = api(f"{prefix}/artifacts/{artifact_id}", token)
    origin = artifact.get("workflow_run") or {}
    digest, size = artifact.get("digest"), artifact.get("size_in_bytes")
    if (str(artifact.get("id")) != artifact_id or artifact.get("name") != ARTIFACT_NAME
            or artifact.get("expired") is not False or str(origin.get("id")) != run_id
            or origin.get("head_sha") != sha or origin.get("head_branch") != branch
            or str(origin.get("repository_id")) != repo_id or str(origin.get("head_repository_id")) != repo_id
            or not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            or digest == "sha256:" + "0" * 64
            or isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT):
        raise ValueError("Recovery requires the exact unexpired, digest-pinned upstream pending artifact")
    if not plan_start <= timestamp(artifact.get("created_at")) <= plan_end:
        raise ValueError("Artifact was not created by the successful SDK staging job")
    if timestamp(artifact.get("expires_at")) <= now:
        raise ValueError("SDK recovery artifact has expired")
    return {"run_id": run_id, "artifact_id": artifact_id, "artifact_digest": digest,
            "producer_ref": ref, "repository_id": repo_id}


def maintenance_path(path):
    """Publishing repair only: no SDK, manifest, lockfile, rules or build drift."""
    if "\\" in path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
        return False
    return (path in RECOVERY_FILES
            or re.fullmatch(r"scripts/tests/test_[a-z0-9_]+\.py", path) is not None
            or path.endswith(".md") and path.startswith(("docs/", "docs-site/docs/")))


def validate_recovery(root, env, event, *, api=github_json, git_fn=source.git, now=None):
    inputs = event.get("inputs") or {}
    if not isinstance(inputs, dict):
        raise ValueError("Recovery inputs must be an object")
    head, producer = env.get("GITHUB_SHA"), inputs.get("producer_sha")
    if (env.get("GITHUB_REPOSITORY") != UPSTREAM or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or env.get("GITHUB_WORKFLOW_REF") != f"{UPSTREAM}/{WORKFLOW}@refs/heads/main"
            or not source.full_sha(head) or env.get("GITHUB_WORKFLOW_SHA") != head
            or not source.enabled(inputs.get("sdk_only")) or not source.enabled(inputs.get("publish"))
            or source.enabled(inputs.get("crates_only"))):
        raise ValueError("SDK recovery requires explicit publish + sdk_only on the upstream current-main workflow")
    if not source.full_sha(producer) or inputs.get("expected_sha") != head:
        raise ValueError("Pin the original producer_sha and current workflow expected_sha separately")
    if git_fn(root, "rev-parse", "HEAD") != head or git_fn(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Recovery requires an unchanged checkout of the pinned workflow SHA")
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("Read-only GitHub authentication is required")
    git_fn(root, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main")
    if git_fn(root, "rev-parse", "refs/remotes/origin/main") != head:
        raise ValueError("expected_sha is no longer the current upstream main SHA")
    git_fn(root, "merge-base", "--is-ancestor", producer, head)
    changed = git_fn(root, "diff", "--name-only", "--no-renames", "-z", producer, head).split("\0")
    for path in filter(None, changed):
        if not maintenance_path(path):
            raise ValueError(f"SDK recovery changes runtime or unapproved package inputs: {path}")
        entry = git_fn(root, "ls-tree", head, "--", path)
        previous = git_fn(root, "ls-tree", producer, "--", path)
        if (not entry.startswith(("100644 blob ", "100755 blob "))
                or previous and previous.split()[0] != entry.split()[0]):
            raise ValueError(f"Recovery must retain regular files and existing file modes: {path}")
    version = source.manifest_version(root, "python", producer, git_fn=git_fn)
    if (inputs.get("expected_version") != version
            or source.manifest_version(root, "python", head, git_fn=git_fn) != version):
        raise ValueError("expected_version and both SDK manifests must match the original stable version")
    result = validate_producer(inputs.get("release_run_id"), inputs.get("release_run_attempt"),
                               producer, inputs.get("artifact_id"), token, api=api, now=now)
    repository = event.get("repository") or {}
    if (repository.get("full_name") != UPSTREAM or str(repository.get("id")) != result.pop("repository_id")
            or str(env.get("GITHUB_RUN_ID")) == result["run_id"]):
        raise ValueError("Recovery event repository or producer run identity mismatch")
    if not source.validate_release_ref(root, result.pop("producer_ref"), producer,
                                       versions={"python": version}, git_fn=git_fn):
        raise ValueError("Original release ref does not match its source manifest")
    result["version"] = version
    return result


def package_metadata(payload, version):
    metadata = BytesParser().parsebytes(payload)
    names, versions = metadata.get_all("Name", []), metadata.get_all("Version", [])
    if (len(names) != 1 or re.sub(r"[-_.]+", "-", names[0]).lower() != PACKAGE
            or versions != [version]):
        raise ValueError("Distribution metadata must name the exact SDK project and version")


def bounded_read(stream):
    payload = stream.read(MAX_METADATA + 1)
    if len(payload) > MAX_METADATA:
        raise ValueError("Distribution metadata exceeds the size limit")
    return payload


def wheel_platform(platform):
    if match := re.fullmatch(r"manylinux(?:_[0-9]+_[0-9]+|2014)_(x86_64|aarch64)", platform):
        return "linux-" + match[1]
    if match := re.fullmatch(r"macosx_[0-9]+_[0-9]+_(x86_64|arm64)", platform):
        return "macos-" + match[1]
    if platform in {"win_amd64", "win_arm64"}:
        return platform
    raise ValueError(f"Unexpected SDK wheel platform: {platform}")


def published_digests(version):
    url = f"https://pypi.org/pypi/{PACKAGE}/{urllib.parse.quote(version, safe='')}/json"
    request = urllib.request.Request(url, headers={"User-Agent": "kingfisher-python-sdk-recovery"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            payload = response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return {}
        raise
    if len(payload) > 8 * 1024 * 1024:
        raise ValueError("PyPI metadata exceeds the response size limit")
    result = json.loads(payload)
    if (result.get("info", {}).get("name") != PACKAGE or result.get("info", {}).get("version") != version
            or not isinstance(result.get("urls"), list) or not result["urls"]):
        raise ValueError("PyPI version is reserved without valid matching distribution metadata")
    digests = {}
    for item in result["urls"]:
        name, digest = item.get("filename"), item.get("digests", {}).get("sha256")
        if not isinstance(name, str) or name in digests or not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValueError("PyPI must report unique filenames with SHA256 digests")
        digests[name] = digest
    return digests


def verify_registry(digests, version, *, registry=published_digests, require_published=False):
    """Do not let skip-existing hide a conflicting concurrent PyPI upload."""
    attempts = 5 if require_published else 1
    for attempt in range(attempts):
        try:
            published = registry(version)
        except (urllib.error.URLError, TimeoutError) as error:
            transient = not isinstance(error, urllib.error.HTTPError) or error.code in {408, 429} or 500 <= error.code < 600
            if not transient or attempt == attempts - 1:
                raise
        else:
            for name, digest in digests.items():
                if name in published and published[name] != digest:
                    raise ValueError(f"Existing immutable PyPI file differs from the original artifact: {name}")
            if not require_published or digests.keys() <= published.keys():
                return
            if attempt == attempts - 1:
                raise ValueError("Not all original artifact files are visible on PyPI after publication")
        time.sleep(2 ** attempt)


def verify_distributions(dist, version, *, registry=published_digests, require_published=False):
    """Inspect metadata only; reject extra files/platforms and immutable conflicts."""
    if not source.VERSION.fullmatch(version) or dist.is_symlink() or not dist.is_dir():
        raise ValueError("Recovery requires a stable version and a regular distribution directory")
    entries, platforms, digests = sorted(dist.iterdir()), set(), {}
    # The pinned publishing action writes these sidecars into dist while signing.
    # They are never accepted in a producer artifact or uploaded as packages.
    sidecars = [path for path in entries if require_published and path.name.endswith(".publish.attestation")]
    files = [path for path in entries if path not in sidecars]
    if not 1 <= len(files) <= 7:
        raise ValueError("Recovery requires one to seven originally staged SDK distributions")
    prefix = f"{DIST_NAME}-{version}"
    for path in files:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_ARTIFACT:
            raise ValueError("Recovered distributions must be nonempty regular files")
        if path.name == f"{prefix}.tar.gz":
            target = f"{prefix}/PKG-INFO"
            found, total_size = False, 0
            with tarfile.open(path, "r:gz") as archive:
                for index, member in enumerate(archive):
                    total_size += member.size
                    if index >= 10000 or total_size > MAX_ARTIFACT:
                        raise ValueError("Source distribution exceeds the archive size limit")
                    if member.name == target:
                        if found or not member.isfile() or member.size > MAX_METADATA:
                            raise ValueError("Source distribution requires one regular PKG-INFO")
                        with archive.extractfile(member) as stream:
                            package_metadata(bounded_read(stream), version)
                        found = True
            if not found:
                raise ValueError("Source distribution is missing its exact PKG-INFO")
            platform = "source"
        elif (match := re.fullmatch(re.escape(prefix) + r"-cp310-abi3-([a-zA-Z0-9_.]+)\.whl", path.name)):
            tags = match[1].split(".")
            variants = {wheel_platform(tag) for tag in tags}
            if len(variants) != 1 or len(tags) != len(set(tags)):
                raise ValueError("Wheel platform tags must identify one SDK target")
            platform = variants.pop()
            metadata_name, wheel_name = f"{prefix}.dist-info/METADATA", f"{prefix}.dist-info/WHEEL"
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                if len(names) > 10000 or len(names) != len(set(names)):
                    raise ValueError("Wheel entries must be unique and bounded")
                for name in (metadata_name, wheel_name):
                    if archive.getinfo(name).file_size > MAX_METADATA:
                        raise ValueError("Wheel metadata exceeds the size limit")
                with archive.open(metadata_name) as stream:
                    package_metadata(bounded_read(stream), version)
                with archive.open(wheel_name) as stream:
                    wheel = BytesParser().parsebytes(bounded_read(stream))
                if (wheel.get_all("Root-Is-Purelib") != ["false"]
                        or set(wheel.get_all("Tag", [])) != {f"cp310-abi3-{tag}" for tag in tags}):
                    raise ValueError("Wheel metadata tags must match the tested native SDK filename")
        else:
            raise ValueError(f"Unexpected file in SDK recovery artifact: {path.name}")
        if platform in platforms:
            raise ValueError("Recovery contains duplicate distributions for an SDK target")
        platforms.add(platform)
        with path.open("rb") as stream:
            digests[path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    for sidecar in sidecars:
        if (sidecar.name.removesuffix(".publish.attestation") not in digests
                or sidecar.is_symlink() or not sidecar.is_file()
                or not 0 < sidecar.stat().st_size <= MAX_METADATA):
            raise ValueError("Only the publisher's exact regular attestation sidecars are allowed after upload")
    verify_registry(digests, version, registry=registry, require_published=require_published)
    return digests


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, help="verify already downloaded original SDK distributions")
    parser.add_argument("--require-published", action="store_true", help="after upload, require every exact file hash on PyPI")
    args = parser.parse_args(argv)
    if args.require_published and args.dist is None:
        parser.error("--require-published requires --dist")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = validate_recovery(ROOT, os.environ, event)
    if args.dist is not None:
        result["verified_files"] = str(len(verify_distributions(
            args.dist, result["version"], require_published=args.require_published)))
    print(json.dumps(result, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError,
            tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"Python SDK recovery validation failed: {error}", file=sys.stderr)
        sys.exit(1)
