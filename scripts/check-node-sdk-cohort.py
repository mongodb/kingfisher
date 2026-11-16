#!/usr/bin/env python3
"""Read-only authorization for the top-level npm workflow's gated artifact bridge.

Validate the producer run and its attempt-aware gates before downloading or
executing its archives. This checker never changes refs, dispatches workflows,
requests OIDC credentials, or writes to a package registry.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = "mongodb/kingfisher"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
NODE_WORKFLOW = ".github/workflows/node-sdk.yml"
DISPATCH_JOB = "Publish npm packages through the existing trusted workflow"
GATE_JOBS = ("Release build gate", "Authorize the complete release cohort")
ARTIFACT_NAME = "node-sdk-registry-staging"
API_VERSION = "2026-03-10"

_spec = importlib.util.spec_from_file_location("npm_cohort_release_source", ROOT / "scripts/check-release-source.py")
source = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(source)


def positive_id(value, label):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{label} must be a positive numeric ID")
    value = str(value)
    if re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
        raise ValueError(f"{label} must be a positive numeric ID")
    return value


def github_json(path, token):
    if not path.startswith(f"/repos/{UPSTREAM}/"):
        raise ValueError("GitHub requests must stay within the upstream repository")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "kingfisher-npm-cohort",
               "X-GitHub-Api-Version": API_VERSION}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(f"https://api.github.com{path}", headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(8 * 1024 * 1024 + 1)
    if len(payload) > 8 * 1024 * 1024:
        raise ValueError("GitHub response exceeds the metadata size limit")
    result = json.loads(payload)
    if not isinstance(result, dict):
        raise ValueError("GitHub metadata must be an object")
    return result


def remote_tag_commit(tag, token, *, api=github_json):
    """Read an exact ref and safely peel annotated tags; only a ref 404 is absent."""
    ref = f"refs/tags/{tag}"
    path = f"/repos/{UPSTREAM}/git/ref/tags/{urllib.parse.quote(tag, safe='')}"
    try:
        metadata = api(path, token)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise
    if not isinstance(metadata, dict) or metadata.get("ref") != ref:
        raise ValueError("GitHub returned a different npm tag ref")
    target = metadata.get("object", {})
    seen = set()
    for _ in range(16):
        sha = target.get("sha")
        if not source.full_sha(sha):
            raise ValueError("npm tag must identify a full nonzero Git SHA")
        if target.get("type") == "commit":
            return sha
        if target.get("type") != "tag" or sha in seen:
            raise ValueError("npm tag must resolve to a commit without tag cycles")
        seen.add(sha)
        annotated = api(f"/repos/{UPSTREAM}/git/tags/{sha}", token)
        if annotated.get("sha") != sha:
            raise ValueError("Annotated npm tag object SHA mismatch")
        target = annotated.get("object", {})
    raise ValueError("npm tag has too many annotated tag indirections")


def attempt_jobs(run_id, attempt, token, *, api=github_json):
    jobs = []
    page = 1
    while True:
        batch = api(f"/repos/{UPSTREAM}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100&page={page}", token).get("jobs")
        if not isinstance(batch, list) or any(not isinstance(job, dict) for job in batch):
            raise ValueError("Producer job metadata must contain an attempt-scoped jobs list")
        if any("run_attempt" in job and str(job["run_attempt"]) != str(attempt) for job in batch):
            raise ValueError("Producer jobs belong to a different run attempt")
        jobs.extend(batch)
        if len(batch) < 100:
            return jobs
        page += 1


def validate_parent(run_id, attempt, sha, token, *, api=github_json):
    """Require current dispatch authorization and effective successful prerequisites.

    Failed-job reruns retain successful prerequisites from earlier attempts. A
    missing gate can reuse its most recent occurrence, never an older success
    behind a newer failed/skipped/pending gate. The dispatcher itself must run in
    the exact current attempt, and all attempts have the same immutable source.
    """
    run_id = positive_id(run_id, "release_run_id")
    attempt = positive_id(attempt, "release_run_attempt")
    if not source.full_sha(sha):
        raise ValueError("The release cohort requires a full source SHA")
    prefix = f"/repos/{UPSTREAM}/actions"
    workflow = api(f"{prefix}/workflows/release.yml", token)
    run = api(f"{prefix}/runs/{run_id}", token)
    repository, head_repository = run.get("repository", {}), run.get("head_repository", {})
    if (workflow.get("path") != RELEASE_WORKFLOW or not workflow.get("id")
            or run.get("workflow_id") != workflow["id"] or run.get("path") != RELEASE_WORKFLOW
            or str(run.get("id")) != run_id or str(run.get("run_attempt")) != attempt
            or repository.get("full_name") != UPSTREAM or head_repository.get("full_name") != UPSTREAM
            or not repository.get("id") or head_repository.get("id") != repository["id"]
            or run.get("head_sha") != sha or run.get("event") not in {"push", "workflow_dispatch"}):
        raise ValueError("Producer must be the exact upstream release workflow run/attempt and SHA")
    if (run.get("status") not in {"in_progress", "completed"}
            or run.get("conclusion") not in {None, "success"}
            or (run.get("status") == "completed" and run.get("conclusion") != "success")):
        raise ValueError("Producer release run failed, was cancelled, or is not eligible")
    current_attempt = int(attempt)
    jobs = attempt_jobs(run_id, current_attempt, token, api=api)
    dispatchers = [job for job in jobs if job.get("name") == DISPATCH_JOB]
    if len(dispatchers) != 1 or not (
            (dispatchers[0].get("status") == "in_progress" and dispatchers[0].get("conclusion") is None)
            or (dispatchers[0].get("status") == "completed" and dispatchers[0].get("conclusion") == "success")):
        raise ValueError("Producer npm dispatcher must be running or successful, never skipped")
    attempts = {current_attempt: jobs}
    selected = {}
    for name in GATE_JOBS:
        for job_attempt in range(current_attempt, 0, -1):
            if job_attempt not in attempts:
                attempts[job_attempt] = attempt_jobs(run_id, job_attempt, token, api=api)
            matches = [job for job in attempts[job_attempt] if job.get("name") == name]
            if matches:
                break
        if (len(matches) != 1 or matches[0].get("status") != "completed"
                or matches[0].get("conclusion") != "success"):
            raise ValueError(f"Producer gate must have succeeded exactly once: {name}")
        selected[name] = job_attempt
    if selected[GATE_JOBS[1]] < selected[GATE_JOBS[0]]:
        raise ValueError("Producer authorization cannot predate its effective release build gate")
    return run


def validate_artifact(artifact_id, run, sha, token, *, api=github_json):
    artifact_id = positive_id(artifact_id, "artifact_id")
    artifact = api(f"/repos/{UPSTREAM}/actions/artifacts/{artifact_id}", token)
    producer = artifact.get("workflow_run", {})
    if (str(artifact.get("id")) != artifact_id or artifact.get("name") != ARTIFACT_NAME
            or artifact.get("expired") is not False or producer.get("id") != run["id"]
            or producer.get("head_sha") != sha):
        raise ValueError("npm staging artifact must belong to the validated producer run and SHA")
    for key in ("repository_id", "head_repository_id"):
        if key in producer and producer[key] != run["repository"]["id"]:
            raise ValueError("npm staging artifact belongs to a different repository")
    digest = artifact.get("digest")
    if digest is not None and (not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None):
        raise ValueError("npm staging artifact digest must be a SHA-256 digest")
    return artifact


def checked_checkout(root, env):
    sha = env.get("GITHUB_SHA")
    if env.get("GITHUB_REPOSITORY") != UPSTREAM:
        raise ValueError("npm cohort publication requires the upstream repository")
    if not source.full_sha(sha) or source.git(root, "rev-parse", "HEAD") != sha:
        raise ValueError("Checkout must match the full pinned GITHUB_SHA")
    return sha


def validate_cohort(root, env, event, *, api=github_json):
    sha = checked_checkout(root, env)
    inputs = event.get("inputs")
    if (env.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or not isinstance(inputs, dict)
            or not source.enabled(inputs.get("publish"))
            or event.get("repository", {}).get("full_name") != UPSTREAM):
        raise ValueError("npm cohort publication requires an authorized upstream workflow dispatch")
    version = source.manifest_version(root, "npm", sha)
    ref = f"refs/tags/npm-v{version}"
    if (env.get("GITHUB_REF") != ref
            or env.get("GITHUB_WORKFLOW_REF") != f"{UPSTREAM}/{NODE_WORKFLOW}@{ref}"):
        raise ValueError("npm publisher must be the original top-level Node SDK workflow at its exact version tag")
    if inputs.get("expected_sha") != sha:
        raise ValueError("expected_sha must match the immutable npm tag workflow SHA")
    run_id = positive_id(inputs.get("release_run_id"), "release_run_id")
    attempt = positive_id(inputs.get("release_run_attempt"), "release_run_attempt")
    artifact_id = positive_id(inputs.get("artifact_id"), "artifact_id")
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN", "")
    source.git(root, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main")
    main = source.git(root, "rev-parse", "refs/remotes/origin/main")
    if not source.full_sha(main):
        raise ValueError("Cannot resolve the current upstream main SHA")
    source.git(root, "merge-base", "--is-ancestor", sha, main)
    run = validate_parent(run_id, attempt, sha, token, api=api)
    artifact = validate_artifact(artifact_id, run, sha, token, api=api)
    if remote_tag_commit(f"npm-v{version}", token, api=api) != sha:
        raise ValueError("The current remote npm version tag no longer identifies the gated source SHA")
    result = {"run_id": run_id, "artifact_id": artifact_id}
    if artifact.get("digest") is not None:
        result["artifact_digest"] = artifact["digest"]
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = validate_cohort(ROOT, os.environ, event)
    print(json.dumps(result, sort_keys=True))
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError) as error:
        print(f"npm release cohort validation failed: {error}", file=sys.stderr)
        sys.exit(1)
