#!/usr/bin/env python3
"""Dispatch the existing trusted npm workflow after the shared release gate.

Never creates, moves, or deletes a ref. An existing npm version tag must point to
the exact producer SHA; other release routes simply skip npm when it does not.
The only remote write is workflow_dispatch, followed by watching that exact run.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cohort = helper("check-node-sdk-cohort")
node = helper("check-node-sdk-release")


def dispatch(root, env, event, *, api=None, runner=None):
    api = api or cohort.github_json
    runner = runner or subprocess.run
    sha = cohort.checked_checkout(root, env)
    ref = env.get("GITHUB_REF", "")
    if (env.get("GITHUB_WORKFLOW_REF") != f"{cohort.UPSTREAM}/{cohort.RELEASE_WORKFLOW}@{ref}"
            or event.get("repository", {}).get("full_name") != cohort.UPSTREAM):
        raise ValueError("Only the original upstream release coordinator can dispatch npm publication")
    version = cohort.source.manifest_version(root, "npm", sha)
    if env.get("NPM_VERSION") != version:
        raise ValueError("NPM_VERSION must match the committed SDK version")
    publish, _ = cohort.source.publication_source(root, env, event, versions={"npm": version})
    if not publish:
        raise ValueError("The producer event does not authorize normal SDK publication")
    run_id = cohort.positive_id(env.get("GITHUB_RUN_ID"), "release_run_id")
    attempt = cohort.positive_id(env.get("GITHUB_RUN_ATTEMPT"), "release_run_attempt")
    artifact_id = cohort.positive_id(env.get("NPM_ARTIFACT_ID"), "artifact_id")
    token = env.get("GH_TOKEN") or env.get("GITHUB_TOKEN", "")
    run = cohort.validate_parent(run_id, attempt, sha, token, api=api)
    if run.get("event") != env.get("GITHUB_EVENT_NAME") or run.get("head_branch") != ref.removeprefix(
            "refs/heads/").removeprefix("refs/tags/"):
        raise ValueError("Producer API event/ref must match the current coordinator event")
    cohort.validate_artifact(artifact_id, run, sha, token, api=api)
    tag = f"npm-v{version}"
    npm_ref = f"refs/tags/{tag}"

    def matching_tag():
        commit = cohort.remote_tag_commit(tag, token, api=api)
        if commit == sha:
            return True
        if ref == npm_ref:
            raise ValueError("The triggering npm tag is missing or no longer identifies this source SHA")
        print(f"Skip npm: existing {tag} must identify this exact release SHA; no tags are created or moved.")
        return False

    if not matching_tag():
        return {"dispatched": False, "reason": "no-matching-npm-tag"}
    # Re-run the normal read-only registry/provenance plan under the original
    # producer event, preserving guarded main and legacy manual CLI semantics.
    plan = node.workflow_plan(root, env, event, version)
    if not plan.get("publish"):
        print(f"Skip npm: SDK {version} is already published unchanged.")
        return {"dispatched": False, "reason": "already-published"}
    # The registry/ancestry preflight can take time: close tag movement races
    # before dispatch. The child independently checks its event SHA and tag.
    if not matching_tag():
        return {"dispatched": False, "reason": "no-matching-npm-tag"}
    payload = {
        "ref": tag,
        "return_run_details": True,
        "inputs": {"publish": True, "release_run_id": run_id,
                   "release_run_attempt": attempt, "expected_sha": sha, "artifact_id": artifact_id},
    }
    command_env = dict(env)
    command_env["GH_HOST"] = "github.com"
    result = runner(
        ["gh", "api", "--hostname", "github.com", "--method", "POST",
         f"/repos/{cohort.UPSTREAM}/actions/workflows/node-sdk.yml/dispatches",
         "-H", "Accept: application/vnd.github+json",
         "-H", f"X-GitHub-Api-Version: {cohort.API_VERSION}", "--input", "-"],
        input=json.dumps(payload), check=True, capture_output=True, text=True, encoding="utf-8", env=command_env,
    )
    response = json.loads(result.stdout)
    child_run_id = cohort.positive_id(response.get("workflow_run_id"), "dispatched workflow_run_id")
    print(f"Dispatched trusted npm workflow: https://github.com/{cohort.UPSTREAM}/actions/runs/{child_run_id}")
    # Leave API rate-limit headroom while waiting for protected npm approval.
    runner(["gh", "run", "watch", child_run_id, "--repo", cohort.UPSTREAM,
            "--exit-status", "--interval", "30"], check=True, env=command_env)
    return {"dispatched": True, "run_id": child_run_id}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    result = dispatch(ROOT, os.environ, event)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError) as error:
        print(f"npm workflow dispatch failed: {error}", file=sys.stderr)
        sys.exit(1)
