#!/usr/bin/env python3
"""Infer committed package versions and launch guarded publication, never retag.

Requires Python 3.11+, Git, authenticated GitHub CLI, and Cargo for crates. Registry
checks and source planning run before dispatch/rerun. GitHub checks establish known
repository/workflow conditions, not external registry or OIDC authorization.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mongodb/kingfisher"
SDK_MANIFEST = "crates/kingfisher-python/Cargo.toml"
MANIFESTS = {
    "kingfisher-core": "crates/kingfisher-core/Cargo.toml",
    "kingfisher-rules": "crates/kingfisher-rules/Cargo.toml",
    "kingfisher-scanner": "crates/kingfisher-scanner/Cargo.toml",
    "kingfisher-bin": "Cargo.toml",
}
SHA = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
CRATES_JOB = "Publish crates.io packages"


class CommandError(RuntimeError):
    """Sanitized tool/transport failure, never an ineligible historical run."""


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publisher = helper("publish-crates")
recovery = helper("check-crates-recovery")


def command(args, root, *, check=True):
    result = subprocess.run(args, cwd=root, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        # In particular, never echo gh auth output or credential-bearing diagnostics.
        raise CommandError(f"{Path(args[0]).name} {args[1]} failed (exit {result.returncode}); "
                         "check authentication, permissions, network and local tool configuration")
    return result


def cargo_failure(stderr, returncode):
    """Keep the first Cargo error useful without dumping credential-bearing logs."""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", stderr)
    summary = next((line.strip() for line in text.splitlines()
                    if re.match(r"^\s*error(?:\[[^\]]+\])?:", line)), "")
    if not summary:
        return f"cargo package failed (exit {returncode}); no Cargo error summary was available"
    # Never include URLs, authorization headers, credential assignments, or known
    # secret environment values. Keep all other tool diagnostics private as before.
    for name, value in os.environ.items():
        if len(value) >= 4 and re.search(r"TOKEN|PASSWORD|PASSWD|SECRET|KEY|CREDENTIAL", name, re.I):
            summary = summary.replace(value, "[REDACTED]")
    summary = re.sub(r"(?:https?|ssh|git\+https?)://[^\s`'\"<>]+", "[REDACTED URL]", summary, flags=re.I)
    summary = re.sub(r"\bauthorization\s*[:=]\s*.*", "Authorization: [REDACTED]", summary, flags=re.I)
    summary = re.sub(
        r"\b[A-Za-z0-9_]*(?:token|password|passwd|secret|credential|api_key|private_key)[A-Za-z0-9_]*\s*[:=]\s*.*",
        "[REDACTED credentials]", summary, flags=re.I,
    )
    summary = "".join(character for character in summary if character.isprintable())
    return f"cargo package failed (exit {returncode}): {summary[:800]}"


def git(root, *args, check=True):
    return command(["git", *args], root, check=check)


def github(root, path):
    response = command(["gh", "api", "--hostname", "github.com", "-H",
                        "Accept: application/vnd.github+json", f"repos/{REPOSITORY}{path}"], root)
    try:
        return json.loads(response.stdout)
    except json.JSONDecodeError:
        raise CommandError("GitHub returned invalid JSON; cannot verify release readiness") from None


def clean_head(root):
    if git(root, "status", "--porcelain", "--untracked-files=normal").stdout:
        raise ValueError("Commit or stash local changes; package release requires a clean checkout")
    sha = git(root, "rev-parse", "HEAD").stdout.strip()
    if not SHA.fullmatch(sha):
        raise ValueError("Invalid committed HEAD")
    return sha


def committed_bytes(root, sha, path):
    result = subprocess.run(["git", "show", f"{sha}:{path}"], cwd=root,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise CommandError(f"Cannot read committed release metadata: {path}")
    return result.stdout


def committed(root, sha, path):
    return committed_bytes(root, sha, path).decode("utf-8")


def versions(root, sha):
    """Read Git objects, not editable manifest bytes or a user-supplied version."""
    manifests = {name: tomllib.loads(committed(root, sha, path)) for name, path in MANIFESTS.items()}
    root_manifest = manifests["kingfisher-bin"]
    workspace = root_manifest["workspace"]["package"]
    result = {}
    for name, manifest in manifests.items():
        package = manifest["package"]
        version = package["version"]
        if package["name"] != name or not VERSION.fullmatch(version):
            raise ValueError(f"Invalid committed package name/version: {name}")
        publish = package.get("publish")
        if publish == {"workspace": True}:
            publish = workspace.get("publish")
        if publish != ["crates-io"]:
            raise ValueError(f"{name} must be configured for crates-io publishing")
        result[name] = version
    sdk = tomllib.loads(committed(root, sha, SDK_MANIFEST))["package"]
    if sdk["name"] != "kingfisher-python" or not VERSION.fullmatch(sdk["version"]):
        raise ValueError("Invalid committed SDK package version")
    result["kingfisher-python"] = sdk["version"]
    project = tomllib.loads(committed(root, sha, "pyproject.toml"))
    if (project["project"]["name"] != "kingfisher-secret-scanner"
            or project["project"].get("dynamic") != ["version"]
            or "version" in project["project"]
            or project["tool"]["maturin"]["manifest-path"] != SDK_MANIFEST):
        raise ValueError("Root Python metadata must derive the SDK version from its Cargo manifest")
    lock = tomllib.loads(committed(root, sha, "Cargo.lock"))
    for name, version in result.items():
        entries = [p for p in lock["package"] if p["name"] == name and "source" not in p]
        if len(entries) != 1 or entries[0]["version"] != version:
            raise ValueError(f"Cargo.lock does not match the committed {name} version")
    for name, manifest in manifests.items():
        for dependency, config in manifest.get("dependencies", {}).items():
            if dependency in MANIFESTS and (not isinstance(config, dict)
                                          or config.get("version") != result[dependency]):
                raise ValueError(f"{name} must require the committed {dependency} version")
    provenance = json.loads(committed(root, sha, recovery.PROVENANCE))
    for path in recovery.PROVENANCE_INPUTS:
        actual = hashlib.sha256(committed_bytes(root, sha, path)).hexdigest()
        if provenance["generator_input_sha256"][path] != actual:
            raise ValueError(f"Stale rule-bundle provenance for {path}; regenerate before release")
    return result


def check_remote(root, remote):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", remote):
        raise ValueError("--remote must name the public mongodb/kingfisher Git remote")
    valid = {
        "https://github.com/mongodb/kingfisher", "https://github.com/mongodb/kingfisher.git",
        "git@github.com:mongodb/kingfisher", "git@github.com:mongodb/kingfisher.git",
        "ssh://git@github.com/mongodb/kingfisher", "ssh://git@github.com/mongodb/kingfisher.git",
    }
    for arguments in (("remote", "get-url", "--all", remote),
                      ("remote", "get-url", "--push", "--all", remote)):
        urls = git(root, *arguments).stdout.splitlines()
        if not urls or any(url not in valid for url in urls):
            raise ValueError("Release remote must identify public mongodb/kingfisher, not a fork or URL alias")


def selected_main(root, remote, sha):
    check_remote(root, remote)
    git(root, "fetch", "--no-tags", remote, "refs/heads/main")
    main = git(root, "rev-parse", "FETCH_HEAD").stdout.strip()
    ancestor = git(root, "merge-base", "--is-ancestor", sha, main, check=False)
    if ancestor.returncode == 1:
        raise ValueError("Committed HEAD must be merged into the public remote main branch")
    if ancestor.returncode:
        raise ValueError("Could not verify main ancestry")
    if main != sha:
        raise ValueError("Stale checkout: committed HEAD must equal the selected workflow main SHA")


def readiness(root, sha, workflow, inputs):
    if shutil.which("gh") is None:
        raise ValueError("Install GitHub CLI (gh) and authenticate with Actions write permission")
    command(["gh", "auth", "status", "--hostname", "github.com"], root)
    repo = github(root, "")
    if (repo["full_name"] != REPOSITORY or repo["private"] or repo.get("fork", False)
            or repo["default_branch"] != "main"):
        raise ValueError("Release requires the public mongodb/kingfisher repository with main as default")
    permissions = repo.get("permissions", {})
    if not any(permissions.get(name, False) for name in ("push", "maintain", "admin")):
        raise ValueError("Authenticated GitHub account needs repository write / Actions permission")
    if github(root, "/commits/main")["sha"] != sha:
        raise ValueError("Public main advanced or differs from selected HEAD; update and retry")
    state = github(root, f"/actions/workflows/{workflow}")
    path = f".github/workflows/{workflow}"
    if state["state"] != "active" or state["path"] != path:
        raise ValueError(f"{workflow} must be active in the public repository")
    remote = github(root, f"/contents/{path}?ref={sha}")
    if remote["encoding"] != "base64":
        raise ValueError("Cannot verify selected remote workflow contents")
    text = base64.b64decode(remote["content"], validate=False).decode()
    if text != committed(root, sha, path):
        raise ValueError("Selected remote workflow does not match committed HEAD")
    # This repository uses block YAML. Scope the check to workflow_dispatch.inputs,
    # rather than accepting an unrelated occurrence in a comment or job command.
    dispatch = re.search(r"(?m)^  workflow_dispatch:\s*\n((?:[ \t]+[^\n]*\n|\n)*)", text)
    supported = set()
    if dispatch:
        block = dispatch.group(1).splitlines()
        in_inputs = False
        for line in block:
            if line.startswith("    inputs:"):
                in_inputs = True
            elif in_inputs and line.strip() and len(line) - len(line.lstrip()) <= 4:
                break
            elif in_inputs:
                match = re.fullmatch(r"      ([A-Za-z_][A-Za-z0-9_]*):\s*(?:#.*)?", line)
                if match:
                    supported.add(match.group(1))
    if not set(inputs) <= supported:
        raise ValueError(f"{workflow} at main lacks guarded dispatch inputs: {', '.join(sorted(set(inputs) - supported))}")


def fresh_crates_plan(root, sha, inferred):
    if clean_head(root) != sha:
        raise ValueError("Checkout changed before crate planning; retry from the selected commit")
    # A cheap all-published check deliberately avoids even Cargo metadata/package.
    # A non-404 error is not an unpublished version and must stop the launcher.
    current = [publisher.published_version(name, inferred[name]) for name in publisher.PACKAGES]
    if all(info is not None for info in current):
        raise ValueError("All committed crate versions already exist; no release is pending")
    with tempfile.TemporaryDirectory(prefix="kingfisher-release-plan-") as temporary:
        staging = Path(temporary)
        checkout = staging / "source"
        hooks = staging / "hooks"
        hooks.mkdir()
        # Cargo's include globs can match ignored virtualenv/cache files even when
        # git status is clean. Package only the selected commit, just as CI does.
        # A private detached clone also leaves the caller's worktrees/refs alone.
        command(["git", "-c", f"core.hooksPath={hooks.as_posix()}",
                 "-c", f"init.templateDir={hooks.as_posix()}",
                 "clone", "--quiet", "--shared", "--no-checkout", "--",
                 root.resolve().as_posix(), checkout.as_posix()], root)
        command(["git", "-c", f"core.hooksPath={hooks.as_posix()}", "-c", "core.autocrlf=false",
                 "checkout", "--quiet", "--detach", sha], checkout)
        if clean_head(checkout) != sha:
            raise ValueError("Packaging checkout does not match the clean selected commit")
        metadata = json.loads(command(
            ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], checkout).stdout)
        for name in publisher.PACKAGES + ("kingfisher-python",):
            packages = [p for p in metadata["packages"] if p["name"] == name and p.get("source") is None]
            if len(packages) != 1 or packages[0]["version"] != inferred[name]:
                raise ValueError(f"Cargo metadata does not match committed {name}")
            expected_path = SDK_MANIFEST if name == "kingfisher-python" else MANIFESTS[name]
            if Path(packages[0]["manifest_path"]).resolve() != (checkout / expected_path).resolve():
                raise ValueError(f"Cargo metadata selects an unexpected manifest for {name}")
        target = staging / "target"
        target.mkdir()
        args = ["cargo", "package", "--locked", "--no-verify", "--target-dir", str(target)]
        for name in publisher.PACKAGES:
            args += ["-p", name]
        result = command(args, checkout, check=False)
        if result.returncode:
            raise CommandError(cargo_failure(result.stderr, result.returncode))
        # The existing planner validates EVERY fresh archive, skips only byte-equivalent
        # published payloads and rejects source conflicts before any remote action.
        plan = publisher.make_plan(metadata, target / "package")
    if not any(item["publish"] for item in plan):
        raise ValueError("No crate publication is pending; nothing was dispatched")
    return plan


def release_base(root, remote, tag):
    ref = f"refs/tags/{tag}"
    rows = git(root, "ls-remote", "--tags", remote, ref, ref + "^{}").stdout.splitlines()
    references = {}
    for row in rows:
        fields = row.split()
        if len(fields) != 2 or not SHA.fullmatch(fields[0]) or fields[1] not in {ref, ref + "^{}"}:
            raise ValueError("Invalid public release tag response")
        if fields[1] in references:
            raise ValueError("Ambiguous public release tag")
        references[fields[1]] = fields[0]
    if ref not in references or ref + "^{}" not in references:
        raise ValueError(f"Existing annotated public CLI tag {tag} is required; run a normal CLI release first")
    base = references[ref + "^{}"]
    local = git(root, "rev-parse", "--verify", "--quiet", ref, check=False)
    if local.returncode == 0 and local.stdout.strip() != references[ref]:
        raise ValueError(f"Local tag {tag} conflicts with the public tag; never retarget published tags")
    if local.returncode not in (0, 1):
        raise ValueError("Could not verify existing local tag")
    git(root, "fetch", "--no-tags", remote, ref)
    if git(root, "rev-parse", "FETCH_HEAD^{commit}").stdout.strip() != base:
        raise ValueError("Public tag changed during preflight; publication stopped")
    return base


def original_release(root, tag, base):
    runs = []
    page = 1
    while True:
        batch = github(root, f"/actions/workflows/release.yml/runs?head_sha={base}&branch={tag}&status=completed&per_page=100&page={page}")["workflow_runs"]
        runs.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    # Choose the earliest eligible tag run; later main recovery runs are never candidates.
    for run in sorted(runs, key=lambda item: int(item["id"])):
        run_id = str(run["id"])
        if not re.fullmatch(r"[1-9][0-9]*", run_id):
            raise ValueError("Invalid original release run ID")
        try:
            jobs = recovery.check_github(REPOSITORY, tag, base, run_id, "",
                                         api=lambda path, token: github(root, path.removeprefix(f"/repos/{REPOSITORY}")))
        except ValueError:
            continue
        crates = [job for job in jobs if job["name"] == CRATES_JOB]
        if len(crates) != 1 or crates[0]["status"] != "completed":
            continue
        return run_id, crates[0]
    raise ValueError("No original public tag release run has all required green build/test/release jobs")


def sdk_preflight(root, version):
    result = command([sys.executable, "scripts/check-sdk-release.py", "--require-new",
                      "--expected-version", version], root, check=False)
    if result.returncode:
        # Only recognize the helper's bounded, known registry conflict message.
        # Other stderr may include credentials from tool/network configuration.
        conflict = f"SDK {version} already exists on PyPI; bump SDK version"
        if conflict in result.stderr[:4096]:
            raise ValueError(conflict)
        raise ValueError(f"SDK preflight failed (exit {result.returncode}); cannot verify a new "
                         "PyPI version/source. Check PyPI availability and SDK metadata before retrying")


def unchanged_source(root, remote, sha, workflow, inputs):
    if clean_head(root) != sha:
        raise ValueError("Checkout changed during preflight; retry from the selected commit")
    selected_main(root, remote, sha)
    readiness(root, sha, workflow, inputs)
    if clean_head(root) != sha:
        raise ValueError("Checkout changed during readiness checks; retry from the selected commit")


def release(package, remote="origin", *, root=ROOT):
    root = Path(root)
    sha = clean_head(root)
    inferred = versions(root, sha)
    selected_main(root, remote, sha)
    if package == "kingfisher-secret-scanner":
        workflow = "python-sdk.yml"
        inputs = {"publish", "expected_sha", "expected_version"}
        readiness(root, sha, workflow, inputs)
        version = inferred["kingfisher-python"]
        sdk_preflight(root, version)
        unchanged_source(root, remote, sha, workflow, inputs)
        command(["gh", "workflow", "run", workflow, "--repo", REPOSITORY, "--ref", "main",
                 "-f", "publish=true", "-f", f"expected_sha={sha}", "-f", f"expected_version={version}"], root)
        print(f"Dispatched SDK {version} at {sha}; no tag was created or moved.")
    elif package == "crates":
        workflow = "release.yml"
        inputs = {"crates_only", "release_run_id", "expected_sha"}
        readiness(root, sha, workflow, inputs)
        tag = f"v{inferred['kingfisher-bin']}"
        base = release_base(root, remote, tag)
        ancestor = git(root, "merge-base", "--is-ancestor", base, sha, check=False)
        if ancestor.returncode:
            raise ValueError("Public release tag must be an ancestor of committed HEAD")
        if sha != base:
            recovery.check_metadata(root, base, sha)
        run_id, job = original_release(root, tag, base)
        if sha == base and job["conclusion"] != "failure":
            raise ValueError("Only the existing failed crates job may be rerun; no eligible job exists")
        plan = fresh_crates_plan(root, sha, inferred)
        for item in plan:
            print(f"{item['name']} {item['version']}: {'publish' if item['publish'] else 'skip (identical published version)'}")
        unchanged_source(root, remote, sha, workflow, inputs)
        # Recheck tag identity and prior public release gates immediately before mutation.
        if release_base(root, remote, tag) != base:
            raise ValueError("Public tag moved during planning; publication stopped")
        latest_jobs = recovery.check_github(REPOSITORY, tag, base, run_id, "",
                                            api=lambda path, token: github(root, path.removeprefix(f"/repos/{REPOSITORY}")))
        if clean_head(root) != sha:
            raise ValueError("Checkout changed before the remote action; retry")
        if sha == base:
            latest = [item for item in latest_jobs if item["name"] == CRATES_JOB]
            if (len(latest) != 1 or latest[0]["id"] != job["id"]
                    or latest[0]["status"] != "completed" or latest[0]["conclusion"] != "failure"):
                raise ValueError("Original failed crates job changed during preflight; retry")
            if not re.fullmatch(r"[1-9][0-9]*", str(job["id"])):
                raise ValueError("Invalid failed crate job ID")
            command(["gh", "run", "rerun", run_id, "--repo", REPOSITORY, "--job", str(job["id"])], root)
            print(f"Reran only the failed crates job in original release run {run_id}.")
        else:
            command(["gh", "workflow", "run", workflow, "--repo", REPOSITORY, "--ref", "main",
                     "-f", "crates_only=true", "-f", f"release_run_id={run_id}", "-f", f"expected_sha={sha}"], root)
            print(f"Dispatched metadata-only crates recovery at {sha}; {tag} and its assets remain unchanged.")
    else:
        raise ValueError("Select crates or kingfisher-secret-scanner")
    print("GitHub readiness checks passed; external registry/OIDC authorization is not proven until authenticated publication.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", choices=("crates", "kingfisher-secret-scanner"))
    parser.add_argument("--remote", default="origin", help="public GitHub Git remote (default: origin)")
    args = parser.parse_args()
    try:
        release(args.package, args.remote)
    except (CommandError, ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        # Command errors are already sanitized; never dump gh credential diagnostics.
        detail = "Git operation failed; check local repository configuration" if isinstance(error, subprocess.CalledProcessError) else str(error)
        print(f"Package release stopped: {detail}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
