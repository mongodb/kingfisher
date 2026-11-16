#!/usr/bin/env python3
"""Read-only npm SDK release preflight (Python 3.11+; no registry writes).

The central coordinator authorizes upstream main, manifest-matching release tags,
guarded manual main publication, and manual CLI-tag completion. Other runs are test-only.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "kingfisher-secret-scanner"
UPSTREAM = "mongodb/kingfisher"


def helper(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sdk = helper("check-sdk-release")
releases = helper("release-packages")


def registry_json(url, *, allow_missing=False):
    """Bounded read-only registry GET; only an allowed 404 means unused."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "kingfisher-release (https://github.com/mongodb/kingfisher)"},
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                if response.status != 200:
                    raise ValueError(f"Unexpected npm HTTP status {response.status}")
                payload = response.read(1024 * 1024 + 1)
                if len(payload) > 1024 * 1024:
                    raise ValueError("npm metadata exceeds the size limit")
                metadata = json.loads(payload)
                if not isinstance(metadata, dict):
                    raise ValueError("npm registry JSON must be an object")
                return metadata
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404 and allow_missing:
                return None
            if (error.code not in {408, 429} and not 500 <= error.code < 600
                    or attempt == 2):
                raise
        except (urllib.error.URLError, TimeoutError, OSError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)


def version_metadata(version):
    metadata = registry_json(
        f"https://registry.npmjs.org/{PACKAGE}/{urllib.parse.quote(version, safe='')}",
        allow_missing=True,
    )
    if metadata is not None and (metadata.get("name") != PACKAGE or metadata.get("version") != version):
        raise ValueError("npm registry package name/version mismatch")
    return metadata


def version_exists(version):
    return version_metadata(version) is not None


def published_source(root, metadata, version):
    """Read npm's recorded SLSA source, bound to this exact published tarball.

    The registry is the trust boundary for this read-only planning check; this is
    not a replacement for npm's consumer-side signature/provenance verification.
    """
    provenance_type = "https://slsa.dev/provenance/v1"
    attestations = registry_json(
        f"https://registry.npmjs.org/-/npm/v1/attestations/{PACKAGE}@{urllib.parse.quote(version, safe='')}"
    )
    matches = [item for item in attestations["attestations"] if item["predicateType"] == provenance_type]
    if len(matches) != 1:
        raise ValueError("Published npm version must have one recorded SLSA source; bump SDK version if absent")
    envelope = matches[0]["bundle"]["dsseEnvelope"]
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        raise ValueError("Unexpected npm provenance payload type")
    statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
    digest = base64.b64decode(metadata["dist"]["integrity"].removeprefix("sha512-"), validate=True)
    if (not metadata["dist"]["integrity"].startswith("sha512-") or len(digest) != 64
            or statement["predicateType"] != provenance_type
            or statement["subject"] != [{"name": f"pkg:npm/{PACKAGE}@{version}",
                                        "digest": {"sha512": digest.hex()}}]):
        raise ValueError("npm provenance must describe the exact published package/integrity")
    definition = statement["predicate"]["buildDefinition"]
    workflow = definition["externalParameters"]["workflow"]
    ref = workflow["ref"]
    event_name = definition["internalParameters"]["github"]["event_name"]
    if (workflow["repository"] != f"https://github.com/{UPSTREAM}"
            or workflow["path"] != ".github/workflows/node-sdk.yml"
            or not (ref == "refs/heads/main" or ref.startswith("refs/tags/npm-v"))
            or not (event_name == "push" or (event_name == "workflow_dispatch"
                    and ref.startswith("refs/tags/npm-v")))
            or statement["predicate"]["runDetails"]["builder"]["id"]
            != "https://github.com/actions/runner/github-hosted"):
        raise ValueError("npm provenance source must retain the upstream Node SDK trusted workflow")
    dependencies = definition["resolvedDependencies"]
    if len(dependencies) != 1 or dependencies[0]["uri"] != f"git+https://github.com/{UPSTREAM}@{ref}":
        raise ValueError("Unexpected npm provenance source dependency")
    commit = dependencies[0]["digest"]["gitCommit"]
    if not sdk.SHA.fullmatch(commit) or commit == "0" * 40:
        raise ValueError("Published npm source must name a full Git commit")
    sdk.git(root, "cat-file", "-e", f"{commit}^{{commit}}")
    if not sdk.release_source.validate_release_ref(
            root, ref, commit, versions={"npm": version}, git_fn=sdk.git):
        raise ValueError("Published npm source must use a validated supported release ref")
    if releases.npm_version(root, commit) != version:
        raise ValueError("Published npm source manifests must match the registry version")
    return commit


def packaged_path(path):
    if path.startswith("javascript/"):
        relative = path.removeprefix("javascript/")
        if "/" not in relative:
            return (relative.endswith((".cjs", ".mjs", ".d.ts"))
                    or relative.startswith(("LICENSE", "NOTICE"))
                    or relative in {"README.md", "THIRD_PARTY_NOTICES", ".npmignore", ".npmrc"})
        return relative.startswith(("lib/", "examples/", "npm/")) or relative in {
            "scripts/build.cjs", "scripts/prepare-package.cjs",
            "scripts/prepare-platforms.cjs", "scripts/collect-artifacts.cjs",
            "scripts/targets.cjs", "scripts/pack-release.cjs",
        }
    if path.startswith("crates/kingfisher-node/"):
        relative = path.removeprefix("crates/kingfisher-node/")
        return relative in {"Cargo.toml", "build.rs"} or relative.startswith("src/")
    if path.startswith("crates/kingfisher-python/") or path.startswith("python/"):
        return False
    return sdk.runtime_path(path) or path in {
        ".gitattributes", ".npmrc", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES",
        "crates/kingfisher-rules/LICENSE",
        "third-party/kingfisher-vectorscan/NOTICE", "third-party/kingfisher-vectorscan/LICENSE-VECTORSCAN",
        "third-party/kingfisher-vectorscan/LICENSE-APACHE", "third-party/kingfisher-vectorscan/LICENSE-MIT",
    }


def runtime_changed(root, base, head):
    paths = sdk.git(root, "diff", "--name-only", "-z", "--no-renames", base, head, "--").split("\0")
    if any(packaged_path(path) for path in paths):
        return True
    if "javascript/package.json" in paths:
        # Development-only metadata is stripped, but build/staging commands and
        # their npm lifecycle hooks can change the actual packaged bytes.
        def manifest(revision):
            value = json.loads(sdk.git(root, "show", f"{revision}:javascript/package.json"))
            commands = {"build", "prepare:package", "prepare:platforms", "collect:artifacts", "pack:release"}
            relevant = {f"{prefix}{command}" for command in commands for prefix in ("", "pre", "post")}
            return {**{key: item for key, item in value.items()
                       if key not in {"scripts", "devDependencies", "private"}},
                    "scripts": {key: item for key, item in value.get("scripts", {}).items() if key in relevant}}
        if manifest(base) != manifest(head):
            return True
    if "Cargo.lock" in paths:
        if sdk.lock_dependencies(sdk.committed_toml(root, base, "Cargo.lock"), "kingfisher-node") != sdk.lock_dependencies(
                sdk.committed_toml(root, head, "Cargo.lock"), "kingfisher-node"):
            return True
    if "Cargo.toml" in paths:
        before = sdk.committed_toml(root, base, "Cargo.toml")
        after = sdk.committed_toml(root, head, "Cargo.toml")
        for key in ("package", "dependencies", "resolver"):
            if before.get("workspace", {}).get(key) != after.get("workspace", {}).get(key):
                return True
        for key in ("patch", "replace"):
            if before.get(key) != after.get(key):
                return True
        for profile in ("release", "node-release"):
            if before.get("profile", {}).get(profile) != after.get("profile", {}).get(profile):
                return True
    return False


def compare_source(root, env, event):
    event_name = env.get("GITHUB_EVENT_NAME")
    if event_name == "pull_request":
        base = event.get("pull_request", {}).get("base", {}).get("sha", "")
    elif event_name == "push" and env.get("GITHUB_REF") == "refs/heads/main":
        base = event.get("before", "")
    else:
        return False
    if not sdk.SHA.fullmatch(base) or base == "0" * 40:
        raise ValueError("A committed push.before / PR base SHA is required for npm source comparison")
    return runtime_changed(root, base, sdk.git(root, "rev-parse", "HEAD"))


def publication_source(root, env, version, event=None):
    publish, _ = sdk.release_source.publication_source(
        root, env, event or {}, versions={"npm": version}, git_fn=sdk.git)
    return publish


def workflow_plan(root, env, event, version):
    publish = publication_source(root, env, version, event)
    changed = compare_source(root, env, event)
    metadata = version_metadata(version) if publish or changed else None
    exists = metadata is not None
    if exists:
        baseline = published_source(root, metadata, version)
        # Compare the release itself, not just push.before: otherwise an unrelated
        # later push hides unresolved drift, while a successful rerun fails on its
        # own version bump. This also covers tag/main races for the same source.
        if runtime_changed(root, baseline, sdk.git(root, "rev-parse", "HEAD")):
            raise ValueError(f"npm SDK packaged/shared inputs changed but {version} already exists; bump SDK version")
    if publish and exists:
        print(f"npm SDK {version} already exists; unchanged publication is a no-op before native builds.")
    return {"build": not (publish and exists), "publish": publish and not exists, "version": version}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-event", action="store_true", help="validate GitHub source and emit build/publish outputs")
    args = parser.parse_args(argv)
    version = releases.npm_version(ROOT, sdk.git(ROOT, "rev-parse", "HEAD"))
    if args.github_event:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        plan = workflow_plan(ROOT, os.environ, event, version)
    else:
        exists = version_exists(version)
        print(f"npm SDK {version}: {'already exists' if exists else 'not yet published'} (read-only check)")
        # A local/read-only invocation never authorizes GitHub publication.
        plan = {"build": not exists, "publish": False, "version": version}
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in plan.items():
                stream.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, AttributeError, subprocess.CalledProcessError,
            releases.CommandError) as error:
        print(f"npm SDK release preflight failed: {error}", file=sys.stderr)
        sys.exit(1)
