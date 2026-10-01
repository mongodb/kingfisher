#!/usr/bin/env python3
"""Plan or publish the four crates, in dependency order. Planning is read-only.

Requires Python 3.11+, Cargo, and archives produced by `cargo package` for the four
packages in PACKAGES. Never logs or stores registry credentials.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ("kingfisher-core", "kingfisher-rules", "kingfisher-scanner", "kingfisher-bin")
USER_AGENT = "kingfisher-release (https://github.com/mongodb/kingfisher)"
API = "https://crates.io/api/v1/crates"


def fetch(url, *, missing_ok=False, timeout=60, attempts=2):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            error.close()
            if missing_ok and error.code == 404:
                return None
            if (error.code not in {408, 429} and not 500 <= error.code < 600
                    or attempt + 1 == attempts):
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt + 1 == attempts:
                raise
        time.sleep(1)


def published_version(name, version):
    body = fetch(f"{API}/{name}/{version}", missing_ok=True)
    if body is None:
        return None
    info = json.loads(body)["version"]
    if info["num"] != version or info["crate"] != name:
        raise ValueError(f"Unexpected registry response for {name} {version}")
    if info["yanked"]:
        raise ValueError(f"{name} {version} is yanked; choose a new version")
    return info


def archive_contents(data, name, version):
    """Compare shipped files, not tar timestamps or Cargo's checkout bookkeeping."""
    prefix = f"{name}-{version}/"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            if member.isdir():
                continue
            if not member.isfile() or not member.name.startswith(prefix):
                raise ValueError(f"Unexpected archive entry: {member.name}")
            path = member.name[len(prefix):]
            if path in {".cargo_vcs_info.json", "Cargo.toml.orig"}:
                continue
            # Library consumers resolve dependencies using their own lockfile.
            # The binary's lockfile remains part of its reproducible install contract.
            if name != "kingfisher-bin" and path == "Cargo.lock":
                continue
            value = archive.extractfile(member).read()
            if path == "Cargo.toml":
                value = json.dumps(tomllib.loads(value.decode()), sort_keys=True).encode()
            if name == "kingfisher-rules" and path == "generated/provenance.json":
                provenance = json.loads(value)
                # A CLI-only version/lockfile change updates these two workspace
                # provenance hashes without changing the catalog or library payload.
                # All other provenance, bundle, source and license bytes are compared.
                inputs = provenance["generator_input_sha256"]
                inputs.pop("Cargo.toml", None)
                inputs.pop("Cargo.lock", None)
                value = json.dumps(provenance, sort_keys=True).encode()
            if path in files:
                raise ValueError(f"Duplicate archive entry: {path}")
            files[path] = value
    if "Cargo.toml" not in files:
        raise ValueError(f"Archive is missing Cargo.toml: {name} {version}")
    manifest = json.loads(files["Cargo.toml"])
    package = manifest.get("package", {})
    if package.get("name") != name or package.get("version") != version:
        raise ValueError(f"Archive manifest does not match {name} {version}")
    return files


def verify_existing(local_bytes, name, version, info):
    remote = fetch(f"https://static.crates.io/crates/{name}/{name}-{version}.crate")
    if hashlib.sha256(remote).hexdigest() != info["checksum"]:
        raise ValueError(f"Published archive checksum mismatch: {name} {version}")
    local_files = archive_contents(local_bytes, name, version)
    remote_files = archive_contents(remote, name, version)
    changed = sorted(path for path in local_files.keys() | remote_files.keys()
                     if local_files.get(path) != remote_files.get(path))
    if changed:
        raise ValueError(f"{name} {version} is published but packaged files changed: "
                         f"{', '.join(changed)}. Bump its version and dependent requirements.")


def make_plan(metadata, package_dir):
    packages = {package["name"]: package for package in metadata["packages"]}
    plan = []
    # Inspect EVERY crate before permitting ANY upload, including the binary.
    for name in PACKAGES:
        package = packages[name]
        if package["publish"] != ["crates-io"]:
            raise ValueError(f"{name} must be configured for crates-io publishing")
        version = package["version"]
        archive = package_dir / f"{name}-{version}.crate"
        data = archive.read_bytes()
        archive_contents(data, name, version)
        info = published_version(name, version)
        if info is not None:
            verify_existing(data, name, version, info)
        plan.append({"name": name, "version": version, "publish": info is None})
    return plan


def wait_for_index(name, version, timeout=180):
    # All our crate names are >= 4 characters: sparse index path convention.
    url = f"https://index.crates.io/{name[:2]}/{name[2:4]}/{name}"
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{name} {version} not visible in registry index; retry workflow")
        try:
            # This loop owns retries so each request respects the remaining deadline.
            body = fetch(url, missing_ok=True, timeout=min(60, remaining), attempts=1)
        except urllib.error.HTTPError as error:
            if error.code not in {408, 429} and not 500 <= error.code < 600:
                raise
            error.close()
            body = None
        except (urllib.error.URLError, TimeoutError):
            body = None
        if body is not None:
            for line in body.splitlines():
                entry = json.loads(line)
                if entry["vers"] == version:
                    if entry["yanked"]:
                        raise ValueError(f"{name} {version} was yanked during publication")
                    return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"{name} {version} not visible in registry index; retry workflow")
        time.sleep(min(5, remaining))


def publish_plan(plan, run=subprocess.run, wait=wait_for_index):
    for item in plan:
        if not item["publish"]:
            continue
        name, version = item["name"], item["version"]
        print(f"Publishing {name} {version}", flush=True)
        # Keep Cargo's package verification enabled. Never ignore a failed upload.
        run(["cargo", "publish", "--locked", "--registry", "crates-io", "-p", name],
            cwd=ROOT, check=True)
        wait(name, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true", help="upload missing versions")
    parser.add_argument("--tag", help="require the CLI version to match this release tag")
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"], cwd=ROOT))
    cli = next(p for p in metadata["packages"] if p["name"] == "kingfisher-bin")
    if args.tag and args.tag != f"v{cli['version']}":
        parser.error(f"release tag {args.tag!r} does not match kingfisher-bin {cli['version']}")
    package_dir = Path(metadata["target_directory"]) / "package"
    plan = make_plan(metadata, package_dir)
    for item in plan:
        action = "publish" if item["publish"] else "skip (identical version already published)"
        print(f"{item['name']} {item['version']}: {action}", flush=True)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"pending={str(any(item['publish'] for item in plan)).lower()}\n")
    if args.publish:
        if not os.environ.get("CARGO_REGISTRY_TOKEN"):
            parser.error("CARGO_REGISTRY_TOKEN is required to publish (API token or OIDC token)")
        publish_plan(plan)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Crates.io release stopped: {error}", file=sys.stderr)
        sys.exit(1)
