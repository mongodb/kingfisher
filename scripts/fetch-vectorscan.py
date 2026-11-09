#!/usr/bin/env python3
"""Stage a checksum-verified Vectorscan archive using GitHub's release API.

The browser release-download endpoint can return 504 while the asset API works.
Hashes come only from the immutable, Cargo-verified sys crate, never release JSON.
The sys build script verifies the archive again via VECTORSCAN_PREBUILT_DIR.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
API = "https://api.github.com"
REPOSITORY = "micksmix/kingfisher-vectorscan"
MAX_ARCHIVE = 128 * 1024 * 1024


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Never send API credentials to the release-asset storage host."""

    def redirect_request(self, request, response, code, message, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise ValueError("Release asset redirects must use HTTPS")
        redirected = super().redirect_request(request, response, code, message, headers, newurl)
        if redirected is not None and urllib.parse.urlsplit(newurl).netloc != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


def api_request(endpoint, accept="application/vnd.github+json"):
    request = urllib.request.Request(f"{API}/repos/{REPOSITORY}/{endpoint}", headers={
        "Accept": accept,
        "User-Agent": "kingfisher-vectorscan-prefetch",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    if token := os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        # Unredirected headers are deliberately not copied by urllib on redirects.
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    return request


def retry(operation):
    for attempt in range(3):
        try:
            return operation()
        except urllib.error.HTTPError as error:
            error.close()
            if (error.code not in {408, 429} and not 500 <= error.code < 600) or attempt == 2:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)


def pinned_archive(target, root=ROOT):
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
        cwd=root, check=True, stdout=subprocess.PIPE, text=True, encoding="utf-8",
    ).stdout)
    packages = [item for item in metadata["packages"]
                if item["name"] == "kingfisher-vectorscan-sys"]
    if len(packages) != 1 or not (packages[0].get("source") or "").startswith("registry+"):
        raise ValueError("Expected one immutable registry Vectorscan sys crate")
    package = packages[0]
    version = package["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a stable Vectorscan sys crate version")
    manifest = Path(package["manifest_path"]).with_name("prebuilt-manifest.txt")
    seen = set()
    checksum = None
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        if (len(fields) != 3 or fields[0] != version
                or not re.fullmatch(r"[A-Za-z0-9_-]+", fields[1])
                or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[2]) or fields[1] in seen):
            raise ValueError("Invalid immutable Vectorscan prebuilt manifest")
        seen.add(fields[1])
        if fields[1] == target:
            checksum = fields[2].lower()
    if checksum is None:
        raise ValueError(f"No pinned Vectorscan archive for {target}")
    return version, f"vectorscan-{version}-{target}.tar.gz", checksum


def verify(path, checksum):
    if path.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Vectorscan archive exceeds size limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise ValueError("Vectorscan archive SHA-256 mismatch")


def fetch(version, name, checksum, directory, opener=None):
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    if destination.resolve().parent != directory:
        raise ValueError("Unsafe Vectorscan archive destination")
    if destination.is_file():
        verify(destination, checksum)
        return destination
    opener = opener or urllib.request.build_opener(SafeRedirect())

    def release_metadata():
        with opener.open(api_request(f"releases/tags/v{version}"), timeout=30) as response:
            return json.load(response)

    release = retry(release_metadata)
    assets = [item for item in release["assets"] if item["name"] == name]
    if (len(assets) != 1 or type(assets[0].get("id")) is not int or assets[0]["id"] <= 0
            or type(assets[0].get("size")) is not int
            or not 0 < assets[0]["size"] <= MAX_ARCHIVE):
        raise ValueError(f"Missing or invalid Vectorscan release asset: {name}")
    asset = assets[0]
    # Construct the API route ourselves; never trust a release-provided URL/hash.
    request = api_request(f"releases/assets/{asset['id']}", "application/octet-stream")
    with tempfile.TemporaryDirectory(prefix=".vectorscan-", dir=directory) as temporary:
        partial = Path(temporary) / name

        def download():
            with opener.open(request, timeout=60) as response, partial.open("wb") as output:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ARCHIVE:
                        raise ValueError("Vectorscan archive exceeds size limit")
                    output.write(chunk)
            if size != asset["size"]:
                raise ValueError("Vectorscan archive size does not match release metadata")

        retry(download)
        verify(partial, checksum)
        partial.replace(destination)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="", help="Rust target triple (default: rustc host)")
    parser.add_argument("--directory", type=Path, default=ROOT / "target/vectorscan-prebuilt")
    parser.add_argument("--github-env", action="store_true", help="Export the directory to subsequent steps")
    args = parser.parse_args()
    target = args.target
    if not target:
        version = subprocess.run(["rustc", "-vV"], check=True, capture_output=True, text=True).stdout
        target = next(line.removeprefix("host: ") for line in version.splitlines() if line.startswith("host: "))
    if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
        raise ValueError("Invalid Rust target triple")
    version, name, checksum = pinned_archive(target)
    archive = fetch(version, name, checksum, args.directory)
    print(f"Verified {archive.name}: SHA-256 {checksum}")
    if args.github_env:
        directory = archive.parent.as_posix()
        if "\n" in directory or "\r" in directory:
            raise ValueError("Invalid GitHub environment path")
        with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as output:
            output.write(f"VECTORSCAN_PREBUILT_DIR={directory}\n")


if __name__ == "__main__":
    main()
