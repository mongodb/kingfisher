#!/usr/bin/env python3
"""Plan missing SDK distributions before entering the PyPI publish job.

Registry queries are read-only. Optional staging copies only missing distributions
without changing the original artifacts.
Requires Python 3.11+.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import time
import tomllib
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "kingfisher-secret-scanner"


def published_filenames(version):
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{PACKAGE}/{version}/json",
        headers={"User-Agent": "kingfisher-release (https://github.com/mongodb/kingfisher)"},
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return {item["filename"] for item in json.load(response)["urls"]}
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return set()
            if (error.code not in {408, 429} and not 500 <= error.code < 600
                    or attempt == 1):
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == 1:
                raise
        time.sleep(1)


def plan(dist, version):
    artifacts = sorted(path for path in dist.iterdir()
                       if path.is_file() and (path.name.endswith(".whl")
                                              or path.name.endswith(".tar.gz")))
    if not artifacts:
        raise ValueError(f"No SDK distributions found in {dist}")
    published = published_filenames(version)
    pending = [artifact for artifact in artifacts if artifact.name not in published]
    print(f"Publish {PACKAGE} {version}: {len(pending)} missing distribution(s)")
    return pending


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True, help="artifact staging directory")
    parser.add_argument("--pending-dir", type=Path, help="stage only missing distributions here")
    args = parser.parse_args()
    with (ROOT / "crates/kingfisher-python/Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    pending = plan(args.dist, version)
    if args.pending_dir is not None:
        if args.pending_dir.exists():
            raise ValueError("Pending directory must be new")
        args.pending_dir.mkdir(parents=True)
        for artifact in pending:
            shutil.copy2(artifact, args.pending_dir / artifact.name)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(f"pending={str(bool(pending)).lower()}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError) as error:
        print(f"PyPI SDK release plan failed: {error}", file=sys.stderr)
        sys.exit(1)
