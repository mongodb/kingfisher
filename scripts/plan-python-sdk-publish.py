#!/usr/bin/env python3
"""Skip an already-published SDK version before entering the PyPI publish job.

Planning is read-only; no registry writes or local artifact changes.
Requires Python 3.11+.
"""
import argparse
import os
from pathlib import Path
import sys
import time
import tomllib
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "kingfisher-secret-scanner"


def version_exists(version):
    request = urllib.request.Request(
        f"https://pypi.org/pypi/{PACKAGE}/{version}/json",
        headers={"User-Agent": "kingfisher-release (https://github.com/mongodb/kingfisher)"},
    )
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=60):
                return True
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return False
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
    if version_exists(version):
        print(f"Skip {PACKAGE} {version}: version already published on PyPI")
        return []
    print(f"Publish {PACKAGE} {version}: new version")
    return artifacts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True, help="artifact staging directory")
    args = parser.parse_args()
    with (ROOT / "crates/kingfisher-python/Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    pending = plan(args.dist, version)
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
