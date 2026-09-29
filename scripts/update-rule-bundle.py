#!/usr/bin/env python3
"""Regenerate and verify Kingfisher's prepared rules using the Rust importer.

Run from any working directory with Python 3.9+ and the repository's Rust toolchain.
Only --refresh downloads rule sources; Cargo may still download dependencies.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "crates" / "kingfisher-rules" / "generated" / "provenance.json"


def run(args: list[str]) -> None:
    command = subprocess.list2cmdline(args) if os.name == "nt" else shlex.join(args)
    print("+ " + command, flush=True)
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--refresh", action="store_true",
        help="fetch the reviewed, pinned upstream sources before regenerating",
    )
    mode.add_argument(
        "--check", action="store_true",
        help="verify and test without rewriting generated artifacts or building docs",
    )
    args = parser.parse_args()
    cargo = shutil.which("cargo")
    if cargo is None:
        parser.error("cargo was not found on PATH; install the repository's Rust toolchain")

    # Formatting changes generator input hashes, so detect it before regeneration.
    run([cargo, "fmt", "--all", "--check"])
    generator = [cargo, "run", "--locked", "-p", "kingfisher-rule-bundle"]
    if not args.check:
        run(generator + (["--", "--refresh"] if args.refresh else []))
    run(generator + ["--", "--check"])
    run([cargo, "test", "--locked", "-p", "kingfisher-rules", "-p", "kingfisher-rule-bundle"])

    if not args.check:
        venv = ROOT / "docs-site" / ".venv"
        mkdocs = next(
            (path for path in [venv / "bin" / "mkdocs", venv / "Scripts" / "mkdocs.exe"]
             if path.is_file()),
            None,
        )
        if mkdocs is None:
            print("Skipped rendered docs: docs-site/.venv has no MkDocs executable.")
            print("The generated Markdown is updated; rebuild the site when its environment is available.")
        else:
            run([str(mkdocs), "build", "-f", str(ROOT / "docs-site" / "mkdocs.yml")])

    with MANIFEST.open(encoding="utf-8") as source:
        count = len(json.load(source)["rules"])
    print(f"Verified {count} rules, provenance, licenses, and generated Markdown.")
    if not args.check:
        print("Review and commit the inputs and generated artifacts together; see docs/PUBLISHING.md.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(f"Stopped: command exited with status {error.returncode}.", file=sys.stderr)
        sys.exit(error.returncode if error.returncode > 0 else 1)
    except OSError as error:
        print(f"Stopped: {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
