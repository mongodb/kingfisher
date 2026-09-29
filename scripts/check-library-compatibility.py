#!/usr/bin/env python3
"""Check the PR base API while preserving its legacy Vectorscan patches."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib


def write_baseline_config(baseline, run_dir):
    manifest = tomllib.loads((baseline / "Cargo.toml").read_text(encoding="utf-8"))
    patches = manifest.get("patch", {}).get("crates-io", {})
    lines = []
    for name in ("vectorscan-rs", "vectorscan-rs-sys"):
        patch = patches.get(name)
        if patch is None:
            continue
        # Keep this workaround limited to the legacy vendored dependencies.
        if set(patch) != {"path"}:
            raise ValueError(f"Unexpected baseline patch for {name}: {patch}")
        path = (baseline / patch["path"]).resolve(strict=True)
        lines.extend([
            f'[patch.crates-io.{json.dumps(name)}]',
            f'path = {json.dumps(str(path))}',
        ])
    if lines:
        config = run_dir / ".cargo" / "config.toml"
        config.parent.mkdir()
        config.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-rev", required=True)
    parser.add_argument("--features", choices=("default-features", "all-features"), required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    lockfile = repo / "Cargo.lock"
    original_lockfile = lockfile.read_bytes()
    with tempfile.TemporaryDirectory(prefix="kingfisher-semver-") as temporary:
        run_dir = Path(temporary)
        baseline = run_dir / "baseline"
        subprocess.run([
            "git", "worktree", "add", "--detach", str(baseline), args.baseline_rev,
        ], cwd=repo, check=True)
        try:
            write_baseline_config(baseline, run_dir)
            # cargo-semver-checks builds an external consumer, so workspace
            # [patch] entries are lost. Cargo configuration in this isolated cwd
            # applies to those builds without changing either checkout's source.
            subprocess.run([
                "cargo", "semver-checks", "--manifest-path", str(repo / "Cargo.toml"),
                "-p", "kingfisher-core", "-p", "kingfisher-rules", "-p", "kingfisher-scanner",
                "--baseline-root", str(baseline), f"--{args.features}",
            ], cwd=run_dir, check=True)
        finally:
            # Cargo records unused baseline patches in the current lockfile.
            # They are temporary build configuration, not release inputs.
            if lockfile.read_bytes() != original_lockfile:
                lockfile.write_bytes(original_lockfile)
            subprocess.run([
                "git", "worktree", "remove", "--force", str(baseline),
            ], cwd=repo, check=True)


if __name__ == "__main__":
    main()
