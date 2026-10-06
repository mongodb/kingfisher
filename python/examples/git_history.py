"""Scan committed file versions using native or Python-managed Git enumeration.

Native (no Git executable):
  uv run --no-sync python python/examples/git_history.py REPO --enumerator engine --all-refs
Python-managed (requires Git on PATH):
  uv run --no-sync python python/examples/git_history.py REPO --enumerator python --ref HEAD

Both routes produce ScanInput objects for the same scanner/archive pipeline.
Scanning stays offline and reports redacted JSONL; validation is not automatic.
"""
import argparse
import json
from pathlib import Path
import subprocess

from kingfisher_sdk import Rules, Scanner, ScanInput, expand_archives, git_history


def git_output(repository, *arguments):
    # Pass arguments separately: repository paths with spaces need no shell quoting.
    # This subprocess belongs to the caller's Python adapter, not the native SDK.
    return subprocess.run(
        ["git", "-C", str(repository), *arguments], check=True, capture_output=True,
    ).stdout


def python_history(repository, refs):
    """Example adapter; replace these Git commands with your own Python Git library."""
    # rev-list follows merge parents and Git's shallow boundaries. --all includes
    # all refs plus HEAD; explicit refs restrict enumeration to their ancestry.
    revisions = ["--all"] if refs is None else refs
    commits = git_output(repository, "rev-list", "--parents", *revisions).decode("ascii").splitlines()
    seen = set()
    for record in commits:
        commit, *parents = record.split()
        # Compare only the first parent, visiting all parents via rev-list. Git
        # skips unchanged subtrees instead of flattening every complete snapshot.
        baseline = [parents[0], commit] if parents else ["--root", commit]
        changes = git_output(repository, "diff-tree", "--no-commit-id", "--raw",
                             "--no-abbrev", "--no-renames", "-r", "-z", *baseline)
        fields = iter(changes.split(b"\0"))
        for metadata in fields:
            if not metadata:
                continue
            name = next(fields)  # NUL records retain spaces, tabs and newlines.
            old_mode, mode, old_id, object_id, status = metadata.split()
            # Deleted files have no target payload. Symlinks and submodules are
            # object references rather than regular file contents.
            if mode not in {b"100644", b"100755"}:
                continue
            # This caller adapter deliberately requires UTF-8 names. Native
            # git_inputs preserves non-UTF-8 raw_path metadata automatically.
            path = name.decode("utf-8")
            blob_id = object_id.decode("ascii")
            if (name, blob_id) in seen:
                continue
            seen.add((name, blob_id))
            data = git_output(repository, "cat-file", "blob", blob_id)
            # One selected occurrence is retained here; native git_inputs also
            # retains every selected occurrence with full shared commit metadata.
            yield ScanInput(path, data, repository=str(repository), commit=commit, blob_id=blob_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--enumerator", choices=["engine", "python"], default="engine")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--ref", action="append", help="Reachable ref; repeatable; default HEAD")
    scope.add_argument("--all-refs", action="store_true", help="Include all refs plus HEAD")
    parser.add_argument("--archive-depth", type=int, choices=range(33), default=1,
                        help="Archive layers to expand; 0 scans raw containers")
    parser.add_argument("--rules-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    args = parser.parse_args()
    repository = args.repository.expanduser()
    refs = None if args.all_refs else (args.ref or ["HEAD"])

    # Choose only enumeration here. Detection and archive expansion below are
    # identical, whether the caller or Kingfisher supplies the file versions.
    sources = (git_history(repository, refs=refs, discover=False,
                                  max_blob_size=16 * 1024 * 1024,
                                  max_commits=100_000, max_inputs=1_000_000) if args.enumerator == "engine"
               else python_history(repository, refs))
    scanner = Scanner(Rules(args.rules_path, builtins=not args.no_builtins))
    for result in scanner.scan_inputs(expand_archives(sources, depth=args.archive_depth)):
        # If adding validation, pass this group's entire findings list to
        # Validator.validate() first, retaining invisible component helpers.
        for finding in result.findings:
            if finding.visible:
                print(json.dumps({"path": result.input.path, "commit": result.input.commit,
                                  "blob_id": result.input.blob_id, "finding": finding.to_dict()}))


if __name__ == "__main__":
    main()
