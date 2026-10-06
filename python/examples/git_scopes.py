"""Read native Git history, snapshots, diffs or staged content with provenance.

uv run --no-sync python python/examples/git_scopes.py repo --since-commit main
uv run --no-sync python python/examples/git_scopes.py repo --mode staged
uv run --no-sync python python/examples/git_scopes.py repo --all-refs --include-unreachable
"""
import argparse
from dataclasses import asdict
import json
from pathlib import Path

from kingfisher_sdk import DetectionScanner, GitScope, Rules, expand_archives, expand_content, git_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("--mode", choices=["history", "snapshot", "diff", "staged"], default="history")
    refs = parser.add_mutually_exclusive_group()
    refs.add_argument("--ref", action="append", help="Repeat for history; default HEAD")
    refs.add_argument("--all-refs", action="store_true")
    bounds = parser.add_mutually_exclusive_group()
    bounds.add_argument("--since-commit", help="Exclude the baseline and its ancestors")
    bounds.add_argument("--branch-root", help="Include this root, excluding its ancestors")
    parser.add_argument("--since-hours", type=float)
    parser.add_argument("--include-unreachable", action="store_true")
    parser.add_argument("--rules-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    args = parser.parse_args()
    scope = GitScope(mode=args.mode, refs=None if args.all_refs else tuple(args.ref or ["HEAD"]),
                     since_commit=args.since_commit, branch_root=args.branch_root,
                     since_hours=args.since_hours, include_unreachable=args.include_unreachable)
    # Diff returns only target versions changed from since_commit, while history
    # also finds intermediate versions deleted before HEAD. Staged reads index
    # blobs rather than working-tree bytes, and never writes a synthetic commit.
    # Require the repository root explicitly. Preparation budgets fail rather
    # than truncate ancestry; oversized blobs warn so coverage gaps are visible.
    # Missing blobs fail (partial clones are never fetched automatically).
    sources = git_inputs(args.repository.expanduser(), scope=scope, discover=False,
                         max_blob_size=16 * 1024 * 1024,
                         max_commits=100_000, max_inputs=1_000_000)
    # Descriptors are prepared up front with one metadata object per commit;
    # payloads load lazily. raw_path retains non-UTF-8 Git names. Controls
    # can be set independently on enumeration, expansion and per-input detection.
    sources = expand_content(expand_archives(sources, depth=2))
    scanner = DetectionScanner(Rules(args.rules_path, builtins=not args.no_builtins))
    for result in scanner.scan_inputs(sources):
        for finding in result.findings:
            if finding.visible:
                # origins enumerate selected change occurrences, not every
                # unchanged snapshot or guaranteed first-ever introduction.
                # Commit messages may contain credentials: omit them from logs.
                origins = [{"id": origin.id, "parents": origin.parents,
                            "author": asdict(origin.author), "committer": asdict(origin.committer)}
                           for origin in result.input.origins]
                print(json.dumps({"path": result.input.path, "blob_id": result.input.blob_id,
                                  "staged": result.input.staged, "unreachable": result.input.unreachable,
                                  "origins": origins, "finding": finding.to_dict()}))


if __name__ == "__main__":
    main()
