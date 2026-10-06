"""Compose Python or native file enumeration, native history and archive expansion.

uv run --no-sync python python/examples/inputs.py path --filesystem-enumerator python
uv run --no-sync python python/examples/inputs.py repo --git-history --archive-depth 2
"""
import argparse
from itertools import chain
import json
from pathlib import Path

from kingfisher_sdk import Rules, Scanner, ScanInput, expand_archives, filesystem, git_history


def python_files(root):
    """Example caller policy: regular files, no symlinks or Git internals."""
    if root.is_symlink():
        return  # Caller policy also excludes explicitly supplied symlinks.
    if root.is_file():
        yield ScanInput.from_file(root)
    else:
        if not root.is_dir():
            raise FileNotFoundError(root)
        # Path.rglob does not follow directory symlinks on Python 3.10+.
        for path in root.rglob("*"):
            # This is Python path selection, not .gitignore parsing. Change
            # the predicate or glob here to implement your application policy.
            if (path.is_file() and not path.is_symlink()
                    and all(part.casefold() != ".git" for part in path.relative_to(root).parts)):
                # Defers the file read while preserving its path for rule filters.
                yield ScanInput.from_file(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--filesystem-enumerator", choices=["engine", "python"], default="engine")
    parser.add_argument("--git-history", action="store_true", help="Add committed history from HEAD")
    parser.add_argument("--archive-depth", type=int, default=1)
    parser.add_argument("--rules-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    args = parser.parse_args()
    root = args.path.expanduser()
    # Select enumeration independently of detection. Native enumeration honors
    # local ignore files; the Python iterator uses the policy defined above.
    sources = filesystem([root]) if args.filesystem_enumerator == "engine" else python_files(root)
    if args.git_history:
        # chain() streams both sources without collecting every file in memory.
        # See git_history.py for native versus Python-managed history enumeration.
        sources = chain(sources, git_history(root))
    # Compile once and reuse the scanner for filesystem and historical inputs.
    scanner = Scanner(Rules(args.rules_path, builtins=not args.no_builtins))
    # Expansion is opt-in. Depth 0 retains containers; 2 reaches nested members.
    # Its byte/entry budgets and timeout are per archive root, while scan_inputs
    # can set a separate per-input detection timeout.
    for result in scanner.scan_inputs(expand_archives(sources, depth=args.archive_depth)):
        # Preserve this complete group for validation, including hidden helpers.
        # Apply visibility filtering only when reporting, and redact by default.
        for finding in result.findings:
            if finding.visible:
                print(json.dumps({"path": result.input.path, "commit": result.input.commit,
                                  "finding": finding.to_dict()}))


if __name__ == "__main__":
    main()
