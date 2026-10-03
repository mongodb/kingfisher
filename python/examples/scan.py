"""Offline file/directory scan with redacted JSONL and optional report filters.

Checkout: uv run --no-sync python python/examples/scan.py ~/mms --timeout 5
Published: uv run --no-project --with kingfisher-secret-scanner python scan.py FILE
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatchcase
from hashlib import blake2b
import json
import os
from pathlib import Path
import sys

from kingfisher_sdk import CancellationToken, Rules, Scanner


def iter_files(root, exclusions):
    """Supply files to the SDK; these globs are not Git's ignore syntax."""
    if root.is_file():
        if not any(fnmatchcase(root.name, pattern) for pattern in exclusions):
            yield root
        return
    if not root.is_dir():
        raise FileNotFoundError(root)
    def walk_error(exc):
        raise exc  # Inaccessible directories must not silently appear clean.

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        # Prune metadata/dependency directories before descending. Add/remove names
        # here to choose your scope; no Git history or archives are expanded.
        dirs[:] = sorted(name for name in dirs if name not in {".git", ".venv", "node_modules"}
                         and not any(fnmatchcase(
                             (Path(directory) / name).relative_to(root).as_posix(), pattern)
                             for pattern in exclusions))
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if not path.is_symlink() and not any(
                fnmatchcase(relative, pattern) for pattern in exclusions
            ):
                yield path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--rules-path", action="append", default=[], help="Custom YAML/TOML path; repeatable")
    parser.add_argument("--no-builtins", action="store_true", help="Load only custom rules")
    parser.add_argument("--confidence", choices=["low", "medium", "high"], default="medium",
                        help="Minimum rule confidence loaded into the scanner")
    parser.add_argument("--rule", action="append", default=[], help="Report rule ID glob; repeatable, OR combined")
    parser.add_argument("--exclude", action="append", default=[], help="Relative path glob to skip; repeatable")
    parser.add_argument("--min-entropy", type=float, help="Report only findings with at least this entropy")
    parser.add_argument("--base64-only", action="store_true", help="Report only Base64 findings")
    parser.add_argument("--no-base64", action="store_true", help="Disable Base64 scanning")
    parser.add_argument("--unique", action="store_true", help="Report once per rule ID and credential value")
    parser.add_argument("--timeout", type=float, help="Cooperative scan limit in seconds PER FILE")
    args = parser.parse_args()
    if args.base64_only and args.no_base64:
        parser.error("--base64-only requires Base64 scanning")
    if args.timeout is not None and (not 0 < args.timeout < float("inf")):
        parser.error("--timeout must be finite and positive")

    rules = Rules(args.rules_path, builtins=not args.no_builtins, confidence=args.confidence)
    scanner = Scanner(rules, base64=not args.no_base64)
    # Reuse compilation and native scratch pools. SDK dedup=True suppresses repeat
    # scans of identical content AT THE SAME PATH; it is not secret-level dedup.
    seen = set()
    dedup_key = os.urandom(32)  # Per-run keyed digests; never output raw values.
    cancellation = CancellationToken()
    failed = False
    # A worker runs native scans while the main thread can handle Ctrl-C and
    # signal cancellation. A signal handler on a native-scanning thread may wait
    # until that native call returns. One worker keeps output deterministic.
    with ThreadPoolExecutor(max_workers=1) as executor:
        try:
            for path in iter_files(args.path.expanduser().resolve(), args.exclude):
                try:
                    findings = executor.submit(scanner.scan_file, path, timeout=args.timeout,
                                               cancellation=cancellation).result()
                except (OSError, TimeoutError, RuntimeError) as exc:
                    failed = True
                    print(f"{path}: {exc}", file=sys.stderr)
                    continue  # An interrupted scan is not a clean file.
                # Keep the complete list if validating later: invisible helpers
                # provide supporting values for multi-part credentials.
                for finding in findings:
                    if not finding.visible:
                        continue
                    data = finding.to_dict()  # Secret AND captures are redacted.
                    if args.rule and not any(fnmatchcase(data["rule_id"], pattern) for pattern in args.rule):
                        continue
                    if args.min_entropy is not None and data["entropy"] < args.min_entropy:
                        continue
                    if args.base64_only and not data["is_base64_encoded"]:
                        continue
                    if args.unique:
                        # Finding fingerprints identify occurrences, not secrets.
                        # Hash explicit raw access internally to dedup credentials
                        # across files without retaining or reporting raw values.
                        digest = blake2b(finding.secret.encode("utf-8"), key=dedup_key).digest()
                        key = (data["rule_id"], digest)
                        if key in seen:
                            continue
                        seen.add(key)
                    # Other predicates: data["confidence"] == "high",
                    # data["location"]["line"] >= 10, or a fingerprint allowlist.
                    # Filter paths before scanning; findings do not store paths.
                    print(json.dumps({"path": str(path), **data}))
        except KeyboardInterrupt:
            cancellation.cancel()
            print("Scan cancelled; waiting for the current native operation to stop.", file=sys.stderr)
            return 130
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
