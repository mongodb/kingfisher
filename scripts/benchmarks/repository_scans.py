#!/usr/bin/env python3
"""Compare two CLI builds on local repositories without live validation.

Reports are redacted and written outside the scanned repositories. Run versions
sequentially, alternating their order, and compare findings independently of
report order. Deduplicated reports can select different representative origins;
use --all-occurrences for strict fingerprint comparisons. Redacted snippets use
a random salt per process, so they are excluded from the report digest.
The results file contains counts, digests, coverage, timings, local paths and flags.
"""
import argparse
import collections
import hashlib
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def digest(counter):
    payload = json.dumps(sorted(counter.items()), separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def summarize(report):
    envelopes = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines() if line]
    findings = [item for envelope in envelopes for item in envelope["findings"]]
    rules = collections.Counter(item["rule"]["id"] for item in findings)
    identities = collections.Counter(
        json.dumps((item["rule"], {key: value for key, value in item["finding"].items()
                                  if key not in ("snippet", "validation")}),
                   sort_keys=True, separators=(",", ":"))
        for item in findings
    )
    fingerprints = collections.Counter(
        (item["rule"]["id"], item["finding"]["fingerprint"])
        for item in findings
    )
    coverage = {}
    for envelope in envelopes:
        for repo in (envelope.get("audit") or {}).get("repositories", []):
            coverage[repo["key"]] = {
                "status": repo["scan"]["status"],
                "scope": repo.get("git", {}).get("scope"),
                "tip": repo.get("git", {}).get("tip_sha"),
                "stats": repo.get("stats"),
            }
    summaries = [(envelope.get("metadata") or {}).get("summary", {}) for envelope in envelopes]
    return {
        "findings": len(findings),
        "rules": dict(sorted(rules.items())),
        "findings_digest": digest(identities),
        "fingerprints_digest": digest(fingerprints),
        "coverage": coverage,
        "summaries": summaries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", type=Path, default=shutil.which("kingfisher"))
    executable = "kingfisher.exe" if sys.platform == "win32" else "kingfisher"
    parser.add_argument("--new", type=Path, default=Path("target") / "release" / executable)
    parser.add_argument("--target", type=Path, action="append", required=True)
    parser.add_argument("--history", choices=("none", "full"), action="append", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--all-occurrences", action="store_true",
                        help="include hidden helpers and disable report deduplication")
    parser.add_argument("--new-first", action="store_true",
                        help="start with the new build, then alternate execution order")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if args.old is None:
        parser.error("kingfisher is not on PATH; pass --old")
    binaries = {"old": args.old.resolve(), "new": args.new.resolve()}
    versions = {
        name: subprocess.check_output([str(binary), "--version"], text=True).strip()
        for name, binary in binaries.items()
    }
    reports = args.reports or Path(tempfile.mkdtemp(prefix="kingfisher-repo-benchmark-"))
    reports.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = ["--no-validate", "--no-update-check", "--quiet", "--redact", "--format", "json",
             "--jobs", "16", "--git-repo-timeout", "0"]
    if args.all_occurrences:
        flags += ["--no-dedup", "--include-hidden-findings"]
    results = {"versions": versions, "binaries": {k: str(v) for k, v in binaries.items()},
               "flags": flags, "reports": str(reports), "runs": []}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    for history in args.history:
        for target_index, target in enumerate(args.target):
            target = target.expanduser().resolve()
            for repeat in range(args.repeats):
                old_first = (repeat % 2 == 0) != args.new_first
                for name in (("old", "new") if old_first else ("new", "old")):
                    stem = f"{target_index}-{target.name}-{history}-{repeat + 1}-{name}"
                    report, errors = reports / f"{stem}.json", reports / f"{stem}.stderr"
                    command = [str(binaries[name]), "scan", str(target), *flags,
                               "--git-history", history, "--output", str(report)]
                    print(f"Starting {versions[name]}: {target} history={history} run={repeat + 1}",
                          flush=True)
                    start = time.perf_counter()
                    with errors.open("w") as stderr:
                        process = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=stderr)
                    seconds = time.perf_counter() - start
                    if process.returncode not in (0, 200):
                        raise RuntimeError(f"Scan exited {process.returncode}; see {errors}")
                    row = {"target": str(target), "history": history, "repeat": repeat + 1,
                           "version": name, "seconds": seconds, "exit_code": process.returncode,
                           **summarize(report)}
                    results["runs"].append(row)
                    args.results.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
                    print(f"Finished in {seconds:.3f}s; findings={row['findings']}; "
                          f"coverage={collections.Counter(r['status'] for r in row['coverage'].values())}",
                          flush=True)
    for history in args.history:
        for target in args.target:
            runs = [r for r in results["runs"]
                    if r["history"] == history and r["target"] == str(target.expanduser().resolve())]
            medians = {name: statistics.median(r["seconds"] for r in runs if r["version"] == name)
                       for name in binaries}
            print(json.dumps({"target": str(target), "history": history, "median_seconds": medians,
                              "speedup": medians["old"] / medians["new"],
                              "counts_equal": len({r["findings"] for r in runs}) == 1,
                              "per_rule_counts_equal": len({json.dumps(r["rules"], sort_keys=True)
                                                            for r in runs}) == 1,
                              "coverage_equal": len({json.dumps(r["coverage"], sort_keys=True)
                                                     for r in runs}) == 1,
                              "findings_equal": len({r["findings_digest"] for r in runs}) == 1,
                              "fingerprints_equal": len({r["fingerprints_digest"] for r in runs}) == 1}),
                  flush=True)


if __name__ == "__main__":
    main()
