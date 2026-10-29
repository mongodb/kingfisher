#!/usr/bin/env python3
"""Compare two CLI builds before and after embedding connection-string rules.

Scans local working trees sequentially with alternating build order, all default
rules at medium confidence, two jobs, and no validation or compiled-rule cache.
Every occurrence and hidden helper finding is included so metadata comparisons
do not depend on deduplication's choice of representative origin.
Private temporary reports are redacted. The results contain timings, coverage,
counts and digests, plus added-rule paths and lines, without snippets or secrets.
"""
import argparse
import collections
import json
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

from repository_scans import digest


NATIVE_PREFIX = "kingfisher.connection-string.password."
SCAN_FLAGS = [
    "--no-validate", "--no-update-check", "--no-rule-cache", "--quiet", "--redact",
    "--format", "json", "--confidence", "medium", "--rule", "all", "--jobs", "2",
    "--git-history", "none", "--git-repo-timeout", "0",
    "--no-dedup", "--include-hidden-findings",
]


def summarize_group(findings):
    """Compare unordered, repeated records without storing their content."""
    identities = collections.Counter(
        json.dumps((item["rule"], {
            key: value for key, value in item["finding"].items()
            if key not in ("snippet", "validation")
        }), sort_keys=True, separators=(",", ":"))
        for item in findings
    )
    fingerprints = collections.Counter(
        (item["rule"]["id"], item["finding"]["fingerprint"])
        for item in findings
    )
    rules = collections.Counter(item["rule"]["id"] for item in findings)
    return {
        "count": len(findings),
        "rules": dict(sorted(rules.items())),
        "metadata_multiset_digest": digest(identities),
        "fingerprint_multiset_digest": digest(fingerprints),
    }


def summarize(report):
    envelopes = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()
                 if line.strip()]
    if not envelopes:
        raise ValueError(f"No JSON report envelopes in {report}")
    findings = [item for envelope in envelopes for item in envelope["findings"]]
    native = [item for item in findings if item["rule"]["id"].startswith(NATIVE_PREFIX)]
    existing = [item for item in findings if not item["rule"]["id"].startswith(NATIVE_PREFIX)]
    locations = collections.Counter(
        (item["rule"]["id"], item["finding"]["path"], item["finding"]["line"])
        for item in native
    )
    coverage = {}
    findings_before_report = {}
    for envelope in envelopes:
        for repo in (envelope.get("audit") or {}).get("repositories", []):
            git = repo.get("git") or {}
            stats = repo.get("stats") or {}
            coverage[repo["key"]] = {
                "status": repo["scan"]["status"],
                "scope": git.get("scope"),
                "tip": git.get("tip_sha"),
                "blobs_scanned": stats.get("blobs_scanned"),
                "bytes_scanned": stats.get("bytes_scanned"),
            }
            findings_before_report[repo["key"]] = stats.get("findings")
    summaries = [(envelope.get("metadata") or {}).get("summary", {})
                 for envelope in envelopes]
    scanned = sorted([
        {key: summary.get(key) for key in ("blobs_scanned", "bytes_scanned")}
        for summary in summaries
    ], key=lambda item: json.dumps(item, sort_keys=True))
    return {
        "findings": len(findings),
        "existing": summarize_group(existing),
        "native": {
            **summarize_group(native),
            "locations": [{"rule": rule, "path": path, "line": line, "count": count}
                          for (rule, path, line), count in sorted(locations.items())],
        },
        "coverage": coverage,
        "findings_before_report": findings_before_report,
        "scanned": scanned,
        "summaries": summaries,
    }


def equal(rows, key):
    return len({json.dumps(row[key], sort_keys=True) for row in rows}) == 1


def numeric_counts(items):
    keys = ("blobs_scanned", "bytes_scanned")
    if not items or any(type(item.get(key)) is not int or item[key] < 0
                        for item in items for key in keys):
        return None
    return {key: sum(item[key] for item in items) for key in keys}


def count_delta(old, new):
    return {key: {"old": (old or {}).get(key), "new": (new or {}).get(key),
                  "delta": new[key] - old[key] if old is not None and new is not None else None}
            for key in ("blobs_scanned", "bytes_scanned")}


def compare(runs, target, expected_repeats):
    rows = [row for row in runs if row["target"] == str(target)]
    builds = {name: [row for row in rows if row["build"] == name] for name in ("old", "new")}
    medians = {name: statistics.median(row["seconds"] for row in group) if group else None
               for name, group in builds.items()}
    native_new = [row["native"] for row in rows if row["build"] == "new"]
    identities = [{key: {field: repo.get(field) for field in ("status", "scope", "tip")}
                   for key, repo in row["coverage"].items()} for row in rows]
    first = {name: group[0] if group else {} for name, group in builds.items()}
    old_coverage = first["old"].get("coverage", {})
    new_coverage = first["new"].get("coverage", {})
    deltas = {
        "repositories": {
            key: count_delta(numeric_counts([old_coverage[key]]) if key in old_coverage else None,
                             numeric_counts([new_coverage[key]]) if key in new_coverage else None)
            for key in sorted(old_coverage.keys() | new_coverage.keys())
        },
        "summary": count_delta(numeric_counts(first["old"].get("scanned", [])),
                               numeric_counts(first["new"].get("scanned", []))),
    }
    all_deltas = [*deltas["repositories"].values(), deltas["summary"]]
    checks = {
        "all_runs_present": all(
            collections.Counter(row["repeat"] for row in group)
            == collections.Counter(range(1, expected_repeats + 1))
            for group in builds.values()
        ) and len(rows) == 2 * expected_repeats,
        "existing_findings_equal": equal(rows, "existing"),
        "repository_identity_equal": len({json.dumps(item, sort_keys=True)
                                           for item in identities}) == 1,
        "coverage_stable_within_build": all(equal(group, "coverage") and equal(group, "scanned")
                                             and equal(group, "findings_before_report")
                                             for group in builds.values()),
        "coverage_completed": bool(rows) and all(row["coverage"] for row in rows) and all(
            repo["status"] == "completed" and numeric_counts([repo]) is not None
            for row in rows for repo in row["coverage"].values()),
        "coverage_not_reduced": all(
            counts["delta"] is not None and counts["delta"] >= 0
            for delta in all_deltas for counts in delta.values()),
        "baseline_has_no_native_rules": all(row["native"]["count"] == 0
                                             for row in rows if row["build"] == "old"),
        "native_findings_stable": len({json.dumps(item, sort_keys=True)
                                       for item in native_new}) == 1,
    }
    return {
        "target": str(target),
        "median_seconds": medians,
        "new_over_old_time": (medians["new"] / medians["old"]
                              if medians["old"] and medians["new"] is not None else None),
        "coverage_delta": deltas,
        "checks": checks,
        "passed": all(checks.values()),
        "native": native_new[0] if native_new else None,
    }


def save_results(path, results):
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recheck-results", type=Path,
                        help="recompute checks and medians from saved runs without scanning")
    parser.add_argument("--old", type=Path, help="baseline CLI binary")
    parser.add_argument("--new", type=Path, help="CLI with embedded rules")
    parser.add_argument("--target", type=Path, action="append",
                        help="local repository working tree; may be repeated")
    parser.add_argument("--repeats", type=int, help="paired scans per target (default: 3)")
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    if args.recheck_results is not None:
        if any(value is not None for value in (args.old, args.new, args.target,
                                              args.repeats, args.results)):
            parser.error("--recheck-results cannot be combined with scan arguments")
        path = args.recheck_results.expanduser().resolve()
        results = json.loads(path.read_text(encoding="utf-8"))
        runs = results.get("runs", [])
        if not runs:
            parser.error("saved results contain no runs")
        targets = results.get("targets") or sorted(
            {row["target"] for row in runs}
            | {item["target"] for item in results.get("comparisons", [])})
        repeats = results.get("repeats", max(row["repeat"] for row in runs))
        if not isinstance(repeats, int) or repeats < 1:
            parser.error("saved results have an invalid repeat count")
        results["comparisons"] = [compare(runs, target, repeats) for target in targets]
        results["passed"] = (not results.get("error")
                             and all(item["passed"] for item in results["comparisons"]))
        save_results(path, results)
        for comparison in results["comparisons"]:
            print(json.dumps(comparison, sort_keys=True), flush=True)
        return 0 if results["passed"] else 1
    if any(value is None for value in (args.old, args.new, args.target, args.results)):
        parser.error("scanning requires --old, --new, --target, and --results")
    if args.repeats is None:
        args.repeats = 3
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    binaries = {"old": args.old.expanduser().resolve(), "new": args.new.expanduser().resolve()}
    if binaries["old"] == binaries["new"]:
        parser.error("--old and --new must identify distinct binaries")
    for name, binary in binaries.items():
        if not binary.is_file():
            parser.error(f"{name} binary is not a file: {binary}")
    targets = [path.expanduser().resolve() for path in args.target]
    if len(set(targets)) != len(targets):
        parser.error("--target paths must be distinct")
    for target in targets:
        if not target.is_dir():
            parser.error(f"target is not a directory: {target}")
    versions = {name: subprocess.check_output([str(binary), "--version"], text=True).strip()
                for name, binary in binaries.items()}
    # mkdtemp creates a private directory. Retain redacted reports for local review.
    reports = Path(tempfile.mkdtemp(prefix="kingfisher-connection-strings-"))
    if any(reports == target or target in reports.parents for target in targets):
        reports.rmdir()
        parser.error("temporary reports must be outside every scanned target")
    results_path = args.results.expanduser().resolve()
    if any(results_path == target or target in results_path.parents for target in targets):
        reports.rmdir()
        parser.error("--results must be outside every scanned target")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    results = {
        "versions": versions,
        "binaries": {name: str(path) for name, path in binaries.items()},
        "flags": SCAN_FLAGS,
        "reports": str(reports),
        "targets": [str(target) for target in targets],
        "repeats": args.repeats,
        "runs": [],
        "comparisons": [],
    }
    save_results(results_path, results)
    for target_index, target in enumerate(targets):
        for repeat in range(args.repeats):
            order = ("old", "new") if (target_index + repeat) % 2 == 0 else ("new", "old")
            for name in order:
                stem = f"{target_index}-{target.name}-{repeat + 1}-{name}"
                report, errors = reports / f"{stem}.json", reports / f"{stem}.stderr"
                command = [str(binaries[name]), "scan", str(target), *SCAN_FLAGS,
                           "--output", str(report)]
                print(f"Starting {name}: {target} run={repeat + 1}", flush=True)
                start = time.perf_counter()
                with errors.open("w", encoding="utf-8") as stderr:
                    process = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=stderr)
                seconds = time.perf_counter() - start
                if process.returncode not in (0, 200):
                    results["error"] = {"target": str(target), "build": name,
                                        "repeat": repeat + 1, "exit_code": process.returncode,
                                        "stderr": str(errors)}
                    save_results(results_path, results)
                    raise RuntimeError(f"Scan exited {process.returncode}; see {errors}")
                row = {"target": str(target), "repeat": repeat + 1, "build": name,
                       "seconds": seconds, "exit_code": process.returncode, **summarize(report)}
                results["runs"].append(row)
                save_results(results_path, results)
                print(f"Finished {seconds:.3f}s; existing={row['existing']['count']}; "
                      f"native={row['native']['count']}", flush=True)
        comparison = compare(results["runs"], target, args.repeats)
        results["comparisons"].append(comparison)
        save_results(results_path, results)
        print(json.dumps(comparison, sort_keys=True), flush=True)
    results["passed"] = all(item["passed"] for item in results["comparisons"])
    save_results(results_path, results)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
