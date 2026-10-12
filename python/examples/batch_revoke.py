"""Prepare a source file, inspect missing inputs, validate, then revoke a batch.

Checkout: uv run --no-sync python python/examples/batch_revoke.py FILE --provider github
Published: uv run --no-project --with kingfisher-secret-scanner python batch_revoke.py FILE --provider github

Default behavior is offline. --validate contacts providers; --confirm authorizes
real revocations after explicitly selecting all ready snapshots. Endpoint/input
overrides optionally come from a JSON object in KINGFISHER_VARIABLES. Output stays
redacted. Overlapping candidates are left for the caller to disambiguate.
Supply --rules-path company.yml (repeatable, files or directories) for custom
YAML revocation actions; --no-builtins restricts the catalog to those rules.
"""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path

from kingfisher_sdk import Revoker, Rules, Validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--provider", help="Exact rule ID/display name or provider family")
    parser.add_argument("--rules-path", action="append", type=Path, default=[], help="Custom YAML/TOML rules; repeatable")
    parser.add_argument("--no-builtins", action="store_true", help="Load only custom rules")
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--confirm", action="store_true", help="Authorize all unambiguous ready credentials")
    args = parser.parse_args()
    rules = Rules(args.rules_path, builtins=not args.no_builtins)
    revoker = Revoker(rules)
    # Optional embedding equivalent: Revoker(Rules(["company.yml"], builtins=False)).
    # Each validated snapshot retains its custom rule's action and supporting inputs.
    plan = revoker.prepare_from_file(args.file, provider=args.provider,
                                    variables=json.loads(os.environ.get("KINGFISHER_VARIABLES", "{}")))
    for candidate in plan.candidates:
        print(f"{candidate.rule_id}: revocation_supported={candidate.revocation_supported}")
        for issue in candidate.input_diagnostics:
            print(f"  {issue.stage}: {issue.message}")
    if not args.validate and not args.confirm:
        return
    results = plan.validate(Validator(timeout=10, concurrency=4))
    for result in results:
        print(f"{result.finding.rule_id}: validation={result.outcome}, revocation_ready={result.revocation_ready}")
    if not args.confirm:
        return
    # Refuse overlapping detector candidates; the batch method deliberately
    # does not infer which detector/provider target the application intended.
    locations = sorted((result.finding.blob_id, result.finding.is_base64_encoded,
                        result.finding.location["start_offset"], result.finding.location["end_offset"])
                       for result in results)
    if any(left[:2] == right[:2] and left[3] > right[2]
           for left, right in zip(locations, locations[1:])):
        parser.error("overlapping candidates require an exact rule ID or application-specific disambiguation")
    try:
        statuses = revoker.revoke_many(results, confirm=True, timeout=60)
    except (RuntimeError, TimeoutError, KeyboardInterrupt) as error:
        # Never print provider/error bodies. A submitted mutation may have applied;
        # inspect provider state before retrying. Preserve already-known outcomes.
        for status in getattr(error, "completed", ()):
            print(json.dumps(asdict(status)))  # This status object contains no credentials.
        print("Batch interrupted; pending actions stopped. Inspect unknown outcomes before retrying.")
        raise SystemExit(1) from None
    for status in statuses:
        # "failed" means configuration/lookup failed before mutation; "unknown"
        # requires inspecting provider state. Neither outcome is retried here.
        print(json.dumps(asdict(status)))


if __name__ == "__main__":
    main()
