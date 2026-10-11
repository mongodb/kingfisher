"""Identify an externally supplied credential without knowing its rule ID.

Checkout: uv run --no-sync python python/examples/prepare_revocation.py github
Published: uv run --no-project --with kingfisher-secret-scanner python prepare_revocation.py github

KINGFISHER_SECRET contains a token or source text with its companion credentials.
KINGFISHER_VARIABLES optionally contains a JSON object of supporting values or
enterprise endpoint overrides. Preparation is offline. --validate contacts
providers; --confirm explicitly authorizes one unambiguous ready candidate.
Supply --rules-path company.yml (repeatable, files or directories) for custom
YAML revocation actions; --no-builtins restricts the catalog to those rules.
"""
import argparse
import json
import os
from pathlib import Path

from kingfisher_sdk import Revoker, Rules, Validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", nargs="?", help="Exact rule ID/name or family, e.g. github")
    parser.add_argument("--file", type=Path, help="Read a source file, preserving paths and companion credentials")
    parser.add_argument("--rules-path", action="append", type=Path, default=[], help="Custom YAML/TOML rules; repeatable")
    parser.add_argument("--no-builtins", action="store_true", help="Load only custom rules")
    parser.add_argument("--validate", action="store_true", help="Check detected candidates live")
    parser.add_argument("--confirm", action="store_true", help="Validate and revoke one ready candidate")
    args = parser.parse_args()
    rules = Rules(args.rules_path, builtins=not args.no_builtins)
    revoker = Revoker(rules)
    # Optional embedding equivalent: Revoker(Rules(["company.yml"], builtins=False)).
    # Custom YAML must define revocation; TOML detection alone adds no action.
    variables = json.loads(os.environ.get("KINGFISHER_VARIABLES", "{}"))
    if args.file is not None:
        plan = revoker.prepare_from_file(args.file, provider=args.provider, variables=variables)
    else:
        plan = revoker.prepare(os.environ["KINGFISHER_SECRET"], provider=args.provider, variables=variables)
    print("Detected revocation candidates:", ", ".join(plan.candidate_rule_ids) or "none")
    for candidate in plan.candidates:
        print(f"{candidate.rule_id}: revocation_supported={candidate.revocation_supported}")
        for issue in candidate.input_diagnostics:
            print(f"  {issue.stage}: {issue.message}")
    # A family selects every loaded matching rule, but only detected credentials
    # with revocation support are validated. Exact IDs select only that rule.
    # Exact display names are accepted; typos only suggest alternatives.
    if not args.validate and not args.confirm:
        return
    results = plan.validate(Validator())
    for result in results:
        print(f"{result.finding.rule_id}: validation={result.outcome}, revocation_ready={result.revocation_ready}")
    if args.confirm:
        # Never treat the first matching/active result as a disambiguation policy.
        if len(results) != 1 or not results[0].revocation_ready:
            parser.error("need one unambiguous ready candidate; supply an exact rule ID and complete inputs")
        result = revoker.revoke(results[0], confirm=True)
        print(f"{result.rule_id}: revoked={result.revoked}, http_status={result.http_status}")


if __name__ == "__main__":
    main()
