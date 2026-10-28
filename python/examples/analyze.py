"""Scan a local file, validate its credentials, and explicitly request analysis.

Checkout: uv run --no-sync python python/examples/analyze.py FILE --rules-path RULES.toml
Published: uv run --no-project --with kingfisher-secret-scanner python analyze.py FILE
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
import json
from pathlib import Path

from kingfisher_sdk import Rules, Scanner, Validator

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
parser.add_argument("--rules-path", action="append", default=[], required=True,
                    help="Trusted custom rules containing Betterleaks validate/analyze programs")
args = parser.parse_args()
rules = Rules(args.rules_path, builtins=False)
# Detection reads this file only. Keep invisible supporting findings for validation.
findings = Scanner(rules).scan_file(args.path, timeout=30)
validator = Validator(timeout=10, concurrency=4)
for result in validator.validate(findings, timeout=60):
    if not result.finding.visible or result.outcome != "verified_active":
        continue
    # Analysis is explicit and may make additional provider requests. It uses the
    # original validation's captures, components and private provider evidence.
    analysis = validator.analyze(result, timeout=30)
    # Provider identities/capabilities may be sensitive. Report only the fields
    # needed by your application; validation serialization stays redacted.
    print(json.dumps({"finding": result.to_dict(),
                      "capabilities": analysis.get("capabilities", [])}))
