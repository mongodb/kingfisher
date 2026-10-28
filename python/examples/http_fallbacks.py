"""Validate a file with trusted HTTP rules; fallback environments require opt-in.

uv run --no-sync python python/examples/http_fallbacks.py FILE --rules-path RULES.yml --fallbacks
Omit --fallbacks to use only each rule's existing primary validator.
"""
import argparse
import json
from pathlib import Path

from kingfisher_sdk import Rules, Scanner, Validator

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
parser.add_argument("--rules-path", action="append", required=True)
parser.add_argument("--fallbacks", action="store_true",
                    help="Allow credentials to reach up to two configured HTTP alternatives")
args = parser.parse_args()
rules = Rules(args.rules_path, builtins=False)
# Scanning stays offline; validation is an explicit network operation.
findings = Scanner(rules).scan_file(args.path)
validator = Validator(http_fallbacks=args.fallbacks)
for result in validator.validate(findings):
    # Default serialization is redacted and excludes private endpoint snapshots.
    # Revoker.revoke(result, confirm=True) is a separate, explicitly confirmed operation.
    print(json.dumps(result.to_dict()))
