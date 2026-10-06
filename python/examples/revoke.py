"""From a source checkout: uv run --no-sync python python/examples/revoke.py EXACT_RULE_ID --confirm

Reads KINGFISHER_SECRET from the environment, never from command-line arguments.
Optional supporting variables are a JSON object in KINGFISHER_VARIABLES.

Published package: uv run --no-project --with kingfisher-secret-scanner python revoke.py EXACT_RULE_ID --confirm
Import name: kingfisher_sdk.
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
from dataclasses import asdict
import json
import os
from kingfisher_sdk import Rules, Revoker

parser = argparse.ArgumentParser(description="Revoke a credential at its provider")
parser.add_argument("rule_id")
parser.add_argument("--confirm", action="store_true", help="Authorize credential revocation")
parser.add_argument("--rules-path", action="append", default=[], help="Custom YAML/TOML rules; repeatable")
parser.add_argument("--no-builtins", action="store_true", help="Load only custom rules")
parser.add_argument("--timeout", type=float, default=10, help="Provider request timeout in seconds")
args = parser.parse_args()
rules = Rules(args.rules_path, builtins=not args.no_builtins)
# Discover exact IDs and supported actions without exposing credential values:
# supported = [r for r in rules.metadata() if r["revocation"]]
# Rule globs used for scan reports are not accepted by revoke(); select one ID.
# Supporting credentials/endpoint variables must be supplied explicitly. They
# are not inferred from scan findings or read from the CLI configuration.
result = Revoker(rules, timeout=args.timeout).revoke(args.rule_id, os.environ["KINGFISHER_SECRET"],
                         confirm=args.confirm,
                         variables=json.loads(os.environ.get("KINGFISHER_VARIABLES", "{}")))
# revoke(..., timeout=..., cancellation=token) also supports application
# shutdown controls. Interruption cannot undo a submitted provider action.
# No automatic retries: a timeout can happen after the provider applied the action.
print(json.dumps(asdict(result)))  # Contains status, never the credential.
