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
from kingfisher_sdk import Revoker

parser = argparse.ArgumentParser(description="Revoke a credential at its provider")
parser.add_argument("rule_id")
parser.add_argument("--confirm", action="store_true", help="Authorize credential revocation")
args = parser.parse_args()
result = Revoker().revoke(args.rule_id, os.environ["KINGFISHER_SECRET"],
                         confirm=args.confirm,
                         variables=json.loads(os.environ.get("KINGFISHER_VARIABLES", "{}")))
print(json.dumps(asdict(result)))
