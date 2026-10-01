"""From a source checkout: uv run --no-sync python python/examples/validate.py path/to/file

Contacts providers using detected credentials. Does not revoke anything.

Published package: uv run --no-project --with kingfisher-secret-scanner python validate.py path/to/file
Import name: kingfisher_sdk.
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
import json
from kingfisher_sdk import Scanner, Validator

parser = argparse.ArgumentParser(description="Scan and validate credentials in one file")
parser.add_argument("path")
args = parser.parse_args()
findings = Scanner().scan_file(args.path)
for result in Validator(timeout=10, concurrency=4).validate(findings):
    if result.finding.visible:
        print(json.dumps(result.to_dict()))
