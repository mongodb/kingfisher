"""From a source checkout: uv run --no-sync python python/examples/scan.py path/to/file

Published package: uv run --no-project --with kingfisher-secret-scanner python scan.py path/to/file
Import name: kingfisher_sdk.
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
import json
from kingfisher_sdk import Scanner

parser = argparse.ArgumentParser(description="Scan one file offline; output redacted JSON")
parser.add_argument("path")
args = parser.parse_args()
for finding in Scanner().scan_file(args.path):
    if finding.visible:
        print(json.dumps(finding.to_dict()))
