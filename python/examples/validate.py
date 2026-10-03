"""Scan one file and explicitly contact providers to validate its credentials.

Checkout: uv run --no-sync python python/examples/validate.py FILE --outcome verified_active
Published: uv run --no-project --with kingfisher-secret-scanner python validate.py FILE
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
from fnmatch import fnmatchcase
import json
from pathlib import Path

from kingfisher_sdk import Rules, Scanner, Validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--rules-path", action="append", default=[])
    parser.add_argument("--no-builtins", action="store_true")
    parser.add_argument("--confidence", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--scan-timeout", type=float, help="Cooperative limit for detection")
    parser.add_argument("--timeout", type=float, default=10, help="Provider request timeout, not whole scan")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--variables-file", type=Path, help="Trusted JSON object of supporting values/endpoints")
    parser.add_argument("--max-response-bytes", type=int, default=1 << 20,
                        help="YAML HTTP response limit; other validator families have their own limits")
    parser.add_argument("--rule", action="append", default=[], help="REPORT rule ID glob; all findings are validated")
    parser.add_argument("--outcome", action="append", default=[], choices=[
        "verified_active", "verified_inactive", "unavailable", "skipped",
        "not_attempted", "assumed", "locally_derived", "invalid_material",
    ], help="REPORT outcome; repeatable, OR combined")
    args = parser.parse_args()
    variables = json.loads(args.variables_file.read_text(encoding="utf-8")) if args.variables_file else {}
    if not isinstance(variables, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in variables.items()
    ):
        parser.error("--variables-file must contain a JSON object of string keys and values")
    rules = Rules(args.rules_path, builtins=not args.no_builtins, confidence=args.confidence)
    # Leave redact=False internally: validation needs raw credentials. to_dict()
    # redacts output. scan_file supplies the path to path-aware rules/filters.
    findings = Scanner(rules).scan_file(args.path.expanduser(), timeout=args.scan_timeout)
    validator = Validator(timeout=args.timeout, concurrency=args.concurrency, retries=args.retries,
                          variables=variables, max_response_bytes=args.max_response_bytes)
    # Validate ONE INPUT's complete list, including invisible component helpers.
    # Report filters below do not reduce provider requests. To limit detection,
    # load a focused custom Rules(..., builtins=False) catalog instead.
    for result in validator.validate(findings):
        if not result.finding.visible:
            continue
        if args.outcome and result.outcome not in args.outcome:
            continue
        data = result.to_dict()
        if args.rule and not any(fnmatchcase(data["finding"]["rule_id"], pattern) for pattern in args.rule):
            continue
        # Other predicates: result.http_status == 401; result.reason is not None;
        # data["finding"]["entropy"] >= 3.5; location or fingerprint allowlists.
        # "unavailable" is inconclusive; "assumed"/"locally_derived" do not prove
        # live provider access. Keep them when investigating incomplete checks.
        print(json.dumps(data))


if __name__ == "__main__":
    main()
