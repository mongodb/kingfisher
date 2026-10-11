"""Detect and explicitly authenticate SMTP credentials without sending email.

Checkout: uv run --no-sync python python/examples/validate_smtp.py CONFIG
Outside the checkout, pass --rules-path pointing to examples/rules/smtp.yml.
Validation contacts detected servers; scanning alone stays offline.
"""
import argparse
from pathlib import Path

from kingfisher_sdk import Rules, Scanner, Validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--rules-path", type=Path,
                        default=Path(__file__).resolve().parents[2] / "examples/rules/smtp.yml")
    parser.add_argument("--allow-internal-ips", action="store_true",
                        help="Allow validation of trusted internal mail servers")
    args = parser.parse_args()
    # Focus this example on separate SMTP fields. Built-in credential URI rules
    # also support smtp/smtps and can be loaded independently with Rules().
    rules = Rules([args.rules_path], builtins=False)
    findings = Scanner(rules).scan_file(args.path)
    # Keep invisible host, username, and port helpers from this input until the
    # shared validator associates them. TLS certificate verification stays on.
    validator = Validator(timeout=10, concurrency=4,
                          allow_internal_ips=args.allow_internal_ips)
    for result in validator.validate(findings, timeout=30):
        if result.finding.visible:
            # Report redacted values after validation; do not print raw findings.
            print(result.to_dict())


if __name__ == "__main__":
    main()
