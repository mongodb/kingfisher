"""Scan a file, validate, and explicitly revoke supported active credentials.

Checkout: uv run --no-sync python python/examples/scan_validate_revoke.py FILE --confirm
Published: uv run --no-project --with kingfisher-secret-scanner python scan_validate_revoke.py FILE --confirm

Targets AWS, GCP, Hugging Face, GitLab, Slack and GitHub. All credential values
come from scan results. Running with --confirm performs real revocations.
"""
import argparse
from pathlib import Path

from kingfisher_sdk import Revoker, Rules, Scanner, Validator

PREFIXES = (
    "betterleaks.aws-", "betterleaks.gcp-", "betterleaks.huggingface-",
    "betterleaks.gitlab-", "betterleaks.slack-", "betterleaks.github-",
    "veles.secrets/slack",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--confirm", action="store_true",
                        help="Perform real revocations; otherwise only report validation/readiness")
    args = parser.parse_args()
    rules = Rules()
    findings = Scanner(rules).scan_file(args.path)
    # Retain helpers for association, and keep each file's findings in its own batch.
    selected = [finding for finding in findings
                if not finding.visible or finding.rule_id.startswith(PREFIXES)]
    validator = Validator(timeout=10, concurrency=4)
    revoker = Revoker(rules, timeout=10)
    validated = [result for result in validator.validate(selected) if result.finding.visible]
    for result in validated:
        if not result.finding.visible:
            continue
        rule_id = result.finding.rule_id
        print(f"{rule_id}: validation={result.outcome}, revocation_ready={result.revocation_ready}")
    if args.confirm:
        # Native action identity and complete resolved inputs control deduplication.
        # Batch interruption stops pending actions and retains safe status metadata.
        for status in revoker.revoke_many(validated, confirm=True):
            print(f"{status.rule_id}: revocation={status.outcome}, reason={status.reason}")



if __name__ == "__main__":
    main()
