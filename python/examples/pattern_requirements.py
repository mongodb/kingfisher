"""Run: uv run --no-sync python python/examples/pattern_requirements.py

Keep structured-data.yml beside this script. All values are synthetic examples.
"""
from pathlib import Path

from kingfisher_sdk import Rules, Scanner


def main():
    # Compile only these custom rules. Scanning and checksums stay offline;
    # neither a Validator nor a CLI subprocess is needed.
    rules = Rules([Path(__file__).with_name("structured-data.yml")], builtins=False)
    scanner = Scanner(rules)
    findings = scanner.scan(
        "card=4111 1111 1111 1111\ncard=4111 1111 1111 1112\n"
        "iban=GB82 WEST 1234 5698 7654 32\niban=GB82 WEST 1234 5698 7654 33"
    )
    assert {finding.rule_id for finding in findings} == {
        "acme.structured.card", "acme.structured.iban"
    }
    assert len(findings) == 2  # Invalid checksums are removed during detection.
    for finding in findings:
        print(finding.to_dict())  # Keep structured personal data redacted too.


if __name__ == "__main__":
    main()
