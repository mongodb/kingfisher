"""SMTP uses the shared native validator and keeps provider work explicit."""
from pathlib import Path

import pytest

from kingfisher_sdk import Rules, Scanner, Validator


@pytest.mark.parametrize("port", ["", "SMTP_PORT=587\n"])
def test_smtp_components_resolve_and_internal_targets_stay_blocked(port):
    rules_path = Path(__file__).resolve().parents[2] / "examples/rules/smtp.yml"
    rules = Rules([rules_path], builtins=False)
    findings = Scanner(rules).scan(
        "SMTP_HOST=127.0.0.1\n"
        f"{port}"
        "SMTP_USERNAME=user@example.com\n"
        "SMTP_PASSWORD=fixture-only-password\n"
    )
    # Preserve all helpers from this input. The default policy rejects the
    # loopback target before opening a connection or submitting credentials.
    results = Validator().validate(findings)
    primary = next(result for result in results if result.finding.visible)
    assert primary.finding.rule_id == "custom.smtp.password"
    assert primary.outcome == "skipped"
    assert primary.reason == "target_blocked"
    assert "fixture-only-password" not in str(primary.to_dict())
