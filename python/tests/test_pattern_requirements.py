"""Rule requirements must run in native detection, before validation/reporting."""
import base64
import json
from pathlib import Path
import subprocess
import sys

import pytest
from kingfisher_sdk import DetectionScanner, Rules, Scanner


@pytest.mark.parametrize("scanner_type", [Scanner, DetectionScanner])
@pytest.mark.parametrize("encoded", [False, True])
@pytest.mark.parametrize("requirements,expected", [
    ({"ignore_if_contains": [" 4111 "]}, []),
    ({"min_uppercase": 1}, []),
    ({"checksum": {"actual": {"template": "0"}, "expected": "1"}}, []),
    ({"checksum": {"actual": {"template": "{{ MATCH | luhn_valid }}"}, "expected": "true"}},
     ["4111 1111 1111 1111"]),
])
def test_requirements_filter_native_candidates(tmp_path, scanner_type, encoded, requirements, expected):
    path = tmp_path / "requirements.yml"
    path.write_text(json.dumps({"rules": [{
        "id": "acme.card", "name": "Card", "confidence": "medium",
        "pattern": r"card ([0-9](?:[ -]?[0-9]){15})\b",
        "pattern_requirements": requirements,
    }]}), encoding="utf-8")
    rules = Rules([path], builtins=False, cache=False)
    assert rules.detail("acme.card")["pattern_requirements"] is not None
    content = b"card 4111 1111 1111 1111\ncard 4111 1111 1111 1112"
    if encoded:
        content = base64.b64encode(content)
    findings = scanner_type(rules).scan(content)
    assert [finding.secret for finding in findings] == expected
    assert all(finding.is_base64_encoded == encoded for finding in findings)


def test_structured_data_example():
    example = Path(__file__).resolve().parents[1] / "examples" / "pattern_requirements.py"
    result = subprocess.run([sys.executable, str(example)], check=True,
                            capture_output=True, text=True, timeout=60)
    assert "[REDACTED]" in result.stdout
    assert "4111" not in result.stdout and "GB82" not in result.stdout


def test_credential_uri_syntax_is_checked_offline(tmp_path):
    path = tmp_path / "uri.yml"
    path.write_text(json.dumps({"rules": [{
        "id": "acme.uri", "name": "Credential URI", "confidence": "medium",
        "pattern": r"(?P<URI>https?://[^\s]+)", "validation": {"type": "CredentialUri"},
    }]}), encoding="utf-8")
    scanner = Scanner(Rules([path], builtins=False, cache=False), base64=False)
    assert scanner.scan("https://user@example.test") == []
    assert len(scanner.scan("https://user:password@example.test")) == 1


def test_full_match_component_windows_survive_python_validation(tmp_path):
    from kingfisher_sdk import Validator
    from test_sdk import mock

    source = {"rules": [{
        "id": "acme.primary", "name": "Primary", "confidence": "medium",
        "pattern": r"PREFIX_x{48}(demo_[a-z0-9]{16})",
        "depends_on_rule": [{"rule_id": "acme.helper", "variable": "HELP", "within": "16C"}],
        "validation": {"type": "Http", "content": {"request": {
            "url": "{{ ENDPOINT }}/identity", "method": "GET",
            "headers": {"Authorization": "Bearer {{ TOKEN }}"},
            "response_matcher": [{"type": "StatusMatch", "status": [200]}],
        }}},
    }, {"id": "acme.helper", "name": "Helper", "confidence": "medium",
        "pattern": r"(HELP_[a-z0-9]{8})", "visible": False}]}
    path = tmp_path / "windows.yml"
    path.write_text(json.dumps(source), encoding="utf-8")
    text = "HELP_efgh5678 PREFIX_" + "x" * 48 + mock.TOKEN
    findings = Scanner(Rules([path], builtins=False, cache=False)).scan(text)
    primary, = [finding for finding in findings if finding.visible]
    assert text[primary.location["start_offset"]:primary.location["end_offset"]] == mock.TOKEN
    with mock.mock_provider() as (endpoint, handler):
        results = Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True).validate(findings)
        assert next(result for result in results if result.finding.visible).outcome == "verified_active"
        assert len(handler.calls) == 1


@pytest.mark.parametrize("verify", [False, True])
def test_candidate_verification_and_batch_request_grouping(tmp_path, verify):
    from kingfisher_sdk import Validator
    from test_sdk import mock

    with mock.mock_provider() as (endpoint, handler):
        path = tmp_path / "candidates.yml"
        path.write_text(json.dumps({"rules": [{
            "id": "acme.primary", "name": "Primary", "confidence": "medium",
            "pattern": r"(primary_[a-z0-9]{8})",
            "depends_on_rule": [{"rule_id": "acme.component", "variable": "SECRET",
                                 "verify_candidates": verify}],
            "validation": {"type": "Http", "content": {"request": {
                "url": endpoint + "/identity", "method": "GET",
                "headers": {"Authorization": "Bearer {{ SECRET }}"},
                "response_matcher": [{"type": "StatusMatch", "status": [200]}],
            }}},
        }, {"id": "acme.component", "name": "Component", "confidence": "medium",
            "pattern": r"(demo_[a-z0-9]{16})", "visible": False}]}), encoding="utf-8")
        findings = Scanner(Rules([path], builtins=False, cache=False)).scan(
            "primary_abcd1234 demo_0000000000000000 primary_abcd1234\n"
            + "padding " * 10 + mock.TOKEN
        )
        results = Validator(allow_internal_ips=True).validate(findings)
        visible = [result for result in results if result.finding.visible]
        assert len(visible) == 2
        if verify:
            assert all(result.outcome == "verified_active" for result in visible)
            assert all(result.credential.variables["SECRET"] == mock.TOKEN for result in visible)
            assert len(handler.calls) == 2  # Both occurrences share each attempted credential.
        else:
            assert all(result.reason == "ambiguous_dependency" for result in visible)
            assert handler.calls == []
