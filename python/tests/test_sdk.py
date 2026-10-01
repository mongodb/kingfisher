"""Native extension contracts; no real provider credentials or internet calls."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from kingfisher_sdk import Rules, Scanner, Validator, Revoker, shannon_entropy

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
spec = importlib.util.spec_from_file_location("local_workflow", EXAMPLES / "local_workflow.py")
mock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mock)


@pytest.fixture
def rules():
    return Rules([mock.RULE_PATH], builtins=False)


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_scan_file_and_redaction(rules, tmp_path, newline):
    scanner = Scanner(rules)
    path = tmp_path / "credential with spaces.txt"
    # Write exact bytes so Windows text-mode newline translation cannot change
    # the fixture. Offsets refer to the scanned bytes for both line endings.
    prefix = b"prefix" + newline
    path.write_bytes(prefix + mock.TOKEN.encode("utf-8"))
    finding, = scanner.scan_file(path)
    assert finding.rule_id == mock.RULE_ID
    assert finding.secret == mock.TOKEN
    assert finding.to_dict()["location"]["line"] == 2
    assert finding.to_dict()["location"]["start_offset"] == len(prefix)
    assert mock.TOKEN not in repr(finding)
    assert mock.TOKEN not in json.dumps(finding.to_dict())
    assert finding.to_dict(redact=False)["secret"] == mock.TOKEN
    assert scanner.scan("nothing here") == []
    with pytest.raises(RuntimeError):
        scanner.scan_file(tmp_path / "missing")


def test_threads_dedup_and_entropy(rules):
    scanner = Scanner(rules)
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert all(len(f) == 1 for f in pool.map(scanner.scan, [mock.TOKEN] * 8))
    scanner = Scanner(rules, dedup=True)
    assert len(scanner.scan(mock.TOKEN)) == 1
    assert scanner.scan(mock.TOKEN) == []
    scanner.reset_dedup()
    assert len(scanner.scan(mock.TOKEN)) == 1
    assert shannon_entropy(b"aaaa") == 0
    assert shannon_entropy(b"abcd") == 2


def test_scan_validate_revoke_without_binary(rules, monkeypatch, tmp_path):
    # A library workflow must work with no CLI on PATH and no subprocesses.
    monkeypatch.setenv("PATH", str(tmp_path))
    def reject_subprocess(*args, **kwargs):
        raise AssertionError("SDK operations must execute in-process")
    monkeypatch.setattr(subprocess, "Popen", reject_subprocess)
    monkeypatch.setattr(os, "system", reject_subprocess)
    for name in ("posix_spawn", "posix_spawnp"):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, reject_subprocess)
    findings = Scanner(rules).scan(mock.TOKEN)
    with mock.mock_provider() as (endpoint, handler):
        variables = {"ENDPOINT": endpoint}
        assert handler.calls == []  # Scanning makes no requests.
        blocked, = Validator(variables=variables).validate(findings)
        assert blocked.outcome != "verified_active"
        assert handler.calls == []
        validator = Validator(variables=variables, allow_internal_ips=True)
        result, = validator.validate(findings)
        assert result.outcome == "verified_active"
        assert mock.TOKEN not in repr(result)
        assert mock.TOKEN not in json.dumps(result.to_dict())
        revoker = Revoker(rules)
        with pytest.raises(ValueError, match="confirm"):
            revoker.revoke(mock.RULE_ID, mock.TOKEN, variables=variables)
        assert handler.active
        with pytest.raises(ValueError, match="exact"):
            revoker.revoke("acme", mock.TOKEN, confirm=True)
        revoked = revoker.revoke(mock.RULE_ID, mock.TOKEN, confirm=True, variables=variables)
        assert revoked.revoked and revoked.http_status == 204
        assert validator.validate(findings)[0].outcome == "verified_inactive"
        assert sum(method == "DELETE" for method, _ in handler.calls) == 1


def test_redacted_and_invalid_input(rules, tmp_path):
    findings = Scanner(rules, redact=True).scan(mock.TOKEN)
    result, = Validator().validate(findings)
    assert result.outcome == "skipped" and result.reason == "redacted_input"
    for timeout in [0, -1, float("nan"), float("inf")]:
        with pytest.raises(ValueError):
            Validator(timeout=timeout)
        with pytest.raises(ValueError):
            Revoker(rules, timeout=timeout)
    with pytest.raises(RuntimeError):
        Validator(concurrency=0)
    with pytest.raises(ValueError):
        Rules(builtins=False)
    with pytest.raises(ValueError):
        Rules(confidence="invalid")
    bad = tmp_path / "bad.yml"
    bad.write_text("rules: [invalid", encoding="utf-8")
    with pytest.raises(RuntimeError):
        Rules([bad], builtins=False)
    with pytest.raises(ValueError):
        Revoker(rules).revoke(mock.RULE_ID, "[REDACTED]", confirm=True)


def test_builtin_catalog_and_custom_toml(tmp_path):
    rules = Rules()
    assert len(rules) > 100
    assert any(r["revocation"] for r in rules.metadata())
    path = tmp_path / "acme.toml"
    path.write_text('''[[rules]]
id = "acme-token"
description = "Synthetic token"
regex = '(demo_[a-z0-9]{16})'
''', encoding="utf-8")
    finding, = Scanner(Rules([path], builtins=False)).scan(mock.TOKEN)
    assert finding.rule_id == "custom.acme-token"
    result, = Validator().validate([finding])
    assert result.outcome == "not_attempted"
    with pytest.raises(ValueError, match="no revocation"):
        Revoker(Rules([path], builtins=False)).revoke(finding.rule_id, mock.TOKEN, confirm=True)


def test_example_lifecycle():
    result = subprocess.run([sys.executable, str(EXAMPLES / "local_workflow.py")],
                            check=True, capture_output=True, text=True, timeout=60)
    assert "After revocation: verified_inactive" in result.stdout
    assert mock.TOKEN not in result.stdout


def test_multistep_revocation(tmp_path):
    # The first request extracts the status, and Liquid uses it in the second.
    source = mock.RULE_PATH.read_text(encoding="utf-8")
    source = source[:source.index("    revocation:")] + '''    revocation:
      type: HttpMultiStep
      content:
        steps:
          - request:
              method: GET
              url: '{{ ENDPOINT }}/identity'
              headers:
                Authorization: 'Bearer {{ TOKEN }}'
            extract:
              STATUS:
                type: StatusCode
          - request:
              method: DELETE
              url: '{{ ENDPOINT }}/token'
              headers:
                Authorization: 'Bearer {{ TOKEN }}'
                X-Lookup-Status: '{{ STATUS }}'
              response_matcher:
                - type: StatusMatch
                  status: [204]
'''
    path = tmp_path / "multistep.yml"
    path.write_text(source, encoding="utf-8")
    with mock.mock_provider() as (endpoint, handler):
        result = Revoker(Rules([path], builtins=False)).revoke(
            mock.RULE_ID, mock.TOKEN, confirm=True, variables={"ENDPOINT": endpoint})
        assert result.revoked
        assert handler.calls == [("GET", "/identity"), ("DELETE", "/token")]


def test_revocation_response_must_match(rules):
    with mock.mock_provider() as (endpoint, handler):
        result = Revoker(rules).revoke(mock.RULE_ID, "demo_wrongcredential1", confirm=True,
                                       variables={"ENDPOINT": endpoint})
        assert not result.revoked
        assert result.http_status == 403
        assert handler.active
