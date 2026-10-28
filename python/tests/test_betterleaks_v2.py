"""Betterleaks provider programs use one explicit shared Rust execution engine."""
import json

import pytest

from kingfisher_sdk import DetectionPolicy, Revoker, Rules, Scanner, ValidationResult, Validator
from test_resolved_credentials import ACCOUNT, TOKEN, provider


def test_v2_validation_analysis_and_revocation_are_separate(tmp_path):
    path = tmp_path / "v2.toml"
    path.write_text('''
minVersion = "v2.0.0"
[[rules]]
id = "account"
regex = '(?P<account>account_[a-z]{4})'
[[rules]]
id = "credential"
regex = '(demo_[a-z0-9]{16})'
components = [{id = "account"}]
validate = \'\'\'
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let response = http.get(endpoint + "/identity", {Authorization: "Bearer " + finding.secret, "X-Account": components["account"].captures.account});
response.status == 200 ? {result: "valid", metadata: {account: components["account"].secret}, analysis: {private: "PRIVATE_HANDOFF_MARKER"}} : validate.unknown(response)
\'\'\'
analyze = \'\'\'
{identity: {id: validation.metadata.account}, capabilities: analysis.capabilities({read: validation.analysis.private == "PRIVATE_HANDOFF_MARKER"})}
\'\'\'
revoke = \'\'\'
let endpoint = env.getOrDefault("ENDPOINT", "https://invalid.example");
let response = http.delete(endpoint + "/token", {Authorization: "Bearer " + finding.secret, "X-Account": components["account"].captures.account});
response.status == 204 ? {result: "revoked"} : revoke.unknown(response)
\'\'\'
''', encoding="utf-8")
    rules = Rules([path], builtins=False)
    with provider() as (endpoint, calls):
        findings = Scanner(rules).scan_with_attributes(ACCOUNT + "\n" + TOKEN, {"path": "settings.env", "git.sha": "synthetic"})
        assert calls == []
        validator = Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True)
        results = validator.validate(findings)
        result, = [item for item in results if item.finding.rule_id == "custom.credential"]
        assert result.outcome == "verified_active"
        assert calls == [("GET", "/identity")]
        changed = validator.with_variables({"ENDPOINT": "https://invalid.example"})
        analysis = changed.analyze(result)
        assert analysis["identity"]["id"] == ACCOUNT
        assert analysis["capabilities"] == ["read"]
        assert "PRIVATE_HANDOFF_MARKER" not in repr(result) + json.dumps(result.to_dict())
        assert calls == [("GET", "/identity")]
        with pytest.raises(ValueError, match="confirm=True"):
            Revoker(rules).revoke(result)
        assert Revoker(rules).revoke(result, confirm=True).revoked
        assert calls == [("GET", "/identity"), ("DELETE", "/token")]
        with pytest.raises(TypeError, match="ValidationResult"):
            validator.analyze("not a validation result")
        synthetic = ValidationResult(result.finding, "verified_active", None, 200)
        with pytest.raises(ValueError, match="original native"):
            validator.analyze(synthetic)


def test_v2_source_attributes_preserve_policy_controls_and_deduplication(tmp_path):
    path = tmp_path / "attributes.toml"
    path.write_text("""
prefilter = 'attributes["git.remote_url"] != "https://example.test/owner/repo"'
[[rules]]
id = "credential"
regex = '(demo_[a-z0-9]{16})'
filter = 'attributes["git.author_name"] == "automation"'
""", encoding="utf-8")
    rules = Rules([path], builtins=False)
    attributes = {"path": "settings.env", "git.remote_url": "https://example.test/owner/repo",
                  "git.author_name": "alice", "git.sha": "first"}
    scanner = Scanner(rules, dedup=True)
    assert scanner.scan(TOKEN) == []
    assert len(scanner.scan_with_attributes(TOKEN, attributes)) == 1
    assert scanner.scan_with_attributes(TOKEN, attributes) == []
    assert len(scanner.scan_with_attributes(TOKEN, {**attributes, "git.sha": "second"})) == 1
    assert scanner.scan_with_attributes(TOKEN, {**attributes, "git.author_name": "automation"}) == []
    policy = Scanner(rules, policy=DetectionPolicy())
    assert policy.scan_with_attributes(TOKEN + " # kingfisher:ignore", attributes) == []
    assert len(policy.scan_with_attributes(TOKEN, attributes)) == 1
    with pytest.raises(TypeError, match="str or bytes"):
        scanner.scan_with_attributes(7, attributes)
    with pytest.raises(TypeError):
        scanner.scan_with_attributes(TOKEN, {"path": 7})


def test_v2_explicit_unknown_revocation_remains_indeterminate(tmp_path):
    path = tmp_path / "unknown.yml"
    path.write_text(json.dumps({"rules": [{
        "id": "acme.unknown", "name": "Indeterminate revocation",
        "pattern": "(demo_[a-z0-9]{16})",
        "validation": {"type": "Betterleaks", "content": {"expression": "{result: \"valid\"}"}},
        "revocation": {"type": "Betterleaks", "content": {"expression": "{result: \"unknown\", reason: \"revoked\"}"}},
    }]}), encoding="utf-8")
    rules = Rules([path], builtins=False)
    validated, = Validator().validate(Scanner(rules).scan(TOKEN))
    revoker = Revoker(rules)
    with pytest.raises(RuntimeError) as error:
        revoker.revoke(validated, confirm=True)
    assert error.value.outcome_unknown is True
    assert TOKEN not in str(error.value)
    batch = revoker.revoke_many([validated], confirm=True)
    assert batch[0].outcome == "unknown"
