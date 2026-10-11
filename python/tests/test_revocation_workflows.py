"""Source preparation, actionable diagnostics and batch revocation boundaries."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
import json
import math
from pathlib import Path
import random
import string
import subprocess
import sys

import pytest

from kingfisher_sdk import CancellationToken, Revoker, Rules, Scanner, Validator
from test_resolved_credentials import ACCOUNT, TOKEN, provider, rules_file


def setup(tmp_path, endpoint, **options):
    rules = Rules([rules_file(tmp_path, **options)], builtins=False)
    return Revoker(rules), Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True)


def test_file_and_logical_path_preparation_preserve_inputs_and_close_file(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        config = tmp_path / "credentials.conf"
        config.write_text(ACCOUNT + "\r\n" + TOKEN, encoding="utf-8")
        plan = revoker.prepare_from_file(config, provider="acme.multipart", variables={"ENDPOINT": endpoint})
        assert calls == []
        assert plan.source_path == str(config)
        assert plan.candidates[0].ready_for_validation
        config.unlink()  # In particular, no mapped handle can remain open on Windows.
        result, = plan.validate(Validator(allow_internal_ips=True))
        assert result.revocation_ready
        assert result.credential.components[0].secret == ACCOUNT
        assert result.credential.revocation.variables["ENDPOINT"] == endpoint
        summary = json.dumps(plan.to_dict())
        assert TOKEN not in summary and ACCOUNT not in summary
        assert TOKEN in json.dumps(plan.to_dict(redact=False))
        assert endpoint not in repr(plan)
        text_plan = revoker.prepare_from_text(ACCOUNT + "\n" + TOKEN, path=config, variables={"ENDPOINT": endpoint})
        assert text_plan.source_path == str(config)
        assert text_plan.candidates[0].input_diagnostics == ()


def test_path_aware_preparation_honors_real_and_logical_path(tmp_path):
    with provider() as (endpoint, calls):
        revoker, _ = setup(tmp_path, endpoint)
        path = tmp_path / "multipart.yml"
        definitions = json.loads(path.read_text(encoding="utf-8"))
        definitions["rules"][0]["path"] = r".*\.conf$"
        path.write_text(json.dumps(definitions), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        source = ACCOUNT + "\n" + TOKEN
        assert revoker.prepare(source).candidate_rule_ids == ()
        assert revoker.prepare_from_text(source, path="settings.conf").candidate_rule_ids == ("acme.multipart",)
        file = tmp_path / "settings.conf"
        file.write_text(source, encoding="utf-8")
        assert revoker.prepare_from_file(file).candidate_rule_ids == ("acme.multipart",)
        assert calls == []


def test_missing_endpoint_and_conflicting_companion_diagnostics_are_safe(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        plan = revoker.prepare_from_text(ACCOUNT + "\n" + TOKEN)
        candidate, = plan.candidates
        assert {(issue.stage, issue.variable) for issue in candidate.missing_inputs} == {
            ("validation", "ENDPOINT"), ("revocation", "ENDPOINT")}
        assert "endpoint variable ENDPOINT required" in candidate.missing_inputs[0].message
        result, = plan.validate()
        assert result.outcome == "skipped" and not result.revocation_ready
        assert calls == []
        result, = plan.validate(validator)
        assert result.revocation_ready  # Re-inspection honors explicit execution variables.
        ambiguous = revoker.prepare(ACCOUNT + "\n" + TOKEN + "\naccount_efgh", variables={"ENDPOINT": endpoint})
        issue, = [issue for issue in ambiguous.candidates[0].input_diagnostics
                  if issue.code == "ambiguous_dependency"]
        assert issue.variable == "ACCOUNT" and issue.rule_id == "acme.account"
        before = len(calls)
        ambiguous.validate(validator)
        assert len(calls) == before
        assert all(value not in repr(ambiguous) + json.dumps(ambiguous.to_dict())
                   for value in (TOKEN, ACCOUNT, "account_efgh", endpoint))


def test_revocation_only_missing_input_allows_validation_but_blocks_revocation(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        path = tmp_path / "multipart.yml"
        definitions = json.loads(path.read_text(encoding="utf-8"))
        definitions["rules"][0]["revocation"]["content"]["request"]["url"] += "/{{ KEY_ID }}"
        path.write_text(json.dumps(definitions), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        plan = revoker.prepare(ACCOUNT + "\n" + TOKEN, variables={"ENDPOINT": endpoint})
        candidate, = plan.candidates
        assert candidate.ready_for_validation
        assert candidate.missing_inputs[0].variable == "KEY_ID"
        result, = plan.validate(validator)
        assert result.outcome == "verified_active" and not result.revocation_ready
        assert result.input_diagnostics[0].variable == "KEY_ID"
        batch = revoker.revoke_many([result], confirm=True)
        assert batch[0].outcome == "skipped"
        assert calls == [("GET", "/identity")]


def test_batch_confirmation_type_checks_and_duplicate_attempts(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        before = len(calls)
        with pytest.raises(ValueError, match="confirm=True"):
            revoker.revoke_many([result])
        with pytest.raises(TypeError, match="ValidationResult"):
            revoker.revoke_many([result, "bad"], confirm=True)
        assert len(calls) == before
        batch = revoker.revoke_many(iter([result, result]), confirm=True)
        assert [item.outcome for item in batch] == ["revoked", "duplicate"]
        assert batch[1].duplicate_of == 0
        assert calls[before:] == [("DELETE", "/token")]
        assert all(value not in repr(batch) + json.dumps([asdict(item) for item in batch])
                   for value in (TOKEN, ACCOUNT, endpoint))
        assert revoker.revoke_many([], confirm=True) == []


def test_batch_distinguishes_original_definitions_and_endpoint_snapshots(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        first, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        path = tmp_path / "multipart.yml"
        definitions = json.loads(path.read_text(encoding="utf-8"))
        definitions["rules"][0]["revocation"]["content"]["request"]["url"] = endpoint + "/other-token"
        path.write_text(json.dumps(definitions), encoding="utf-8")
        second, = Revoker(Rules([path], builtins=False)).prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        batch = revoker.revoke_many([first, second, first], confirm=True)
        assert [item.outcome for item in batch] == ["revoked", "revoked", "duplicate"]
        assert [path for method, path in calls if method == "DELETE"] == ["/token", "/other-token"]
    with provider() as (endpoint_a, calls_a), provider() as (endpoint_b, calls_b):
        first, = revoker.prepare(ACCOUNT + "\n" + TOKEN, variables={"ENDPOINT": endpoint_a}).validate(Validator(allow_internal_ips=True))
        second, = revoker.prepare(ACCOUNT + "\n" + TOKEN, variables={"ENDPOINT": endpoint_b}).validate(Validator(allow_internal_ips=True))
        assert [item.outcome for item in revoker.revoke_many([first, second], confirm=True)] == ["revoked", "revoked"]
        assert calls_a[-1][0] == calls_b[-1][0] == "DELETE"


def test_unknown_provider_failure_is_not_retried_for_duplicate(tmp_path, monkeypatch):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        attempted = []
        def fail(*args, **kwargs):
            attempted.append(True)
            raise RuntimeError("potentially secret-bearing exception")
        monkeypatch.setattr(revoker, "revoke", fail)
        batch = revoker.revoke_many([result, result], confirm=True)
        assert [item.outcome for item in batch] == ["unknown", "duplicate"]
        assert len(attempted) == 1
        assert "secret-bearing" not in repr(batch)
        assert calls == [("GET", "/identity")]


@pytest.mark.parametrize("failure", ["invalid_url", "unsupported_scheme"])
def test_native_preflight_failure_is_failed_not_unknown(tmp_path, failure):
    with provider() as (endpoint, calls):
        path = rules_file(tmp_path)
        definitions = json.loads(path.read_text(encoding="utf-8"))
        request = definitions["rules"][0]["revocation"]["content"]["request"]
        if failure == "invalid_url":
            request["url"] = "invalid URL"
        else:
            request["url"] = "ftp://unused.invalid"
        path.write_text(json.dumps(definitions), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(
            Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True))
        assert result.revocation_ready
        with pytest.raises(RuntimeError, match="before mutation") as caught:
            revoker.revoke(result, confirm=True)
        assert caught.value.outcome_unknown is False
        assert TOKEN not in str(caught.value) and ACCOUNT not in str(caught.value)
        batch = revoker.revoke_many([result, result], confirm=True)
        assert [item.outcome for item in batch] == ["failed", "duplicate"]
        assert batch[0].reason == "request_failed"
        assert calls == [("GET", "/identity")]


def test_native_lookup_extraction_failure_is_failed_not_unknown(tmp_path):
    with provider() as (endpoint, calls):
        path = rules_file(tmp_path)
        definitions = json.loads(path.read_text(encoding="utf-8"))
        final = definitions["rules"][0]["revocation"]["content"]["request"]
        lookup = dict(definitions["rules"][0]["validation"]["content"]["request"])
        definitions["rules"][0]["revocation"] = {"type": "HttpMultiStep", "content": {
            "steps": [{"request": lookup, "extract": {"KEY_ID": {"type": "JsonPath", "path": "$.id"}}},
                      {"request": final}]}}
        path.write_text(json.dumps(definitions), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(
            Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True))
        assert result.revocation_ready
        # The lookup returns non-JSON; extraction fails before the DELETE.
        batch = revoker.revoke_many([result, result], confirm=True)
        assert [item.outcome for item in batch] == ["failed", "duplicate"]
        assert calls == [("GET", "/identity"), ("GET", "/identity")]


def test_batch_distinguishes_compound_pairs_and_reports_nonconfirmation(tmp_path):
    with provider(remapped=True) as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint, remapped=True)
        first, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        second, = revoker.prepare("account_efgh\n" + TOKEN).validate(validator)
        assert first.revocation_ready and second.revocation_ready
        batch = revoker.revoke_many([first, second, first, second], confirm=True)
        assert [item.outcome for item in batch] == ["revoked", "not_confirmed", "duplicate", "duplicate"]
        assert batch[1].result.http_status == 403
        assert [item.duplicate_of for item in batch[2:]] == [0, 1]
        assert calls == [("DELETE", "/token"), ("DELETE", "/token")]


def test_batch_skips_inactive_unsupported_and_manual_results(tmp_path):
    from kingfisher_sdk import ValidationResult
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare("account_efgh\n" + TOKEN).validate(validator)
        assert not result.revocation_ready
        unsupported, other_validator = setup(tmp_path, endpoint, revocation=False)
        finding = next(finding for finding in Scanner(unsupported.rules).scan(ACCOUNT + "\n" + TOKEN)
                       if finding.visible)
        unsupported_result = next(result for result in other_validator.validate([finding]) if result.finding.visible)
        manual = ValidationResult(result.finding, "verified_active", None, 200)
        before = len(calls)
        batch = revoker.revoke_many([result, unsupported_result, manual], confirm=True)
        assert [item.outcome for item in batch] == ["skipped"] * 3
        assert batch[2].reason == "unresolved_inputs"
        assert len(calls) == before


@pytest.mark.parametrize("cancel", [False, True])
def test_batch_interruption_retains_unknown_action_and_pending_indices(tmp_path, cancel):
    with provider(delay_delete=True) as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        cancellation = CancellationToken()
        with ThreadPoolExecutor(max_workers=1) as workers:
            future = workers.submit(revoker.revoke_many, [result, result], confirm=True,
                                    timeout=2 if cancel else 0.2, cancellation=cancellation)
            assert calls.entered.wait(timeout=3)
            if cancel:
                cancellation.cancel()
            try:
                with pytest.raises(RuntimeError if cancel else TimeoutError) as raised:
                    future.result(timeout=3)
                assert [item.outcome for item in raised.value.completed] == ["unknown"]
                assert raised.value.pending_indices == (1,)
                assert TOKEN not in repr(raised.value.completed)
            finally:
                calls.release.set()


@pytest.mark.parametrize("timeout", [0, -1, math.inf, math.nan, 1e30, 1e-300])
def test_invalid_deadlines_fail_before_mutation(tmp_path, timeout):
    with provider() as (endpoint, calls):
        revoker, _ = setup(tmp_path, endpoint)
        with pytest.raises(ValueError, match="timeout"):
            revoker.prepare(TOKEN, timeout=timeout)
        with pytest.raises(ValueError, match="timeout"):
            revoker.revoke_many([], confirm=True, timeout=timeout)
        assert calls == []


def test_unrelated_helper_validator_is_not_contacted(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        path = tmp_path / "multipart.yml"
        definitions = json.loads(path.read_text(encoding="utf-8"))
        definitions["rules"][1]["validation"] = {"type": "Http", "content": {"request": {
            "method": "GET", "url": "{{ ENDPOINT }}/helper-check",
            "response_matcher": [{"type": "StatusMatch", "status": [200]}]}}}
        path.write_text(json.dumps(definitions), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        assert result.revocation_ready
        assert calls == [("GET", "/identity")]


def test_preparation_controls_and_normal_scan_behavior(tmp_path):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        assert Scanner(revoker.rules).scan(TOKEN) == []
        plan = revoker.prepare(TOKEN)
        assert plan.candidate_rule_ids == ("acme.multipart",)
        token = CancellationToken()
        token.cancel()
        with pytest.raises(RuntimeError, match="cancel"):
            revoker.prepare_from_text(TOKEN, cancellation=token)
        with pytest.raises(RuntimeError, match="cancel"):
            plan.validate(validator, cancellation=token)
        with pytest.raises(RuntimeError):
            revoker.prepare_from_file(tmp_path / "absent.conf")
        assert calls == []


def test_new_examples_default_to_offline_redacted_output(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    secret = "ghp_" + "".join(random.Random(42).sample(string.ascii_letters + string.digits, 36))
    source = tmp_path / "application.conf"
    source.write_text(secret, encoding="utf-8")
    monkeypatch.setenv("KINGFISHER_VARIABLES", "{}")
    for name, arguments in [
        ("prepare_revocation.py", ["github", "--file", str(source)]),
        ("batch_revoke.py", [str(source), "--provider", "github"]),
    ]:
        result = subprocess.run([sys.executable, str(root / "python/examples" / name), *arguments],
                                check=True, capture_output=True, text=True, timeout=60)
        assert "betterleaks.github-pat" in result.stdout
        assert secret not in result.stdout + result.stderr


def test_revocation_examples_accept_custom_only_catalogs(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[2]
    catalog = tmp_path / "rules"
    catalog.mkdir()
    rule = catalog / "demo.yml"
    rule.write_text((root / "python/examples/demo.yml").read_text(encoding="utf-8"), encoding="utf-8")
    empty = tmp_path / "extra-rules"
    empty.mkdir()
    source = tmp_path / "application.conf"
    source.write_text(TOKEN, encoding="utf-8")
    monkeypatch.setenv("KINGFISHER_VARIABLES", "{}")
    # Repeated file/directory paths compose; the exact ID and family both select
    # our custom action without built-ins, provider requests or raw secret output.
    for name, arguments in [
        ("prepare_revocation.py", ["acme.python-demo", "--file", str(source)]),
        ("batch_revoke.py", [str(source), "--provider", "acme"]),
    ]:
        result = subprocess.run(
            [sys.executable, str(root / "python/examples" / name), *arguments,
             "--rules-path", str(rule), "--rules-path", str(empty), "--no-builtins"],
            check=True, capture_output=True, text=True, timeout=60)
        assert "acme.python-demo: revocation_supported=True" in result.stdout
        assert "ENDPOINT" in result.stdout  # The custom action's explicit input.
        assert "betterleaks." not in result.stdout
        assert TOKEN not in result.stdout + result.stderr


@pytest.mark.parametrize("confirm", [False, True])
def test_exact_rule_revoke_requires_secret_with_typeerror(confirm):
    with pytest.raises(TypeError, match="secret is required"):
        Revoker().revoke("github-pat", confirm=confirm)


def test_batch_keyboard_interrupt_during_bookkeeping_keeps_pending_inputs(tmp_path, monkeypatch):
    from kingfisher_sdk import ValidationResult
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        before = len(calls)
        def interrupted(_):
            raise KeyboardInterrupt()
        monkeypatch.setattr(ValidationResult, "revocation_ready", property(interrupted))
        with pytest.raises(KeyboardInterrupt) as raised:
            revoker.revoke_many([result, result], confirm=True)
        assert raised.value.completed == ()
        assert raised.value.pending_indices == (0, 1)
        assert len(calls) == before


def test_batch_keyboard_interrupt_after_response_keeps_completed_evidence(tmp_path, monkeypatch):
    import kingfisher_sdk.revocation as module
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        real = module.BatchRevocationResult
        interrupted = False
        def convert(*args, **kwargs):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return real(*args, **kwargs)
        monkeypatch.setattr(module, "BatchRevocationResult", convert)
        with pytest.raises(KeyboardInterrupt) as raised:
            revoker.revoke_many([result, result], confirm=True)
        assert [item.outcome for item in raised.value.completed] == ["revoked"]
        assert raised.value.completed[0].result.revoked
        assert raised.value.pending_indices == (1,)


def test_batch_keyboard_interrupt_in_flight_is_labeled_interrupted(tmp_path, monkeypatch):
    with provider() as (endpoint, calls):
        revoker, validator = setup(tmp_path, endpoint)
        result, = revoker.prepare(ACCOUNT + "\n" + TOKEN).validate(validator)
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()
        monkeypatch.setattr(revoker, "revoke", interrupted)
        with pytest.raises(KeyboardInterrupt) as raised:
            revoker.revoke_many([result, result], confirm=True)
        assert raised.value.completed[0].reason == "interrupted"
        assert raised.value.pending_indices == (1,)
