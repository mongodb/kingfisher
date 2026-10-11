"""Resolved multi-part credentials and explicit revocation; loopback services only."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from socketserver import TCPServer
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor

import pytest

from kingfisher_sdk import (
    CancellationToken, ResolvedCredential, RevocationInputs, Revoker, Rules,
    Scanner, ValidationResult, Validator,
)

TOKEN = "demo_abcd1234efgh5678"
ACCOUNT = "account_abcd"
RULE_ID = "acme.multipart"


@contextmanager
def provider(*, remapped=False, delay_delete=False):
    class Calls(list):
        entered = Event()
        release = Event()

    calls = Calls()

    class Server(ThreadingHTTPServer):
        def server_bind(self):
            TCPServer.server_bind(self)
            self.server_name = "localhost"
            self.server_port = self.server_address[1]

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path))
            valid = (self.headers.get("Authorization") == f"Bearer {TOKEN}"
                     and self.headers.get("X-Account") == ACCOUNT)
            self.send_response(200 if valid else 401)
            self.end_headers()
            self.wfile.write(b"authenticated" if valid else b"denied")

        def do_DELETE(self):
            calls.append(("DELETE", self.path))
            calls.entered.set()
            if delay_delete:
                calls.release.wait(timeout=5)
            secret, companion = (ACCOUNT, TOKEN) if remapped else (TOKEN, ACCOUNT)
            valid = (self.headers.get("Authorization") == f"Bearer {secret}"
                     and self.headers.get("X-Account") == companion)
            self.send_response(204 if valid else 403)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = Server(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        calls.release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def rules_file(tmp_path, *, remapped=False, revocation=True, optional=False):
    def request(method, path, account="ACCOUNT"):
        return {"method": method, "url": "{{ ENDPOINT }}" + path,
                "headers": {"Authorization": "Bearer {{ TOKEN }}",
                            "X-Account": "{{ " + account + " }}"},
                "response_matcher": [{"type": "StatusMatch",
                                      "status": [200 if method == "GET" else 204]}]}

    validation = {"type": "Http", "content": {"request": request("GET", "/identity")}}
    if remapped:
        # A synthetic Betterleaks expression exercises capability remapping
        # without using real AWS credentials or contacting AWS.
        validation = {"type": "Betterleaks", "content": {
            "expression": {"kind": "map", "pairs": [{"kind": "pair",
                "key": {"kind": "string", "value": "result"},
                "value": {"kind": "string", "value": "valid"}}]},
            "components": {"account": "ACCOUNT"},
            "capabilities": {"revocation_bindings": {
                "secret": "components.account", "variables": {"AKID": "finding.secret"}}},
        }}
    primary = {"id": RULE_ID, "name": "Synthetic multi-part credential",
               "pattern": r"\b(demo_[a-z0-9]{16})\b", "validation": validation,
               "depends_on_rule": [{"rule_id": "acme.account", "variable": "ACCOUNT",
                                    "within": "2L", "optional": optional}]}
    if revocation:
        primary["revocation"] = {"type": "Http", "content": {
            "request": request("DELETE", "/token", "AKID" if remapped else "ACCOUNT")}}
    path = tmp_path / "multipart.yml"
    path.write_text(json.dumps({"rules": [primary, {
        "id": "acme.account", "name": "Synthetic account component",
        "pattern": r"\b(account_[a-z]{4})\b", "visible": False,
    }]}), encoding="utf-8")
    return path


def visible(results):
    return next(result for result in results if result.finding.visible)


@pytest.mark.parametrize("remapped", [False, True], ids=["yaml", "betterleaks-binding"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
def test_resolved_pair_revokes_with_original_inputs(tmp_path, monkeypatch, remapped, newline):
    path = rules_file(tmp_path, remapped=remapped)
    rules = Rules([path], builtins=False)
    # A different value outside the rule's window must never be selected.
    findings = Scanner(rules).scan(newline.join(["account_efgh", "", ACCOUNT, TOKEN]))
    with provider(remapped=remapped) as (endpoint, calls):
        # No credential or endpoint should come from ambient environment values.
        monkeypatch.setenv("ENDPOINT", "http://unused.invalid")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "wrong")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wrong")
        variables = {"ENDPOINT": endpoint, "ACCOUNT": "overridden"}
        result = visible(Validator(variables=variables, allow_internal_ips=True).validate(findings))
        assert result.outcome == "verified_active"
        assert result.revocation_supported and result.revocation_ready
        assert result.revocation_reason is None
        credential = result.credential
        assert isinstance(credential, ResolvedCredential)
        assert credential.secret == TOKEN
        assert credential.variables["ACCOUNT"] == ACCOUNT
        assert [f.secret for f in credential.components] == [ACCOUNT]
        assert not credential.components[0].visible
        assert credential.revocation.secret == (ACCOUNT if remapped else TOKEN)
        assert credential.revocation.variables["ENDPOINT"] == endpoint
        if remapped:
            assert credential.revocation.variables["AKID"] == TOKEN
        for secret in (TOKEN, ACCOUNT, endpoint):
            assert secret not in repr(result)
            assert secret not in repr(credential)
            assert secret not in repr(credential.revocation)
            assert secret not in json.dumps(result.to_dict())
            assert secret not in json.dumps(credential.to_dict())
        assert credential.to_dict(redact=False)["components"][0]["secret"] == ACCOUNT
        assert set(result.to_dict()) == {"finding", "outcome", "reason", "http_status"}
        with pytest.raises(FrozenInstanceError):
            credential.secret = "changed"
        with pytest.raises(TypeError):
            credential.variables["ACCOUNT"] = "changed"
        raw = credential.to_dict(redact=False)
        raw["revocation"]["variables"]["ENDPOINT"] = "http://unused.invalid"
        variables["ENDPOINT"] = "http://unused.invalid"
        findings.clear()  # Retained components survive caller filtering/disposal.

        # A differently configured revoker must use the result's original rule.
        other_path = tmp_path / "other.yml"
        other_path.write_text(json.dumps({"rules": [{"id": RULE_ID, "name": "Other",
            "pattern": "(other)", "revocation": {"type": "Http", "content": {
                "request": {"method": "DELETE", "url": "http://unused.invalid",
                            "response_matcher": [{"type": "StatusMatch", "status": [204]}]}}}}]}),
            encoding="utf-8")
        revoker = Revoker(Rules([other_path], builtins=False))
        with pytest.raises(ValueError, match="confirm"):
            revoker.revoke(result)
        with pytest.raises(ValueError, match="overrides"):
            revoker.revoke(result, confirm=True, variables={})
        with pytest.raises(ValueError, match="overrides"):
            revoker.revoke(result, "different", confirm=True)
        cancellation = CancellationToken()
        cancellation.cancel()
        with pytest.raises(RuntimeError, match="cancelled"):
            revoker.revoke(result, confirm=True, cancellation=cancellation)
        for timeout in (0, -1, float("nan"), float("inf")):
            with pytest.raises(ValueError):
                revoker.revoke(result, confirm=True, timeout=timeout)
        assert not any(method == "DELETE" for method, _ in calls)
        revoked = revoker.revoke(result, confirm=True, timeout=2)
        assert revoked.rule_id == RULE_ID
        assert revoked.revoked and revoked.http_status == 204
        assert calls.count(("DELETE", "/token")) == 1


@pytest.mark.parametrize("case", ["missing", "ambiguous", "foreign", "encoding", "redacted"])
def test_unresolved_pairs_never_revoke(tmp_path, case):
    rules = Rules([rules_file(tmp_path)], builtins=False)
    scanner = Scanner(rules, redact=case == "redacted")
    text = f"{ACCOUNT}\n{TOKEN}"
    if case == "ambiguous":
        text = f"{ACCOUNT} account_efgh\n{TOKEN}"
    findings = scanner.scan(text)
    if case == "missing":
        # Reporting filters must not silently supply a missing helper.
        findings = [f for f in findings if f.visible]
    elif case == "foreign":        findings = [f for f in findings if f.visible] + scanner.scan(ACCOUNT + " ")
    elif case == "encoding":
        import base64
        findings = [f for f in findings if f.visible] + scanner.scan(
            base64.b64encode(ACCOUNT.encode()).decode())
    with provider() as (endpoint, calls):
        result = visible(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True)
                         .validate(findings))
        assert result.outcome == "skipped"
        assert result.credential is None
        assert result.revocation_supported and not result.revocation_ready
        assert result.revocation_reason == ("ambiguous_dependency" if case == "ambiguous"
                                            else "redacted_input" if case == "redacted"
                                            else "missing_dependency")
        with pytest.raises(ValueError, match="verified_active"):
            Revoker(rules).revoke(result, confirm=True)
        assert calls == []


def test_revocation_missing_binding_is_independent_of_validation(tmp_path):
    path = rules_file(tmp_path, remapped=True, optional=True)
    rules = Rules([path], builtins=False)
    result = visible(Validator().validate(Scanner(rules).scan(TOKEN)))
    assert result.outcome == "verified_active"
    assert result.credential is not None
    assert result.credential.components == ()
    assert result.credential.revocation is None
    assert result.revocation_supported and not result.revocation_ready
    assert result.revocation_reason == "missing_dependency"
    with pytest.raises(ValueError, match="verified_active"):
        Revoker(rules).revoke(result, confirm=True)


@pytest.mark.parametrize("state", ["inactive", "unsupported"])
def test_non_active_and_unsupported_results_do_not_revoke(tmp_path, state):
    rules = Rules([rules_file(tmp_path, revocation=state != "unsupported")], builtins=False)
    findings = Scanner(rules).scan(f"{ACCOUNT}\n{TOKEN}")
    with provider() as (endpoint, calls):
        result = visible(Validator(variables={"ENDPOINT": endpoint,
                                             "TOKEN": "ignored"}, allow_internal_ips=True)
                         .validate(findings))
        if state == "inactive":
            # Use a validly detected but rejected token.
            result = visible(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True)
                             .validate(Scanner(rules).scan(f"{ACCOUNT}\ndemo_9999abcd8888efgh")))
            assert result.outcome == "verified_inactive"
        else:
            assert result.outcome == "verified_active"
            assert not result.revocation_supported
            assert result.credential.revocation is None
        assert not result.revocation_ready
        with pytest.raises(ValueError, match="verified_active"):
            Revoker(rules).revoke(result, confirm=True)
        assert not any(method == "DELETE" for method, _ in calls)


def test_legacy_result_construction_and_low_level_signature(tmp_path):
    rules = Rules([rules_file(tmp_path)], builtins=False)
    finding = Scanner(rules).scan(f"{ACCOUNT}\n{TOKEN}")[0]
    manual = ValidationResult(finding, "verified_active", None, 200)
    assert manual.credential is None
    assert not manual.revocation_ready
    with pytest.raises(ValueError, match="Validator.validate"):
        Revoker(rules).revoke(manual, confirm=True)
    with pytest.raises(TypeError, match="secret is required"):
        Revoker(rules).revoke(RULE_ID, confirm=True)
    inputs = RevocationInputs(TOKEN, {"ACCOUNT": ACCOUNT})
    assert TOKEN not in repr(inputs) and ACCOUNT not in repr(inputs)
    assert inputs.to_dict(redact=False)["secret"] == TOKEN


@pytest.mark.parametrize("operation", ["cancel", "deadline"])
def test_result_revocation_interrupts_pending_mutation(tmp_path, operation):
    rules = Rules([rules_file(tmp_path)], builtins=False)
    findings = Scanner(rules).scan(f"{ACCOUNT}\n{TOKEN}")
    with provider(delay_delete=True) as (endpoint, calls):
        result = visible(Validator(variables={"ENDPOINT": endpoint}, allow_internal_ips=True)
                         .validate(findings))
        token = CancellationToken()
        kwargs = {"confirm": True, "cancellation": token}
        if operation == "deadline":
            kwargs["timeout"] = 0.2
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(Revoker(rules, timeout=5).revoke, result, **kwargs)
            assert calls.entered.wait(timeout=3)
            if operation == "cancel":
                token.cancel()
            with pytest.raises(RuntimeError if operation == "cancel" else TimeoutError):
                pending.result(timeout=2)
        assert calls.count(("DELETE", "/token")) == 1


def test_named_captures_are_retained_for_revocation(tmp_path):
    path = rules_file(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    primary = document["rules"][0]
    primary["pattern"] = r"\b(?P<TOKEN>demo_[a-z0-9]{16});(?P<ACCOUNT>account_[a-z]{4})\b"
    primary.pop("depends_on_rule")
    path.write_text(json.dumps(document), encoding="utf-8")
    rules = Rules([path], builtins=False)
    findings = Scanner(rules).scan(f"{TOKEN};{ACCOUNT}")
    with provider() as (endpoint, calls):
        result = visible(Validator(variables={"ENDPOINT": endpoint, "ACCOUNT": "wrong"},
                                   allow_internal_ips=True).validate(findings))
        assert result.revocation_ready
        assert result.credential.components == ()
        assert result.credential.variables["ACCOUNT"] == ACCOUNT
        assert Revoker(rules).revoke(result, confirm=True).revoked
        assert calls.count(("DELETE", "/token")) == 1


def test_invalid_capability_binding_is_an_explicit_readiness_failure(tmp_path):
    path = rules_file(tmp_path, remapped=True)
    document = json.loads(path.read_text(encoding="utf-8"))
    document["rules"][0]["validation"]["content"]["capabilities"]["revocation_bindings"]["secret"] = "unknown.source"
    path.write_text(json.dumps(document), encoding="utf-8")
    rules = Rules([path], builtins=False)
    result = visible(Validator().validate(Scanner(rules).scan(f"{ACCOUNT}\n{TOKEN}")))
    assert result.outcome == "verified_active"
    assert result.revocation_supported and not result.revocation_ready
    assert result.revocation_reason == "invalid_configuration"
    assert result.credential.revocation is None
    with pytest.raises(ValueError, match="verified_active"):
        Revoker(rules).revoke(result, confirm=True)
