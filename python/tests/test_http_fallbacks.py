"""HTTP alternatives are opt-in and retain environment-specific actions privately."""
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kingfisher_sdk import Revoker, Rules, Scanner, Validator


@contextmanager
def service():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            calls.append(self.path)
            self.send_response(401 if self.path == "/primary" else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_DELETE(self):
            calls.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("reuse", [True, False])
def test_fallbacks_require_explicit_opt_in(tmp_path, reuse):
    with service() as (origin, calls):
        def validation(path):
            return {"type": "Http", "content": {"request": {
                "method": "GET", "url": origin + path,
                "headers": {"Authorization": "Bearer {{ TOKEN }}"},
                "response_matcher": [{"type": "StatusMatch", "status": [200]}],
            }}}

        fallback = {"id": "secondary"}
        if reuse:
            fallback.update(reuse_primary_validation_logic=True, url=origin + "/secondary")
        else:
            # Logic reuse is deliberately omitted: independent validation is the default.
            fallback["validation"] = validation("/secondary")
        rule = {"id": "custom.fallback", "name": "Fixture", "pattern": "(synthetic-secret)",
                "validation": validation("/primary"), "fallbacks": [fallback]}
        path = tmp_path / "rules.yml"
        path.write_text(json.dumps({"rules": [rule]}), encoding="utf-8")
        findings = Scanner(Rules([path], builtins=False), redact=False).scan("synthetic-secret")
        primary = Validator(allow_internal_ips=True).validate(findings)[0]
        assert primary.outcome == "verified_inactive"
        assert calls == ["/primary"]
        calls.clear()
        accepted = Validator(allow_internal_ips=True, http_fallbacks=True).validate(findings)[0]
        assert accepted.outcome == "verified_active"
        assert calls == ["/primary", "/secondary"]
        assert "synthetic-secret" not in repr(accepted.to_dict())
        assert origin not in repr(accepted.to_dict())


@pytest.mark.parametrize("action_mode", ["independent", "primary", "none"])
def test_result_revocation_uses_only_the_selected_fallback_action(tmp_path, action_mode):
    with service() as (origin, calls):
        request = {"method": "GET", "url": origin + "/primary",
                   "response_matcher": [{"type": "StatusMatch", "status": [200]}]}
        fallback = {"id": "secondary", "reuse_primary_validation_logic": True,
                    "url": origin + "/secondary"}
        action = {"type": "Http", "content": {"request": {
            "method": "DELETE", "url": "{{ VALIDATION_ORIGIN }}/revoke",
            "response_matcher": [{"type": "StatusMatch", "status": [200]}],
        }}}
        has_action = action_mode != "none"
        if action_mode == "independent":
            fallback["revocation"] = action
        elif action_mode == "primary":
            fallback.update(reuse_primary_revocation_logic=True,
                            revocation_url="{{ VALIDATION_ORIGIN }}/revoke")
        rule = {"id": "custom.fallback", "name": "Fixture", "pattern": "(synthetic-secret)",
                "validation": {"type": "Http", "content": {"request": request}},
                # Primary revocation reuse must be a separate explicit opt-in.
                "revocation": action, "fallbacks": [fallback]}
        path = tmp_path / "rules.yml"
        path.write_text(json.dumps({"rules": [rule]}), encoding="utf-8")
        rules = Rules([path], builtins=False)
        findings = Scanner(rules, redact=False).scan("synthetic-secret")
        result = Validator(allow_internal_ips=True, http_fallbacks=True).validate(findings)[0]
        assert result.revocation_supported is has_action
        assert result.revocation_ready is has_action
        if has_action:
            assert Revoker(rules).revoke(result, confirm=True).revoked
            assert calls == ["/primary", "/secondary", "/revoke"]
        else:
            with pytest.raises(ValueError):
                Revoker(rules).revoke(result, confirm=True)
            assert calls == ["/primary", "/secondary"]


@pytest.mark.parametrize("primary_action", ["Http", "AWS"])
def test_direct_revocation_rejects_forged_fallback_selection(tmp_path, primary_action):
    with service() as (origin, calls):
        action = {"type": "Http", "content": {"request": {
            "method": "DELETE", "url": origin + "/revoke",
            "response_matcher": [{"type": "StatusMatch", "status": [200]}],
        }}}
        rule = {"id": "custom.fallback", "name": "Fixture", "pattern": "(synthetic-secret)",
                "validation": {"type": "Http", "content": {"request": {
                    "method": "GET", "url": origin + "/primary",
                    "response_matcher": [{"type": "StatusMatch", "status": [200]}],
                }}},
                "revocation": action if primary_action == "Http" else {"type": "AWS"},
                "fallbacks": [{"id": "secondary", "reuse_primary_validation_logic": True,
                               "url": origin + "/secondary", "revocation": action}]}
        path = tmp_path / "rules.yml"
        path.write_text(json.dumps({"rules": [rule]}), encoding="utf-8")
        revoker = Revoker(Rules([path], builtins=False))
        with pytest.raises(ValueError, match="selection variables are reserved"):
            revoker.revoke("custom.fallback", "synthetic-secret", confirm=True,
                           variables={"validation_fallback_id": "secondary",
                                      "VALIDATION_ORIGIN": origin})
        assert calls == []
