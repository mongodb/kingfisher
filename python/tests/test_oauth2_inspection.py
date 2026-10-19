"""Rule inspection redacts operator credentials without changing live validation."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs

from kingfisher_sdk import Rules, Scanner, Validator


def test_oauth2_detail_redacts_credentials_without_mutating_validation(tmp_path):
    credentials = {
        "username": "operator-user-secret",
        "password": "operator-password-secret",
        "client_id": "scanner",
        "client_secret": "operator-client-secret",
    }

    class Handler(BaseHTTPRequestHandler):
        forms = []

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            Handler.forms.append(parse_qs(body.decode("utf-8")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"access_token":"service-token","token_type":"Bearer"}')

        def do_GET(self):
            valid = self.headers.get("Authorization") == "Bearer service-token"
            self.send_response(200 if valid else 401)
            self.end_headers()
            self.wfile.write(b"authenticated" if valid else b"unauthenticated")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_port}"
        path = tmp_path / "oauth2 inspection.yml"
        path.write_text(json.dumps({"rules": [{
            "id": "acme.oauth2-inspection", "name": "OAuth2 inspection fixture",
            "pattern": "(synthetic-secret)",
            "validation": {"type": "Http", "content": {
                "auth": {"oauth2": {"token_endpoint": f"{endpoint}/token", "ropc": credentials}},
                "request": {"method": "GET", "url": f"{endpoint}/verify",
                            "response_matcher": [{"type": "StatusMatch", "status": [200]}]},
            }},
        }]}), encoding="utf-8")
        rules = Rules([path], builtins=False)
        detail = rules.detail("acme.oauth2-inspection")
        inspected = detail["validation"]["content"]["auth"]["oauth2"]
        assert inspected["token_header"] == "Authorization"
        assert inspected["ropc"]["client_id"] == "scanner"
        for field in ["username", "password", "client_secret"]:
            assert inspected["ropc"][field] == "[REDACTED]"
            assert credentials[field] not in json.dumps(detail)
        assert Handler.forms == []  # Inspection must not exchange a token.
        inspected["ropc"]["password"] = "changed-inspection-copy"
        findings = Scanner(rules).scan("synthetic-secret")
        result, = Validator(allow_internal_ips=True, timeout=5).validate(findings)
        assert result.outcome == "verified_active"
        assert Handler.forms == [{"grant_type": ["password"], **{
            key: [value] for key, value in credentials.items()
        }}]
        assert rules.detail("acme.oauth2-inspection")["validation"]["content"]["auth"][
            "oauth2"]["ropc"]["password"] == "[REDACTED]"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_oauth2_detail_preserves_environment_references_without_resolving_them(tmp_path):
    credentials = {
        "username_env": "KF_INSPECT_UNSET_USERNAME",
        "password_env": "KF_INSPECT_UNSET_PASSWORD",
        "client_id": "scanner",
        "client_secret_env": "KF_INSPECT_UNSET_CLIENT_SECRET",
    }
    path = tmp_path / "oauth2 environment.yml"
    path.write_text(json.dumps({"rules": [{
        "id": "acme.oauth2-environment", "name": "OAuth2 environment fixture",
        "pattern": "(synthetic-secret)",
        "validation": {"type": "Http", "content": {
            "auth": {"oauth2": {"token_endpoint": "https://idp.example.com/token",
                                "ropc": credentials}},
            "request": {"method": "GET", "url": "https://verifier.example.com/verify",
                        "response_matcher": [{"type": "StatusMatch", "status": [200]}]},
        }},
    }]}), encoding="utf-8")
    detail = Rules([path], builtins=False).detail("acme.oauth2-environment")
    inspected = detail["validation"]["content"]["auth"]["oauth2"]["ropc"]
    assert all(inspected[field] == value for field, value in credentials.items())
    assert all(inspected[field] is None for field in ["username", "password", "client_secret"])
