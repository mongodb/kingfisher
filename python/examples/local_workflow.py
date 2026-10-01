"""From a source checkout: uv run --no-sync python python/examples/local_workflow.py

Complete lifecycle using only a loopback mock and a synthetic credential.

Published package: uv run --no-project --with kingfisher-secret-scanner python local_workflow.py
Import name: kingfisher_sdk.
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
Keep demo.yml beside this script when downloading it from GitHub.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

from kingfisher_sdk import Rules, Scanner, Validator, Revoker

TOKEN = "demo_abcd1234efgh5678"
RULE_ID = "acme.python-demo"
RULE_PATH = Path(__file__).with_name("demo.yml")


@contextmanager
def mock_provider():
    class Handler(BaseHTTPRequestHandler):
        active = True
        calls = []

        def do_GET(self):
            Handler.calls.append(("GET", self.path))
            valid = (self.path == "/identity" and Handler.active
                     and self.headers.get("Authorization") == f"Bearer {TOKEN}")
            self.send_response(200 if valid else 401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"authenticated":true}' if valid else b'{}')

        def do_DELETE(self):
            Handler.calls.append(("DELETE", self.path))
            valid = self.path == "/token" and self.headers.get("Authorization") == f"Bearer {TOKEN}"
            if valid:
                Handler.active = False
            self.send_response(204 if valid else 403)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", Handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    rules = Rules([RULE_PATH], builtins=False)
    findings = Scanner(rules).scan(f"token={TOKEN}")
    assert len(findings) == 1
    with mock_provider() as (endpoint, _):
        variables = {"ENDPOINT": endpoint}
        validator = Validator(variables=variables, allow_internal_ips=True)
        before = validator.validate(findings)[0]
        assert before.outcome == "verified_active", before
        print("Before revocation:", before.outcome)
        revoked = Revoker(rules).revoke(RULE_ID, findings[0].secret,
                                       confirm=True, variables=variables)
        assert revoked.revoked
        print("Revoked:", revoked.revoked)
        after = validator.validate(findings)[0]
        assert after.outcome == "verified_inactive", after
        print("After revocation:", after.outcome)


if __name__ == "__main__":
    main()
