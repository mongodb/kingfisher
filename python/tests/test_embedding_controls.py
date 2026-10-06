"""Embedding contracts: immutable policies, structured results and cancellable I/O."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import subprocess
import sys
import textwrap

import pytest

from kingfisher_sdk import (
    CancellationToken, DetectionPolicy, DetectionScanner, Revoker, Rules, Scanner,
    Validator,
)
from test_sdk import mock


@pytest.fixture
def rules():
    return Rules([mock.RULE_PATH], builtins=False, cache=False)


def test_immutable_policy_and_compatibility_facade(rules):
    markers = ["acme:ignore"]
    policy = DetectionPolicy(ignore_comments=markers)
    markers.append("another:ignore")
    assert policy.ignore_comments == ("acme:ignore",)
    with pytest.raises(FrozenInstanceError):
        policy.inline_ignores = False
    contextual = Scanner(rules, policy=policy)
    facade = DetectionScanner(rules, ignore_comments=policy.ignore_comments)
    content = mock.TOKEN + " # ACME:IGNORE"
    assert contextual.scan(content) == facade.scan(content) == []
    assert len(Scanner(rules).scan(content)) == 1
    with ThreadPoolExecutor(max_workers=4) as workers:
        assert all(len(result) == 1 for result in workers.map(
            contextual.scan, [mock.TOKEN] * 8))
    with pytest.raises(TypeError, match="policy"):
        Scanner(rules, policy={})


def test_structured_results_are_copies_and_preserve_redaction(rules):
    finding, = Scanner(rules).scan(mock.TOKEN)
    raw = finding.to_dict(redact=False)
    for name in ("rule_id", "rule_name", "secret", "entropy", "fingerprint",
                 "blob_id", "confidence", "is_base64_encoded", "location", "captures"):
        assert getattr(finding, name) == raw[name]
    raw["location"]["line"] = 999
    raw["captures"]["TOKEN"] = "changed"
    assert finding.location["line"] == 1
    assert "changed" not in finding.captures.values()
    assert mock.TOKEN not in str(finding.to_dict())
    redacted, = Scanner(rules, redact=True).scan(mock.TOKEN)
    assert redacted.secret == "[REDACTED]"
    assert mock.TOKEN not in str(redacted.captures)
    detail = rules.detail(mock.RULE_ID)
    detail["name"] = "changed"
    assert rules.detail(mock.RULE_ID)["name"] != "changed"


@contextmanager
def slow_provider():
    entered, release = Event(), Event()

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            entered.set()
            release.wait(timeout=5)
            self.send_response(204)
            self.end_headers()

        do_GET = do_DELETE = handle_request

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", entered
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


@pytest.mark.parametrize("operation", ["validate", "revoke"])
def test_cancellation_interrupts_pending_provider_work(rules, operation):
    token = CancellationToken()
    finding, = Scanner(rules).scan(mock.TOKEN)
    with slow_provider() as (endpoint, entered):
        variables = {"ENDPOINT": endpoint}
        validator = Validator(timeout=5, variables=variables, allow_internal_ips=True)
        revoker = Revoker(rules, timeout=5)
        with ThreadPoolExecutor(max_workers=1) as workers:
            if operation == "validate":
                pending = workers.submit(validator.validate, [finding], cancellation=token)
            else:
                pending = workers.submit(revoker.revoke, mock.RULE_ID, mock.TOKEN,
                                         confirm=True, variables=variables, cancellation=token)
            assert entered.wait(timeout=3), "provider request did not start"
            token.cancel()
            with pytest.raises(RuntimeError, match="cancelled"):
                pending.result(timeout=2)
    # Cancellation must not poison reusable provider resources.
    assert validator.validate([]) == []


@pytest.mark.parametrize("operation", ["validate", "revoke"])
def test_operation_deadline_and_precancelled_token(rules, operation):
    token = CancellationToken()
    token.cancel()
    finding, = Scanner(rules).scan(mock.TOKEN)
    with slow_provider() as (endpoint, entered):
        variables = {"ENDPOINT": endpoint}
        if operation == "validate":
            runner = Validator(timeout=5, variables=variables, allow_internal_ips=True)
            call = lambda **kwargs: runner.validate([finding], **kwargs)
        else:
            runner = Revoker(rules, timeout=5)
            call = lambda **kwargs: runner.revoke(mock.RULE_ID, mock.TOKEN, confirm=True,
                                                variables=variables, **kwargs)
        with pytest.raises(RuntimeError, match="cancelled"):
            call(cancellation=token)
        assert not entered.is_set()
        with pytest.raises(TimeoutError):
            call(timeout=0.05)
        for timeout in (0, -1, float("nan"), float("inf")):
            with pytest.raises(ValueError):
                call(timeout=timeout)


def test_revocation_failure_category_does_not_expose_request(rules):
    # Reserve then close an ephemeral local port: no provider account or DNS.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with pytest.raises(RuntimeError, match="connection") as failed:
        Revoker(rules).revoke(mock.RULE_ID, mock.TOKEN, confirm=True,
                             variables={"ENDPOINT": f"http://127.0.0.1:{port}"})
    assert mock.TOKEN not in str(failed.value)
    assert "127.0.0.1" not in str(failed.value)


@pytest.mark.parametrize("operation", ["validate", "revoke"])
@pytest.mark.parametrize("restricted_signals", [False, True], ids=["default", "restricted"])
def test_keyboard_interrupt_stops_pending_provider_work(operation, restricted_signals):
    # Isolate SIGINT so a regression cannot interrupt the parent test runner.
    # On Unix, send a process signal as terminal Ctrl-C would. raise_signal
    # targets the calling worker thread and may leave delivery thread-bound.
    # Windows needs raise_signal; os.kill(SIGINT) terminates its target there.
    script = textwrap.dedent("""
        import faulthandler
        import os
        import signal
        import sys
        import time
        from threading import Thread

        # CI launchers can leave SIGINT ignored or blocked across exec. This
        # isolated child must establish the KeyboardInterrupt behavior it tests.
        if sys.argv[4] == "restricted":
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            if hasattr(signal, "pthread_sigmask"):
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        signal.signal(signal.SIGINT, signal.default_int_handler)
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
        faulthandler.dump_traceback_later(10)

        sys.path.insert(0, sys.argv[1])
        from test_embedding_controls import slow_provider
        from test_sdk import mock
        from kingfisher_sdk import Rules, Scanner, Validator, Revoker

        rules = Rules([sys.argv[2]], builtins=False, cache=False)
        finding, = Scanner(rules).scan(mock.TOKEN)
        with slow_provider() as (endpoint, entered):
            def interrupt():
                if entered.wait(timeout=3):
                    if os.name == "nt":
                        signal.raise_signal(signal.SIGINT)
                    else:
                        os.kill(os.getpid(), signal.SIGINT)

            worker = Thread(target=interrupt, daemon=True)
            worker.start()
            started = time.monotonic()
            try:
                if sys.argv[3] == "validate":
                    Validator(timeout=5, variables={"ENDPOINT": endpoint},
                              allow_internal_ips=True).validate([finding])
                else:
                    Revoker(rules, timeout=5).revoke(
                        mock.RULE_ID, mock.TOKEN, confirm=True,
                        variables={"ENDPOINT": endpoint})
            except KeyboardInterrupt:
                assert time.monotonic() - started < 2
            else:
                raise AssertionError("SIGINT did not interrupt provider work")
            worker.join(timeout=3)
            assert not worker.is_alive()
        faulthandler.cancel_dump_traceback_later()
    """)
    result = subprocess.run(
        [sys.executable, "-c", script, str(Path(__file__).resolve().parent),
         str(mock.RULE_PATH), operation, "restricted" if restricted_signals else "default"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr
