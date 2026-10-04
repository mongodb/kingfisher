"""In-process scanning from kingfisher-scanner; scanning never uses the network."""
from __future__ import annotations
import os
from . import _native
from .core import Finding
from .rules import Rules

CancellationToken = _native.CancellationToken


class Scanner:
    def __init__(self, rules: Rules | None = None, *, base64: bool = True,
                 dedup: bool = False, redact: bool = False,
                 min_entropy: float | None = None) -> None:
        self.rules = rules if rules is not None else Rules()
        self._native = _native.Scanner(self.rules._native, base64, dedup, redact, min_entropy)

    def scan(self, data: str | bytes, *, timeout: float | None = None,
             cancellation: CancellationToken | None = None) -> list[Finding]:
        """Scan UTF-8 text or bytes, retaining invisible component helpers.

        Keep one input's full result list together for validation. Filter on
        finding.visible only when reporting. Offsets refer to the scanner's
        decoded content (UTF-16/32 inputs may be normalized).
        Optional timeout (seconds) and cancellation are cooperative: individual
        native operations cannot be preempted. Interruption raises TimeoutError
        or RuntimeError, never returning partial findings.
        """
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, bytes):
            raise TypeError("data must be str or bytes")
        return [Finding(f) for f in self._native.scan_bytes(data, timeout=timeout, cancellation=cancellation)]

    def scan_file(self, path: str | os.PathLike[str], *, timeout: float | None = None,
                  cancellation: CancellationToken | None = None) -> list[Finding]:
        """Scan a file with path-aware filters and optional cooperative controls.

        File reads cannot be preempted. See scan() for interruption behavior.
        """
        return [Finding(f) for f in self._native.scan_file(os.fspath(path), timeout=timeout, cancellation=cancellation)]

    def reset_dedup(self) -> None:
        self._native.reset_dedup()
