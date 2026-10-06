"""Explicit credential validation with bounded concurrency and deadlines."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable, Mapping
from . import _native
from .core import Finding
from .scanner import CancellationToken


@dataclass(frozen=True)
class ValidationResult:
    finding: Finding = field(repr=False)
    outcome: str
    reason: str | None
    http_status: int | None

    def to_dict(self, *, redact: bool = True) -> dict:
        return {"finding": self.finding.to_dict(redact=redact),
                "outcome": self.outcome, "reason": self.reason,
                "http_status": self.http_status}


class Validator:
    def __init__(self, *, timeout: float = 10, concurrency: int = 8,
                 retries: int = 0, max_response_bytes: int = 1 << 20,
                 allow_internal_ips: bool = False,
                 variables: Mapping[str, str] | None = None) -> None:
        self._native = _native.Validator(timeout, concurrency, retries,
                                        max_response_bytes, allow_internal_ips,
                                        dict(variables or {}))

    def validate(self, findings: Iterable[Finding], *, timeout: float | None = None,
                 cancellation: CancellationToken | None = None) -> list[ValidationResult]:
        """Validate one input's complete findings, preserving order and context.

        ``timeout`` bounds this entire batch; the constructor timeout applies
        to provider requests. Cancellation and Ctrl-C stop pending work and
        propagate errors without partial results.

        Outcomes include verified_active, verified_inactive, unavailable,
        skipped, assumed, locally_derived, invalid_material, and not_attempted. Only verified_active is proof of
        activity. No provider request is made for absent/unsupported validators.
        """
        findings = list(findings)
        states = self._native.validate([f._native for f in findings],
                                       timeout=timeout, cancellation=cancellation)
        return [ValidationResult(f, **s) for f, s in zip(findings, states, strict=True)]
