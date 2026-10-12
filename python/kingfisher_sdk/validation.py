"""Explicit credential validation with bounded concurrency and deadlines."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Iterable, Mapping
from types import MappingProxyType
from . import _native
from .core import Finding
from .scanner import CancellationToken


@dataclass(frozen=True)
class InputDiagnostic:
    """Actionable input names/categories; never values, endpoints or error bodies."""
    stage: str
    code: str
    variable: str | None
    rule_id: str | None

    @property
    def message(self) -> str:
        labels = {"AKID": "AWS access-key ID", "ACCESS_KEY_ID": "AWS access-key ID",
                  "AWS_SECRET_ACCESS_KEY": "AWS secret-access key", "KEY_ID": "key ID",
                  "PRIVATE_KEY_ID": "private-key ID", "TOKEN": "credential"}
        label = labels.get(self.variable, self.variable or "credential inputs")
        if self.variable and (self.variable.endswith("_URL") or self.variable == "ENDPOINT"):
            label = f"endpoint variable {self.variable}"
        return {"missing_dependency": f"{label} required from supporting source context",
                "missing_variable": f"{label} required",
                "ambiguous_dependency": f"multiple conflicting values for {label}; provide unambiguous context",
                "redacted_input": f"original non-redacted {label} required",
                "invalid_configuration": "request template cannot be resolved; check rule configuration and inputs",
                }.get(self.code, "credential input inspection was inconclusive")

    def to_dict(self) -> dict:
        return {"stage": self.stage, "code": self.code, "variable": self.variable,
                "rule_id": self.rule_id, "message": self.message}


@dataclass(frozen=True)
class RevocationInputs:
    """Resolved action inputs. Secret-bearing fields are omitted from repr."""

    secret: str = field(repr=False)
    variables: Mapping[str, str] = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self, "variables", MappingProxyType(dict(self.variables)))

    def to_dict(self, *, redact: bool = True) -> dict:
        return {"secret": "[REDACTED]" if redact else self.secret,
                "variables": {key: "[REDACTED]" if redact else value
                              for key, value in self.variables.items()}}


@dataclass(frozen=True)
class ResolvedCredential:
    """Snapshot of validation inputs and the associated revocation inputs.

    Components retain the exact supporting findings from this input. Values are
    available explicitly and redacted by default in to_dict(). Neither repr nor
    serialization includes provider response bodies.
    """

    secret: str = field(repr=False)
    variables: Mapping[str, str] = field(repr=False)
    components: tuple[Finding, ...] = field(repr=False)
    revocation: RevocationInputs | None = field(default=None, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "variables", MappingProxyType(dict(self.variables)))
        object.__setattr__(self, "components", tuple(self.components))

    def to_dict(self, *, redact: bool = True) -> dict:
        return {"secret": "[REDACTED]" if redact else self.secret,
                "variables": {key: "[REDACTED]" if redact else value
                              for key, value in self.variables.items()},
                "components": [finding.to_dict(redact=redact) for finding in self.components],
                "revocation": self.revocation.to_dict(redact=redact) if self.revocation else None}


@dataclass(frozen=True)
class ValidationResult:
    finding: Finding = field(repr=False)
    outcome: str
    reason: str | None
    http_status: int | None
    # Preserve the existing four positional fields and serialization shape.
    _native: _native.ValidatedFinding | None = field(default=None, repr=False, compare=False)

    @property
    def credential(self) -> ResolvedCredential | None:
        data = self._native.credential if self._native is not None else None
        if data is None:
            return None
        action = data["revocation"]
        return ResolvedCredential(
            data["secret"], data["variables"],
            tuple(Finding(finding) for finding in data["components"]),
            RevocationInputs(*action) if action is not None else None,
        )

    @property
    def revocation_supported(self) -> bool:
        """Whether the original rule defines revocation, independently of readiness."""
        return self._native.revocation_supported if self._native is not None else False

    @property
    def revocation_ready(self) -> bool:
        """Verified active, with resolved revocation inputs available."""
        return self._native.revocation_ready if self._native is not None else False

    @property
    def revocation_reason(self) -> str | None:
        """Credential-free binding/validation failure; not a provider response."""
        return self._native.revocation_reason if self._native is not None else "unresolved_inputs"

    @property
    def input_diagnostics(self) -> tuple[InputDiagnostic, ...]:
        """Named input issues retained with this validation snapshot."""
        return tuple(InputDiagnostic(**issue) for issue in self._native.input_diagnostics) if self._native else ()

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

    def with_variables(self, variables: Mapping[str, str]) -> Validator:
        """Clone execution policy and pooled client with explicit variable overrides.

        Names are case-insensitive; captures/components still take precedence.
        No provider work occurs. The original Validator remains unchanged.
        """
        clone = object.__new__(Validator)
        clone._native = self._native.with_variables(dict(variables))
        return clone

    def inspect(self, findings: Iterable[Finding], *, timeout: float | None = None,
                cancellation: CancellationToken | None = None) -> list[tuple[InputDiagnostic, ...]]:
        """Inspect complete same-input findings offline, preserving input order.

        Reuses native component windows/defaults and template parsing. Diagnostics
        identify missing/ambiguous/redacted dependencies and HTTP/gRPC inputs;
        they do not prove activity, permissions or every Betterleaks expression
        branch. Control-flow templates may lack a specific variable name.
        """
        findings = list(findings)
        return [tuple(InputDiagnostic(**issue) for issue in group)
                for group in self._native.inspect([finding._native for finding in findings],
                                                  timeout=timeout, cancellation=cancellation)]

    def validate(self, findings: Iterable[Finding], *, timeout: float | None = None,
                 cancellation: CancellationToken | None = None) -> list[ValidationResult]:
        """Validate one input's complete findings, preserving order and context.

        ``timeout`` bounds this entire batch; the constructor timeout applies
        to provider requests. Cancellation and Ctrl-C stop pending work and
        propagate errors without partial results.

        Outcomes include verified_active, verified_inactive, unavailable,
        skipped, assumed, locally_derived, invalid_material, and not_attempted. Only verified_active is proof of
        activity. Each result retains the resolved credential inputs for explicit
        revocation; validation never revokes. No provider request is made for absent/unsupported validators.
        """
        findings = list(findings)
        states = self._native.validate([f._native for f in findings],
                                       timeout=timeout, cancellation=cancellation)
        return [ValidationResult(f, **s) for f, s in zip(findings, states, strict=True)]
