"""Explicit, potentially irreversible provider revocation."""
from __future__ import annotations
from dataclasses import dataclass
import json
from typing import Mapping
from . import _native
from .rules import Rules


@dataclass(frozen=True)
class RevocationResult:
    rule_id: str
    revoked: bool
    http_status: int | None


class Revoker:
    """Revoke by exact rule ID without bulk selector expansion.

    HTTP revocation is not retried; AWS uses its provider-specific retry policy.

    Uses the shared CLI HTTP/multi-step engine and AWS/GCP helpers. Only load
    trusted rules and endpoints: revocation sends credentials to rule URLs,
    including private addresses. Provider bodies are not returned to Python.
    """
    def __init__(self, rules: Rules | None = None, *, timeout: float = 10) -> None:
        self.rules = rules if rules is not None else Rules()
        self._native = _native.Revoker(self.rules._native, timeout)

    def revoke(self, rule_id: str, secret: str, *, confirm: bool = False,
               variables: Mapping[str, str] | None = None) -> RevocationResult:
        """Perform revocation only with confirm=True. Pass supporting values
        (e.g. AKID, KEY_ID and enterprise endpoint variables) explicitly.
        A timeout/error can mean the provider applied the operation without a
        response; inspect provider state before manually retrying.
        """
        if confirm is not True:
            raise ValueError("revocation requires confirm=True")
        return RevocationResult(**json.loads(
            self._native.revoke(rule_id, secret, dict(variables or {}))))
