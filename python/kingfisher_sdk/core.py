"""Shared finding types and entropy from kingfisher-core."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from . import _native


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte."""
    return _native.shannon_entropy(data)


@dataclass(frozen=True)
class Finding:
    """A native finding. Repr excludes secrets; to_dict() redacts by default.

    Redaction hides credentials and captures, but retains entropy, fingerprint
    and content identity for correlation. These can reveal information about
    guessable inputs; restrict report access accordingly.

    Retain the native finding until validation finishes. Redaction does not
    securely erase the input or earlier copies of a secret.
    """
    _native: Any = field(repr=False)

    @property
    def rule_id(self) -> str:
        return self._native.rule_id

    @property
    def secret(self) -> str:
        """Return the stored credential; redact=True scanning leaves it redacted."""
        return self._native.secret

    @property
    def visible(self) -> bool:
        return self._native.visible

    @property
    def rule_name(self) -> str:
        return self._native.rule_name

    @property
    def entropy(self) -> float:
        return self._native.entropy

    @property
    def fingerprint(self) -> int:
        return self._native.fingerprint

    @property
    def blob_id(self) -> str:
        return self._native.blob_id

    @property
    def is_base64_encoded(self) -> bool:
        return self._native.is_base64_encoded

    @property
    def confidence(self) -> str:
        return self._native.confidence

    @property
    def location(self) -> dict[str, int]:
        return self._native.location

    @property
    def captures(self) -> dict[str, str]:
        return self._native.captures

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        return self._native.to_dict(redact)
