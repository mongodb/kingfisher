"""Shared finding types and entropy from kingfisher-core."""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any
from . import _native


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte."""
    return _native.shannon_entropy(data)


@dataclass(frozen=True)
class Finding:
    """A native finding. Repr excludes secrets; to_dict() redacts by default.

    Retain the native finding until validation finishes. Redaction does not
    securely erase the input or earlier copies of a secret.
    """
    _native: Any = field(repr=False)

    @property
    def rule_id(self) -> str:
        return self.to_dict()["rule_id"]

    @property
    def secret(self) -> str:
        """Explicit access to the unredacted credential."""
        return self.to_dict(redact=False)["secret"]

    @property
    def visible(self) -> bool:
        return self._native.visible

    def to_dict(self, *, redact: bool = True) -> dict[str, Any]:
        return json.loads(self._native.to_json(redact))
