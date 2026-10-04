"""Rule loading and compiled databases from kingfisher-rules."""
from __future__ import annotations
import json
import os
from typing import Iterable, Literal, Any
from . import _native


class Rules:
    """Compile built-ins and/or custom YAML/TOML files and directories once."""
    def __init__(self, paths: Iterable[str | os.PathLike[str]] = (), *,
                 builtins: bool = True,
                 confidence: Literal["low", "medium", "high"] = "medium") -> None:
        if isinstance(paths, (str, os.PathLike)):
            raise TypeError("paths must be an iterable of paths, e.g. [path]")
        self._native = _native.Rules([os.fspath(p) for p in paths], builtins, confidence)

    def metadata(self) -> list[dict[str, Any]]:
        """List exact IDs, names, visibility, validation and revocation support."""
        return json.loads(self._native.metadata())

    def detail(self, rule_id: str) -> dict[str, Any]:
        """Return an exact loaded rule's definition and compiled detection regex.

        Includes pattern, entropy, filters, capture selection, dependencies,
        examples, references, validation and revocation. Missing configurations
        are None. Betterleaks logic is a serialized expression tree; typed/raw
        handlers identify Rust implementations rather than exposing their code.
        This is offline inspection. Returned data is a copy; editing it does not
        change scanning behavior. Unknown IDs raise ValueError.
        """
        return json.loads(self._native.detail(rule_id))

    def __len__(self) -> int:
        return len(self.metadata())
