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

    def __len__(self) -> int:
        return len(self.metadata())
