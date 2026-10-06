"""Rule loading and compiled databases from kingfisher-rules."""
from __future__ import annotations
import os
from typing import Iterable, Literal, Any
from . import _native


class Rules:
    """Load built-ins and/or custom YAML/TOML rules with a reusable disk cache.

    ``cache_dir`` overrides ``KF_RULE_CACHE_DIR`` and the OS cache directory.
    Incompatible or unreadable entries are recompiled; cache writes are best effort.
    Directories must be trusted; unsafe ownership/permissions disable caching.
    The default never uses shared temporary storage. ``cache_status`` reports
    loaded/stored/bypassed for operational checks.
    ``cache=False`` disables both cache reads and writes, including env settings.
    """
    def __init__(self, paths: Iterable[str | os.PathLike[str]] = (), *,
                 builtins: bool = True,
                 confidence: Literal["low", "medium", "high"] = "medium",
                 cache: bool = True,
                 cache_dir: str | os.PathLike[str] | None = None) -> None:
        if isinstance(paths, (str, os.PathLike)):
            raise TypeError("paths must be an iterable of paths, e.g. [path]")
        self._native = _native.Rules(
            [os.fspath(p) for p in paths], builtins, confidence, cache=cache,
            cache_dir=None if cache_dir is None else os.fspath(cache_dir),
        )

    def metadata(self) -> list[dict[str, Any]]:
        """List exact IDs, names, visibility, validation and revocation support."""
        return self._native.metadata()

    def detail(self, rule_id: str) -> dict[str, Any]:
        """Return an exact loaded rule's definition and compiled detection regex.

        Includes pattern, entropy, filters, capture selection, dependencies,
        examples, references, validation and revocation. Missing configurations
        are None. Betterleaks logic is a serialized expression tree; typed/raw
        handlers identify Rust implementations rather than exposing their code.
        This is offline inspection. Returned data is a copy; editing it does not
        change scanning behavior. Unknown IDs raise ValueError.
        """
        return self._native.detail(rule_id)

    def __len__(self) -> int:
        return len(self._native)

    @property
    def cache_status(self) -> Literal["loaded", "stored", "bypassed"]:
        """Disk-cache outcome; bypass still produces a usable compiled catalog."""
        return self._native.cache_status
