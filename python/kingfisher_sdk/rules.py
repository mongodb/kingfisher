"""Rule loading and compiled databases from kingfisher-rules."""
from __future__ import annotations
import os
from difflib import get_close_matches
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

    def resolve(self, provider: str) -> list[str]:
        """Resolve an exact rule ID, exact display name, or rule-ID family offline.

        Exact IDs take precedence, followed by case-insensitive exact display
        names (ambiguous names raise ValueError). Families are case-insensitive
        prefixes ending at a '.', '-' or '/' boundary. Both qualified IDs and
        IDs without betterleaks., custom., kingfisher. or veles.secrets/ work:
        ``github`` selects every loaded GitHub rule, while
        ``betterleaks.github-pat`` selects only that exact rule.

        This is ID-based selection, not semantic provider classification or
        CLI selector/legacy-alias compatibility. Globs and fuzzy execution are
        not supported. Typos may receive suggestions but never select rules.
        Selection is limited to this catalog and its confidence setting.
        """
        if not isinstance(provider, str):
            raise TypeError("provider must be a string")
        if not provider or provider != provider.strip():
            raise ValueError("provider must be nonempty without surrounding whitespace")
        metadata = self.metadata()
        if any(rule["id"] == provider for rule in metadata):
            return [provider]
        selector = provider.casefold()
        named = sorted(rule["id"] for rule in metadata
                       if rule["name"].casefold() == selector)
        if len(named) > 1:
            raise ValueError("ambiguous rule name; use an exact rule ID: " + ", ".join(named))
        if named:
            return named

        def unqualified(rule_id: str) -> str:
            for prefix in ("betterleaks.", "custom.", "kingfisher.", "veles.secrets/"):
                if rule_id.startswith(prefix):
                    return rule_id[len(prefix):]
            return rule_id

        def matches(rule_id: str) -> bool:
            for value in (rule_id.casefold(), unqualified(rule_id).casefold()):
                if value == selector or (value.startswith(selector)
                                         and value[len(selector):len(selector) + 1] in (".", "-", "/")):
                    return True
            return False

        selected = sorted(rule["id"] for rule in metadata if matches(rule["id"]))
        if not selected:
            suggestions = get_close_matches(selector, sorted({
                unqualified(rule["id"]).casefold() for rule in metadata}), n=3)
            hint = "; did you mean: " + ", ".join(suggestions) if suggestions else ""
            raise ValueError("unknown provider selector" + hint)
        return selected

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
