"""In-process scanning from kingfisher-scanner; scanning never uses the network."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from collections.abc import Iterable, Iterator
from . import _native
from .core import Finding
from .rules import Rules

from .inputs import ScanInput


@dataclass(frozen=True)
class ScanResult:
    """Findings grouped with their input; helpers remain available for validation."""
    input: ScanInput
    findings: list[Finding] = field(repr=False)


CancellationToken = _native.CancellationToken


@dataclass(frozen=True)
class DetectionPolicy:
    """Immutable opt-in detection settings, reusable across scanners.

    Context filters run before component resolution and redaction. Defaults
    match the CLI's context and two-layer Base64 policies. ``Scanner`` without
    a policy retains its existing matching and one-layer decoding behavior.
    """
    inline_ignores: bool = True
    ignore_comments: Iterable[str] = ()
    markup_context: bool = True
    language: str | None = None
    cli_match_semantics: bool = True
    base64_max_depth: int = 2
    base64_max_input_bytes: int | None = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        if isinstance(self.ignore_comments, str):
            raise TypeError("ignore_comments must be an iterable of markers")
        markers = tuple(self.ignore_comments)
        if any(not isinstance(marker, str) for marker in markers):
            raise TypeError("ignore_comments must contain strings")
        object.__setattr__(self, "ignore_comments", markers)
        if self.language is not None and self.language not in ("html", "css"):
            raise ValueError("language must be html, css, or None (infer from path)")
        for name in ("inline_ignores", "markup_context", "cli_match_semantics"):
            if not isinstance(getattr(self, name), bool):
                raise TypeError(f"{name} must be bool")
        for name in ("base64_max_depth", "base64_max_input_bytes"):
            value = getattr(self, name)
            if value is None and name == "base64_max_input_bytes":
                continue
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be a nonnegative integer" +
                                (" or None" if name == "base64_max_input_bytes" else ""))
            if value < 0:
                raise ValueError(f"{name} must be nonnegative")


class Scanner:
    def __init__(self, rules: Rules | None = None, *, base64: bool = True,
                 dedup: bool = False, redact: bool = False,
                 min_entropy: float | None = None,
                 policy: DetectionPolicy | None = None) -> None:
        if policy is not None and not isinstance(policy, DetectionPolicy):
            raise TypeError("policy must be a DetectionPolicy or None")
        self._policy = policy
        self.rules = rules if rules is not None else Rules()
        self._native = _native.Scanner(self.rules._native, base64, dedup, redact, min_entropy, policy=policy)

    @property
    def policy(self) -> DetectionPolicy | None:
        """The immutable policy selected at construction, or legacy defaults."""
        return self._policy

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

    def scan_input(self, source: ScanInput, *, timeout: float | None = None,
                   cancellation: CancellationToken | None = None) -> list[Finding]:
        """Scan one composable input, applying filters to its source path."""
        if not isinstance(source, ScanInput):
            raise TypeError("source must be a ScanInput")
        if source.file is not None:
            return self.scan_file(source.file, timeout=timeout, cancellation=cancellation)
        return [Finding(f) for f in self._native.scan_input(
            source.data, source.path, timeout=timeout, cancellation=cancellation)]

    def scan_inputs(self, inputs: Iterable[ScanInput], *, timeout: float | None = None,
                    cancellation: CancellationToken | None = None) -> Iterator[ScanResult]:
        """Scan lazily, returning one complete group per input (including empty groups).

        Timeout applies per input. Errors propagate; groups already yielded stay
        with the caller, and the failed input never yields partial findings.
        Enumeration controls are configured on the input iterator separately.
        """
        for source in inputs:
            yield ScanResult(source, self.scan_input(source, timeout=timeout, cancellation=cancellation))

    def reset_dedup(self) -> None:
        """Clear successful-scan dedup entries; in-flight scans may add entries afterward."""
        self._native.reset_dedup()


class DetectionScanner(Scanner):
    """Scanner with opt-in CLI matching, bounded Base64 and context policies.

    CLI matching uses full-match component windows and suppresses contained
    secrets and overlapping credential-URI fallbacks. Base64 defaults to two
    decoding layers on inputs up to 64 MiB; offsets cover the outer encoded region.
    This compatibility facade constructs the same immutable DetectionPolicy
    accepted by Scanner(policy=...). Context filters run
    before component dependency checks, catalog deduplication and redaction.
    All inherited scanning methods, controls and result contracts apply.
    """
    def __init__(self, rules: Rules | None = None, *, inline_ignores: bool = True,
                 ignore_comments: Iterable[str] = (), markup_context: bool = True,
                 language: str | None = None, cli_match_semantics: bool = True,
                 base64_max_depth: int = 2, base64_max_input_bytes: int | None = 64 * 1024 * 1024,
                 base64: bool = True, dedup: bool = False, redact: bool = False,
                 min_entropy: float | None = None) -> None:
        policy = DetectionPolicy(
            inline_ignores=inline_ignores, ignore_comments=ignore_comments,
            markup_context=markup_context, language=language,
            cli_match_semantics=cli_match_semantics,
            base64_max_depth=base64_max_depth,
            base64_max_input_bytes=base64_max_input_bytes,
        )
        super().__init__(rules, base64=base64, dedup=dedup, redact=redact,
                         min_entropy=min_entropy, policy=policy)
