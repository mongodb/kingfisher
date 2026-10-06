"""Composable offline inputs, independent of detection and validation.

Use your own Python iterators or Kingfisher's native filesystem/Git enumerators.
Archive expansion is an explicit transform, never implicit in scan_file().
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import os
from collections.abc import Iterable, Iterator

from . import _native
CancellationToken = _native.CancellationToken


@dataclass(frozen=True)
class ScanInput:
    """One source: bytes with a logical path, or a lazily read local file.

    Git metadata identifies the original repository blob even after expansion.
    Data is excluded from repr; it can still contain raw credentials.
    """
    path: str
    data: bytes | None = field(default=None, repr=False)
    file: str | None = field(default=None, repr=False)
    repository: str | None = None
    commit: str | None = None
    blob_id: str | None = None
    extraction_error: str | None = field(default=None, repr=False, kw_only=True)

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise TypeError("path must be str")
        if (self.data is None) == (self.file is None):
            raise ValueError("provide exactly one of data or file")
        if self.data is not None and not isinstance(self.data, bytes):
            raise TypeError("data must be bytes")
        if self.file is not None and not isinstance(self.file, str):
            raise TypeError("file must be str")
        if self.file is not None and self.path != self.file:
            raise ValueError("file inputs must use their filesystem path; use bytes for logical paths")

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> ScanInput:
        """Create an input without reading the file yet."""
        name = os.fspath(path)
        return cls(path=name, file=name)


def filesystem(
    roots: Iterable[str | os.PathLike[str]], *, gitignore: bool = True,
    hidden: bool = False, max_file_size: int | None = None,
    timeout: float | None = None, cancellation: CancellationToken | None = None,
) -> Iterator[ScanInput]:
    """Enumerate regular files natively, skipping symlinks and .git entries.

    Read local .gitignore/.ignore files by default, but not global Git ignores or
    CLI configuration. Hidden entries are opt-in. Errors propagate; the timeout
    covers the iterator's lifetime, including time spent by its consumer.
    File contents are read only when scanned or expanded. max_file_size silently
    skips oversized files; this iterator does not emit skip warnings.
    """
    if isinstance(roots, (str, bytes, os.PathLike)):
        raise TypeError("roots must be an iterable of paths, e.g. [path]")
    native = _native.Filesystem(
        [os.fspath(root) for root in roots], gitignore=gitignore, hidden=hidden,
        max_file_size=max_file_size, timeout=timeout, cancellation=cancellation,
    )
    return (ScanInput.from_file(path) for path in native)


def git_history(
    path: str | os.PathLike[str], *, refs: Iterable[str] | None = ("HEAD",),
    timeout: float | None = None, cancellation: CancellationToken | None = None,
    discover: bool = True, max_blob_size: int | None = None,
    max_commits: int | None = None, max_inputs: int | None = None,
    skip_missing_blobs: bool = False,
) -> Iterator[ScanInput]:
    """Enumerate reachable file versions through ``git_inputs`` history mode.

    Pass refs=None for all refs plus HEAD. Visits merge parents and shallow
    boundaries, supports bare repositories, and emits each (raw path, blob ID)
    once. Returned ``GitInput`` objects retain all selected change occurrences;
    commit is one occurrence, not a claim of first introduction. Symlinks,
    submodules, unreachable objects and working-tree changes are excluded.
    An empty refs iterable returns an empty iterator for compatibility.

    No Git executable, CLI, network or checkout is required. Timeout covers
    preparation and the iterator lifetime, including consumer processing time.
    Ancestor repository discovery is enabled by default; set discover=False for
    explicit repository roots. See ``git_inputs`` for limits, missing-blob
    warnings, raw path metadata and local revision grammar. Order is unspecified.
    """
    from .git import GitScope, git_inputs
    if isinstance(refs, str):
        raise TypeError("refs must be an iterable of ref names, e.g. ['HEAD']")
    selected = None if refs is None else tuple(refs)
    if selected == ():
        return iter(())
    return git_inputs(path, scope=GitScope(refs=selected), timeout=timeout,
                      cancellation=cancellation, discover=discover,
                      max_blob_size=max_blob_size, max_commits=max_commits,
                      max_inputs=max_inputs, skip_missing_blobs=skip_missing_blobs)


def expand_archives(
    inputs: Iterable[ScanInput], *, depth: int = 1,
    max_bytes: int = 256 * 1024 * 1024, max_entries: int = 10_000,
    timeout: float | None = None, cancellation: CancellationToken | None = None,
    temp_dir: str | os.PathLike[str] | None = None,
) -> Iterator[ScanInput]:
    """Expand archives with the shared native CLI extractors, preserving sources.

    Supports ZIP and ZIP-based formats, TAR, gzip/bzip2/xz (including compressed
    TAR), zlib, ASAR and HWP; detects ZIP by signature as well as extension.
    Paths use ``outer.zip!member``. Normal inputs pass through as byte inputs.
    Depth 0 leaves containers raw; depth is bounded to 32. Each root is expanded
    completely before yielding members; budgets and timeout apply per root.
    Repeated TAR member names retain each occurrence's bytes under the same path.
    Every nested layer consumes the remaining root byte/entry budgets during
    extraction. max_bytes bounds extracted output cumulatively across layers;
    the root input has a separate max_bytes cap and is not debited from output.
    Root and extracted buffers can coexist, and conversion to Python bytes adds
    transient copies; max_bytes is not a total process memory bound.
    Entry budgets count inspected members, including skipped unsafe entries.
    TAR/ZIP count directories too; ASAR counts indexed files and HWP counts streams. Intermediate streams include TAR headers and padding in their
    byte cap; exceeding a budget raises without yielding partial members.
    Failed extraction raises RuntimeError. The shared extractors skip unsafe or
    unreadable entries and enforce their own limits, so expansion is best effort.
    Small ZIP archives decode in memory. Other formats use temporary
    directories under temp_dir (the system temporary directory by default).
    Choose a protected temp_dir parent on every platform. SDK staging directories
    use owner-only Unix mode 0700 (umask may restrict it further); Windows inherits
    the parent DACL.
    Cleanup is attempted on completion; plaintext may survive a crash or failure;
    choose encrypted or memory-backed storage when that matters for your inputs.
    Unsafe archive member paths are skipped before filesystem extraction.
    """
    # Validate options eagerly without consuming the input iterable.
    if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= 32:
        raise ValueError("depth must be an integer between 0 and 32")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries <= 0:
        raise ValueError("max_entries must be a positive integer")

    def expanded() -> Iterator[ScanInput]:
        for source in inputs:
            if not isinstance(source, ScanInput):
                raise TypeError("inputs must contain ScanInput objects")
            for path, data in _native.expand_archive(
                source.path, source.data, file=source.file, depth=depth,
                max_bytes=max_bytes, max_entries=max_entries,
                timeout=timeout, cancellation=cancellation,
                temp_dir=None if temp_dir is None else os.fspath(temp_dir),
            ):
                yield replace(source, path=path, data=data, file=None)

    return expanded()


def expand_content(
    inputs: Iterable[ScanInput], *, sqlite: bool = True, pyc: bool = True,
    strict: bool = False, max_bytes: int = 256 * 1024 * 1024,
    timeout: float | None = None, cancellation: CancellationToken | None = None,
    temp_dir: str | os.PathLike[str] | None = None,
) -> Iterator[ScanInput]:
    """Extract SQLite SQL and .pyc strings with the shared native CLI extractors.

    Compose after expand_archives() to extract archive members. Normal inputs,
    empty databases and unsupported bytecode pass through unchanged. Malformed
    inputs fall back to raw scanning unless strict=True, with a non-secret
    extraction_error category on the returned input. Bytecode is parsed in memory
    and is never run. SQLite reads a separate staged copy in temp_dir (the system
    temporary directory by default). Choose a protected temp_dir parent on every
    platform. SDK staging directories use owner-only Unix mode 0700 (umask may
    restrict it further); Windows inherits the parent DACL. Cleanup is attempted
    on completion; plaintext may
    survive a crash or cleanup failure. Choose encrypted or memory-backed storage
    when needed.
    Checkpoint live databases before scanning to include WAL-only values. Budgets/controls apply per
    input, with no partial input yielded on interruption or budget errors.
    Output is bounded during extraction. Hitting output/work limits raises;
    incomplete extraction never silently turns into raw scanning. SQLite VM
    progress and bytecode parsing cooperate with deadlines and cancellation.
    Logical paths use ``database!table.sql`` and ``module.pyc!strings.py``;
    finding offsets refer to extracted content, not the original binary.
    """
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    def expanded() -> Iterator[ScanInput]:
        for source in inputs:
            if not isinstance(source, ScanInput):
                raise TypeError("inputs must contain ScanInput objects")
            output, diagnostic = _native.expand_content(
                source.path, source.data, file=source.file, sqlite=sqlite, pyc=pyc,
                strict=strict, max_bytes=max_bytes, timeout=timeout, cancellation=cancellation,
                temp_dir=None if temp_dir is None else os.fspath(temp_dir),
            )
            if output is None:
                yield source if diagnostic is None else replace(source, extraction_error=diagnostic)
            else:
                for path, data in output:
                    yield replace(source, path=path, data=data, file=None)

    return expanded()
