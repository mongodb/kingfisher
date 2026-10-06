"""Native, read-only Git scopes and provenance for composable scanning."""
from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Iterator
import os
import warnings

from . import _native
from .inputs import ScanInput, CancellationToken


@dataclass(frozen=True)
class GitScope:
    """Select history changes, a snapshot, a net diff, or staged index content.

    History visits all merge parents; each version is compared with its first
    parent. since_commit excludes that commit and its ancestors; branch_root
    includes the root but excludes its ancestors. Time bounds are inclusive
    committer Unix timestamps and filter after traversal (clock skew is safe).
    since_hours must be positive and fit in signed 64-bit seconds.
    refs=None selects all refs plus HEAD. Snapshot/diff require one ref. Staged
    reads index blobs, excluding unstaged edits, without creating commits.
    include_unreachable requires unbounded all-ref history; it also emits stored
    blobs without regular-file provenance under @git/<object-id>.
    """
    mode: str = "history"
    refs: tuple[str, ...] | None = ("HEAD",)
    since_commit: str | None = None
    since_hours: float | None = None
    since_time: int | None = None
    until_time: int | None = None
    branch_root: str | None = None
    include_unreachable: bool = False

    def __post_init__(self) -> None:
        if self.mode not in ("history", "snapshot", "diff", "staged"):
            raise ValueError("mode must be history, snapshot, diff, or staged")
        if self.refs is not None:
            if isinstance(self.refs, str):
                raise TypeError("refs must be an iterable of ref names")
            refs = tuple(self.refs)
            if not refs or any(not isinstance(ref, str) or not ref for ref in refs):
                raise ValueError("refs must contain nonempty strings")
            object.__setattr__(self, "refs", refs)
        if self.mode == "staged" and self.refs != ("HEAD",):
            raise ValueError("staged uses since_commit for its baseline; refs must stay at the default")
        if self.mode in ("snapshot", "diff") and (self.refs is None or len(self.refs) != 1):
            raise ValueError("snapshot/diff require exactly one ref")
        for name in ("since_commit", "branch_root"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{name} must be a nonempty commit ref")
        if self.since_commit is not None and self.branch_root is not None:
            raise ValueError("since_commit and branch_root are mutually exclusive")
        if self.since_hours is not None:
            if (isinstance(self.since_hours, bool)
                    or not isinstance(self.since_hours, (int, float))
                    or not 0 < self.since_hours < (2**63 / 3600)
                    or self.since_hours * 3600 >= 2**63):
                raise ValueError("since_hours must be positive and fit in signed 64-bit seconds")
            if self.since_time is not None:
                raise ValueError("since_hours and since_time are mutually exclusive")
        for name in ("since_time", "until_time"):
            value = getattr(self, name)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not -(2**63) <= value < 2**63):
                raise ValueError(f"{name} must be a signed 64-bit Unix timestamp")
        if self.since_time is not None and self.until_time is not None and self.since_time > self.until_time:
            raise ValueError("since_time must not exceed until_time")
        history_filters = (self.since_hours, self.since_time, self.until_time, self.branch_root)
        if self.mode != "history" and any(value is not None for value in history_filters):
            raise ValueError("time and branch-root filters require history mode")
        if self.mode == "snapshot" and self.since_commit is not None:
            raise ValueError("snapshot does not accept since_commit; use diff")
        if self.mode == "diff" and self.since_commit is None:
            raise ValueError("diff requires since_commit")
        if self.include_unreachable and (self.mode != "history" or self.refs is not None or self.since_commit is not None or any(value is not None for value in history_filters)):
            raise ValueError("include_unreachable requires unbounded history with refs=None")


@dataclass(frozen=True)
class GitSignature:
    """Git identity and timestamp; timezone_offset is seconds east of UTC."""
    name: str
    email: str = field(repr=False)
    timestamp: int
    timezone_offset: int


@dataclass(frozen=True)
class GitCommit:
    """Original author/committer, parents and message for one scoped occurrence."""
    id: str
    author: GitSignature
    committer: GitSignature
    parents: tuple[str, ...]
    message: str = field(repr=False)


@dataclass(frozen=True)
class GitInput(ScanInput):
    """A file version and every change occurrence selected by its Git scope.

    origins are not a claim of first-ever introduction, nor a list of every
    unchanged snapshot. Snapshot/diff origins identify the selected target.
    Staged inputs have no commit/origins. unreachable=None means a stored blob
    has no regular-file provenance, so reachability cannot be inferred.
    Metadata survives archive/content expansion through dataclasses.replace().
    """
    origins: tuple[GitCommit, ...] = field(default=(), kw_only=True)
    staged: bool = field(default=False, kw_only=True)
    unreachable: bool | None = field(default=False, kw_only=True)
    raw_path: bytes | None = field(default=None, kw_only=True, repr=False)


class GitInputWarning(UserWarning):
    """A Git blob was explicitly skipped; coverage is incomplete.

    Warnings contain an object ID and reason, excluding potentially sensitive
    paths and payloads. Turn these into errors with the standard warnings API if
    complete coverage is required.
    """


def git_inputs(
    path: str | os.PathLike[str], *, scope: GitScope | None = None,
    timeout: float | None = None, cancellation: CancellationToken | None = None,
    discover: bool = True, max_blob_size: int | None = None,
    max_commits: int | None = None, max_inputs: int | None = None,
    skip_missing_blobs: bool = False,
) -> Iterator[GitInput]:
    """Prepare native scope descriptors, then read each blob lazily.

    No Git executable, network, checkout or writes are required. Supports bare
    repositories (except staged mode), all merge parents and shallow boundaries.
    Staged mode rejects conflicts and sparse indexes; intent-to-add entries,
    symlinks and submodules are excluded. Revisions use gix's Git revision grammar,
    including reflogs and ``@{...}`` forms; no commands run during resolution.

    ``discover=True`` searches parent directories, matching the original API;
    set it to False to require the supplied repository root or Git directory.
    Non-UTF-8 paths use a lossy display name and retain exact bytes in ``raw_path``.
    Distinct raw names remain separate even when their display paths are equal.

    Commit metadata is shared across versions. Descriptor memory grows with
    selected changes and ancestry, including with time filters (clock skew must
    not hide newer ancestors). ``max_commits`` bounds distinct visited commits,
    including exclusion ancestry; ``max_inputs`` bounds distinct file versions.
    Either limit fails preparation rather than returning truncated coverage.
    ``max_blob_size`` checks object headers before reading payloads and warns for
    each skipped descriptor. All limits default to None (unlimited).

    Partial/blobless clones are never fetched: missing blobs fail by default.
    ``skip_missing_blobs=True`` warns and skips them; missing trees/commits and
    corrupt objects still fail. ``GitInputWarning`` signals incomplete coverage.
    Timeout covers preparation and the iterator's lifetime, including consumer
    processing time. Native object reads cannot be preempted. Completed inputs
    remain usable after later errors; no partial failed input is returned.
    Order is unspecified. Metadata includes private emails/messages and blob IDs;
    redacted finding output does not remove this provenance.
    """
    if scope is None:
        scope = GitScope()
    if not isinstance(scope, GitScope):
        raise TypeError("scope must be a GitScope")
    for name, value in (("max_blob_size", max_blob_size), ("max_commits", max_commits),
                        ("max_inputs", max_inputs)):
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be a nonnegative integer or None")
            if value < 0:
                raise ValueError(f"{name} must be nonnegative")
    if not isinstance(discover, bool) or not isinstance(skip_missing_blobs, bool):
        raise TypeError("discover and skip_missing_blobs must be bool")
    repository = os.fspath(path)
    native = _native.GitInputs(
        repository, scope, timeout=timeout, cancellation=cancellation,
        discover=discover, max_blob_size=max_blob_size, max_commits=max_commits,
        max_inputs=max_inputs, skip_missing_blobs=skip_missing_blobs,
    )

    def adapt() -> Iterator[GitInput]:
        # One immutable Python object per commit avoids repeating large messages
        # and signatures across every changed file, including merge occurrences.
        commits: dict[str, GitCommit] = {}
        for name, data, blob_id, native_origins, staged, unreachable, raw_path, skipped in native:
            if skipped is not None:
                warnings.warn(f"Git blob {blob_id} skipped ({skipped}); coverage is incomplete",
                              GitInputWarning, stacklevel=2)
                continue
            origins = []
            for origin in native_origins:
                commit_id = origin.id
                if commit_id not in commits:
                    commits[commit_id] = GitCommit(
                        id=commit_id, author=GitSignature(*origin.author),
                        committer=GitSignature(*origin.committer),
                        parents=tuple(origin.parents), message=origin.message,
                    )
                origins.append(commits[commit_id])
            yield GitInput(name, data, repository=repository,
                           commit=origins[0].id if origins else None,
                           blob_id=blob_id, origins=tuple(origins), staged=staged,
                           unreachable=unreachable, raw_path=raw_path)
    return adapt()
