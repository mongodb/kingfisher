"""Git acquisition bounds, shared provenance, and coverage diagnostics.

Fixtures use local Git argument arrays and binary tree records, including for
non-UTF-8 names, so path tests work independently of the host filesystem encoding.
"""
from pathlib import Path
import hashlib
import struct
import zlib
import stat
import subprocess
import warnings

import pytest

from kingfisher_sdk import GitScope, git_history, git_inputs
from kingfisher_sdk.git import GitInputWarning
from test_inputs import TOKEN, git, repo


def test_shared_history_facade_and_commit_identity(repo):
    histories = list(git_history(repo))
    scopes = list(git_inputs(repo))
    assert {(s.path, s.blob_id, s.origins) for s in histories} == {
        (s.path, s.blob_id, s.origins) for s in scopes
    }
    root_versions = [s for s in scopes if not s.origins[0].parents]
    assert len(root_versions) > 1
    assert all(s.origins[0] is root_versions[0].origins[0] for s in root_versions)
    assert root_versions[0].origins[0].author.email not in repr(root_versions[0])


def test_git_limits_and_warning_contract(repo):
    with pytest.raises(RuntimeError, match="max_commits"):
        git_inputs(repo, max_commits=1)
    with pytest.raises(RuntimeError, match="max_inputs"):
        git_inputs(repo, max_inputs=1)
    with pytest.warns(GitInputWarning, match="max_blob_size") as emitted:
        assert list(git_inputs(repo, max_blob_size=0)) == []
    assert emitted and all("coverage is incomplete" in str(w.message) for w in emitted)
    assert all("deleted.txt" not in str(w.message) for w in emitted)
    largest = max(len(s.data) for s in git_inputs(repo))
    with warnings.catch_warnings(record=True) as emitted:
        assert list(git_inputs(repo, max_blob_size=largest))
    assert emitted == []
    for name in ("max_commits", "max_inputs", "max_blob_size"):
        with pytest.raises(TypeError):
            git_inputs(repo, **{name: True})
        with pytest.raises(ValueError):
            git_inputs(repo, **{name: -1})


def test_explicit_repository_roots(repo):
    inside = repo / "ordinary directory"
    inside.mkdir()
    assert {s.blob_id for s in git_inputs(inside)} == {s.blob_id for s in git_inputs(repo)}
    with pytest.raises(RuntimeError):
        git_inputs(inside, discover=False)
    assert list(git_inputs(repo, discover=False))
    assert list(git_inputs(repo / ".git", discover=False))


def test_missing_blobs_fail_or_warn_without_fetch(repo):
    blob = git(repo, "rev-parse", "HEAD^:deleted.txt")
    # This fixture creates a normal working repository. Use its native path:
    # MSYS2 Git prints /c/... paths that native Windows pathlib cannot consume.
    gitdir = repo / ".git"
    object_path = gitdir / "objects" / blob[:2] / blob[2:]
    # Git marks loose objects read-only on Windows. Remove that fixture-only
    # attribute before deliberately deleting the blob to simulate corruption.
    object_path.chmod(object_path.stat().st_mode | stat.S_IWRITE)
    object_path.unlink()
    with pytest.raises(RuntimeError, match="missing"):
        list(git_inputs(repo))
    with pytest.warns(GitInputWarning, match="missing"):
        sources = list(git_inputs(repo, skip_missing_blobs=True))
    assert all(s.blob_id != blob for s in sources)
    # No promisor remote is contacted or object silently restored.
    assert not object_path.exists()


def test_non_utf8_names_keep_distinct_raw_identity_and_transform_metadata(repo):
    blob = git(repo, "rev-parse", "HEAD^:deleted.txt")
    records = b"".join(b"100644 blob " + blob.encode("ascii") + b"\t" + name + b"\0"
                       for name in (b"name-\xfe.txt", b"name-\xff.txt"))
    tree = subprocess.run(["git", "-C", str(repo), "mktree", "-z"], input=records,
                          capture_output=True, check=True).stdout.decode("ascii").strip()
    commit = subprocess.run(["git", "-C", str(repo), "commit-tree", tree],
                            input=b"non-UTF-8 tree\n", capture_output=True,
                            check=True).stdout.decode("ascii").strip()
    git(repo, "update-ref", "refs/heads/raw-names", commit)
    sources = list(git_inputs(repo, scope=GitScope(mode="snapshot", refs=("raw-names",))))
    assert len(sources) == 2 and sources[0].path == sources[1].path
    assert {s.raw_path for s in sources} == {b"name-\xfe.txt", b"name-\xff.txt"}
    assert all(s.data == TOKEN for s in sources)
    assert sources[0].origins[0] is sources[1].origins[0]


def test_reflog_revision_is_local_and_leading_option_is_rejected(repo):
    assert list(git_inputs(repo, scope=GitScope(mode="snapshot", refs=("HEAD@{0}",))))
    with pytest.raises(RuntimeError, match="must not start"):
        git_inputs(repo, scope=GitScope(refs=("--all",)))


@pytest.mark.parametrize("hours", [1e300, float("nan"), float("inf"), 2**63 / 3600, 10**1000])
def test_scope_rejects_unrepresentable_hour_bounds_eagerly(hours):
    with pytest.raises(ValueError, match="since_hours"):
        GitScope(since_hours=hours)


def test_staged_legacy_nonexecuting_mode_is_not_a_change(repo):
    index_path = repo / ".git" / "index"
    original = index_path.read_bytes()
    assert original[:4] == b"DIRC"
    assert struct.unpack_from(">I", original, 8)[0] > 0
    modified = bytearray(original[:-20])
    assert struct.unpack_from(">I", modified, 36)[0] == 0o100644
    struct.pack_into(">I", modified, 36, 0o100664)
    index_path.write_bytes(modified + hashlib.sha1(modified).digest())
    assert list(git_inputs(repo, scope=GitScope(mode="staged"))) == []


def test_staged_baseline_rejects_a_crafted_tree_cycle(repo):
    objects = repo / ".git" / "objects"

    def write_object(kind, content, oid=None):
        raw = f"{kind} {len(content)}\0".encode("ascii") + content
        identity = hashlib.sha1(raw).hexdigest() if oid is None else oid
        path = objects / identity[:2] / identity[2:]
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        return identity

    tree = "1" * 40
    # A corrupt loose object can lie about its object ID; ordinary hashed trees
    # cannot be self-referential. Fixture writes never touch the caller's repo.
    write_object("tree", b"40000 loop\0" + bytes.fromhex(tree), tree)
    commit = write_object("commit", (
        f"tree {tree}\nauthor Test <test@example.com> 1700000000 +0000\n"
        "committer Test <test@example.com> 1700000000 +0000\n\ncycle fixture\n"
    ).encode("ascii"))
    with pytest.raises(RuntimeError, match="cyclic Git tree"):
        git_inputs(repo, scope=GitScope(mode="staged", since_commit=commit), timeout=5)
