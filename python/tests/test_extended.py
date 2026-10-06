"""Regression coverage for additive policies, binary extraction and Git provenance."""
import base64
from dataclasses import replace
import inspect
import os
import py_compile
import sqlite3
import subprocess
import sys
import time

import pytest

from kingfisher_sdk import (
    CancellationToken, DetectionScanner, GitInput, GitScope, Rules, Scanner,
    ScanInput, expand_archives, expand_content, git_inputs,
)
from test_inputs import TOKEN, RULE_PATH, git, repo, zip_bytes


@pytest.fixture
def rules():
    return Rules([RULE_PATH], builtins=False)


def test_detection_opt_in_preserves_contract(rules):
    raw = Scanner(rules)
    filtered = DetectionScanner(rules)
    ignored = TOKEN + b" # kingfisher:ignore"
    assert len(raw.scan(ignored)) == 1
    assert filtered.scan(ignored) == []
    assert len(DetectionScanner(rules, inline_ignores=False).scan(ignored)) == 1
    custom = DetectionScanner(rules, ignore_comments=["acme:ignore"])
    assert custom.scan(TOKEN + b" # ACME:IGNORE") == []
    encoded = base64.b64encode(b"token=" + TOKEN)
    assert len(raw.scan(encoded)) == 1
    assert filtered.scan(encoded + b" # kingfisher:ignore") == []
    assert filtered.scan((TOKEN + b" # kingfisher:ignore").decode().encode("utf-16")) == []
    assert list(inspect.signature(Scanner.__init__).parameters) == [
        "self", "rules", "base64", "dedup", "redact", "min_entropy", "policy",
    ]
    assert list(inspect.signature(ScanInput).parameters) == [
        "path", "data", "file", "repository", "commit", "blob_id", "extraction_error",
    ]


def test_detection_base64_policy_preserves_legacy_defaults(rules):
    once = base64.b64encode(b"token=" + TOKEN)
    twice = base64.b64encode(once)
    thrice = base64.b64encode(twice)
    assert Scanner(rules).scan(twice) == []
    finding, = DetectionScanner(rules).scan(twice)
    assert finding.secret.encode() == TOKEN
    detail = finding.to_dict()
    assert detail["is_base64_encoded"]
    assert (detail["location"]["start_offset"], detail["location"]["end_offset"]) == (0, len(twice))
    assert DetectionScanner(rules, base64_max_depth=1).scan(twice) == []
    assert DetectionScanner(rules, base64_max_depth=0).scan(once) == []
    assert DetectionScanner(rules, base64_max_input_bytes=len(twice) - 1).scan(twice) == []
    assert len(DetectionScanner(rules, base64_max_input_bytes=len(twice)).scan(twice)) == 1
    assert DetectionScanner(rules).scan(thrice) == []
    assert len(DetectionScanner(rules, base64_max_depth=3, base64_max_input_bytes=None).scan(thrice)) == 1
    assert DetectionScanner(rules, base64=False, base64_max_depth=3).scan(thrice) == []
    for options in ({"base64_max_depth": -1}, {"base64_max_input_bytes": -1}):
        with pytest.raises(ValueError):
            DetectionScanner(rules, **options)
    for options in ({"base64_max_depth": True}, {"base64_max_depth": 1.5}, {"base64_max_input_bytes": "64"}, {"cli_match_semantics": "yes"}):
        with pytest.raises(TypeError):
            DetectionScanner(rules, **options)


def test_markup_and_redaction(rules):
    scanner = DetectionScanner(rules, redact=True)
    comment = ScanInput("config.HTML", b"<!-- " + TOKEN + b" -->")
    assert scanner.scan_input(comment) == []
    attribute = ScanInput("config.html", b'<input password="' + TOKEN + b'">')
    finding, = scanner.scan_input(attribute)
    assert finding.to_dict()["secret"] == "[REDACTED]"
    assert DetectionScanner(rules, language="html").scan(comment.data) == []
    assert len(DetectionScanner(rules, markup_context=False).scan_input(comment)) == 1
    assert len(scanner.scan_input(ScanInput("config.css", b'body { password: "' + TOKEN + b'"; }'))) == 1
    assert scanner.scan_input(ScanInput("config.css", b"/* " + TOKEN + b" */")) == []
    # The CLI bounds structural parsing to 2 MiB and retains candidates beyond it.
    assert len(scanner.scan_input(replace(comment, data=comment.data + b" " * (2 * 1024 * 1024)))) == 1


def test_context_dedup_not_poisoned_by_rejections(rules):
    scanner = DetectionScanner(rules, dedup=True, language="html")
    ignored = ScanInput("same.html", b"<!-- " + TOKEN + b" -->")
    assert scanner.scan_input(ignored) == []
    assert scanner.scan_input(ignored) == []
    keep = ScanInput("same.html", b'<input value="' + TOKEN + b'">')
    assert len(scanner.scan_input(keep)) == 1
    assert scanner.scan_input(keep) == []
    scanner.reset_dedup()
    assert len(scanner.scan_input(keep)) == 1


def database(tmp_path):
    path = tmp_path / "database with spaces.db"
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE "credential table" (secret TEXT)')
        db.execute('INSERT INTO "credential table" VALUES (?)', (TOKEN.decode(),))
    # sqlite3's context manager commits but does not close its handle.
    db.close()
    return path


def test_sqlite_file_bytes_archive_and_metadata(rules, tmp_path):
    path = database(tmp_path)
    original = path.read_bytes()
    source = ScanInput.from_file(path)
    members = list(expand_content([source]))
    assert len(members) == 1
    assert members[0].path.endswith("!credential table.sql")
    assert b"INSERT INTO" in members[0].data
    assert path.read_bytes() == original
    assert len(Scanner(rules).scan_input(members[0])) == 1
    origin = GitInput("db", original, repository="repository", commit="a" * 40, blob_id="b" * 40)
    extracted, = expand_content([origin])
    assert isinstance(extracted, GitInput) and extracted.commit == origin.commit
    zipped = ScanInput("backup.zip", zip_bytes([("data.db", original)]))
    nested, = expand_content(expand_archives([zipped]))
    assert nested.path == "backup.zip!data.db!credential table.sql"
    assert len(Scanner(rules).scan_input(nested)) == 1
    assert list(expand_content([source], sqlite=False)) == [source]
    with pytest.raises(RuntimeError, match="max_bytes"):
        list(expand_content([source], max_bytes=16))


def test_pyc_never_executes_and_preserves_constants(rules, tmp_path):
    marker = tmp_path / "must never be created"
    source = tmp_path / "module.py"
    source.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\ndef nested():\n    return {TOKEN.decode()!r}\n", encoding="utf-8")
    pyc = tmp_path / "module.pyc"
    py_compile.compile(str(source), cfile=str(pyc), doraise=True)
    extracted, = expand_content([ScanInput.from_file(pyc)], strict=True)
    assert extracted.path.endswith("module.pyc!strings.py")
    assert len(Scanner(rules).scan_input(extracted)) == 1
    assert not marker.exists()
    zipped = ScanInput("wheel.zip", zip_bytes([("module.pyc", pyc.read_bytes())]))
    nested, = expand_content(expand_archives([zipped]))
    assert nested.path == "wheel.zip!module.pyc!strings.py"
    assert not marker.exists()


def test_content_fallback_and_controls(tmp_path):
    plain = ScanInput("ordinary.txt", TOKEN)
    corrupt = ScanInput("corrupt.pyc", b"bad header")
    unsupported = ScanInput("future.pyc", b"\xff\xff\r\n" + bytes(16))
    normal, fallback, unknown = expand_content([plain, corrupt, unsupported])
    assert normal is plain and unknown is unsupported
    assert fallback.path == corrupt.path and fallback.data is corrupt.data
    assert fallback.extraction_error == "malformed_pyc"
    assert "malformed_pyc" not in repr(fallback)
    with pytest.raises(RuntimeError):
        list(expand_content([corrupt], strict=True))
    assert list(expand_content([corrupt], pyc=False)) == [corrupt]
    token = CancellationToken()
    token.cancel()
    with pytest.raises(RuntimeError, match="cancelled"):
        list(expand_content([plain], cancellation=token))
    for bad in (0, -1, "invalid"):
        with pytest.raises(ValueError):
            list(expand_content([], max_bytes=bad))


def test_git_scopes_metadata_and_composition(repo, rules):
    root = git(repo, "rev-parse", "HEAD~1")
    head = git(repo, "rev-parse", "HEAD")
    history = list(git_inputs(repo))
    old = next(source for source in history if source.path == "deleted.txt")
    assert old.commit == root and old.data == TOKEN
    origin, = old.origins
    assert origin.author.name == "SDK Test"
    assert origin.author.email == "sdk@example.invalid"
    assert origin.committer.timestamp > 0 and origin.parents == ()
    assert origin.message.strip() == "historical credential"
    assert origin.message not in repr(origin)
    assert TOKEN.decode() not in repr(old)
    ranged = list(git_inputs(repo, scope=GitScope(since_commit=root)))
    assert {source.path for source in ranged} == {"archive.zip"}
    assert ranged[0].origins[0].parents == (root,)
    assert list(git_inputs(repo, scope=GitScope(since_commit=head))) == []
    inclusive = list(git_inputs(repo, scope=GitScope(branch_root=root)))
    assert {source.path for source in inclusive} == {source.path for source in history}
    snapshot = list(git_inputs(repo, scope=GitScope(mode="snapshot")))
    assert {source.path for source in snapshot} == {"archive.zip", "unchanged.txt"}
    assert all(source.commit == head for source in snapshot)
    diff = list(git_inputs(repo, scope=GitScope(mode="diff", since_commit=root)))
    assert {source.path for source in diff} == {"archive.zip"}
    expanded, = expand_content(expand_archives(ranged))
    assert isinstance(expanded, GitInput) and expanded.origins == ranged[0].origins
    assert len(DetectionScanner(rules).scan_input(expanded)) == 1
    empty = list(git_inputs(repo, scope=GitScope(since_time=int(time.time()) + 3600)))
    assert empty == []
    assert list(git_inputs(repo, scope=GitScope(since_hours=24)))


def test_git_staged_uses_index_without_writes(repo):
    path = repo / "staged.txt"
    path.write_bytes(TOKEN)
    git(repo, "add", str(path))
    path.write_bytes(b"unstaged replacement")
    gitdir = repo / ".git"
    before = {name: (gitdir / name).read_bytes() for name in ("index", "HEAD")}
    staged, = git_inputs(repo, scope=GitScope(mode="staged"))
    assert staged.path == "staged.txt" and staged.data == TOKEN
    assert staged.staged and staged.commit is None and staged.origins == ()
    assert {name: (gitdir / name).read_bytes() for name in before} == before


def test_git_unborn_staged(tmp_path):
    git(tmp_path, "init", "-b", "main")
    path = tmp_path / "initial.txt"
    path.write_bytes(TOKEN)
    git(tmp_path, "add", ".")
    source, = git_inputs(tmp_path, scope=GitScope(mode="staged"))
    assert source.data == TOKEN and source.commit is None


def test_git_reintroduction_multiple_origins_and_unreachable(repo):
    (repo / "deleted.txt").write_bytes(TOKEN)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "reintroduce")
    source = next(source for source in git_inputs(repo) if source.path == "deleted.txt")
    assert len(source.origins) == 2
    # Write an orphan blob and commit, without leaving either selected by refs.
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                          input=b"unassociated " + TOKEN, capture_output=True, check=True).stdout.decode().strip()
    git(repo, "checkout", "--orphan", "abandoned")
    git(repo, "rm", "-rf", ".")
    (repo / "orphan.txt").write_bytes(TOKEN)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "unreachable credential")
    orphan = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "main")
    git(repo, "branch", "-D", "abandoned")
    assert "orphan.txt" not in {source.path for source in git_inputs(repo)}
    sources = list(git_inputs(repo, scope=GitScope(refs=None, include_unreachable=True)))
    source = next(source for source in sources if source.path == "orphan.txt")
    assert source.unreachable and source.commit == orphan
    raw = next(source for source in sources if source.blob_id == blob)
    assert raw.path == f"@git/{blob}" and raw.unreachable is None and raw.origins == ()


@pytest.mark.parametrize("kwargs", [
    {"mode": "bad"}, {"refs": "HEAD"}, {"refs": []},
    {"mode": "diff"}, {"mode": "snapshot", "refs": None},
    {"since_commit": "HEAD", "branch_root": "HEAD"},
    {"since_hours": float("nan")}, {"since_hours": 0}, {"since_hours": True},
    {"since_time": 2, "until_time": 1}, {"since_time": 1.5},
    {"mode": "staged", "since_hours": 1}, {"include_unreachable": True},
    {"mode": "snapshot", "since_commit": "HEAD"},
    {"mode": "staged", "refs": ("other",)},
])
def test_git_scope_validation(kwargs):
    with pytest.raises((TypeError, ValueError)):
        GitScope(**kwargs)


def test_git_controls_errors_and_bare(repo, tmp_path):
    token = CancellationToken()
    token.cancel()
    with pytest.raises(RuntimeError, match="cancelled"):
        git_inputs(repo, cancellation=token)
    with pytest.raises(RuntimeError):
        git_inputs(repo, scope=GitScope(refs=("missing-ref",)))
    bare = tmp_path / "bare.git"
    git(repo, "clone", "--bare", str(repo), str(bare))
    assert {source.path for source in git_inputs(bare)} == {source.path for source in git_inputs(repo)}
    delayed = git_inputs(repo, timeout=0.1)
    time.sleep(0.2)
    with pytest.raises(TimeoutError):
        next(delayed)


def test_git_merge_and_shallow(repo, tmp_path):
    baseline = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "-b", "side")
    (repo / "side.txt").write_bytes(TOKEN)
    git(repo, "add", ".")
    git(repo, "commit", "-m", "side credential")
    side = git(repo, "rev-parse", "HEAD")
    git(repo, "checkout", "main")
    (repo / "main.txt").write_bytes(b"main content")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "main change")
    git(repo, "merge", "--no-ff", "side", "-m", "merge side")
    sources = list(git_inputs(repo, scope=GitScope(since_commit=baseline)))
    changed = next(source for source in sources if source.path == "side.txt")
    assert side in {origin.id for origin in changed.origins}
    assert any(len(origin.parents) == 2 for origin in changed.origins)
    shallow = tmp_path / "shallow repo"
    git(repo, "clone", "--no-local", "--depth", "1", str(repo), str(shallow))
    sources = list(git_inputs(shallow))
    assert {source.path for source in sources} == {"archive.zip", "unchanged.txt", "side.txt", "main.txt", "untracked.txt"}
    assert all(len(source.origins) == 1 for source in sources)


def test_git_clock_skew_does_not_prune_ancestor(repo):
    path = repo / "skew.txt"
    path.write_bytes(TOKEN)
    git(repo, "add", ".")
    env = dict(os.environ, GIT_AUTHOR_DATE="2024-01-02T00:00:00+05:30",
               GIT_COMMITTER_DATE="2024-01-02T00:00:00+05:30")
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "newer ancestor"],
                   env=env, capture_output=True, check=True)
    newer = git(repo, "rev-parse", "HEAD")
    path.write_bytes(b"older descendant")
    git(repo, "add", ".")
    env.update(GIT_AUTHOR_DATE="2023-01-02T00:00:00+00:00", GIT_COMMITTER_DATE="2023-01-02T00:00:00+00:00")
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "older descendant"],
                   env=env, capture_output=True, check=True)
    source = next(source for source in git_inputs(repo, scope=GitScope(since_time=1704067200)) if source.path == "skew.txt")
    assert source.data == TOKEN and source.commit == newer
    assert source.origins[0].committer.timezone_offset == 19800


def test_git_staged_rejects_conflicts(repo):
    path = repo / "unchanged.txt"
    git(repo, "checkout", "-b", "conflict")
    path.write_bytes(b"side")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "side")
    git(repo, "checkout", "main")
    path.write_bytes(b"main")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "main")
    with pytest.raises(subprocess.CalledProcessError):
        git(repo, "merge", "conflict")
    with pytest.raises(RuntimeError, match="conflicts"):
        git_inputs(repo, scope=GitScope(mode="staged"))


@pytest.mark.parametrize("example", ["detection.py", "content.py", "git_scopes.py"])
def test_new_examples(example, repo):
    path = RULE_PATH.with_name(example)
    args = [sys.executable, str(path)]
    if example == "git_scopes.py":
        args += [str(repo), "--rules-path", str(RULE_PATH), "--no-builtins"]
    result = subprocess.run(args, capture_output=True, text=True, check=True)
    import json
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows and TOKEN.decode() not in result.stdout
    if example == "detection.py":
        assert [row["context_count"] for row in rows] == [0, 0, 1, 1]
        assert [row["legacy_count"] for row in rows] == [1, 1, 1, 0]
        assert rows[-1]["findings"][0]["is_base64_encoded"]
    elif example == "content.py":
        assert len(rows) == 3 and all(row["findings"] for row in rows[:2])
        assert rows[-1] == {"path": "broken.pyc", "extraction_error": "malformed_pyc"}
    else:
        assert all(row["origins"] for row in rows)
