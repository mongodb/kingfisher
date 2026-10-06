"""Composable enumeration contracts, with portable synthetic local fixtures."""
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
import bz2
import gzip
import inspect
import io
import lzma
import os
from pathlib import Path
import subprocess
import sys
import json
import zlib
import tarfile
import zipfile

import pytest

from kingfisher_sdk import (
    CancellationToken, Rules, Scanner, ScanInput, expand_archives, filesystem, git_history,
)

TOKEN = b"demo_abcd1234efgh5678"
RULE_PATH = Path(__file__).resolve().parents[1] / "examples" / "demo.yml"


@pytest.fixture
def scanner():
    return Scanner(Rules([RULE_PATH], builtins=False))


def zip_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def tar_bytes(entries=None):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in ([("dir/credential.txt", TOKEN)] if entries is None else entries):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "repository with spaces"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "SDK Test")
    git(repo, "config", "user.email", "sdk@example.invalid")
    git(repo, "config", "commit.gpgsign", "false")
    (repo / "deleted.txt").write_bytes(TOKEN)
    (repo / "unchanged.txt").write_bytes(b"no credential")
    git(repo, "add", ".")
    git(repo, "commit", "-m", "historical credential")
    (repo / "deleted.txt").unlink()
    (repo / "archive.zip").write_bytes(zip_bytes([("config.txt", TOKEN)]))
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "remove plaintext credential")
    (repo / "untracked.txt").write_bytes(TOKEN)
    return repo


def test_original_signatures_and_file_contract(scanner, tmp_path):
    assert str(inspect.signature(Scanner.scan)) == (
        "(self, data: 'str | bytes', *, timeout: 'float | None' = None, "
        "cancellation: 'CancellationToken | None' = None) -> 'list[Finding]'"
    )
    assert list(inspect.signature(Scanner.__init__).parameters) == [
        "self", "rules", "base64", "dedup", "redact", "min_entropy", "policy",
    ]
    assert list(inspect.signature(Scanner.scan_file).parameters) == [
        "self", "path", "timeout", "cancellation",
    ]
    archive = tmp_path / "compressed.zip"
    archive.write_bytes(zip_bytes([("token.txt", TOKEN)]))
    # scan_file still scans the container bytes without implicit extraction.
    assert scanner.scan_file(archive) == []
    assert len(list(scanner.scan_inputs(expand_archives([ScanInput.from_file(archive)])))[0].findings) == 1


def test_python_inputs_lazy_grouping_and_errors(scanner, tmp_path):
    path = tmp_path / "file with spaces.txt"
    file = ScanInput.from_file(path)  # No read during construction.
    path.write_bytes(TOKEN)
    seen = []
    def python_sources():
        seen.append("first")
        yield ScanInput("logical/config.txt", TOKEN)
        seen.append("second")
        yield file
        yield ScanInput("empty.txt", b"")
        raise OSError("enumeration failed")
    groups = scanner.scan_inputs(python_sources())
    assert seen == []
    first = next(groups)
    assert seen == ["first"]
    assert first.input.path == "logical/config.txt" and len(first.findings) == 1
    assert TOKEN.decode() not in repr(first) and TOKEN.decode() not in repr(first.input)
    assert len(next(groups).findings) == 1
    assert next(groups).findings == []
    with pytest.raises(OSError, match="enumeration failed"):
        next(groups)
    with pytest.raises(ValueError):
        ScanInput("missing")
    with pytest.raises(ValueError):
        ScanInput("ambiguous", TOKEN, file=str(path))
    with pytest.raises(TypeError):
        scanner.scan_input(TOKEN)
    with pytest.raises(RuntimeError):
        scanner.scan_input(ScanInput.from_file(tmp_path / "missing"))


def test_path_filters_and_dedup_for_custom_enumeration(tmp_path):
    path = tmp_path / "paths.toml"
    path.write_text('''[[rules]]
id = "path-token"
description = "Synthetic path token"
regex = '(demo_[a-z0-9]{16})'
path = '(included|other)\\.txt$'
''', encoding="utf-8")
    scanner = Scanner(Rules([path], builtins=False), dedup=True)
    assert scanner.scan_input(ScanInput("excluded.txt", TOKEN)) == []
    assert len(scanner.scan_input(ScanInput("included.txt", TOKEN))) == 1
    assert scanner.scan_input(ScanInput("included.txt", TOKEN)) == []
    assert len(scanner.scan_input(ScanInput("other.txt", TOKEN))) == 1
    scanner.reset_dedup()
    assert len(scanner.scan_input(ScanInput("included.txt", TOKEN))) == 1


def test_native_filesystem_selection(scanner, tmp_path):
    git(tmp_path, "init")  # .gitignore handling matches Git repository semantics.
    assert list(git_history(tmp_path, refs=None)) == []
    (tmp_path / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_bytes(TOKEN)
    (tmp_path / ".hidden.txt").write_bytes(TOKEN)
    (tmp_path / "kept.txt").write_bytes(TOKEN)
    (tmp_path / "large.txt").write_bytes(b"x" * 100)
    names = {Path(source.path).name for source in filesystem([tmp_path])}
    assert names == {"kept.txt", "large.txt"}
    names = {Path(source.path).name for source in filesystem([tmp_path], hidden=True, gitignore=False, max_file_size=50)}
    assert names == {".gitignore", ".hidden.txt", "ignored.txt", "kept.txt"}
    sources = list(filesystem([tmp_path / "kept.txt"]))
    assert sources[0].data is None and sources[0].file is not None
    assert len(list(scanner.scan_inputs(sources))[0].findings) == 1
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "kept.txt")
    except OSError:
        pass  # Windows may require a privilege to create symlinks.
    else:
        assert "link.txt" not in {Path(source.path).name for source in filesystem([tmp_path])}
    with pytest.raises(TypeError):
        filesystem(tmp_path)
    with pytest.raises(ValueError):
        filesystem([])
    with pytest.raises(RuntimeError):
        list(filesystem([tmp_path / "missing"]))


# Raw archive bytes make PYTEST_CURRENT_TEST exceed Windows' environment limit.
@pytest.mark.parametrize("name,content", [
    ("test.zip", zip_bytes([("dir/credential.txt", TOKEN)])),
    ("test.jar", zip_bytes([("dir/credential.txt", TOKEN)])),
    ("plan", zip_bytes([("dir/credential.txt", TOKEN)])),
    ("CON.zip", zip_bytes([("dir/credential.txt", TOKEN)])),
    ("test.tar", tar_bytes()),
    ("test.tar.gz", gzip.compress(tar_bytes())),
    ("test.tgz", gzip.compress(tar_bytes())),
    ("test.tar.bz2", bz2.compress(tar_bytes())),
    ("test.tar.xz", lzma.compress(tar_bytes())),
    ("test.gz", gzip.compress(TOKEN)),
    ("test.bz2", bz2.compress(TOKEN)),
    ("test.xz", lzma.compress(TOKEN)),
    ("test.zlib", zlib.compress(TOKEN)),
], ids=lambda value: value if isinstance(value, str) else "payload")
def test_archive_formats(scanner, name, content):
    source = ScanInput(name, content, repository="repo", commit="commit", blob_id="git-blob")
    groups = list(scanner.scan_inputs(expand_archives([source])))
    assert len(groups) == 1 and len(groups[0].findings) == 1
    assert groups[0].input.path.startswith(name + "!")
    assert groups[0].input.repository == "repo" and groups[0].input.commit == "commit"
    assert groups[0].input.blob_id == "git-blob"
    assert groups[0].input.data == TOKEN


@pytest.mark.parametrize("name,encode", [
    ("repeated.tar", lambda data: data),
    ("repeated.tar.gz", gzip.compress),
    ("repeated.tar.bz2", bz2.compress),
    ("repeated.tar.xz", lzma.compress),
], ids=["tar", "tar.gz", "tar.bz2", "tar.xz"])
def test_archive_repeated_names_preserve_each_occurrence(scanner, name, encode):
    payloads = [TOKEN, b"clean text"]
    source = ScanInput(name, encode(tar_bytes([("config.txt", data) for data in payloads])),
                       repository="repo", commit="commit", blob_id="container")
    expanded = list(expand_archives([source]))
    assert [member.path for member in expanded] == [name + "!config.txt"] * 2
    assert [member.data for member in expanded] == payloads
    assert all(member.repository == source.repository and member.commit == source.commit
               and member.blob_id == source.blob_id for member in expanded)
    groups = list(scanner.scan_inputs(expanded))
    assert [len(group.findings) for group in groups] == [1, 0]


@pytest.mark.parametrize("name,encode", [
    ("over-budget.tar.gz", gzip.compress),
    ("over-budget.tgz", gzip.compress),
    ("over-budget.tar.bz2", bz2.compress),
    ("over-budget.tar.xz", lzma.compress),
], ids=["tar.gz", "tgz", "tar.bz2", "tar.xz"])
def test_compressed_tar_budget_exhaustion_never_yields_partial_members(name, encode):
    tar = tar_bytes([("first.txt", TOKEN), ("second.txt", b"x" * 3000)])
    compressed = encode(tar)
    assert len(compressed) < 1536 < len(tar)
    source = ScanInput(name, compressed)
    expanded = expand_archives([source], max_bytes=1536)
    with pytest.raises(RuntimeError, match="max_bytes.*budget"):
        next(expanded)
    # An exact intermediate-stream limit must succeed, including TAR padding.
    members = list(expand_archives([source], max_bytes=len(tar)))
    assert [member.data for member in members] == [TOKEN, b"x" * 3000]


def test_nested_archives_budgets_and_safe_paths(scanner, tmp_path):
    inner = zip_bytes([("config.txt", TOKEN)])
    source = ScanInput("dir/outer!.zip", zip_bytes([("nested.zip", inner)]))
    raw, = expand_archives([source], depth=0)
    assert raw.path == source.path and raw.data == source.data
    shallow, = expand_archives([source], depth=1)
    assert shallow.path == "dir/outer!.zip!nested.zip" and shallow.data == inner
    deep, = expand_archives([source], depth=2)
    assert deep.path == "dir/outer!.zip!nested.zip!config.txt" and deep.data == TOKEN
    with pytest.raises(RuntimeError, match="budget"):
        list(expand_archives([source], depth=2, max_bytes=len(inner)))
    with pytest.raises(RuntimeError, match="max_entries"):
        list(expand_archives([source], depth=2, max_entries=1))
    with pytest.raises(RuntimeError):
        list(expand_archives([ScanInput("broken.zip", b"invalid")]))
    assert list(expand_archives([ScanInput("empty.zip", zip_bytes([]))])) == []
    archive = tmp_path / "safe.zip"
    archive.write_bytes(zip_bytes([("../escape.txt", TOKEN), ("/absolute.txt", TOKEN), ("safe.txt", TOKEN)]))
    safe, = expand_archives([ScanInput.from_file(archive)])
    assert safe.path.endswith("!safe.txt") and safe.data == TOKEN
    assert not (tmp_path / "escape.txt").exists()
    for option in (
        {"depth": -1}, {"depth": 33}, {"depth": True}, {"max_bytes": 0},
        {"max_bytes": True}, {"max_entries": 0}, {"max_entries": True},
    ):
        with pytest.raises(ValueError):
            list(expand_archives([], **option))


def test_git_history_metadata_and_composition(scanner, repo, monkeypatch, tmp_path):
    original_commit = git(repo, "rev-parse", "HEAD^")
    original_blob = git(repo, "rev-parse", "HEAD^:deleted.txt")
    # Setup can use git, but SDK enumeration/scanning must work with no executable.
    monkeypatch.setenv("PATH", str(tmp_path))
    def reject(*args, **kwargs):
        raise AssertionError("SDK must not run subprocesses")
    monkeypatch.setattr(subprocess, "Popen", reject)
    sources = list(git_history(repo))
    assert len([source for source in sources if source.path == "unchanged.txt"]) == 1
    historical, = [source for source in sources if source.path == "deleted.txt"]
    assert historical.commit == original_commit and historical.blob_id == original_blob
    assert historical.repository == str(repo) and historical.data == TOKEN
    assert not any(source.path == "untracked.txt" for source in sources)
    groups = list(scanner.scan_inputs(expand_archives(chain(sources, [ScanInput("python.txt", TOKEN)]))))
    assert {group.input.path for group in groups if group.findings} == {
        "deleted.txt", "archive.zip!config.txt", "python.txt",
    }
    assert all(len(group.findings) == 1 for group in groups if group.findings)


def test_git_refs_bare_merge_and_shallow(repo, tmp_path):
    git(repo, "checkout", "-b", "feature", "HEAD^")
    (repo / "branch.txt").write_bytes(TOKEN)
    git(repo, "add", "branch.txt")
    git(repo, "commit", "-m", "branch credential")
    git(repo, "checkout", "main")
    assert "branch.txt" not in {source.path for source in git_history(repo)}
    assert "branch.txt" in {source.path for source in git_history(repo, refs=["feature"])}
    assert "branch.txt" in {source.path for source in git_history(repo, refs=None)}
    git(repo, "merge", "--no-ff", "feature", "-m", "merge branch")
    git(repo, "rm", "branch.txt")
    git(repo, "commit", "-m", "remove merged credential")
    sources = list(git_history(repo))
    assert {"branch.txt", "deleted.txt"} <= {source.path for source in sources}
    bare = tmp_path / "bare repo.git"
    subprocess.run(["git", "clone", "--bare", str(repo), str(bare)], check=True, capture_output=True)
    assert {(s.path, s.blob_id) for s in git_history(bare)} == {(s.path, s.blob_id) for s in sources}
    # Explicit shallow marker avoids file:// clone portability problems on MSYS2.
    # The controlled fixture has a normal .git directory. MSYS2 Git's absolute
    # /c/... output cannot be used as a native Windows filesystem path.
    git_dir = repo / ".git"
    (git_dir / "shallow").write_text(git(repo, "rev-parse", "HEAD") + "\n", encoding="ascii")
    assert "deleted.txt" not in {source.path for source in git_history(repo)}
    with pytest.raises(RuntimeError):
        list(git_history(repo, refs=["does-not-exist"]))
    with pytest.raises(TypeError):
        git_history(repo, refs="HEAD")
    assert list(git_history(repo, refs=[])) == []


def test_cancellation_and_timeout(scanner, repo, tmp_path):
    token = CancellationToken()
    token.cancel()
    with pytest.raises(RuntimeError, match="cancel"):
        list(filesystem([tmp_path], cancellation=token))
    with pytest.raises(RuntimeError, match="cancel"):
        list(git_history(repo, cancellation=token))
    with pytest.raises(RuntimeError, match="cancel"):
        list(expand_archives([ScanInput("token.txt", TOKEN)], cancellation=token))
    with pytest.raises(RuntimeError, match="cancel"):
        scanner.scan_input(ScanInput("token.txt", TOKEN), cancellation=token)
    for enumerate_inputs in (lambda: filesystem([tmp_path], timeout=1e-9), lambda: git_history(repo, timeout=1e-9)):
        with pytest.raises(TimeoutError):
            list(enumerate_inputs())
    with pytest.raises(TimeoutError):
        list(expand_archives([ScanInput("token.txt", TOKEN)], timeout=1e-9))
    with pytest.raises(TimeoutError):
        scanner.scan_input(ScanInput("token.txt", TOKEN), timeout=1e-9)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert all(pool.map(lambda _: len(scanner.scan_input(ScanInput("token.txt", TOKEN))) == 1, range(4)))


@pytest.mark.parametrize("enumerator", ["python", "engine"])
def test_composable_example(enumerator, tmp_path):
    fixture = tmp_path / "config with spaces.txt"
    fixture.write_bytes(TOKEN)
    example = RULE_PATH.with_name("inputs.py")
    result = subprocess.run(
        [sys.executable, str(example), str(fixture), "--filesystem-enumerator", enumerator,
         "--rules-path", str(RULE_PATH), "--no-builtins"],
        check=True, capture_output=True, text=True,
    )
    finding = json.loads(result.stdout)
    assert finding["path"] == str(fixture)
    assert finding["finding"]["secret"] == "[REDACTED]"
    assert TOKEN.decode() not in result.stdout


@pytest.mark.parametrize("enumerator", ["python", "engine"])
def test_git_history_example(enumerator, repo):
    example = RULE_PATH.with_name("git_history.py")
    result = subprocess.run(
        [sys.executable, str(example), str(repo), "--enumerator", enumerator,
         "--all-refs", "--rules-path", str(RULE_PATH), "--no-builtins"],
        check=True, capture_output=True, text=True,
    )
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert {row["path"] for row in rows} == {"deleted.txt", "archive.zip!config.txt"}
    assert all(row["commit"] and row["blob_id"] for row in rows)
    assert all(row["finding"]["secret"] == "[REDACTED]" for row in rows)
    assert TOKEN.decode() not in result.stdout


@pytest.mark.parametrize("source", ["file", "bytes"])
@pytest.mark.parametrize("depth", [0, 1, 2])
def test_archive_example(source, depth):
    example = RULE_PATH.with_name("archives.py")
    result = subprocess.run(
        [sys.executable, str(example), "--source", source, "--depth", str(depth)],
        check=True, capture_output=True, text=True,
    )
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(rows) == (1 if depth == 0 else 2)
    findings = [row for row in rows if row["findings"]]
    if depth == 2:
        finding, = findings
        assert finding["path"].endswith("demo.zip!nested.zip!config.txt")
        assert finding["findings"][0]["secret"] == "[REDACTED]"
    else:
        assert findings == []
    assert TOKEN.decode() not in result.stdout


def test_archive_logical_paths_with_bang_in_temp_directory(tmp_path):
    # Discover the platform temp location in a fresh process using this root.
    temp_root = tmp_path / "profile!temp"
    temp_root.mkdir()
    env = dict(os.environ, TMPDIR=str(temp_root), TMP=str(temp_root), TEMP=str(temp_root))
    script = """
import gzip
import io
import tarfile
import zipfile
from kingfisher_sdk import ScanInput, expand_archives
payload = b"content"
with io.BytesIO() as buffer:
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("member!name.txt", payload)
    zipped = buffer.getvalue()
with io.BytesIO() as buffer:
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("member!name.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    tarred = buffer.getvalue()
for path, data, suffix in [
    ("outer!.gz", gzip.compress(payload), "content"),
    ("outer!.zip", zipped, "member!name.txt"),
    ("outer!.tar.gz", gzip.compress(tarred), "member!name.txt"),
]:
    expanded, = expand_archives([ScanInput(path, data)])
    assert expanded.path == path + "!" + suffix, expanded.path
    assert expanded.data == payload
"""
    subprocess.run([sys.executable, "-c", script], env=env, check=True)


@pytest.mark.parametrize("options", [{"depth": 99}, {"max_bytes": 0}, {"max_entries": 0}])
def test_archive_options_are_validated_before_iteration(options):
    with pytest.raises(ValueError):
        expand_archives([], **options)


def test_content_options_are_validated_before_iteration():
    from kingfisher_sdk import expand_content
    with pytest.raises(ValueError):
        expand_content([], max_bytes=0)


def test_filesystem_skips_case_variants_of_git_directory(tmp_path):
    metadata = tmp_path / ".GIT"
    metadata.mkdir()
    (metadata / "objects").write_bytes(TOKEN)
    (tmp_path / "source.txt").write_bytes(TOKEN)
    assert {Path(source.path).name for source in filesystem([tmp_path], hidden=True, gitignore=False)} == {"source.txt"}
