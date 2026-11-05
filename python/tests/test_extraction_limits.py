"""Resource/error boundaries for explicit content transforms (offline fixtures)."""
import gzip
import io
import json
import py_compile
import sqlite3
import struct
import tarfile
import zipfile

import pytest

from kingfisher_sdk import GitInput, ScanInput, expand_archives, expand_content


def zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


def tar_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in entries:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def asar_bytes(entries):
    files = {}
    payload = bytearray()
    for name, data in entries:
        directory = files
        *parents, filename = name.split("/")
        for parent in parents:
            directory = directory.setdefault(parent, {"files": {}})["files"]
        directory[filename] = {"size": len(data), "offset": str(len(payload))}
        payload.extend(data)
    header = json.dumps({"files": files}, separators=(",", ":")).encode("utf-8")
    padded_size = len(header) + (-len(header) % 4)
    # Electron ASAR framing: a size pickle, then a padded JSON-string pickle.
    framing = struct.pack("<4I", 4, padded_size + 8, padded_size + 4, len(header))
    return framing + header + bytes(padded_size - len(header)) + bytes(payload)


@pytest.mark.parametrize("kind, make_archive", [
    ("tar", tar_bytes), ("zip", zip_bytes), ("asar", asar_bytes),
], ids=["tar", "zip", "asar"])
@pytest.mark.parametrize("file_backed", [False, True], ids=["memory", "file"])
def test_unsafe_archive_never_yields_partial_members_and_cleans_storage(
    tmp_path, kind, make_archive, file_backed,
):
    staging = tmp_path / "staging"
    staging.mkdir()
    safe_entries = [("first.txt", b"complete")]
    safe, = expand_archives([
        ScanInput(f"safe.{kind}", make_archive(safe_entries)),
    ], temp_dir=staging)
    assert safe.data == b"complete"  # Validate the synthetic framing too.
    # ASAR sorts paths; this unsafe member sorts after the complete first file.
    data = make_archive(safe_entries + [("z/../../escape.txt", b"hidden")])
    if file_backed:
        path = tmp_path / f"unsafe.{kind}"
        path.write_bytes(data)
        source = ScanInput.from_file(path)
    else:
        source = ScanInput(f"unsafe.{kind}", data)
    iterator = expand_archives([source], temp_dir=staging)
    with pytest.raises(RuntimeError, match="unsafe"):
        next(iterator)  # Root rejection must precede even the safe first member.
    assert list(staging.iterdir()) == []
    assert not (tmp_path / "escape.txt").exists()


def test_nested_entry_budget_counts_skipped_directories():
    inner = zip_bytes([("first.txt", b"a"), ("second.txt", b"b")])
    outer = ScanInput("outer.zip", zip_bytes([("directory/", b""), ("inner.zip", inner)]))
    iterator = expand_archives([outer], depth=2, max_entries=3)
    with pytest.raises(RuntimeError, match="max_entries budget"):
        next(iterator)  # No members from a failed root escape before the error.
    members = list(expand_archives([outer], depth=2, max_entries=4))
    assert [member.data for member in members] == [b"a", b"b"]


def test_nested_stream_cap_uses_remaining_root_budget(tmp_path):
    # The first layer consumes almost all the root budget. Even though the
    # stream's own output fits that original budget, the remaining budget does not.
    stream = gzip.compress(b"x" * 2048)
    outer_bytes = zip_bytes([("padding.txt", b"p" * 1900), ("payload.gz", stream)])
    assert len(outer_bytes) < 2048
    iterator = expand_archives([ScanInput("outer.zip", outer_bytes)], depth=2,
                               max_bytes=2048, temp_dir=tmp_path)
    with pytest.raises(RuntimeError, match="max_bytes budget"):
        next(iterator)
    assert list(tmp_path.iterdir()) == []  # Private staging is cleaned on failure.


def test_tar_budget_fails_during_extraction_and_cleans_private_storage(tmp_path):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in ("a.txt", "b.txt"):
            member = tarfile.TarInfo(name)
            member.size = 16
            archive.addfile(member, io.BytesIO(b"x" * 16))
    iterator = expand_archives([ScanInput("input.tar", output.getvalue())],
                               max_entries=1, temp_dir=tmp_path)
    with pytest.raises(RuntimeError, match="max_entries budget"):
        next(iterator)
    assert list(tmp_path.iterdir()) == []


def test_corrupt_tar_never_yields_partial_members_and_cleans_storage(tmp_path):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name in ("first.txt", "second.txt"):
            member = tarfile.TarInfo(name)
            member.size = 8
            archive.addfile(member, io.BytesIO(b"complete"))
    data = bytearray(output.getvalue())
    data[1024] ^= 1  # Corrupt the second header after a complete first member.
    iterator = expand_archives([ScanInput("corrupt.tar", bytes(data))],
                               temp_dir=tmp_path)
    with pytest.raises(RuntimeError):
        next(iterator)
    assert list(tmp_path.iterdir()) == []


def test_small_zip_and_bytecode_do_not_require_temporary_disk(tmp_path):
    # Missing staging storage would fail any attempt to create a temporary file.
    missing = tmp_path / "not-created"
    member, = expand_archives([ScanInput("data.zip", zip_bytes([("a.txt", b"a")]))],
                              temp_dir=missing)
    assert member.data == b"a"
    source = tmp_path / "module.py"
    source.write_text("TOKEN = 'synthetic token'\n", encoding="utf-8")
    bytecode = tmp_path / "module.pyc"
    py_compile.compile(str(source), cfile=str(bytecode), doraise=True)
    extracted, = expand_content([ScanInput("module.pyc", bytecode.read_bytes())],
                               strict=True, temp_dir=missing)
    assert b"synthetic token" in extracted.data
    assert not missing.exists()


def test_sqlite_output_budget_never_falls_back_to_raw(tmp_path):
    database = tmp_path / "large.db"
    connection = sqlite3.connect(database)
    try:
        connection.execute("CREATE TABLE tokens (token BLOB)")
        connection.execute("INSERT INTO tokens VALUES (?)", (b"x" * 64_000,))
        connection.commit()
    finally:
        connection.close()
    # Input fits, but SQL's hex encoding would exceed the same output budget.
    source = ScanInput.from_file(database)
    staging = tmp_path / "staging"
    staging.mkdir()
    for strict in (False, True):
        with pytest.raises(RuntimeError, match="max_bytes budget"):
            list(expand_content([source], max_bytes=database.stat().st_size,
                                strict=strict, temp_dir=staging))
    assert list(staging.iterdir()) == []


def test_malformed_bytecode_diagnostic_preserves_specialized_provenance():
    # The header is supported, but the marshal stream is malformed after a value.
    data = (3413).to_bytes(2, "little") + b"\r\n" + bytes(12) + b")\x02z\x03abc?"
    source = GitInput("module.pyc", data, repository="repository", commit="a" * 40,
                      blob_id="b" * 40, raw_path=b"module.pyc")
    fallback, = expand_content([source])
    assert isinstance(fallback, GitInput)
    assert fallback.data is source.data
    assert fallback.raw_path == source.raw_path
    assert fallback.commit == source.commit and fallback.blob_id == source.blob_id
    assert fallback.extraction_error == "malformed_pyc"
    assert "abc" not in repr(fallback)
    with pytest.raises(RuntimeError):
        list(expand_content([source], strict=True))


def test_bytecode_work_limits_do_not_turn_into_raw_fallback():
    # A well-framed tuple advertises more elements than the shared work limit.
    # Work exhaustion must remain an error in best-effort malformed-input mode.
    data = (3413).to_bytes(2, "little") + b"\r\n" + bytes(12)
    data += b"(" + (1_000_001).to_bytes(4, "little")
    with pytest.raises(RuntimeError, match="work limit"):
        list(expand_content([ScanInput("input.pyc", data)]))
