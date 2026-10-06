"""Compiled rule cache contracts, using local rules and no provider requests."""
import os
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from kingfisher_sdk import Rules, ScanInput, Scanner

DEMO_RULE = Path(__file__).resolve().parents[1] / "examples" / "demo.yml"
TOKEN = "demo_abcd1234efgh5678"


def load_demo(**kwargs):
    return Rules([DEMO_RULE], builtins=False, **kwargs)


def assert_detects(rules):
    finding, = Scanner(rules).scan(TOKEN)
    assert finding.rule_id == "acme.python-demo"
    assert finding.secret == TOKEN


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch, tmp_path):
    cache = tmp_path / "env cache"
    monkeypatch.setenv("KF_RULE_CACHE_DIR", str(cache))
    return cache


def test_default_cache_and_hit(isolated_cache):
    first = load_demo()
    assert first.cache_status == "stored"
    assert_detects(first)
    entry, = isolated_cache.glob("*.vscdb")
    assert entry.read_bytes().startswith(b"KFRULEDB")
    # A cache hit must actually reuse the entry, not compile and rewrite it.
    os.utime(entry, (1_000_000, 1_000_000))
    before = entry.stat().st_mtime_ns
    cached = load_demo()
    assert cached.cache_status == "loaded"
    assert_detects(cached)
    assert cached.metadata() == first.metadata()
    assert cached.detail("acme.python-demo") == first.detail("acme.python-demo")
    assert entry.stat().st_mtime_ns == before


@pytest.mark.parametrize("read_only", [
    False,
    pytest.param(True, marks=pytest.mark.skipif(os.name == "nt", reason="Unix mode permissions")),
])
def test_transferred_cache_reuses_consumer_owned_entry(tmp_path, read_only):
    producer = tmp_path / "producer cache"
    warmed = load_demo(cache_dir=producer)
    assert warmed.cache_status == "stored"
    source, = producer.glob("*.vscdb")
    payload = source.read_bytes()

    # Provision the consumer leaf/file through native creation so their owner is
    # the process user even when Windows defaults to Administrators ownership.
    # A different catalog ensures the target rules have never been cached here.
    provisioning_rule = tmp_path / "consumer provisioning.yml"
    provisioning_rule.write_text(
        "rules:\n  - id: acme.cache-provisioning\n    name: Cache provisioning\n"
        "    pattern: '(provision_[A-Z]{8})'\n    confidence: high\n",
        encoding="utf-8",
    )
    consumer = tmp_path / "consumer cache"
    provisioned = Rules([provisioning_rule], builtins=False, cache_dir=consumer)
    assert provisioned.cache_status == "stored"
    placeholder, = consumer.glob("*.vscdb")
    entry = consumer / source.name
    placeholder.rename(entry)
    # Overwrite bytes without importing producer ownership or replacing the
    # already consumer-owned file. Deployment tools must likewise retain or
    # assign the runtime user's ownership when transferring a warmed cache.
    shutil.copyfile(source, entry)
    os.utime(entry, (1_000_000, 1_000_000))
    before = entry.stat().st_mtime_ns
    if os.name == "posix":
        assert consumer.stat().st_uid == os.geteuid()
        assert entry.stat().st_uid == os.geteuid()
        assert consumer.stat().st_mode & 0o077 == 0
        assert entry.stat().st_mode & 0o077 == 0
    if read_only:
        entry.chmod(0o400)
        consumer.chmod(0o500)
    try:
        cached = load_demo(cache_dir=consumer)
        assert cached.cache_status == "loaded"
        assert cached.metadata() == warmed.metadata()
        assert_detects(cached)
        assert list(consumer.iterdir()) == [entry]
        assert entry.read_bytes() == payload
        assert entry.stat().st_mtime_ns == before
    finally:
        if read_only:
            consumer.chmod(0o700)
            entry.chmod(0o600)


def test_explicit_directory_overrides_environment(isolated_cache, tmp_path):
    explicit = tmp_path / "explicit cache"
    assert_detects(load_demo(cache_dir=explicit))
    assert len(list(explicit.glob("*.vscdb"))) == 1
    assert not isolated_cache.exists()
    assert_detects(load_demo(cache_dir=str(explicit)))


@pytest.mark.parametrize("explicit", [False, True])
def test_opt_out_skips_reads_and_writes(isolated_cache, tmp_path, explicit):
    selected = tmp_path / "explicit" if explicit else isolated_cache
    options = {"cache_dir": selected} if explicit else {}
    uncached = load_demo(cache=False, **options)
    assert uncached.cache_status == "bypassed"
    assert_detects(uncached)
    assert not selected.exists()
    load_demo(**options)
    entry, = selected.glob("*.vscdb")
    entry.write_bytes(b"corrupt cache must remain untouched")
    assert_detects(load_demo(cache=False, **options))
    assert entry.read_bytes() == b"corrupt cache must remain untouched"


@pytest.mark.parametrize("rejection", ["corrupt", "cpu", "version"])
def test_rejected_cache_recompiles(isolated_cache, rejection):
    load_demo()
    entry, = isolated_cache.glob("*.vscdb")
    original = entry.read_bytes()
    bad = bytearray(original)
    if rejection == "corrupt":
        bad[:] = b"invalid cache"
    else:
        header_len, = struct.unpack_from("<I", bad, 8)
        native_start = 12 + header_len
        # Vectorscan 5.x encodes u32 magic/version/length then a u64 CPU mask.
        # Keep the integrity digest valid to reach native compatibility checks.
        if rejection == "cpu":
            bad[native_start + 12:native_start + 20] = b"\xff" * 8
        else:
            bad[native_start + 4:native_start + 8] = b"\0" * 4
        header = json.loads(original[12:native_start])
        native = bytes(bad[native_start:])
        header["database_sha256"] = hashlib.sha256(native).hexdigest()
        encoded = json.dumps(header, separators=(",", ":")).encode()
        bad = bytearray(original[:8] + struct.pack("<I", len(encoded)) + encoded + native)
    entry.write_bytes(bad)
    assert_detects(load_demo())
    repaired = entry.read_bytes()
    assert repaired.startswith(b"KFRULEDB") and repaired != bad
    os.utime(entry, (1_000_000, 1_000_000))
    before = entry.stat().st_mtime_ns
    assert_detects(load_demo())
    assert entry.stat().st_mtime_ns == before


def test_cache_io_failure_is_best_effort(tmp_path):
    # A regular file cannot be a directory; deterministic on Windows and Unix,
    # even for root. Scanning must succeed despite both read and write failures.
    blocker = tmp_path / "not a directory"
    blocker.write_bytes(b"keep")
    rules = load_demo(cache_dir=blocker / "cache")
    assert rules.cache_status == "bypassed"
    assert_detects(rules)
    assert blocker.read_bytes() == b"keep"


def test_builtin_cache_hit_and_confidence_keys(isolated_cache):
    first = Rules(confidence="medium")
    entry, = isolated_cache.glob("*.vscdb")
    os.utime(entry, (1_000_000, 1_000_000))
    before = entry.stat().st_mtime_ns
    cached = Rules(confidence="medium")
    assert cached.metadata() == first.metadata()
    token = 'pscale ID "abcdefghijkl"'
    expected = [(f.rule_id, f.secret) for f in Scanner(first).scan(token)]
    assert expected
    assert [(f.rule_id, f.secret) for f in Scanner(cached).scan(token)] == expected
    # Collection-level source filtering must survive both cold and cached loads.
    ignored = ScanInput("repo/node_modules/package.js", data=token.encode())
    assert Scanner(first).scan_input(ignored) == []
    assert Scanner(cached).scan_input(ignored) == []
    assert entry.stat().st_mtime_ns == before
    Rules(confidence="high")
    assert len(list(isolated_cache.glob("*.vscdb"))) == 2


def set_windows_everyone_write(path, *, grant, inherit_only=False):
    """Change one private fixture's DACL through the supported Windows utility."""
    arguments = ["icacls", os.fspath(path)]
    if grant:
        permissions = "(OI)(IO)M" if inherit_only else "(OI)(CI)M" if path.is_dir() else "M"
        arguments += ["/grant", f"*S-1-1-0:{permissions}"]
    else:
        arguments += ["/remove:g", "*S-1-1-0"]
    subprocess.run(arguments + ["/q"], check=True, capture_output=True)


@pytest.mark.skipif(os.name != "nt" or sys.version_info < (3, 13),
                    reason="Windows Python 3.13 owner-rights ACL")
def test_windows_python_private_directory_owner_rights_are_trusted(tmp_path):
    # Python 3.13 grants OWNER RIGHTS instead of naming the user's SID directly.
    # It permits only the actual owner; native cache children still need their
    # own checked ownership and must preserve the parent's inherited ACLs.
    parent = tmp_path / "python private directory"
    parent.mkdir(mode=0o700)
    cache = parent / "compiled cache"
    first = load_demo(cache_dir=cache)
    assert first.cache_status == "stored"
    assert_detects(first)
    entry, = cache.glob("*.vscdb")
    os.utime(entry, (1_000_000, 1_000_000))
    before = entry.stat().st_mtime_ns
    assert load_demo(cache_dir=cache).cache_status == "loaded"
    assert entry.stat().st_mtime_ns == before


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL regression")
def test_windows_writable_cache_directory_is_bypassed(isolated_cache):
    assert load_demo().cache_status == "stored"
    entry, = isolated_cache.glob("*.vscdb")
    before = entry.read_bytes()
    set_windows_everyone_write(isolated_cache, grant=True)
    try:
        untrusted = load_demo()
        assert untrusted.cache_status == "bypassed"
        assert_detects(untrusted)
        assert entry.read_bytes() == before
    finally:
        set_windows_everyone_write(isolated_cache, grant=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL regression")
def test_windows_inherited_file_write_permissions_are_bypassed(isolated_cache):
    # Let the native API create a user-owned fixture even when an elevated token's
    # default owner would be Administrators, then clear its initially valid entry.
    assert load_demo().cache_status == "stored"
    entry, = isolated_cache.glob("*.vscdb")
    entry.unlink()
    # This ACE leaves the directory itself protected, but new files would give
    # Everyone Modify access. Such files must never be published as reusable.
    set_windows_everyone_write(isolated_cache, grant=True, inherit_only=True)
    try:
        untrusted = load_demo()
        assert untrusted.cache_status == "bypassed"
        assert_detects(untrusted)
        assert not list(isolated_cache.iterdir())
    finally:
        set_windows_everyone_write(isolated_cache, grant=False)
    assert load_demo().cache_status == "stored"
    assert load_demo().cache_status == "loaded"


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL regression")
def test_windows_writable_entry_cannot_replace_detection_rules(isolated_cache, tmp_path):
    assert load_demo().cache_status == "stored"
    entry, = isolated_cache.glob("*.vscdb")
    original = entry.read_bytes()
    header_size, = struct.unpack_from("<I", original, 8)
    header = json.loads(original[12:12 + header_size])

    # A compatible native database plus a valid SHA can silently suppress this
    # token if loaded. Integrity checks alone must not substitute for DACL trust.
    other_rule = tmp_path / "different.yml"
    other_rule.write_text("rules:\n  - id: acme.python-demo\n    name: Different secret\n"
                          "    pattern: 'other_[0-9]{4}'\n    confidence: high\n")
    other_cache = tmp_path / "different cache"
    Rules([other_rule], builtins=False, cache_dir=other_cache)
    alternative, = other_cache.glob("*.vscdb")
    alternate = alternative.read_bytes()
    alternate_header_size, = struct.unpack_from("<I", alternate, 8)
    native = alternate[12 + alternate_header_size:]
    header["database_sha256"] = hashlib.sha256(native).hexdigest()
    encoded = json.dumps(header, separators=(",", ":")).encode()
    forged = b"KFRULEDB" + struct.pack("<I", len(encoded)) + encoded + native
    entry.write_bytes(forged)
    set_windows_everyone_write(entry, grant=True)
    try:
        recovered = load_demo()
        assert recovered.cache_status == "stored"
        assert_detects(recovered)
        assert entry.read_bytes() != forged
        assert load_demo().cache_status == "loaded"
    finally:
        set_windows_everyone_write(entry, grant=False)
