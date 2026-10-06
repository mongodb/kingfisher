"""Offline archive example with synthetic data, file/byte inputs and nested depth.

uv run --no-sync python python/examples/archives.py --source bytes --depth 2
uv run --no-sync python python/examples/archives.py --source file --depth 1

Download demo.yml beside this script when running outside a source checkout.
No real credential or provider is used. Output is redacted JSONL.
"""
import argparse
import io
import json
from pathlib import Path
import tempfile
import zipfile

from kingfisher_sdk import Rules, Scanner, ScanInput, expand_archives


def zip_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["file", "bytes"], default="bytes")
    parser.add_argument("--depth", type=int, choices=range(33), default=2,
                        help="0: raw outer ZIP; 1: nested ZIP bytes; 2: inner file content")
    args = parser.parse_args()

    # Build the same nested fixture for both routes. Only the deepest member
    # contains the synthetic token matched by the bundled demo rule.
    token = b"demo_abcd1234efgh5678"
    inner = zip_bytes([("config.txt", token)])
    outer = zip_bytes([("nested.zip", inner), ("readme.txt", b"ordinary content")])
    rules = Rules([Path(__file__).with_name("demo.yml")], builtins=False)
    scanner = Scanner(rules)

    with tempfile.TemporaryDirectory(prefix="kingfisher-python-example-") as directory:
        if args.source == "file":
            path = Path(directory) / "demo.zip"
            path.write_bytes(outer)
            # from_file() does not read yet. Keep the fixture alive until the
            # input iterator has been consumed; expansion reads it lazily.
            source = ScanInput.from_file(path)
        else:
            # Logical paths let callers supply archives from a Python Git library,
            # storage client, or any other byte producer without writing a file.
            source = ScanInput("demo.zip", outer)

        # Extraction is an explicit transform. scan_file() still scans raw file
        # bytes. Budgets apply to each root across all expanded archive layers;
        # max_entries counts inspected members, including directories or unsafe
        # names that are skipped. Bounds are enforced while decoding, and a root
        # budget failure raises before any of that root's members are yielded.
        # Small ZIPs stay in memory; other formats stage inside temp_dir.
        # Choose a protected temp_dir parent on every platform. SDK staging uses
        # Unix mode 0700; Windows inherits the parent DACL. For real credentials, choose
        # encrypted/memory-backed storage; crashes or cleanup failures may leave
        # temporary plaintext behind.
        members = expand_archives([source], depth=args.depth,
                                  max_bytes=1024 * 1024, max_entries=100, timeout=5,
                                  temp_dir=directory)
        for result in scanner.scan_inputs(members, timeout=5):
            # A group is returned even when no findings match. Depth 1 stops at
            # demo.zip!nested.zip; depth 2 reaches ...!nested.zip!config.txt.
            print(json.dumps({"path": result.input.path,
                              "findings": [f.to_dict() for f in result.findings if f.visible]}))
            # With Python-managed extraction, yield ScanInput(member_path, bytes)
            # yourself and feed those inputs to the same scan_inputs() method.
            # For validation, retain each complete group, including hidden helpers.


if __name__ == "__main__":
    main()
