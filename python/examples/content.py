"""Extract SQLite and .pyc inside an archive, without executing bytecode.

uv run --no-sync python python/examples/content.py
"""
import io
import json
from pathlib import Path
import py_compile
import sqlite3
import tempfile
import zipfile

from kingfisher_sdk import DetectionPolicy, Rules, Scanner, ScanInput, expand_archives, expand_content


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        database = root / "credentials.db"
        # Close before reading/deleting for Windows compatibility. This sample
        # uses a checkpointed database; live WAL-only writes aren't in its bytes.
        connection = sqlite3.connect(database)
        try:
            connection.execute("CREATE TABLE credentials (token TEXT)")
            connection.execute("INSERT INTO credentials VALUES (?)", ("demo_abcd1234efgh5678",))
            connection.commit()
        finally:
            connection.close()
        module = root / "module.py"
        module.write_text('def nested():\n    return "demo_abcd1234efgh5678"\n', encoding="utf-8")
        bytecode = root / "module.pyc"
        # Compilation does not run the source. Kingfisher parses marshal strings
        # and nested code constants; it never imports or executes this module.
        py_compile.compile(str(module), cfile=str(bytecode), doraise=True)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("credentials.db", database.read_bytes())
            archive.writestr("module.pyc", bytecode.read_bytes())
        inputs = [ScanInput("backup.zip", buffer.getvalue())]
        # Choose these stages independently. The same transform accepts file
        # inputs, native Git versions, or bytes from your own Python enumerator.
        # SQLite uses a separate snapshot. Choose a protected temp_dir parent on
        # every platform. SDK staging uses Unix mode 0700; Windows inherits its DACL.
        # Choose encrypted/memory-backed storage for real data; crashes or cleanup
        # failures may leave plaintext. Bytecode and small ZIPs parse in memory.
        # Budgets bound generated output during native work, and timeout checks
        # run during SQLite VM execution and bytecode parsing. Limits and
        # cancellation always raise, regardless of the malformed-input policy.
        sources = expand_content(
            expand_archives(inputs, max_bytes=1024 * 1024, max_entries=100,
                            timeout=5, temp_dir=directory),
            strict=True, max_bytes=1024 * 1024, timeout=5, temp_dir=directory,
        )
        scanner = Scanner(Rules([Path(__file__).with_name("demo.yml")], builtins=False),
                          policy=DetectionPolicy())
        for result in scanner.scan_inputs(sources, timeout=5):
            # Paths/offsets identify extracted SQL or string content; GitInput
            # origins would still identify the original repository blob.
            # Keep the full group, including invisible helpers, for validation.
            print(json.dumps({"path": result.input.path,
                              "findings": [f.to_dict() for f in result.findings if f.visible]}))

        # Applications choosing best-effort malformed-input fallback can inspect
        # a safe category rather than silently mistaking raw binary scanning for
        # successful extraction. The original bytes/provenance remain attached.
        fallback, = expand_content([ScanInput("broken.pyc", b"bad header")])
        print(json.dumps({"path": fallback.path,
                          "extraction_error": fallback.extraction_error}))


if __name__ == "__main__":
    main()
