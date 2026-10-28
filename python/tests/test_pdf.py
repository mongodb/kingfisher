"""PDF extraction is explicit, offline, bounded, and preserves source metadata."""
from pathlib import Path
import json
import re
import subprocess
import sys

import pytest

from kingfisher_sdk import (
    CancellationToken, GitInput, Rules, Scanner, ScanInput, expand_archives, expand_content,
)
from test_inputs import RULE_PATH, TOKEN, zip_bytes


def _pdf_from_objects(objects):
    data = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(data))
        data.extend(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = len(data)
    data.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets:
        data.extend(f"{offset:010} 00000 n \n".encode())
    data.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
                f"startxref\n{xref}\n%%EOF\n".encode())
    return bytes(data)


@pytest.fixture
def pdf_bytes():
    fixture = Path(__file__).resolve().parents[2] / (
        "crates/kingfisher-scanner/src/extraction/testdata/pages.pdf.hex"
    )
    return bytes.fromhex(fixture.read_text(encoding="ascii"))


def test_pdf_opt_in_extracts_pages_from_bytes_and_files(pdf_bytes, tmp_path):
    path = tmp_path / "document.PDF"
    path.write_bytes(pdf_bytes)
    scanner = Scanner(Rules([RULE_PATH], builtins=False))
    for source in (ScanInput.from_file(path), ScanInput("extensionless", pdf_bytes)):
        assert list(expand_content([source])) == [source]  # Existing defaults are unchanged.
        pages = list(expand_content([source], pdf=True, strict=True))
        assert [page.path for page in pages] == [
            f"{source.path}!page-1.txt", f"{source.path}!page-2.txt",
        ]
        assert TOKEN in pages[0].data
        assert b"demo_1234abcd5678efgh" in pages[1].data
        for page in pages:
            finding, = scanner.scan_input(page)
            start, end = finding.location["start_offset"], finding.location["end_offset"]
            assert page.data[start:end] == finding.secret.encode()
    assert path.read_bytes() == pdf_bytes


def test_pdf_archive_members_and_git_provenance(pdf_bytes):
    source = GitInput("backup.zip", zip_bytes([("document.pdf", pdf_bytes)]),
                      repository="repository", commit="a" * 40, blob_id="b" * 40)
    pages = list(expand_content(expand_archives([source]), pdf=True))
    assert len(pages) == 2
    assert pages[0].path == "backup.zip!document.pdf!page-1.txt"
    assert all(isinstance(page, GitInput) and page.commit == source.commit
               and page.repository == source.repository and page.blob_id == source.blob_id
               for page in pages)


def test_pdf_malformed_fallback_does_not_leak_parser_messages():
    source = ScanInput("broken.pdf", b"%PDF-1.4\nprivate-content")
    fallback, = expand_content([source], pdf=True)
    assert fallback.data is source.data and fallback.path == source.path
    assert fallback.extraction_error == "malformed_pdf"
    with pytest.raises(RuntimeError) as error:
        list(expand_content([source], pdf=True, strict=True))
    assert "private-content" not in str(error.value)


def test_pdf_corrupt_streams_preserve_other_pages_unless_strict(pdf_bytes, tmp_path):
    objects = re.findall(rb"\d+ 0 obj\n(.*?)\nendobj", pdf_bytes, re.DOTALL)
    # Use a codec that reports corruption instead of silently recovering it.
    # Page 2's encoded/split token must remain detectable.
    body = b"not a brotli stream"
    objects[3] = (f"<< /Length {len(body)} /Filter /BrotliDecode >>\nstream\n".encode()
                  + body + b"\nendstream")
    damaged = _pdf_from_objects(objects)
    path = tmp_path / "damaged.pdf"
    path.write_bytes(damaged)
    for source in (ScanInput("damaged.pdf", damaged), ScanInput.from_file(path)):
        page, = expand_content([source], pdf=True)
        assert page.path == f"{source.path}!page-2.txt"
        assert b"demo_1234abcd5678efgh" in page.data
        scanner = Scanner(Rules([RULE_PATH], builtins=False))
        finding, = scanner.scan_input(page)
        assert finding.secret == "demo_1234abcd5678efgh"
        with pytest.raises(RuntimeError, match="invalid or unsupported PDF") as error:
            list(expand_content([source], pdf=True, strict=True))
        assert "demo_" not in str(error.value)
    assert path.read_bytes() == damaged


def test_pdf_budgets_and_controls_never_fall_back(pdf_bytes, tmp_path):
    path = tmp_path / "document.pdf"
    path.write_bytes(pdf_bytes)
    for source in (ScanInput.from_file(path), ScanInput("document.pdf", pdf_bytes)):
        with pytest.raises(RuntimeError, match="max_bytes"):
            list(expand_content([source], pdf=True, max_bytes=16))
        token = CancellationToken()
        token.cancel()
        with pytest.raises(RuntimeError, match="cancelled"):
            list(expand_content([source], pdf=True, cancellation=token))


def test_pdf_empty_pages_pass_through_unchanged(pdf_bytes):
    empty = re.sub(rb"stream\n(.*?)\nendstream",
                   lambda match: b"stream\n" + b" " * len(match[1]) + b"\nendstream",
                   pdf_bytes, flags=re.DOTALL)
    source = ScanInput("empty.pdf", empty)
    unchanged, = expand_content([source], pdf=True, strict=True)
    assert unchanged is source


def test_pdf_example_is_runnable_and_keeps_output_redacted(pdf_bytes, tmp_path):
    path = tmp_path / "example.pdf"
    path.write_bytes(pdf_bytes)
    example = RULE_PATH.with_name("pdf.py")
    output = subprocess.run([sys.executable, str(example), str(path)],
                            capture_output=True, text=True, check=True).stdout
    rows = [json.loads(line) for line in output.splitlines()]
    assert len(rows) == 2 and rows[0]["path"].endswith("!page-1.txt")
    assert TOKEN.decode() not in output


def test_pdf_page_budget_raises_even_without_strict_mode(pdf_bytes):
    objects = re.findall(rb"\d+ 0 obj\n(.*?)\nendobj", pdf_bytes, re.DOTALL)
    # Repeated references are legal to parse, but cannot bypass the work cap.
    objects[1] = re.sub(rb"/Kids \[[^]]*\]", b"/Kids [" + b"3 0 R " * 10_001 + b"]",
                        objects[1]).replace(b"/Count 2", b"/Count 10001")
    # lopdf also caps traversal by the number of loaded objects.
    objects.extend([b"null"] * 10_001)
    with pytest.raises(RuntimeError, match="page limit"):
        list(expand_content([ScanInput("many-pages.pdf", _pdf_from_objects(objects))], pdf=True))
