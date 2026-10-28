"""Extract PDF pages and scan offline, keeping output free of plaintext secrets.

uv run --no-sync python python/examples/pdf.py document.pdf
"""
import argparse
import json

from kingfisher_sdk import ScanInput, Scanner, expand_archives, expand_content


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", help="PDFs or archives containing PDFs")
    args = parser.parse_args()

    # Transforms are explicit and independent. The same composition accepts
    # git_inputs(...), retaining original Git provenance and source metadata.
    # PDFs have no OCR/password support; findings identify extracted page text.
    sources = expand_content(
        expand_archives((ScanInput.from_file(path) for path in args.paths),
                        max_bytes=64 * 1024 * 1024, max_entries=1000, timeout=10),
        pdf=True, sqlite=False, pyc=False, strict=True,
        max_bytes=64 * 1024 * 1024, timeout=10,
    )
    # Budgets are per input; failures/cancellation never yield partial page sets.
    # Decoded streams are capped at 32 MiB and PDFs at 10,000 pages. Neither
    # these caps nor cooperative deadlines are process-memory/hard time limits.
    # strict=True rejects malformed/encrypted PDFs rather than scanning raw bytes.
    for result in Scanner(redact=True).scan_inputs(sources, timeout=10):
        print(json.dumps({"path": result.input.path,
                          "findings": [f.to_dict() for f in result.findings if f.visible]}))


if __name__ == "__main__":
    main()
