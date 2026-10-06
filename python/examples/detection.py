"""Compare legacy detection with opt-in CLI matching/Base64/context policies, offline.

uv run --no-sync python python/examples/detection.py
"""
import base64
import json
from pathlib import Path

from kingfisher_sdk import DetectionPolicy, DetectionScanner, Rules, Scanner, ScanInput


def main():
    # Compile a synthetic-only rule catalog, without provider requests.
    rules = Rules([Path(__file__).with_name("demo.yml")], builtins=False)
    legacy = Scanner(rules)
    # A frozen policy can be reused across a worker pool. Construction applies
    # every setting atomically, before the scanner can be shared between threads.
    policy = DetectionPolicy(ignore_comments=("acme:ignore",))
    contextual = Scanner(rules, policy=policy)
    # DetectionScanner(rules, ignore_comments=["acme:ignore"]) is equivalent.
    sources = [
        ScanInput("config.env", b"demo_abcd1234efgh5678 # kingfisher:ignore"),
        ScanInput("config.html", b"<!-- demo_abcd1234efgh5678 -->"),
        ScanInput("config.html", b'<input password="demo_abcd1234efgh5678">'),
        # A policy decodes two levels; Scanner without one retains its one-level default.
        ScanInput("encoded.env", base64.b64encode(base64.b64encode(b"token=demo_abcd1234efgh5678"))),
    ]
    for source in sources:
        # All inherited methods/controls apply. A logical .html/.css path (or
        # explicit language='html'/'css') selects structural context checking.
        # Filters run before component checks and redaction, so an ignored helper
        # cannot satisfy a required credential component.
        original = legacy.scan_input(source)
        filtered = contextual.scan_input(source)
        print(json.dumps({"path": source.path, "legacy_count": len(original),
                          "context_count": len(filtered),
                          "findings": [finding.to_dict() for finding in filtered if finding.visible]}))
    # CLI matching uses full-match component windows and overlap/containment
    # suppression. It can change findings/offsets compared with legacy Scanner.
    # Default Base64 decoding is limited to two levels on original inputs <= 64 MiB;
    # raw matching still runs above that cap, and nested locations cover the outer encoding.
    # Choose limits explicitly; use None to remove the input cap. Existing Scanner
    # keeps its one-level, uncapped default.
    bounded = DetectionScanner(rules, base64_max_depth=2, base64_max_input_bytes=1024)
    assert len(bounded.scan_input(sources[-1])) == 1
    # Set inline_ignores=False or markup_context=False independently. To retain
    # legacy matching/decoding with context filters, use all three settings below.
    legacy_context = DetectionScanner(rules, cli_match_semantics=False,
                                      base64_max_depth=1, base64_max_input_bytes=None)
    assert legacy_context.scan_input(sources[-1]) == []
    # Both scanners remain offline; validation is a separate step.


if __name__ == "__main__":
    main()
