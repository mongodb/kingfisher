#!/usr/bin/env python3
"""Issue #537: benchmark dense built-in matches after compiling Rules once.

Run with the Python environment containing the SDK under test. Scans use all
built-ins, default Base64 handling, and no live validation. Timings exclude rule
compilation and input generation. Each row reports the median of three scans.
"""
import argparse
import base64
import random
import re
import statistics
import string
import subprocess
import tempfile
import time
from pathlib import Path


def fixtures():
    rng = random.Random(3)
    for size in (25_000, 50_000, 100_000, 200_000):
        parts, length = [], 0
        while length < size:
            junk = ["".join(rng.choices(string.printable, k=rng.randrange(16))) for _ in range(2)]
            token = "".join(rng.choices(string.ascii_lowercase + string.digits, k=12))
            part = f"pscale{junk[0]}ID{junk[1]}{token}\n"
            parts.append(part)
            length += len(part)
        yield "issue-537", size, "".join(parts)
    for name, line in (
        ("planetscale", "pscale ID ab12cd34ef56\n"),
        ("jfrog", "acme-team.jfrog.io\n"),
        ("clickhouse", "clickhouse ID ab12cd34ef56gh78ij90\n"),
        ("cloudinary", "cloudinary CLOUD NAME ab12cd34ef56\n"),
        ("salesforce", "acme-team.my.salesforce.com\n"),
        ("tableau", "acme-team.online.tableau.com\n"),
        ("visible-catalog", "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\n"),
        ("single-line-visible", "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 "),
        ("single-line-filter", "cloudflare = 'q8W2e9R4t7Y1u6I3o5P0a8S2d9F4g7H1j6K3l5Z0' "),
        ("components", "pscale ID ab12cd34ef56\npscale_tkn_ab12cd34ef56gh78ij90kl12mn34op56qr\n"),
    ):
        for size in (25_000, 50_000, 100_000, 200_000):
            yield name, size, line * ((size + len(line) - 1) // len(line))
    for size in (25_000, 50_000, 100_000, 200_000):
        # Different decoded values must survive deduplication despite sharing
        # one encoded span. CLI-compatible scans also run URI suppression.
        parts, length = [], 0
        while length < size * 3 // 4:
            password = "".join(rng.choices(string.ascii_letters + string.digits, k=24))
            part = f"mysql://user:{password}@db.invalid/test "
            parts.append(part)
            length += len(part)
        yield "base64-uris", size, base64.b64encode("".join(parts).encode()).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--case", action="append", help="run only selected cases")
    parser.add_argument("--cli", type=Path, help="benchmark a CLI binary (includes startup and reporting)")
    parser.add_argument("--detection", action="store_true", help="use SDK CLI-compatible detection policies")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    with tempfile.TemporaryDirectory(prefix="kingfisher-dense-") as temp_dir:
        input_path = Path(temp_dir) / "dense.txt"
        if args.cli:
            cli = args.cli.resolve()
            print(subprocess.check_output([str(cli), "--version"], text=True).strip(), flush=True)
            def scan(content):
                input_path.write_bytes(content.encode("utf-8"))
                result = subprocess.run([
                    str(cli), "scan", str(input_path), "--no-update-check", "--no-validate",
                    "--format", "toon", "--quiet", "--no-dedup", "--include-hidden-findings",
                ], capture_output=True, text=True)
                # Visible findings use the CLI's default exit status 200.
                if result.returncode not in (0, 200):
                    result.check_returncode()
                count = re.search(r"^    findings: (\d+)$", result.stdout, re.MULTILINE)
                if count is None:
                    raise RuntimeError("CLI TOON output is missing the findings count")
                return int(count.group(1))
        else:
            import kingfisher_sdk
            scanner_type = kingfisher_sdk.DetectionScanner if args.detection else kingfisher_sdk.Scanner
            scanner = scanner_type(kingfisher_sdk.Rules())
            print(f"SDK {kingfisher_sdk.__version__}", flush=True)
            def scan(content):
                return len(scanner.scan(content))
        print("case,bytes,findings,median_seconds", flush=True)
        for name, _, content in fixtures():
            if args.case and name not in args.case:
                continue
            elapsed = []
            count = None
            for _ in range(args.repeats):
                start = time.perf_counter()
                found = scan(content)
                elapsed.append(time.perf_counter() - start)
                if count is not None:
                    assert count == found
                count = found
            print(f"{name},{len(content)},{count},{statistics.median(elapsed):.6f}", flush=True)


if __name__ == "__main__":
    main()
