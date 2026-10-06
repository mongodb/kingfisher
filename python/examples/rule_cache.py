"""Prewarm the SDK cache at image build time, or load it at service startup.

Checkout: uv run --no-sync python python/examples/rule_cache.py --cache-dir rule-cache
Opt out:  uv run --no-sync python python/examples/rule_cache.py --no-cache
Verify:   uv run --no-sync python python/examples/rule_cache.py --cache-dir rule-cache --require-hit
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md#reuse-the-compiled-rule-cache
"""
import argparse
from pathlib import Path

from kingfisher_sdk import Rules, Scanner


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--require-hit", action="store_true",
                        help="Fail unless this host reuses an existing compatible entry")
    args = parser.parse_args()
    # An explicit path overrides KF_RULE_CACHE_DIR; otherwise the env variable
    # or OS cache directory is used. --no-cache skips all disk cache access.
    # Keep this confidence and catalog selection identical at build and startup.
    # Prewarm as the runtime account, or transfer files with COPY --chown in
    # rule_cache.Dockerfile. Ownership is checked locally, not encoded in the DB.
    rules = Rules(confidence="medium", cache=not args.no_cache, cache_dir=args.cache_dir)
    # Observe persistence explicitly in image-build/service-startup diagnostics.
    print("cache_status:", rules.cache_status)
    if args.require_hit and rules.cache_status != "loaded":
        parser.error(f"expected a cache hit, got {rules.cache_status!r}")
    scanner = Scanner(rules)
    # Reuse this scanner for the lifetime of a service process. Loading a cache
    # performs no provider requests. Rejected native databases recompile locally;
    # unavailable/read-only cache directories do not prevent detection.
    print(f"Loaded {len(rules)} rules")
    for finding in scanner.scan("ordinary application configuration"):
        if finding.visible:
            print(finding.to_dict())  # Redacted by default.


if __name__ == "__main__":
    main()
