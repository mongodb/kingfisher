"""Seed on one host, then check the transferred cache on another host.

Run with an installed SDK: python cache_portability.py seed|check DIRECTORY.
--require-hit additionally asserts reuse without recompilation on compatible hosts.
The wheel CI exchanges these fixtures across all supported OS/architecture pairs.
"""
import argparse
import os
from pathlib import Path

from kingfisher_sdk import Rules, Scanner


def snapshot(directory):
    return {p.name: p.stat().st_mtime_ns for p in directory.glob("*.vscdb")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["seed", "check"])
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-hit", action="store_true")
    args = parser.parse_args()
    demo = Path(__file__).resolve().parents[1] / "examples" / "demo.yml"
    for name in ("demo", "builtins"):
        cache = args.directory / name
        if args.mode == "check":
            assert snapshot(cache), f"missing source fixture: {cache}"
            for entry in cache.glob("*.vscdb"):
                os.utime(entry, (1_000_000, 1_000_000))
        before = snapshot(cache)

        def load():
            if name == "demo":
                return Rules([demo], builtins=False, cache_dir=cache)
            return Rules(confidence="medium", cache_dir=cache)

        rules = load()
        assert rules.cache_status in ("stored", "loaded"), (
            name, "cache persistence/reuse was bypassed", rules.cache_status,
        )
        token = "demo_abcd1234efgh5678" if name == "demo" else 'pscale ID "abcdefghijkl"'
        findings = [(f.rule_id, f.secret) for f in Scanner(rules).scan(token)]
        expected = ("acme.python-demo", token) if name == "demo" else (
            "betterleaks.planetscale-id", "abcdefghijkl",
        )
        assert expected in findings, (name, findings)
        after = snapshot(cache)
        assert after, f"cache not written: {cache}"
        if args.mode == "check":
            hit = rules.cache_status == "loaded"
            if hit:
                assert before == after, f"cache hit rewrote the source fixture: {cache}"
            if args.require_hit:
                assert hit, f"compatible fixture was recompiled: {cache}"
            # A foreign incompatible database must compile into a locally reusable
            # entry, with equivalent findings and metadata on the next construction.
            for entry in cache.glob("*.vscdb"):
                os.utime(entry, (1_000_000, 1_000_000))
            before_reload = snapshot(cache)
            reloaded = load()
            assert reloaded.cache_status == "loaded", f"local cache bypassed: {cache}"
            assert reloaded.metadata() == rules.metadata()
            assert [(f.rule_id, f.secret) for f in Scanner(reloaded).scan(token)] == findings
            assert snapshot(cache) == before_reload, f"local cache not reused: {cache}"
            print(f"{cache}: {'hit' if hit else 'recompiled'}, reload hit", flush=True)
        else:
            print(f"{cache}: seeded {len(rules)} rules", flush=True)


if __name__ == "__main__":
    main()
