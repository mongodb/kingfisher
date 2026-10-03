"""List the SDK catalog or inspect one exact rule's definition, without requests.

Checkout: uv run --no-sync python python/examples/rules.py --with-revocation
Detail:   uv run --no-sync python python/examples/rules.py betterleaks.aws-access-token
Custom:   uv run --no-sync python python/examples/rules.py acme.python-demo --rules-path python/examples/demo.yml --no-builtins
Published: uv run --no-project --with kingfisher-secret-scanner python rules.py
Guide: https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md
"""
import argparse
from fnmatch import fnmatchcase
import json

from kingfisher_sdk import Rules


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rule_id", nargs="?", help="Exact ID to inspect; omit to list the catalog")
    parser.add_argument("--rules-path", action="append", default=[], help="Custom YAML/TOML path; repeatable")
    parser.add_argument("--no-builtins", action="store_true")
    parser.add_argument("--confidence", choices=["low", "medium", "high"], default="low",
                        help="Minimum confidence loaded; low includes the full catalog")
    parser.add_argument("--id-glob", default="*", help="Catalog ID filter, e.g. 'betterleaks.aws*'")
    parser.add_argument("--with-validation", action="store_true", help="List only rules with validation configured")
    parser.add_argument("--with-revocation", action="store_true", help="List only rules with revocation configured")
    parser.add_argument("--field", action="append", choices=[
        "pattern", "detection_regex", "validation", "revocation", "depends_on_rule",
        "betterleaks_filter", "pattern_requirements", "examples", "references",
    ], help="Detail fields to show; repeatable, defaults to the full definition")
    args = parser.parse_args()
    if args.field and not args.rule_id:
        parser.error("--field requires an exact rule_id")
    if args.rule_id and (args.id_glob != "*" or args.with_validation or args.with_revocation):
        parser.error("catalog filters apply when rule_id is omitted")
    rules = Rules(args.rules_path, builtins=not args.no_builtins, confidence=args.confidence)

    if args.rule_id is None:
        # metadata() is a compact inventory: exact ID, name, visibility and
        # validation/revocation support. Combine predicates with AND here.
        for summary in rules.metadata():
            if not fnmatchcase(summary["id"], args.id_glob):
                continue
            if args.with_validation and not summary["validation"]:
                continue
            if args.with_revocation and not summary["revocation"]:
                continue
            print(json.dumps(summary))
        return

    try:
        detail = rules.detail(args.rule_id)
    except ValueError as exc:
        parser.error(str(exc))
    # pattern is the stored rule pattern, including any rule comments.
    # detection_regex is the already-compiled Rust confirmation regex after
    # comment stripping. It does not include the internal endpoint wrapper.
    # Both candidates and their selected captures still pass entropy, path,
    # pattern requirements, filters and dependency checks before reporting.
    # validation/revocation contain configured type and content (or None).
    # Http/Grpc show requests and matchers; Betterleaks shows a portable AST.
    # Typed/raw handlers show their dispatch type/name, not Rust source code.
    # Inspecting these configurations never validates or revokes anything.
    if args.field:
        detail = {"id": detail["id"], **{key: detail[key] for key in args.field}}
    print(json.dumps(detail, indent=2))


if __name__ == "__main__":
    main()
