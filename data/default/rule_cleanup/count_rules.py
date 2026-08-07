#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["PyYAML>=6.0"]
# ///

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError as exc:
    raise SystemExit(
        "PyYAML isn't installed.\n"
        "Run the script with `uv run …` or add PyYAML to the dependency list."
    ) from exc


DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "crates/kingfisher-rules/data/rules"
)
NON_LIVE_VALIDATION_TYPES = {"Assumed", "Ethereum"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count total rules and standalone detector rules. "
            "Standalone detector rules are rules that do not "
            "declare depends_on_rule."
        )
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help="Directory containing rule YAML files (default: %(default)s)",
    )
    parser.add_argument(
        "--list-validators",
        action="store_true",
        help=(
            "Print the IDs of standalone detectors with and "
            "without a live validator"
        ),
    )
    return parser.parse_args()


def iter_rule_files(rules_dir: Path) -> list[Path]:
    return sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])


def iter_rule_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for document in yaml.safe_load_all(handle):
            if not isinstance(document, dict):
                continue
            rules = document.get("rules", [])
            if isinstance(rules, list):
                entries.extend(
                    rule for rule in rules if isinstance(rule, dict)
                )
    return entries


def rule_identifier(rule: dict, path: Path, index: int) -> str:
    if isinstance(rule.get("id"), str) and rule["id"].strip():
        return rule["id"]
    if isinstance(rule.get("name"), str) and rule["name"].strip():
        return rule["name"]
    return f"{path.stem}#{index}"


def main() -> int:
    args = parse_args()
    rules_dir = args.rules_dir.resolve()

    if not rules_dir.exists():
        print(f"error: directory does not exist: {rules_dir}", file=sys.stderr)
        return 2

    rule_files = iter_rule_files(rules_dir)
    if not rule_files:
        print(f"No YAML rule files found in {rules_dir}")
        return 1

    total_rules = 0
    dependent_rules = 0
    standalone_with_validator: list[str] = []
    standalone_without_validator: list[str] = []

    for path in rule_files:
        try:
            rules = iter_rule_entries(path)
        except yaml.YAMLError as exc:
            print(f"error: failed to parse {path}: {exc}", file=sys.stderr)
            return 1

        total_rules += len(rules)
        dependent_rules += sum(
            1 for rule in rules if rule.get("depends_on_rule")
        )
        for index, rule in enumerate(rules, start=1):
            if rule.get("depends_on_rule"):
                continue

            identifier = rule_identifier(rule, path, index)
            validation = rule.get("validation")
            is_non_live = (
                isinstance(validation, dict)
                and validation.get("type") in NON_LIVE_VALIDATION_TYPES
            )
            if validation and not is_non_live:
                standalone_with_validator.append(identifier)
            else:
                standalone_without_validator.append(identifier)

    standalone_detector_rules = total_rules - dependent_rules

    print(f"Rules directory: {rules_dir}")
    print(f"Total rules: {total_rules}")
    print(f"Dependent rules: {dependent_rules}")
    print(f"Standalone detectors: {standalone_detector_rules}")
    print(
        "Standalone detectors with live validator: "
        f"{len(standalone_with_validator)}"
    )
    print(
        "Standalone detectors without live validator: "
        f"{len(standalone_without_validator)}"
    )

    if args.list_validators:
        print(
            "\nStandalone detectors with live validator "
            f"({len(standalone_with_validator)}):"
        )
        for name in standalone_with_validator:
            print(f"  {name}")
        print(
            "\nStandalone detectors without live validator "
            f"({len(standalone_without_validator)}):"
        )
        for name in standalone_without_validator:
            print(f"  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
