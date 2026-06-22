#!/usr/bin/env python3
"""
Reads all YAML rule definition files from crates/kingfisher-rules/data/rules/
and generates a searchable markdown page listing all built-in rules.
"""

from html import escape
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = REPO_ROOT / "crates" / "kingfisher-rules" / "data" / "rules"
OUTPUT = REPO_ROOT / "docs-site" / "docs" / "rules" / "builtin-rules.md"


def load_rules():
    """Load all rules from YAML files.

    Uses yaml.safe_load_all to handle multi-document YAML files, and looks
    for rules under a 'rules' key in each document — matching the canonical
    counting logic in data/default/rule_cleanup/count_rules.py.
    """
    all_rules = []

    for yml_file in sorted(RULES_DIR.glob("*.yml")):
        provider = yml_file.stem.replace("_", " ").replace("-", " ").title()
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                documents = list(yaml.safe_load_all(f))
        except Exception as e:
            print(f"  WARNING: Failed to parse {yml_file.name}: {e}")
            continue

        for document in documents:
            if not isinstance(document, dict):
                continue

            rules = document.get("rules", [])
            if not isinstance(rules, list):
                continue

            for rule in rules:
                if not isinstance(rule, dict):
                    continue

                name = rule.get("name", "Unknown")
                rule_id = rule.get("id", "")
                confidence = rule.get("confidence") or "medium"
                has_validation = "validation" in rule
                has_revocation = "revocation" in rule
                is_dependent = bool(rule.get("depends_on_rule"))

                all_rules.append({
                    "provider": provider,
                    "name": name,
                    "id": rule_id,
                    "confidence": confidence,
                    "validates": has_validation,
                    "revokes": has_revocation,
                    "dependent": is_dependent,
                })

    return all_rules


def generate_markdown(rules):
    """Generate the markdown page content."""
    total = len(rules)
    detectors = sum(1 for r in rules if not r["dependent"])
    dependent = total - detectors
    validated = sum(1 for r in rules if r["validates"] and not r["dependent"])
    revocable = sum(1 for r in rules if r["revokes"] and not r["dependent"])
    providers = len(set(r["provider"] for r in rules))

    lines = [
        '---',
        'title: "Built-in Rules List"',
        f'description: "Complete list of all {total} built-in secret detection rules in Kingfisher. Searchable and filterable by provider, confidence level, and validation support."',
        '---',
        '',
        '# Built-in Rules',
        '',
        f'Kingfisher ships with **{total} detection rules** across **{providers} providers**',
        f'({detectors} detectors + {dependent} dependent rules).',
        f'Of these, **{validated}** include live validation and **{revocable}** support direct revocation.',
        '',
        '!!! tip "Search"',
        '    Use the search box below to filter rules by provider name, rule ID, or confidence level.',
        '',
        '<input type="text" class="rules-search" placeholder="Search rules... (e.g. github, aws, anthropic)" />',
        '<div class="rules-count"></div>',
        '',
        '<table class="rules-table">',
        '<thead>',
        '<tr>',
        '<th>Provider</th>',
        '<th>Rule Name</th>',
        '<th>Rule ID</th>',
        '<th>Confidence</th>',
        '<th>Validates</th>',
        '<th>Revokes</th>',
        '</tr>',
        '</thead>',
        '<tbody>',
    ]

    for rule in sorted(rules, key=lambda r: (r["provider"].lower(), r["id"])):
        validates = "Yes" if rule["validates"] else ""
        revokes = "Yes" if rule["revokes"] else ""
        confidence = escape(rule["confidence"].capitalize())
        provider = escape(rule["provider"])
        name = escape(rule["name"])
        rule_id = escape(rule["id"])
        lines.append('<tr>')
        lines.append(f'<td>{provider}</td>')
        lines.append(f'<td>{name}</td>')
        lines.append(f'<td><code>{rule_id}</code></td>')
        lines.append(f'<td>{confidence}</td>')
        lines.append(f'<td>{validates}</td>')
        lines.append(f'<td>{revokes}</td>')
        lines.append('</tr>')

    lines.extend([
        '</tbody>',
        '</table>',
    ])

    return "\n".join(lines) + "\n"


def main():
    print("Generating built-in rules page...")
    rules = load_rules()
    print(f"  Found {len(rules)} rules")

    content = generate_markdown(rules)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  Written to {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
