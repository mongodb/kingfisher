#!/usr/bin/env python3
"""Extract the first versioned changelog section, requiring the requested tag."""
import argparse
from pathlib import Path
import re


def release_notes(changelog, tag):
    headings = list(re.finditer(r"^## \[([^\]]+)\].*$", changelog, re.MULTILINE))
    for index, heading in enumerate(headings):
        if heading[1] == "Unreleased":
            continue
        if heading[1] != tag:
            raise ValueError(f"First changelog version is {heading[1]}, expected {tag}")
        end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
        return changelog[heading.start():end].rstrip() + "\n"
    raise ValueError("No versioned changelog section found")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    args = parser.parse_args()
    try:
        print(release_notes(args.changelog.read_text(encoding="utf-8"), args.tag), end="")
    except ValueError as error:
        parser.exit(1, f"{error}\n")


if __name__ == "__main__":
    main()
