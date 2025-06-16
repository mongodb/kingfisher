#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["PyYAML>=6.0", "idna>=3.7"]
# ///

import os
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

import idna

try:
    import yaml
except ModuleNotFoundError as exc:
        raise SystemExit(
            "PyYAML isn’t installed.\n"
            "Run the script with `uv run …` or add PyYAML to the dependency list."
        ) from exc


RULES_DIR     = Path(os.path.expanduser("../../data/rules"))
URL_KEY_RE    = re.compile(r"url$", re.IGNORECASE)          # keys literally named “url”
TEMPLATE_RE   = re.compile(r"\{\{.*?\}\}")                  # strip Liquid placeholders
DOMAIN_RE     = re.compile(r"^(?:[a-z][a-z0-9+\-.]*://)?([^/]+)", re.I)


def find_yaml_files(root: Path):
    yield from root.rglob("*.yml")
    yield from root.rglob("*.yaml")


def extract_domains(obj):
    """Recursively yield every domain appearing in any 'url' key."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if URL_KEY_RE.fullmatch(str(k)) and isinstance(v, str):
                cleaned = TEMPLATE_RE.sub("", v).strip()
                parsed  = urlparse(cleaned).netloc
                if not parsed:
                    m = DOMAIN_RE.match(cleaned)
                    if not m:                     # value wasn’t a URL/host – ignore
                        continue
                    parsed = m.group(1)

                domain = (
                    parsed.split("@")[-1]         # drop any creds
                          .split(":")[0]          # drop port
                          .lstrip(".")
                          .rstrip(".")
                          .lower()
                )
                if domain and "{{" not in domain: # ignore Liquid tokens
                    yield domain
            else:
                yield from extract_domains(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from extract_domains(item)


def domain_active(domain: str) -> bool:
    """Return True iff *domain* resolves via DNS."""
    if not domain:
        return False
    try:
        ascii_domain = idna.encode(domain).decode()  # puny-encode if needed
        socket.gethostbyname(ascii_domain)
        return True
    except (socket.gaierror, UnicodeError, idna.IDNAError):
        return False


def main():
    # list of (yaml_path, [dead_domain, …])
    inactive_files: list[tuple[Path, list[str]]] = []

    for yml_path in find_yaml_files(RULES_DIR):
        try:
            docs = yaml.safe_load_all(yml_path.read_text())
        except yaml.YAMLError as e:
            print(f"⚠️  Skipping {yml_path} (YAML error: {e})")
            continue

        domains: set[str] = set()
        for doc in docs:
            if doc is not None:
                domains.update(extract_domains(doc))

        if not domains:
            continue

        dead = sorted({d for d in domains if not domain_active(d)})
        if dead:
            inactive_files.append((yml_path, dead))

    if inactive_files:
        print("YAML files with at least one non-resolving domain:")
        for path, dead in inactive_files:
            print(f" - {path}: {', '.join(dead)}")
    else:
        print("✅ All domains resolve.")


if __name__ == "__main__":
    main()
