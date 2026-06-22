#!/usr/bin/env python3
"""
Copies documentation from /docs/ into docs-site/docs/ with transformations:
- Removes breadcrumb links ([<- Back to README](../README.md))
- Rewrites internal links for MkDocs site structure
- Adds SEO frontmatter (title + description)
"""

import os
import re
import shutil

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCS_SRC = os.path.join(REPO_ROOT, "docs")
DOCS_DST = os.path.join(REPO_ROOT, "docs-site", "docs")
VIEWER_SRC_DIR = os.path.join(DOCS_SRC, "viewer")
VIEWER_DST_DIR = os.path.join(DOCS_DST, "viewer")
VIEWER_CLI_BOOTSTRAP = "    loadCliReport();\n"
VIEWER_STATIC_BOOTSTRAP = (
    "    // Static docs-site build: skip the CLI-only /report bootstrap.\n"
)

# Mapping: source filename -> (destination path, title, description)
DOC_MAP = {
    "INSTALLATION.md": (
        "getting-started/installation.md",
        "Installation",
        "Install Kingfisher via Homebrew, PyPI, Docker, install scripts, or compile from source. Includes pre-commit hook setup.",
    ),
    "USAGE.md": (
        "usage/basic-scanning.md",
        "Basic Scanning",
        "Learn how to scan files, Git repos, and platforms for secrets with Kingfisher. Includes output formats, filtering, and validation options.",
    ),
    "INTEGRATIONS.md": (
        "usage/integrations.md",
        "Platform Integrations",
        "Scan GitHub, GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, Docker, S3, Jira, Confluence, Slack, and Teams for leaked secrets.",
    ),
    "ADVANCED.md": (
        "usage/advanced.md",
        "Advanced Configuration",
        "Advanced Kingfisher features: confidence levels, validation tuning, CI pipeline scanning, filtering, suppression, and profiling.",
    ),
    "BASELINE.md": (
        "usage/baseline.md",
        "Baseline Management",
        "Track known secrets with baselines to suppress known findings and detect only new credential leaks.",
    ),
    "DEPLOYMENT.md": (
        "usage/deployment.md",
        "Deployment",
        "Deployment strategies for Kingfisher: self-serve CLI, CI/pre-commit enforcement, centralized scanning, and embedded library.",
    ),
    "CONFIG.md": (
        "usage/configuration.md",
        "Project Configuration (kingfisher.yaml)",
        "Use kingfisher.yaml as project-default policy: confidence, filters, output, alerts, and global flags. Loaded only via --config FILE.",
    ),
    "ACCESS_MAP.md": (
        "features/access-map.md",
        "Access Map (Blast Radius)",
        "Map the blast radius of leaked credentials by authenticating and enumerating accessible resources and permissions.",
    ),
    "REVOCATION_PROVIDERS.md": (
        "features/revocation.md",
        "Secret Revocation",
        "Revoke compromised credentials directly from the CLI using built-in provider-specific revocation flows.",
    ),
    "PARSING.md": (
        "features/parsing.md",
        "Source Code Parsing",
        "Language-aware secret detection using lightweight parser-based context verification across 16 supported source and config languages.",
    ),
    "FINGERPRINT.md": (
        "features/fingerprints.md",
        "Finding Fingerprints",
        "Stable fingerprints for deduplication and tracking of discovered secrets across scans.",
    ),
    "RULES.md": (
        "rules/overview.md",
        "Writing Custom Rules",
        "Write custom YAML-based detection rules with regex patterns, entropy thresholds, validation, revocation, and checksum intelligence.",
    ),
    "ARCHITECTURE.md": (
        "reference/architecture.md",
        "Architecture",
        "High-level architecture of Kingfisher: CLI, scanner pipeline, rule engine, validation, access mapping, and output formats.",
    ),
    "LIBRARY.md": (
        "reference/library.md",
        "Rust Library Crates",
        "Embed Kingfisher's scanning engine in your own Rust applications using kingfisher-core, kingfisher-rules, and kingfisher-scanner crates.",
    ),
    "PYPI.md": (
        "reference/python-bindings.md",
        "Python Bindings",
        "Install and use Kingfisher from Python via PyPI wheels. Build and publish wheels for multiple platforms.",
    ),
    "COMPARISON.md": (
        "reference/comparison.md",
        "Benchmarks & Comparison",
        "Benchmark results comparing Kingfisher performance against TruffleHog, GitLeaks, and detect-secrets across major open source repositories.",
    ),
}

# Link rewriting rules: old link target -> new relative path
# These are approximate; the script handles common patterns
LINK_REWRITES = {
    "INSTALLATION.md": "../getting-started/installation.md",
    "USAGE.md": "../usage/basic-scanning.md",
    "INTEGRATIONS.md": "../usage/integrations.md",
    "ADVANCED.md": "../usage/advanced.md",
    "BASELINE.md": "../usage/baseline.md",
    "DEPLOYMENT.md": "../usage/deployment.md",
    "CONFIG.md": "../usage/configuration.md",
    "ACCESS_MAP.md": "../features/access-map.md",
    "REVOCATION_PROVIDERS.md": "../features/revocation.md",
    "TOKEN_REVOCATION_SUPPORT.md": "../features/revocation.md",
    "MULTI_STEP_REVOCATION.md": "../features/revocation.md",
    "PARSING.md": "../features/parsing.md",
    "TREE_SITTER.md": "../features/parsing.md",
    "FINGERPRINT.md": "../features/fingerprints.md",
    "RULES.md": "../rules/overview.md",
    "ARCHITECTURE.md": "../reference/architecture.md",
    "LIBRARY.md": "../reference/library.md",
    "PYPI.md": "../reference/python-bindings.md",
    "COMPARISON.md": "../reference/comparison.md",
    "ALERTS.md": "https://github.com/mongodb/kingfisher/blob/main/docs/ALERTS.md",
}


def add_frontmatter(content: str, title: str, description: str) -> str:
    """Add YAML frontmatter to the beginning of the content."""
    # Remove existing frontmatter if present
    if content.startswith("---"):
        end = content.find("---", 3)
        if end != -1:
            content = content[end + 3:].lstrip("\n")

    frontmatter = f"""---
title: "{title}"
description: "{description}"
---

"""
    return frontmatter + content


def remove_breadcrumbs(content: str) -> str:
    """Remove [<- Back to README](../README.md) style links."""
    content = re.sub(
        r"\[←?\s*Back to README\]\([^\)]+\)\s*\n?", "", content
    )
    return content


def rewrite_links(content: str) -> str:
    """Rewrite internal documentation links to match site structure."""
    for old, new in LINK_REWRITES.items():
        # Handle various link patterns:
        # [text](FILENAME.md) or [text](./FILENAME.md) or [text](docs/FILENAME.md)
        content = re.sub(
            rf"\((?:\./|docs/)?{re.escape(old)}(#[^\)]+)?\)",
            lambda m: f"({new}{m.group(1) if m.group(1) else ''})",
            content,
        )
    # Rewrite image references from docs/ relative paths (markdown and HTML src=)
    content = content.replace("](./runtime-comparison.png", "](../assets/images/runtime-comparison.png")
    content = content.replace('src="./runtime-comparison.png"', 'src="../assets/images/runtime-comparison.png"')
    content = content.replace("](./assets/icons/", "](../assets/icons/")

    # Rewrite links to files that live at non-standard site locations
    content = content.replace("](../README.md)", "](../getting-started/quick-start.md)")
    content = content.replace("](../CHANGELOG.md)", "](../changelog.md)")
    return content


def fix_table_spacing(content: str) -> str:
    """Ensure a blank line exists before markdown table headers.

    Markdown requires a blank line before a table when preceded by other
    block-level content (like italic text). Without it, the table renders
    as plain text.
    """
    # Match a non-blank line followed immediately by a table header row
    content = re.sub(
        r"(\S[^\n]*)\n(\|[^\n]+\|\s*\n\|[-| :]+\|)",
        r"\1\n\n\2",
        content,
    )
    return content


def process_file(src_path: str, dst_path: str, title: str, description: str):
    """Read, transform, and write a single documentation file."""
    with open(src_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = remove_breadcrumbs(content)
    content = rewrite_links(content)
    content = fix_table_spacing(content)
    content = add_frontmatter(content, title, description)

    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  {os.path.basename(src_path)} -> {os.path.relpath(dst_path, DOCS_DST)}")


def copy_changelog():
    """Copy CHANGELOG.md to docs-site with frontmatter."""
    src = os.path.join(REPO_ROOT, "CHANGELOG.md")
    dst = os.path.join(DOCS_DST, "changelog.md")
    if os.path.exists(src):
        with open(src, "r", encoding="utf-8") as f:
            content = f.read()
        content = add_frontmatter(
            content,
            "Changelog",
            "Kingfisher release history: new features, rules, bug fixes, and improvements.",
        )
        with open(dst, "w", encoding="utf-8") as f:
            f.write(content)
        print("  CHANGELOG.md -> changelog.md")


def transform_viewer_for_docs_site(content: str) -> str:
    """Disable the CLI-only embedded report bootstrap in the hosted viewer."""
    if VIEWER_CLI_BOOTSTRAP not in content:
        raise RuntimeError(
            "Could not find CLI bootstrap marker in report viewer"
        )
    return content.replace(VIEWER_CLI_BOOTSTRAP, VIEWER_STATIC_BOOTSTRAP, 1)


def copy_report_viewer():
    """Publish a static-hosted copy of the report viewer into docs-site/docs."""
    src_index = os.path.join(VIEWER_SRC_DIR, "index.html")
    dst_index = os.path.join(VIEWER_DST_DIR, "index.html")
    if not os.path.exists(src_index):
        print(
            "  WARNING: docs/viewer/index.html not found, "
            "skipping viewer publish"
        )
        return

    os.makedirs(VIEWER_DST_DIR, exist_ok=True)

    with open(src_index, "r", encoding="utf-8") as f:
        content = f.read()
    transformed = transform_viewer_for_docs_site(content)
    with open(dst_index, "w", encoding="utf-8") as f:
        f.write(transformed)
    print("  viewer/index.html -> viewer/index.html")

    sample_src = os.path.join(VIEWER_SRC_DIR, "sample-report.json")
    sample_dst = os.path.join(VIEWER_DST_DIR, "sample-report.json")
    if os.path.exists(sample_src):
        shutil.copy2(sample_src, sample_dst)
        print(
            "  viewer/sample-report.json -> "
            "viewer/sample-report.json"
        )


def main():
    print("Preparing documentation...")
    for src_name, (dst_rel, title, desc) in DOC_MAP.items():
        src_path = os.path.join(DOCS_SRC, src_name)
        dst_path = os.path.join(DOCS_DST, dst_rel)
        if os.path.exists(src_path):
            process_file(src_path, dst_path, title, desc)
        else:
            print(f"  WARNING: {src_name} not found, skipping")

    copy_changelog()
    copy_report_viewer()
    print("Done.")


if __name__ == "__main__":
    main()
