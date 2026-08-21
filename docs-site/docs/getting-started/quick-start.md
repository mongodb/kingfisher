---
title: "Quick Start"
description: "Get up and running with Kingfisher in under a minute. Scan files, Git repos, and cloud platforms for leaked secrets."
---

# Quick Start

Get scanning in under a minute.

## 1. Install Kingfisher

=== "Homebrew"

    ```bash
    brew install kingfisher
    ```

=== "PyPI"

    ```bash
    uv tool install kingfisher-bin
    ```

=== "Docker"

    ```bash
    docker run --rm -v "$PWD":/src ghcr.io/mongodb/kingfisher:latest scan /src
    ```

=== "Script (Linux/macOS)"

    ```bash
    curl -sSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash
    ```

=== "PowerShell (Windows)"

    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.ps1' -OutFile install-kingfisher.ps1
    ./install-kingfisher.ps1
    ```

For all installation options, see the [Installation Guide](installation.md).

## 2. Scan a Directory

```bash
kingfisher scan /path/to/code
```

Kingfisher automatically detects whether the path is a Git repo or plain directory.

## 3. View Results in Your Browser

```bash
kingfisher scan /path/to/code --view-report
```

You can also open existing Kingfisher, Gitleaks, or TruffleHog JSON reports with `kingfisher view <report.json>`.

If you want a shareable upload-based version, the docs site also hosts the [report viewer](../features/report-viewer.md).

## 4. Show Only Live Secrets

Filter to only secrets confirmed active by provider APIs:

```bash
kingfisher scan /path/to/code --only-valid
```

To include live credentials plus high-signal findings such as private keys that require manual
review, use:

```bash
kingfisher scan /path/to/code --validation-filter actionable
```

## 5. Map the Blast Radius (aka Access Map)

See exactly what resources a leaked credential can access:

```bash
kingfisher scan /path/to/code --access-map --view-report
```

## 6. Revoke a Compromised Secret

Kingfisher joins selected Betterleaks detectors to safe revocation actions in a build-validated
capability overlay:

```bash
kingfisher revoke --rule github-pat "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Kingfisher 1.x custom YAML rules may also define `revocation:`.

## 7. Scan a GitHub Organization

```bash
KF_GITHUB_TOKEN="ghp_..." kingfisher scan github --organization my-org
```

## 8. Output JSON for CI/CD

```bash
kingfisher scan /path/to/code --format json --output findings.json
```

## What's Next?

- [Basic Scanning](../usage/basic-scanning.md) — full scanning guide with all options
- [Platform Integrations](../usage/integrations.md) — GitHub, GitLab, S3, Docker, Slack, and more
- [Kingfisher 1.x Custom Rules](../rules/overview.md) — create private, organization-specific detections
- [Blast Radius (aka Access Map)](../features/access-map.md) — blast radius mapping for 43 providers
- [Report Viewer & Triager](../features/report-viewer.md) — local and hosted viewer for Kingfisher, Gitleaks, and TruffleHog JSON reports
