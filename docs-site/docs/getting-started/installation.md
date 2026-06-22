---
title: "Installation"
description: "Install Kingfisher via Homebrew, PyPI, Docker, install scripts, or compile from source. Includes pre-commit hook setup."
---

# Installation Guide

This guide covers all installation methods for Kingfisher, including pre-commit hook setup.

## Table of Contents

- [Pre-built Releases](#pre-built-releases)
- [Homebrew](#homebrew)
- [Linux and macOS](#linux-and-macos)
- [Windows](#windows)
- [Pre-commit Hooks](#pre-commit-hooks)
  - [macOS and Linux](#macos-and-linux)
  - [Windows PowerShell](#windows-powershell)
  - [Using the pre-commit Framework](#using-the-pre-commit-framework)
  - [Using Husky (Node.js projects)](#using-husky-nodejs-projects)
- [Compile from Source](#compile-from-source)
- [PyPI Wheels](#pypi-wheels)
- [Run Kingfisher in Docker](#run-kingfisher-in-docker)

## Pre-built Releases

Pre-built binaries are available from the [Releases](https://github.com/mongodb/kingfisher/releases) section.

## Homebrew

![Homebrew Formula Version](https://img.shields.io/homebrew/v/kingfisher)

```bash
brew install kingfisher
```

## Linux and macOS

Use the bundled installer script to fetch the latest release and place it in
`~/.local/bin` (or a directory of your choice):

```bash
# Linux, macOS
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | \
  bash
```

To install into a custom location, pass the desired directory as an argument:

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | \
  bash -s -- /opt/kingfisher
```

To install a specific tag:

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | \
  bash -s -- --tag v1.71.0
```

## Windows

Download and run the PowerShell installer to place the binary in
`$env:USERPROFILE\bin` (or another directory you specify):

```powershell
# Windows
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.ps1' -OutFile install-kingfisher.ps1
./install-kingfisher.ps1
```

The installer auto-detects your Windows architecture and downloads the matching
release artifact (`windows-x64` or `windows-arm64`).

You can provide a custom destination using the `-InstallDir` parameter:

```powershell
./install-kingfisher.ps1 -InstallDir 'C:\Tools\Kingfisher'
```

To install a specific tag:

```powershell
./install-kingfisher.ps1 -Tag v1.71.0
```

To explicitly override architecture selection:

```powershell
./install-kingfisher.ps1 -Arch arm64
```

## Pre-commit Hooks

Install a Git pre-commit hook to block commits that introduce new secrets.

The installer:

- Preserves any existing `pre-commit` hook by chaining it **before** Kingfisher.
- Supports custom hook directories via `--hooks-path` (or Git's `core.hooksPath`).
- Can be installed either **per-repository** or as a **global** hook.

### macOS and Linux

Install a **per-repository** hook from the root of the repo you want to protect:

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher-pre-commit.sh | \
  bash
```

Uninstall from that repository:

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher-pre-commit.sh | \
  bash -s -- --uninstall
```

Install as a **global** pre-commit hook (using core.hooksPath):

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher-pre-commit.sh | \
  bash -s -- --global
```

Uninstall the **global** hook:

```bash
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher-pre-commit.sh | \
  bash -s -- --global --uninstall
```

### Windows PowerShell

Install a **per-repository** hook from the root of the target repo:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher-pre-commit.ps1' -OutFile install-kingfisher-pre-commit.ps1
./install-kingfisher-pre-commit.ps1
```

Uninstall from that repository:

```powershell
./install-kingfisher-pre-commit.ps1 -Uninstall
```

Install as a **global** hook (using core.hooksPath):

```powershell
./install-kingfisher-pre-commit.ps1 -Global
```

Uninstall the **global** hook:

```powershell
./install-kingfisher-pre-commit.ps1 -Global -Uninstall
```

> The installer automatically runs any existing `pre-commit` hook first, then
> executes `kingfisher scan . --staged --quiet --no-update-check`
> against the staged diff (anchored to `HEAD` when no commits exist yet).

### Using the `pre-commit` Framework

Add Kingfisher as a hook in your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/mongodb/kingfisher
    rev: <version-or-commit>
    hooks:
      # Recommended: Auto-downloads and caches the binary - no manual install or Docker required
      - id: kingfisher-auto

      # Alternative: Runs Kingfisher from Docker (requires Docker)
      - id: kingfisher-docker

      # Alternative: Uses locally installed Kingfisher (fastest, requires manual install)
      - id: kingfisher
```

**Available hooks:**

| Hook ID | Description | Requirements |
| ------- | ----------- | ------------ |
| `kingfisher-auto` | Automatically downloads and caches the appropriate binary for your platform | curl, tar (or unzip on Windows) |
| `kingfisher-docker` | Runs Kingfisher in Docker | Docker |
| `kingfisher` | Uses locally installed Kingfisher binary | Manual installation |

The `kingfisher-auto` hook is recommended for most users as it:

- Automatically downloads the correct binary for your OS and architecture
- Caches the binary in `~/.cache/kingfisher` (Linux/macOS) or `%LOCALAPPDATA%\kingfisher` (Windows)
- Works across Linux, macOS, and Windows (via Git Bash which comes with Git for Windows)
- Requires no Docker or manual installation

**Windows users:** The `kingfisher-auto` hook uses a bash script that runs via Git Bash (included with [Git for Windows](https://gitforwindows.org/)). For native PowerShell, a `kingfisher-pre-commit-auto.ps1` script is also available in the `scripts/` directory.

The PowerShell auto-hook script also auto-detects Windows architecture and
downloads the matching `windows-x64` or `windows-arm64` binary.

Then install the hook via `pre-commit install`. Every hook now drives Kingfisher
directly with the built-in `--staged` flag:

```bash
kingfisher scan . --staged --quiet --no-update-check
```

When `--staged` is set, Kingfisher snapshots the staged index into a temporary
commit, diffs it against `HEAD` (or an empty tree if no commits exist yet), and
scans only those staged changes.

> Exit codes: Kingfisher exits `0` when no findings are present and returns
> `205` when validated credentials are discovered (other findings use codes in
> the `200` range). The hook surfaces those exit codes directly to `pre-commit`,
> so no extra handling is required—the commit will fail automatically on
> non-zero exits.

To trigger a hook in CI without installing to `.git/hooks`, run (for example):

```bash
pre-commit run kingfisher-auto --all-files
```

**Pin to a specific version:**

To use a specific Kingfisher version with the `kingfisher-auto` hook, set the `KINGFISHER_VERSION` environment variable:

```yaml
repos:
  - repo: https://github.com/mongodb/kingfisher
    rev: v1.76.0
    hooks:
      - id: kingfisher-auto
        # Optional: pin to a specific kingfisher binary version
        # env:
        #   KINGFISHER_VERSION: "1.76.0"
```

### Using Husky (Node.js projects)

For Node.js projects using [Husky](https://typicode.github.io/husky/), you can add Kingfisher to your pre-commit hooks:

**Quick setup (recommended):**

```bash
# Initialize Husky if you haven't already
npx husky init

# Add Kingfisher to the pre-commit hook (auto-downloads binary)
echo 'curl -fsSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/kingfisher-pre-commit-auto.sh | bash' >> .husky/pre-commit
```

**Or use the helper script:**

```bash
curl -fsSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-husky.sh | bash -s -- --auto-install
```

**Available options:**

```bash
# Use auto-download (recommended - no pre-installation needed)
./scripts/install-husky.sh --auto-install

# Use Docker (requires Docker, no binary installation)
./scripts/install-husky.sh --use-docker

# Use local binary (requires kingfisher to be installed)
./scripts/install-husky.sh

# Uninstall
./scripts/install-husky.sh --uninstall
```

**Manual setup:**

If you prefer to configure Husky manually, add one of these to your `.husky/pre-commit`:

```bash
# Option 1: Auto-download binary (recommended)
curl -fsSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/kingfisher-pre-commit-auto.sh | bash

# Option 2: Use Docker
docker run --rm -v "$(pwd)":/src ghcr.io/mongodb/kingfisher:latest scan /src --staged --quiet --no-update-check

# Option 3: Use locally installed binary
kingfisher scan . --staged --quiet --no-update-check
```

For faster repeated hook runs, pre-warm the compiled rule cache:

```bash
kingfisher rules compile-cache
kingfisher scan . --staged --quiet --no-update-check
```

Kingfisher caches compiled rules by default and uses a platform default cache directory when `--rule-cache-dir` is omitted. See [ADVANCED.md](../usage/advanced.md#compiled-rule-cache) for cache locations, custom-rule behavior, and the `--no-rule-cache` opt-out.

For long-lived developer machines or shared CI cache volumes, prune old compiled rule databases explicitly:

```bash
kingfisher rules prune-cache --dry-run
kingfisher rules prune-cache
```

**Windows with PowerShell:**

For Windows users preferring native PowerShell over Git Bash, create a `.husky/pre-commit.ps1` or add to your hook:

```powershell
# Download and run the PowerShell auto-install script
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/kingfisher-pre-commit-auto.ps1' -OutFile "$env:TEMP\kf-scan.ps1"
& "$env:TEMP\kf-scan.ps1"
```

If needed, you can override architecture explicitly:

```powershell
& "$env:TEMP\kf-scan.ps1" -Arch arm64
```

Or if Kingfisher is already installed:

```powershell
kingfisher scan . --staged --quiet --no-update-check
```

## Compile from Source

You may compile for your platform via `make`:

```bash
# NOTE: Requires Docker
make linux

# macOS --- must build from a macOS host
make darwin

# Windows x64 --- requires building from a Windows host with Visual Studio installed
./buildwin.bat -force
```

```bash
# Build all targets
make linux-all # builds both x64 and arm64
make darwin-all # builds both x64 and arm64
make all # builds for every OS and architecture supported
```

## Run Kingfisher in Docker

Run the dockerized Kingfisher container:

```bash
# GitHub Container Registry 
docker run --rm ghcr.io/mongodb/kingfisher:latest --version

# Scan the current working directory
# (mounts your code at /src and scans it)
docker run --rm \
  -v "$PWD":/src \
  ghcr.io/mongodb/kingfisher:latest scan /src

# Reuse the compiled rule cache across disposable containers:
# mount a host cache directory and set KF_RULE_CACHE_DIR.
docker run --rm \
  -v "$PWD":/src \
  -v "$HOME/.cache/kingfisher-rule-cache":/kf-cache \
  -e KF_RULE_CACHE_DIR=/kf-cache \
  ghcr.io/mongodb/kingfisher:latest scan /src

# Optionally prune old mounted cache entries during the scan.
docker run --rm \
  -v "$PWD":/src \
  -v "$HOME/.cache/kingfisher-rule-cache":/kf-cache \
  -e KF_RULE_CACHE_DIR=/kf-cache \
  ghcr.io/mongodb/kingfisher:latest scan /src --prune-rule-cache


# Scan while providing a GitHub token
# Mounts your working dir at /proj and passes in the token:
docker run --rm \
  -e KF_GITHUB_TOKEN=ghp_… \
  -v "$PWD":/proj \
  ghcr.io/mongodb/kingfisher:latest \
    scan https://github.com/org/private_repo.git

# Scan an S3 bucket
# Credentials can come from KF_AWS_KEY/KF_AWS_SECRET, --role-arn, or --profile
docker run --rm \
  -e KF_AWS_KEY=AKIA... \
  -e KF_AWS_SECRET=g5nYW... \
  ghcr.io/mongodb/kingfisher:latest \
    scan s3 bucket-name


# Scan and write a JSON report locally
# Here we:
#    1. Mount $PWD → /proj
#    2. Tell Kingfisher to write findings.json inside /proj/reports
#   3. Ensure ./reports exists on your host so Docker can mount it
mkdir -p reports

# run and output into host's ./reports directory
docker run --rm \
  -v "$PWD":/proj \
  ghcr.io/mongodb/kingfisher:latest \
    scan /proj \
    --format json \
    --output /proj/reports/findings.json


# Tip: you can combine multiple mounts if you prefer separating source vs. output:
# Here /src is read‑only, and /out holds your generated reports
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/reports":/out \
  ghcr.io/mongodb/kingfisher:latest \
    scan /src \
    --format json \
    --output /out/findings.json

# Scan and view the HTML report in your browser (Docker)
# Use --view-report-address 0.0.0.0 and -p to expose the report server to the host
docker run --rm \
  -v "$PWD":/src \
  -p 7890:7890 \
  ghcr.io/mongodb/kingfisher:latest \
  scan /src --access-map --view-report --view-report-address 0.0.0.0
# Then open http://localhost:7890 in your browser
```

## PyPI Wheels

If you want to run Kingfisher from PyPI, you can install it using `uv`, `pip`, or run it directly with `uvx`:

```bash
# Install with uv (recommended)
uv tool install kingfisher-bin

# Or install with pip
pip install kingfisher-bin

# Then run Kingfisher
kingfisher --help
```

Or run it without installation using `uvx`:

```bash
uvx kingfisher-bin --help
```

For maintainers who need to build and publish wheels, see
[docs/PYPI.md](../reference/python-bindings.md).
