# Installation Guide

[← Back to README](../README.md)

This guide covers all installation methods for Kingfisher, including pre-commit hook setup.

## Table of Contents

- [Pre-built Releases](#pre-built-releases)
- [Verifying Release Artifacts](#verifying-release-artifacts)
- [Linux Packages (RPM and DEB)](#linux-packages-rpm-and-deb)
- [Homebrew](#homebrew)
- [mise](#mise)
- [Linux and macOS](#linux-and-macos)
- [Windows](#windows)
- [Pre-commit Hooks](#pre-commit-hooks)
  - [macOS and Linux](#macos-and-linux)
  - [Windows PowerShell](#windows-powershell)
  - [Using the pre-commit Framework](#using-the-pre-commit-framework)
  - [Using Husky (Node.js projects)](#using-husky-nodejs-projects)
- [Cargo](#cargo)
- [Compile from Source](#compile-from-source)
- [PyPI Wheels](#pypi-wheels)
- [Run Kingfisher in Docker](#run-kingfisher-in-docker)

## Pre-built Releases

Pre-built binaries are available from the [Releases](https://github.com/mongodb/kingfisher/releases) section.

## Verifying Release Artifacts

Verify a downloaded release **before extracting or running it**. This checks that the file
matches a signed artifact from Kingfisher's release workflow and the exact version you requested.
It prevents a modified download or an older genuine release from silently replacing your pinned
version in CI.

Install a current [GitHub CLI](https://cli.github.com/) and authenticate with `gh auth login`.
In a fresh directory, run these Bash commands, replacing `vX.Y.Z` with your pinned release tag:

```bash
set -euo pipefail
VERSION=vX.Y.Z
ASSET=kingfisher-linux-x64.tgz

gh release download "$VERSION" --repo mongodb/kingfisher \
  --pattern "$ASSET" --pattern multiple.intoto.jsonl

gh attestation verify "$ASSET" \
  --repo mongodb/kingfisher \
  --signer-workflow mongodb/kingfisher/.github/workflows/release.yml \
  --source-ref "refs/tags/$VERSION" \
  --bundle multiple.intoto.jsonl
```

Change `ASSET` for your platform: `kingfisher-linux-arm64.tgz`,
`kingfisher-darwin-x64.tgz`, `kingfisher-darwin-arm64.tgz`,
`kingfisher-windows-x64.zip`, or `kingfisher-windows-arm64.zip`.
The same verification command works for release `.deb` and `.rpm` packages and
`kingfisher-rule-bundle.tgz`.

Only install the file if verification succeeds. Keep `--source-ref`: verifying just the
repository or workflow accepts genuine artifacts from other versions too. Renaming an older
archive does not bypass the tag check. In CI, let a failed verification stop the install.

The downloaded `multiple.intoto.jsonl` contains the
[SLSA build-provenance attestation](https://github.com/actions/attest-build-provenance).
The GitHub CLI verifies the signature and artifact digest, then enforces the workflow and tag.
See the [verification options](https://cli.github.com/manual/gh_attestation_verify).
This verifies release provenance; it does not guarantee that the software has no vulnerabilities.

Older releases attested from `refs/heads/main` cannot pass this version-specific check.
Do not remove `--source-ref` to make them pass: use a release attested from its version tag,
or independently pin a trusted artifact SHA-256 for a legacy release.

## Linux Packages (RPM and DEB)

The native Linux package name is **`kingfisher`**, and the command is `kingfisher`.
This is separate from the intentional crates.io and PyPI name `kingfisher-bin`.

Download the `.rpm` or `.deb` for your architecture from
[Releases](https://github.com/mongodb/kingfisher/releases), then
[verify it](#verifying-release-artifacts) before installing. These examples use x64;
substitute `arm64` in the filename for ARM64:

```bash
# RPM: install or upgrade.
sudo dnf install ./kingfisher-linux-x64.rpm
# DEB: install or upgrade.
sudo apt install ./kingfisher-linux-x64.deb
```

For updates, download and verify the newer release and run the corresponding local-file
install command again. A repository upgrade command alone does not fetch GitHub release
assets. Do not use `kingfisher self-update` to overwrite a package-managed binary.

To uninstall:

```bash
sudo dnf remove kingfisher  # RPM; use yum instead of dnf where applicable.
sudo apt remove kingfisher # DEB
```

## Homebrew

![Homebrew Formula Version](https://img.shields.io/homebrew/v/kingfisher)

```bash
brew install kingfisher
```

## mise

Install the latest release globally with the
[mise GitHub backend](https://mise.jdx.dev/dev-tools/backends/github.html):

```bash
mise use --global github:mongodb/kingfisher
```

Append a version to install a specific release:

```bash
mise use --global github:mongodb/kingfisher@2.10.0
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
  bash -s -- --tag v2.10.0
```

## Windows

HTTPS repository cloning, history scanning, and `--staged` scans use native Rust
libraries; no Git executable or Git for Windows installation is required.
SSH targets additionally require an SSH client: the Windows "OpenSSH Client"
optional feature (`ssh.exe` on `PATH`) or, if that is absent, the `ssh.exe` bundled
with Git for Windows. They also need configured keys or an SSH agent and trusted
`known_hosts` entries.
`KF_GIT_BINARY` and `KF_GIT_SSL_BACKEND` are obsolete and ignored. Git is still
needed to create commits or run Git hooks, but not to run Kingfisher scans.

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
./install-kingfisher.ps1 -Tag v2.10.0
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

The file-scoped hooks are available starting with Kingfisher v2.20.0. Add one
to `.pre-commit-config.yaml`.

```yaml
repos:
  - repo: https://github.com/mongodb/kingfisher
    rev: v2.20.0
    hooks:
      - id: kingfisher-auto-files
```

Choose the hook that matches how you install Kingfisher.

| Hook ID | How it runs | Requirements |
| ------- | ----------- | ------------ |
| `kingfisher-auto-files` | Downloads and caches the binary for your platform | Bash, curl, tar (or unzip on Windows) |
| `kingfisher-docker-files` | Runs the published Kingfisher image | Docker and a Kingfisher image at version 2.20.0 or later |
| `kingfisher-files` | Uses the locally installed binary | Kingfisher 2.20.0 or later on `PATH` |

The auto-download hook stores its binary in the `pre-commit-files` subdirectory
of the Kingfisher cache. If you pin the download with the `KINGFISHER_VERSION`
environment variable, use v2.20.0 or later. The `rev` in the hook configuration
pins the hook definition. On Windows, the auto-download hook uses Bash, which
comes with [Git for Windows](https://gitforwindows.org/).

If Docker has an older cached image, refresh it with
`docker pull ghcr.io/mongodb/kingfisher:latest`.

Run `pre-commit install` to enable the hook for commits. The hook scans only the
files selected by the runner, with Git history disabled. During an ordinary
commit, pre-commit and prek temporarily hide unstaged edits. Manual
`--all-files` and `--files` runs read the selected files as they are on disk.
The runner's `files`, `exclude`, and file type filters apply in each case.

In CI, run the hook directly to scan all eligible tracked files.

```bash
pre-commit run kingfisher-auto-files --all-files
```

Use `--files` to scan specific files.

```bash
pre-commit run kingfisher-auto-files --files src/app.py config/settings.yml
```

If you set custom `args`, end the list with an empty string. Pre-commit replaces
the hook's default `args` with this list and then appends the filenames. The
last empty string marks where the filenames begin, so an option can still take
an empty value. Selected symlinks are skipped; Kingfisher scans their targets
only when the runner selects those files too.

```yaml
- id: kingfisher-auto-files
  args: [--no-validate, --redact, '']
```

The hook passes Kingfisher's exit codes to the runner, which fails the check on
any nonzero code. Validated credentials use exit code `205`.

The runner may split a large file list across multiple Kingfisher invocations.
Run Kingfisher directly to produce a single combined report or update a
baseline with `--manage-baseline`.

**Staged-index hooks**

The existing `kingfisher-auto`, `kingfisher-docker`, and `kingfisher` hooks
scan staged changes by comparing the Git index with `HEAD`. Use these IDs
for workflows that need the exact bytes in the index. On a clean checkout,
`--all-files` and `--files` still leave these hooks with no staged changes to
scan. The standalone Git installer and Husky hooks also use staged-index
scans.

If your CI is pinned to an older hook revision, scan the clean checkout
directly. This uses Kingfisher's file selection rules for the checkout.

```bash
kingfisher scan . --git-history none --redact --no-update-check
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

Kingfisher caches compiled rules by default and uses a platform default cache directory when `--rule-cache-dir` is omitted. See [ADVANCED.md](ADVANCED.md#compiled-rule-cache) for cache locations, custom-rule behavior, and the `--no-rule-cache` opt-out.

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

## Cargo

The crates.io package is named `kingfisher-bin`, matching PyPI; the installed command is
`kingfisher`. Once the release is published to crates.io:

```sh
cargo install --locked kingfisher-bin
kingfisher --version
```

This compiles from source and requires Rust 1.99 or newer and the platform's native build
prerequisites described below. The rule catalog is bundled; installation does not fetch
Betterleaks or Veles sources.

## Compile from Source

Source builds embed the prepared catalog of 503 rules; they do not download Betterleaks or
Veles sources. Cargo dependencies and native build prerequisites must still be available.
The repository preserves license texts, source headers, and provenance under
`crates/kingfisher-rules/generated/`; the source archive includes those files.

After installing the native prerequisites, build the headless CLI for the host with:

```bash
cargo build --release --locked --bin kingfisher
```

Release builds retain the throughput-focused optimization profile and losslessly
compressed tokenizer vocabulary. No extra machine-outlining or inlining-threshold
flags are required. On Windows, use the MSYS2 targets below to select the supported
GNU/LLVM toolchain and static libraries.

Static release builds for `x86_64-unknown-linux-musl` pack relative relocations
with `-Wl,-z,pack-relative-relocs`. Use GNU binutils 2.38 or newer, or a compatible
LLVM lld linker with RELR support. Older linkers may reject this option; upgrade
the linker or use the Docker-based `make linux` build, which supplies the release
toolchain. Other targets, debug builds, and SDK libraries do not use this option.

You may compile for your platform via `make`:

```bash
# NOTE: Requires Docker
make linux

# macOS --- must build from a macOS host
make darwin

# Windows x64 --- run from an MSYS2 MINGW64 shell
make windows-x64

# Windows ARM64 --- run from an MSYS2 CLANGARM64 shell
make windows-arm64
```

These Windows targets use the published GNU/LLVM Vectorscan archives. The
Vectorscan crate does not support MSVC targets; use the matching MSYS2 target
environment when building Kingfisher from source.

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
  scan /src --blast-radius --view-report --view-report-address 0.0.0.0
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

For in-process Python embedding, install `kingfisher-secret-scanner` and import
`kingfisher_sdk`; `kingfisher-bin` installs the CLI command. See the
[Python SDK and wheel guide](PYPI.md) for SDK examples and publishing.
