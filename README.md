# Kingfisher: Open Source Secret Scanner with Live Validation

<p align="center">
  <img src="docs/kingfisher_logo.png" alt="Kingfisher Logo" width="126" height="173" style="vertical-align: right;" />
  <br>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License" style="height: 24px;" />
  </a>
  <a href="https://github.com/mongodb/kingfisher">
    <img src="https://img.shields.io/badge/Detection%20Rules-954-2ea043.svg" alt="Detection Rules" style="height: 24px;" />
  </a>
  <br>
  <a href="https://github.com/mongodb/kingfisher/pkgs/container/kingfisher">
    <img src="https://ghcr-badge.elias.eu.org/shield/mongodb/kingfisher/kingfisher" alt="ghcr downloads" />
  </a>
  <a href="https://github.com/mongodb/kingfisher/releases">
    <img src="https://img.shields.io/github/downloads/mongodb/kingfisher/total" alt="GitHub Downloads" style="height: 24px;" />
  </a>
  <br>

Kingfisher is an open source secret scanner and **live secret validation** tool built in Rust.

It combines Intel's SIMD-accelerated regex engine (Hyperscan) with language-aware parsing to achieve high accuracy at massive scale, and ships with [950+ built-in rules](https://mongodb.github.io/kingfisher/rules/builtin-rules/) to detect, **validate**, and triage leaked API keys, tokens, and credentials before they ever reach production.

Kingfisher also ships a **browser-based report viewer** that visualizes and triages findings from Kingfisher **and** from Gitleaks and TruffleHog JSON reports — so you can import scans from other tools and triage them in the same UI. A [hosted copy of the viewer](https://mongodb.github.io/kingfisher/viewer/) is published on the Kingfisher docs site [or run locally](#3-scan-and-view-results-in-browser)

Designed for offensive security engineers and blue-team defenders alike, Kingfisher helps you scan repositories, cloud storage, chat, docs, and CI pipelines to find and verify exposed secrets quickly.

</p>

**Learn more:** [Introducing Kingfisher: Real‑Time Secret Detection and Validation](https://www.mongodb.com/blog/post/product-release-announcements/introducing-kingfisher-real-time-secret-detection-validation)

## What Is Kingfisher?

Kingfisher is a high-performance, open source secret detection tool for source code and developer platforms. If you are searching for a "GitHub secret scanner," "API key scanner," "token leak detection," or "Git secrets scanner," this project is built for that workflow.

- Scan code, Git history, and integrated platforms (GitHub, GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, Jira, Confluence, Slack, Microsoft Teams, Postman, Docker, AWS S3, and Google Cloud Storage)
- Validate discovered credentials against provider APIs to reduce false positives
- Revoke supported secrets directly from the CLI
- Generate JSON, SARIF, TOON, and HTML outputs for security teams, compliance, and CI

## Key Features

### Multiple Scan Targets
<div align="center">

| Files / Dirs | Local Git | GitHub | GitLab | Azure Repos | Bitbucket | Gitea | Hugging Face |
|:-------------:|:----------:|:------:|:------:|:-------------:|:----------:|:------:|:-------------:|
| <img src="./docs/assets/icons/files.svg" height="40" alt="Files / Dirs"/><br/><sub>Files / Dirs</sub> | <img src="./docs/assets/icons/local-git.svg" height="40" alt="Local Git"/><br/><sub>Local Git</sub> | <img src="./docs/assets/icons/github.svg" height="40" alt="GitHub"/><br/><sub>GitHub</sub> | <img src="./docs/assets/icons/gitlab.svg" height="40" alt="GitLab"/><br/><sub>GitLab</sub> | <img src="./docs/assets/icons/azure-devops.svg" height="40" alt="Azure Repos"/><br/><sub>Azure Repos</sub> | <img src="./docs/assets/icons/bitbucket.svg" height="40" alt="Bitbucket"/><br/><sub>Bitbucket</sub> | <img src="./docs/assets/icons/gitea.svg" height="40" alt="Gitea"/><br/><sub>Gitea</sub> |<img src="./docs/assets/icons/huggingface.svg" height="40" width="40" alt="Hugging Face"/><br/><sub>Hugging Face</sub> |

| Docker | Jira | Confluence | Slack | Teams | Postman | AWS S3 | Google Cloud |
|:------:|:----:|:-----------:|:-----:|:-----:|:-------:|:------:|:---:|
| <img src="./docs/assets/icons/docker.svg" height="40" alt="Docker"/><br/><sub>Docker</sub> | <img src="./docs/assets/icons/jira.svg" height="40" alt="Jira"/><br/><sub>Jira</sub> | <img src="./docs/assets/icons/confluence.svg" height="40" alt="Confluence"/><br/><sub>Confluence</sub> | <img src="./docs/assets/icons/slack.svg" height="40" alt="Slack"/><br/><sub>Slack</sub> | <img src="./docs/assets/icons/teams.svg" height="40" alt="Microsoft Teams"/><br/><sub>Teams</sub> | <img src="./docs/assets/icons/postman.svg" height="40" alt="Postman"/><br/><sub>Postman</sub> | <img src="./docs/assets/icons/aws-s3.svg" height="40" alt="AWS S3"/><br/><sub>AWS&nbsp;S3</sub> |  <img src="./docs/assets/icons/gcs.svg" height="40" alt="Google Cloud Storage"/><br/><sub>Cloud Storage</sub> |

</div>

### Performance, Accuracy, and 954 Rules
- **Performance**: multithreaded, Hyperscan‑powered scanning built for huge codebases  
- **Extensible rules**: 954 built-in rules plus YAML-defined custom rules ([docs/RULES.md](/docs/RULES.md))
- **Validate & Revoke**: live validation of discovered secrets, plus direct revocation for supported platforms (GitHub, GitLab, Slack, AWS, GCP, and more) ([docs/USAGE.md](/docs/USAGE.md))
- **Revocation support matrix**: current built-in revocation coverage across providers and rule IDs ([docs/REVOCATION_PROVIDERS.md](/docs/REVOCATION_PROVIDERS.md))
- **Blast Radius Mapping**: instantly map leaked keys to their effective cloud identities and exposed resources with `--access-map` (alias `--blast-radius`). Supports 43 providers (see table below).
- **Broad AI SaaS coverage**: finds and validates tokens for OpenAI, Anthropic, Google Gemini, Cohere, AWS Bedrock, Voyage AI, Mistral, Stability AI, Replicate, xAI (Grok), Ollama, Langchain, Perplexity, Weights & Biases, Cerebras, Friendli, Fireworks.ai, NVIDIA NIM, Together.ai, Zhipu, and many more
- **Compressed Files**: Supports extracting and scanning compressed files for secrets, including `tar.gz`/`bz2`/`xz`, ZIP-family containers (`zip`, `jar`, `docx`, `xlsx`, `pptx`, `odt`, `epub`, `hwpx`, and more), `asar`, HWP (Hancom OLE2/CFBF binary with DEFLATE/zlib stream decoding), and EGG (ALZip; raw-byte scanning)
- **SQLite Database Scanning**: Automatically extracts and scans SQLite database contents for secrets stored in table rows
- **Python Bytecode (.pyc) Scanning**: Extracts and scans string constants from compiled Python (`.pyc`, `.pyo`) files
- **Baseline management**: generate and track baselines to suppress known secrets ([docs/BASELINE.md](/docs/BASELINE.md))
- **Checksum-aware detection**: verifies tokens with built-in checksums (e.g., GitHub, Confluent, Zuplo) — no API calls required
- **Report Viewer (local + hosted)**: Visualize and triage Kingfisher, **Gitleaks, and TruffleHog** JSON output locally with `kingfisher view ./report.json` or online with the [hosted viewer](https://mongodb.github.io/kingfisher/viewer/). Multiple files, directories, and imported third-party reports are merged and deduplicated. See [docs/USAGE.md](/docs/USAGE.md#report-viewer-local-and-hosted).
- **Audit reporting**: Generate compliance-oriented HTML reports with scan metadata and validation ordering
- **Library crates**: Embed Kingfisher's scanning engine in your own Rust applications ([docs/LIBRARY.md](docs/LIBRARY.md))

# Benchmark Results

See ([docs/COMPARISON.md](docs/COMPARISON.md))

<p align="center">
  <img src="docs/runtime-comparison.png" alt="Kingfisher Runtime Comparison" style="vertical-align: center;" />
</p>

## Basic Usage Demo
```bash
kingfisher scan /path/to/scan --view-report
```
NOTE: Replay has been slowed down for demo
![Kingfisher secret scanning demo](docs/kingfisher-usage-01.gif)

# Table of Contents

- [What Is Kingfisher?](#what-is-kingfisher)
- [Key Features](#key-features)
- [Report Viewer (local and hosted)](#report-viewer-local-and-hosted)
- [Compliance and Audit-Ready Scans](#compliance-and-audit-ready-scans)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
  - [Quick Start](#quick-start)
  - [Installation](#installation)
- [Detection Rules](#detection-rules)
- [Usage Examples](#usage-examples)
- [Platform Integrations](#platform-integrations)
  - [Environment Variables](#environment-variables)
- [Advanced Features](#advanced-features)
- [Documentation](#documentation)
- [Library Usage](#library-usage)
- [Roadmap](#roadmap)
- [License](#license)

# Getting Started

## Quick Start

### 1: Install Kingfisher ([INSTALLATION.md](docs/INSTALLATION.md))

```bash
# Homebrew (Linux/macOS)
brew install kingfisher

# Or install from PyPI with uv
uv tool install kingfisher-bin

# Or use the install script (Linux/macOS)
curl -sSL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash

# Or use PowerShell based install script on Windows
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.ps1' -OutFile install-kingfisher.ps1
./install-kingfisher.ps1

# Or run with Docker (no install required)
docker run --rm -v "$PWD":/src ghcr.io/mongodb/kingfisher:latest scan /src
```

### 2: Scan a directory for secrets ([USAGE.md](/docs/USAGE.md))

```bash
kingfisher scan /path/to/code
```

### 3: Scan and view results in browser

```bash
kingfisher scan /path/to/code --view-report
```

You can also open existing Kingfisher, Gitleaks, or TruffleHog JSON reports with `kingfisher view <report.json>`:

```bash
# Kingfisher report
kingfisher view kingfisher.json

# Import a Gitleaks JSON report
kingfisher view gitleaks-report.json

# Import a TruffleHog JSON or JSONL report
kingfisher view trufflehog-report.jsonl

# Combine multiple reports (deduplicated by fingerprint / secret identity)
kingfisher view kingfisher.json gitleaks.json trufflehog.jsonl

# Or load every JSON/JSONL report in a directory
kingfisher view ./reports/
```

For a shareable, upload-based experience, the docs site also hosts the same viewer as a static page: **[https://mongodb.github.io/kingfisher/viewer/](https://mongodb.github.io/kingfisher/viewer/)**. Everything runs client-side in the browser — no reports leave your machine.

### 4: Show only validated (live) secrets

```bash
kingfisher scan /path/to/code --only-valid
```

### 5: Revoke a discovered secret

```bash
# Revoke a GitHub token
kingfisher revoke --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Revoke AWS credentials (sets access key to Inactive)
kingfisher revoke --rule aws --arg "AKIAIOSFODNN7EXAMPLE" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### 6: Scan a GitHub organization ([INTEGRATIONS.md](docs/INTEGRATIONS.md))

```bash
KF_GITHUB_TOKEN="ghp_..." kingfisher scan github --organization my-org
```

### 7: Scan a GitLab group

```bash
KF_GITLAB_TOKEN="glpat-..." kingfisher scan gitlab --group my-group
```

### 8: Scan Azure Repos

```bash
KF_AZURE_PAT="pat" kingfisher scan azure --azure-organization my-org
```

### 9: Scan Bitbucket workspace

```bash
KF_BITBUCKET_TOKEN="token" kingfisher scan bitbucket --workspace my-team
```

### 10: Scan Gitea organization

```bash
KF_GITEA_TOKEN="token" kingfisher scan gitea --organization my-org
```

### 11: Scan Hugging Face

```bash
KF_HUGGINGFACE_TOKEN="hf_..." kingfisher scan huggingface --huggingface-organization my-org
```

### 12: Scan an S3 bucket

```bash
kingfisher scan s3 bucket-name --prefix path/
```

### 13: Scan Google Cloud Storage

```bash
kingfisher scan gcs bucket-name --prefix path/
```

### 14: Scan a Docker image or saved image archive

```bash
kingfisher scan docker ghcr.io/org/image:latest
kingfisher scan docker --archive image.tar
```

### 15: Scan Jira issues

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com --jql "project = SEC"
```

Add `--include-comments` and/or `--include-changelog` to expand the scan beyond the issue body.

### 16: Scan Confluence pages

```bash
KF_CONFLUENCE_TOKEN="token" kingfisher scan confluence --url https://confluence.company.com --cql "label = secret"
```

### 17: Scan Slack messages

```bash
KF_SLACK_TOKEN="xoxp-..." kingfisher scan slack "api_key OR password"
```

### 18: Run with Docker (no install required)

```bash
docker run --rm -v "$PWD":/src ghcr.io/mongodb/kingfisher:latest scan /src
```

### 19: Run with Docker and view report in browser

To run a scan in Docker and view the HTML report on your host machine, use `--view-report-address 0.0.0.0` so the server is reachable from outside the container, and map the port with `-p`:

```bash
docker run --rm \
  -v "$PWD":/src \
  -p 7890:7890 \
  ghcr.io/mongodb/kingfisher:latest \
  scan https://github.com/leaktk/fake-leaks \
  --access-map \
  --view-report \
  --view-report-address 0.0.0.0
```

Then open **http://localhost:7890** in your browser. If port 7890 is already in use, use `--view-report-port` and map accordingly:

```bash
docker run --rm \
  -v "$PWD":/src \
  -p 7891:7891 \
  ghcr.io/mongodb/kingfisher:latest \
  scan https://github.com/leaktk/fake-leaks \
  --access-map \
  --view-report \
  --view-report-port 7891 \
  --view-report-address 0.0.0.0
```

Then open **http://localhost:7891**.

### 20: Output JSON results

```bash
kingfisher scan /path/to/code --format json --output findings.json
```

### 21: Map blast radius of discovered credentials

```bash
kingfisher scan /path/to/code --access-map --view-report
```

## Installation

Kingfisher supports multiple installation methods:

- **Homebrew**: `brew install kingfisher` ![Homebrew Formula Version](https://img.shields.io/homebrew/v/kingfisher)
- **PyPI with uv**: `uv tool install kingfisher-bin`
- **Pre-built releases**: Download from [GitHub Releases](https://github.com/mongodb/kingfisher/releases)
- **Install scripts**: One-line installers for Linux, macOS, and Windows - [INSTALLATION.md](docs/INSTALLATION.md)
- **Docker**: `docker run ghcr.io/mongodb/kingfisher:latest`
- **Pre-commit hooks**: Integrate with git hooks, pre-commit framework, or Husky
- **Compile from source**: Build with `make` for your platform

**For complete installation instructions and pre-commit hook setup, see [docs/INSTALLATION.md](docs/INSTALLATION.md).**

### Faster Pre-commit and CI Runs

Repeated hook and CI scans can reuse Kingfisher's compiled Vectorscan rule database:

```bash
kingfisher rules compile-cache
kingfisher scan . --staged
```

Kingfisher caches compiled rules by default and uses a platform default cache directory unless `--rule-cache-dir` or `KF_RULE_CACHE_DIR` is set. For Docker runs, mount a host cache directory and set `KF_RULE_CACHE_DIR` so repeated disposable containers can reuse it. Custom rules loaded with `--rules-path` are included in the cache key, so changing a rule automatically refreshes the cache entry. Use `--no-rule-cache` to opt out, and `--prune-rule-cache` or `kingfisher rules prune-cache` to remove old entries. See [Compiled Rule Cache](docs/ADVANCED.md#compiled-rule-cache) for details.

## Verifying Releases

Every release ships [SLSA v1 build-provenance attestations](https://github.com/actions/attest-build-provenance) (Sigstore keyless OIDC) proving the artifact was built by our CI workflow at a known commit and hasn't been tampered with. Attestations are available via the GitHub attestation store or as the `multiple.intoto.jsonl` release asset.

**Option 1 — `gh attestation verify`** (simplest; requires [GitHub CLI](https://cli.github.com/))

```bash
gh release download <version> --repo mongodb/kingfisher --pattern 'kingfisher-linux-x64.tgz'
gh attestation verify kingfisher-linux-x64.tgz --repo mongodb/kingfisher
```

**Option 2 — `cosign`** (offline-friendly; requires [cosign](https://docs.sigstore.dev/system_config/installation/) ≥ 2.x)

```bash
gh release download <version> --repo mongodb/kingfisher \
  --pattern 'kingfisher-linux-x64.tgz' --pattern 'multiple.intoto.jsonl'

cosign verify-blob-attestation \
  --bundle multiple.intoto.jsonl \
  --new-bundle-format \
  --certificate-identity-regexp '^https://github.com/mongodb/kingfisher/\.github/workflows/release\.yml@refs/tags/v.*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  kingfisher-linux-x64.tgz
```

**Option 3 — `slsa-verifier`** (requires [slsa-verifier](https://github.com/slsa-framework/slsa-verifier))

```bash
slsa-verifier verify-artifact kingfisher-linux-x64.tgz \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/mongodb/kingfisher \
  --source-tag <version>
```

A successful verification prints `Verified OK`. The attestation proves the artifact's SHA-256, the signing identity (the release workflow at a specific tag), and the source commit — all recorded in the public [Rekor transparency log](https://search.sigstore.dev/).


## Report Viewer (local and hosted)

Kingfisher ships a browser-based **report viewer and triager** for three formats:

- Kingfisher JSON / JSONL (with full `access_map` blast-radius data when present)
- **Gitleaks** JSON
- **TruffleHog** JSON / JSONL (verified findings are surfaced as active credentials)

There are two ways to use it:

1. **Locally via the CLI** — `kingfisher view ./report.json` (bundled into every Kingfisher binary; no external services)
2. **Hosted** — [https://mongodb.github.io/kingfisher/viewer/](https://mongodb.github.io/kingfisher/viewer/) — a static, client-side upload-based copy of the same viewer. Drag in Kingfisher, Gitleaks, or TruffleHog reports and triage in your browser; nothing is uploaded to a server.

### Why use a visual viewer / triager?

Raw JSON from Kingfisher, Gitleaks, or TruffleHog is great for machines, but awful for humans making decisions on which findings are real and which need to be rotated first. The viewer lets a security engineer:

- **Skim hundreds of findings at a glance**, grouped by detector, file, repository, and validation status instead of one line per finding in a terminal.
- **Triage across multiple tools in one place** — import a Gitleaks report plus a TruffleHog report plus a Kingfisher scan of the same repo and look at them side-by-side with dedup, instead of eyeballing three different JSON schemas.
- **Prioritize real, validated secrets** — validated Kingfisher findings and TruffleHog-verified findings float to the top so you act on live credentials first.
- **Drop duplicates** — repeated imports and overlapping scans are deduplicated by fingerprint/secret identity so you don't open the same key five times. Per-tool "duplicates removed" cards on the dashboard show how much noise each tool contributed, and an upload-time **Deduplicate findings** toggle (on by default) lets you inspect raw rows when you need to.
- **Cross-tool enrichment** — when a Gitleaks or TruffleHog finding lines up with a Kingfisher finding at the same commit, file, and line, the imported row picks up Kingfisher's validation verdict and validate / revoke commands. This is useful when a team already has a Gitleaks or TruffleHog pipeline in CI and wants to layer Kingfisher's validation and remediation data on top of the reports they already produce, without replacing their existing tooling.
- **See blast radius** — for Kingfisher reports generated with `--access-map`, the viewer renders the identity, permissions, and resources a leaked credential can reach, so you can tell a dev token apart from a production admin key.
- **Export triage decisions** — filter down to what matters and export a cleaned-up subset for a ticket, a rotation runbook, or an audit reviewer.

Gitleaks and TruffleHog are both widely used open-source secret scanners with their own strengths; Kingfisher's viewer reads their standard JSON output so teams that already run them can pull those findings into the same triage workflow. Kingfisher is not affiliated with or endorsed by the Gitleaks project or Truffle Security Co.; TruffleHog and Gitleaks are trademarks of their respective owners.

Note: when you pass `--view-report`, Kingfisher starts a web server on port `7890` (default) and opens it in your default browser. By default it binds to `127.0.0.1` for security. You'll see this near the end of the scan output, and **Kingfisher will keep running** until you stop it.

```bash
INFO kingfisher::cli::commands::view: Starting access-map viewer address=127.0.0.1:7890
Serving access-map viewer at http://127.0.0.1:7890 (Ctrl+C to stop)
```

**Usage:**
```bash
kingfisher scan /path/to/scan --access-map --view-report
```

![Kingfisher access map and report viewer demo](docs/kingfisher-usage-access-map-01.gif)

**Click to view video**
[![Demo](docs/demos/findings-thumbnail.png)](https://github.com/user-attachments/assets/d33ee7a6-c60a-4e42-88e0-ac03cb429a46)

# Detection Rules

Kingfisher ships with [954 built-in rules](crates/kingfisher-rules/data/rules/) covering cloud keys, AI tokens, CI/CD secrets, database credentials, and SaaS API keys. Below is an overview — see the full list in [crates/kingfisher-rules/data/rules/](crates/kingfisher-rules/data/rules/):

| Category | What we catch |
|----------|---------------|
| **Cloud Providers** | AWS, GCP, Azure (Storage, DevOps, OpenAI, Speech, Translator), Alibaba Cloud, DigitalOcean, IBM Cloud, Cloudflare, Heroku, Fly.io, Railway, Render, Temporal Cloud, and more |
| **AI & ML** | OpenAI, Anthropic, Google Gemini, Azure OpenAI, Cohere, Mistral, DeepSeek, Groq, xAI (Grok), Stability AI, Replicate, ElevenLabs, Ollama, Langchain, Perplexity, Weights & Biases, NVIDIA NIM, Fireworks.ai, Together.ai, Cerebras, Friendli, Hugging Face, Pinecone, Cursor, Zhipu, and more |
| **Dev & CI/CD** | GitHub, GitLab, Bitbucket, Buildkite, CircleCI, TravisCI, TeamCity, Jenkins, Drone CI, Harness, Docker Hub, npm, PyPI, RubyGems, Crates.io, NuGet, Vercel, Netlify, Pulumi, Terraform, and more |
| **Databases** | PostgreSQL, MySQL, MongoDB, Redis, PlanetScale, Supabase, Neon, ClickHouse, DataStax Astra, Firebase, JDBC, ODBC, and more |
| **Messaging & Email** | Slack, Discord, Microsoft Teams, Telegram, Twilio, SendGrid, Mailgun, Mailchimp, Mailjet, Postmark, Brevo (Sendinblue), Resend, and more |
| **Observability** | Datadog, Grafana, New Relic, Sentry, Dynatrace, Honeycomb, PagerDuty, OpsGenie, Sumo Logic, Better Stack, and more |
| **Payments & Fintech** | Stripe, PayPal, Square, GoCardless, Flutterwave, Razorpay, Plaid, Coinbase, and more |
| **Security & Identity** | Snyk, Auth0, Okta, Clerk, LaunchDarkly, 1Password, JFrog Artifactory/Xray, SonarCloud, Endor Labs, Dependency-Track, StackHawk, and more |
| **CRM & Business SaaS** | Salesforce, HubSpot, Jira, Confluence, Asana, Linear, Monday.com, Zendesk, Intercom, Shopify, and more |
| **Crypto Material** | Private keys (PEM, PGP/GPG, SSH), JWTs, age encryption keys, WireGuard keys, and more |

## Write Custom Rules

Kingfisher ships with 954 built-in rules.

However, you may want to add your own custom rules, or modify a detection to better suit your needs / environment.

**For complete rule documentation, see [docs/RULES.md](docs/RULES.md).**

### Checksum Intelligence

Modern API tokens increasingly include **built-in checksums**, short internal digests that make each credential self-verifiable. (For background, see [GitHub's write-up on their newer token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) and why checksums slash false positives.)

Kingfisher supports **checksum-aware matching** in rules, enabling **offline structural verification** of credentials *without* calling third-party APIs.

By validating each token's internal checksum (for tokens that support checksums), Kingfisher eliminates nearly all false positives—automatically skipping structurally invalid or fake tokens before validation ever runs.

**Why this matters**
- **Offline verification** — no API call required  
- **Industry-aligned** — compatible with prefix + checksum token designs (e.g., modern PATs)  
- **Lower false positives** — invalid tokens are filtered out by structure alone

**Learn more**: implementation details and templating are documented in **[docs/RULES.md](docs/RULES.md)**

# Usage Examples

> **Note**: `kingfisher scan` automatically detects whether the input is a Git repository or a plain directory—no extra flags required.

## Basic Scanning

```bash
# Scan with secret validation
kingfisher scan /path/to/code
## NOTE: This path can refer to:
# 1. a local git repo
# 2. a directory with many git repos
# 3. or just a folder with files and subdirectories

# Scan without validation
kingfisher scan ~/src/myrepo --no-validate

# Turbo mode: run as fast as possible by disabling Git commit metadata, Base64 decoding,
# MIME sniffing, language detection, and parser-based context verification
# (findings omit commit context, Base64-only matches, MIME type, and language metadata)
kingfisher scan ~/src/myrepo --turbo

# Display only secrets confirmed active by third‑party APIs
kingfisher scan /path/to/repo --only-valid

# Output JSON and capture to a file
kingfisher scan . --format json | tee kingfisher.json

# Output SARIF directly to disk
kingfisher scan /path/to/repo --format sarif --output findings.sarif
```

## Access Map and Visualization

**Stop Guessing, Start Mapping: Understand Your True Blast Radius**

Finding a leaked credential is only the first step. The critical question isn't just "Is this a secret?"—it's "What can an attacker do with it?"

Kingfisher's `--access-map` feature transforms secret detection from a simple alert into a comprehensive threat assessment. Instead of leaving you with a cryptic API key, Kingfisher actively authenticates against the provider to map the full extent of the credential's power.

* **Instant Identity Resolution**: Immediately identify who the key belongs to—whether it's a specific IAM user, an assumed role, or a service account.
* **Visualize the Blast Radius**: See exactly which resources (S3 buckets, EC2 instances, projects, storage containers) are exposed and at risk.

```bash
# Generate access map during scan
kingfisher scan /path/to/code --access-map --view-report

# View access-map reports locally
kingfisher view kingfisher.json

# Import third-party reports for local triage
kingfisher view trufflehog.json
kingfisher view gitleaks.json

# Combine multiple reports (deduplicated by fingerprint)
kingfisher view report1.json report2.jsonl

# Load all reports from a directory (non-recursive, skips non-JSON/JSONL files)
kingfisher view ./reports/
```

The viewer can import Gitleaks JSON and TruffleHog JSON/JSONL in addition to native Kingfisher reports. Imported findings are normalized for browsing, filtering, and export, and imported TruffleHog/Gitleaks findings deduplicate by secret identity. Imported reports remain display-oriented: native `access_map`, validate/revoke commands, and blast-radius linking still require a Kingfisher scan.

> **Use the access map functionality only when you are authorized to inspect the target account, as Kingfisher will issue additional network requests to determine what access the secret grants**

### Supported Access Map Providers (43)

| Cloud & Infra | DevOps & CI/CD | SaaS & APIs | Data & Messaging |
|:---|:---|:---|:---|
| AWS | GitHub | Airtable | MongoDB |
| GCP | GitLab | Algolia | MySQL |
| Azure Storage | Azure DevOps | Auth0 | PostgreSQL |
| Alibaba Cloud | Bitbucket | HubSpot | SendGrid |
| DigitalOcean | Buildkite | Salesforce | Sendinblue / Brevo |
| IBM Cloud | CircleCI | Shopify | Slack |
| Terraform Cloud | Harness | Zendesk | Microsoft Teams |
| | JFrog Artifactory | Stripe | Pinecone |
| | JFrog Xray | Square | |
| | Jira | PayPal | |
| | | Plaid | |
| | | Fastly | |
| | | OpenAI | |
| | | Anthropic | |
| | | Hugging Face | |
| | | Weights & Biases | |
| | | Gitea | |
| | | monday.com | |
| | | Asana | |

## Direct Secret Validation & Revocation

```bash
# Validate a known secret without scanning
kingfisher validate --rule opsgenie "12345678-9abc-def0-1234-56789abcdef0"

# Validate from stdin
echo "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | kingfisher validate --rule github -

# Revoke a Slack token
kingfisher revoke --rule slack "xoxb-..."

# Revoke a GitHub PAT
kingfisher revoke --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

Validation throttling is also available for direct validation:

- `--validation-rps <RPS>` sets a global request rate.
- `--validation-rps-rule <RULE_SELECTOR=RPS>` sets per-rule overrides (repeatable).
- Rule selectors accept short names, so `github=2` matches `kingfisher.github.*`.

```bash
# Limit direct validation to 1 req/sec for GitHub rules
kingfisher validate --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
  --validation-rps-rule github=1
```


## Compliance and Audit-Ready Scans

Kingfisher is built to support compliance and security-assurance goals, not just detection. In addition to finding secrets, it helps teams produce evidence that secure development controls are operating.

- **Audit scan output**: generate a standalone HTML report with scan timestamp, report generation time, validation status, and file-level links for findings
- **Evidence-friendly metadata**: include version, scan stats, and sanitized command arguments for review workflows
- **Control narrative support**: demonstrate that hardcoded credentials/secrets are actively detected and triaged in CI/CD and developer workflows

```bash
# Generate an audit-ready HTML report
kingfisher scan /path/to/code --format html --output kingfisher-audit.html
```

## Advanced Scanning Options

```bash
# Pipe any text directly into Kingfisher
cat /path/to/file.py | kingfisher scan -

# Limit maximum file size scanned (default: 256 MB)
kingfisher scan /some/file --max-file-size 500

# Turbo mode: equivalent to --commit-metadata=false --no-base64 and disables MIME sniffing,
# language detection/parser-based context verification for maximum speed
# No Git commit metadata (author, date, hash), Base64 decoding, MIME, or language metadata in findings
kingfisher scan /path/to/repo --turbo

# Scan using a rule family
kingfisher scan /path/to/repo --rule kingfisher.aws

# Display rule performance statistics
kingfisher scan /path/to/repo --rule-stats

# Throttle validation request rate globally
kingfisher scan /path/to/repo --validation-rps 5

# Override specific rule families (kingfisher. prefix optional)
kingfisher scan /path/to/repo \
  --validation-rps 10 \
  --validation-rps-rule github=2 \
  --validation-rps-rule pypi=0.5

# Increase validation response storage limit (default: 2048 bytes)
kingfisher scan /path/to/repo --max-validation-response-length 8192

# Disable validation response storage truncation entirely (0 = unlimited)
kingfisher scan /path/to/repo --max-validation-response-length 0

# Include full validation response bodies end-to-end (no validation or reporter truncation)
# Useful for parsing complete validation responses (e.g., GitHub token metadata)
kingfisher scan /path/to/repo --full-validation-response

# Exclude specific paths
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude '[Tt]ests'

# Scan changes in CI pipelines
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"
```

> Validation rate limiting applies to all built-in validator types (HTTP/gRPC, cloud SDK validators such as AWS/GCP/Coinbase, and database/token validators such as MongoDB, Postgres, MySQL, JDBC, JWT, and Azure Storage). `Raw` validators are excluded.

# Platform Integrations

Kingfisher can scan multiple platforms and services directly:

**Version Control & Code Hosting:**
- GitHub (organizations, users, repositories)
- GitLab (groups, users, projects)
- Azure Repos (organizations, projects)
- Bitbucket (workspaces, users, repositories)
- Gitea (organizations, users, repositories)
- Hugging Face (models, datasets, spaces)

**Cloud Storage:**
- AWS S3
- Google Cloud Storage

**Containers:**
- Docker (images from registries)

**Collaboration & Documentation:**
- Jira (issues via JQL queries)
- Confluence (pages via CQL queries)
- Slack (messages via search queries)
- Microsoft Teams (messages via Microsoft Graph search)
- Postman (workspaces, collections, and environments — including plaintext "secret"-typed environment variables)

See **[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md)** for complete integration documentation and authentication setup.

## Quick Examples

```bash
# Scan AWS S3 bucket
kingfisher scan s3 bucket-name --prefix path/

# Scan Google Cloud Storage
kingfisher scan gcs bucket-name

# Scan Docker image
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# Scan Docker image archive produced by docker save
kingfisher scan docker --archive image.tar

# Scan GitHub organization
kingfisher scan github --organization my-org

# Scan GitLab group
kingfisher scan gitlab --group my-group

# Scan Azure Repos
kingfisher scan azure --azure-organization my-org

# Scan Jira issues
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
  --jql "project = TEST AND status = Open"

# Scan Jira issues, comments, and changelog entries
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
  --jql "project = TEST AND status = Open" \
  --include-comments \
  --include-changelog

# Scan Confluence pages
KF_CONFLUENCE_TOKEN="token" kingfisher scan confluence --url https://confluence.company.com \
  --cql "label = secret"

# Scan Slack messages
KF_SLACK_TOKEN="xoxp-..." kingfisher scan slack "from:username has:link"

# Scan Microsoft Teams messages
KF_TEAMS_TOKEN="eyJ0..." kingfisher scan teams "password OR api_key"

# Scan every Postman workspace, collection, and environment visible to the API key
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all
```

**For detailed integration instructions and authentication setup, see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).**

## Environment Variables

| Variable          | Purpose                      |
| ----------------- | ---------------------------- |
| `KF_GITHUB_TOKEN` | GitHub Personal Access Token |
| `KF_GITLAB_TOKEN` | GitLab Personal Access Token |
| `KF_GITEA_TOKEN` | Gitea Personal Access Token |
| `KF_GITEA_USERNAME` | Username for private Gitea clones (used with `KF_GITEA_TOKEN`) |
| `KF_AZURE_TOKEN` / `KF_AZURE_PAT` | Azure Repos Personal Access Token |
| `KF_AZURE_USERNAME` | Username to use with Azure Repos PATs (defaults to `pat` when unset) |
| `KF_BITBUCKET_TOKEN` | Bitbucket Cloud workspace API token or Bitbucket Server PAT |
| `KF_BITBUCKET_USERNAME` | Optional Bitbucket username for legacy app passwords or server tokens |
| `KF_BITBUCKET_APP_PASSWORD` | Legacy Bitbucket app password (deprecated September 9, 2025; disabled June 9, 2026) |
| `KF_BITBUCKET_OAUTH_TOKEN` | Bitbucket OAuth or PAT token |
| `KF_HUGGINGFACE_TOKEN` | Hugging Face access token for API enumeration and git cloning |
| `KF_HUGGINGFACE_USERNAME` | Optional username for Hugging Face git operations (defaults to `hf_user`) |
| `KF_JIRA_TOKEN`   | Jira API token               |
| `KF_CONFLUENCE_TOKEN` | Confluence API token      |
| `KF_SLACK_TOKEN`  | Slack API token              |
| `KF_TEAMS_TOKEN`  | Microsoft Graph API token for Teams message search |
| `KF_POSTMAN_TOKEN` / `POSTMAN_API_KEY` | Postman API key for workspace, collection, and environment scanning |
| `KF_DOCKER_TOKEN` | Docker registry token (`user:pass` or bearer token). If unset, credentials from the Docker keychain are used |
| `KF_AWS_KEY`, `KF_AWS_SECRET`, and `KF_AWS_SESSION_TOKEN` | AWS credentials for S3 bucket scanning. Session token is optional, for temporary credentials |

Set them temporarily per command:

```bash
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab --group my-group
```

Or export for the session:

```bash
export KF_GITLAB_TOKEN="glpat-…"
```

# Advanced Features

Kingfisher offers powerful features for complex scanning scenarios. See **[docs/ADVANCED.md](docs/ADVANCED.md)** for complete advanced documentation.

## Baseline Management

Track known secrets and detect only new ones:

```bash
# Create/update baseline
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml

# Scan with baseline (suppress known findings)
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yaml
```

## Filtering and Suppression

```bash
# Skip known false positives
kingfisher scan --skip-regex '(?i)TEST_KEY' path/
kingfisher scan --skip-word dummy path/

# Skip AWS canary tokens
kingfisher scan /path/to/code \
  --skip-aws-account "171436882533,534261010715"

# Inline ignore directives in code
# Add `kingfisher:ignore` on the same line or surrounding lines
```

## CI Pipeline Scanning

```bash
# Scan only changes between branches
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"

# Scan specific commit range
kingfisher scan /tmp/repo --branch feature-1 \
  --branch-root-commit $(git -C /tmp/repo merge-base main feature-1)
```

**For more advanced features including confidence levels, validation tuning, and custom rules, see [docs/ADVANCED.md](docs/ADVANCED.md).** See also [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for centralized and self-serve deployment strategies.

# Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](docs/INSTALLATION.md) | Complete installation guide including pre-commit hooks setup for git, pre-commit framework, and Husky |
| [INTEGRATIONS.md](docs/INTEGRATIONS.md) | Platform-specific scanning guide (GitHub, GitLab, AWS S3, Docker, Jira, Confluence, Slack, etc.) |
| [ACCESS_MAP.md](docs/ACCESS_MAP.md) | Access map: supported tokens and credential formats (43 providers including AWS, GCP, Azure, Alibaba Cloud, Stripe, Jira, monday.com, Asana, Pinecone, and more) |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level Mermaid architecture diagram of the CLI, scanner pipeline, validation, access map, and outputs |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Deployment models for self-serve CLI use, CI/pre-commit enforcement, centralized scanning, and embedded library integrations |
| [ADVANCED.md](docs/ADVANCED.md) | Advanced features: baselines, confidence levels, validation tuning, CI scanning, and more |
| [RULES.md](docs/RULES.md) | Writing custom detection rules, pattern requirements, and checksum intelligence |
| [REVOCATION_PROVIDERS.md](docs/REVOCATION_PROVIDERS.md) | Built-in revocation coverage by provider and rule ID |
| [BASELINE.md](docs/BASELINE.md) | Baseline management for tracking known secrets and detecting new ones |
| [LIBRARY.md](docs/LIBRARY.md) | Using Kingfisher as a Rust library in your own applications |
| [FINGERPRINT.md](docs/FINGERPRINT.md) | Understanding finding fingerprints and deduplication |
| [COMPARISON.md](docs/COMPARISON.md) | Benchmark results and performance comparisons |
| [PARSING.md](docs/PARSING.md) | Language-aware parsing details |
| [CONTEXT_VERIFICATION.md](docs/CONTEXT_VERIFICATION.md) | Context-verification flow, gates, and parser backends |

# Library Usage

(**beta feature**) - Kingfisher's scanning engine is available as a set of Rust library crates (`kingfisher-core`, `kingfisher-rules`, `kingfisher-scanner`) that can be embedded into other applications. This enables you to integrate secret scanning directly into your own tools and workflows.

**For complete documentation and examples, see [docs/LIBRARY.md](docs/LIBRARY.md).**

# Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |

# Lineage and Evolution

Kingfisher began as an internal fork of [Nosey Parker](https://github.com/praetorian-inc/noseyparker), used as a high-performance foundation for secret detection. 

Since then it has evolved far beyond that starting point, introducing live validation, hundreds of new rules, additional scan targets, and major architectural changes across nearly every subsystem.

**Key areas of evolution**
- **Live validation** of detected secrets directly within rules  
- **Hundreds of new built-in rules** and an expanded YAML rule schema  
- **Baseline management** to suppress known findings over time  
- **Parser-based context verification** layered on Hyperscan for language-aware detection  
- **More scan targets** (GitLab, Bitbucket, Gitea, Jira, Confluence, Slack, Microsoft Teams, Postman, S3, GCS, Docker, Hugging Face, etc.)  
- **Compressed Files**, **SQLite database**, and **Python bytecode (.pyc)** scanning support
- **New storage model** (in-memory + Bloom filter, replacing SQLite)  
- **Unified workflow** with JSON/BSON/SARIF outputs  
- **Cross-platform builds** for Linux, macOS, and Windows

# Roadmap

- More rules
- More targets
- Please file a [feature request](https://github.com/mongodb/kingfisher/issues), or open a PR, if you have features you'd like added

# License

[Apache2 License](LICENSE)
