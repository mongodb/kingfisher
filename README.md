# Detect and Validate Secrets Anywhere. Map Access. Revoke Fast.

<p align="center">
  <img src="docs/kingfisher_logo.png" alt="Kingfisher Logo" width="126" height="173" />
  <br>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="Apache 2.0 License" />
  </a>
  <a href="https://github.com/mongodb/kingfisher/pkgs/container/kingfisher">
    <img src="https://ghcr-badge.elias.eu.org/shield/mongodb/kingfisher/kingfisher" alt="Container downloads" />
  </a>
  <br>
  <a href="https://github.com/mongodb/kingfisher/releases">
    <img src="https://img.shields.io/github/downloads/mongodb/kingfisher/total?label=GitHub%20Downloads" alt="GitHub downloads" />
  </a>
  <a href="https://pypi.org/project/kingfisher-bin/">
    <img src="https://img.shields.io/pepy/dt/kingfisher-bin?label=PyPI%20Downloads" alt="PyPI downloads" />
  </a>
</p>

**Find leaked secrets. Validate what’s live. Map the blast radius. Revoke fast.**

Kingfisher is a blazingly fast, completely free and open source secret scanner built in Rust. It detects leaked secrets across your entire stack with [hundreds of built-in rules](https://mongodb.github.io/kingfisher/rules/builtin-rules/), validates which credentials are actually live, maps the blast radius of every leak, and revokes exposed secrets in minutes - the full defender workflow in one Apache-2.0-licensed release:

**Detect → Validate → Map → Triage → Revoke**

 - scan source code, Git history, cloud storage, container images, archives, and developer platforms
 - validate which credentials are active
 - map a leaked secrete's identity, permissions, and reachable resources
 - triage findings in a browser, or output as SARIF, JSON, TOON
 - revoke supported secrets

> **Defender workflow:** Follow the [end-to-end defender workflow](docs/DEFENDER_WORKFLOW.md) for secret detection, validation, notifications, blast-radius mapping, and revocation.

## Scan Targets

Kingfisher handles local files and directories, Git repositories and history, compressed and
office-document archives, SQLite databases, Python bytecode, Docker images, source-hosting
organizations, cloud object storage, collaboration tools, and API-development platforms.

<div align="center">

| Files / Dirs | Local Git | GitHub | GitLab | Azure Repos | Bitbucket | Gitea | Hugging Face |
|:-------------:|:----------:|:------:|:------:|:-------------:|:----------:|:------:|:-------------:|
| <img src="./docs/assets/icons/files.svg" height="40" alt="Files / Dirs"/><br/><sub>Files / Dirs</sub> | <img src="./docs/assets/icons/local-git.svg" height="40" alt="Local Git"/><br/><sub>Local Git</sub> | <img src="./docs/assets/icons/github.svg" height="40" alt="GitHub"/><br/><sub>GitHub</sub> | <img src="./docs/assets/icons/gitlab.svg" height="40" alt="GitLab"/><br/><sub>GitLab</sub> | <img src="./docs/assets/icons/azure-devops.svg" height="40" alt="Azure Repos"/><br/><sub>Azure Repos</sub> | <img src="./docs/assets/icons/bitbucket.svg" height="40" alt="Bitbucket"/><br/><sub>Bitbucket</sub> | <img src="./docs/assets/icons/gitea.svg" height="40" alt="Gitea"/><br/><sub>Gitea</sub> | <img src="./docs/assets/icons/huggingface.svg" height="40" width="40" alt="Hugging Face"/><br/><sub>Hugging Face</sub> |

| Docker | Jira | Confluence | Slack | Teams | Postman | AWS S3 | Google Cloud |
|:------:|:----:|:-----------:|:-----:|:-----:|:-------:|:------:|:------------:|
| <img src="./docs/assets/icons/docker.svg" height="40" alt="Docker"/><br/><sub>Docker</sub> | <img src="./docs/assets/icons/jira.svg" height="40" alt="Jira"/><br/><sub>Jira</sub> | <img src="./docs/assets/icons/confluence.svg" height="40" alt="Confluence"/><br/><sub>Confluence</sub> | <img src="./docs/assets/icons/slack.svg" height="40" alt="Slack"/><br/><sub>Slack</sub> | <img src="./docs/assets/icons/teams.svg" height="40" alt="Microsoft Teams"/><br/><sub>Teams</sub> | <img src="./docs/assets/icons/postman.svg" height="40" alt="Postman"/><br/><sub>Postman</sub> | <img src="./docs/assets/icons/aws-s3.svg" height="40" alt="AWS S3"/><br/><sub>AWS&nbsp;S3</sub> | <img src="./docs/assets/icons/gcs.svg" height="40" alt="Google Cloud Storage"/><br/><sub>Cloud Storage</sub> |

</div>

For target-specific commands, authentication, scope, and pagination behavior, use the
[platform integration guide](docs/INTEGRATIONS.md).


## Built for Speed and Accuracy

Kingfisher's multithreaded Vectorscan engine recorded the lowest runtime on every repository in the published benchmark suite, from small projects through the Linux kernel and GitLab monorepo.
Lower runtimes are better.

<p align="center">
  <img src="docs/runtime-comparison.png" alt="Kingfisher runtime comparison across open source repositories" />
</p>

Despite it's broad feature-set, Kingfisher ships as a compact static binary. For example, the published macOS arm64 comparison measures Kingfisher 2.1.0 at 25.3 MiB, making it easy to distribute in CI jobs and container images.

See the [binary-size comparison](docs/COMPARISON.md#binary-size-comparison-macos-arm64) and
[deployment options](docs/DEPLOYMENT.md), which includes validation results, network-request counts, test environment, and binary-size comparison.

## Why Kingfisher

| Stage | What Kingfisher provides | Learn more |
|---|---|---|
| **Detect** | A blazingly fast, multithreaded Vectorscan regex engine combines SIMD-accelerated matching with language-aware verification across repositories, files, archives, cloud storage, containers, and developer platforms | [Scanning](docs/USAGE.md), [integrations](docs/INTEGRATIONS.md), [benchmarks](docs/COMPARISON.md) |
| **Validate** | Live provider checks that distinguish active credentials from static candidates | [Validation and filtering](docs/USAGE.md#display-only-secrets-confirmed-active-by-third-party-apis) |
| **Map** | Read-only blast-radius analysis for supported providers, including advanced AWS role and GCP service-account reachability plus bounded Google API-key probes | [Blast radius](docs/BLAST_RADIUS.md) |
| **Triage** | A local and hosted browser viewer for filtering, deduplication, prioritization, blast-radius inspection, and export | [Viewer usage](docs/USAGE.md#report-viewer-local-and-hosted), [hosted guide](https://mongodb.github.io/kingfisher/features/report-viewer/) |
| **Revoke** | Conservative provider-specific containment workflows for supported credentials | [Revocation](docs/REVOCATION_PROVIDERS.md) |

Live validation, advanced cloud blast-radius analysis, visual triage,
and supported revocation all ship in the free, open source Kingfisher. There is no separate paid or
enterprise tier.

A few examples:

```bash
kingfisher scan /path/to/code --only-valid --blast-radius --view-report  # a local repo and its Git history
kingfisher scan s3 some-example-bucket --prefix path/to/data/           # an S3 bucket
kingfisher scan gcs bucket-name --prefix path/to/data/                  # a GCS bucket
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master  # a container image from any registry
kingfisher scan docker --archive image.tar                              # a saved image archive
kingfisher scan github --organization my-org                            # a GitHub organization
```

See [usage](docs/USAGE.md) for the full command reference and
[integrations](docs/INTEGRATIONS.md) for platform-specific examples, including GitLab, Azure DevOps,
Gitea, Slack, and Jira.

See Kingfisher in action with [basic scan and validation examples](docs/USAGE.md#basic-examples),
the [end-to-end defender workflow](docs/DEFENDER_WORKFLOW.md),
[platform-specific scan examples](docs/INTEGRATIONS.md),
[blast-radius examples](docs/BLAST_RADIUS.md#standalone-flow),
[direct revocation](docs/USAGE.md#direct-secret-revocation-with-kingfisher-revoke), and
[CI and pre-commit deployment](docs/DEPLOYMENT.md#ci-and-pre-commit).

## Map the Blast Radius. Revoke the Credential.

For supported credentials, `--blast-radius` goes beyond a live/inactive verdict. It maps the
effective identity, permissions, reachable roles or service accounts, and affected resource
scopes. This includes advanced AWS role-assumption, GCP service-account impersonation analysis,
and exact read methods accepted by a bounded Google API-key probe allowlist.

The HTML viewer turns that evidence into an interactive access map for rapid investigation and
prioritization:

![Kingfisher blast-radius access-map HTML view](docs/access-map.png)

Kingfisher also provides explicit, defender-led revocation for supported credentials. Revocation
is opt-in and is exposed only where Kingfisher has a bounded provider workflow; responders should
always confirm the target and operational impact before containment.

</div>

### Performance, Accuracy, and Extensible Rules
- **Performance**: multithreaded, Hyperscan‑powered scanning built for huge codebases  
- **Extensible rules**: Betterleaks is the main catalog, with selected Veles detectors filling gaps;
  custom Betterleaks TOML and Kingfisher 1.x YAML rules are supported ([built-in rules](https://mongodb.github.io/kingfisher/rules/builtin-rules/), [docs/RULES.md](docs/RULES.md))
- **Validation and defender-led revocation**: validate discovered credentials live, then revoke supported credentials from the CLI. For supported provider flows, responders can contain a leaked token even when its owner is unknown or has left the company ([docs/USAGE.md](docs/USAGE.md), [docs/REVOCATION_PROVIDERS.md](docs/REVOCATION_PROVIDERS.md))
- **Blast-radius mapping included by default**: use `--blast-radius` (alias `--access-map`) to map supported credentials to their effective identities, permissions, reachable roles/service accounts, and impacted resource scopes. All 43 providers—including advanced AWS role-assumption and GCP service-account impersonation analysis—are included in the Apache-2.0 release ([blast-radius docs](https://mongodb.github.io/kingfisher/features/blast-radius/))
- **Broad provider coverage**: detect and validate credentials across cloud, AI, developer tooling, databases, SaaS, messaging, identity, and cryptographic systems through the Betterleaks- and Veles-based candidate catalog
- **Compressed Files**: Supports extracting and scanning compressed files for secrets, including `tar.gz`/`bz2`/`xz`, ZIP-family containers (`zip`, `jar`, `docx`, `xlsx`, `pptx`, `odt`, `epub`, `hwpx`, and more), `asar`, HWP (Hancom OLE2/CFBF binary with DEFLATE/zlib stream decoding), and EGG (ALZip; raw-byte scanning)
- **SQLite Database Scanning**: Automatically extracts and scans SQLite database contents for secrets stored in table rows
- **Python Bytecode (.pyc) Scanning**: Extracts and scans string constants from compiled Python (`.pyc`, `.pyo`) files
- **Baseline management**: generate and track baselines to suppress known secrets ([docs/BASELINE.md](docs/BASELINE.md))
- **Checksum-aware custom detection**: Kingfisher 1.x custom rules can verify token checksums offline before validation ([checksum intelligence](docs/RULES.md#checksum-intelligence))
- **Report Viewer (local + hosted)**: Visualize and triage Kingfisher, **SARIF, Gitleaks, and TruffleHog** output locally with `kingfisher view ./report.json` or online with the [hosted viewer](https://mongodb.github.io/kingfisher/viewer/). Multiple files, directories, and imported third-party reports are merged and deduplicated. See [docs/USAGE.md](docs/USAGE.md#report-viewer-local-and-hosted).
- **Audit reporting**: Generate compliance-oriented HTML reports with scan metadata and validation ordering
- **Library crates**: Embed Kingfisher's scanning engine in your own Rust applications ([docs/LIBRARY.md](docs/LIBRARY.md))

## Basic Usage Demo
```bash
kingfisher scan /path/to/scan --view-report
```
NOTE: Replay has been slowed down for demo
![Kingfisher secret scanning demo](docs/kingfisher-usage-01.gif)


# Getting Started

## Quick Start

Install with your preferred package manager:

```bash
# Homebrew (macOS/Linux)
brew install kingfisher

# PyPI wrapper
uv tool install kingfisher-bin
```

Then scan a repository, including its Git history:

```bash
kingfisher scan /path/to/repository
```

Open the results in the bundled local viewer:

```bash
kingfisher scan /path/to/repository --view-report
```

### Scan files and Git history

See [documentation](docs/INTEGRATIONS.md) for full detailed examples.

```bash
# Clone a remote repository and scan its Git history
kingfisher scan https://github.com/my-org/my-repo.git

# Scan checked-out files without Git history or live validation
kingfisher scan /path/to/repository --git-history none --no-validate

# Check staged changes before committing
kingfisher scan . --staged

# Scan an archive or an office document
kingfisher scan backup.tar.gz credentials.xlsx

# Show only live credentials and map their access
kingfisher scan /path/to/repository --only-valid --blast-radius

# Include active credentials and high-confidence assumed or locally derived secrets
kingfisher scan /path/to/repository --validation-filter actionable
```

### Save and combine reports

```bash
# Save a JSON report and open it later
kingfisher scan /path/to/repository --format json --output findings.json
kingfisher view findings.json

# Export SARIF for code-scanning integrations
kingfisher scan /path/to/repository --format sarif --output findings.sarif

# Generate a standalone HTML audit report
kingfisher scan /path/to/repository --format html --output audit.html

# Import and combine Kingfisher, Gitleaks, and TruffleHog reports
kingfisher view findings.json gitleaks.json trufflehog.jsonl

# Load every supported report in a directory
kingfisher view ./reports/
```

### Scan source-hosting organizations

Set the relevant authentication variables from the [integration guide](docs/INTEGRATIONS.md#environment-variables),
then choose a target:

```bash
# GitHub organization
kingfisher scan github --organization my-org

# GitLab group, including nested subgroups
kingfisher scan gitlab --group my-group --include-subgroups

# Azure Repos organization
kingfisher scan azure --azure-organization my-org

# Bitbucket workspace
kingfisher scan bitbucket --workspace my-team

# Gitea organization
kingfisher scan gitea --organization my-org

# Hugging Face organization
kingfisher scan huggingface --huggingface-organization my-org

# Preview the GitHub repository scope without scanning
kingfisher scan github --organization my-org --list-only
```

### Scan S3 and GCS buckets

Scan a whole bucket, or use `--prefix` to limit scanning to objects whose names start with the
given prefix. Use a bucket name without `s3://` or `gs://`; omit `--prefix` to scan the whole bucket.

```bash
# AWS S3: whole bucket
kingfisher scan s3 my-bucket

# AWS S3: only objects under backups/production/, using a named AWS profile
kingfisher scan s3 my-bucket --prefix backups/production/ --profile security

# Google Cloud Storage: whole bucket
kingfisher scan gcs my-bucket

# Google Cloud Storage: only objects under exports/daily/
kingfisher scan gcs my-bucket --prefix exports/daily/
```

Authenticate to S3 with `KF_AWS_KEY` / `KF_AWS_SECRET` or `--profile`; GCS uses Application Default
Credentials, or an explicit `--service-account /path/to/key.json`. See the [S3](docs/INTEGRATIONS.md#aws-s3) and
[GCS](docs/INTEGRATIONS.md#google-cloud-storage) guides for authentication and public-bucket examples.

### Scan containers or run Kingfisher in Docker

```bash
# Scan a registry image
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# Scan an image exported with docker save
kingfisher scan docker --archive image.tar

# Run Kingfisher against the current directory without installing it
docker run --rm -v "$PWD":/src ghcr.io/mongodb/kingfisher:latest scan /src

# Run in Docker and serve the report viewer to the host
docker run --rm -v "$PWD":/src -p 127.0.0.1:7890:7890 \
  ghcr.io/mongodb/kingfisher:latest scan /src \
  --view-report --view-report-address 0.0.0.0
```

For the Docker viewer, open [localhost:7890](http://localhost:7890) in your browser.

### Scan issues, documents, and messages

These commands use the platform credentials described in the
[integration guide](docs/INTEGRATIONS.md#environment-variables).

```bash
# Jira: search a project and include issue comments
kingfisher scan jira --url https://jira.example.com --jql "project = SEC" --include-comments

# Confluence: scan pages in a space
kingfisher scan confluence --url https://confluence.example.com --cql 'space = "ENG"'

# Slack: search messages and associated files
kingfisher scan slack "api_key OR password"

# Microsoft Teams: search messages
kingfisher scan teams "api_key OR password"

# Postman: scan a workspace's collections and environments
kingfisher scan postman --workspace my-workspace-id
```

### Validate or revoke a known credential

```bash
# Validate a GitHub personal access token directly
kingfisher validate --rule github-pat "$GITHUB_PAT"

# Revoke that token when ready to contain the exposure
kingfisher revoke --rule github-pat "$GITHUB_PAT"
```

See [direct validation](docs/USAGE.md#direct-secret-validation-with-kingfisher-validate) and
[supported revocation providers](docs/REVOCATION_PROVIDERS.md) for other credential types.

See the [installation guide](docs/INSTALLATION.md) for pre-built binaries, Docker, mise, Windows,
pre-commit hooks, release verification, and source builds. See the [usage guide](docs/USAGE.md) for
validation filters, output formats, scan scope, and command examples.

> Live validation and blast-radius mapping make authorized requests to provider APIs. Review the
> relevant documentation and use them only where you are authorized to inspect the target account.

## Common Workflows

| Goal | Start here |
|---|---|
| Run an end-to-end credential response | [Defender workflow](docs/DEFENDER_WORKFLOW.md) |
| Scan GitHub, GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, S3, GCS, Docker, Jira, Confluence, Slack, Teams, or Postman | [Platform integrations](docs/INTEGRATIONS.md) |
| Configure authentication and environment variables | [Environment-variable reference](docs/INTEGRATIONS.md#environment-variables) |
| Validate or revoke a known credential | [Direct validation](docs/USAGE.md#direct-secret-validation-with-kingfisher-validate), [revocation](docs/REVOCATION_PROVIDERS.md) |
| Map identity, permissions, and affected resources | [Blast-radius guide](docs/BLAST_RADIUS.md) |
| Triage one or more reports visually | [Viewer usage](docs/USAGE.md#report-viewer-local-and-hosted), [hosted guide](https://mongodb.github.io/kingfisher/features/report-viewer/) |
| Configure CI, pre-commit, or centralized scanning | [Deployment](docs/DEPLOYMENT.md), [advanced configuration](docs/ADVANCED.md) |
| Send findings to chat or webhook destinations | [Alerts](docs/ALERTS.md) |
| Produce repository coverage and audit evidence | [Repository audit log](docs/AUDIT_LOG.md) |
| Suppress existing findings without hiding new ones | [Baselines](docs/BASELINE.md) |
| Write or import custom rules | [Rule authoring](docs/RULES.md) |
| Embed the scanner in Rust or use it from Python | [Rust library](docs/LIBRARY.md), [Python distribution](docs/PYPI.md) |

## Output for People and Machines

Kingfisher supports human-readable output plus TOON, JSON, JSONL, SARIF, BSON, and HTML reports.
Use TOON for token-efficient LLM and agent workflows:

```bash
kingfisher scan /path/to/repository --format toon --no-update-check
```

Machine consumers should use structured validation outcomes and finding fingerprints rather than
parsing display labels. See [output and validation semantics](docs/USAGE.md),
[finding fingerprints](docs/FINGERPRINT.md), and the [full documentation index](docs/INDEX.md).

## Documentation

- **[Documentation index](docs/INDEX.md):** task-oriented map of every user, operator, rule-author,
  and developer guide in the repository.
- **[Hosted documentation](https://mongodb.github.io/kingfisher/):** searchable rendered version.
- **[llms.txt](llms.txt):** compact machine-readable map of the documentation set.
- **[Architecture](docs/ARCHITECTURE.md):** codebase layout and data flow.
- **[Changelog](CHANGELOG.md):** release-by-release behavior changes.

## Project

Kingfisher is used in MongoDB's production security workflows and is integrated by projects such
as [Prowler](https://prowler.com/blog/whats-new-in-prowler-july-2026) and
[MegaLinter](https://megalinter.io/latest/descriptors/repository_kingfisher/). Read more about its
[lineage, evolution, and public adoption](docs/PROJECT.md).

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), report vulnerabilities through
[SECURITY.md](SECURITY.md), and file feature requests in
[GitHub Issues](https://github.com/mongodb/kingfisher/issues).

Kingfisher is licensed under the [Apache License 2.0](LICENSE).
