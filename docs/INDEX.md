# Kingfisher Documentation Index

[← Back to README](../README.md)

This page routes users, operators, LLM agents, rule authors, and library developers to the
authoritative Kingfisher documentation for each task.

## Start by Goal

| Goal | Documentation |
|---|---|
| Install or upgrade Kingfisher | [Installation](INSTALLATION.md) |
| Run a first scan or understand scan output | [Usage](USAGE.md) |
| Scan a hosted service or developer platform | [Integrations](INTEGRATIONS.md) |
| Configure project-wide defaults | [Project configuration](CONFIG.md) |
| Follow detection through containment | [Defender workflow](DEFENDER_WORKFLOW.md) |
| Validate credentials and filter by outcome | [Usage: validation](USAGE.md#display-only-secrets-confirmed-active-by-third-party-apis) |
| Map credential identity, permissions, and resources | [Blast radius](BLAST_RADIUS.md) |
| Review and prioritize findings in a browser | [Viewer usage](USAGE.md#report-viewer-local-and-hosted), [hosted guide](https://mongodb.github.io/kingfisher/features/report-viewer/) |
| Revoke a supported credential | [Revocation providers](REVOCATION_PROVIDERS.md) |
| Send alerts to chat or webhook destinations | [Alert webhooks](ALERTS.md) |
| Deploy in CI, pre-commit, or a central service | [Deployment](DEPLOYMENT.md) |
| Tune performance, validation, filtering, or CI behavior | [Advanced configuration](ADVANCED.md) |
| Track accepted findings without hiding new ones | [Baseline management](BASELINE.md) |
| Preserve repository coverage evidence | [Repository audit log](AUDIT_LOG.md) |
| Write, import, or verify detection rules | [Rule authoring](RULES.md) |
| Embed Kingfisher in Rust | [Library API](LIBRARY.md) |
| Install or maintain the Python distribution | [Python/PyPI](PYPI.md) |

## Response Workflow

- [Defender workflow](DEFENDER_WORKFLOW.md) — end-to-end detection, validation, notification,
  blast-radius analysis, triage, and revocation.
- [Blast radius](BLAST_RADIUS.md) — provider coverage, evidence fields, safety boundaries, and
  standalone or scan-integrated commands.
- [Revocation providers](REVOCATION_PROVIDERS.md) — supported provider actions and operational
  safeguards.
- [Multi-step revocation](MULTI_STEP_REVOCATION.md) — authoring lookup-then-revoke HTTP flows.
- [Token revocation support](TOKEN_REVOCATION_SUPPORT.md) — how imported detectors connect to
  Kingfisher-specific containment capabilities.
- [Alert webhooks](ALERTS.md) — summary and finding notifications.
- [Repository audit log](AUDIT_LOG.md) — scan coverage, lifecycle events, and evidence semantics.

## Detection and Finding Semantics

- [Rule authoring](RULES.md) — Betterleaks TOML, private Kingfisher YAML, regex constraints,
  components, validation, filters, and checksums.
- [Parser-based context verification](CONTEXT_VERIFICATION.md) — how assignment context reduces
  false positives.
- [Source parsing](PARSING.md) — supported languages and parser pipeline.
- [Finding fingerprints](FINGERPRINT.md) — stable identifiers, deduplication, and `--no-dedup`.
- [Baseline management](BASELINE.md) — suppressing accepted findings while detecting new ones.

## Operations and Deployment

- [Installation](INSTALLATION.md) — package managers, binaries, Docker, source builds, hooks, cache,
  and release-attestation verification.
- [Integrations](INTEGRATIONS.md) — authentication and commands for every remote scan target.
- [Project configuration](CONFIG.md) — `kingfisher.yaml` policy and CLI precedence.
- [Advanced configuration](ADVANCED.md) — confidence, validation tuning, CI diffs, performance,
  exclusions, updates, and exit codes.
- [Deployment](DEPLOYMENT.md) — local, CI, centralized, and embedded deployment patterns.

## Development and Project Reference

- [Architecture](ARCHITECTURE.md) — crates, CLI paths, scanner pipeline, validation, and reporters.
- [Rust library API](LIBRARY.md) — embedding the scanner and selecting validation features.
- [Python/PyPI](PYPI.md) — Python installation, wheels, and publishing.
- [Benchmarks](COMPARISON.md) — methodology, performance, network requests, and binary size.
- [Project background](PROJECT.md) — production use, lineage, evolution, and roadmap.
- [Changelog](../CHANGELOG.md) — release history.
- [Contributing](../CONTRIBUTING.md) — development workflow and contribution expectations.
- [Security policy](../SECURITY.md) — vulnerability reporting.

## Guidance for LLMs and Automation

1. Read the repository [AGENTS.md](../AGENTS.md) before changing code or documentation.
2. Use `kingfisher scan --format toon` for token-efficient scan output. Add
   `--no-update-check` in reproducible automation.
3. Use structured `validation.outcome` values and finding fingerprints; do not infer state by
   parsing human-readable labels.
4. Treat [USAGE.md](USAGE.md), [CONFIG.md](CONFIG.md), and command `--help` as authoritative for
   CLI behavior. Use [ARCHITECTURE.md](ARCHITECTURE.md) for source routing.
5. Read [RULES.md](RULES.md) before non-trivial detector or schema changes. Generally useful rules
   belong upstream in Betterleaks; organization-specific rules may use Kingfisher YAML.
6. Live validation, blast-radius mapping, alerts, and revocation can make network requests or cause
   external effects. Follow the authorization and safety guidance in the relevant document.
