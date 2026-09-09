---
title: "Documentation Index"
description: "Task-oriented map of Kingfisher documentation for users, operators, LLM agents, rule authors, and library developers."
---

# Kingfisher Documentation Index

This page routes users, operators, LLM agents, rule authors, and library developers to the
authoritative Kingfisher documentation for each task.

## Start by Goal

| Goal | Documentation |
|---|---|
| Install or upgrade Kingfisher | [Installation](../getting-started/installation.md) |
| Run a first scan or understand scan output | [Usage](../usage/basic-scanning.md) |
| Scan a hosted service or developer platform | [Integrations](../usage/integrations.md) |
| Configure project-wide defaults | [Project configuration](../usage/configuration.md) |
| Follow detection through containment | [Defender workflow](../usage/defender-workflow.md) |
| Validate credentials and filter by outcome | [Usage: validation](../usage/basic-scanning.md#display-only-secrets-confirmed-active-by-third-party-apis) |
| Map credential identity, permissions, and resources | [Blast radius](../features/blast-radius.md) |
| Review and prioritize findings in a browser | [Viewer usage](../usage/basic-scanning.md#report-viewer-local-and-hosted), [hosted guide](https://mongodb.github.io/kingfisher/features/report-viewer/) |
| Revoke a supported credential | [Revocation providers](../features/revocation.md) |
| Send alerts to chat or webhook destinations | [Alert webhooks](../usage/alerts.md) |
| Deploy in CI, pre-commit, or a central service | [Deployment](../usage/deployment.md) |
| Tune performance, validation, filtering, or CI behavior | [Advanced configuration](../usage/advanced.md) |
| Track accepted findings without hiding new ones | [Baseline management](../usage/baseline.md) |
| Preserve repository coverage evidence | [Repository audit log](../features/repository-audit.md) |
| Write, import, or verify detection rules | [Rule authoring](../rules/overview.md) |
| Embed Kingfisher in Rust | [Library API](../reference/library.md) |
| Install or maintain the Python distribution | [Python/PyPI](../reference/python-bindings.md) |

## Response Workflow

- [Defender workflow](../usage/defender-workflow.md) — end-to-end detection, validation, notification,
  blast-radius analysis, triage, and revocation.
- [Blast radius](../features/blast-radius.md) — provider coverage, evidence fields, safety boundaries, and
  standalone or scan-integrated commands.
- [Revocation providers](../features/revocation.md) — supported provider actions and operational
  safeguards.
- [Multi-step revocation](../features/multi-step-revocation.md) — authoring lookup-then-revoke HTTP flows.
- [Token revocation support](../features/token-revocation-support.md) — how imported detectors connect to
  Kingfisher-specific containment capabilities.
- [Alert webhooks](../usage/alerts.md) — summary and finding notifications.
- [Repository audit log](../features/repository-audit.md) — scan coverage, lifecycle events, and evidence semantics.

## Detection and Finding Semantics

- [Rule authoring](../rules/overview.md) — Betterleaks TOML, private Kingfisher YAML, regex constraints,
  components, validation, filters, and checksums.
- [Parser-based context verification](../features/context-verification.md) — how assignment context reduces
  false positives.
- [Source parsing](../features/parsing.md) — supported languages and parser pipeline.
- [Finding fingerprints](../features/fingerprints.md) — stable identifiers, deduplication, and `--no-dedup`.
- [Baseline management](../usage/baseline.md) — suppressing accepted findings while detecting new ones.

## Operations and Deployment

- [Installation](../getting-started/installation.md) — package managers, binaries, Docker, source builds, hooks, cache,
  and release-attestation verification.
- [Integrations](../usage/integrations.md) — authentication and commands for every remote scan target.
- [Project configuration](../usage/configuration.md) — `kingfisher.yaml` policy and CLI precedence.
- [Advanced configuration](../usage/advanced.md) — confidence, validation tuning, CI diffs, performance,
  exclusions, updates, and exit codes.
- [Deployment](../usage/deployment.md) — local, CI, centralized, and embedded deployment patterns.

## Development and Project Reference

- [Architecture](../reference/architecture.md) — crates, CLI paths, scanner pipeline, validation, and reporters.
- [Rust library API](../reference/library.md) — embedding the scanner and selecting validation features.
- [Python/PyPI](../reference/python-bindings.md) — Python installation, wheels, and publishing.
- [Benchmarks](../reference/comparison.md) — methodology, performance, network requests, and binary size.
- [Project background](../reference/project.md) — production use, lineage, evolution, and roadmap.
- [Changelog](../changelog.md) — release history.
- [Contributing](https://github.com/mongodb/kingfisher/blob/main/CONTRIBUTING.md) — development workflow and contribution expectations.
- [Security policy](https://github.com/mongodb/kingfisher/blob/main/SECURITY.md) — vulnerability reporting.

## Guidance for LLMs and Automation

1. Read the repository [AGENTS.md](https://github.com/mongodb/kingfisher/blob/main/AGENTS.md) before changing code or documentation.
2. Use `kingfisher scan --format toon` for token-efficient scan output. Add
   `--no-update-check` in reproducible automation.
3. Use structured `validation.outcome` values and finding fingerprints; do not infer state by
   parsing human-readable labels.
4. Treat [USAGE.md](../usage/basic-scanning.md), [CONFIG.md](../usage/configuration.md), and command `--help` as authoritative for
   CLI behavior. Use [ARCHITECTURE.md](../reference/architecture.md) for source routing.
5. Read [RULES.md](../rules/overview.md) before non-trivial detector or schema changes. Generally useful rules
   belong upstream in Betterleaks; organization-specific rules may use Kingfisher YAML.
6. Live validation, blast-radius mapping, alerts, and revocation can make network requests or cause
   external effects. Follow the authorization and safety guidance in the relevant document.
