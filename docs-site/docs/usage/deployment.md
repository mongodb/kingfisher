---
title: "Deployment"
description: "Deployment strategies for Kingfisher: self-serve CLI, CI/pre-commit enforcement, centralized scanning, and embedded library."
---

# Deployment Strategies

This guide summarizes practical ways to deploy Kingfisher in teams, CI systems, and shared security workflows.

## Deployment Models

### Self-Serve CLI

Best for developers, security engineers, and incident responders who want a local tool.

- Install via Homebrew, PyPI, Docker, or release binaries.
- Run scans directly against local repositories, remote git hosts, cloud storage, chat exports, and other supported inputs.
- Use `--format toon`, `json`, `sarif`, or `html` depending on whether the consumer is a human, CI system, or another tool.

Good fit:

- local triage
- ad hoc repo reviews
- one-off credential validation or revocation
- pre-commit and developer workstation enforcement

See:

- [INSTALLATION.md](../getting-started/installation.md)
- [USAGE.md](../usage/basic-scanning.md)
- [INTEGRATIONS.md](../usage/integrations.md)

### CI and Pre-Commit

Best for preventing new secrets from landing in repositories.

- Run `kingfisher scan` in CI against the working tree or a branch diff.
- Use pre-commit hooks for developer-side enforcement before code is pushed.
- Emit SARIF when integrating with code scanning or security dashboards.

Common patterns:

- scan the entire repository on protected branches
- scan only changed content in pull request workflows
- fail builds on findings or validated findings depending on policy

See:

- [INSTALLATION.md](../getting-started/installation.md)
- [ADVANCED.md](../usage/advanced.md)

### Centralized Security Scanning

Best for security teams scanning many repositories or data sources from a controlled environment.

- Run Kingfisher from a dedicated automation host, container job, or scheduled workflow.
- Store platform credentials in your existing secret manager and inject them at runtime.
- Prefer structured outputs like JSON, SARIF, or HTML for downstream ingestion and review.
- Use `--blast-radius` when you are authorized to assess blast radius for validated credentials.

Typical centralized inputs:

- GitHub, GitLab, Gitea, Bitbucket, Azure Repos, Hugging Face
- Jira, Confluence, Slack, Microsoft Teams
- S3, GCS, and Docker images

See:

- [INTEGRATIONS.md](../usage/integrations.md)
- [ACCESS_MAP.md](../features/access-map.md)
- [ARCHITECTURE.md](../reference/architecture.md)

### Embedded Library Usage

Best when you want Kingfisher scanning inside another Rust application or service.

- Use `kingfisher-core` for shared content and location types.
- Use `kingfisher-rules` to load or compile rules.
- Use `kingfisher-scanner` for the embeddable scanning API.

This model is useful for:

- internal developer platforms
- custom ingestion pipelines
- security automation services
- specialized report generation

See:

- [LIBRARY.md](../reference/library.md)

## Operational Guidance

- Start with self-serve or CI deployment before building centralized automation.
- Prefer scoped credentials for integrations and validation.
- Use structured output formats when results are consumed by other systems.
- Treat `--blast-radius`, validation, and revocation as privileged operations and run them only where authorized.
- Keep rules and binaries updated together so documentation, features, and provider coverage stay aligned.

## Related Documentation

- [INSTALLATION.md](../getting-started/installation.md)
- [USAGE.md](../usage/basic-scanning.md)
- [ADVANCED.md](../usage/advanced.md)
- [INTEGRATIONS.md](../usage/integrations.md)
- [ACCESS_MAP.md](../features/access-map.md)
- [LIBRARY.md](../reference/library.md)
