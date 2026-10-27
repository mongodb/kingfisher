# Project Background

[← Back to README](../README.md)

## Production Use and Integrations

Kingfisher is used in production security workflows and integrated into other open source tools.
These public references are not an exhaustive list:

- [MongoDB](https://www.mongodb.com/company/blog/product-release-announcements/introducing-kingfisher-real-time-secret-detection-validation)
  uses Kingfisher in internal security workflows including pre-commit scanning, CI/CD integration,
  historical code analysis, and cloud and database validation.
- [Prowler](https://prowler.com/blog/whats-new-in-prowler-july-2026) uses Kingfisher as an offline
  secret-scanning engine with optional live validation.
- [MegaLinter](https://megalinter.io/latest/descriptors/repository_kingfisher/) distributes
  Kingfisher as the `REPOSITORY_KINGFISHER` linter in its standard and security flavors.
- [Osmedeus](https://github.com/j3ssie/osmedeus/blob/main/platform/osmedeus-workflow/fragments/do-scan-repo.yaml)
  runs Kingfisher in repository scans and imports its SARIF findings.
- [DefectDojo](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/kingfisher.md)
  imports Kingfisher JSON reports for vulnerability management.
- [hk](https://github.com/jdx/hk/blob/main/pkl/builtins/kingfisher.pkl) includes a built-in
  Kingfisher secret-scanning check.
- [Weblate](https://github.com/WeblateOrg/weblate/blob/main/.pre-commit-config.yaml) configures
  Kingfisher as a developer pre-commit hook.

If your organization or project uses Kingfisher and would like to be included, open an
[issue](https://github.com/mongodb/kingfisher/issues/new/choose) or
[pull request](https://github.com/mongodb/kingfisher/pulls).

## Lineage and Evolution

Kingfisher started as an internal fork of
[Nosey Parker](https://github.com/praetorian-inc/noseyparker), building on its fast Rust and
Vectorscan scanning engine. Since then, MongoDB has expanded it into a tool for finding exposed
secrets, checking which credentials still work, understanding what they can access, and revoking
them where supported.

Kingfisher's additions cover the full workflow:

| Area | What Kingfisher adds |
| --- | --- |
| **Live credential validation** | HTTP, gRPC, and provider-specific checks that distinguish active credentials, inactive credentials, and inconclusive results. Known secrets can also be checked directly with `validate`. |
| **[Blast-radius mapping](BLAST_RADIUS.md)** | Provider-specific identity, permission, and resource discovery to help teams understand what an exposed credential can reach. Available during scans and through the standalone `blast-radius` command. |
| **[Credential revocation](MULTI_STEP_REVOCATION.md)** | Explicit revocation of supported credentials, including multi-step provider API workflows and a standalone `revoke` command. |
| **[More source hosts](INTEGRATIONS.md)** | Native enumeration and scanning for GitLab, Azure Repos, Gitea, Bitbucket, and Hugging Face, alongside expanded GitHub support. |
| **[Repository content beyond code](INTEGRATIONS.md)** | Scanning of issues, wikis, gists, and snippets, including gist and snippet history where supported. |
| **[Cloud storage and containers](INTEGRATIONS.md)** | S3, Google Cloud Storage, Azure Blob Storage, Hugging Face buckets, and Docker/OCI images and image archives. |
| **[Collaboration and API platforms](INTEGRATIONS.md)** | Secrets discovery in Jira, Confluence, Slack, Microsoft Teams, and Postman workspaces, collections, and environments. |
| **[Content extraction](ADVANCED.md)** | Scanning inside archives, office documents, SQLite databases, and Python bytecode. |
| **[Detection and filtering](CONTEXT_VERIFICATION.md)** | Base64 secret discovery, entropy and checksum checks, and targeted HTML/CSS context verification to reduce noisy matches. |
| **[Multi-part credentials](RULES.md)** | Association of nearby keys, secrets, endpoints, and other supporting values so complete credentials can be validated together. |
| **[Upstream detector coverage](RULES.md)** | A catalog built from pinned Betterleaks and selected Veles sources, with reproducible generation, archived licenses, and provenance hashes. Kingfisher adds validation, access-map, and revocation capabilities to imported detectors. |
| **[Custom rules](RULES.md)** | Support for both Kingfisher YAML and Betterleaks TOML. Kingfisher's rule schema also supports HTTP/gRPC validation, Liquid templates, component dependencies, filters, checksums, and revocation definitions. |
| **[CI and developer workflows](ADVANCED.md)** | [Baselines](BASELINE.md) and [finding fingerprints](FINGERPRINT.md) for tracking known findings, plus staged-file, branch, and commit-range scanning for focused checks. |
| **[Repository coverage and audit](AUDIT_LOG.md)** | Per-repository discovery, fetch, and scan status, resolved Git revisions, scan scope, timing, and incremental audit logs. |
| **Visual triage** | A local browser viewer with finding filters and an interactive blast-radius graph, plus an optional [native scan wizard and report workspace](WIZARD.md). |
| **[Additional report formats](USAGE.md)** | Token-efficient TOON for agents and LLMs, BSON, and standalone HTML audit reports, with credential validation and blast-radius context in supported outputs. |
| **[Notifications](ALERTS.md)** | Filtered scan summaries and finding details sent to Slack, Teams, Discord, Mattermost, Google Chat, or generic webhooks. |
| **[Rust](LIBRARY.md) and [Python](PYPI.md) SDKs** | Reusable scanning APIs with separate validation and revocation operations. Python calls the native engine in process; detection can run entirely offline. |
| **[Native Windows support](INSTALLATION.md)** | Windows builds alongside Linux and macOS, across x64 and ARM64. |

The application has changed underneath these features, too. Kingfisher replaces the SQLite-backed
scan datastore with in-memory findings storage and optional temporary disk offload. Its scan
pipeline brings discovery, detection, validation, access mapping, and reporting into one run,
backed by shared core, rules, and scanner crates, reusable scanner pools, and bounded regex
confirmation.

See [Architecture](ARCHITECTURE.md) for the current implementation and
[Changelog](../CHANGELOG.md) for release-by-release development.

## Roadmap and Contributions

Ongoing work includes broader upstream detector coverage, more scan targets, and deeper safe
response capabilities. File a [feature request](https://github.com/mongodb/kingfisher/issues) or
read [CONTRIBUTING.md](../CONTRIBUTING.md) to propose or implement an improvement.

Security vulnerabilities should be reported according to [SECURITY.md](../SECURITY.md).
Kingfisher is licensed under the [Apache License 2.0](../LICENSE).
