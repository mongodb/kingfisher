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

If your organization or project uses Kingfisher and would like to be included, open an
[issue](https://github.com/mongodb/kingfisher/issues/new/choose) or
[pull request](https://github.com/mongodb/kingfisher/pulls).

## Lineage and Evolution

Kingfisher began as an internal fork of
[Nosey Parker](https://github.com/praetorian-inc/noseyparker), which provided a high-performance
foundation for secret detection.

It has since evolved across nearly every subsystem. Major areas of development include:

- Live validation and provider-specific credential outcome handling.
- Betterleaks- and Veles-derived detector coverage plus private Kingfisher YAML rules.
- Blast-radius analysis, visual triage, and supported credential revocation.
- Baseline management and stable finding fingerprints.
- Parser-based context verification layered on SIMD-accelerated matching.
- Remote targets spanning source hosts, cloud storage, containers, collaboration systems, and API
  development platforms.
- Extraction from archives, office documents, SQLite databases, and Python bytecode.
- Structured TOON, JSON, JSONL, SARIF, BSON, and HTML reporting.
- Cross-platform builds for Linux, macOS, and Windows.

See [Architecture](ARCHITECTURE.md) for the current implementation and
[Changelog](../CHANGELOG.md) for release-by-release development.

## Roadmap and Contributions

Ongoing work includes broader upstream detector coverage, more scan targets, and deeper safe
response capabilities. File a [feature request](https://github.com/mongodb/kingfisher/issues) or
read [CONTRIBUTING.md](../CONTRIBUTING.md) to propose or implement an improvement.

Security vulnerabilities should be reported according to [SECURITY.md](../SECURITY.md).
Kingfisher is licensed under the [Apache License 2.0](../LICENSE).
