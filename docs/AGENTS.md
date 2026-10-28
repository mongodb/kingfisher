# AGENTS.md

Guidance for editing documentation under `docs/`.

## Scope

- Applies to `docs/` and all files under it.
- This file overrides broader repository guidance for documentation work in this subtree.

## Purpose

- Keep documentation accurate, link-safe, and aligned with the current CLI, library APIs, and repository structure.

## Documentation Conventions

- Prefer concise, task-oriented docs over long narrative prose.
- Use relative links for repo-local documentation (`INSTALLATION.md`, `../README.md`, etc.).
- When adding a new top-level doc that users should discover, update the README documentation table.
- Keep command examples consistent with current CLI syntax and option names.
- When documenting output formats, prefer `toon` for agent/LLM-oriented examples unless human-interactive formatting is the point.

## Link Hygiene

- Check local markdown links after substantial doc edits.
- Prefer fixing broken links by creating or restoring the intended target when the topic is still relevant.
- If a document is intentionally removed, update all inbound links in README and related docs in the same change.

## Diagrams

- Keep Mermaid diagrams simple enough to render reliably in GitHub/Cursor markdown viewers.
- Prefer short labels and fewer crossing arrows over exhaustive detail.
- If one diagram becomes hard to read, split it into a small number of focused diagrams.

## Content Alignment

- State backward compatibility explicitly when documenting rule/schema changes: existing
  Kingfisher YAML and Betterleaks TOML rules must work without edits. New HTTP fallback
  execution uses `--fallbacks`; both primary-reuse booleans default to false. Reusing validation
  does not imply revocation reuse. Explain explicit revocation URL replacement and no mutation failover.
- Document CLI `revoke --fallbacks` as validate-to-select followed by one action, without manual
  `VALIDATION_*` variables. Distinguish SDK snapshot-based revocation and unchanged direct-primary defaults.

- Installation flows belong in `INSTALLATION.md`.
- Platform-specific usage belongs in `INTEGRATIONS.md`.
- Advanced runtime flags and tuning belong in `ADVANCED.md`.
- Library embedding guidance belongs in `LIBRARY.md`.
- Rule-authoring and validation schema guidance belongs in `RULES.md`.
- Architecture overviews belong in `ARCHITECTURE.md`.

## Validation

- For doc-only changes, verify link targets and obvious command/example consistency.
- If examples depend on current crate/module names, confirm they still exist before updating prose.
