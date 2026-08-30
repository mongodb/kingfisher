---
title: "Moving to Kingfisher v2.0.x"
description: "What changes when Kingfisher adopts Betterleaks as its default rule catalog."
---

# Moving to Kingfisher v2.0.x

Kingfisher v2.0.x sources its candidate detector catalog from Betterleaks and selected Veles
detectors. We chose Betterleaks because its rule format is well designed and gives the broader
secret-scanning community a strong path toward one shared, interoperable format.

## What changes

- Candidate detectors are fetched from Betterleaks and selected Veles source files and parsed during
  the Kingfisher build. They are no longer maintained as a second, vendored Kingfisher catalog.
- Betterleaks IDs use the `betterleaks.` namespace and selected Veles IDs use `veles.`. Update
  scripts and rule selectors that refer to former built-in `kingfisher.*` IDs.
- Kingfisher's 1.x YAML rule format remains supported for private, organization-specific custom rules. Use Betterleaks TOML for new generally useful built-in detectors.
- Betterleaks rules continue to participate in Kingfisher validation, blast-radius/access-map analysis, and supported credential revocation through Kingfisher's capability mappings.

The v2 catalog is not a byte-for-byte replacement for every 1.x detector. Families without a 2.x
replacement still require the 1.x YAML catalog through `--rules-path` when that original detector is
needed.

## Why this is a positive change

This move lets MongoDB concentrate on improving the Kingfisher engine: fast scanning, repository and artifact coverage, validation workflows, reporting, blast-radius analysis, revocation, and integrations. Rule development can be abstracted into a community-maintained upstream catalog, so improvements can be shared across tools instead of being reimplemented in separate formats.

If you want a new generally useful Kingfisher rule, please support this direction by creating or improving it in the [Betterleaks repository](https://github.com/betterleaks/betterleaks). Keep the Kingfisher 1.x YAML format for rules that are intentionally private or specific to your environment; see [Kingfisher 1.x Custom Rules](../rules/overview.md).
