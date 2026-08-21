---
title: "Moving to Kingfisher v2.0.x"
description: "What changes when Kingfisher adopts Betterleaks as its default rule catalog."
---

# Moving to Kingfisher v2.0.x

Kingfisher v2.0.x makes Betterleaks the default source of built-in detection rules. We chose Betterleaks because its rule format is well designed and gives the broader secret-scanning community a strong path toward one shared, interoperable format.

## What changes

- Built-in rules are fetched from Betterleaks and parsed during the Kingfisher build. They are no longer maintained as a second, vendored Kingfisher catalog.
- Built-in rule IDs use the `betterleaks.` namespace. Update scripts and rule selectors that refer to former built-in `kingfisher.*` IDs.
- Kingfisher's 1.x YAML rule format remains supported for private, organization-specific custom rules. Use Betterleaks TOML for new generally useful built-in detectors.
- Betterleaks rules continue to participate in Kingfisher validation, blast-radius/access-map analysis, and supported credential revocation through Kingfisher's capability mappings.

## Why this is a positive change

This move lets MongoDB concentrate on improving the Kingfisher engine: fast scanning, repository and artifact coverage, validation workflows, reporting, blast-radius analysis, revocation, and integrations. Rule development can be abstracted into a community-maintained upstream catalog, so improvements can be shared across tools instead of being reimplemented in separate formats.

If you want a new generally useful Kingfisher rule, please support this direction by creating or improving it in the [Betterleaks repository](https://github.com/betterleaks/betterleaks). Keep the Kingfisher 1.x YAML format for rules that are intentionally private or specific to your environment; see [Kingfisher 1.x Custom Rules](../rules/overview.md).

For the implementation details and known format differences, see the repository's `private-notes/BETTERLEAKS_RULE_PARITY.md` file when working from a checkout.
