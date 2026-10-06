---
title: "Token Revocation Support"
description: "Understand the relationship between Betterleaks detectors and Kingfisher's operational revocation capabilities."
---

# Token Revocation Support

The former Kingfisher-owned detection-rule matrix was removed with the previous built-in YAML
catalog. Kingfisher now joins selected imported detector
IDs to safe operational actions in `crates/kingfisher-rules/data/imported-rules-capabilities.yml`.
That overlay contains no candidate detector regexes, but may add narrow operational filters and
capability metadata; it is validated against the pinned catalog during bundle generation.

Revocation is supported for mapped Betterleaks credentials and for Kingfisher custom rules through
`Http`, `HttpMultiStep`, `AWS`, and `GCP` configurations. See
[REVOCATION_PROVIDERS.md](../features/revocation.md) for the current support model and
[RULES.md](../rules/overview.md) for Kingfisher custom-rule authoring details.

Betterleaks 2.x defines [explicit `revoke` expressions](https://github.com/betterleaks/betterleaks/blob/v2.0.0-rc.1/docs/config.md#explicit-credential-revocation).
Kingfisher's importer currently uses its reviewed overlay instead of executing those expressions.
Contribute generally applicable detector and provider improvements upstream; translating new
revocation expressions requires explicit importer support. Until that support exists, extend
the operational capability overlay. Do not
restore detection behavior or provider dispatch by hardcoding removed `kingfisher.*` rule IDs.
