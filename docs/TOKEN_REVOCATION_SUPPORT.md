# Token Revocation Support

The former Kingfisher-owned detection-rule matrix was removed with the previous built-in YAML
catalog. Kingfisher now joins selected imported detector
IDs to safe operational actions in `crates/kingfisher-rules/data/imported-rules-capabilities.yml`.
That overlay contains no candidate detector regexes, but may add narrow operational filters and
capability metadata; it is validated against the pinned catalog during bundle generation.

Revocation is supported for mapped Betterleaks credentials and custom YAML/TOML rules through
`Betterleaks`, `Http`, `HttpMultiStep`, `AWS`, and `GCP` configurations. See
[REVOCATION_PROVIDERS.md](REVOCATION_PROVIDERS.md) for credential-family limits, required inputs,
and the distinction between accepted reports and confirmed revocation; see [RULES.md](RULES.md)
for custom-rule authoring details.

Betterleaks 2.x defines [explicit `revoke` expressions](https://github.com/betterleaks/betterleaks/blob/8f376ff9c31ed5309ac448fe601c5dd21b376155/docs/config.md#explicit-credential-revocation).
Kingfisher imports these expressions, with reviewed overlay actions taking precedence for mapped
detector IDs. Expressions execute only through explicit revocation, never scanning or validation.
Existing YAML/TOML rules and legacy primary actions remain compatible without edits.
Contribute generally applicable detector and provider improvements upstream; maintain reviewed
operational bindings in the capability overlay. Do not restore detection behavior or provider
dispatch by hardcoding removed `kingfisher.*` rule IDs.
