# Token Revocation Support

Betterleaks currently has no revocation metadata. The former Kingfisher-owned detection-rule matrix
was removed with the previous built-in YAML catalog. Kingfisher now joins selected imported detector
IDs to safe operational actions in `crates/kingfisher-rules/data/imported-rules-capabilities.yml`.
That overlay contains no candidate detector regexes, but may add narrow operational filters and
capability metadata; it is validated against the downloaded catalog during the build.

Revocation is supported for mapped Betterleaks credentials and for Kingfisher 1.x custom rules through
`Http`, `HttpMultiStep`, `AWS`, and `GCP` configurations. See
[REVOCATION_PROVIDERS.md](REVOCATION_PROVIDERS.md) for the current support model and
[RULES.md](RULES.md) for Kingfisher 1.x custom-rule authoring details.

New generally applicable revocation metadata should be designed and contributed upstream to
[Betterleaks](https://github.com/betterleaks/betterleaks), then added to Kingfisher's build-time
translation layer. Until that schema exists, extend only the operational capability overlay. Do not
restore detection behavior or provider dispatch by hardcoding removed `kingfisher.*` rule IDs.
