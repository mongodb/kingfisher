# Moving to Kingfisher v2.0.x

Kingfisher v2.0.x makes Betterleaks the primary source of its candidate detector catalog, with
selected Veles detectors filling gaps. We chose Betterleaks because its rule format is well
designed and gives the broader secret-scanning community a strong path toward one shared,
interoperable format. Kingfisher-specific validation, filtering, access-map, and revocation
capabilities remain operational behavior layered onto those upstream candidates.

## What changes

- Candidate detectors are fetched from Betterleaks and selected Veles source files and parsed
  during the Kingfisher build. They are no longer maintained as a second, vendored Kingfisher
  catalog.
- Built-in rule IDs use the `betterleaks.` and `veles.` namespaces. Update scripts and rule selectors that refer to former built-in `kingfisher.*` IDs; see [Migrating rule selectors](#migrating-rule-selectors) for the compatibility shim.
- Kingfisher's 1.x YAML rule format remains supported for private, organization-specific custom rules. Use Betterleaks TOML for new generally useful built-in detectors.
- Betterleaks rules continue to participate in Kingfisher validation, blast-radius/access-map analysis, and supported credential revocation through Kingfisher's capability mappings.

## Migrating rule selectors

Built-in rule IDs changed namespace. `--rule`, `--exclude-rule`, and `rules.disabled` entries that
reference 1.x `kingfisher.*` IDs still resolve: Kingfisher maps the 1.x rule *family* to its 2.x
replacements and logs a deprecation warning naming the selector to migrate to.

```console
$ kingfisher scan ./repo --rule kingfisher.aws.1
WARN Rule selector `kingfisher.aws.1` is a Kingfisher 1.x ID. Kingfisher 2.0 renamed the
     built-in catalog; resolving it as `betterleaks.aws` for now. Update your configuration -
     this fallback will be removed in a future release.
```

Notes:

- The alias resolves to the whole provider family, not the single 1.x rule. `kingfisher.aws.1`
  selects every `betterleaks.aws-*` rule, because 1.x ordinals have no 2.x equivalent.
- If you load the 1.x catalog yourself with `--rules-path`, exact `kingfisher.*` IDs match
  directly and the alias fallback does not apply.
- A `kingfisher.*` selector with no known replacement is still an error, so typos are not
  silently ignored.

The mapping covers migrated families with known 2.x replacements and lives in
[`crates/kingfisher-rules/data/legacy-rule-aliases.yml`](../crates/kingfisher-rules/data/legacy-rule-aliases.yml).
It doubles as a coverage guard: every entry must resolve against the built-in catalog, so an
upstream release that drops a replacement fails the build instead of quietly breaking that
compatibility path. Families without a 2.x replacement still require the 1.x catalog through
`--rules-path` if their original detector is needed.

Run `kingfisher rules list` to see the current catalog.

## Why this is a positive change

This move lets MongoDB concentrate on improving the Kingfisher engine: fast scanning, repository and artifact coverage, validation workflows, reporting, blast-radius analysis, revocation, and integrations. Rule development can be abstracted into a community-maintained upstream catalog, so improvements can be shared across tools instead of being reimplemented in separate formats.

If you want a new generally useful Kingfisher rule, please support this direction by creating or improving it in the [Betterleaks repository](https://github.com/betterleaks/betterleaks). Keep the Kingfisher 1.x YAML format for rules that are intentionally private or specific to your environment; see [Kingfisher 1.x Custom Rules](RULES.md).

For the implementation details and known format differences, see [Betterleaks rule parity notes](BETTERLEAKS_RULE_PARITY.md).
