# kingfisher-rules

Rule definitions and compiled rule database support for Kingfisher.

This crate provides:
- rule syntax and rule model types
- Kingfisher 1.x YAML loading and parsing for custom rules
- an embedded rule database generated from Betterleaks and selected Veles detectors at build time
- `RulesDatabase` compilation for scanning engines

Use this crate with `kingfisher-core` and `kingfisher-scanner` to build reusable scanning workflows.

Building this crate requires outbound HTTPS access. Kingfisher's candidate detector catalog is
sourced from Betterleaks and selected Veles detectors. The build downloads the pinned Betterleaks
catalog snapshot from its [source permalink](https://github.com/betterleaks/betterleaks/blob/2ba7943682b82a3659a89dae8fc680de1ef6b781/config/betterleaks.toml)
and the Veles source files selected by the pinned commit in `data/veles-rules.yml`, converts them,
and embeds the generated database in the binary. The importer and Kingfisher runtime add effective
matching, filtering, validation, access-map, and revocation behavior around those candidates. A
Betterleaks release is preferred; the current post-release commit is pinned because the latest
release predates detectors that Kingfisher ships.
Kingfisher does not check in or distribute the upstream rule source. Betterleaks takes precedence
when its catalog covers a Veles detector.

`KINGFISHER_BETTERLEAKS_CONFIG` may point to a local TOML file for controlled importer development;
normal builds fetch the configured upstream sources. The build also regenerates
`docs-site/docs/rules/builtin-rules.md` from the generated catalog. Kingfisher-only operational
metadata for both imports lives in `data/imported-rules-capabilities.yml`.
