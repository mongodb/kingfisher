# kingfisher-rules

Rule definitions and compiled rule database support for Kingfisher.

This crate provides:
- rule syntax and rule model types
- Kingfisher 1.x YAML loading and parsing for custom rules
- an embedded rule database generated from Betterleaks and selected Veles detectors at build time
- `RulesDatabase` compilation for scanning engines

Use this crate with `kingfisher-core` and `kingfisher-scanner` to build reusable scanning workflows.

Building this crate requires outbound HTTPS access. The build downloads Betterleaks `v1.8.0`'s
canonical `config/betterleaks.toml` and the Veles source files selected by the pinned commit in
`data/veles-rules.yml`, converts them, and embeds the generated database in the binary. Kingfisher
does not check in or distribute the upstream rule source. Betterleaks takes precedence when its
pinned catalog covers a Veles detector.

`KINGFISHER_BETTERLEAKS_CONFIG` may point to a local TOML file for controlled importer development;
normal builds fetch the pinned upstream sources. The build also regenerates
`docs-site/docs/rules/builtin-rules.md` from the generated catalog. Kingfisher-only operational
metadata for both imports lives in `data/imported-rules-capabilities.yml`.
