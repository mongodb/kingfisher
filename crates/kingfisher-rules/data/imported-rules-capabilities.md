# Imported Rule Capabilities

`imported-rules-capabilities.yml` is Kingfisher's operational overlay for pinned Betterleaks and
Veles rules. Detection patterns and upstream validation remain owned by their source projects; this
file adds Kingfisher-specific behavior without creating another detector catalog.

## Format

```yaml
version: 1
betterleaks:
  upstream-rule-id:
    confidence: low | medium | high
    authoritative: true | false
    validation: Assumed | JWT | MongoDB | { type: Ethereum, content: private_key | public_key | mnemonic }
    validation_override: 'Betterleaks validation expression'
    filter_override: 'Betterleaks filter expression'
    tls_mode: strict | lax | off
    access_map:
      handler: provider
      inputs:
        input_name: finding.secret | components.component-rule-id
      reachable_2xx: true | false
    revocation:
      # Kingfisher revocation definition
    revocation_bindings:
      secret: finding.secret | components.component-rule-id
      variables:
        NAME: finding.secret | components.component-rule-id
veles:
  secrets/upstream-plugin-id:
    revocation:
      # Kingfisher revocation definition
```

## Fields

- `confidence` overrides the upstream rule confidence. Valid values are `low`, `medium`, and
  `high`.
- `authoritative` controls whether successful validation may classify a finding as an active
  credential. It defaults to `true`. Set it to `false` for broad detection rules whose matches
  must never be reported as active or valid credentials.
- `validation` attaches a Kingfisher validator. It supports `Assumed`, `JWT`, `MongoDB`, and
  configured `Ethereum` validation for `private_key`, `public_key`, or `mnemonic` material.
- `validation_override` replaces an upstream Betterleaks validation expression.
- `filter_override` adds a filter to the upstream Betterleaks filter expression. A filter returning
  true discards the finding.
- `tls_mode` declares how strictly the rule's validator should verify TLS certificates. Valid
  values are `strict` (default), `lax`, and `off`. Betterleaks has no equivalent concept, so this
  is a Kingfisher operational capability. It is **opt-in on both sides**: a rule declaring `lax`
  still gets full WebPKI verification unless the operator also runs with `--tls-mode lax`
  (`--tls-mode off` relaxes every rule regardless). Use it for validators that legitimately reach
  self-managed endpoints presenting private-CA or self-signed certificates — databases, JWKS
  endpoints on self-hosted IdPs — and not to paper over a broken certificate chain on a public
  SaaS API. The build rejects a `tls_mode` on a rule that has no validator, since it would have no
  effect.
- `access_map` selects a provider mapper and optionally supplies component values. `reachable_2xx`
  permits access mapping on a reachable 2xx response when the validator is otherwise inconclusive.
- `revocation` defines a Kingfisher revocation action.
- `revocation_bindings` maps the finding secret and validator variables to the detected secret or
  component captures. Bindings require a Betterleaks validation expression and a revocation action.

Betterleaks keys are unqualified upstream IDs such as `mongodb-connection-string`, not generated
`betterleaks.mongodb-connection-string` IDs. Veles keys, when present, are upstream plugin IDs rather than
generated `veles.*` IDs. Every entry must match a pinned, selected source rule; the build rejects
stale and unselected IDs.
