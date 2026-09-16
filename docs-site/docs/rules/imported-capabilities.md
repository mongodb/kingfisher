---
title: "Imported Rule Capabilities"
description: "Built-in rule capabilities, validation bindings, bare-token detection, and placeholder exclusions."
---

# Imported Rule Capabilities

`imported-rules-capabilities.yml` is Kingfisher's operational overlay for Betterleaks and Veles rules.
Detection patterns and upstream validation remain owned by their source projects; this file adds
Kingfisher-specific behavior without creating another detector catalog.

## Format

```yaml
version: 1
betterleaks:
  upstream-rule-id:
    bare: true | false
    confidence: low | medium | high
    authoritative: true | false
    validation: Assumed | JWT | MongoDB | CredentialUri | { type: Ethereum, content: private_key | public_key | mnemonic }
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

- `bare` derives a context-free token pattern from the upstream Betterleaks capture. It defaults
  to `false` and is accepted only for supported single-capture layouts; unsupported upstream
  changes fail the build.
- `confidence` overrides the upstream rule confidence. Valid values are `low`, `medium`, and
  `high`.
- `authoritative` controls whether successful validation may classify a finding as an active
  credential. It defaults to `true`. Set it to `false` for broad detection rules whose matches
  must never be reported as active or valid credentials.
- `validation` attaches a Kingfisher validator. It supports `Assumed`, `JWT`, `MongoDB`,
  `CredentialUri`, and configured `Ethereum` validation for `private_key`, `public_key`, or
  `mnemonic` material. `CredentialUri` uses a named `URI` capture, validates HTTPS URIs with
  Basic Auth, dispatches supported database schemes to their typed validators, and leaves other
  unsupported URI schemes unvalidated.
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

## Bare token detection (Betterleaks only)

`bare: true` derives a pattern from the pinned upstream regex at build time; it does not
accept a replacement regex. It removes provider/assignment context before the reported
secret while retaining the secret format, effective scoped flags, and trailing delimiters.
The default is `false`. DeepSeek, Kimi/Moonshot, ZAI/GLM, and Voyage AI enable it in the
bundled overlay. These rules use medium confidence; MiniMax is already context-free upstream.

```yaml
version: 1
betterleaks:
  deepseek-api-key:
    bare: true
    confidence: medium
```

The importer uses `regex-syntax` HIR and requires exactly one nonempty, mandatory top-level
capture (implicit group 1 or explicit `secretGroup = 1`). Alternation/repetition inside that
capture is supported. Multiple captures, captures beneath alternation/repetition, missing
captures, and path-only rules fail import with the rule ID. Unsupported upstream changes
therefore fail the build instead of silently retaining contextual detection.

An assertion-only prefix on an already-bare pattern is preserved. Otherwise the prefix is
replaced by start-of-input or a consumed byte outside `[A-Za-z0-9_-]`. The reported secret
excludes that delimiter. Trailing constraints are retained exactly in meaning; no lookbehind
is introduced. Token lengths and alphabets are not widened, so this does not repair format
variants such as different Anthropic key lengths or missing AWS components.

Upstream filters, components, and validation remain in place. Enabling `bare` changes the full
match and removes evidence of provider identity: review any expressions using the full match
and the validator destination before opting in another rule. Bare matches are candidates;
medium confidence does not disable live validation. Detection-only scans also use the bare
pattern. This is a source-controlled build overlay, not a runtime custom-rule option.

## Placeholder exclusions

The `private-key` filter discards PEM-shaped candidates with fewer than 64 characters
between the BEGIN and END boundaries, including short concatenated source-code placeholders.
This is a conservative size check, not cryptographic validation: retained candidates still use
`Assumed`, and compact Ed25519 PKCS#8 keys remain detectable.

The `mongodb-connection-string` filter excludes passwords consisting entirely of a variable
reference: `$(NAME)`, `${NAME}`, `$NAME`, or `{{ NAME }}` (including dotted template names).
This additional filter does not exclude literal passwords merely because usernames or hosts
are templated, or passwords that mix literal text with variable-like syntax. Existing upstream
filters remain in effect. Filtering occurs before live validation and
also applies to detection-only scans.
