# AGENTS.md

Guidance for working in `src/access_map/`.

## Scope

- Applies to `src/access_map/` and all files under it.
- This file overrides broader repository guidance for this subtree.

## Purpose

- Keep access-map providers consistent, read-only by default, and aligned with the shared result model.

## Provider Layout

- Prefer one provider per file.
- Keep provider-specific HTTP/API logic inside the provider module.
- Shared rendering belongs in `report.rs`; shared types and dispatch stay in `src/access_map.rs`.

## Behavioral Rules

- Access map should inspect blast radius, not modify remote state.
- Prefer read-only enumeration and metadata lookups.
- If a provider requires best-effort probing because APIs are limited, document that behavior clearly in code comments or docs.
- Return partial but useful results instead of failing hard when a provider can still identify the principal or some resources.

## Result Shape

- Populate `AccessMapResult` consistently: identity, roles, permissions, resources, severity, recommendations, and risk notes.
- Use provider-specific metadata only when it adds clear value and fits the shared schema.
- Keep severity and recommendation logic understandable and comparable across providers.

## Wiring Checklist

- Add the provider module here.
- Wire the provider into `src/access_map.rs`.
- Wire the CLI enum/aliases in `src/cli/commands/access_map.rs`.
- Update `docs/BLAST_RADIUS.md` and any relevant README/docs mentions.
- If scan-time auto-collection should support the provider, verify the validation-to-access-map path too.

## Testing

- Prefer focused tests around result shaping, severity classification, and graceful handling of partial permissions.
- Avoid introducing provider implementations that require destructive credentials or side effects for normal verification.
