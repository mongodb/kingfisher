# AGENTS.md

Rule-authoring instructions for this directory.

## Scope
- Applies to `crates/kingfisher-rules/data/rules/` and all files under it.
- This file overrides broader AGENTS guidance for rule-writing tasks in this subtree.

## Goal
- Add or update YAML detection rules with high precision, low false positives, and safe remediation support.

## Rule File Conventions
- Keep provider rules in provider-named files (for example `github.yml`, `openai.yml`).
- Prefer lowercase filenames with `.yml`.
- Keep rule IDs stable and unique. Prefer `kingfisher.<provider>.<number>` unless a descriptive suffix is already established for that provider.
- Reuse nearby provider patterns/styles instead of inventing new structure.

## Required Rule Shape
Each rule entry should define:
- `name`
- `id`
- `pattern`
- `min_entropy` (use 3.0 as an authoring baseline; the schema default is 0.0)
- `confidence` (default to medium)
- `examples` (at least one realistic positive example)

Strongly recommended fields:
- `pattern_requirements` (for extra filtering)
- `references`

## Pattern Quality Rules
- Prefer specific anchors/prefixes and provider context over broad generic regex.
- Keep helper/context regex narrow. Avoid patterns that match generic URLs, hostnames, query params, or assignments without strong provider-specific constraints; broad helpers can create huge match counts and cause major memory/time regressions on large repos and git history.
- When the token format is generic or common-looking (for example bare 32-hex keys), prefer contextual patterns of the form: provider keyword -> short flexible gap -> key/secret label -> short flexible gap -> token. A good default is:
  - `\b`
  - provider identifier (for example `amplitude`, `azure`, `speech`, `translator`)
  - `(?:.|[\n\r]){0,N}?`
  - common credential labels such as `(?:SECRET|PRIVATE|ACCESS|KEY|TOKEN|AUTHORIZATION|API)`
  - `(?:.|[\n\r]){0,M}?`
  - the token capture wrapped in a single unnamed capture group
- Do not add surrounding context when the token is already strongly self-identifying by prefix or structure (for example `sk-ant-api...`, `AstraCS:...`, `dvc_client_...`, `secret-test-...`). In those cases, prefer the tighter self-identifying regex.
- Use `pattern_requirements` to enforce quality constraints (`min_digits`, `min_uppercase`, `min_lowercase`, `min_special_chars`, `ignore_if_contains`, `checksum`).
- Use checksum validation in `pattern_requirements.checksum` when token formats support it. This is preferred when the provider token format includes a documented or reverse-engineered check segment, because it can sharply reduce false positives without adding brittle surrounding context.
- For checksum-based rules, prefer named captures for the main token body and checksum suffix/prefix, then compute the expected checksum in Liquid. A typical pattern is:
  - `(
      prefix_(?P<body>...)(?P<checksum>...)
    )`
  - with:
    - `actual.template: "{{ checksum }}"`
    - `actual.requires_capture: checksum`
    - `expected: "{{ body | <checksum-filter> | <encoding/filter chain> }}"`
    - `skip_if_missing: true`
- Example: GitHub PATs use a CRC32-derived base62 checksum. The rule in `github.yml` captures `body` and `checksum`, then compares `{{ checksum }}` against `{{ body | crc32 | base62: 6 }}`.
- Prefer checksum validation over extra loose context whenever the token structure itself supports it. If the checksum is only present on some token generations, keep `skip_if_missing: true` so older examples continue to load safely.
- Use POSIX character classes for token alphabets. Relevant classes (written as `[[:name:]]`):
  - `[:alnum:]` — letters and digits `[a-zA-Z0-9]` (the default for most tokens)
  - `[:alpha:]` — letters only `[a-zA-Z]`
  - `[:digit:]` — digits only `[0-9]` (no letters)
  - `[:lower:]` — lowercase letters only `[a-z]`; under `(?i)`/`(?xi)` also matches uppercase
  - `[:upper:]` — uppercase letters only `[A-Z]`; under `(?i)`/`(?xi)` also matches lowercase
  - `[:xdigit:]` — hex digits `[0-9A-Fa-f]` (case-insensitive regardless of `(?i)`)
  - `[:space:]`, `[:blank:]`, `[:punct:]`, `[:graph:]`, `[:print:]`, `[:cntrl:]` — structural classes
  - Classes combine inside one bracket: `[[:alnum:]_=-]` adds `_`, `=`, `-` to alphanumerics.
- Use `visible: false` for helper/non-secret captures used only by dependent rules.
- Use `depends_on_rule` for multi-part credential validation (for example ID + secret).

## Validation Policy (Important)
- Default: define validation logic in YAML under `validation:`.
- Do not move validation logic into Rust unless YAML cannot reliably express it.
- For new rules, first attempt `Http`/`Grpc` YAML validation before considering exception paths.
- Typed validation kinds such as `AWS`, `AzureStorage`, `Coinbase`, `GCP`, `MongoDB`, `MySQL`, `Postgres`, `Jdbc`, and `JWT` are schema-level validator families. Use them when an existing typed validator already matches the problem.
- `validation: { type: Raw, content: <name> }` is the ad-hoc exception path for provider-specific or protocol-specific flows that cannot be expressed cleanly in YAML. Raw implementations live in `crates/kingfisher-scanner/src/validation/raw.rs`.
- When Rust validation is unavoidable for a one-off provider, prefer adding a raw validator instead of inventing a new typed validator.
- Do not convert existing typed validators to `Raw` just for consistency.

## HTTP Validation Request Capabilities
The `validation.content.request` block under `type: Http` supports these fields:
- `method` (required): `GET`, `POST`, `DELETE`, `HEAD`, `PUT`, etc.
- `url` (required): target URL; supports Liquid templating (`{{ TOKEN }}`, filters, etc.)
- `headers` (optional): map of header name → value; supports Liquid templating.
- `body` (optional): request body string; supports Liquid templating. Use with `Content-Type: application/x-www-form-urlencoded` for form-encoded POST bodies or `application/json` for JSON bodies.
- `multipart` (optional): multipart form data; use for file-upload endpoints.
- `response_is_html` (optional, bool): allow HTML responses (default false).

Useful Liquid filters for bodies and headers: `b64enc`, `url_encode`, `append`, `crc32`, `base62`.

**OAuth client credential validation pattern** — when a provider's token endpoint accepts `grant_type=authorization_code`, send an invalid code with real credentials. Valid credentials return `400` (bad code); invalid credentials return `401` (bad client). Example body:
```
grant_type=authorization_code&client_id={{ CLIENT_ID | url_encode }}&client_secret={{ TOKEN | url_encode }}&code=invalid&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback
```
Pair with `StatusMatch: [400]` and `JsonValid`.

## Revocation Policy
- If a rule has validation and the provider API safely supports revocation, add `revocation:` in the same YAML rule.
- Prefer explicit success criteria in `response_matcher`.
- Use `HttpMultiStep` revocation when API workflows require pre-fetch/extraction steps.
- If revocation is intentionally not supported, document why with an inline YAML comment.

## Authoring Workflow
1. Choose the target provider file (or add a new provider file if no suitable file exists).
2. Copy a structurally similar rule from this directory.
3. Implement/adjust `pattern`, `examples`, and filtering (`pattern_requirements`, `min_entropy`).
4. Add YAML `validation` (default path). Prefer `Http`/`Grpc`; if that fails, use an existing typed validator or `type: Raw` only when justified.
5. Add YAML `revocation` when supported.
6. Add `references` for token format/API behavior.
7. Verify locally (below).

## Local Verification Checklist
- Syntax/load checks:
  - `cargo test -p kingfisher-rules`
  - `kingfisher rules check --rules-path crates/kingfisher-rules/data/rules/<file>.yml --load-builtins=false --no-update-check`
- Broader regression check:
  - `cargo test --workspace --all-targets`
- Match-volume check on a realistic large target:
  - `kingfisher scan <large-repo-or-test-corpus> --rule-stats`
  - Review unexpected high-match helper/generic rules before submitting.
- **Warning-free build**: `cargo check` (or `make darwin` / `make linux`) must produce zero warnings. Address all `dead_code`, `unused_*`, and other warnings before submitting. Use `#[allow(dead_code)]` on individual struct fields kept for deserialization completeness, and remove truly unused code.
- Behavioral check against sample content:
  - `kingfisher scan ./testdata --rule <rule-family-or-id> --rule-stats`
- Validation check (when validation is present):
  - `kingfisher validate --rule <rule-id> <token-or-secret>`

## Documentation
Read these before complex edits:
- `docs/RULES.md` (schema, pattern requirements, checksum, Liquid, validation/revocation)
- `docs/MULTI_STEP_REVOCATION.md`
- `docs/TOKEN_REVOCATION_SUPPORT.md`

## Change Discipline
- Keep changes scoped to the specific provider/rule request.
- Do not refactor unrelated rules in the same PR unless explicitly asked.
- Preserve existing YAML style and indentation conventions in this directory.
