# Secret Revocation

Finding an active credential is not containment. Deleting it from the current branch does not
invalidate copies in Git history, logs, forks, caches, or an attacker's hands.

Kingfisher lets defenders revoke supported leaked credentials directly from the CLI. For
self-revocable credentials and other provider flows that can safely identify the exact key, this
removes a common incident-response dependency: locating the employee who created or leaked the
credential. The responder can contain the risk even when ownership is unclear, the credential
predates the current team, or the original owner has left the company.

Revocation is provider- and credential-specific, not a universal promise. Some APIs require extra
captured values or permissions, and some credential formats cannot safely identify the exact key to
disable. Kingfisher exposes a revoke action only when it has a bounded provider workflow. Always
review the target and operational impact before running it; revocation can interrupt workloads that
still depend on the credential.

Kingfisher supports direct revocation for selected built-in imported detectors and custom rules in
the Kingfisher YAML or Betterleaks TOML formats. The generated catalog now has **42 revocation
bindings** across **502 built-in rules**. A binding does not imply support for every
credential format matched by that detector.

Reviewed operational actions live in the
[capability overlay](../crates/kingfisher-rules/data/imported-rules-capabilities.yml), the authoritative
exact-ID list. It contains no candidate detector regexes; entries join the pinned catalog by upstream
ID during bundle generation. Overlay actions take precedence over imported `revoke` expressions.
Custom Betterleaks TOML `revoke` expressions are also supported; see [custom rules](#custom-rules).

## Provider coverage and limits

The [provider contracts](../crates/kingfisher-rules/data/revocation-sources.md#inputs-and-limits) detail
required inputs and response checks, with [first-party API and pinned SDK sources](../crates/kingfisher-rules/data/revocation-sources.md#first-party-provenance).
Coverage is credential-specific:

| Provider | Supported action and inputs | Limits / confirmation |
| --- | --- | --- |
| Notion | App-owned OAuth access token: `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`; introspect, revoke, introspect again. | Requires active before and inactive after. Internal integration tokens and PATs require manual owner action in integration settings. |
| Hugging Face | Access / organization tokens: unauthenticated credentials report. | Always 202, even for nonexistent tokens: accepted, not proof of validity or completed invalidation. Existing behavior is unchanged. |
| Vercel | Personal / integration tokens: current-token deletion. OAuth: app client ID (`VERCEL_APP_CLIENT_ID` or `NEXT_PUBLIC_VERCEL_APP_CLIENT_ID`) and `VERCEL_APP_CLIENT_SECRET`. AI Gateway: `VERCEL_OWNER_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_AI_GATEWAY_KEY_ID`, `VERCEL_AI_GATEWAY_KEY_VALUE`. | Existing personal/integration/OAuth behavior is unchanged; OAuth access-token revocation also revokes its associated refresh token. AI Gateway deletes one attested key, requires 204; masked `partialKey` is insufficient. The compromised-secret report endpoint is not used. |
| Resend | Full-access `RESEND_ADMIN_API_KEY`, `RESEND_API_KEY_ID`, `RESEND_API_KEY_VALUE`; delete one key UUID. | Sending-only credentials cannot manage keys. Requires 200, `object: api_key`, exact ID, and boolean `deleted: true`. |
| RubyGems | Owner/manual or authorized-partner flow only; no automatic built-in action. | Owner deletes/rotates the individual key in the account UI. Partner reporting requires an authorized signature over the exact request body, not ordinary RubyGems credentials. Never substitute an account-wide reset. |
| Twilio | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`; delete the detected `SK…` API key SID. | The detected value is an identifier, not the API-key secret. Requires 204; the binding targets US1 and needs matching regional management credentials. Does not rotate Auth Tokens. |
| GitHub | PAT / fine-grained PAT / OAuth / refresh: existing unauthenticated credentials report. App user access tokens (`ghu_`): new report action. | Existing 202 success flags mean accepted, not confirmed completion or per-token validity. New `ghu_` reports return indeterminate / `unknown` on 202. Installation tokens (`ghs_`) are unsupported and rejected before HTTP. |
| Slack | User / bot / legacy workspace tokens: existing `auth.revoke`. | Requires `ok: true` and `revoked: true`; bot revocation can deactivate the bot/remove memberships. App-level (`xapp-`) and configuration access/refresh tokens are unsupported; rotation or app deletion/uninstallation is not a substitute. Legacy bindings do not establish support for those types. |
| GCP | API key: separate `GCP_ACCESS_TOKEN`, exact full-key lookup, delete returned resource, at most one operation GET. Service-account key: existing detected-JSON-key IAM deletion. | API-key deletion needs lookup/delete IAM permissions and cloud-platform scope; requires completed, error-free operation for the exact key resource. Pending/error/unrecognized operations are unknown: inspect before retrying. Soft deletion is recoverable for 30 days. Service-account-key deletion does not delete the account or invalidate already issued short-lived credentials. |
| Anthropic | Ordinary API key: separate `ANTHROPIC_ADMIN_KEY`, `ANTHROPIC_API_KEY_ID`, `ANTHROPIC_API_KEY_VALUE`; set inactive. | Requires 200, `type: api_key`, exact ID, `status: inactive`. No documented raw-key-to-ID lookup. Admin-key revocation is unsupported and requires manual owner action. |
| OpenAI | Project / service-account-owned key: separate `OPENAI_ADMIN_KEY`, `OPENAI_PROJECT_ID`, `OPENAI_API_KEY_ID`, `OPENAI_API_KEY_VALUE`. Admin key (`sk-admin-`): same inputs except project ID; separate admin-key endpoint. | Deletes only the attested key, never the service account. Requires 200, exact ID, boolean `deleted: true`, and the project/admin deletion object type. Legacy organization keys without a known project mapping need owner intervention. |

Other existing actions include AWS access keys, GitLab PAT formats, Buildkite, Cloudflare, crates.io,
DigitalOcean, Doppler, Heroku, npm, and Twitch credentials. Consult the overlay for exact detector IDs;
Kingfisher must never guess which credential to disable.

### Owner-ID attestation and runtime variables

For Vercel AI Gateway, Resend, Anthropic ordinary keys, and OpenAI keys, each `*_KEY_VALUE` must equal
the **entire current secret before any HTTP request**. Supply its exact key ID and a separate,
authorized management credential, plus the project/team ID where required. This is an explicit owner
attestation, not a provider-verified lookup: obtain the full-secret-to-key-ID association from trusted
creation records. Never infer it from names, masked prefixes/suffixes, timestamps, list order, or a
neighboring user/service-account ID. Missing inputs or malformed IDs fail closed before mutation.

Expression `env.get` reads supplied runtime variables, not the process environment. **Exporting a
variable alone is insufficient:** pass each input explicitly with `--var NAME=value`, or through the
SDK variables map. For example:

```bash
kingfisher revoke --rule gcp-api-key \
  --var "GCP_ACCESS_TOKEN=$GCP_ACCESS_TOKEN" \
  "$LEAKED_GCP_API_KEY"
```

The existing GitHub/Hugging Face 202-only primary matchers and success flags are preserved; they mean
report acceptance, not verified completion. The new GitHub App action deliberately reports 202 as
`revocation_status: unknown`. All new mutation flows make one attempt: transport failures or
unconfirmed results must not trigger automatic retries or alternate mutation endpoints. GCP's one
read-only operation check is bounded, not a polling loop. Scanning and validation never revoke.

Examples:

```bash
kingfisher revoke --rule github-pat "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

kingfisher revoke --rule aws-access-token \
  --var AKID=AKIAIOSFODNN7EXAMPLE \
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### AWS access keys

By default, AWS revocation uses the supplied long-term access key to identify its IAM user and
deactivate itself. Kingfisher resolves the caller with STS and sends the IAM username explicitly,
making IAM resource evaluation unambiguous. AWS permits self-management requests to omit the user
name, and supplying it does not grant permission: the target key still needs
`iam:UpdateAccessKey`. Temporary `ASIA` credentials cannot be revoked through the IAM access-key
APIs and are rejected before mutation.

For an incident-response principal with permission to manage the target user's keys, opt in to a
named profile and identify the target user:

```bash
kingfisher revoke --rule aws-access-token \
  --var AKID=AKIAIOSFODNN7EXAMPLE \
  --aws-profile incident-response \
  --aws-user-name srv-example \
  --aws-action deactivate \
  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Use `--aws-use-default-credentials` instead of `--aws-profile` to opt in to the AWS SDK default
credential chain, such as an instance, container, or workload role. Kingfisher never falls back to
ambient AWS credentials implicitly. `--aws-action deactivate` is the default and is reversible;
`--aws-action delete` is irreversible and must be selected explicitly.

The responder configuration's resolved region is preserved. Use `--aws-region` to select a different
region explicitly; this is required for self-revocation in AWS GovCloud or China partitions. The
CLI timeout applies to each AWS request, while `--retries` applies only to HTTP 429 responses on
read-only lookup steps in configurable HTTP revocation. Custom HTTP mutations are never retried;
a 429 after submission is an unknown outcome because the mutation may already have been applied.
HTTP failure messages expose safe error categories without rendered URLs or credentials.
STS identity lookups have bounded read retries. IAM mutations retry only definitive
throttling responses, with at most three attempts; ambiguous failures are not retried.

AWS permission failures are not repaired by retrying the same request. If the response is lost
after IAM may have accepted a mutation, Kingfisher reports an unknown outcome rather than claiming
failure or attempting a more destructive fallback. Verify the key state with separately authorized
credentials before retrying. JSON and TOON output expose this as `revocation_status: unknown`.

Deactivating or deleting a long-term key does not invalidate STS sessions already created from it;
those sessions can remain usable until they expire or are revoked separately.

## Custom rules

Kingfisher YAML custom rules may define these `revocation:` types:

- `Http` for a single provider API request
- `HttpMultiStep` for lookup-then-delete workflows (up to two steps)
- `AWS` for IAM access-key revocation
- `GCP` for service-account key revocation
- `Betterleaks` for an explicit expression program (`content.expression`)

Custom Betterleaks TOML rules support `revoke` expressions and load through the same `--rules-path`
option; their IDs receive the `custom.` namespace. See [expression programs](RULES.md#betterleaks-v2-programs).
Revocation runs only through the explicit revoke command/API, never during scanning or validation.
Existing Kingfisher YAML and Betterleaks TOML rules continue to work without edits; legacy primary
validation and revocation defaults are unchanged.

Without `--fallbacks`, direct revocation remains primary-only and adds no validation requests.
`revoke --fallbacks` validates to select an environment, then executes only its action, with no
mutation failover; SDK result-based revocation instead retains its validation snapshot. Both
`reuse_primary_validation_logic` and `reuse_primary_revocation_logic` default to false. Validation
reuse does not imply revocation reuse; revocation reuse needs explicit replacement URL(s), never
implicit primary destinations. See [HTTP fallbacks](RULES.md#ordered-http-fallback-endpoints).

Invoke a Kingfisher YAML custom revocation rule with:

```bash
kingfisher revoke \
  --rules-path ./custom-rules.yml \
  --rule custom.provider.token \
  "secret"
```

See [USAGE.md](USAGE.md#direct-secret-revocation-with-kingfisher-revoke) for the command and
[RULES.md](RULES.md) for the Kingfisher custom-rule schema.
