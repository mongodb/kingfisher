# Provider revocation contracts

These operational bindings live in [the capability overlay](imported-rules-capabilities.yml),
not in a separate detector catalog. They use first-party API contracts and compatible SDKs;
no SDK implementation is copied. Revocation is an explicit destructive action, never part of
ordinary detection or validation. Existing custom YAML/TOML and existing primary actions are
unchanged; additions use the existing HTTP and expression engines.

## Inputs and limits

| Provider / credential | Action and operator inputs | Confirmation / limits |
| --- | --- | --- |
| Notion OAuth access token | App `NOTION_CLIENT_ID`, `NOTION_CLIENT_SECRET`; introspect the exact candidate, revoke it, introspect again | Requires active before and inactive after. Internal integration tokens and PATs have no supported automatic path; use the owner's integration settings. |
| Hugging Face access / organization token | Existing unauthenticated `POST /api/credentials/revoke` with the raw token | Always 202, including nonexistent tokens. Acceptance is not proof of prior validity or completed invalidation. |
| Vercel AI Gateway | `VERCEL_OWNER_TOKEN`, `VERCEL_TEAM_ID`, `VERCEL_AI_GATEWAY_KEY_ID`, `VERCEL_AI_GATEWAY_KEY_VALUE`; delete that one key | 204 only. The owner must supply an exact full-key-to-ID mapping; `partialKey` is insufficient. |
| Vercel personal / integration / OAuth | Existing current-token deletion or OAuth revoke with app client credentials | Existing behavior preserved. OAuth access-token revocation also revokes its associated refresh token. |
| Resend | Full-access `RESEND_ADMIN_API_KEY`, `RESEND_API_KEY_ID`, `RESEND_API_KEY_VALUE`; delete one UUID | 200, `object: api_key`, matching ID and boolean `deleted: true`. Sending-only credentials cannot manage keys. |
| RubyGems | **Owner/manual or authorized partner only** | No general single-key bearer API. Owner deletes/rotates the individual key in the account UI. Partner reporting needs an authorized GitHub/deps.dev signature over the exact body; ordinary RubyGems credentials cannot produce it. Never substitute an account-wide reset. |
| Twilio API key SID | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`; delete the detected `SK…` SID | 204 only. The detector finds an identifier, not the API-key secret. The binding targets US1; use matching regional management credentials. Does not rotate Auth Tokens. |
| GitHub App user access token (`ghu_`) | Unauthenticated credentials report for exactly the candidate | 202 yields **unknown**, not confirmed revoked. Installation tokens (`ghs_`) are rejected before HTTP. |
| GitHub PAT / fine-grained / OAuth / refresh | Existing unauthenticated credentials report | Existing 202 matcher is retained for compatibility; its success flag means accepted, not completed. Do not infer per-token validity. |
| Slack user / bot / legacy workspace | Existing `auth.revoke` | Requires `ok: true` and `revoked: true`; bot revocation can deactivate the bot/remove memberships. App-level and configuration-token families are not newly claimed supported. |
| GCP API key | Separately supplied `GCP_ACCESS_TOKEN`; exact full-key lookup, delete returned resource, at most one operation GET | Requires lookup/delete IAM permissions and cloud-platform scope. Success requires a completed operation without error and the exact key resource in its response. Pending/unrecognized/error operations are unknown: inspect the operation before retrying. Soft deletion is recoverable for 30 days. |
| GCP service-account key | Existing credential-specific IAM key deletion using the detected JSON key | Does not delete the service account and does not invalidate already issued short-lived credentials. |
| Anthropic ordinary API key | Separate `ANTHROPIC_ADMIN_KEY`, `ANTHROPIC_API_KEY_ID`, `ANTHROPIC_API_KEY_VALUE`; set status inactive | 200, `type: api_key`, exact ID and `status: inactive`. No documented raw-key-to-ID lookup. Admin-key detection remains manual; ordinary-key management is not assumed to manage admin credentials. |
| OpenAI project / service-account-owned API key | Separate `OPENAI_ADMIN_KEY`, `OPENAI_PROJECT_ID`, `OPENAI_API_KEY_ID`, `OPENAI_API_KEY_VALUE`; delete that key | 200, exact ID, `object: organization.project.api_key.deleted`, boolean `deleted: true`. Never deletes a service account. Legacy organization keys without a known project mapping need owner intervention. |
| OpenAI admin API key | Separate `OPENAI_ADMIN_KEY`, `OPENAI_API_KEY_ID`, `OPENAI_API_KEY_VALUE`; admin-key deletion endpoint | 200, exact ID, `object: organization.admin_api_key.deleted`, boolean `deleted: true`. Project ID is not needed for `sk-admin-` candidates. |

For owner-ID flows, each `*_VALUE` must equal the current candidate **before any HTTP request**.
This prevents a global ID/admin variable from deleting an unrelated key when several findings
are processed. It is an explicit owner attestation of the full-token-to-ID mapping, not a
provider-verified lookup. Obtain that association from trusted creation records; never infer it
from names, masked prefixes/suffixes, timestamps, list position, or neighboring user/service-account
IDs. Missing inputs or malformed IDs fail closed before mutation.

Expression `env.get` reads supplied runtime variables, not the SDK process environment. Pass
inputs explicitly through the SDK's existing variables map. On the CLI, use existing
`--var NAME=value` bindings, for example `--var "GCP_ACCESS_TOKEN=$GCP_ACCESS_TOKEN"`.
Exporting an arbitrary variable alone does not populate expression inputs. Positional/suggested
inputs include literal `env.get` names. Branch-only names may be listed even when not needed on the executed
branch. All new mutation flows make one attempt; a transport failure or unconfirmed result is
not an invitation to retry automatically. GCP's single read-only operation check is bounded,
not a polling loop. No alternate mutation endpoints or account-wide actions are attempted.

The existing GitHub/Hugging Face 202-only primary definitions are deliberately not reinterpreted
by this additive change. Callers must distinguish their accepted-report semantics from verified
completion. The newly added GitHub App handler uses the existing indeterminate-result channel.

The documented unauthenticated Vercel `POST /external/compromised_secret` report is not used:
its public example does not specify a reliable response/completion contract. The documented,
SDK-tested owner-ID deletion is used instead. Likewise, Slack configuration-token rotation is
not a standalone revocation operation and is not replaced with app deletion/uninstallation.

## First-party provenance

The following immutable SDK/source revisions document the implemented protocol. MIT and
Apache-2.0 sources are compatible with this project. Linked API documentation supplies current
semantics; requests/matchers above are independently authored, not copied implementation code.

- **Notion (MIT):** [SDK client](https://github.com/makenotion/notion-sdk-js/blob/dcae0f1cb13af453b5b65fbc29b259f57ab06f58/src/Client.ts),
  [license](https://github.com/makenotion/notion-sdk-js/blob/dcae0f1cb13af453b5b65fbc29b259f57ab06f58/LICENSE);
  [revoke](https://developers.notion.com/reference/revoke-token),
  [introspect](https://developers.notion.com/reference/introspect-token),
  [credential security](https://developers.notion.com/guides/authorization/credential-security).
- **Resend (MIT):** [API key SDK](https://github.com/resend/resend-node/blob/3576a65b8d63bc61becf6ace238f56e3543290ca/src/api-keys/api-keys.ts),
  [license](https://github.com/resend/resend-node/blob/3576a65b8d63bc61becf6ace238f56e3543290ca/LICENSE),
  [OpenAPI](https://github.com/resend/resend-openapi/blob/0b2a456ec468f07eb2e6fac73f0a76fb5463823c/resend.yaml),
  [delete API](https://resend.com/docs/api-reference/api-keys/delete-api-key).
- **Twilio (MIT):** [Keys SDK](https://github.com/twilio/twilio-python/blob/416dc912045bf863edf30b48bf0e7be67e27ecb2/twilio/rest/iam/v1/api_key.py),
  [license](https://github.com/twilio/twilio-python/blob/416dc912045bf863edf30b48bf0e7be67e27ecb2/LICENSE),
  [key resource](https://www.twilio.com/docs/iam/api-keys/key-resource-v1),
  [regional credentials](https://www.twilio.com/docs/global-infrastructure/manage-regional-api-credentials).
- **RubyGems limitation (MIT):** [authorized partners](https://github.com/rubygems/rubygems.org/blob/8b646ca4e41bf63d944097f879902699a7478bbd/config/secret_scanning.yml),
  [revocations controller](https://github.com/rubygems/rubygems.org/blob/8b646ca4e41bf63d944097f879902699a7478bbd/app/controllers/api/v1/api_key_revocations_controller.rb),
  [license](https://github.com/rubygems/rubygems.org/blob/8b646ca4e41bf63d944097f879902699a7478bbd/MIT-LICENSE).
- **GitHub (MIT):** [REST description](https://github.com/github/rest-api-description/blob/87267030f4b1cb33c3b076e4999f3da2e1290450/descriptions/api.github.com/api.github.com.json),
  [license](https://github.com/github/rest-api-description/blob/87267030f4b1cb33c3b076e4999f3da2e1290450/LICENSE.md),
  [credentials API](https://docs.github.com/en/rest/credentials/revoke).
- **Slack (MIT):** [SDK client](https://github.com/slackapi/python-slack-sdk/blob/d9618f86e9ea7e4a7692240f7418474f4849ebeb/slack_sdk/web/client.py),
  [license](https://github.com/slackapi/python-slack-sdk/blob/d9618f86e9ea7e4a7692240f7418474f4849ebeb/LICENSE),
  [auth.revoke](https://docs.slack.dev/reference/methods/auth.revoke/).
- **GCP (Apache-2.0):** [API Keys protocol](https://github.com/googleapis/googleapis/blob/fb371f32cad34201edad925e8ef17f73207f8812/google/api/apikeys/v2/apikeys.proto),
  [IAM protocol](https://github.com/googleapis/googleapis/blob/fb371f32cad34201edad925e8ef17f73207f8812/google/iam/admin/v1/iam.proto),
  [license](https://github.com/googleapis/googleapis/blob/fb371f32cad34201edad925e8ef17f73207f8812/LICENSE),
  [lookup](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/keys/lookupKey),
  [delete](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/projects.locations.keys/delete),
  [operation GET](https://docs.cloud.google.com/api-keys/docs/reference/rest/v2/operations/get).
- **Anthropic (Apache-2.0):** [API keys SDK](https://github.com/anthropics/anthropic-sdk-python/blob/dd18a659419fe4d83aa9109bdcdcf9a35d5c8ddb/src/anthropic/resources/beta/organization/api_keys.py),
  [license](https://github.com/anthropics/anthropic-sdk-python/blob/dd18a659419fe4d83aa9109bdcdcf9a35d5c8ddb/LICENSE),
  [update API](https://platform.claude.com/docs/en/api/organization/api_keys/update).
- **OpenAI (Apache-2.0):** [project keys SDK](https://github.com/openai/openai-python/blob/c9fe3355fd43084df817543d0d7bd5bc72065c0f/src/openai/resources/admin/organization/projects/api_keys.py),
  [admin keys SDK](https://github.com/openai/openai-python/blob/c9fe3355fd43084df817543d0d7bd5bc72065c0f/src/openai/resources/admin/organization/admin_api_keys.py),
  [license](https://github.com/openai/openai-python/blob/c9fe3355fd43084df817543d0d7bd5bc72065c0f/LICENSE),
  [project delete API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys/methods/delete),
  [admin delete API](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/admin_api_keys/methods/delete).
- **Vercel (Apache-2.0):** [CLI deletion](https://github.com/vercel/vercel/blob/84878e532142f0ac584953695658b324eb9e5b80/packages/cli/src/util/ai-gateway/api-keys.ts),
  [204 contract test](https://github.com/vercel/vercel/blob/84878e532142f0ac584953695658b324eb9e5b80/packages/cli/test/unit/commands/ai-gateway/api-keys-remove.test.ts),
  [license](https://github.com/vercel/vercel/blob/84878e532142f0ac584953695658b324eb9e5b80/LICENSE),
  [AI Gateway keys](https://vercel.com/docs/ai-gateway/authentication-and-byok/api-keys),
  [OAuth authorization server](https://vercel.com/docs/sign-in-with-vercel/authorization-server-api).
- **Hugging Face:** existing request contract cross-checked against the [official OpenAPI](https://huggingface.co/.well-known/openapi.json);
  documentation project [Apache-2.0 license](https://github.com/huggingface/hub-docs/blob/main/LICENSE).
  No OpenAPI text or implementation is copied into the overlay.

## Verification

[Portable provider contract tests](../../kingfisher-scanner/tests/provider_revocation_contracts.rs)
exercise the generated built-ins against local HTTP mocks: paths, methods, authentication,
exact JSON, refusal of unrelated targets, unknown responses, and no mutation retry. They never
use real vendor credentials or perform a live revocation. Catalog assertions also preserve the
unsupported RubyGems/admin-Anthropic families without inventing a destructive fallback.
