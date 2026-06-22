---
title: "Access Map (Blast Radius)"
description: "Map the blast radius of leaked credentials by authenticating and enumerating accessible resources and permissions."
---

# Access Map: supported tokens & credential formats

Kingfisher’s **access map** determines the *effective identity* and *blast radius* of a credential by authenticating to the target provider and enumerating accessible resources and permissions.

There are two ways to produce access maps:

- **During scanning**: `kingfisher scan ... --access-map`  
  Kingfisher validates detected secrets and automatically generates access-map entries for supported credential types.
- **Standalone**: `kingfisher access-map <provider> [credential_file]`  
  This reads a credential artifact from disk and maps it directly.
  Standalone access-map defaults to JSON output. The examples below use
  `--format json` explicitly so the output type stays unambiguous when
  redirecting to a file. Use `--format html` for a standalone HTML report,
  and `--output <PATH>` if you prefer writing directly instead of using shell
  redirection.

> Access mapping runs additional network requests. Only use it when you are authorized to inspect the target account/workspace.

## How Access Map Works

### Standalone Flow

```mermaid
flowchart LR
    CLI[kingfisher access-map] --> Args[Provider and credential input]
    Args --> Dispatch[Provider dispatch]
    Dispatch --> Provider[Provider mapper]
    Provider --> APIs[Provider APIs]
    APIs --> Result[AccessMapResult]
    Result --> Output[JSON or HTML output]
```

### Scan-Time Flow

```mermaid
flowchart LR
    Scan[kingfisher scan --access-map] --> Detect[Detect findings]
    Detect --> Validate[Validate supported credentials]
    Validate --> Collect[AccessMapCollector]
    Collect --> Requests[AccessMapRequest values]
    Requests --> Map[access_map::map_requests]
    Map --> Results[AccessMapResult values]
    Results --> Report[Report and viewer output]
```

### Provider Dispatch Model

```mermaid
flowchart TD
    Request[Access map request] --> Kind{Credential kind}

    Kind --> Token[Single token providers]
    Kind --> Complex[Structured credential providers]

    Token --> Trait[TokenAccessMapper]
    Trait --> Modules[GitHub GitLab Slack Gitea Bitbucket and similar providers]

    Complex --> Custom[Custom provider mapping]
    Custom --> ComplexModules[AWS GCP Azure Postgres MongoDB and other multi-field providers]

    Modules --> Result[AccessMapResult]
    ComplexModules --> Result
```

## What “supported tokens” means

Access map only runs for credential types Kingfisher knows how to authenticate with and enumerate. In the codebase, these map to `AccessMapRequest` variants recorded from validated findings (see `src/scanner/validation.rs`).

## Providers and supported credential formats

### GitHub (`github`)

- **Credential**: a single GitHub token string (read from a file for `kingfisher access-map github <FILE>`).
- **Token types supported**: any token accepted by GitHub’s REST API `Authorization` scheme used by Kingfisher (`Authorization: token <TOKEN>`), including:
  - Classic PATs (commonly `ghp_...`)
  - Fine-grained PATs (commonly `github_pat_...`)
  - OAuth / user tokens (various prefixes; GitHub controls these)
  - GitHub App tokens (Kingfisher detects `ghu_...` and `ghs_...` and uses the installations APIs for richer mapping)

#### Standalone example (GitHub)

```bash
printf '%s' 'ghp_example...' > ./github.token
kingfisher access-map github ./github.token --format json > github.access-map.json
```

#### Notes (GitHub)

- Access map currently uses `https://api.github.com` as the API base.

### GitLab (`gitlab`)

- **Credential**: a single GitLab token string (read from a file for `kingfisher access-map gitlab <FILE>`).
- **Token types supported**: any token accepted by GitLab’s `PRIVATE-TOKEN` header (PATs like `glpat-...`, plus other GitLab token types that work with that header).  
  When available, Kingfisher also queries the token-self endpoint for metadata; some token types may not expose token details there.

#### Standalone example (GitLab)

```bash
printf '%s' 'glpat-example...' > ./gitlab.token
kingfisher access-map gitlab ./gitlab.token --format json > gitlab.access-map.json
```

#### Notes (GitLab)

- Access map currently uses `https://gitlab.com/api/v4/` as the API base.

### Slack (`slack`)

- **Credential**: a single Slack token string (read from a file for `kingfisher access-map slack <FILE>`).
- **Token types supported**: tokens accepted by Slack Web API with `Authorization: Bearer <TOKEN>` (for example `xoxp-...`, `xoxb-...`, etc.).  
  Kingfisher derives scopes from the `x-oauth-scopes` response header when Slack returns it.

#### Standalone example (Slack)

```bash
printf '%s' 'xoxp-example...' > ./slack.token
kingfisher access-map slack ./slack.token --format json > slack.access-map.json
```

### AWS (`aws`)

- **Credential**: AWS access key credentials.
- **Supported formats for `kingfisher access-map aws <FILE>`**:
  - **JSON object** with case-insensitive support for the following keys:
    - `access_key_id` / `accessKeyId` / `aws_access_key_id` / `AccessKeyId`
    - `secret_access_key` / `secretAccessKey` / `aws_secret_access_key` / `SecretAccessKey`
    - optional `session_token` / `sessionToken` / `aws_session_token` / `SessionToken`
  - **Key/value file** containing `KEY=VALUE` lines (comments allowed with `#`), supporting:
    - `aws_access_key_id` or `access_key_id`
    - `aws_secret_access_key` or `secret_access_key`
    - optional `aws_session_token` or `session_token`

#### Standalone examples (AWS)

```bash
cat > ./aws.json <<'EOF'
{
  "access_key_id": "AKIA....",
  "secret_access_key": "....",
  "session_token": "...."
}
EOF

kingfisher access-map aws ./aws.json --format json > aws.access-map.json
```

```bash
cat > ./aws.env <<'EOF'
aws_access_key_id=AKIA....
aws_secret_access_key=....
aws_session_token=....
EOF

kingfisher access-map aws ./aws.env --format json > aws.access-map.json
```

Kingfisher performs read-only enumeration for the IAM principal and, when allowed by the credential, visible resources in several common AWS services including S3, EC2, IAM, Lambda, DynamoDB, KMS, Secrets Manager, SQS, SNS, RDS, ECR, and SSM Parameter Store.

### Alibaba Cloud (`alibaba` / `aliyun`)

- **Credential**: an Alibaba Cloud access key pair, with an optional STS security token.
- **Supported formats for `kingfisher access-map alibaba <FILE>`**:
  - **JSON object** with support for:
    - `access_key_id` / `accessKeyId` / `AccessKeyId`
    - `access_key_secret` / `accessKeySecret` / `AccessKeySecret`
    - optional `security_token` / `securityToken` / `SecurityToken`
  - **Key/value file** containing `KEY=VALUE` or `KEY: VALUE` lines, supporting:
    - `access_key_id` or `AccessKeyId`
    - `access_key_secret` or `AccessKeySecret`
    - optional `security_token` or `SecurityToken`

#### Standalone examples (Alibaba Cloud)

```bash
cat > ./alibaba.json <<'EOF'
{
  "access_key_id": "LTAI....",
  "access_key_secret": "....",
  "security_token": "...."
}
EOF

kingfisher access-map alibaba ./alibaba.json --format json > alibaba.access-map.json
```

```bash
cat > ./alibaba.env <<'EOF'
access_key_id=LTAI....
access_key_secret=....
security_token=....
EOF

kingfisher access-map alibaba ./alibaba.env --format json > alibaba.access-map.json
```

Kingfisher resolves the Alibaba Cloud caller identity with `sts:GetCallerIdentity` for both long-lived access key pairs and STS temporary credentials discovered during scanning. Current coverage is identity-focused: it maps the account and resolved RAM principal, and records that broader Alibaba service enumeration is not yet available.

### GCP (`gcp`)

- **Credential**: a Google Cloud **service account key JSON** file.

#### Standalone example (GCP)

```bash
kingfisher access-map gcp ./service-account.json --format json > gcp.access-map.json
```

### Azure Storage (`azure`)

- **Credential**: a JSON file containing:
  - `storage_account` (string)
  - `storage_key` (string, base64-encoded account key as provided by Azure)

#### Standalone example (Azure Storage)

```bash
cat > ./azure-storage.json <<'EOF'
{
  "storage_account": "mystorageacct",
  "storage_key": "base64=="
}
EOF

kingfisher access-map azure ./azure-storage.json --format json > azure.access-map.json
```

Kingfisher treats the account key as full-control Storage credentials and performs best-effort enumeration across Blob containers, File shares, and Queue resources reachable with that key.

### Azure DevOps (scan `--access-map` only)

Azure DevOps access mapping is supported when a **validated Azure DevOps PAT** is discovered during scanning (the access-map record includes both the PAT and the organization). At the moment, there is **no standalone** `kingfisher access-map azure-devops ...` provider flag.

### PostgreSQL (`postgres`)

- **Credential**: a single Postgres connection URI string (read from a file).

#### Standalone example (Postgres)

```bash
printf '%s' 'postgres://user:pass@db.example.com:5432/mydb' > ./postgres.uri
kingfisher access-map postgres ./postgres.uri --format json > postgres.access-map.json
```

### MongoDB (`mongodb` / `mongo`)

- **Credential**: a single MongoDB connection URI string (read from a file), including `mongodb+srv://...` URIs.

#### Standalone example (MongoDB)

```bash
printf '%s' 'mongodb+srv://user:pass@cluster.example.net/?retryWrites=true&w=majority' > ./mongodb.uri
kingfisher access-map mongodb ./mongodb.uri --format json > mongodb.access-map.json
```

### Hugging Face (`huggingface` / `hf`)

- **Credential**: a single Hugging Face token string (read from a file for `kingfisher access-map huggingface <FILE>`).
- **Token types supported**: tokens accepted by the Hugging Face API with `Authorization: Bearer <TOKEN>`, including:
  - User access tokens (commonly `hf_...`)
  - Organization API tokens (commonly `api_org_...`)

Kingfisher queries the `/api/whoami-v2` endpoint to resolve the token identity, role, and organization memberships. It also performs best-effort enumeration of authored models, datasets, and Spaces for the user and visible organizations to assess the blast radius.

#### Standalone example (Hugging Face)

```bash
printf '%s' 'hf_example...' > ./huggingface.token
kingfisher access-map huggingface ./huggingface.token --format json > huggingface.access-map.json
```

#### Notes (Hugging Face)

- Access map uses `https://huggingface.co/api` as the API base.
- Token role (read, write, admin, fineGrained) is derived from the `auth` section of the whoami response when available.

### Gitea (`gitea`)

- **Credential**: a single Gitea token string (read from a file for `kingfisher access-map gitea <FILE>`).
- **Token types supported**: any token accepted by Gitea's `Authorization: token <TOKEN>` header (personal access tokens).

Kingfisher queries `/api/v1/user` for identity, enumerates organizations via `/api/v1/user/orgs`, and lists accessible repositories via `/api/v1/user/repos`. Repository-level permissions (admin, push, pull) are used to classify risk.

#### Standalone example (Gitea)

```bash
printf '%s' 'your_gitea_pat...' > ./gitea.token
kingfisher access-map gitea ./gitea.token --format json > gitea.access-map.json
```

#### Notes (Gitea)

- Access map currently uses `https://gitea.com/api/v1/` as the default API base.
- If the token belongs to a site administrator, severity is classified as Critical.

### Bitbucket (`bitbucket`)

- **Credential**: a single Bitbucket token string (read from a file for `kingfisher access-map bitbucket <FILE>`).
- **Token types supported**: tokens accepted by Bitbucket Cloud's `Authorization: Bearer <TOKEN>` header (OAuth access tokens, app passwords, repository access tokens).

Kingfisher queries `/2.0/user` for identity, enumerates workspace memberships and permissions via `/2.0/user/permissions/workspaces`, and lists accessible repositories via `/2.0/repositories?role=member`. Workspace ownership and private repository access are used to classify risk.

#### Standalone example (Bitbucket)

```bash
printf '%s' 'your_bitbucket_token...' > ./bitbucket.token
kingfisher access-map bitbucket ./bitbucket.token --format json > bitbucket.access-map.json
```

#### Notes (Bitbucket)

- Access map uses `https://api.bitbucket.org/2.0` as the API base.
- Workspace owners are classified as High severity.

### Buildkite (`buildkite`)

- **Credential**: a single Buildkite API token string (read from a file for `kingfisher access-map buildkite <FILE>`).
- **Token types supported**: tokens accepted by Buildkite's REST API with `Authorization: Bearer <TOKEN>` (API access tokens, commonly `bkua_...`).

Kingfisher queries `/v2/access-token` for token metadata and scopes, `/v2/user` for identity, `/v2/organizations` for organization memberships, and `/v2/organizations/{org}/pipelines` for pipeline enumeration. Token scopes and organization access are used to classify risk.

#### Standalone example (Buildkite)

```bash
printf '%s' 'bkua_example...' > ./buildkite.token
kingfisher access-map buildkite ./buildkite.token --format json > buildkite.access-map.json
```

#### Notes (Buildkite)

- Access map uses `https://api.buildkite.com/v2` as the API base.
- Tokens with `write_organizations` or `write_teams` scopes are classified as High severity.

### Harness (`harness`)

- **Credential**: a single Harness API key / personal access token (PAT) string (read from a file for `kingfisher access-map harness <FILE>`).
- **Auth header**: Harness APIs authenticate via `x-api-key: <TOKEN>` (see the Harness API docs).

Kingfisher performs best-effort, read-only enumeration:

- Queries the API key aggregate endpoint for basic token metadata (when available).
- Enumerates organizations via `GET https://app.harness.io/v1/orgs` and projects via `GET https://app.harness.io/v1/orgs/{org}/projects` when the key has permission.

If organizations/projects are not enumerable (scope-limited keys), Kingfisher still produces an access-map record with a conservative severity and a note explaining the limitation.

#### Standalone example (Harness)

```bash
printf '%s' 'pat.example...' > ./harness.token
kingfisher access-map harness ./harness.token --format json > harness.access-map.json
```

#### Notes (Harness)

- Access map uses `https://app.harness.io` as the API base.

### OpenAI (`openai`)

- **Credential**: a single OpenAI API key string (read from a file for `kingfisher access-map openai <FILE>`).
- **Token types supported**: OpenAI keys accepted by `Authorization: Bearer <TOKEN>` (for example `sk-...`, `sk-proj-...`, `sk-svcacct-...`).

Kingfisher performs read-only scope probing and best-effort resource enumeration via:

- `GET https://api.openai.com/v1/models` to verify Models API read access and enumerate visible models.
- `GET https://api.openai.com/v1/me` for token identity metadata when available.
- `GET https://api.openai.com/v1/organization/projects` for project visibility when the key has permission.
- `GET https://api.openai.com/v1/files` to enumerate visible uploaded files when the key has file-list access.
- `GET https://api.openai.com/v1/assistants` to enumerate visible assistants when the key has assistant read access.
- `GET https://api.openai.com/v1/fine_tuning/jobs` to enumerate visible fine-tuning jobs when the key has fine-tuning read access.

#### Standalone example (OpenAI)

```bash
printf '%s' 'sk-example...' > ./openai.token
kingfisher access-map openai ./openai.token --format json > openai.access-map.json
```

#### Notes (OpenAI)

- Access map uses `https://api.openai.com/v1` as the API base.

### Anthropic (`anthropic`)

- **Credential**: a single Anthropic API key string (read from a file for `kingfisher access-map anthropic <FILE>`).
- **Token types supported**: Anthropic keys accepted via `x-api-key`, including standard API keys and admin-style keys when exposed by Anthropic.

Kingfisher performs read-only enumeration via:

- `GET https://api.anthropic.com/v1/models` to enumerate visible models.
- `GET https://api.anthropic.com/v1/organizations/api_keys/me` or `GET https://api.anthropic.com/v1/api_keys/me` to introspect the current key when supported.
- `GET https://api.anthropic.com/v1/organizations/api_keys` to enumerate visible organization API keys when the credential can access them.

#### Standalone example (Anthropic)

```bash
printf '%s' 'sk-ant-api-example...' > ./anthropic.token
kingfisher access-map anthropic ./anthropic.token --format json > anthropic.access-map.json
```

#### Notes (Anthropic)

- Access map uses `https://api.anthropic.com/v1` as the API base.
- Keys that can enumerate organization API keys are treated as having broader administrative visibility.

### Salesforce (`salesforce`)

- **Credential**: Salesforce access token plus instance domain.
- **Supported standalone formats** for `kingfisher access-map salesforce <FILE>`:
  - JSON:
    - `token` (or `access_token`)
    - `instance_url` (or `instance`), such as `https://mydomain.my.salesforce.com`
  - Free-form text containing both:
    - a Salesforce access token (`00...!...`)
    - an instance host (`<instance>.my.salesforce.com`)

Kingfisher performs read-only enumeration via:

- `GET /services/data/v60.0/limits` to confirm API access and gather account-level API context.
- `GET /services/oauth2/userinfo` for identity metadata when available.
- `GET /services/data/v60.0/sobjects` for visible object metadata (best-effort).

#### Standalone example (Salesforce)

```bash
cat > ./salesforce.json <<'EOF'
{
  "token": "00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLE...",
  "instance_url": "https://mydomain.my.salesforce.com"
}
EOF

kingfisher access-map salesforce ./salesforce.json --format json > salesforce.access-map.json
```

#### Notes (Salesforce)

- Access map currently targets `https://<instance>.my.salesforce.com` and API version `v60.0`.

### Weights & Biases (`weightsandbiases` / `wandb`)

- **Credential**: a single Weights & Biases API key string (read from a file for `kingfisher access-map weightsandbiases <FILE>`).
- **Token types supported**:
  - Legacy 40-character hex API keys
  - New v1 keys (`wandb_v1_...`)

Kingfisher performs read-only identity resolution via:

- `POST https://api.wandb.ai/graphql` with a GraphQL `viewer` query.

#### Standalone example (Weights & Biases)

```bash
printf '%s' 'wandb_v1_example...' > ./wandb.token
kingfisher access-map weightsandbiases ./wandb.token --format json > wandb.access-map.json
```

#### Notes (Weights & Biases)

- Access map uses `https://api.wandb.ai/graphql` as the API endpoint.
- W&B key introspection does not currently expose fine-grained scopes in this workflow, so risk is reported conservatively.

### Microsoft Teams (`microsoftteams` / `msteams`)

- **Credential**: a Microsoft Teams Incoming Webhook URL (read from a file for `kingfisher access-map microsoftteams <FILE>`).
- **Webhook types supported**:
  - Legacy Incoming Webhooks (`*.office.com/webhook/...`)
  - Workflow-based webhooks (`*.webhook.office.com/webhookb2/...`)

Kingfisher parses the webhook URL to extract the tenant ID and webhook identity, then sends a benign probe (`{"text":""}`) to determine whether the webhook is still active. Active webhooks can post messages to the configured Teams channel.

#### Standalone example (Microsoft Teams)

```bash
printf '%s' 'https://contoso.webhook.office.com/webhookb2/...' > ./teams.webhook
kingfisher access-map microsoftteams ./teams.webhook --format json > teams.access-map.json
```

#### Notes (Microsoft Teams)

- The webhook URL is the credential — it contains the tenant ID and grants write access to a single Teams channel.
- Access map severity is Medium for active webhooks (write-only to one channel) and Low for inactive/removed webhooks.
- The probe request does not post any visible message; Teams responds with HTTP 400 "Text is required" for valid endpoints.

### monday.com (`monday`)

- **Credential**: a single monday.com API token (read from a file for `kingfisher access-map monday <FILE>`).
- **Token types supported**: personal or account-level API tokens accepted by the monday.com GraphQL API with the `Authorization: <TOKEN>` header (the JWT-style token is sent verbatim, without the `Bearer` prefix — this matches monday.com's native scheme).

Kingfisher performs read-only enumeration against `https://api.monday.com/v2`:

- `me { ..., account { id, name, slug, plan { tier } }, teams { name } }` for caller identity, role, and account metadata
- `workspaces(limit: 100) { id, name, kind, state }` for workspace-level resource exposure
- `boards(limit: 50) { id, name, board_kind, state }` for board-level resource exposure

Severity is Critical for account administrators, High for standard members with broad workspace/board visibility (>5 workspaces or >20 boards), Medium for standard members with any workspace/board access, and Low for guest/viewer tokens or empty accounts.

#### Standalone example (monday.com)

```bash
printf '%s' 'eyJhbGciOi...' > ./monday.token
kingfisher access-map monday ./monday.token --format json > monday.access-map.json
```

#### Notes (monday.com)

- Access map currently uses `https://api.monday.com/v2` (GraphQL v2) as the API base.
- monday.com API tokens do not carry granular scopes; permissions follow the underlying user's role (admin/member/viewer/guest).
- `provider_metadata.version` carries the monday.com plan tier when exposed by the account.
- Recorded during `scan --access-map` for validated `kingfisher.monday.1` findings.

### Asana (`asana`)

- **Credential**: a single Asana access token (read from a file for `kingfisher access-map asana <FILE>`).
- **Token types supported**: tokens accepted by Asana's REST API with `Authorization: Bearer <TOKEN>`:
  - Legacy OAuth / personal access tokens (`0/...`)
  - Personal Access Tokens V1 (`1/<user_gid>:<secret>`)
  - Personal Access Tokens V2 (`2/<app_gid>/<user_gid>:<secret>`)

Kingfisher performs read-only enumeration against `https://app.asana.com/api/1.0`:

- `GET /users/me?opt_fields=gid,name,email,resource_type,workspaces.gid,workspaces.name,workspaces.is_organization,workspaces.resource_type` for caller identity and accessible workspaces/organizations
- `GET /projects?workspace=<gid>&limit=50&opt_fields=gid,name,privacy_setting,archived` for per-workspace project exposure
- `GET /users/me/teams?organization=<gid>&opt_fields=gid,name` for team memberships in each organization workspace

Severity is High when the token reaches an organization workspace with more than 20 visible projects, Medium when it reaches an organization workspace or has broad project visibility (>5 projects), and Low for single-workspace or empty tokens.

#### Standalone example (Asana)

```bash
printf '%s' '2/12345.../abcdef...' > ./asana.token
kingfisher access-map asana ./asana.token --format json > asana.access-map.json
```

#### Notes (Asana)

- Asana access tokens do not expose granular scopes. Access follows the underlying user's membership in each workspace, organization, and team.
- `token_details.token_type` is classified from the token prefix (`personal_access_token_v2`, `personal_access_token_v1`, `oauth_or_legacy_pat`, or generic `asana_token`).
- Recorded during `scan --access-map` for validated `kingfisher.asana.3`, `kingfisher.asana.4`, and `kingfisher.asana.5` findings only. `kingfisher.asana.1` is a client ID and `kingfisher.asana.2` is a client secret (requiring the client ID for an OAuth exchange), so neither is used on its own to enumerate user-level resources.

### Pinecone (`pinecone`)

- **Credential**: a single Pinecone API key (read from a file for `kingfisher access-map pinecone <FILE>`).
- **Token types supported**: API keys accepted by Pinecone's control-plane API with the `Api-Key: <KEY>` header.

Kingfisher performs read-only enumeration against `https://api.pinecone.io` (`X-Pinecone-API-Version: 2025-10`):

- `GET /indexes` for index inventory, dimension, metric, status, deletion-protection state, and serverless cloud/region or pod environment/type
- `GET /collections` for collection inventory in pod-based projects (gracefully skipped on serverless-only projects)

Severity is High when the token reaches more than 10 indexes, Medium when it reaches one or more indexes (especially with deletion protection disabled) or any collections, and Low for empty projects or validation failures.

#### Standalone example (Pinecone)

```bash
printf '%s' '62b0dbfe-3489-4b79-b850-34d911527c88' > ./pinecone.key
kingfisher access-map pinecone ./pinecone.key --format json > pinecone.access-map.json
```

The `kingfisher blast-radius` and `kingfisher blast_radius` aliases also work for any provider, e.g. `kingfisher blast-radius pinecone ./pinecone.key`.

#### Notes (Pinecone)

- Pinecone API keys do not carry granular scopes; access follows the API key's project-level permissions, which include read and write (upsert/delete) against any index in the project.
- Indexes with `deletion_protection: enabled` are flagged in the resource record but still accessible for read/write.
- Recorded during `scan --access-map` (or the `--blast-radius` alias) for validated `kingfisher.pinecone.1` findings.

## Notes on access-map generation during `scan --access-map`

- Access-map entries are only recorded for **validated** findings.
- Some providers require extra context that Kingfisher infers from the finding context or validation response (for example, Azure DevOps organization name).
- Validated Hugging Face, Gitea, Bitbucket, Buildkite, Harness, OpenAI, Anthropic, Salesforce, Weights & Biases, Microsoft Teams, monday.com, Asana, and Pinecone credentials discovered during scans with `--access-map` (or the `--blast-radius` alias) are automatically collected and mapped, matching the existing behavior for other platforms.
