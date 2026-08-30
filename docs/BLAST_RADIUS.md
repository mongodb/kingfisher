# Blast Radius: supported tokens & credential formats

Kingfisher’s **blast-radius mapping** determines the *effective identity* and
*blast radius* of a credential by authenticating to the target provider and enumerating accessible
resources and permissions. It turns “we found a key” into the questions defenders need answered:
*Who or what is this credential? What can it reach? Which permissions make it urgent?*

All 43 provider implementations are included by default in the Apache-2.0 open-source release.
That includes AWS and GCP alongside major providers such as Azure, Alibaba Cloud, GitHub, GitLab,
Bitbucket, Slack, Salesforce, DigitalOcean, Terraform Cloud, MongoDB, PostgreSQL, MySQL, OpenAI,
and Anthropic.

AWS mapping resolves the principal, policies and group inheritance, visible resources, and potential
role-assumption paths. GCP mapping resolves the service account, visible project/folder/organization
IAM context, role bindings and permissions, authorization paths, and resources across major Google
Cloud services. Both report explicit limitations when permissions or safety caps prevent a complete
view.

There are two ways to produce blast-radius results:

- **During scanning**: `kingfisher scan ... --blast-radius`
  Kingfisher validates detected secrets and automatically generates blast-radius entries for supported credential types.
- **Standalone**: `kingfisher blast-radius <provider> [credential_file]`  
  This reads a credential artifact from disk and maps it directly.
  The standalone command defaults to JSON output. The examples below use
  `--format json` explicitly so the output type stays unambiguous when
  redirecting to a file. Use `--format html` for a standalone HTML report,
  and `--output <PATH>` if you prefer writing directly instead of using shell
  redirection.

Add `--view-report` to open the result in the interactive local viewer instead of printing the
standalone result. The viewer starts on `127.0.0.1:7890` and opens the browser automatically.
This works with both direct rule mappings and provider credential files. `--format html` remains
available when a self-contained static HTML file is preferred.

For backward compatibility, `--access-map` remains an alias for `--blast-radius`.
The standalone `kingfisher access-map` and `kingfisher blast_radius` spellings also remain aliases
for `kingfisher blast-radius`.

The HTML blast-radius viewer is built for triage: it starts in a topology view,
groups identities by provider, lets you click through to individual resources,
and keeps the detailed permissions in a side inspector. That makes it easier
to compare two credentials at a glance, prioritize administrator or production access, and decide
what to revoke first without reading nested JSON by hand.

> Blast-radius mapping runs additional network requests. Only use it when you are authorized to inspect the target account/workspace.

## How Blast Radius Works

### Standalone Flow

```mermaid
flowchart LR
    CLI[kingfisher blast-radius] --> Args[Provider and credential input]
    Args --> Dispatch[Provider dispatch]
    Dispatch --> Provider[Provider mapper]
    Provider --> APIs[Provider APIs]
    APIs --> Result[AccessMapResult]
    Result --> Output[JSON or HTML output]
```

### Scan-Time Flow

```mermaid
flowchart LR
    Scan[kingfisher scan --blast-radius] --> Detect[Detect findings]
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
    Request[Blast-radius request] --> Kind{Credential kind}

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

Blast-radius mapping only runs for credential types Kingfisher knows how to authenticate with and enumerate. In the codebase, these map to `AccessMapRequest` variants recorded from validated findings (see `src/scanner/validation.rs`).

### Authorization evidence output

AWS and GCP results may populate `provider_metadata.authorization_evidence` in standalone and scan-time output. Its provider-neutral fields are:

- `principal`: canonical identity, groups, tag-key presence, and provider attributes;
- `policies`: policy or binding provenance and normalized statements;
- `paths`: ordered identity hops with `outbound`/`inbound` direction and `potential`, `conditional`, or provider-specific status;
- `role_impacts`: reachable roles with effective permission summaries and statement-level resource grants;
- `hierarchy`: visible project, folder, or organization scopes; and
- `limitations`: incomplete reads, traversal caps, and policy-evaluation constraints.

Structured JSON, JSONL, BSON, TOON, and SARIF reports preserve the complete evidence payload. Pretty output summarizes paths, scan HTML summarizes evidence counts, and the standalone HTML report and interactive report viewer expose policy and path details without storing condition values.

## Providers and supported credential formats

### GitHub (`github`)

- **Credential**: a single GitHub token string (read from a file for `kingfisher blast-radius github <FILE>`).
- **Token types supported**: any token accepted by GitHub’s REST API `Authorization` scheme used by Kingfisher (`Authorization: token <TOKEN>`), including:
  - Classic PATs (commonly `ghp_...`)
  - Fine-grained PATs (commonly `github_pat_...`)
  - OAuth / user tokens (various prefixes; GitHub controls these)
  - GitHub App tokens (Kingfisher detects `ghu_...` and `ghs_...` and uses the installations APIs for richer mapping)

#### Standalone example (GitHub)

```bash
printf '%s' 'ghp_example...' > ./github.token
kingfisher blast-radius github ./github.token --format json > github.blast-radius.json
```

#### Notes (GitHub)

- Blast-radius mapping currently uses `https://api.github.com` as the API base.

### GitLab (`gitlab`)

- **Credential**: a single GitLab token string (read from a file for `kingfisher blast-radius gitlab <FILE>`).
- **Token types supported**: any token accepted by GitLab’s `PRIVATE-TOKEN` header (PATs like `glpat-...`, plus other GitLab token types that work with that header).

#### Standalone example (GitLab)

```bash
printf '%s' 'glpat-example...' > ./gitlab.token
kingfisher blast-radius gitlab ./gitlab.token --format json > gitlab.blast-radius.json
```

#### Notes (GitLab)

- Blast-radius mapping currently uses `https://gitlab.com/api/v4/` as the API base.
- Implementation provenance: identity and membership enumeration follow GitLab's vendor REST API
  documentation for [the current user](https://docs.gitlab.com/api/users/#retrieve-the-current-user)
  and [project listing](https://docs.gitlab.com/api/projects/#list-all-projects). Requests and
  pagination use the MIT/Apache-2.0-licensed Rust `gitlab` client.

### Slack (`slack`)

- **Credential**: a single Slack token string (read from a file for `kingfisher blast-radius slack <FILE>`).
- **Token types supported**: tokens accepted by Slack Web API with `Authorization: Bearer <TOKEN>` (for example `xoxp-...`, `xoxb-...`, etc.).  
  Kingfisher derives scopes from the `x-oauth-scopes` response header when Slack returns it.

#### Standalone example (Slack)

```bash
printf '%s' 'xoxp-example...' > ./slack.token
kingfisher blast-radius slack ./slack.token --format json > slack.blast-radius.json
```

### AWS (`aws`)

- **Credential**: AWS access key credentials.
- **Supported formats for `kingfisher blast-radius aws <FILE>`**:
  - **JSON object** with case-insensitive support for the following keys:
    - `access_key_id` / `accessKeyId` / `aws_access_key_id` / `AccessKeyId`
    - `secret_access_key` / `secretAccessKey` / `aws_secret_access_key` / `SecretAccessKey`
    - optional `session_token` / `sessionToken` / `aws_session_token` / `SessionToken`
  - **Key/value file** containing `KEY=VALUE` lines (comments allowed with `#`), supporting:
    - `aws_access_key_id` or `access_key_id`
    - `aws_secret_access_key` or `secret_access_key`
    - optional `aws_session_token` or `session_token`
    - optional shell-style `export` prefixes and quoted values

#### Standalone examples (AWS)

```bash
cat > ./aws.json <<'EOF'
{
  "access_key_id": "AKIA....",
  "secret_access_key": "....",
  "session_token": "...."
}
EOF

kingfisher blast-radius aws ./aws.json --format json > aws.blast-radius.json
```

```bash
cat > ./aws.env <<'EOF'
aws_access_key_id=AKIA....
aws_secret_access_key=....
aws_session_token=....
EOF

kingfisher blast-radius aws ./aws.env --format json > aws.blast-radius.json
```

Kingfisher performs read-only enumeration for the IAM principal and, when allowed by the credential, visible resources in several common AWS services including S3, EC2, IAM, Lambda, DynamoDB, KMS, Secrets Manager, SQS, SNS, RDS, ECR, and SSM Parameter Store. Enumeration follows paginated API responses, and IAM users include permissions inherited from IAM groups.

When IAM read access is available, the result also includes `provider_metadata.authorization_evidence`:

- canonical IAM identity metadata, user group membership, and principal tag-key presence;
- managed and inline policy statements with attachment provenance, including group inheritance;
- role trust-policy statements;
- potential direct and one-additional-hop role-assumption paths;
- `role_impacts` that pair each reachable role with its effective action summary and the
  statement-level resource scopes those actions grant; and
- explicit coverage limits when IAM reads are denied or safety caps are reached.

Reachable roles are also emitted in the top-level `roles` list. Their permissions contribute to the
credential's effective permission summary and severity, while their policy resource patterns appear
as `assumable_role_scope` resources. This makes a path such as credential → deployment role →
production Lambda function visible in JSON/TOON/SARIF and in both blast-radius viewers without
mixing the role's policy-derived resources with resources directly enumerated by the original
session.

Role paths and their resource impact are derived passively. Kingfisher does not call
`sts:AssumeRole` or mint credentials for a discovered role. A path marked `potential` or
`conditional` is included in effective blast radius; a `trust_only` path is retained for
investigation but is not counted as granted access because no matching identity-policy allow was
found. The listed role resources come from visible IAM policy statements, not API enumeration under
an assumed-role session. Permissions boundaries, session policies, organization policies, resource
control policies, resource policies, and request context can further restrict access. Condition
values are used only for local evaluation and are not retained in reports; reports contain condition
operator and key names.

IAM policy summaries are intentionally conservative: explicit denies, `NotAction`, resource scoping, and conditions are called out in risk notes because a flat action list cannot fully reproduce AWS policy evaluation. Global services are mapped account-wide; regional services use the region selected by the AWS SDK configuration.

### Alibaba Cloud (`alibaba` / `aliyun`)

- **Credential**: an Alibaba Cloud access key pair, with an optional STS security token.
- **Supported formats for `kingfisher blast-radius alibaba <FILE>`**:
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

kingfisher blast-radius alibaba ./alibaba.json --format json > alibaba.blast-radius.json
```

```bash
cat > ./alibaba.env <<'EOF'
access_key_id=LTAI....
access_key_secret=....
security_token=....
EOF

kingfisher blast-radius alibaba ./alibaba.env --format json > alibaba.blast-radius.json
```

Kingfisher resolves the Alibaba Cloud caller identity with `sts:GetCallerIdentity` for both long-lived access key pairs and STS temporary credentials discovered during scanning. Current coverage is identity-focused: it maps the account and resolved RAM principal, and records that broader Alibaba service enumeration is not yet available.

### GCP (`gcp`)

- **Credential**: a Google Cloud **service account key JSON** file.

#### Standalone example (GCP)

```bash
kingfisher blast-radius gcp ./service-account.json --format json > gcp.blast-radius.json
```

Kingfisher resolves the service account and reads visible project, folder, and organization IAM policies. When the credential exposes `iam.serviceAccounts.getIamPolicy`, it also uses bounded, read-only policy checks on visible target service accounts to find direct impersonation grants. Authorization evidence records the scope that contributed each role binding, expands roles into permissions, and records both inbound and outbound authorization-capability paths involving visible service accounts. Relationships distinguish access-token creation, OpenID-token creation, `actAs`, signing, and delegation permissions. For target service accounts reachable through access-token or signing capabilities, `role_impacts` matches the target to its visible project/folder/organization role bindings, expands those roles, and pairs their permissions with the hierarchy scopes they affect. `actAs`, OpenID-token, and delegation-only relationships remain path evidence without inheriting the target's Google API roles. Propagated roles are included in the effective severity and their scopes appear as `impersonated_service_account_scope` resources. The mapper also enumerates visible resources in the key's project across services including Cloud Storage, BigQuery, Secret Manager, Compute Engine, Cloud SQL, Pub/Sub, Cloud Run, Artifact Registry, GKE, Cloud KMS, Cloud Functions, Firestore, and Spanner.

GCP analysis is best effort and passive: Kingfisher does not mint an access token for a discovered target service account or repeat resource enumeration as that target. Conditional bindings and deny policies are not fully evaluated, Google group membership is not resolved, service-account inventory is limited to its first API response, direct target-policy checks are capped at 128 visible service accounts, and live resource enumeration is limited to the project associated with the original credential even when an inherited folder or organization role can apply to other descendants. Target role impact is limited to bindings visible in the hierarchy policies the original credential can read. These limits are included in `provider_metadata.authorization_evidence.limitations`.

### Microsoft Azure, Entra ID, and Microsoft Graph (`azure`)

The Azure mapper supports three credential families:

- **Azure Storage account key**:
  - `storage_account`
  - `storage_key` (base64-encoded account key)
- **Microsoft Entra application / service-principal credentials**:
  - `tenant_id`, `client_id`, and `client_secret`
  - Azure CLI aliases are accepted: `tenant`, `appId`, and `password`
  - Azure SDK/environment aliases such as `AZURE_TENANT_ID`,
    `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET` are also accepted in
    `KEY=VALUE` files
- **Existing OAuth2 access tokens**:
  - `graph_access_token` for Microsoft Graph
  - `management_access_token` or `arm_access_token` for Azure Resource Manager
  - `access_token` for a single token; Kingfisher uses the JWT audience to
    distinguish Azure Resource Manager from Microsoft Graph when possible

#### Standalone example (Azure Storage)

```bash
cat > ./azure-storage.json <<'EOF'
{
  "storage_account": "mystorageacct",
  "storage_key": "base64=="
}
EOF

kingfisher blast-radius azure ./azure-storage.json --format json > azure.blast-radius.json
```

Kingfisher treats the account key as full-control Storage credentials and performs best-effort enumeration across Blob containers, File shares, and Queue resources reachable with that key.

#### Standalone example (Microsoft Entra client credentials)

```bash
cat > ./azure-entra.json <<'EOF'
{
  "tenant_id": "11111111-2222-4333-8444-555555555555",
  "client_id": "12345678-90ab-4cde-8f01-234567890abc",
  "client_secret": "..."
}
EOF

kingfisher blast-radius azure ./azure-entra.json --format json > azure.blast-radius.json
```

For Entra client credentials, Kingfisher requests separate read-only access
tokens for Microsoft Graph and Azure Resource Manager using each resource's
`/.default` scope. It then performs best-effort mapping of:

- the Entra user or service principal and tenant;
- Graph application permissions or delegated scopes carried by the token;
- transitive Entra group and directory-role membership when allowed;
- visible Azure subscriptions and resource groups;
- direct Azure RBAC assignments, group-inherited assignments when Entra group
  membership is visible, and their role definitions.

Graph and Azure Resource Manager permission failures are recorded as partial
results instead of discarding identity or token-claim context that was already
resolved. Enumeration is capped to avoid unbounded traversal in very large
enterprise tenants.

#### Existing OAuth2 token example

```bash
cat > ./azure-token.json <<'EOF'
{
  "graph_access_token": "eyJ...",
  "management_access_token": "eyJ..."
}
EOF

kingfisher blast-radius azure ./azure-token.json --format json
```

A single access token only maps the API audience for which it was issued.
Supplying both Graph and management tokens gives the broadest view. Kingfisher
decodes JWT claims for mapping hints, but API calls remain the source of truth;
Microsoft access-token formats are not guaranteed to remain readable JWTs.

#### Sovereign and private endpoint overrides

Credential documents may set `authority_host`, `graph_base_url`, and
`management_base_url` for Microsoft national clouds or authorized test/private
endpoints. Keep all three values aligned with the target cloud.

During scanning, validated Entra client secrets detected with their tenant and
client IDs, plus Azure-context OAuth2 JWTs, can automatically feed
`scan --blast-radius`.

### Azure DevOps (scan `--blast-radius` only)

Azure DevOps blast-radius mapping is supported when a **validated Azure DevOps PAT** is discovered during scanning (the `access_map` record includes both the PAT and the organization). At the moment, there is **no standalone** `kingfisher blast-radius azure-devops ...` provider flag.

### PostgreSQL (`postgres`)

- **Credential**: a single Postgres connection URI string (read from a file).

#### Standalone example (Postgres)

```bash
printf '%s' 'postgres://user:pass@db.example.com:5432/mydb' > ./postgres.uri
kingfisher blast-radius postgres ./postgres.uri --format json > postgres.blast-radius.json
```

Kingfisher derives role attributes and memberships from PostgreSQL's documented
[`pg_roles`](https://www.postgresql.org/docs/current/view-pg-roles.html) and
[`pg_auth_members`](https://www.postgresql.org/docs/current/catalog-pg-auth-members.html) catalogs.
Database checks use PostgreSQL's
[`has_database_privilege`](https://www.postgresql.org/docs/current/functions-info.html) function;
effective table privileges come from
[`pg_catalog.pg_tables`](https://www.postgresql.org/docs/current/view-pg-tables.html) combined with
[`has_table_privilege`](https://www.postgresql.org/docs/current/functions-info.html), so inherited
role and `PUBLIC` privileges are included.
The PostgreSQL source and documentation carrying these interfaces use the permissive PostgreSQL
License.

### MongoDB (`mongodb` / `mongo`)

- **Credential**: a single MongoDB connection URI string (read from a file), including `mongodb+srv://...` URIs.

#### Standalone example (MongoDB)

```bash
printf '%s' 'mongodb+srv://user:pass@cluster.example.net/?retryWrites=true&w=majority' > ./mongodb.uri
kingfisher blast-radius mongodb ./mongodb.uri --format json > mongodb.blast-radius.json
```

To inspect a direct rule mapping in the interactive viewer without saving the credential-bearing
result to a report file:

```bash
printf '%s' 'ghp_example0000000000000000000000000000' \
  | kingfisher blast-radius \
      --rule betterleaks.github-pat \
      - \
      --view-report
```

For a GitHub PAT file, use the same option:

```bash
printf '%s' 'ghp_example0000000000000000000000000000' > ./github.token
kingfisher blast-radius github ./github.token --view-report
```

### Hugging Face (`huggingface` / `hf`)

- **Credential**: a single Hugging Face token string (read from a file for `kingfisher blast-radius huggingface <FILE>`).
- **Token types supported**: tokens accepted by the Hugging Face API with `Authorization: Bearer <TOKEN>`, including:
  - User access tokens (commonly `hf_...`)
  - Organization API tokens (commonly `api_org_...`)

Kingfisher queries the `/api/whoami-v2` endpoint to resolve the token identity,
role, and organization memberships. It uses Hugging Face's vendor-documented unified repository
storage listings for the user and each organization to map visible models, datasets, Spaces, and
storage buckets. Resource visibility
(`public`, `private`, or protected Spaces) and storage usage are included when
reported by the API.

#### Standalone example (Hugging Face)

```bash
printf '%s' 'hf_example...' > ./huggingface.token
kingfisher blast-radius huggingface ./huggingface.token --format json > huggingface.blast-radius.json
```

#### Notes (Hugging Face)

- Blast-radius mapping uses `https://huggingface.co/api` as the API base.
- Token role (`read`, `write`, or `fineGrained`) is derived from the `auth`
  section of the whoami response when available.
- Fine-grained tokens are not treated as administrator tokens. Their exact
  per-resource scopes are not exposed by `whoami`, so the map reports resources
  the token could enumerate and notes that limitation.
- Organization roles (`no_access`, `read`, `contributor`, `write`, and `admin`)
  are recorded separately from the token role because effective access is the
  intersection of both.
- Implementation provenance: the response fields and repository inventory routes are defined in
  Hugging Face's [Hub OpenAPI schema](https://huggingface.co/.well-known/openapi.json), and bucket
  behavior follows the official [Storage Buckets guide](https://huggingface.co/docs/hub/storage-buckets).
  Identity and token-role handling also follows the Apache-2.0
  [`huggingface_hub` v0.24.3 SDK](https://github.com/huggingface/huggingface_hub/tree/v0.24.3).

### Gitea (`gitea`)

- **Credential**: a single Gitea token string (read from a file for `kingfisher blast-radius gitea <FILE>`).
- **Token types supported**: any token accepted by Gitea's `Authorization: token <TOKEN>` header (personal access tokens).

Kingfisher queries `/api/v1/user` for identity, enumerates organizations via `/api/v1/user/orgs`, and lists accessible repositories via `/api/v1/user/repos`. Repository-level permissions (admin, push, pull) are used to classify risk.

#### Standalone example (Gitea)

```bash
printf '%s' 'your_gitea_pat...' > ./gitea.token
kingfisher blast-radius gitea ./gitea.token --format json > gitea.blast-radius.json
```

#### Notes (Gitea)

- Blast-radius mapping currently uses `https://gitea.com/api/v1/` as the default API base.
- If the token belongs to a site administrator, severity is classified as Critical.

### Bitbucket (`bitbucket`)

- **Credential**: a single Bitbucket token string (read from a file for `kingfisher blast-radius bitbucket <FILE>`).
- **Token types supported**: tokens accepted by Bitbucket Cloud's `Authorization: Bearer <TOKEN>` header (OAuth access tokens, app passwords, repository access tokens).

Kingfisher queries `/2.0/user` for identity, enumerates workspace memberships and permissions via `/2.0/user/permissions/workspaces`, and lists accessible repositories via `/2.0/repositories?role=member`. Workspace ownership and private repository access are used to classify risk.

#### Standalone example (Bitbucket)

```bash
printf '%s' 'your_bitbucket_token...' > ./bitbucket.token
kingfisher blast-radius bitbucket ./bitbucket.token --format json > bitbucket.blast-radius.json
```

#### Notes (Bitbucket)

- Blast-radius mapping uses `https://api.bitbucket.org/2.0` as the API base.
- Workspace owners are classified as High severity.

### Buildkite (`buildkite`)

- **Credential**: a single Buildkite API token string (read from a file for `kingfisher blast-radius buildkite <FILE>`).
- **Token types supported**: tokens accepted by Buildkite's REST API with `Authorization: Bearer <TOKEN>` (API access tokens, commonly `bkua_...`).

Kingfisher queries `/v2/access-token` for token metadata and scopes, `/v2/user` for identity, `/v2/organizations` for organization memberships, and `/v2/organizations/{org}/pipelines` for pipeline enumeration. Token scopes and organization access are used to classify risk.

#### Standalone example (Buildkite)

```bash
printf '%s' 'bkua_example...' > ./buildkite.token
kingfisher blast-radius buildkite ./buildkite.token --format json > buildkite.blast-radius.json
```

#### Notes (Buildkite)

- Blast-radius mapping uses `https://api.buildkite.com/v2` as the API base.
- Tokens with `write_organizations` or `write_teams` scopes are classified as High severity.

### Harness (`harness`)

- **Credential**: a single Harness API key / personal access token (PAT) string (read from a file for `kingfisher blast-radius harness <FILE>`).
- **Auth header**: Harness APIs authenticate via `x-api-key: <TOKEN>` (see the Harness API docs).

Kingfisher performs best-effort, read-only enumeration:

- Queries the API key aggregate endpoint for basic token metadata (when available).
- Enumerates organizations via `GET https://app.harness.io/v1/orgs` and projects via `GET https://app.harness.io/v1/orgs/{org}/projects` when the key has permission.

If organizations/projects are not enumerable (scope-limited keys), Kingfisher still produces a blast-radius record with a conservative severity and a note explaining the limitation.

#### Standalone example (Harness)

```bash
printf '%s' 'pat.example...' > ./harness.token
kingfisher blast-radius harness ./harness.token --format json > harness.blast-radius.json
```

#### Notes (Harness)

- Blast-radius mapping uses `https://app.harness.io` as the API base.

### OpenAI (`openai`)

- **Credential**: a single OpenAI API key string (read from a file for `kingfisher blast-radius openai <FILE>`).
- **Token types supported**: OpenAI keys accepted by `Authorization: Bearer <TOKEN>` (for example `sk-...`, `sk-proj-...`, `sk-svcacct-...`).

Kingfisher performs only documented read-only inventory requests. It does not send synthetic write
requests or infer access to one endpoint from another endpoint's response. Current inventory uses:

- `GET https://api.openai.com/v1/models` to verify Models API read access and enumerate visible models.
- `GET https://api.openai.com/v1/organization/projects` for project visibility when the key has permission.
- For organization admin keys, documented GET-only project administration inventory: API keys,
  service accounts, users, model policies, hosted-tool settings, and model rate limits.
- `GET https://api.openai.com/v1/files` to enumerate visible uploaded files when the key has file-list access.
- `GET https://api.openai.com/v1/assistants` to enumerate visible assistants when the key has assistant read access.
- `GET https://api.openai.com/v1/fine_tuning/jobs` to enumerate visible fine-tuning jobs when the key has fine-tuning read access.

#### Standalone example (OpenAI)

```bash
printf '%s' 'sk-example...' > ./openai.token
kingfisher blast-radius openai ./openai.token --format json > openai.blast-radius.json
```

#### Notes (OpenAI)

- Blast-radius mapping uses `https://api.openai.com/v1` as the API base.
- Access is reported only when a list endpoint returns data successfully; no write permission or
  inference capability is claimed from these read-only requests.
- OpenAI does not expose a stable public identity endpoint for every API-key family, so the mapper
  identifies the credential by key family and observed inventory rather than reusing an
  undocumented identity response schema.
- Endpoint selection follows OpenAI's vendor API reference for models, files, assistants,
  fine-tuning jobs, and organization administration. Supported endpoints use the MIT-licensed Rust
  `async-openai` client generated from OpenAI's
  [OpenAPI specification](https://github.com/openai/openai-openapi/blob/master/openapi.yaml).

### Anthropic (`anthropic`)

- **Credential**: a single Anthropic API key string (read from a file for `kingfisher blast-radius anthropic <FILE>`).
- **Token types supported**: Anthropic keys accepted via `x-api-key`, including standard API keys and admin-style keys when exposed by Anthropic.

Kingfisher performs read-only enumeration via:

- `GET https://api.anthropic.com/v1/models` to enumerate visible models.
- `GET https://api.anthropic.com/v1/organizations/api_keys/me` or `GET https://api.anthropic.com/v1/api_keys/me` to introspect the current key when supported.
- `GET https://api.anthropic.com/v1/organizations/api_keys` to enumerate visible organization API keys when the credential can access them.

#### Standalone example (Anthropic)

```bash
printf '%s' 'sk-ant-api-example...' > ./anthropic.token
kingfisher blast-radius anthropic ./anthropic.token --format json > anthropic.blast-radius.json
```

#### Notes (Anthropic)

- Blast-radius mapping uses `https://api.anthropic.com/v1` as the API base.
- Keys that can enumerate organization API keys are treated as having broader administrative visibility.

### Salesforce (`salesforce`)

- **Credential**: Salesforce access token plus instance domain.
- **Supported standalone formats** for `kingfisher blast-radius salesforce <FILE>`:
  - JSON:
    - `token` (or `access_token`)
    - `instance_url` (or `instance`), such as `https://mydomain.my.salesforce.com`
  - Free-form text containing both:
    - a Salesforce access token (`00...!...`)
    - an instance host (`<instance>.my.salesforce.com`, a sandbox My Domain, or a legacy host such as `na123.salesforce.com`)

Kingfisher performs read-only enumeration via:

- `GET /services/data/` to negotiate the newest API version advertised by the org (falling back to `v60.0` if discovery fails).
- `GET /services/data/<version>/limits` to confirm API access and gather account-level API context.
- `GET /services/oauth2/userinfo` for identity metadata when available.
- `GET /services/data/<version>/sobjects` for effective per-object query, search, create, update, delete, and undelete capabilities.
- Read-only SOQL queries for the current user's profile and role, assigned permission sets and permission-set groups, and high-signal effective permissions exposed by `UserPermissionAccess` (best-effort).

Object capabilities are prioritized so sensitive CRM, identity, content, audit, and custom objects remain visible when an org exposes more than the report limit. Salesforce record sharing and field-level security can further restrict the records and fields available within an object.

#### Standalone example (Salesforce)

```bash
cat > ./salesforce.json <<'EOF'
{
  "token": "00DE0X0A0M0PeLE!AQcAQH0dMHEXAMPLE...",
  "instance_url": "https://mydomain.my.salesforce.com"
}
EOF

kingfisher blast-radius salesforce ./salesforce.json --format json > salesforce.blast-radius.json
```

#### Notes (Salesforce)

- Blast-radius mapping accepts production My Domain, sandbox My Domain, and legacy Salesforce instance hosts. Authentication hosts such as `login.salesforce.com` and non-Salesforce hosts are rejected.
- The mapper is read-only and does not issue record-count, export, or data-retrieval queries.

### Weights & Biases (`weightsandbiases` / `wandb`)

- **Credential**: a single Weights & Biases API key string (read from a file for `kingfisher blast-radius weightsandbiases <FILE>`).
- **Token types supported**:
  - Legacy 40-character hex API keys
  - New v1 keys (`wandb_v1_...`)

Kingfisher performs read-only identity resolution via:

- `POST https://api.wandb.ai/graphql` with a GraphQL `viewer` query.

#### Standalone example (Weights & Biases)

```bash
printf '%s' 'wandb_v1_example...' > ./wandb.token
kingfisher blast-radius weightsandbiases ./wandb.token --format json > wandb.blast-radius.json
```

#### Notes (Weights & Biases)

- Blast-radius mapping uses `https://api.wandb.ai/graphql` as the API endpoint.
- W&B key introspection does not currently expose fine-grained scopes in this workflow, so risk is reported conservatively.

### Microsoft Teams (`microsoftteams` / `msteams`)

- **Credential**: a Microsoft Teams Incoming Webhook URL (read from a file for `kingfisher blast-radius microsoftteams <FILE>`).
- **Webhook types supported**:
  - Legacy Incoming Webhooks (`*.office.com/webhook/...`)
  - Workflow-based webhooks (`*.webhook.office.com/webhookb2/...`)

Kingfisher parses the webhook URL to extract the tenant ID and webhook identity, then sends a benign probe (`{"text":""}`) to determine whether the webhook is still active. Active webhooks can post messages to the configured Teams channel.

#### Standalone example (Microsoft Teams)

```bash
printf '%s' 'https://contoso.webhook.office.com/webhookb2/...' > ./teams.webhook
kingfisher blast-radius microsoftteams ./teams.webhook --format json > teams.blast-radius.json
```

#### Notes (Microsoft Teams)

- The webhook URL is the credential — it contains the tenant ID and grants write access to a single Teams channel.
- Blast-radius severity is Medium for active webhooks (write-only to one channel) and Low for inactive/removed webhooks.
- The probe request does not post any visible message; Teams responds with HTTP 400 "Text is required" for valid endpoints.

### monday.com (`monday`)

- **Credential**: a single monday.com API token (read from a file for `kingfisher blast-radius monday <FILE>`).
- **Token types supported**: personal or account-level API tokens accepted by the monday.com GraphQL API with the `Authorization: <TOKEN>` header (the JWT-style token is sent verbatim, without the `Bearer` prefix — this matches monday.com's native scheme).

Kingfisher performs read-only enumeration against `https://api.monday.com/v2`:

- `me { ..., account { id, name, slug, plan { tier } }, teams { name } }` for caller identity, role, and account metadata
- `workspaces(limit: 100) { id, name, kind, state }` for workspace-level resource exposure
- `boards(limit: 50) { id, name, board_kind, state }` for board-level resource exposure

Severity is Critical for account administrators, High for standard members with broad workspace/board visibility (>5 workspaces or >20 boards), Medium for standard members with any workspace/board access, and Low for guest/viewer tokens or empty accounts.

#### Standalone example (monday.com)

```bash
printf '%s' 'eyJhbGciOi...' > ./monday.token
kingfisher blast-radius monday ./monday.token --format json > monday.blast-radius.json
```

#### Notes (monday.com)

- Blast-radius mapping currently uses `https://api.monday.com/v2` (GraphQL v2) as the API base.
- monday.com API tokens do not carry granular scopes; permissions follow the underlying user's role (admin/member/viewer/guest).
- `provider_metadata.version` carries the monday.com plan tier when exposed by the account.
- The standalone provider remains available. The validated `betterleaks.monday-api-token.1` rule
  also supports automatic `scan --blast-radius` collection.

### Asana (`asana`)

- **Credential**: a single Asana access token (read from a file for `kingfisher blast-radius asana <FILE>`).
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
kingfisher blast-radius asana ./asana.token --format json > asana.blast-radius.json
```

#### Notes (Asana)

- Asana access tokens do not expose granular scopes. Access follows the underlying user's membership in each workspace, organization, and team.
- `token_details.token_type` is classified from the token prefix (`personal_access_token_v2`, `personal_access_token_v1`, `oauth_or_legacy_pat`, or generic `asana_token`).
- The standalone provider remains available. The current Betterleaks catalog does not expose a
  compatible validated Asana rule for automatic `scan --blast-radius` collection.

### Pinecone (`pinecone`)

- **Credential**: a single Pinecone API key (read from a file for `kingfisher blast-radius pinecone <FILE>`).
- **Token types supported**: API keys accepted by Pinecone's control-plane API with the `Api-Key: <KEY>` header.

Kingfisher performs read-only enumeration against `https://api.pinecone.io` (`X-Pinecone-API-Version: 2025-10`):

- `GET /indexes` for index inventory, dimension, metric, status, deletion-protection state, and serverless cloud/region or pod environment/type
- `GET /collections` for collection inventory in pod-based projects (gracefully skipped on serverless-only projects)

Severity is High when the token reaches more than 10 indexes, Medium when it reaches one or more indexes (especially with deletion protection disabled) or any collections, and Low for empty projects or validation failures.

#### Standalone example (Pinecone)

```bash
printf '%s' '62b0dbfe-3489-4b79-b850-34d911527c88' > ./pinecone.key
kingfisher blast-radius pinecone ./pinecone.key --format json > pinecone.blast-radius.json
```

#### Notes (Pinecone)

- Pinecone API keys do not carry granular scopes; access follows the API key's project-level permissions, which include read and write (upsert/delete) against any index in the project.
- Indexes with `deletion_protection: enabled` are flagged in the resource record but still accessible for read/write.
- Recorded during `scan --blast-radius` for validated
  `betterleaks.pinecone-api-key.1` and `betterleaks.pinecone-api-key.2` findings.

## Notes on blast-radius generation during `scan --blast-radius`

- Blast-radius entries are recorded for **validated** findings. A capability may explicitly allow
  a reachable 2xx result when that provider's validator cannot classify it more precisely (the
  current GitLab mappings use this behavior).
- Some providers require extra context that Kingfisher infers from the finding context or validation response (for example, Azure DevOps organization name).
- Automatic collection is driven by successfully validated imported credential shapes with an
  explicit Kingfisher blast-radius handler. Standalone providers remain usable even when Betterleaks
  has no compatible validation rule.
- Imported-detector ID-to-handler and component bindings live in
  `crates/kingfisher-rules/data/imported-rules-capabilities.yml`. The build verifies those bindings
  against the downloaded imported-detector catalog; blast-radius Rust code does not match rule IDs.
