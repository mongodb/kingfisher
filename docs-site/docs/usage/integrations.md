---
title: "Platform Integrations"
description: "Scan GitHub, GitLab, Azure Repos, Bitbucket, Gitea, Hugging Face, Docker, S3, Jira, Confluence, Slack, and Teams for leaked secrets."
---

# Platform Integrations

This guide covers how to scan various platforms and services with Kingfisher.

## Table of Contents

- [AWS S3](#aws-s3)
- [Google Cloud Storage](#google-cloud-storage)
- [Docker](#docker)
- [GitHub](#github)
- [GitLab](#gitlab)
- [Azure Repos](#azure-repos)
- [Gitea](#gitea)
- [Bitbucket](#bitbucket)
- [Hugging Face](#hugging-face)
- [Jira](#jira)
- [Confluence](#confluence)
- [Slack](#slack)
- [Microsoft Teams](#microsoft-teams)
- [Postman](#postman)
- [Environment Variables](#environment-variables)

## AWS S3

You can scan S3 objects directly:

```bash
kingfisher scan s3 bucket-name [--prefix path/]
```

Credential resolution happens in this order:

1. `KF_AWS_KEY` and `KF_AWS_SECRET` environment variables (optionally `KF_AWS_SESSION_TOKEN` for temporary credentials)
2. `--profile` pointing to a profile in `~/.aws/config` (works with AWS SSO)
3. anonymous access for public buckets

If `--role-arn` is supplied, the credentials from steps 1–2 are used to assume that role.

### Examples

```bash
# using explicit keys
export KF_AWS_KEY=AKIA...
export KF_AWS_SECRET=g5nYW...
kingfisher scan s3 some-example-bucket

# Above can also be run as:
KF_AWS_KEY=AKIA... KF_AWS_SECRET=g5nYW... kingfisher scan s3 some-example-bucket

# using a local profile (e.g., SSO) that exists in your AWS profile (~/.aws/config)
kingfisher scan s3 some-example-bucket --profile default

# anonymous scan of a bucket, while providing an object prefix to only scan subset of the s3 bucket
kingfisher scan s3 awsglue-datasets \
  --prefix examples/us-legislators/all

# assuming a role when scanning
kingfisher scan s3 some-example-bucket \
  --role-arn arn:aws:iam::123456789012:role/MyRole

# anonymous scan of a public bucket
kingfisher scan s3 some-example-bucket
```

Docker example:

```bash
docker run --rm \
  -e KF_AWS_KEY=AKIA... \
  -e KF_AWS_SECRET=g5nYW... \
  ghcr.io/mongodb/kingfisher:latest \
    scan s3 bucket-name
```

## Google Cloud Storage

Use the `gcs` scan subcommand to stream objects directly from Google Cloud Storage. Authentication
uses Application Default Credentials, so you can provide a service-account JSON file via the
`GOOGLE_APPLICATION_CREDENTIALS` environment variable or by passing `--service-account`. Public
buckets work without credentials.

```bash
kingfisher scan gcs bucket-name

# scan a sub-tree inside the bucket
kingfisher scan gcs bucket-name --prefix path/to/data/

# supply a service-account key explicitly
kingfisher scan gcs bucket-name --service-account /path/to/key.json
```

Functional example:
```bash
kingfisher scan gcs cloud-samples-data --prefix "storage/"
```

## Docker

Kingfisher will first try to use any locally available image, then fall back to pulling via OCI.  

To skip local image lookup, registry access, and `docker save`, scan a Docker or OCI image archive
directly with `--archive`. Archive inputs include files produced by `docker save`. Supported archive
formats are `.tar`, `.tar.gz`, `.tar.gzip`, `.tgz`, `.tar.bz2`, `.tar.bzip2`, and `.tar.xz`.

Authentication happens *in this order*:

1. **`KF_DOCKER_TOKEN`** env var  
   - If it contains `user:pass`, it's used as Basic auth
   - Otherwise it's sent as a Bearer token
2. **Docker CLI credentials**  
   - Checks `credHelpers` (per-registry) and `credsStore` in `~/.docker/config.json`.  
   - Falls back to the legacy `auths` → `auth` (base64) entries.  
3. **Anonymous** (no credentials)

### Examples

```bash
# 1) Scan public or already-pulled image
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# 2) For private registries, explicitly set KF_DOCKER_TOKEN:
#    - Basic auth:     "user:pass"
#    - Bearer only:    "TOKEN"
export KF_DOCKER_TOKEN="AWS:$(aws ecr get-login-password --region us-east-1)"
kingfisher scan docker some-private-registry.dkr.ecr.us-east-1.amazonaws.com/base/amazonlinux2023:latest

# 3) Or rely on your Docker CLI login/keychain:
#    (e.g. aws ecr get-login-password … | docker login …)
kingfisher scan docker private.registry.example.com/my-image:tag

# 4) Scan a Docker image archive created by docker save:
docker save ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master -o image.tar
kingfisher scan docker --archive image.tar
gzip -k image.tar
kingfisher scan docker --archive image.tar.gz
```

> **Deprecated**
> Older documentation may refer to legacy provider flags such as
> `--github-user`, `--gitlab-group`, `--bitbucket-workspace`,
> `--slack-query`, `--jira-url`, `--confluence-url`, `--s3-bucket`,
> `--gcs-bucket`, and `--docker-image`. Use the
> `kingfisher scan <provider>` subcommands below instead.

## GitHub

### Scan GitHub organization (requires `KF_GITHUB_TOKEN`)

```bash
kingfisher scan github --organization my-org
kingfisher scan github --organization my-org --repo-clone-limit 500
```

### Skip specific GitHub repositories during enumeration

Repeat `--github-exclude` for every repository you want to ignore when scanning
users or organizations. You can provide exact repositories like
`OWNER/REPO` or gitignore-style glob patterns such as `owner/*-archive`
(matching is case-insensitive).

```bash
kingfisher scan github --organization my-org \
  --github-exclude my-org/huge-repo \
  --github-exclude my-org/*-archive
```

### Scan remote GitHub repository

Pass a repository URL as a positional scan target to clone and scan its files and history.
(The legacy `--git-url` flag still works but is deprecated.) When the URL
targets GitHub and you pass `--include-contributors`, Kingfisher enumerates
repository contributors and attempts to clone the public repos owned by those
contributors—a common offensive and blue-team pivot when developers leak
secrets in personal or side projects. By default Kingfisher excludes forks;
pass `--github-repo-type all` to include them or `--github-repo-type fork` for
forks only. Use `--repo-clone-limit` to cap how many repositories are cloned
during this enumeration.

**NOTE**: This may cause you to be temporarily rate-limited by GitHub.
Providing a token (`KF_GITHUB_TOKEN`) will provide a higher rate limit.

To inspect related server-side data, supply `--repo-artifacts`. This flag pulls
down the repository's issues (including pull requests), wiki, and any public
gists owned by the repository owner and scans them for secrets. Fetching these
extras counts against API rate limits and private artifacts require a
`KF_GITHUB_TOKEN`.

Use `--git-clone-dir` to choose where cloned repositories land and
`--keep-clones` to preserve them for follow-on analysis.

> **Why can scanning a remote URL report fewer findings than scanning a local checkout?**. 
> 
> Remote clones default to `--mirror`/bare mode so Kingfisher only
> reads the Git history. When you point Kingfisher at an existing working tree (for example
> `kingfisher scan ./repo`), it enumerates both the filesystem contents *and* the Git
> history. Any secrets that are present in the checked-out files therefore appear twice:
> once from the working tree path and once from the commit where the secret entered the
> history. To replicate the remote behavior locally, either scan a bare clone or disable
> history scanning with `--git-history none` when targeting a working tree.

```bash
# Scan the repository only
kingfisher scan github.com/org/repo

# Scan the repository plus contributor repos, but cap the crawl
kingfisher scan https://github.com/org/repo.git \
  --include-contributors \
  --repo-clone-limit 250

# Keep clones for later manual inspection
kingfisher scan https://github.com/org/repo.git \
  --git-clone-dir ./kingfisher-clones \
  --keep-clones

# Include issues, wiki, and owner gists
kingfisher scan https://github.com/org/repo.git --repo-artifacts

# Private repositories or artifacts
KF_GITHUB_TOKEN="ghp_…" kingfisher scan https://github.com/org/private_repo.git --repo-artifacts
```

### Scan a GitHub Enterprise / self-hosted GitHub instance

For GitHub Enterprise Server (GHES) or any self-hosted GitHub install, you
need two flags:

- `--api-url <URL>` (on `kingfisher scan github`) — points the
  **enumeration / clone** flow at the custom API root (typically
  `https://ghe.example.com/api/v3/`).
- `--endpoint github=<URL>` — points the **token validation / revocation**
  flow at the same instance, so any GitHub PATs Kingfisher discovers in the
  scanned source are checked against your GHE rather than `api.github.com`.

```bash
# 1. Scan every org repo on GHE and validate discovered tokens against the same instance
KF_GITHUB_TOKEN="ghp_…" kingfisher scan github \
  --organization my-org \
  --api-url https://ghe.corp.example.com/api/v3/ \
  --endpoint github=https://ghe.corp.example.com

# 2. Scan a single GHE repo by URL (positional target)
KF_GITHUB_TOKEN="ghp_…" kingfisher scan https://ghe.corp.example.com/org/repo.git \
  --endpoint github=https://ghe.corp.example.com

# 3. Scan ALL orgs on a GHE instance (requires non-default --api-url)
KF_GITHUB_TOKEN="ghp_…" kingfisher scan github \
  --all-orgs \
  --api-url https://ghe.corp.example.com/api/v3/ \
  --endpoint github=https://ghe.corp.example.com

# 4. GHE on a private network — add --allow-internal-ips so the validator
#    can reach RFC1918 / loopback hosts (SSRF guard is on by default).
KF_GITHUB_TOKEN="ghp_…" kingfisher scan github \
  --organization my-org \
  --api-url https://ghe.internal/api/v3/ \
  --endpoint github=https://ghe.internal \
  --allow-internal-ips

# 5. Validate a single PAT against GHE without scanning anything
kingfisher validate --rule github \
  --endpoint github=https://ghe.corp.example.com \
  "<your-github-pat>"

# 6. Revoke (delete) a confirmed-leaked PAT against GHE
kingfisher revoke --rule github \
  --endpoint github=https://ghe.corp.example.com \
  "<your-github-pat>"
```

`--api-url` is the GHE *cloning* root that Kingfisher walks to enumerate
orgs, repos, and contributors. `--endpoint github=…` is the *validator*
root used to live-check discovered tokens. They are usually the same host,
but they're separate flags because some deployments front-load auth (an
SSO portal for repo access vs. a direct API endpoint for token
validation).

## GitLab

### Scan GitLab group (requires `KF_GITLAB_TOKEN`)

```bash
kingfisher scan gitlab --group my-group
# include repositories from all nested subgroups
kingfisher scan gitlab --group my-group --include-subgroups
kingfisher scan gitlab --group my-group --repo-clone-limit 500
```

### Scan GitLab user

```bash
kingfisher scan gitlab --user johndoe
```

### Skip specific GitLab projects during enumeration

Repeat `--gitlab-exclude` for every project path you want to ignore when scanning
users or groups. Specify project paths as `group/project` (case-insensitive) or
use gitignore-style glob patterns like `group/**/archive-*` to drop families of
projects across nested subgroups.

```bash
kingfisher scan gitlab --group my-group \
  --gitlab-exclude my-group/huge-project \
  --gitlab-exclude my-group/**/archive-*
```

### Scan remote GitLab repository by URL

A Git URL target by itself clones the project repository. When the URL targets
GitLab and you pass `--include-contributors`, Kingfisher enumerates contributors
and tries to clone **their other public projects** to catch secrets that escape
the main repo. Apply `--repo-clone-limit` to cap the total repos cloned during
this pivot.

**NOTE**: This may cause you to be temporarily rate-limited by GitLab.
Providing a token (`KF_GITLAB_TOKEN`) will provide a higher rate limit.

To include server-side artifacts owned by the project, add `--repo-artifacts`.
Kingfisher will retrieve the project's issues, wiki, and snippets and scan them
for secrets. These extra requests may take longer and require a
`KF_GITLAB_TOKEN` for private projects.

Use `--git-clone-dir` to choose where cloned projects land and `--keep-clones`
to preserve them for later review.

```bash
# Scan the repository only
kingfisher scan gitlab.com/group/project.git

# Scan the repository plus contributor projects, but cap the crawl
kingfisher scan https://gitlab.com/group/project.git \
  --include-contributors \
  --repo-clone-limit 250

# Keep clones for later manual inspection
kingfisher scan https://gitlab.com/group/project.git \
  --git-clone-dir ./kingfisher-clones \
  --keep-clones

# Include issues, wiki, and snippets
kingfisher scan https://gitlab.com/group/project.git --repo-artifacts

# Private projects or artifacts
KF_GITLAB_TOKEN="glpat-…" kingfisher scan https://gitlab.com/group/private_project.git --repo-artifacts
```

### Scan a self-hosted (Omnibus / Cloud Native) GitLab instance

For GitLab self-hosted (Omnibus, Helm, or Cloud Native), pair the
enumeration flag with a matching validation endpoint:

- `--api-url <URL>` (on `kingfisher scan gitlab`) — points the
  **enumeration / clone** flow at the custom GitLab root (typically
  `https://gitlab.example.com/`).
- `--endpoint gitlab=<URL>` — points the **token validation / revocation**
  flow at the same instance, so any GitLab PATs found in the scanned
  source are checked against your self-hosted GitLab rather than
  `gitlab.com`.

```bash
# 1. Scan a self-hosted group and validate discovered tokens against the same instance
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab \
  --group my-group \
  --include-subgroups \
  --api-url https://gitlab.corp.example.com/ \
  --endpoint gitlab=https://gitlab.corp.example.com

# 2. Scan a single self-hosted GitLab project by URL
KF_GITLAB_TOKEN="glpat-…" kingfisher scan https://gitlab.corp.example.com/group/project.git \
  --endpoint gitlab=https://gitlab.corp.example.com

# 3. Scan ALL groups on a self-hosted GitLab (requires non-default --api-url)
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab \
  --all-groups \
  --api-url https://gitlab.corp.example.com/ \
  --endpoint gitlab=https://gitlab.corp.example.com

# 4. Self-hosted GitLab on a private network — add --allow-internal-ips so
#    the validator can reach RFC1918 / loopback hosts.
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab \
  --group my-group \
  --api-url https://gitlab.internal/ \
  --endpoint gitlab=https://gitlab.internal \
  --allow-internal-ips

# 5. Validate a single PAT against self-hosted GitLab without scanning anything
kingfisher validate --rule gitlab \
  --endpoint gitlab=https://gitlab.corp.example.com \
  "<your-gitlab-pat>"

# 6. Revoke (delete) a confirmed-leaked PAT against self-hosted GitLab
kingfisher revoke --rule gitlab \
  --endpoint gitlab=https://gitlab.corp.example.com \
  "<your-gitlab-pat>"
```

### Many endpoints at once: `--endpoint-config`

If you maintain a fleet of self-hosted instances (GHE, self-hosted GitLab,
Gitea, Jira DC, Confluence, Artifactory), put them in a single YAML file
and reference it instead of repeating `--endpoint` on every command:

```yaml
# kingfisher-endpoints.yml
endpoints:
  github: https://ghe.corp.example.com
  gitlab: https://gitlab.corp.example.com
  gitea: https://gitea.corp.example.com
  jira: https://jira.corp.example.com
  confluence: https://wiki.corp.example.com
  artifactory: http://artifactory.internal:8081
```

```bash
KF_GITHUB_TOKEN="ghp_…" KF_GITLAB_TOKEN="glpat-…" kingfisher scan github \
  --organization my-org \
  --api-url https://ghe.corp.example.com/api/v3/ \
  --endpoint-config ./kingfisher-endpoints.yml \
  --allow-internal-ips
```

### Tip: bake the endpoints into `kingfisher.yaml`

Once you've worked out the right flags, capture them as project defaults
so every scan uses the same config:

```bash
kingfisher config init \
  --github-api-url https://ghe.corp.example.com/api/v3/ \
  --gitlab-api-url https://gitlab.corp.example.com/ \
  --endpoint github=https://ghe.corp.example.com \
  --endpoint gitlab=https://gitlab.corp.example.com \
  --allow-internal-ips \
  > kingfisher.yaml

# Then every scan inherits the same self-hosted defaults:
KF_GITHUB_TOKEN="ghp_…" kingfisher scan github --organization my-org \
  --config ./kingfisher.yaml
```

### List GitLab repositories

```bash
kingfisher scan gitlab --group my-group --list-only
# include repositories from all nested subgroups
kingfisher scan gitlab --group my-group --include-subgroups --list-only
# skip specific projects when listing or scanning (supports glob patterns)
kingfisher scan gitlab --group my-group --gitlab-exclude my-group/**/legacy-* --list-only
```

## Azure Repos

### Scan Azure Repos organization or collection (requires `KF_AZURE_TOKEN` or `KF_AZURE_PAT`)

```bash
kingfisher scan azure --azure-organization my-org

# Azure Repos Server example
KF_AZURE_PAT="pat" kingfisher scan azure --azure-organization DefaultCollection --base-url https://ado.internal.example/tfs/
```

### Scan specific Azure Repos projects

Projects are specified as `ORGANIZATION/PROJECT`. Repeat the flag for multiple projects.

```bash
kingfisher scan azure --azure-project my-org/payments \
  --azure-project my-org/core-platform
```

### Skip specific Azure repositories during enumeration

Repeat `--azure-exclude` to ignore repositories when scanning organizations or projects.
Use identifiers like `ORGANIZATION/PROJECT/REPOSITORY`. Repositories that share the same
name as their project can be excluded with `ORGANIZATION/PROJECT`, and gitignore-style
patterns such as `my-org/*/archive-*` are also supported.

```bash
kingfisher scan azure --azure-organization my-org \
  --azure-exclude my-org/payments/legacy-service \
  --azure-exclude my-org/**/archive-*
```

### List Azure repositories

```bash
kingfisher scan azure --azure-organization my-org --list-only
# list repositories for specific projects
kingfisher scan azure --azure-project my-org/app --azure-project my-org/api --list-only
# skip specific repositories while listing (supports glob patterns)
kingfisher scan azure --azure-organization my-org --azure-exclude my-org/**/experimental-* --list-only
```

## Gitea

### Scan Gitea organization (requires `KF_GITEA_TOKEN`)

```bash
kingfisher scan gitea --organization my-org
# self-hosted example
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --organization platform --api-url https://gitea.internal.example/api/v1/
```

### Scan Gitea user

```bash
kingfisher scan gitea --user johndoe
```

### Skip specific Gitea repositories during enumeration

Repeat `--gitea-exclude` for each repository you want to ignore when scanning users
or organizations. Accepts `owner/repo` identifiers or gitignore-style glob patterns
like `team/**/archive-*`.

```bash
kingfisher scan gitea --organization my-org \
  --gitea-exclude my-org/legacy-repo \
  --gitea-exclude my-org/**/archive-*
```

### Scan remote Gitea repository by URL

A Git URL target clones the repository and scans its history. Adding `--repo-artifacts`
also clones the repository wiki if one exists. Private repositories and wikis
require `KF_GITEA_TOKEN` (and `KF_GITEA_USERNAME` when cloning via HTTPS).

```bash
# Scan the repository only
kingfisher scan https://gitea.com/org/repo.git

# Include the repository wiki (if present)
KF_GITEA_TOKEN="gtoken" KF_GITEA_USERNAME="org" \
  kingfisher scan https://gitea.com/org/repo.git --repo-artifacts
```

### List Gitea repositories

```bash
kingfisher scan gitea --organization my-org --list-only
# enumerate every organization visible to the authenticated user
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --all-organizations --list-only
# self-hosted example
KF_GITEA_TOKEN="gtoken" kingfisher scan gitea --user johndoe --api-url https://gitea.internal.example/api/v1/ --list-only
```

## Bitbucket

### Scan Bitbucket workspace

```bash
kingfisher scan bitbucket --workspace my-team
# include Bitbucket Cloud repositories from every accessible workspace
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket --all-workspaces
```

### Scan Bitbucket user

```bash
kingfisher scan bitbucket --user johndoe
```

### Skip specific Bitbucket repositories during enumeration

Use `--bitbucket-exclude` to ignore repositories while scanning users, workspaces,
or projects. Patterns accept either `owner/repo` (case-insensitive) or
gitignore-style globs such as `workspace/**/archive-*`.

```bash
kingfisher scan bitbucket --workspace my-team \
  --bitbucket-exclude my-team/legacy-repo \
  --bitbucket-exclude my-team/**/archive-*
```

### Scan remote Bitbucket repository by URL

A Git URL target clones the repository and scans its files and history. To inspect
Bitbucket artifacts such as issues, add `--repo-artifacts`. Private artifacts
require credentials (see [Authenticate to Bitbucket](#authenticate-to-bitbucket)).

```bash
# Scan the repository only
kingfisher scan https://bitbucket.org/hashashash/secretstest.git

# Include repository issues
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan https://bitbucket.org/workspace/project.git --repo-artifacts
```

### List Bitbucket repositories

```bash
kingfisher scan bitbucket --workspace my-team --list-only
# enumerate all accessible workspaces or projects
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket --all-workspaces --list-only
# filter out repositories using glob patterns
kingfisher scan bitbucket --workspace my-team --bitbucket-exclude my-team/**/experimental-* --list-only
```

### Authenticate to Bitbucket

Kingfisher supports Bitbucket Cloud and Bitbucket Server credentials:

- **Workspace API token (Cloud)** – set `KF_BITBUCKET_TOKEN`. Kingfisher automatically uses the token for Bitbucket REST APIs and authenticates git operations as `x-token-auth`.
- **Bitbucket Server token** – set `KF_BITBUCKET_USERNAME` and either
  `KF_BITBUCKET_TOKEN` or `KF_BITBUCKET_PASSWORD`.
- **Legacy app password (Cloud)** – set `KF_BITBUCKET_USERNAME` and
  `KF_BITBUCKET_APP_PASSWORD`.
- **OAuth/PAT token** – set `KF_BITBUCKET_OAUTH_TOKEN`.

These credentials match the options described in the [ghorg setup
guide](https://github.com/gabrie30/ghorg/blob/master/README.md#bitbucket-setup).

Bitbucket no longer supports App Tokens as of September 9, 2025:
https://support.atlassian.com/bitbucket-cloud/docs/api-tokens/

> As of September 9, 2025, app passwords can no longer be created. Use API tokens with scopes instead. All existing app passwords will be disabled on June 9, 2026. Migrate any integrations before then to avoid disruptions.

### Self-hosted Bitbucket Server

Use `--api-url` to point Kingfisher at your server's REST endpoint, for example
`https://bitbucket.example.com/rest/api/1.0/`. Provide credentials with
`KF_BITBUCKET_USERNAME` plus either `KF_BITBUCKET_TOKEN` or `KF_BITBUCKET_PASSWORD`,
and pass `--ignore-certs` when connecting to HTTP or otherwise insecure instances.

## Hugging Face

Hugging Face hosts git repositories for models, datasets, and Spaces. Kingfisher can enumerate and scan all three resource types.

### Scan Hugging Face user

```bash
kingfisher scan huggingface --huggingface-user <username>
```

### Scan Hugging Face organization

```bash
kingfisher scan huggingface --huggingface-organization <orgname>
```

### Scan specific Hugging Face resources

Scan individual repositories by ID (owner/name) or by passing the full HTTPS URL:

```bash
kingfisher scan huggingface --huggingface-model <owner/model>
kingfisher scan huggingface --huggingface-dataset https://huggingface.co/datasets/<owner>/<dataset>
kingfisher scan huggingface --huggingface-space <owner/space>
```

Use `--huggingface-exclude` to omit results returned by user or organization enumeration. Prefix values with `model:`, `dataset:`, or `space:` when you only want to skip a specific resource type.

### List Hugging Face repositories

```bash
kingfisher scan huggingface --huggingface-user <username> --list-only
```

### Authenticate to Hugging Face

Private repositories require an access token provided through the `KF_HUGGINGFACE_TOKEN` environment variable. For git authentication the helper also honours `KF_HUGGINGFACE_USERNAME` (default `hf_user`).

## Jira

### Scan Jira issues matching a JQL query

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
    --jql "project = TEST AND status = Open" \
    --max-results 500
```

### Include Jira comments and changelog entries

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
    --jql "project = TEST AND status = Open" \
    --include-comments \
    --include-changelog
```

`--include-comments` writes and scans per-issue `comments.json` artifacts.  
`--include-changelog` writes and scans per-issue `changelog.json` artifacts.

### Scan the last 1,000 Jira issues

```bash
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.mongodb.org \
  --jql 'ORDER BY created DESC' \
  --max-results 1000
```

## Confluence

### Scan Confluence pages matching a CQL query

```bash
# Bearer token
KF_CONFLUENCE_TOKEN="token" kingfisher scan confluence --url https://confluence.company.com \
    --cql "label = secret" \
    --max-results 500

# Basic auth with username and token
KF_CONFLUENCE_USER="user@example.com" KF_CONFLUENCE_TOKEN="token" \
  kingfisher scan confluence --url https://confluence.company.com \
    --cql "text ~ 'password'" \
    --max-results 500
```

Use the base URL of your Confluence site for `--url`. Kingfisher
automatically adds `/rest/api` to the end, so `https://example.com/wiki` and
`https://example.com` both work depending on your server configuration.

Generate a personal access token and set it in the `KF_CONFLUENCE_TOKEN` environment variable. By default, Kingfisher sends the token as a bearer token in the `Authorization` header.

To use basic authentication instead, also set `KF_CONFLUENCE_USER` to your Confluence email address; Kingfisher will then send the username and `KF_CONFLUENCE_TOKEN` as a Basic auth header. If the server responds with a redirect to a login page, the credentials are invalid or lack the required permissions.

## Slack

### Scan Slack messages matching a search query

```bash
KF_SLACK_TOKEN="<your-slack-user-token>" kingfisher scan slack "from:username has:link" \
    --max-results 1000

KF_SLACK_TOKEN="<your-slack-user-token>" kingfisher scan slack "akia" \
    --max-results 1000
```

*The Slack token must be a user token with the `search:read` scope. Bot tokens (those beginning with `xoxb-`) cannot call the Slack search API.*

## Microsoft Teams

### Scan Teams messages matching a search query

```bash
KF_TEAMS_TOKEN="eyJ0..." kingfisher scan teams "password OR api_key" \
    --max-results 1000

KF_TEAMS_TOKEN="eyJ0..." kingfisher scan teams "akia" \
    --max-results 1000
```

The token must be a Microsoft Graph API access token with `ChannelMessage.Read.All` (application) or `Chat.Read` (delegated) permissions.

**Note:** Microsoft Graph does not support personal Microsoft accounts for Teams chat operations. Teams scanning requires a **Microsoft 365 work or school account**; free/personal Teams accounts are not supported by the Graph API.

**Obtaining a token:**

1. Register an application in Azure Active Directory (Microsoft Entra ID)
2. Grant `ChannelMessage.Read.All` (application) or `Chat.Read` (delegated) API permission
3. Obtain an access token using one of:
   - Azure CLI: `az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv`
   - Client credentials flow for application permissions
   - Authorization code flow for delegated permissions

## Postman

Kingfisher fetches Postman workspaces, collections, and environments via the public Postman API (`https://api.getpostman.com/`) and scans the JSON for hard-coded credentials. The most common high-value findings are:

- Bearer tokens, API keys, and basic-auth passwords inside collection request `auth` blocks
- Hard-coded credentials inside pre-request and test scripts
- Saved example responses that echo tokens
- **"Secret"-typed environment variables** — Postman's `secret` flag is a UI-mask only, the API returns the plaintext value to any read-capable key

### Scan every workspace, collection, and environment visible to the API key

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all
```

### Scan a specific workspace (by ID or web URL)

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman \
    --workspace 11111111-2222-3333-4444-555555555555

KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman \
    --workspace https://www.postman.com/team-handle/workspace/abc-uid-123
```

### Scan a single collection or environment

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman \
    --collection 12345678-abcd-efgh-ijkl-mnopqrstuvwx

KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman \
    --environment 12345678-abcd-efgh-ijkl-mnopqrstuvwx
```

### Include mocks and monitors

Mocks and monitors are scanned only when explicitly requested (they are lower-yield surfaces):

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all \
    --include-mocks-monitors
```

### Self-hosted / enterprise endpoint

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all \
    --api-url https://postman.internal.example.com/
```

The token is sent as the `X-Api-Key` header. Either `KF_POSTMAN_TOKEN` or `POSTMAN_API_KEY` is accepted (the latter matches the env var Postman's own docs reference). Mint a key from postman.com → Settings → API keys.

> Top-level `kingfisher scan --postman-*` flags remain accepted as hidden aliases for backward compatibility, but new usage should prefer the `kingfisher scan postman` subcommand shown above.

**Out of scope:** Postman Vault secrets are client-side and not reachable via the API. The Postman API Network does not expose a search endpoint; supply specific public-workspace IDs via `kingfisher scan postman --workspace` to scan public surfaces.

## Environment Variables

| Variable          | Purpose                      |
| ----------------- | ---------------------------- |
| `KF_GITHUB_TOKEN` | GitHub Personal Access Token |
| `KF_GITLAB_TOKEN` | GitLab Personal Access Token |
| `KF_GITEA_TOKEN` | Gitea Personal Access Token |
| `KF_GITEA_USERNAME` | Username for private Gitea clones (used with `KF_GITEA_TOKEN`) |
| `KF_AZURE_TOKEN` / `KF_AZURE_PAT` | Azure Repos Personal Access Token |
| `KF_AZURE_USERNAME` | Username to use with Azure Repos PATs (defaults to `pat` when unset) |
| `KF_BITBUCKET_TOKEN` | Bitbucket Cloud workspace API token or Bitbucket Server PAT |
| `KF_BITBUCKET_USERNAME` | Optional Bitbucket username for legacy app passwords or server tokens |
| `KF_BITBUCKET_APP_PASSWORD` | Legacy Bitbucket app password (deprecated September 9, 2025; disabled June 9, 2026) |
| `KF_BITBUCKET_OAUTH_TOKEN` | Bitbucket OAuth or PAT token |
| `KF_HUGGINGFACE_TOKEN` | Hugging Face access token for API enumeration and git cloning |
| `KF_HUGGINGFACE_USERNAME` | Optional username for Hugging Face git operations (defaults to `hf_user`) |
| `KF_JIRA_TOKEN`   | Jira API token               |
| `KF_CONFLUENCE_TOKEN` | Confluence API token      |
| `KF_SLACK_TOKEN`  | Slack API token              |
| `KF_TEAMS_TOKEN`  | Microsoft Graph API token for Teams message search |
| `KF_POSTMAN_TOKEN` / `POSTMAN_API_KEY` | Postman API key (sent as `X-Api-Key`) for workspace, collection, and environment scanning |
| `KF_DOCKER_TOKEN` | Docker registry token (`user:pass` or bearer token). If unset, credentials from the Docker keychain are used |
| `KF_AWS_KEY`, `KF_AWS_SECRET`, and `KF_AWS_SESSION_TOKEN` | AWS credentials for S3 bucket scanning. Session token is optional, for temporary credentials |

Set them temporarily per command:

```bash
KF_GITLAB_TOKEN="glpat-…" kingfisher scan gitlab --group my-group
```

Or export for the session:

```bash
export KF_GITLAB_TOKEN="glpat-…"
```

To authenticate Jira requests:
```bash
export KF_JIRA_TOKEN="token"
```

To authenticate Confluence requests:
```bash
export KF_CONFLUENCE_TOKEN="token"
```

*If no token is provided Kingfisher still works for public repositories.*
