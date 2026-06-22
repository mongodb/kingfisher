# Project Configuration (`kingfisher.yaml`)

Long CLI invocations are awkward in CI. Kingfisher loads a project-local
`kingfisher.yaml` to provide defaults for nearly every `kingfisher scan` flag,
plus alert webhooks and filter lists. Lists are **additive** (config + CLI
concatenated); scalars are **default-only** — a config value applies only when
the user did not pass the matching `--flag`. This keeps CI overrides
predictable and makes the CLI authoritative.

## Loading a config

Kingfisher does **not** auto-discover `kingfisher.yaml`. The file is loaded
only when you pass `--config FILE` explicitly:

```bash
kingfisher scan . --config ./kingfisher.yaml
```

A missing or malformed file is a fatal error — there is no silent fallback,
so a typo in the path or a broken YAML block fails fast instead of running
with surprising defaults. Auto-discovery was rejected because it makes scan
results depend on where the binary was launched from, which is too easy to
get wrong in CI.

## Precedence

```
CLI flag  >  environment variable  >  kingfisher.yaml  >  built-in default
```

For list-typed values both sources are concatenated, so passing
`--skip-word EXAMPLE` and listing `EXAMPLE` again in `kingfisher.yaml` is safe
but redundant. The one nuance: `rules.enabled` *replaces* the synthetic
`["all"]` default when you don't pass `--rule`, so a config that lists
`["custom"]` actually narrows the selection.

## End-to-end: create a config and scan with it

### Step 1 — generate the config

Don't write the YAML by hand. Start from the **scan-default flags** you
already pass to `kingfisher scan` (the policy-shaped ones — confidence,
redaction, filters, output, alerts, TLS, self-hosted API roots) and pass
them to `kingfisher config init`:

```bash
# Print to stdout, redirect to file:
kingfisher config init \
  --confidence high \
  --redact \
  --exclude vendor/ \
  --skip-word EXAMPLE \
  --format sarif \
  --output ./kingfisher.sarif \
  --alert-min-confidence high \
  --alert-webhook https://hooks.slack.com/services/T0/B0/AAA \
  --tls-mode lax \
  --github-api-url https://ghe.corp.example.com/api/v3/ \
  --gitlab-api-url https://gitlab.corp.example.com/ \
  > kingfisher.yaml

# Or write the file directly (pass --force to overwrite):
kingfisher config init [...flags...] --out kingfisher.yaml
```

Only flags you actually supply appear in the output; clap defaults are
omitted to keep the file minimal. Scan-target inputs (paths, `--git-url`,
GitHub/GitLab/etc. user/org/group flags, S3/GCS buckets) are stripped —
they describe *what* this run scans and don't belong in shared project
policy.

> **Important:** `config init` does **not** accept the provider-subcommand
> form. `kingfisher scan gitlab --group my-group --api-url https://...`
> cannot be pasted verbatim — `config init` has no `gitlab` subcommand,
> and `--group` / the subcommand-scoped `--api-url` are not accepted at
> the top level. Use the top-level aliases instead: `--gitlab-api-url`
> for the GitLab API root and `--github-api-url` for GHE. Target
> selectors like `--group` / `--organization` are intentionally CLI-only
> and have no config-file equivalent.

### Step 2 — run the scan, passing the config explicitly

```bash
kingfisher scan . --config ./kingfisher.yaml
```

`--config FILE` is required: there is no auto-discovery. CLI flags can
still override any individual value for a single run:

```bash
kingfisher scan . --config ./kingfisher.yaml --confidence low
# scan.confidence: high in YAML → CLI flag wins, runs at low confidence
```

## Webhook URL policy

`alerts.webhooks[].url` (and `--alert-webhook URL`) **must use `https://`**.
Webhook URLs typically embed a secret token in the path and the alert
payload contains finding metadata, so cleartext transport is never the right
default. `http://` is allowed only when the host is a loopback address
(`localhost`, `127.0.0.0/8`, `::1`) — useful for local development against an
on-host receiver. Loopback decisions are made on the literal hostname / IP
in the URL; we do not consult DNS, so a resolver cannot trick the validator
into permitting `http://` for a remote host.

## Caveats

- **`scan.jobs` and the Tokio runtime.** The Tokio runtime is sized from the
  CLI value of `--jobs` *before* `kingfisher.yaml` is loaded, so config-only
  `scan.jobs` will resize the scanner's job pool but not the underlying async
  worker pool. If you want both to match, pass `--jobs N` on the CLI (or set
  the same value in both places). This only affects parallelism, never
  correctness.
- **Subcommand scope.** Project config only applies to `kingfisher scan`.
  `validate`, `revoke`, `access-map`, `view`, and `rules` commands ignore
  `kingfisher.yaml`; pass their flags on the CLI directly.

## What is *not* config-overridable

Scan-target inputs are intentionally CLI-only — they describe *what* this
invocation is scanning, not project policy:

- positional paths, `--git-url`
- `--github-user` / `--github-org`, `--gitlab-user` / `--gitlab-group` and
  the equivalent Gitea / Bitbucket / Azure / Hugging Face flags
- `--s3-bucket`, `--gcs-bucket`, `--docker-image`, Docker `--archive`
- `--jira-url`, `--confluence-url`, `--slack-query`, `--teams-query`,
  `--postman-*`

Auth tokens are also intentionally not in YAML; they continue to come from
env vars (`KINGFISHER_GITHUB_TOKEN`, etc.) so secrets stay out of
checked-in config files.

## Schema

```yaml
scan:
  confidence: medium            # low | medium | high           (--confidence)
  min_entropy: 3.5              # float                          (--min-entropy)
  no_validate: false            # bool                           (--no-validate)
  only_valid: false             # bool                           (--only-valid)
  redact: false                 # bool                           (--redact)
  no_dedup: false               # bool                           (--no-dedup)
  turbo: false                  # bool                           (--turbo)
  no_base64: false              # bool                           (--no-base64)
  access_map: false             # bool                           (--access-map)
  rule_stats: false             # bool                           (--rule-stats)
  jobs: 8                       # int                            (--jobs)
  git_repo_timeout: 1800        # seconds                        (--git-repo-timeout)

rules:
  enabled: ["all"]              # list, additive                 (--rule)
  paths:                        # list, additive                 (--rules-path)
    - ./custom-rules/
  load_builtins: true           # bool                           (--load-builtins)
  cache: true                   # bool, default true             (--no-rule-cache disables)
  cache_dir: ./.kingfisher-cache # optional path                 (--rule-cache-dir, KF_RULE_CACHE_DIR)

validation:
  timeout: 10                   # seconds, 1..=60                (--validation-timeout)
  retries: 1                    # int, 0..=5                     (--validation-retries)
  rps: 5.0                      # float                          (--validation-rps)
  rps_per_rule:                 # map, additive                  (--validation-rps-rule)
    kingfisher.aws: 1.0
  full_response: false          # bool                           (--full-validation-response)
  max_response_length: 2048     # bytes                          (--max-validation-response-length)

filters:
  skip_words:                   # list, additive                 (--skip-word)
    - EXAMPLE
    - PLACEHOLDER
  skip_regex:                   # list, additive                 (--skip-regex)
    - '^DUMMY_[A-Z]+$'
  exclude:                      # list, additive                 (--exclude)
    - vendor/
    - "**/node_modules/**"
  max_file_size_mb: 256.0       # float                          (--max-file-size)
  no_binary: false              # bool                           (--no-binary)
  no_extract_archives: false    # bool                           (--no-extract-archives)
  extraction_depth: 2           # int, 1..=25                    (--extraction-depth)
  no_inline_ignore: false       # bool                           (--no-ignore)
  no_ignore_if_contains: false  # bool                           (--no-ignore-if-contains)
  extra_ignore_comments: []     # list, additive                 (--ignore-comment)
  skip_aws_accounts: []         # list, additive                 (--skip-aws-account)
  skip_aws_account_file: null   # path                           (--skip-aws-account-file)

output:
  format: pretty                # pretty|json|jsonl|bson|toon|sarif|html  (--format)
  path: ./kingfisher-report.json  # path                         (--output)

baseline:
  file: ./baseline.json         # path                           (--baseline-file)
  manage: false                 # bool                           (--manage-baseline)

alerts:
  defaults:                     # global defaults; per-webhook overrides still win
    format: null                # null = auto-infer              (--alert-format)
    on: findings                # findings | always              (--alert-on)
    min_confidence: medium      # low | medium | high            (--alert-min-confidence)
    include_secret: false       # bool                           (--alert-include-secret)
    report_url: null            # URL                            (--alert-report-url)
    detail: auto                # summary | detail | auto        (--alert-detail)
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA   # required
      format: slack                                      # slack | teams | generic | discord | mattermost | googlechat
      on: findings                                       # findings | always
      min_confidence: medium                             # low | medium | high
      include_secret: false                              # default false
      report_url: https://ci.example/run/42              # optional pivot link rendered in payload
      detail: auto                                       # summary | detail | auto (default auto)

global:
  tls_mode: strict              # strict | lax | off             (--tls-mode)
  allow_internal_ips: false     # bool                           (--allow-internal-ips)
  no_update_check: false        # bool                           (--no-update-check)
  user_agent_suffix: null       # string                         (--user-agent-suffix)
  endpoints:                    # list, additive                 (--endpoint)
    - github=https://ghe.example.com/api/v3
  endpoint_config: null         # path                           (--endpoint-config)

git:
  clone_dir: null               # path                           (--git-clone-dir)
  keep_clones: false            # bool                           (--keep-clones)
  repo_clone_limit: null        # int                            (--repo-clone-limit)
  include_contributors: false   # bool                           (--include-contributors)
  github_api_url: null          # URL  GHE / self-hosted GH       (--github-api-url)
  gitlab_api_url: null          # URL  self-hosted GitLab         (--gitlab-api-url)
```

Unknown fields are rejected (typo protection). Empty sections and a missing
top-level file are both fine.

Rule cache pruning is intentionally CLI-only. Use `kingfisher rules prune-cache` for manual cleanup, or pass `--prune-rule-cache` with optional `--rule-cache-max-entries` and `--rule-cache-max-age` thresholds on scans.

## Example: CI workflow

A typical `kingfisher.yaml` for a CI repo, paired with a workflow step
that runs `kingfisher scan` against it:

```bash
# .github/workflows/secrets.yml — run step
kingfisher scan . \
  --config ./kingfisher.yaml \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK"
# `--alert-webhook` here is appended to any webhooks already in
# kingfisher.yaml (lists are additive). Everything else comes from the
# config file.
```

The committed `kingfisher.yaml`:

```yaml
scan:
  confidence: high
  redact: true
output:
  format: sarif
  path: ./kingfisher.sarif
filters:
  exclude:
    - vendor/
    - "**/node_modules/**"
    - "**/__snapshots__/**"
  skip_aws_accounts:
    - "111122223333"   # a test account whose creds we tolerate in test fixtures
alerts:
  defaults:
    min_confidence: high
  webhooks:
    - url: https://hooks.slack.com/services/T0/B0/AAA
      format: slack
```

Combined with [`docs/ALERTS.md`](ALERTS.md), this lets one repo own its
webhook configuration and CI policy without baking it into command-line strings.
