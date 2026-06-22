---
date: 2026-04-28
title: "Scanning an Entire GitHub Organization for Leaked Secrets"
description: >
  Step-by-step guide to scanning every repository in a GitHub organization
  for leaked credentials with Kingfisher — including history, issues, wikis,
  and gists — and validating which secrets are still live.
categories:
  - Tutorials
tags:
  - github
  - secret-scanning
  - validation
  - tutorial
---

# Scanning an Entire GitHub Organization for Leaked Secrets

Most organizations have more GitHub surface area than they think: active
services, abandoned repositories, internal tooling, forks, experiments, and
projects inherited through acquisitions. A credential leaked in a five-year-old
archived repo can still be live today.

Kingfisher can enumerate every repository in a GitHub organization, scan the
full git history, and then **validate which credentials are still live** so
you can focus on what needs rotation first.

<!-- more -->

## What you need

- Kingfisher installed (`brew install kingfisher`, or grab a
  release from [GitHub](https://github.com/mongodb/kingfisher/releases)).
- A GitHub personal access token exported as `KF_GITHUB_TOKEN`. A classic
  token with `repo` and `read:org` scopes is enough for private repos; for
  public-only scans, even an unscoped token raises your rate limit and
  is strongly recommended.
- About 5 GB of free disk for clones (varies by org size — use
  `--git-clone-dir /path/to/big/disk` if your home volume is small).

## The one-liner

```bash
export KF_GITHUB_TOKEN=ghp_yourTokenHere
kingfisher scan github --organization my-org
```

That single command enumerates the org, clones each repository, scans working
tree content plus git history, and validates supported findings against
provider APIs.

## Tuning for real-world orgs

Real organizations have huge monorepos, archived junk, mirrored forks, and
repositories you already know are out of scope. Three flags handle most of
the tuning:

```bash
kingfisher scan github --organization my-org \
  --repo-clone-limit 500 \
  --github-exclude 'my-org/*-archive' \
  --github-exclude 'my-org/legacy-monorepo' \
  --git-clone-dir /var/tmp/kf-clones \
  --format sarif \
  --output kf-findings.sarif
```

- **`--repo-clone-limit`** caps the number of clones per scan. It is useful
  for staged rollouts or staying under a disk budget.
- **`--github-exclude`** accepts exact `OWNER/REPO` strings or gitignore-style
  globs (`my-org/*-archive`). Repeat the flag for each pattern. Matching is
  case-insensitive.
- **`--git-clone-dir`** moves clones off your home volume. Combine with
  `--keep-clones` if you want to re-scan later without re-cloning.

## Pulling in issues, wikis, and gists

Secrets don't only live in code. Issues and pull request descriptions are a
common leak source: someone pastes a stack trace with a JWT, or an
"on-call handoff" issue with a temporary token that never gets rotated. Add
`--repo-artifacts` to fetch these:

```bash
kingfisher scan github --organization my-org --repo-artifacts
```

This pulls each repo's issues, pull requests, wiki, and any **public** gists
owned by the repo owner, then scans that material as well. It does consume API
calls, so budget for that if the org is large or your token is already near a
rate limit.

## Following the people, not just the org

Developers also leak secrets in *personal* repositories: side projects,
dotfiles, and throwaway forks. If a contributor to your org has a public repo
containing a still-live credential that reaches company infrastructure, that is
still your incident.

Pass a single repo URL with `--include-contributors` and Kingfisher will
enumerate the contributors, then clone and scan **every public repo they own**:

```bash
kingfisher scan https://github.com/my-org/critical-service \
  --include-contributors \
  --repo-clone-limit 200
```

This is a noisy operation. Start with one or two critical repositories rather
than the entire organization. GitHub will also rate-limit aggressive
enumeration, so `KF_GITHUB_TOKEN` is effectively required.

## Reading the output

The default `pretty` output is fine for interactive terminal use. For
automation, pick a format that matches your downstream consumer:

```bash
# JSON for custom tooling
kingfisher scan github --organization my-org --format json --output findings.json

# SARIF for GitHub code scanning, GitLab, or any SARIF-aware UI
kingfisher scan github --organization my-org --format sarif --output findings.sarif

# TOON for piping to an LLM or agent
kingfisher scan github --organization my-org --format toon
```

The interactive HTML report is often the fastest way to triage a large scan.
You can filter by rule, validation status, or repository, then click through
to the exact commit and line:

```bash
kingfisher scan github --organization my-org --format html --output kf-report.html
```

## Triage by validation status

The single most important field in the output is **validation**. A live
credential should be triaged immediately; a value that never authenticated is
usually just cleanup work. Filter to live findings first:

```bash
jq '.findings[] | select(.validation.status == "Active")' findings.json
```

Then prioritize by blast radius. For AWS, GCP, GitHub, GitLab, and Slack
tokens, Kingfisher can already map what each credential can access. Look at
the `access_map` field in JSON output, or the **Access Map** panel in the
HTML report (`kingfisher view ./report.json` or `kingfisher scan /path/to/code --view-report`)

## Revoke from the CLI

For supported providers, you do not need to pivot into the provider console.
Kingfisher can revoke directly:

```bash
kingfisher revoke --rule kingfisher.aws.access_key.1 AKIAEXAMPLE...
```

Each rule that supports revocation declares the API call in its YAML. See
[`docs/RULES.md`](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md)
for the schema and the current approach.

## Wiring it into a recurring job

The first scan gives you a baseline. The real value comes from running the
same workflow continuously so new leaks are caught within hours instead of
months. A practical starting point is a scheduled GitHub Action in a dedicated
security repository. For the token, prefer a fine-grained PAT scoped to the
target organization with read-only access to repository contents and
organization metadata, or a GitHub App installation token if you're operating
at scale — a classic PAT with `repo` works but grants more than the scan
needs. Store it in `KF_GITHUB_TOKEN`, pin a specific Kingfisher image tag (a
floating `:latest` will silently change findings between runs as rules
update), and upload the JSON report as an artifact:

```yaml
name: nightly-org-secret-scan

on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch:

concurrency:
  group: kingfisher-nightly
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 360
    permissions: {}
    steps:
      - name: Prepare output directory
        run: mkdir -p reports

      - name: Scan the GitHub organization
        env:
          KF_GITHUB_TOKEN: ${{ secrets.KF_GITHUB_TOKEN }}
        run: |
          docker run --rm \
            -e KF_GITHUB_TOKEN \
            -v "$PWD/reports:/reports" \
            ghcr.io/mongodb/kingfisher:v<PINNED_VERSION> \
            scan github --organization my-org \
              --git-history none \
              --format json \
              --output /reports/findings.json

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: kingfisher-findings-${{ github.run_id }}
          path: reports/findings.json
```

A few notes on the choices above. `--git-history none` scans only what's
currently checked out at `HEAD` of each repo; for a midsize org this can be
the difference between a job that finishes in minutes and one that runs for
hours and exhausts the runner's ~14 GB of free disk. If you also need
historical coverage, run a *separate weekly* job with `--git-history full`
rather than paying that cost every night. The same goes for
`--repo-artifacts`, which fetches each repo's issues, wiki, and gists — it's
worth running, just not nightly. `concurrency` keeps a slow run from piling
up on the next cron tick, `timeout-minutes` caps a hung run before it burns
the default six hours, and `if: always()` on the upload step ensures you
still get the report even when the scan exits non-zero (e.g. once you start
gating the workflow on Active findings). The run-ID-suffixed artifact name
makes it easy to diff last night's report against tonight's.

For larger orgs, consider sharding by feeding `gh repo list` into a job
matrix so several runners scan in parallel — the total minutes are similar,
but each runner gets its own disk budget and the wall-clock time drops
sharply. Above a certain size, a self-hosted runner (or a dedicated VM
running the same `docker run` command on cron) becomes cheaper and removes
the disk cap entirely.

From there, add whatever response path fits your process: open an issue, post
to Slack, diff against the previous artifact, or fail the workflow if `jq`
finds any `Active` credentials in `findings.json`.

### A weekly deep scan

The nightly above is intentionally narrow: current `HEAD` content, no
ancillary artifacts. Pair it with a *weekly* job that pays the cost of full
history and `--repo-artifacts` so issues, wiki pages, and rewritten commits
don't slip through unnoticed:

```yaml
name: weekly-org-deep-scan

on:
  schedule:
    - cron: "23 4 * * 6"  # Saturday 04:23 UTC
  workflow_dispatch:

concurrency:
  group: kingfisher-weekly
  cancel-in-progress: false

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 1080  # up to 18h; tune to your org size
    permissions: {}
    steps:
      - name: Prepare output directory
        run: mkdir -p reports

      - name: Deep-scan the GitHub organization
        env:
          KF_GITHUB_TOKEN: ${{ secrets.KF_GITHUB_TOKEN }}
        run: |
          docker run --rm \
            -e KF_GITHUB_TOKEN \
            -v "$PWD/reports:/reports" \
            ghcr.io/mongodb/kingfisher:v<PINNED_VERSION> \
            scan github --organization my-org \
              --git-history full \
              --repo-artifacts \
              --format json \
              --output /reports/findings.json

      - name: Upload deep-scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: kingfisher-deep-${{ github.run_id }}
          path: reports/findings.json
```

The deep scan is where `ubuntu-latest`'s ~14 GB disk limit will bite first.
If your org is large enough that the weekly job fails on disk or runs past
its timeout, that's the signal to shard the repo list across a job matrix
or move this workload to a self-hosted runner. A simple matrix looks like:

```yaml
strategy:
  fail-fast: false
  matrix:
    shard: [0, 1, 2, 3]
# ...then in the scan step, list repos with `gh repo list my-org --limit 1000`
# and filter to those whose name hash mod 4 == matrix.shard, scanning each
# with `kingfisher scan <git-url> --git-history full --repo-artifacts`.
```

Each shard gets its own runner and its own disk budget, and you can upload
one artifact per shard for triage.

If there is a workflow you want us to cover, open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
