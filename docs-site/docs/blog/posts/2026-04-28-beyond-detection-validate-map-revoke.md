---
date: 2026-04-28
title: "Beyond Detection: Live Validation, Blast Radius, and One-Command Revocation"
description: >
  Detection alone is noise. Kingfisher answers the three questions that
  actually matter when a secret leaks — is it live, what does it reach,
  and can we revoke it now — across AWS, GCP, GitHub, GitLab, Slack,
  and dozens of other providers.
categories:
  - Features
tags:
  - validation
  - blast-radius
  - revocation
  - secret-scanning
---

# Beyond Detection: Live Validation, Blast Radius, and One-Command Revocation

A regex hit is the easy part. Any scanner can tell you that a string looks
like an AWS access key or a GitHub token. The harder question is what to do
next, and that is usually what turns a scan result into either a routine
cleanup task or a real incident.

Kingfisher answers the three questions that actually matter:

1. **Is this credential alive right now?**
2. **What can it reach?**
3. **Can we revoke it from here?**

<!-- more -->

## 1. Live validation, not just pattern matching

Kingfisher can drastically reduce false positives by identifying
secrets that are still active and valid.

When a provider exposes a safe check call, Kingfisher uses that
provider's own API to report each credential as `Active`, `Inactive`, or
`NotAttempted`.

That changes the output from "thousands of regex matches" to a much shorter
list of findings that actually authenticate today.

Validation runs automatically when you run a scan:

```bash
kingfisher scan github --organization my-org --view-report

kingfisher scan https://github.com/leaktk/fake-leaks.git --view-report
```

Or you can run it standalone when you've already pulled a suspicious value
out of a paste, a log, or a customer ticket:

```bash
# Hit GitHub's user API to confirm the token works
kingfisher validate --rule github "$GITHUB_TOKEN"

# AWS needs both halves of the keypair
kingfisher validate --rule aws \
  --arg "$AWS_ACCESS_KEY_ID" \
  "$AWS_SECRET_ACCESS_KEY"

# A GCP service account JSON, straight from the file
kingfisher validate --rule gcp "$(cat service-account.json)"

# A Postgres connection URI — does it actually authenticate?
kingfisher validate --rule postgres "$POSTGRES_URI"
```

Most validation logic lives in the rule YAML rather than bespoke compiled
code. That makes it practical to grow coverage rule-by-rule instead of
treating validation as a separate engineering project.

## 2. Blast radius mapping — what does this token actually reach?

A leaked AWS key bound to a single read-only S3 bucket and a leaked AWS key
bound to organization-wide `AdministratorAccess` are not the same incident.
The first is a ticket. The second is a war room.

Add `--access-map` to a scan and Kingfisher authenticates each live
credential, enumerates what it can do, and writes the result alongside
the finding:

```bash
kingfisher scan github --organization my-org \
  --access-map \
  --format json \
  --output findings.json
```

Each supported finding gets an `access_map` block with the identity,
permissions, and concrete resources reachable. Today that includes
**AWS, GCP, Azure Storage, Azure DevOps, GitHub, GitLab, Slack, and
Microsoft Teams**.

You can also run it standalone — useful when triaging a single credential
you've fished out of a paste or a customer report:

```bash
# What does this AWS keypair actually own?
kingfisher access-map aws ./aws.json --format json > aws.access-map.json

# Same for a GitHub token
kingfisher access-map github ./github.token --format json > github.access-map.json

# Or a GCP service account
kingfisher access-map gcp ./service-account.json --format json > gcp.access-map.json
```

The access-map HTML report renders the access map as a
clickable tree: identity at the root, then services, then individual
resources and permissions. It is a much faster way to explain severity to
an incident commander or manager than pasting IAM JSON into chat.

## 3. Revocation — revoke the token from where you found it

Validation tells you a credential is live. Blast radius tells you why it's
urgent. Revocation closes the loop.

For every rule whose provider exposes a safe revocation API, Kingfisher
ships the revocation call as part of the rule definition:

```bash
# Revoke a GitHub PAT
kingfisher revoke --rule github "$GITHUB_TOKEN"

# Revoke a GitLab token
kingfisher revoke --rule gitlab "$GITLAB_TOKEN"

# Revoke a Slack bot token
kingfisher revoke --rule slack "$SLACK_TOKEN"

# Deactivate an AWS access key
kingfisher revoke --rule aws \
  --arg "$AWS_ACCESS_KEY_ID" \
  "$AWS_SECRET_ACCESS_KEY"

# Disable a GCP service account key
kingfisher revoke --rule gcp "$(cat service-account.json)"
```

The same Liquid templating that powers validation also powers revocation,
including multi-step flows for providers that require a lookup before
disabling the credential. See
[`docs/RULES.md`](https://github.com/mongodb/kingfisher/blob/main/docs/RULES.md#multi-step-revocation)
for the schema.

This matters in two scenarios:

- **Mass revocation after a leak.** A laptop or a CI runner gets popped and
  you have a list of live credentials. `kingfisher revoke` walks that list
  without forcing a human to pivot between provider consoles.
- **Automated response.** Wire `kingfisher revoke` into the same job that
  scanned and validated, gated by an allow-list of rule IDs you've decided
  are safe to auto-revoke (typically: short-lived CI tokens, dev-environment
  secrets). The credential is dead before the on-call gets paged.

## The combined workflow

In practice, these three capabilities collapse into one response workflow:

```bash
# 1. Scan + validate + map blast radius in one call
kingfisher scan github --organization my-org \
  --access-map \
  --format json \
  --output findings.json

# 2. Pull just the live, high-blast-radius findings
jq '.findings
    | map(select(.validation.status == "Active"))
    | map(select(.access_map != null))' \
   findings.json > urgent.json

# 3. Triage in the HTML viewer (or revoke programmatically)
kingfisher view findings.json
```

That is the full incident loop in three steps: find, prioritize, revoke.

## Why this is the right shape

Most scanners stop at step one because going further is expensive: every
provider has its own auth flow, its own permission model, its own
revocation API. Kingfisher gets to a high-coverage version of all three by
keeping the logic in YAML rule files (the same place the detection regex
lives), reusing typed validators for the common families (AWS, GCP, JWT,
Postgres, MongoDB, MySQL, JDBC, Azure Storage, Coinbase), and letting rule
authors drop down to a `Raw` validator only for genuinely odd providers.

The practical result is that new rules can ship with detection plus
post-detection response logic, instead of detection today and validation or
revocation on some later roadmap.

If there is a provider you want validation or revocation support for, open
an issue at [mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
