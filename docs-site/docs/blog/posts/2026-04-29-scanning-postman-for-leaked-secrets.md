---
date: 2026-04-29
title: "Scanning Postman for Leaked Secrets — Including the Ones the UI Hides"
description: >
  Postman workspaces are a quietly underrated leak surface. Kingfisher now
  scans collections, environments, mocks, and monitors directly via the
  Postman API — and reads the plaintext of "secret"-typed environment
  variables that the Postman UI masks but the API does not.
categories:
  - Features
tags:
  - postman
  - secret-scanning
  - validation
  - integrations
---

# Scanning Postman for Leaked Secrets — Including the Ones the UI Hides

Postman is everywhere — across backend teams, mobile teams, partner
integrations, and the public Postman API Network. It is also a quietly
prolific leak surface. CloudSEK's December 2024 audit found over **30,000
public Postman workspaces leaking access tokens** across GitHub, Slack,
Salesforce, Stripe, and Razorpay, among others. Postman themselves now run
server-side secret scans on public content, which tells you everything you
need to know about how often this happens.

Kingfisher now scans Postman workspaces directly — and finds credentials
that other scanners miss, because most other tools only scan collection
exports a developer has dropped into a repo. They never see the live
workspace.

<!-- more -->

## The leak surface inside a Postman workspace

A Postman workspace is more than a list of saved requests. Each of the
following can — and routinely does — contain hard-coded credentials:

- **Request `auth` blocks**: Bearer tokens, API keys, basic-auth passwords
  pinned directly to a request.
- **Request headers and URLs**: `Authorization`, `X-Api-Key`, signed query
  strings, pre-signed S3 URLs.
- **Request bodies**: form-encoded `client_secret`, JSON payloads with
  service account JSON pasted in.
- **Pre-request and test scripts**: JavaScript snippets that hard-code an
  AWS keypair "just for testing."
- **Saved example responses**: an example response with a real token that
  was captured when the engineer was debugging.
- **Environment variables, including the "secret" type** — see below.
- **Globals**, **mocks**, and **monitors** — same shape as environments.

## The headline: Postman's "secret" type does not redact over the API

Postman environments support a `secret` variable type. In the UI, the value
is masked — you see `••••••••`. It feels like a vault.

It is not. The `secret` flag is a **UI-masking hint only**. When you call
`GET /environments/{uid}` with an API key that has read access, Postman
returns the value in plaintext:

```json
{
  "environment": {
    "name": "prod",
    "values": [
      {
        "key": "STRIPE_SECRET",
        "value": "sk_live_51H...",
        "type": "secret",
        "enabled": true
      }
    ]
  }
}
```

That means a Postman API key with workspace read access is, in practice,
a key to every "secret" variable across every environment that workspace
can see. Postman documents this — only **Postman Vault** secrets are
genuinely client-side and unreachable via the API. Anything stored as a
"secret" environment variable is fully exposed.

This is the surface Kingfisher now scans.

## Get an API key

1. Go to **postman.com → Settings → API keys → Generate API key**.
2. Copy the value (it starts with `PMAK-`).
3. Export it:

```bash
export KF_POSTMAN_TOKEN="PMAK-..."
```

`POSTMAN_API_KEY` also works as an alias if that's already in your shell —
Kingfisher checks both.

The key acts with the minting user's permissions — there are no per-scope
toggles. Rate limit is 300 req/min/user across all plans. Kingfisher honors
`X-RateLimit-RetryAfter` and backs off automatically on 429.

## Scan everything visible to the key

The fastest way to get a baseline of your team's exposure:

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all
```

That walks every workspace the key can see, fans out to each collection
and environment, writes the JSON to disk, and runs the full Kingfisher
ruleset against it. Live validation runs by default, so you get back a
list of credentials that **actually authenticate today**, not just regex
matches.

Mocks and monitors are off by default (lower-yield, more API calls). Add
them explicitly when you want a complete sweep:

```bash
kingfisher scan postman --all --include-mocks-monitors
```

## Scan a specific workspace

When you want to scope to one team's workspace — or to audit a public
workspace someone flagged in a bug bounty report — pass the workspace ID
or paste the URL straight from the browser:

```bash
# By workspace UID
kingfisher scan postman \
  --workspace 11111111-2222-3333-4444-555555555555

# Or paste the web URL — Kingfisher extracts the UID
kingfisher scan postman \
  --workspace https://www.postman.com/team-handle/workspace/abc-uid-123
```

Repeat the flag to scan multiple workspaces in one run.

## Scan a single collection or environment

For CI, you usually want to scan the specific collection that gets shared
with partners on every release, not the whole workspace:

```bash
# Single collection — useful in CI on a known-shared collection
kingfisher scan postman \
  --collection 12345678-abcd-efgh-ijkl-mnopqrstuvwx

# Single environment — useful when you suspect one env in particular
kingfisher scan postman \
  --environment 12345678-abcd-efgh-ijkl-mnopqrstuvwx
```

Both flags are repeatable.

## What a finding looks like

Findings come back tagged with the Postman web URL of the resource they
were found in. That makes triage one click — paste the URL into a browser
and you're looking at the exact collection or environment that needs
remediation:

```
GITHUB PERSONAL ACCESS TOKEN => [KINGFISHER.GITHUB.2]
 |Finding.......: ghp_EZopZDMW...
 |Confidence....: medium
 |Validation....: Active
 |Path..........: https://go.postman.co/environments/env-uid-1
```

In JSON output, the URL appears in the finding's source/origin block, so
it round-trips into your triage tooling alongside the validation verdict.

## The end-to-end response loop

Combine Postman scanning with the rest of Kingfisher's response chain and
you have a complete incident workflow:

```bash
# 1. Scan + validate + map blast radius across every workspace
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all \
  --access-map \
  --format json \
  --output postman-findings.json

# 2. Pull just the live, high-blast-radius findings
jq '.findings
    | map(select(.validation.status == "Active"))
    | map(select(.access_map != null))' \
   postman-findings.json > urgent.json

# 3. Revoke the most urgent ones in place — by rule
kingfisher revoke --rule github "$LEAKED_GITHUB_TOKEN"
kingfisher revoke --rule slack "$LEAKED_SLACK_TOKEN"
```

Find → prioritize → revoke, all without leaving the terminal.

## Self-hosted and enterprise

If your team runs Postman behind a corporate proxy or uses an enterprise
endpoint, override the API URL:

```bash
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all \
  --api-url https://postman.internal.example.com/
```

## Out of scope (so you can plan around it)

- **Postman Vault secrets.** Vault values stay client-side and are not
  reachable from the Postman API. If you've migrated everything sensitive
  into Vault, those values are not in this scan's blast radius — by
  design. Anything still in `type: secret` environment variables, however,
  is fully exposed.
- **Postman API Network discovery.** Postman does not expose a public
  search API for the API Network. If you want to scan a public workspace,
  you have to hand Kingfisher its workspace ID. There is no `--query`
  option that crawls all of Postman.
- **Postman request history.** Per-user, never API-accessible.

## Why this matters

Most secret scanners only see Postman content if a developer has manually
exported a collection JSON and committed it. That's the smallest fraction
of the actual exposure. The majority of leaked Postman credentials live in
the workspace itself: in a "secret" environment variable that someone set
six months ago, in a saved example response from a debugging session, in
a pre-request script that hard-codes an AWS keypair "just for now."

By scanning the API directly, Kingfisher sees the same surface a
compromised Postman API key would see — which is exactly the surface that
matters from a defender's perspective.

## Get started

```bash
# Install — see the README for other platforms
brew install kingfisher

# Scan
KF_POSTMAN_TOKEN="PMAK-..." kingfisher scan postman --all
```

If there's a Postman feature you want covered or you find a workflow that
doesn't fit, open an issue at
[mongodb/kingfisher](https://github.com/mongodb/kingfisher/issues).
