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

Kingfisher supports direct revocation for selected built-in imported detectors and through a
rule-level `revocation:` block in the Kingfisher rule format. The current open-source
catalog includes 34 revocation-enabled rules across 15 provider families.

Kingfisher keeps reviewed operational revocation actions in
`crates/kingfisher-rules/data/imported-rules-capabilities.yml`. This file contains no candidate
detector regexes; it may add narrow operational filters and capability metadata. Every entry
is joined to the pinned imported-detector catalog by upstream ID during bundle generation.
Betterleaks 2.x supports `revoke` expressions, but Kingfisher's importer currently uses
these overlay actions instead of executing those expressions.

Current built-in provider families include:

- AWS access keys and GCP service-account keys
- GitHub PAT, fine-grained PAT, OAuth, and refresh credentials
- GitLab PAT formats
- Buildkite, Cloudflare, crates.io, DigitalOcean, Doppler, Heroku, and npm credentials
- Hugging Face credentials and selected Slack, Twitch, and Vercel token formats

The capability file is the authoritative exact-ID list. Kingfisher intentionally omits actions
when an upstream detector combines credential types with different revocation APIs, when required
context cannot be bound safely, or when a provider lookup cannot identify the exact credential.
That conservative boundary is important: a remediation shortcut should never guess which key to
disable.

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
CLI timeout applies to each AWS request, while `--retries` applies only to configurable HTTP
revocation. STS identity lookups have bounded read retries. IAM mutations retry only definitive
throttling responses, with at most three attempts; ambiguous failures are not retried.

AWS permission failures are not repaired by retrying the same request. If the response is lost
after IAM may have accepted a mutation, Kingfisher reports an unknown outcome rather than claiming
failure or attempting a more destructive fallback. Verify the key state with separately authorized
credentials before retrying. JSON and TOON output expose this as `revocation_status: unknown`.

Deactivating or deleting a long-term key does not invalidate STS sessions already created from it;
those sessions can remain usable until they expire or are revoked separately.

Kingfisher custom rules may define these revocation types:

- `Http` for a single provider API request
- `HttpMultiStep` for lookup-then-delete workflows
- `AWS` for IAM access-key revocation
- `GCP` for service-account key revocation

Invoke a Kingfisher custom revocation rule with:

```bash
kingfisher revoke \
  --rules-path ./custom-rules.yml \
  --rule custom.provider.token \
  "secret"
```

See [USAGE.md](USAGE.md#direct-secret-revocation-with-kingfisher-revoke) for the command and
[RULES.md](RULES.md) for the Kingfisher custom-rule schema.
