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
rule-level `revocation:` block in the Kingfisher 1.x custom-rule format. The current open-source
catalog includes 34 revocation-enabled rules across 15 provider families.

Betterleaks does not currently define revocation metadata. Kingfisher therefore keeps operational
revocation actions in `crates/kingfisher-rules/data/imported-rules-capabilities.yml`. This file is not a
detection catalog: it contains no regexes or filters, and every entry is joined to the downloaded
imported-detector catalog by upstream ID at build time.

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

Kingfisher 1.x custom rules may define these revocation types:

- `Http` for a single provider API request
- `HttpMultiStep` for lookup-then-delete workflows
- `AWS` for IAM access-key revocation
- `GCP` for service-account key revocation

Invoke a Kingfisher 1.x custom revocation rule with:

```bash
kingfisher revoke \
  --rules-path ./custom-rules.yml \
  --rule custom.provider.token \
  "secret"
```

See [USAGE.md](USAGE.md#direct-secret-revocation-with-kingfisher-revoke) for the command and
[RULES.md](RULES.md) for the Kingfisher 1.x custom-rule schema.
