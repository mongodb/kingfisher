# Secret Revocation

Kingfisher supports direct secret revocation for selected built-in imported detectors and
through a rule-level `revocation:` block in the Kingfisher 1.x custom-rule format.

Betterleaks does not currently define revocation metadata. Kingfisher therefore keeps operational
revocation actions in `crates/kingfisher-rules/data/imported-rules-capabilities.yml`. This file is not a
detection catalog: it contains no regexes or filters, and every entry is joined to the downloaded
imported-detector catalog by upstream ID at build time.

Current built-in coverage includes:

- AWS access keys and GCP service-account keys
- GitHub PAT, fine-grained PAT, OAuth, and refresh credentials
- GitLab PAT formats
- Buildkite user tokens, Cloudflare API tokens, crates.io keys, and DigitalOcean access tokens
- Hugging Face credentials and selected Slack and Vercel token formats

The capability file is the authoritative exact-ID list. Kingfisher intentionally omits actions
when an upstream detector combines credential types with different revocation APIs, when required
context cannot be bound safely, or when a provider lookup cannot identify the exact credential.

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
