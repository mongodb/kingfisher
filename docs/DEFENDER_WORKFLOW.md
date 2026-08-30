# Secret-response workflow

This is a practical workflow for a fictional private repository,
`https://github.com/example-org/checkout-service.git`. Replace that URL with the repository you
are authorized to scan.

The workflow is straightforward: scan the repository and its history, validate detected
credentials, alert on credentials that are active, map access when impact is unclear, then revoke
or rotate the credential and scan again.

```mermaid
flowchart LR
    Repo["GitHub repository<br/>example-org/checkout-service"] --> Scan["kingfisher scan"]
    Scan --> Detect["Detect candidates"]
    Detect --> Validate["Validate supported credentials"]
    Validate --> Report["Write scan report"]
    Validate -->|Active| Alert["Alert security channel"]
    Alert --> Impact{"Need access context?"}
    Impact -->|Yes| Map["Map blast radius"]
    Impact -->|No| Contain["Revoke or rotate"]
    Map --> Contain
    Contain --> Rescan["Remove from source and rescan"]
```

## 1. Set up a restricted alert channel

Create incoming webhooks for a private Slack or Discord channel and store the URLs in the CI
secret store. A webhook URL is a credential too; do not commit it or print it in job logs.

Expose the values only to the scan job:

```bash
export SLACK_SECURITY_WEBHOOK='https://hooks.slack.com/services/...'
export DISCORD_SECURITY_WEBHOOK='https://discord.com/api/webhooks/...'
export KINGFISHER_ALERT_REPORT_URL='https://ci.example.test/runs/1234/artifacts/report'
```

`KINGFISHER_ALERT_REPORT_URL` is optional. When set, it gives responders a link from the alert to
a protected CI artifact or report viewer.

## 2. Test the scan without sending alerts

Use `--alert-dry-run` to inspect the alert payload before posting it:

```bash
kingfisher scan https://github.com/example-org/checkout-service.git \
  --redact \
  --format json \
  --output ./kingfisher-report.json \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-webhook "$DISCORD_SECURITY_WEBHOOK" \
  --alert-on findings \
  --alert-finding-filter only-active \
  --alert-prevent-empty \
  --alert-detail auto \
  --alert-dry-run
```

Once the payload and report look right, remove `--alert-dry-run`. The `only-active` filter limits
notifications to findings whose provider validation succeeded. Inactive, unavailable, skipped,
and inconclusive findings remain in the report but do not page the channel.

`--alert-prevent-empty` suppresses the alert when no finding passes the filter. If the report itself
should contain only active findings, add `--validation-filter active` (or the compatibility flag
`--only-valid`). Keeping the full report and filtering only the notification is usually more useful
for investigation.

## 3. Find the validation command in the report

For a finding with validation configured, Kingfisher includes a ready-to-run `Validate Cmd....` line
in pretty scan output. JSON and TOON reports expose the same value as `validate_command`; SARIF
stores it as a `validate_command` property.

For a JSON report, use `jq` to print the validation commands without printing the rest of the
finding:

```bash
REPORT=./kingfisher-report.json
jq -r '.findings[] | .finding.validate_command? // empty' "$REPORT"
```

The output contains the detected credential, so review it only in a protected terminal. Do not
paste the output into a shared shell, ticket, or chat.

The command contains the finding, so it is present only in an unredacted report. When `--redact` is
enabled, Kingfisher omits the validate, revoke, and blast-radius commands. Treat an unredacted
report as sensitive and keep it in a protected location.

The following is a synthetic example; the token and response are not real:

```text
🔓 BETTERLEAKS.GITHUB-PAT => [betterleaks.github-pat]
 |Finding.........: ghp_example0000000000000000000000000000
 |Description.....: GitHub Personal Access Token
 |Fingerprint.....: 1234567890123456789
 |Confidence......: medium
 |Entropy.........: 4.20
 |Validation......: Active Credential
 |__Response......: {"active":true,"login":"example-user","scopes":["repo"]}
 |Validate Cmd....: kingfisher validate --rule betterleaks.github-pat 'ghp_example0000000000000000000000000000'
 |Revoke Cmd......: kingfisher revoke --rule betterleaks.github-pat 'ghp_example0000000000000000000000000000'
 |Blast Radius Cmd: kingfisher blast-radius --rule betterleaks.github-pat 'ghp_example0000000000000000000000000000'
 |Language........: Unknown
 |Line Num........: 11047
 |Path............: checkout-service/config/example.env
```

The generated command reflects the rule and any supporting values captured during the scan. Review
it before use; do not paste a secret-bearing command into a shared terminal, ticket, or chat.

## 4. Map impact when needed

Validation answers whether a credential is accepted. `--blast-radius` goes further for supported
providers by collecting identity, permissions, and reachable resources:

For an unredacted JSON report, use `jq` to print the generated blast-radius commands:

```bash
jq -r '.findings[] | .finding.blast_radius_command? // empty' "$REPORT"
```

The output contains the detected credential and any supporting values, so review it only in a
protected terminal. An empty result means that no supported blast-radius command was emitted, or
that the report was redacted.

For a single finding, use the direct `blast-radius` command with the finding's rule ID and secret.
Pass the credential as the positional secret argument:

```bash
kingfisher blast-radius --rule betterleaks.github-pat 'ghp_example0000000000000000000000000000'
```

Composite credentials need their supporting values passed with `--var` or `--arg`, just as with
`validate`. For example, an AWS access-key finding uses the access key ID as the secret and the
secret access key as a required variable:

```bash
kingfisher blast-radius --rule betterleaks.aws-access-token \
  --var AWS_SECRET_ACCESS_KEY='<AWS_SECRET_ACCESS_KEY>' \
  '<AWS_ACCESS_KEY_ID>'
```

This maps one credential rather than every supported finding in a scan. The command is rule-based,
so it can reconstruct the same provider-specific inputs used during scan-time mapping. See
[Blast Radius](BLAST_RADIUS.md) for supported providers and credential requirements. Keep all
secret-bearing arguments and supporting values protected, and use this only when authorized to
inspect the target account.

To map all supported findings while scanning, use `--blast-radius`:

```bash
kingfisher scan https://github.com/example-org/checkout-service.git \
  --blast-radius \
  --redact \
  --format json \
  --output ./kingfisher-blast-radius.json \
  --alert-webhook "$SLACK_SECURITY_WEBHOOK" \
  --alert-webhook "$DISCORD_SECURITY_WEBHOOK" \
  --alert-on findings \
  --alert-finding-filter only-active \
  --alert-prevent-empty \
  --alert-detail auto
```

Blast-radius mapping runs after validation. A mapping failure does not hide an active finding, so
`only-active` is the appropriate default for the alert channel. Use
`--alert-finding-filter access-map-only` only when the alert should include active findings with a
successful blast-radius result.

Inspect the enriched report with:

```bash
kingfisher view ./kingfisher-blast-radius.json
```

Mapping makes it easier to distinguish a low-impact development credential from one that can reach
production resources. It also makes additional authenticated requests, so use it only when you are
authorized to inspect the target account. See [Blast Radius](BLAST_RADIUS.md) for
provider coverage and limitations.

## 5. Contain the credential

For supported credentials, revoke the credential after confirming the affected workload and likely
impact. Passing the value through standard input keeps it out of shell history and the process
argument list:

If an unredacted JSON report contains a generated revocation command, extract it with `jq`:

```bash
jq -r '.findings[] | .finding.revoke_command? // empty' "$REPORT"
```

An empty result means that no revocation command was emitted for the findings in the report. The
rule may not support revocation, or the report may have been redacted. Review any extracted command
before using it; its output contains the detected credential.

```bash
kingfisher revoke --rule betterleaks.github-pat -
# Paste the credential, then send EOF with Ctrl-D.
```

Some providers require additional captured values, and some credentials cannot be revoked through
Kingfisher. In those cases, disable or rotate the credential in the provider. Revocation can
interrupt a workload that still depends on the credential, so coordinate the change when needed.
See [Secret Revocation](REVOCATION_PROVIDERS.md) for supported families.

## 6. Remove the leak and verify the result

Revocation does not remove copies from Git history, forks, logs, caches, or artifacts. Remove the
credential from the current source, clean retained copies where appropriate, rotate dependent
workloads, and review provider audit logs.

To check that the old value is no longer accepted:

```bash
kingfisher validate --rule betterleaks.github-pat -
# Paste the revoked credential, then send EOF with Ctrl-D.
```

Finally, rerun the original scan. The old string may still be reported as detected but inactive if
it remains in history; it should no longer pass the `only-active` alert filter.

## Operational notes

- Run scans, validation, blast-radius mapping, and revocation only against repositories, accounts,
  and provider APIs you are authorized to access.
- Do not use `--no-validate` with an active-only notification policy; without validation, Kingfisher
  cannot identify active findings.
- Alert delivery is best-effort. A webhook failure produces a warning but does not replace CI job
  monitoring.
- Kingfisher exits with `205` when it discovers a validated active finding, `200` for findings with
  no validated active credential, and `0` when there are no findings. Preserve those codes in CI
  policy.
- Use validation rate limits for large scans so provider APIs are not overwhelmed; see
  [Advanced Usage](ADVANCED.md).
- Baseline known findings instead of weakening the active-only notification policy; see
  [Baseline Management](BASELINE.md).
