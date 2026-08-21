# Build a Baseline / Detect Only New Secrets

[← Back to README](../README.md)

A baseline records findings that are already known so later scans report only findings that are
new for the repository in which they occur.

Kingfisher baseline format version 2 is repository-aware. One baseline file can safely cover a
Bitbucket project, GitHub organization, GitLab group, directory containing multiple repositories,
or any other multi-repository scan. Each finding belongs to a canonical repository ID, so a finding
accepted in one repository does not suppress the same fingerprint in another repository.

## Create a baseline

Run the same scan you intend to use later and add `--manage-baseline`. Using low confidence is
common when the baseline should capture every existing candidate:

```bash
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml
```

For a Bitbucket Server or Data Center project, the same single file contains a separate section for
every repository:

```bash
KF_BITBUCKET_USERNAME="scanner" KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket \
  --project SEC \
  --api-url https://bitbucket.example.com/rest/api/1.0/ \
  --confidence low \
  --manage-baseline \
  --baseline-file ./sec-project-baseline.yml
```

For Bitbucket Cloud, select a workspace instead:

```bash
KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket --workspace my-team \
  --manage-baseline \
  --baseline-file ./my-team-baseline.yml
```

`--manage-baseline` automatically enables `--no-dedup`, ensuring the update observes every
repository occurrence.

## Use a baseline

Pass the same file on future scans. Kingfisher selects the appropriate repository section
automatically; no repository-to-file mapping is required on the command line.

```bash
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yml
```

For the Bitbucket project example:

```bash
KF_BITBUCKET_USERNAME="scanner" KF_BITBUCKET_TOKEN="$BITBUCKET_TOKEN" \
  kingfisher scan bitbucket \
  --project SEC \
  --api-url https://bitbucket.example.com/rest/api/1.0/ \
  --baseline-file ./sec-project-baseline.yml
```

## Version 2 file format

A managed scan creates a version 2 YAML file:

```yaml
version: 2
fingerprint_algorithm: kingfisher-v1
repositories:
- id: git://bitbucket.example.com/scm/SEC/payments
  findings:
  - path: src/config.rs
    fingerprint: '389162583612032034'
    rule_id: betterleaks.github-pat
    line: 52
    first_seen_at: 2026-08-11T17:17:42.123456Z
    last_updated_at: 2026-08-11T17:17:42.123456Z
- id: git://bitbucket.example.com/scm/SEC/orders
  findings:
  - path: deploy/production.env
    fingerprint: '14862156687550263216'
    rule_id: betterleaks.aws-access-token
    line: 19
    first_seen_at: 2026-08-11T17:17:42.123456Z
    last_updated_at: 2026-08-11T17:17:42.123456Z
```

Repository IDs are derived from the remote Git URL. Kingfisher removes credentials, query strings,
fragments, the transport (`http`, `https`, or SSH), and a trailing `.git`; it lowercases the host.
For example, both `https://Example.COM/team/repo.git` and `git@example.com:team/repo.git` become
`git://example.com/team/repo`.

For a local Git checkout, Kingfisher uses its `remote.origin.url` when available. A non-Git local
input falls back to a `local://` ID derived from the normalized absolute input path. Consequently,
a baseline for a plain non-Git directory is tied to that path, while a Git checkout remains stable
when it is cloned into a different directory.

The fields under each finding have the following meaning:

- `fingerprint` is the decimal `u64` emitted by Kingfisher reports.
- `rule_id`, `path`, and `line` make the entry reviewable. Version 2 matching is keyed by the
  repository ID and fingerprint; these fields are metadata.
- `first_seen_at` records when the scoped entry was created.
- `last_updated_at` changes only when the entry's metadata changes. Re-running an unchanged managed
  scan therefore does not rewrite timestamps or churn the file.
- `fingerprint_algorithm` versions the fingerprint contract independently of the YAML schema.

`kingfisher-v1` fingerprints include the matched secret value, the origin kind, and byte offsets.
Moving a finding within a file can therefore produce a new fingerprint. Repository identity is
applied as a separate baseline scope and is not embedded into this legacy-compatible fingerprint.

## Update and pruning behavior

To accept current new findings or remove findings that no longer exist, rerun the complete intended
scan scope with both options:

```bash
kingfisher scan /path/to/code \
  --manage-baseline \
  --baseline-file /path/to/baseline-file.yml
```

During a multi-repository scan, workers only read the already-loaded baseline. After every
repository has finished successfully, Kingfisher performs one deterministic update and atomically
replaces the baseline file. This prevents parallel repositories from overwriting or pruning one
another's entries.

Version 2 pruning is repository-scoped:

- Repositories successfully included in the managed scan are replaced with exactly the findings
  encountered in that scan. Exclusions and narrower scan options can therefore remove entries in
  those repositories.
- Existing sections for repositories not included in the scan are preserved unchanged. Updating
  one repository does not prune another repository's section.
- If a repository worker or artifact producer fails, Kingfisher returns the scan error before
  updating the baseline, leaving the existing file unchanged.

Use the same confidence level, rule selection, history mode, exclusions, and other scan options for
baseline creation and later management. Changing the scan scope intentionally changes which
findings are retained.

## Backward compatibility with legacy baselines

Kingfisher continues to read the original unversioned format:

```yaml
ExactFindings:
  matches:
  - filepath: repository/src/config.rs
    fingerprint: '389162583612032034'
    linenum: 52
    lastupdated: Mon, 14 Jul 2025 10:17:56 -0700
```

Legacy compatibility behaves as follows:

- An unversioned `ExactFindings` file is treated as version 1.
- Version 1 fingerprints remain global because the old format contains no repository identity.
  A matching legacy fingerprint can therefore suppress a finding in any scanned repository.
- Read-only use with `--baseline-file` does not rewrite or migrate the file.
- A successful run with `--manage-baseline` rewrites the file as version 2 and associates every
  current finding with its repository. Because management retains only findings in the managed scan
  scope, perform migration using the same complete multi-repository scan that originally owned the
  legacy file.
- Decimal fingerprints copied from scan output remain accepted.
- Legacy 16-character zero-padded hexadecimal fingerprints such as `056876f00ffd0622`, and explicit
  `0x`-prefixed hexadecimal fingerprints, remain accepted.
- An unknown future `version` or `fingerprint_algorithm` fails with an error instead of silently
  applying incompatible matching behavior.

No manual conversion is required. Keeping an existing version 1 file is supported; migrate when
repository isolation is desired.

## Troubleshooting

Enable verbose logging to see when findings are suppressed by the baseline:

```bash
kingfisher scan /path/to/project \
  --baseline-file ./baseline-file.yml \
  -v
```

If a finding unexpectedly reappears, compare the repository ID and fingerprint in the version 2
file with the scan output. Common causes are a changed remote URL, scanning a plain local directory
from a different absolute path, moving the finding so its byte offsets change, or changing scan
options between baseline creation and use.
