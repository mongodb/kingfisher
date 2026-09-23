---
title: "Advanced Configuration"
description: "Advanced Kingfisher features: confidence levels, validation tuning, CI pipeline scanning, filtering, suppression, and profiling."
---

# Advanced Configuration

This guide covers advanced Kingfisher features for power users.

## Table of Contents

- [Advanced Configuration](#advanced-configuration)
  - [Table of Contents](#table-of-contents)
  - [Baseline Management](#baseline-management)
  - [Understanding Confidence Levels](#understanding-confidence-levels)
  - [Filtering and Suppression](#filtering-and-suppression)
    - [Skip Known False Positives](#skip-known-false-positives)
    - [Skip Canary Tokens (AWS)](#skip-canary-tokens-aws)
      - [Common CLI flows](#common-cli-flows)
    - [Inline Ignore Directives](#inline-ignore-directives)
  - [Validation Tuning](#validation-tuning)
  - [Scanning in CI Pipelines](#scanning-in-ci-pipelines)
    - [Compiled Rule Cache](#compiled-rule-cache)
  - [Custom Rules](#custom-rules)
    - [Scan with only custom rules](#scan-with-only-custom-rules)
    - [Add custom rules alongside built-ins](#add-custom-rules-alongside-built-ins)
    - [Check custom rules](#check-custom-rules)
    - [Scan using a rule family](#scan-using-a-rule-family)
  - [Rule Performance Profiling](#rule-performance-profiling)
  - [Disk Offload](#disk-offload)
  - [Notable Scan Options](#notable-scan-options)
    - [Exclude specific paths](#exclude-specific-paths)
    - [Scan while ignoring likely test files](#scan-while-ignoring-likely-test-files)
    - [Limit maximum file size scanned](#limit-maximum-file-size-scanned)
    - [Customize the HTTP User-Agent](#customize-the-http-user-agent)
  - [Finding Fingerprints](#finding-fingerprints)
  - [Update Checks](#update-checks)
  - [Exit Codes](#exit-codes)

## Baseline Management

There are situations where a repository already contains checked‑in secrets, but you want to ensure no **new** secrets are introduced. A baseline file lets you document the known findings so future scans only report anything that is not already in that list.

The easiest way to create a baseline is to run a normal scan with the `--manage-baseline` flag (typically at a low confidence level to capture all potential matches):

```bash
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml
```

`--manage-baseline` automatically enables `--no-dedup` so the baseline captures every individual occurrence.

Use the same YAML file with the `--baseline-file` option on future scans to hide all recorded findings:

```bash
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yaml
```

Running the scan again with `--manage-baseline` refreshes the baseline by adding new findings and pruning entries for secrets that no longer appear. See [BASELINE.md](../usage/baseline.md) for full detail.

## Understanding Confidence Levels

The `--confidence` flag sets a minimum confidence threshold, not an exact match.

- If you pass `--confidence medium`, findings with **medium and higher** confidence (medium + high) will be included.
- If you pass `--confidence low`, you'll see **all levels** (low, medium, high).

```bash
# Only show high-confidence findings
kingfisher scan /path/to/code --confidence high

# Show medium and high confidence findings
kingfisher scan /path/to/code --confidence medium

# Show all findings (low, medium, high)
kingfisher scan /path/to/code --confidence low
```

## Filtering and Suppression

### Skip Known False Positives

Use `--skip-regex` and `--skip-word` to suppress findings you know are benign. Both flags may be provided multiple times and are tested against the secret value **and** the full match context.

With `--skip-regex`, these should be Rust compatible regular expressions, which you can test out at [regex101](https://regex101.com)

```bash
# Skip any finding where the finding mentions TEST_KEY
kingfisher scan --skip-regex '(?i)TEST_KEY' path/

# Skip findings that contain the word "dummy" anywhere in the match
kingfisher scan --skip-word dummy path/

# Combine multiple patterns
kingfisher scan \
  --skip-regex 'AKIA[0-9A-Z]{16}' \
  --skip-word placeholder \
  --skip-word dummy \
  path/
```

If a `--skip-regex` regular expression fails to compile, the scan aborts with an error so that typos are caught early.

### Skip Canary Tokens (AWS)

Canary/honey tokens are intentionally leaked credentials used to catch misuse. Kingfisher can **recognize and skip** known AWS canary accounts so hygiene scans don't set off alerts.

**How to skip**  
Pass the 12-digit AWS account IDs for your canaries via `--skip-aws-account` (comma-separated) or `--skip-aws-account-file` (one ID per line; blank lines and `#` comments allowed). Kingfisher also ships with a **pre-seeded (but not exhaustive)** list of Thinkst Canary account IDs used by canarytokens.org, so many are skipped automatically.

```bash
kingfisher scan /path/to/code \
  --skip-aws-account "171436882533,534261010715"

# or combine preloaded canary IDs with a just-created decoy account
printf '999900001111 \n534261010715' > /tmp/canary_accounts.txt

kingfisher scan /path/to/repo \
  --skip-aws-account-file /tmp/canary_accounts.txt
```

**What you'll see**  
Findings tied to a skip-listed account report `Validation: Canary Token (Skipped)` and note in the `Response:` that the entry came from the skip list:

```bash
AWS ACCESS TOKEN => [BETTERLEAKS.AWS-ACCESS-TOKEN]
 |Finding.........: <REDACTED>
 |Fingerprint.....: 2141074333616819500
 |Confidence......: medium
 |Entropy.........: 5.00
 |Validation......: Canary Token (Skipped)
 |__Response......: (skip list entry) AWS validation not attempted for account 171436882533.
 |Language........: Unknown
 |Line Num........: 21
 |Path............: /tmp/test_canary_accounts.log
```

**Why this matters**  
Skipping prevents noisy tripwires in prod telemetry while keeping the status explicit—"Canary Token (Skipped)" signals that the credential likely belongs to an active honeypot but was intentionally not validated. If needed, verify these credentials out-of-band or with a safe, non-triggering method.

#### Common CLI flows

```bash
# Skip a few in-house canaries during a filesystem scan
kingfisher scan repo/ \
  --skip-aws-account "111122223333,444455556666"

# Read a longer list from disk
kingfisher scan repo/ \
  --skip-aws-account-file /tmp/scripts/canary_accounts.txt

# Combine preloaded canary IDs with a just-created decoy account
printf '999900001111\n534261010715\n' > /tmp/new_canary.txt

kingfisher scan /path/to/repo \
  --skip-aws-account-file /tmp/new_canary.txt
```

Tip: if you manage multiple canary fleets (Thinkst, self-hosted alternatives, or bespoke decoys), checkpoint the account IDs alongside your infrastructure-as-code so security teams can rotate or expand the skip list without editing pipelines.

### Inline Ignore Directives

Add `kingfisher:ignore` anywhere on the same line as a finding to silence it. Multi-line strings and PEM-style blocks may also be ignored by placing the directive on the closing delimiter line (for example, `"""  # kingfisher:ignore`), on the next logical line after the string, **or** on a comment immediately before the value:

```python
# kingfisher:ignore
API_KEY = """
line 1
line 2
"""
# kingfisher:ignore
```

Kingfisher searches the surrounding lines for these tokens without requiring language-specific comment markers. To reuse existing inline directives from other scanners, add them with repeatable `--ignore-comment` flags (for example `--ignore-comment "gitleaks:allow" --ignore-comment "NOSONAR"`). Use `--no-ignore` when you want to disable inline suppressions entirely.

## Validation Tuning

Use these options with `kingfisher scan` to customize live validation behavior:

```bash
# Set per-request timeout (default: 10 seconds, range: 1-60)
kingfisher scan /path/to/code --validation-timeout 15

# Set number of retry attempts (default: 1, range: 0-5)
kingfisher scan /path/to/code --validation-retries 2

# Increase validation response storage limit (default: 2048 bytes)
kingfisher scan /path/to/code --max-validation-response-length 8192

# Disable validation response storage truncation entirely (0 = unlimited)
kingfisher scan /path/to/code --max-validation-response-length 0

# Include full validation response bodies end-to-end (no validation or reporter truncation)
kingfisher scan /path/to/code --full-validation-response

# Combine options
kingfisher scan /path/to/code \
  --validation-timeout 20 \
  --validation-retries 3 \
  --max-validation-response-length 8192
```

- `--validation-timeout SECONDS`: per-request and per-match timeout for validation (default: 10, range: 1-60).
- `--validation-retries N`: number of retry attempts for validation requests (default: 1, range: 0-5).
- `--max-validation-response-length BYTES`: maximum bytes stored from validation response bodies (default: 2048; `0` disables truncation at storage time).
- `--full-validation-response`: include complete validation response bodies end-to-end. This bypasses both storage-time truncation and reporter display truncation, and takes precedence over `--max-validation-response-length`.

## Scanning in CI Pipelines

Limit scanning to the delta between your default branch and a pull request branch by combining `--since-commit` with `--branch` (defaults to `HEAD`). This only scans files that differ between the two references, which keeps CI runs fast while still blocking new secrets.

Use `--branch-root-commit` alongside `--branch` when you need to include a specific commit (and everything after it) in a diff-focused scan without re-examining earlier history. Provide the branch tip (or other comparison ref) via `--branch`, and pass the commit or merge-base you want to include with `--branch-root-commit`. If you omit `--branch-root-commit`, you can still enable `--branch-root` to fall back to treating the `--branch` ref itself as the inclusive root for backwards compatibility. This is especially useful in long-lived branches where you want to resume scanning from a previous review point or from the commit where a hotfix forked.

> **How is this different from `--since-commit`?**   
> `--since-commit` computes a diff between the branch tip and another ref, so it only inspects files that changed between those two points in history. `--branch-root-commit` rewinds to the parent of the commit you provide and then scans everything introduced from that commit forward, even if the files are unchanged relative to another baseline. Reach for `--since-commit` to keep CI scans fast by checking only the latest delta, and use `--branch-root-commit` when you want to re-audit the full contents of a branch starting at a specific commit.

```bash
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"
```

Another example:

```bash
cd /tmp
git clone https://github.com/micksmix/SecretsTest.git

cd /tmp/SecretsTest
git checkout feature-1
#
# scan diff between main and feature-1 branch
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --since-commit=$(git -C /tmp/SecretsTest merge-base main feature-1)
#
# scan only the snapshot of a specific commit
kingfisher scan /tmp/SecretsTest \
  --branch baba6ccb453963d3f6136d1ace843e48d7007c3f --git-history none
#
# scan feature-1 starting at a specific commit (inclusive)
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --branch-root-commit baba6ccb453963d3f6136d1ace843e48d7007c3f
#
# scan feature-1 starting from the commit where the branch diverged from main
kingfisher scan /tmp/SecretsTest --branch feature-1 \
  --branch-root-commit $(git -C /tmp/SecretsTest merge-base main feature-1)
#
# scan from a hotfix commit that should be re-checked before merging
HOTFIX_COMMIT=$(git -C /tmp/SecretsTest rev-parse hotfix~1)
kingfisher scan /tmp/SecretsTest --branch hotfix \
  --branch-root-commit "$HOTFIX_COMMIT"
```

When the branch under test is already checked out, `--branch HEAD` or omitting `--branch` entirely is sufficient. Kingfisher exits with `200` when any findings are discovered and `205` when validated secrets are present, allowing CI jobs to fail automatically if new credentials slip in.

> **Tip:** You can point Kingfisher at a local working tree and scan another branch or commit without changing checkouts. The CLI now resolves repositories from their worktree roots, so commands like the following work without needing to pass the `.git` directory explicitly:

```bash
kingfisher scan /path/to/local/repo --branch <ref>
kingfisher scan C:\\src\\repo --branch <commit-hash>
```

The same diff-focused workflow works when cloning repositories on the fly by passing a Git URL directly to `scan`. Kingfisher automatically tries remote-tracking names like `origin/main` and `origin/feature-1`, so you can target the branches involved in a pull request without performing a local checkout first.

```bash
kingfisher scan https://github.com/org/repo.git \
  --since-commit main \
  --branch development
```

When no explicit diff options (`--since-commit`, `--branch-root`, `--branch-root-commit`, or `--staged`) are supplied, `--branch` scans all history reachable from the requested ref, including merged branches. This is the default `--git-history full` behavior and finds secrets deleted in later commits without scanning unrelated branches or checking out the selected ref. Use `--git-history none` to scan only the selected ref’s snapshot. Full-history enumeration takes more time and buffers blob metadata before scanning; the revision walk and commit diffs share one `--git-repo-timeout` budget. Increase that timeout for large histories when needed.

```bash
# Scan a branch from an existing checkout
kingfisher scan ~/tmp/repo --branch feature-123

# Or scan a branch when cloning on the fly
kingfisher scan https://github.com/org/repo.git \
  --branch origin/feature-123
```

In CI systems that expose the base and head commits explicitly, you can pass those SHAs directly while scanning a Git URL:

```bash
kingfisher scan https://github.com/org/repo.git \
  --since-commit "$BASE_COMMIT" \
  --branch "$PR_HEAD_COMMIT"
```

If you want to know which files are being skipped, enable verbose debugging (-v) when scanning, which will report any files being skipped by the baseline file (or via --exclude):

```bash
# Skip all Python files and any directory named tests, and report to stderr any skipped files
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude tests \
  -v
```

### Compiled Rule Cache

Kingfisher persists the compiled Vectorscan rule database by default so repeated short runs, such as pre-commit hooks and CI jobs, do not pay the full database compilation cost every time.

If no cache directory is specified, Kingfisher uses a platform default:

- Windows: `%LOCALAPPDATA%\Kingfisher\rule-cache`
- macOS: `~/Library/Caches/kingfisher/rule-cache`
- Linux/Unix: `$XDG_CACHE_HOME/kingfisher/rule-cache`, then `~/.cache/kingfisher/rule-cache`

```bash
kingfisher scan . --staged

KF_RULE_CACHE_DIR=.kingfisher-cache kingfisher scan . --staged

kingfisher scan . --staged --rule-cache-dir .kingfisher-cache
```

For Docker runs, the default cache directory lives inside the container and is lost when the container is removed. Mount a host directory and set `KF_RULE_CACHE_DIR` so repeated `docker run --rm` scans reuse the cache:

```bash
docker run --rm \
  -v "$PWD":/src \
  -v "$HOME/.cache/kingfisher-rule-cache":/kf-cache \
  -e KF_RULE_CACHE_DIR=/kf-cache \
  ghcr.io/mongodb/kingfisher:latest scan /src --staged
```

Use `--no-rule-cache` to disable the cache for a scan:

```bash
kingfisher scan . --staged --no-rule-cache
```

To pre-warm the cache before the first scan, run:

```bash
kingfisher rules compile-cache
```

Cache pruning is opt-in. To remove old compiled databases during a scan, pass `--prune-rule-cache`. By default, pruning keeps at least 10 cache entries and removes only entries older than 30 days. Tune those thresholds with `--rule-cache-max-entries` and `--rule-cache-max-age`:

```bash
kingfisher scan . --staged --prune-rule-cache

kingfisher scan . --staged \
  --prune-rule-cache \
  --rule-cache-max-entries 20 \
  --rule-cache-max-age 14d
```

To inspect or prune the cache without scanning, use `kingfisher rules prune-cache`:

```bash
kingfisher rules prune-cache --dry-run

kingfisher rules prune-cache \
  --rule-cache-max-entries 20 \
  --rule-cache-max-age 14d
```

By default, Kingfisher logs the cache directory in use. Pass `--debug` or `-v` to see cache hit/miss details and when new entries are written.

The cache key includes the resolved rule order, rule patterns, platform, cache format, and Vectorscan runtime version. This works with the default Betterleaks catalog and custom rules loaded through `--rules-path`. When any loaded rule pattern or the Vectorscan runtime version changes, Kingfisher uses a new cache entry automatically. If a cache entry is missing, corrupt, or incompatible with the current platform, Kingfisher falls back to compiling normally and refreshes the cache.

## Default Betterleaks Rules

[Betterleaks](https://github.com/betterleaks/betterleaks) supplies Kingfisher's main candidate
detector catalog, with selected [Veles](https://github.com/google/osv-scalibr/tree/main/veles)
detectors filling gaps. They load automatically and use the `betterleaks.` and `veles.` namespaces:

```bash
kingfisher scan --rule betterleaks.openai-api-key /path/to/repo
kingfisher validate --rule betterleaks.github-pat TOKEN
```

The `betterleaks.` prefix is optional for short selectors such as `--rule github-pat`. Custom rules
loaded through `--rules-path` are additive by default. Use `--load-builtins=false` for a custom-only
scan, or `--no-builtins` with `validate` and `revoke`.

Kingfisher omits Betterleaks' `generic-api-key`, `generic-password`, and `generic-username` rules
from the built-in catalog because their broad patterns provide low signal at disproportionate scan
cost. Use a targeted custom TOML or YAML rule when your organization needs generic credential
detection for a known naming convention.

Kingfisher embeds 485 built-in rules. It does not vendor the upstream rule catalogs. Clean source
builds require outbound HTTPS access: the build downloads the pinned Betterleaks catalog snapshot from its
[source permalink](https://github.com/betterleaks/betterleaks/blob/95237cf8eb4d8e9f67409595b245e674832992cf/config/betterleaks.toml) and
selected Veles source files from the full OSV-SCALIBR commit in
`crates/kingfisher-rules/data/veles-rules.yml`, then converts and embeds the generated database.
A Betterleaks release is preferred; the current immutable post-release commit is pinned because
the latest release predates detectors that Kingfisher ships.
`KINGFISHER_BETTERLEAKS_CONFIG` may point to a local TOML file for controlled importer development.
Veles import is not available through `--rules-path`.

Detection regexes, path constraints, confidence changes, component dependencies, and Betterleaks
validation expressions are translated into Kingfisher's runtime model. The top-level Betterleaks
`prefilter` is stored once on the compiled rule database, compiled into its own Vectorscan
database, and evaluated once per source path before content matching. The top-level finding
`filter` and each rule's `filter` are combined and evaluated only after a candidate match; their
regex helpers are likewise compiled once into shared Vectorscan databases. Betterleaks `keywords`
are intentionally ignored because Vectorscan already performs candidate selection. Production
validation runs in Rust; Go and Betterleaks itself are not runtime dependencies. Provider endpoint
overrides are exposed to Betterleaks validation environment variables.

The source prefilter applies only to Betterleaks rules. Custom and Veles rules still run on paths
that Betterleaks excludes.

`--blast-radius` (alias `--access-map`) works for validated Betterleaks findings when Kingfisher has
an access-map handler for the credential shape. Because Betterleaks currently has no revocation or
checksum metadata, Kingfisher maintains a checked-in capability overlay for access-map bindings and
selected safe revocation actions. It contains no candidate detector regexes, but may add narrow
operational filters and capability metadata; it is validated against the downloaded imported-detector IDs
and components during the build. Checksum templates remain available to
Kingfisher 1.x custom rules; Betterleaks detectors rely on their upstream regex/filter behavior until the
upstream schema exposes checksum metadata.

The `betterleaks.gcp-api-key` binding uses this path to run the bounded, read-only Google API-key
mapper. It records exact accepted, restricted, invalid, and inconclusive probe outcomes without
inferring access to untested methods; see [Blast Radius](../features/blast-radius.md#gcp-gcp) for its allowlist
and safety boundaries.

New generally useful rules and validation improvements must be contributed to the
[Betterleaks repository](https://github.com/betterleaks/betterleaks) first. Do not add a new
Kingfisher-owned built-in YAML catalog.

## Custom Rules

Kingfisher's 1.x YAML format remains supported for private, organization-specific custom rules.

First, review [RULES.md](../rules/overview.md) to learn how to create custom Kingfisher rules.

### Scan with only custom rules

To scan using **only** your own `my_rules.yaml`:

```bash
kingfisher scan \
  --load-builtins=false \
  --rules-path path/to/my_rules.yaml \
  ./src/
```

### Add custom rules alongside built-ins

To add your rules alongside the built‑ins:

```bash
kingfisher scan \
  --rules-path ./custom-rules/ \
  --rules-path my_rules.yml \
  ~/path/to/project-dir/
```

### Scan a custom rules directory

`--rules-path` accepts a directory of `.yml`/`.yaml` rule files, not just a single file. Point it at any rules directory to load every rule file it contains.

**Custom-only** (no built‑ins loaded):

```bash
kingfisher scan --load-builtins=false --rules-path path/to/rules/ <target>
```

**Additive** (your rules run alongside the Betterleaks built‑ins):

```bash
kingfisher scan --rules-path path/to/rules/ <target>
```

Note that a custom-only scan (`--load-builtins=false`) has no Betterleaks source prefilter, so paths that the built-in catalog would otherwise exclude are scanned by your rules. See [Default Betterleaks Rules](#default-betterleaks-rules) above.

### Check custom rules

```bash
# Check custom rules - ensures all regexes compile and match rule examples
kingfisher rules check --rules-path ./my_rules.yml

# List all built-in rules
kingfisher rules list
```

### Scan using a rule family

_(prefix matching: `--rule betterleaks.aws` loads the Betterleaks AWS family)_

```bash
# Only apply Betterleaks AWS-related rules
kingfisher scan /path/to/repo --rule betterleaks.aws
```

## Rule Performance Profiling

Use `--rule-stats` to collect timing information for every rule. After scanning, the summary prints a **Rule Performance Stats** section showing how many matches each rule produced along with its slowest and average match times. Useful when creating rules or debugging rules.

```bash
kingfisher scan /path/to/repo --rule-stats
```

## Control Scan Concurrency

`--jobs` sets the scanner worker pool used for matching and Git scans. By default, Kingfisher uses
the available logical CPUs, capped at approximately one worker per GiB of RAM. Reduce the value on
memory-constrained CI runners or when scanning very large Git histories; a lower value trades some
throughput for lower peak memory usage.

```bash
# Use four scanner workers for a large repository
kingfisher scan /path/to/large-repo --jobs 4
```

For project config, set `scan.jobs`. Pass `--jobs` on the command line when the Tokio runtime and
scanner pool must use the same explicit value; see [Project Configuration caveats](../usage/configuration.md#caveats).

## Disk Offload

`--disk-offload` trades temporary storage I/O for lower memory use while findings accumulate
across repositories or input roots. It is **disabled by default**. It preserves captured values,
commit metadata, dependency helpers, validation results, and global deduplication, without
changing worker count or Git history coverage.

```bash
kingfisher scan /path/to/repos --scan-nested-repos --disk-offload --format toon
```

### When to use it

Enable it for scans of many repositories or input roots when findings from completed inputs
consume memory needed by the inputs still being scanned. It is most useful when those completed
inputs produce many findings or large associated metadata or validation responses, and a fast
local temporary-storage volume has sufficient free space. It lets you reduce that accumulation
without reducing `--jobs` or narrowing history coverage.

It is less useful for a single repository or scans with few findings. It does **not** limit the
memory needed to scan an individual repository, hold concurrently active repositories, or
perform final processing. All findings are restored to RAM before the final consumers run, so
it cannot prevent an out-of-memory failure if that final working set is too large. Digest
and blob-ID indexes also remain in memory throughout the scan.

For example, when `kingfisher scan ~/mms --disk-offload --format toon` scans `~/mms`
as a single repository, all of that repository's findings accumulate in RAM until its scan
finishes. They are then written to disk and loaded back into RAM for final processing.
**Similar memory usage with and without the flag is expected for this workload**, including
similar peak memory. Offloading happens between completed repositories or input roots, not
between files, commits, or finding batches within an active repository. The flag does not
bound total scan memory or reduce Git scanning and worker memory.

Disk-backed storage adds serialization, writes, and reads; it is not a speed optimization. Measure elapsed
time and peak memory on your workload before enabling it routinely. A memory-backed temporary
filesystem such as `tmpfs` still consumes system memory, so it may not relieve overall memory
pressure even if the scanner's own resident memory falls.

### How it works

1. Kingfisher opens a temporary file when the option is enabled.
2. After a completed repository or input root's results are merged into the accumulated store,
   Kingfisher appends those findings as internal JSON Lines records and flushes the write buffer.
   Only after the write succeeds does it release that accumulated in-memory batch and its
   metadata maps. With parallel scans, active repositories still keep their own working sets.
3. Before final processing, Kingfisher reads the records back in batches, reconstructing the
   findings and shared metadata. Final deduplication, validation, and reporting still operate
   on an in-memory store. After successful restoration, the temporary file is truncated to zero
   bytes; its handle is closed when the store is dropped or the process exits.

This internal representation is independent of report serialization. It contains **unredacted
credentials**, including when `--redact` is used, so later processing receives the original
values. It is not an exported report, saved scan, or resumable checkpoint. If temporary storage
fills up, Kingfisher attempts the in-memory fallback described below.
Other creation, write, or restore failures fail the scan explicitly rather than silently
discarding findings.

### If temporary storage fills up

If the OS reports that temporary storage is full while creating the file, Kingfisher prints a
warning and continues with findings in memory. If it fills up during a write, Kingfisher:

1. Rolls back the incomplete append to the last successfully written batch. The current batch
   is still in memory and has not been discarded.
2. Prints a warning, restores all previously stored findings to memory, and keeps the pending
   findings alongside them, preserving deduplication and metadata.
3. Closes the temporary file and disables disk offload for the rest of that scan.
   It does not repeatedly retry a full disk.

This allows the scan to continue without losing findings, **provided enough RAM is available**.
Memory use may increase substantially; the fallback cannot guarantee completion if RAM is also
exhausted. The disk must still be readable. If rollback or restoration fails, Kingfisher stops
with an error instead of continuing with an incomplete result. Other I/O errors, such as denied
access or corrupt records, remain fatal. This fallback applies only to temporary findings
storage; it does not recover failures writing reports, fetching repositories, or extracting
archives.

### Privacy and location

The file is created with `tempfile::tempfile()` in the operating system's temporary directory.
Kingfisher retains an open file handle, not a user-facing filename. It does not place the temporary file
in the scanned repository, report output directory, or `--git-clone-dir`.

“Private” and “anonymous” describe file access and lifetime, not encryption:

- **Linux:** where supported, the file is created without a directory entry using `O_TMPFILE`.
  Otherwise, it uses the Unix fallback below.
- **macOS and the Unix fallback:** a randomly named file is created with owner-only read/write
  permissions (`0600`, further restricted by the process umask), then immediately unlinked.
  Unlinking removes its directory entry while the open handle keeps its contents available to
  Kingfisher. After unlinking, another process cannot simply open it by its former pathname.
- **Windows:** a randomly named temporary file is opened without file sharing and with
  delete-on-close enabled. Its name can remain visible until the handle closes, so “anonymous”
  does not mean an invisible directory entry on Windows. Ordinary attempts to open the file
  while Kingfisher holds it are denied by the sharing mode.

These protections do not isolate the data from an administrator or a process with sufficient
rights to inspect Kingfisher or its open handles. The contents are not encrypted by Kingfisher,
and deletion is not secure erasure. Use suitably protected temporary storage if captured
credentials must be encrypted at rest.

On Unix, set `TMPDIR` before launching Kingfisher to choose a different existing temporary
directory, for example on a protected local disk with enough free space:

```bash
TMPDIR=/path/to/private-temp kingfisher scan /path/to/repos \
  --scan-nested-repos --disk-offload --format toon
```

### Cleanup and crashes

Normal completion truncates the temporary file after restoration and closes its handle when the store
is released. On an error, closing the handle also releases the temporary file, even if its
contents were never restored. No separate Kingfisher cleanup command or scheduled sweep is
needed for the normal case.

If Kingfisher panics, aborts, or is forcibly terminated (including `SIGKILL` on Unix), the OS
closes its handles when the process exits. An already-unlinked Unix file is reclaimed after
its last handle closes; Windows deletes the file through its delete-on-close setting. This
cleanup does not depend on Rust destructors or a signal handler running. The temporarily stored findings
are lost and cannot be used to resume the interrupted scan.

There are limits to that guarantee. In the Unix named-file fallback, termination in the brief
interval between creation and unlinking can leave a randomly named file behind; an unlink
failure can also leave a name behind. A whole-machine crash or power loss additionally depends
on filesystem recovery and is not a secure-erasure guarantee. Kingfisher does not run a startup
sweep for such remnants. If a leftover is found in the chosen temporary directory, treat it as
sensitive data and remove it after confirming it is no longer in use. Filesystem snapshots,
backups, or recoverable storage blocks can also retain data after deletion.

## Notable Scan Options

- `--jobs <N>`: Set the number of parallel scanner workers; see [Control Scan Concurrency](#control-scan-concurrency).
- `--disk-offload`: Store accumulated repository findings in a private temporary file; see [Disk Offload](#disk-offload).
- `--no-dedup`: Report every occurrence of a finding instead of grouping repeated credential content
- `--include-hidden-findings`: Include hidden helper-rule matches in reports and scan summary counts (diagnostic use)
- `--no-base64`: By default, Kingfisher finds and decodes base64 blobs and scans them for secrets. This adds a slight performance overhead; use this flag to disable
- `--confidence <LEVEL>`: (low|medium|high)
- `--min-entropy <VAL>`: Override default threshold
- `--include-contributors`: When scanning GitHub or GitLab URLs, include contributor-owned repos in the scan
- `--git-clone-dir <DIR>`: Choose the parent directory for cloned repos and scan artifacts (use with Git URL scans)
- `--keep-clones`: Preserve cloned repositories on disk after a scan completes
- `--repo-clone-limit <N>`: Cap GitHub and GitLab clone targets when enumerating users, orgs/groups, or contributor repos; this includes opted-in GitHub gists and GitLab snippets
- `--no-binary`: Skip binary files
- `--no-extract-archives`: Do not scan inside archives
- `--extraction-depth <N>`: Specifies how deep nested archives should be extracted and scanned (default: 2)
- `--redact`: Replaces discovered secrets with a one-way hash for secure output
- `--exclude <PATTERN>`: Skip any file or directory whose path matches this glob pattern (repeatable, uses gitignore-style syntax, case sensitive)
- `--baseline-file <FILE>`: Ignore matches listed in a baseline YAML file
- `--manage-baseline`: Create or update the baseline file with current findings (automatically enables `--no-dedup`)
- `--skip-regex <PATTERN>`: Ignore findings whose text matches this regex (repeatable)
- `--skip-word <WORD>`: Ignore findings containing this case-insensitive word (repeatable)
- `--skip-aws-account <ACCOUNT_ID>`: Skip live AWS validation for findings tied to the specified AWS account number (repeatable, accepts comma-separated lists)
- `--skip-aws-account-file <FILE>`: Load AWS account numbers to skip from a file (one account per line; `#` comments allowed)
- `--ignore-comment <DIRECTIVE>`: Honor additional inline directives from other scanners (repeatable; e.g. `--ignore-comment "gitleaks:allow"`)
- `--no-ignore`: Disable inline directives entirely so every match is reported
- `--no-ignore-if-contains`: Ignore the `ignore_if_contains` filter in rules so placeholder words still produce findings
- `--validation-timeout SECONDS`: per-request and per-match timeout for validation (default: 10, range: 1-60).
- `--validation-retries N`: number of retry attempts for validation requests (default: 1, range: 0-5).
- `--max-validation-response-length BYTES`: maximum bytes stored from validation response bodies (default: 2048; `0` disables truncation at storage time).
- `--full-validation-response`: include complete validation response bodies end-to-end (bypasses storage and reporter truncation).

### Exclude specific paths

```bash
# Skip all Python files and any directory named tests
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude '[Tt]ests'
```

### Scan while ignoring likely test files

`--exclude` skips any file or directory whose path matches this glob pattern (repeatable, uses gitignore-style syntax, case sensitive)

```bash
# Scan source but skip likely unit / integration tests
kingfisher scan ./my-project \
  --exclude='[Tt]est' \
  --exclude='spec' \
  --exclude='[Ff]ixture' \
  --exclude='example' \
  --exclude='sample'
```

### Limit maximum file size scanned

By default, Kingfisher skips files larger than **256 MB**. You can raise or lower this cap per run with `--max-file-size`, which takes a value in **megabytes**.

```bash
# Scan files up to 500 mb in size
kingfisher scan /some/file --max-file-size 500
```

### Customize the HTTP User-Agent

Kingfisher identifies its HTTP requests with a user-agent that includes the binary name and version followed by a browser-style
string. Some environments require extra context, such as a contact address, a change-ticket number, or a temporary test label.
Use the global `--user-agent-suffix` flag to append this information between the Kingfisher identifier and the browser portion:

```bash
# Attach a contact email to all outbound validation requests
kingfisher --user-agent-suffix "contact=security@example.com" scan path/

# Label a one-off experiment
kingfisher --user-agent-suffix "Sept 2025 testing" scan github --user my-user --list-only
```

When omitted, Kingfisher defaults to `kingfisher/<version> Mozilla/5.0 ...`. The suffix is trimmed; passing an empty string has no effect.

## Finding Fingerprints

Kingfisher separates its location-sensitive reported fingerprint from its default,
credential-focused scan deduplication. The document below explains both identities, why repeated
locations are normally grouped into one actionable credential, and how `--no-dedup` reports every
individual occurrence.

See [FINGERPRINT.md](../features/fingerprints.md) for complete details.

## Update Checks

Kingfisher automatically queries GitHub for a newer release when it starts and tells you whether an update is available. The check is informational only — the binary is not modified unless you explicitly opt in.

- **Update and exit** – Run `kingfisher self-update` (alias `kingfisher update`) to download the latest release, replace the running binary in place, and exit. No scanning occurs.

- **Update then run with the new version** – Pass the global `--self-update` flag (alias `--update`) on any scan or other command. If a newer release exists, Kingfisher downloads it, replaces the on-disk binary, and **re-execs into the freshly installed binary** so the current invocation completes with the new code (including the latest detection rules). On Unix this is a true `exec()` (same PID); on Windows the new binary is spawned and the parent exits with its status code. If no update is available, the command runs normally with no extra steps.

- **Disable version checks** – Pass `--no-update-check` to skip both the startup and shutdown checks entirely. Recommended for CI runs to keep behavior reproducible.

Self-update writes to wherever the running binary lives, so it requires the calling user to have write access to that location. If you installed Kingfisher via a package manager (Homebrew, the `.deb`/`.rpm` packages, the PyPI wrapper, etc.), use that package manager's upgrade command instead — Kingfisher will detect the permission error and tell you so.

Self-update supports all six release platforms: Linux x64/arm64, macOS x64/arm64, and Windows x64/arm64.

## Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |
