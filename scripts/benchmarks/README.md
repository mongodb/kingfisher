# Dense-finding benchmarks (#537)

The PlanetScale reproducer repeatedly rescanned regex confirmation windows, including
rejected endpoints. The fix reuses safe match boundaries and caches shifted match
sequences while preserving EOF, leftmost-match, and capture behavior. The review also
found independent dense-input costs in catalog deduplication, component association,
credential-URI overlap checks, and inline-ignore searches; these now use indexes.

Run from the repository root with the SDK's Python environment active:

```sh
maturin develop --profile python-release
python scripts/benchmarks/dense_findings.py
cargo build --release --bin kingfisher
python scripts/benchmarks/dense_findings.py --cli target/release/kingfisher
```

Use `--case issue-537` to run just the exact issue reproducer, or repeat `--case`
to select other fixtures. `--size` limits runs to selected nominal input sizes;
`--repeats` defaults to three. The fixtures cover
PlanetScale, JFrog, ClickHouse, Cloudinary, Salesforce, Tableau, visible catalog
findings, repeated credential components, Auth0 domains, and eBay client IDs. Scans never
validate credentials.

Measurements recorded on October 5, 2026, on macOS 26.7.1 arm64 with Rust 1.99.0
and Python 3.11. Before: installed SDK 1.1.0, CLI 2.10.0, scanner crate 1.2.0.
After: SDK 1.1.1 (`python-release`), CLI 2.11.0 and scanner crate 1.2.1 (`release`).
These are the version labels recorded for that run; the SDK and scanner manifests
now use 1.3.0. Finding counts alone do not verify secret, offset, or fingerprint parity;
those contracts are covered by the scanner regression tests.
Times are medians of three runs in seconds; fixtures and finding counts match
between versions. SDK timings exclude rule compilation and input generation;
CLI timings include process startup, file I/O, and TOON reporting.

| Input bytes | Findings | SDK before | SDK after | CLI before | CLI after |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 25,026 | 662 | 0.218 | 0.015 | 0.769 | 0.219 |
| 50,035 | 1338 | 0.904 | 0.031 | 2.533 | 0.248 |
| 100,014 | 2669 | 4.972 | 0.071 | 8.889 | 0.345 |
| 200,039 | 5332 | 26.349 | 0.183 | 47.165 | 0.640 |

At 200 KB the SDK is **144× faster** and the CLI is **74× faster**, retaining
all 5,332 findings. The largest doubling takes about 2.6× in the SDK and 1.9×
in the CLI, versus roughly 5.3× in both original runs.

The complete PlanetScale token-and-ID component fixture retains 5,798 findings
at 200 KB and improves CLI time from 3.876 to 0.669 seconds (**5.8× faster**).

These are local microbenchmarks, not cross-machine performance guarantees.
Unbounded EOF-sensitive expressions
retain the original search when safe skipping cannot be proved. A regex may restart after a
newline only when HIR analysis proves that no match can consume a newline and then continue.

Verification for the recorded benchmark run: 1,552 Rust workspace tests passed (two existing tests ignored),
19 Python tests passed, workspace Clippy passed with warnings denied, and the
485-rule bundle passed reproducibility checks. The MkDocs site rebuilt successfully.
New regression coverage compares indexed catalog selection, regex captures, component
windows, and inline-ignore searches against their original behavior, checks cache
reuse and bounded candidate work, and verifies the exact SDK issue fixture.
Windows x64/arm64 was not verified in that benchmark run.

## Embedded connection-string rule comparison (#558)

`connection_string_password.py` compares a baseline CLI without the embedded
`kingfisher.connection-string.password.*` family with the CLI containing it.
Use unchanged local working trees, for example the public croc, Django, Rails,
Ruby, and TypeScript repositories:

```sh
python scripts/benchmarks/connection_string_password.py \
  --old /tmp/kingfisher-558-baseline --new target/debug/kingfisher \
  --target /path/to/croc --target /path/to/django --target /path/to/rails \
  --target /path/to/ruby --target /path/to/typescript \
  --repeats 3 --results /tmp/kingfisher-558-comparison.json
```

Runs are sequential and alternate build order. Both binaries use all default
rules at medium confidence, two jobs, and working trees only (`--git-history none`).
They include every occurrence and hidden helper finding (`--no-dedup
--include-hidden-findings`) so strict metadata comparisons do not depend on
deduplication's choice of representative origin. Live validation, update checks, and the
compiled-rule cache are disabled. Timings include startup, rule compilation,
scanning, and redacted JSON reporting. Build both binaries with the same profile
and toolchain when assessing the cost of the added rules.

The results record distinct binary paths and version labels, each run's time
and counts, median times, scanned blobs/bytes, repository completion and commit
coverage, and audit findings before report filtering. Standard JSON reports do
not expose pre-filter candidate counts. Redacted reports remain in a private
temporary directory outside the scanned inputs; the results file records its
location. Keep the results file outside all targets too.

Existing-rule findings are compared as fingerprint and metadata multisets,
excluding snippets and validation. Added findings are summarized by rule and
path/line without credential content, and must remain stable across repeated
new-build scans. The script exits unsuccessfully if existing findings or coverage
identities change, a paired run or completed audit is missing, scanned counts are
unstable within a build or decrease in the new build, the baseline reports an
added-rule finding, or added-rule findings vary across repeats.

Scanned blob and byte counts can increase: the first-party rules also examine
paths excluded by the imported source catalog's prefilter. Without an eligible
rule from another source, the baseline can skip those blobs before incrementing
scan counters. Results record explicit per-repository and summary coverage deltas;
repository identities, scope, commit tips, and completed status must still match.
This is expanded detection scope, so report the extra scanned data when assessing
timing changes. Review added finding locations to assess noise; stable counts
alone do not establish accuracy.

Recompute checks and median times from saved raw runs without rescanning:

```sh
python scripts/benchmarks/connection_string_password.py \
  --recheck-results /tmp/kingfisher-558-comparison.json
```

This mode replaces the saved comparisons in place, retains every raw run, and
cannot be combined with scan arguments. It checks for every requested paired
repeat; older results without an explicit repeat count use the largest recorded
repeat number across all targets.

### Local corpus verification (October 29, 2026)

The final 501-rule catalog, including five first-party connection-string rules, was
checked against the 496-rule baseline using one paired scan per unchanged working
tree (`--repeats 1`). Both Linux arm64 CLI builds reported 2.16.0 and used Rust
1.99.0's unoptimized `dev` profile with debug information and the flags above.

| Working tree | Existing findings | Added findings | Additional blobs | Additional bytes |
| --- | ---: | ---: | ---: | ---: |
| croc | 0 | 0 | 4 | 681,344 |
| django | 0 | 0 | 92 | 2,123,160 |
| rails | 0 | 0 | 88 | 12,850,667 |
| ruby | 47 | 0 | 6 | 370,450 |
| typescript | 0 | 0 | 32 | 372,295 |

All ten scans completed. Existing fingerprint and finding-record multisets matched
exactly, including the 47 findings in Ruby. The five first-party rules added no
findings on these checkouts. Synthetic regressions separately verify positive
detection, exact captures and offsets, JDBC query and SQL Server formats, quoting,
placeholder exclusions and their override, percent encoding, and Base64 behavior.

The final catalog scanned 222 additional blobs totaling 16,397,916 bytes because the
first-party rules do not inherit Betterleaks-only source exclusions. No scan counts
decreased. This single-pair run checks finding parity and coverage; use repeated
runs with matching release builds to assess throughput. Windows x64/arm64
verification remains pending.

## Additional dense-input variants

`dense_findings.py` also covers `single-line-visible`, `single-line-filter`, and
`base64-uris`. Use `--detection` to include SDK CLI-compatible URI suppression:

```sh
python scripts/benchmarks/dense_findings.py --detection \
  --case single-line-visible --case single-line-filter --case base64-uris
```

A follow-up run on October 6, 2026 compared the installed SDK with the rebuilt
SDK on macOS arm64; both reported version 1.3.0. Before timings are one scan;
after timings are the median of three. Rules are compiled once and reused.
At approximately 200 KB, all finding counts were unchanged:

| Fixture | Findings | Before (s) | After (s) |
| --- | ---: | ---: | ---: |
| Visible tokens on one line | 4,879 | 4.545 | 0.038 |
| Cloudflare line filters | 3,572 | 24.813 | 0.076 |
| Distinct Base64 credential URIs | 2,778 | 2.440 | 0.104 |

After the fixes, doubling from 100 KB to 200 KB takes approximately 2× for
all three fixtures. Deterministic regressions additionally check scan cursor
progress, required-component propagation, column-bounded candidate work,
line-regex reuse, and same-rule overlap pruning. These fixes target the tested
variants; arbitrary broad component windows and cross-rule substring joins can
still require work proportional to the candidate relationships.

## Local repository comparisons

`repository_scans.py` compares the installed binary found on `PATH` with the
release build. Both versions use all default rules, medium confidence, normal
report deduplication, Base64 decoding, archive extraction, inline ignores, and
commit metadata. It fixes concurrency at 16 jobs, disables update checks and live
validation, and removes the repository timeout for complete history scans.
Runs execute sequentially with alternating version order. Reports are redacted
and kept in a private temporary directory outside the input repositories.
Results record counts, digests, coverage, timings, local paths and scan flags.

```sh
python scripts/benchmarks/repository_scans.py \
  --target ~/example-repo --target ~/dev/bench-repos --history none --repeats 3 \
  --results /tmp/kingfisher-working-trees.json
python scripts/benchmarks/repository_scans.py \
  --target ~/example-repo --target ~/dev/bench-repos --history full --repeats 1 \
  --results /tmp/kingfisher-full-history.json
python scripts/benchmarks/repository_scans.py \
  --target ~/example-repo --target ~/dev/bench-repos --history none --repeats 1 \
  --all-occurrences --results /tmp/kingfisher-occurrences.json
```

The occurrence check includes hidden helper findings and disables report
deduplication. This permits strict fingerprint comparison; normal deduplicated
reports may choose different representative origins even within one version.
Redacted snippets use a random salt in each process and are excluded from the
report digest.

The installed baseline on `PATH` reported version 2.10.0; the release build
reported 2.11.0. Working-tree times below are medians of three runs; full-history
times are one complete run per version. These local timings do not establish cross-machine guarantees.

| Target | Scope | Reported findings (both) | 2.10.0 seconds | 2.11.0 seconds |
| --- | --- | ---: | ---: | ---: |
| Local repository | Working tree | 84 | 6.101 | 5.960 |
| `~/dev/bench-repos` | Working trees | 328 | 18.901 | 18.926 |
| Local repository | Full history | 735 | 94.530 | 86.977 |
| `~/dev/bench-repos` | Full histories | 868 | 607.817 | 594.589 |

Every run matched per-rule reported counts, findings before report filtering,
and per-repository blob and byte totals. All repository audit statuses were
`completed`. The full-history scans covered 2,018,621 blobs / 100.52 GB in the local repository
and 7,736,379 blobs / 441.68 GB across the nine benchmark repositories.
Working-tree performance is effectively unchanged; neither complete history
comparison showed a slowdown.

The additional working-tree occurrence check returned 543 findings in the local repository
and 547 in `bench-repos` in each version. Per-rule counts, complete coverage,
fingerprint multisets, and finding-record multisets (excluding salted redactions)
matched exactly, including hidden helper findings.

## Auth0 and eBay follow-up (October 8, 2026)

The later [issue #537 comment](https://github.com/mongodb/kingfisher/issues/537#issuecomment-6063792972)
reports dense Auth0 domains and eBay client IDs on separate lines. For these
unbounded, assertion-sensitive rules, regex analysis certifies that a match cannot
continue after a newline. The match index records the most recent safe line start
once per indexed match, so confirmation does not repeatedly search earlier lines.

The SDK fixture uses all built-in rules with rule compilation outside the timer.
These are three-run medians on macOS arm64. The before extension was the existing
editable SDK 1.3.0 build; the after extension was rebuilt from this worktree and
also reports 1.3.0. The 400 KB before SDK cases were omitted because the 200 KB
baseline already took 39 seconds for Auth0 and 8 seconds for eBay per scan.

| Fixture | Bytes | Findings (both) | SDK before (s) | SDK after (s) |
| --- | ---: | ---: | ---: | ---: |
| Auth0 domains | 100,018 | 3,702 | 9.758 | 0.042 |
| Auth0 domains | 200,010 | 7,381 | 39.071 | 0.064 |
| Auth0 domains | 400,022 | 14,815 | not run | 0.112 |
| eBay client IDs | 100,024 | 2,268 | 2.364 | 0.048 |
| eBay client IDs | 200,015 | 4,540 | 8.454 | 0.069 |
| eBay client IDs | 400,008 | 9,094 | not run | 0.113 |

Run just the completed before/after sizes with:

```sh
python scripts/benchmarks/dense_findings.py \
  --case auth0-domain --case ebay-client-id --size 100000 --size 200000
```

The CLI comparison used the installed 2.11.1 binary and the patched 2.12.0
release build. At 400 KB, Auth0 took 1.159 versus 0.454 seconds and eBay took
0.645 versus 0.388 seconds, with identical finding counts. Working-tree scans
of a local large repository had medians of 17.082 versus 16.827 seconds (three
paired runs); `~/dev/bench-repos` had medians of 20.986 versus 21.328 seconds
(five paired runs). The latter difference was within observed run-to-run variation.
Counts, per-rule totals, and scan coverage matched on every run. Strict
all-occurrence scans also matched finding and fingerprint digests: 543 findings
in the local repository and 547 in `bench-repos`.
