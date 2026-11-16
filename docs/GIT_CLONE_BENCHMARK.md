# Git clone performance: native Git versus Kingfisher/gix

Measured on 2026-11-14 against <https://github.com/mongodb/mongo.git>.
These are **full-history mirror clones**, not shallow/filtered clones or scanner timings.
There is no checkout; HEAD tree entries are compared to verify the same files.

## macOS results

Environment: macOS 27.2, Apple M4 Max (arm64), 16 logical CPUs, 48 GiB RAM;
Git 2.56.0, gix 0.90.0, Rust 1.99.0. Kingfisher uses its release profile and
normal mimalloc allocator. Both engines use their default thread settings.
Each pair uses fresh destinations in alternating order: Git/gix, then gix/Git.
No concurrent builds, inventories, or other clone jobs run during measured rounds.
OS caches were not flushed; the replay payload was warm.

Medians; all individual samples and build fingerprints are in the
[machine-readable results](GIT_CLONE_BENCHMARK.json).

| Transport / stage | Samples per engine | Native Git | Kingfisher/gix | Gix less elapsed time |
| --- | ---: | ---: | ---: | ---: |
| GitHub HTTPS, baseline | 2 | 64.615 s | 50.560 s | 21.8% |
| GitHub HTTPS, optimized | 3 | 62.916 s | 55.838 s | 11.3% |
| Identical-pack loopback HTTP, baseline | 2 | 24.636 s | 16.712 s | 32.2% |
| Identical-pack loopback HTTP, optimized | 2 | 24.518 s | 16.325 s | 33.4% |

Gix already beat native Git before tuning. The optimized controlled replay takes
33.4% less elapsed time (1.50× throughput). Its gix median is 2.3% below baseline;
with only two samples, that small change is not an established optimization gain.
Loopback timings are **not** GitHub HTTPS timings: they remove WAN/server
pack-generation variability and use smart HTTP v0.

Optimized HTTPS samples were Git **62.916 / 60.230 / 65.263 s** and gix
**102.966 / 55.838 / 51.192 s**. After the first two varied substantially, one
additional paired round was run; no samples were discarded. These WAN results do
not establish a tuning improvement over baseline, despite the lower gix median
than native Git. Small local samples are not a universal performance guarantee.

## Equal coverage

The snapshot has HEAD `525eca950da83a9beba9c4e3cf8f060799e37e98` and 4,799
advertised refs (excluding HEAD and peeled-tag advertisement lines).

| Object/file category | Count |
| --- | ---: |
| Blobs across full history | 915,033 |
| Trees | 911,086 |
| Commits | 162,732 |
| Annotated tag objects | 1,330 |
| Total stored and reachable objects | 1,990,181 |
| HEAD files (blob entries, including symlinks) | 56,155 |

Verification compares HEAD, all oracle refs, every stored object ID/type/size,
all reachable object IDs, and the complete NUL-delimited HEAD tree listing.
Matching counts alone are not sufficient. Gix additionally retains origin aliases
in mirror mode: only candidate-added aliases absent from the oracle and pointing
to the same canonical object are excluded from ref comparison. Real oracle refs
are never normalized away. Shallow repositories, alternates, repeated repository
paths, missing refs, and additional unmatched objects fail verification.

All **18 macOS timed clones** matched the frozen source (19 distinct repositories).
Native Git `fsck --full --no-reflogs` additionally passed on the first optimized
Git and gix clones of **each** transport: four full content-integrity checks.
Repeated clones passed metadata/OID parity, not separate full rehashes.

Canonical inventory SHA-256 digests:

```text
stored ID/type/size: 9d04520ab82e37695e46d72ce6e23dfe158cc25f3b40f56340c2bedf51cfd188
reachable IDs:      f8e59d58a8647863eefddb93c7507d987c4b683daa68291de8265709f4185077
HEAD tree listing:  8292efd0e56d5be17881a90df19821956058729c5510837edfaaf216df396c5b
```

The replay sends exactly the same 1,499,492,635-byte pack (1,990,181 objects) to
both clients. Its pack trailer is `68bde6663be030d32ab65910540f7ade0fd6b7b2`;
SHA-256 of the complete sideband-framed HTTP response is
`4453d7d52ce1820f6371034a4e35e160555d7ee9f412f3d13eb9dd038e348060`.
GitHub can send differently compressed packs containing the same objects.

## Optimizations

- Store initial network-clone refs in one packed-ref transaction, as gix's own
  clone implementation does. Incremental fetches retain normal loose-ref/reflog
  behavior, including pruning previously packed refs.
- Compile `crc32fast` with release optimization level 3 rather than size-oriented
  `z`, retaining checksum validation instead of bypassing it.
- Keep the existing inflater, SHA-1 collision detection, TLS/authentication, and
  full-history/ref scope. No Git fallback is used.

The regression tests exercise many initial packed refs followed by changed,
deleted, and new refs, and reject a corrupt per-object checksum even when the
outer pack digest has been recomputed. Packed-only mode avoids persistent loose-ref
writes, not per-ref locks; preparing packed refs also reads their target objects.
Upstream gix still cannot clone case-distinct ref names on a case-insensitive
filesystem. This optimization does not claim to fix that limitation.

## Reproduce

The [clone-only driver](../examples/git_clone.rs) calls the actual production
repository acquisition API without starting a scan. The
[benchmark harness](../scripts/benchmark-git-clone.py) records commands, binary
SHA-256, exit statuses, elapsed time, and child CPU time. For gix it empties PATH
and sets an unusable Git-binary override, so invoking native Git cannot succeed.
Native Git is used only as the independent benchmark/verification oracle.

```sh
cargo build --locked --release --example git_clone
python3 scripts/benchmark-git-clone.py run \
  --gix target/release/examples/git_clone \
  --output target/clone-benchmark/wan --rounds 2
python3 scripts/benchmark-git-clone.py verify \
  --output target/clone-benchmark/wan-parity.json --fsck \
  --repo git=target/clone-benchmark/wan/git-r1.git \
  --repo gix=target/clone-benchmark/wan/gix-r1.git \
  --repo git2=target/clone-benchmark/wan/git-r2.git \
  --repo gix2=target/clone-benchmark/wan/gix-r2.git
```

Verification is outside clone timing. `--fsck` additionally checks full stored
content integrity with native Git; without it the result establishes metadata
parity, not independent rehashing of every stored object's content.
Use new output paths for each run. The harness accepts HTTP(S) only, preventing
native Git's local-path hardlink shortcut from contaminating comparisons.

For the identical-byte control, start the
[frozen snapshot replay](../scripts/serve-git-clone-snapshot.py) in another terminal:

```sh
python3 scripts/serve-git-clone-snapshot.py \
  --repository target/clone-benchmark/wan/git-r1.git \
  --output target/clone-benchmark/replay --port 8765
```

Then rerun the benchmark with a fresh output directory and
`--url http://127.0.0.1:8765/mongo.git`, followed by verification as above.
Preparation requires a trusted, full SHA-1 mirror containing one self-contained
pack. The loopback-only server preframes that pack and never runs upload-pack
while a clone is timed; it is not a general-purpose Git hosting service.

## Validation

Passed on this macOS host: 1,122 library tests (one ignored), 48 integration tests,
two live private HTTPS/SSH authentication tests, and 12 benchmark-harness tests.
Formatting, Clippy (`--all-targets -- -D warnings`), generated rule-bundle checks,
and the MkDocs build also passed. Full macOS workspace tests were not rerun;
the fresh Rust test run covered the CLI library and Git/provider integrations.

After the guest-discovered fixture corrections, macOS reruns passed all 16 affected
timeout/repository-ID integration tests and 12 SSH unit tests (one fixture ignored).

## VMware Fusion guest validation

Fusion 26.0.1 (build 25689522) runs two ARM64 guests on the same M4 Max host.
Each has six vCPUs: Ubuntu 24.04.5/kernel 6.8.0-147 has 16 GiB RAM and ext4;
Windows 11 has 12.5 GiB and guest-local NTFS. Sources and outputs are not on HGFS.
Windows ARM64 executes natively; **Windows x64 executes under Prism emulation**,
not on x64 hardware. The x64 build uses the native ARM64 Rust compiler with an
explicit x64 target. Rust is 1.99.0 on both guests.

### Mongo replay

Guest timings use the same frozen 1,499,607,087-byte smart-HTTP response described
above, served over guest loopback—not GitHub WAN. Each engine makes two full-history,
all-ref mirrors with default threading, warm OS caches, and no competing task builds,
tests, or inventories during timing. Builds use the unchanged production release
profile, including LTO and one codegen unit.

| Execution target | Native Git median | Gix median | Gix elapsed-time reduction |
| --- | ---: | ---: | ---: |
| Linux ARM64 | 51.123 s | 23.109 s | 54.8% |
| Windows ARM64 | 47.104 s | 26.830 s | 43.0% |
| Windows x64 / Prism | 70.687 s | 39.514 s | 44.1% |

All 12 guest mirrors and both guest source copies (14 distinct repositories) passed
`git fsck --full --no-reflogs`, matching every canonical ref, stored/reachable object,
and HEAD-tree fingerprint above. The Windows source and all eight mirrors emitted
the same historical `zeroPaddedFilemode` warning; these were not strict fsck runs.
Two paired rounds are a small local sample, not statistical or cross-hardware proof.

On Windows, the unchanged benchmark helper hashes the driver once at each
architecture group's start, outside timing. No replay-payload/repository hashes,
inventories, or fsck ran between the groups. The original prewarm proof and its
explicit scope correction are preserved. The identical replay server and Python
harness run under x64/Prism for both client targets; client PE headers establish
native ARM64 versus x64/Prism execution, not the raw result's host-architecture field.

### Regression and authentication

Guest workspace/all-target tests exclude `kingfisher-node`:

| Execution target | Workspace tests | Additional validation |
| --- | --- | --- |
| Linux ARM64 | 2,768 passed, 7 ignored | Formatting, all-target Clippy with warnings denied |
| Windows ARM64 | 2,740 passed, 7 ignored | `make windows-test-arm64`; 12 Python harness tests |
| Windows x64 / Prism | 2,740 passed, 7 ignored | `make windows-test-x64`; 12 Python harness tests |

Each target additionally passed both ignored live private HTTPS/SSH tests, with
Git unavailable to gix, an invalid Git-binary override, pinned SSH host trust,
and no credential persistence. Linux also passed the 12 Python harness tests.
The four source adjustments made during guest validation are test-only: native
`ssh.exe` assertions, timeout diagnostic expectations, clean local Bitbucket URL
rewrites, and an optional isolated SSH configuration for the live test. No
transport/runtime changes were introduced during VM validation. The JSON report
records the frozen guest source fingerprint separately from later host report edits.

The Windows SSH-based launcher inherited stale Win32-OpenSSH descriptor metadata.
A controlled held-open-stdin probe stalled for 12 seconds with that metadata and
returned the v2 header in 0.97 seconds without it; native Git reproduced the same
failure. Only the test-process environment was sanitized, case-insensitively;
no guest-wide SSH/environment setting, stdin EOF workaround, or protocol preload was used.
Both architectures then passed with the **stock Microsoft OpenSSH 9.5** client.
This matches the upstream warning about stale state across non-POSIX intermediary
processes ([Win32-OpenSSH source](https://github.com/PowerShell/openssh-portable/blob/v9.5.0.0/contrib/win32/win32compat/w32fd.c#L114-L127)).

### Evidence, cleanup and shutdown

Evidence was exported and SHA-256-verified before deletion. Each guest ran
`make clean` successfully before its Fusion `soft` shutdown was requested.
Both were subsequently confirmed off, with zero VMs in Fusion's running list.
Cargo reported 26,814 files/21.3 GiB removed on Linux and 29,613 files/58.7 GiB
on Windows. Owned Mongo benchmark trees were also removed; sources, logs, and
tools were retained. Post-cleanup audits verified the expected output paths absent,
with no owned replay/build processes remaining. These validation-cleanup guards
assume a quiescent controlled guest, not hostile concurrent path swaps.
