# Kingfisher Secret Scanner for Python

Fast secret detection, credential validation and revocation for Python, powered
by [Kingfisher's Rust libraries](https://github.com/mongodb/kingfisher).
Native, in-process execution; no CLI subprocess required. Requires CPython 3.10+.

## Install

```bash
uv add kingfisher-secret-scanner
```

The **PyPI distribution** is `kingfisher-secret-scanner`; the **Python import** is
`kingfisher_sdk`. It coexists with the separately distributed `kingfisher-bin` CLI.

## Scan offline

```python
from kingfisher_sdk import Scanner

scanner = Scanner()  # Compile the bundled rules once and reuse the scanner.
for finding in scanner.scan_file("application.conf"):
    if finding.visible:
        print(finding.to_dict())  # Secrets and captures are redacted by default.
```

## Inspect rules, regexes and configured actions

```python
import json
from kingfisher_sdk import Rules

rules = Rules(confidence="low")  # Include the complete bundled catalog.
print([r["id"] for r in rules.metadata() if r["revocation"]])
detail = rules.detail("betterleaks.aws-access-token")  # Exact loaded rule ID.
print(detail["pattern"])
print(detail["detection_regex"])  # Compiled confirmation regex, comments removed.
print(json.dumps(detail["validation"], indent=2))
print(json.dumps(detail["revocation"], indent=2))
```

`detail()` also includes entropy, path/candidate filters, capture selection,
dependencies, examples and references. It returns a copy; edits do not change
scanning. Absent actions are `None`. HTTP/gRPC configurations show requests and
matchers; Betterleaks logic is a serialized expression tree. Typed/raw handlers
identify Rust implementations rather than exposing their source code. Inspection
makes no provider requests and does not execute revocation. Custom rule literals
are returned as configured.

The [rule example](https://github.com/mongodb/kingfisher/blob/main/python/examples/rules.py)
supports catalog capability filters and detailed field selection:

```bash
uv run --no-sync python python/examples/rules.py --with-revocation
uv run --no-sync python python/examples/rules.py betterleaks.aws-access-token --field pattern --field validation --field revocation
```

## Filter findings and choose inputs

`Rules()` and the default `Scanner()` reuse the CLI's compiled Vectorscan rule
cache. Use `Rules(cache_dir="rule-cache")` to choose a directory, or set
`KF_RULE_CACHE_DIR`; an explicit directory wins. Otherwise the OS cache directory
is used. `Rules(cache=False)` disables all cache reads and writes.

Prewarm at image build time with the same rules and confidence used at startup.
Build as the runtime account, or transfer both the cache directory and its files
to that account with `COPY --chown`; ownership is checked on the receiving files,
not tied to the builder's identity. The commented
[container example](examples/rule_cache.Dockerfile) demonstrates root image-build
prewarming followed by a non-root runtime, including read-only cache hits.
Reuse entries with the same wheel/engine build and compatible CPU architecture; native CPU/version rejection or corrupt entries trigger automatic
recompilation. Cache writes are best effort. Older cache formats recompile once.
Rule loading and confirmation/path/filter initialization still run per `Rules()`;
reuse a scanner within each process. The cache stores rules, not scan results. Cache directories must be trusted.
Unix directories are private; unsafe ownership/permissions disable caching, and
no default falls back to shared temporary storage. Windows cache directories/files
must belong to the caller; DACLs also permit Administrators/SYSTEM, with
TrustedInstaller permitted for protected ancestors only. Payload SHA-256 detects
corruption before native deserialization, rather than authenticating cache writers.
See the commented [cache example](examples/rule_cache.py) and
[cache guide](../docs/PYPI.md#reuse-the-compiled-rule-cache).

Use `Rules(confidence="high")` to load only high-confidence rules, or
`Rules(["company.yml"], builtins=False)` for a custom-only YAML/TOML catalog.
`Scanner(base64=False)` disables Base64 detection. Leave native entropy thresholds
at their defaults unless you intend to override every rule's threshold.

For report filtering, serialize once and inspect the redacted fields:

```python
from fnmatch import fnmatchcase
from kingfisher_sdk import Scanner

findings = Scanner().scan_file("application.conf")
for finding in findings:
    data = finding.to_dict()
    if finding.visible and fnmatchcase(data["rule_id"], "betterleaks.*"):
        if data["entropy"] >= 3.5:
            print(data)
```

Native finding properties expose these fields without serializing the whole
result. Redaction retains fingerprints, entropy and content identity, which can
disclose information about guessable secrets. Keep reports access-controlled.

You can also filter confidence (`low`/`medium`/`high`), Base64 status, line/byte
location, capture-name presence, fingerprint or blob ID. Keep paths alongside
findings for path filters; `Finding` does not contain a filename. After validation,
filter `result.outcome`, `result.http_status` or `result.reason`. Retain invisible
helper findings until validation finishes. Report filters do not reduce detection
work or validation requests.

The [scan example](https://github.com/mongodb/kingfisher/blob/main/python/examples/scan.py)
supports directories, repeated `--rules-path`, `--confidence`, `--exclude`, `--rule`,
`--min-entropy`, `--base64-only`, `--no-base64`, `--unique`, per-file `--timeout`,
and Ctrl-C cancellation. Its entropy option filters output, while
`Scanner(min_entropy=...)` overrides detector thresholds. `--unique` deduplicates
reports by rule and credential value using per-run keyed digests internally; SDK `dedup=True` instead skips repeat successful
scans of identical content at the same path.

```bash
uv run --no-sync python python/examples/scan.py ~/example-repo --timeout 5 --unique --exclude '*.min.js'
uv run --no-sync python python/examples/scan.py application.conf --rule 'betterleaks.*' --min-entropy 3.5
uv run --no-sync python python/examples/validate.py application.conf --outcome verified_active --concurrency 4
```

The directory example skips `.git`, `.venv`, `node_modules` and symlink entries;
its path globs are not `.gitignore` syntax. The composable input APIs below support native filesystem/Git history enumeration
and archive/content expansion. `DetectionScanner` opts into shared CLI matching,
bounded nested Base64, inline-ignore and HTML/CSS checks; validation remains explicit. Enumeration and CLI deduplication can change results
compared with `kingfisher scan`. See the
[filtering and CLI comparison guide](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md#choose-detection-and-reporting-filters).

## Detection policies, SQLite/bytecode and Git scopes

```python
from kingfisher_sdk import DetectionPolicy, Scanner, GitScope, git_inputs, expand_archives, expand_content

sources = git_inputs("./repo", scope=GitScope(since_commit="main"))
sources = expand_content(expand_archives(sources, depth=2))
for result in Scanner(policy=DetectionPolicy()).scan_inputs(sources):
    for finding in result.findings:
        if finding.visible:
            print(result.input.path, [origin.id for origin in result.input.origins], finding.to_dict())
```

`Scanner(policy=DetectionPolicy(...))` adds CLI matching, bounded nested Base64,
inline-ignore and HTML/CSS checks. The frozen policy is reusable; the existing
`DetectionScanner` convenience API constructs that same policy. Default `Scanner`
behavior is unchanged. It defaults to full-match
component windows, URI fallback/secret containment suppression, two Base64 layers,
and a 64 MiB original-input cap for the Base64 pass. Raw scanning still runs above
the cap; nested findings keep the outer encoded region's offsets.
Containment checks are separate for raw input and each decoded buffer, preserving
separately encoded sibling secrets even when they share those outer offsets.
Set `cli_match_semantics=False`, `base64_max_depth=1`, and
`base64_max_input_bytes=None` to retain legacy SDK matching/decoding while choosing
context filters. Each policy can be configured independently. `expand_content` extracts SQLite SQL and `.pyc` strings without
executing bytecode. `GitScope` supports history ranges, inclusive branch roots,
time bounds, snapshots, net diffs, staged index content and unreachable objects.
`since_hours` must be positive and fit in signed 64-bit seconds; scope bounds are
validated when constructing `GitScope`.
`GitInput.origins` retains author/committer identities, times, parents and messages
through extraction. Commit metadata is shared across origins, tree comparisons
skip unchanged subtrees, and payloads load lazily. `max_blob_size`, `max_commits`
and `max_inputs` bound Git work; missing objects raise errors unless explicit
`skip_missing_blobs=True` requests warning-and-skip behavior. Use `discover=False`
to require a repository root. Non-UTF-8 paths retain their bytes as `raw_path`.
Keep messages out of logs; they may contain credentials.

Commented examples: [detection](https://github.com/mongodb/kingfisher/blob/main/python/examples/detection.py),
[SQLite/bytecode](https://github.com/mongodb/kingfisher/blob/main/python/examples/content.py),
and [Git scopes](https://github.com/mongodb/kingfisher/blob/main/python/examples/git_scopes.py).
See the [SDK guide](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md#select-git-scopes-and-retain-provenance)
for scope semantics, extraction limits, WAL handling and controls.

## Compose enumeration and archive scanning

```python
from itertools import chain
from kingfisher_sdk import Scanner, filesystem, git_history, expand_archives

inputs = chain(filesystem(["./repo"]), git_history("./repo", refs=["HEAD"]))
for result in Scanner().scan_inputs(expand_archives(inputs, depth=2)):
    for finding in result.findings:
        if finding.visible:
            print(result.input.path, result.input.commit, finding.to_dict())
```

Supply your own Python enumerator with `ScanInput.from_file(path)` or
`ScanInput(path="config.txt", data=blob_bytes, commit=commit_hex)` instead of either
native iterator. Both use the same scanner and archive transform. Native Git runs
without a Git executable and enumerates reachable file versions, including merge
parents; filesystem enumeration honors local ignore files and skips symlinks.
Archive expansion shares CLI extractors, with explicit depth and per-root budgets.
Repeated TAR member names retain each occurrence's bytes. The byte budget also caps
intermediate decompressed streams (including TAR headers/padding); exhaustion
raises before any members from that root are yielded.
Shared extractors skip unsafe/unreadable entries and enforce format limits, so
coverage is best effort. `scan()` and `scan_file()` keep their existing behavior.
Each `ScanResult` retains its source and complete findings for separate validation.

See the [input API guide](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md#compose-filesystem-git-history-and-archives)
for formats, metadata, limits and cooperative controls, and the
[composable example](https://github.com/mongodb/kingfisher/blob/main/python/examples/inputs.py)
for `--filesystem-enumerator python` or `engine` workflows. The commented
[Git-history example](https://github.com/mongodb/kingfisher/blob/main/python/examples/git_history.py)
lets callers choose native traversal or a Python adapter using Git subprocesses;
only the latter requires Git on `PATH`. The
[archive example](https://github.com/mongodb/kingfisher/blob/main/python/examples/archives.py)
creates synthetic nested ZIPs and compares file/byte inputs, depth and budgets:

```bash
uv run --no-sync python python/examples/git_history.py ./repo --enumerator engine --all-refs
uv run --no-sync python python/examples/git_history.py ./repo --enumerator python --ref HEAD
uv run --no-sync python python/examples/archives.py --source bytes --depth 2
uv run --no-sync python python/examples/archives.py --source file --depth 1
```

Download `demo.yml` beside `archives.py` when running outside a checkout. These
examples report redacted results; validation remains a separate explicit stage.

## Scan timeouts and cancellation

```python
from kingfisher_sdk import CancellationToken, Scanner

scanner = Scanner()
cancellation = CancellationToken()
findings = scanner.scan("text to inspect", timeout=2.0, cancellation=cancellation)
# Another thread can call cancellation.cancel() while scanning runs.
```

`scan_file` accepts the same keyword arguments. Timeout values must be finite,
positive seconds; omit `timeout` for unlimited execution. An interrupted scan
raises `TimeoutError` for an expired deadline or `RuntimeError` for cancellation,
without partial findings or a dedup-cache entry. Tokens remain cancelled; create
a new token for new work.

These controls are cooperative. Checks run between matching/filtering operations,
in native match callbacks and during Base64 enumeration. File reads, decoding,
rule compilation and individual native operations cannot be preempted. Python
releases the GIL during scanning, allowing another thread to signal cancellation.
Use a separate process when a hard wall-clock execution limit is required.

## Validate explicitly

```python
from kingfisher_sdk import Scanner, Validator

findings = Scanner().scan_file("application.conf")
for result in Validator(timeout=10, concurrency=4).validate(findings, timeout=30):
    if result.finding.visible:
        print(result.to_dict())
```

Scanning is offline. Validation may contact providers using detected credentials.
Keep the complete scan result, including invisible supporting findings, until
validation finishes. Report redacted results; do not log `finding.secret`.

Revocation is available through `Revoker.revoke()` and requires `confirm=True`.
It can disable or delete real credentials. The
[local lifecycle example](https://github.com/mongodb/kingfisher/blob/main/python/examples/local_workflow.py)
demonstrates detection, validation and revocation against a loopback mock with a
synthetic credential. Blocking SDK operations release the GIL; use
`asyncio.to_thread` in async applications.

## Documentation and examples

- [Python guide on GitHub](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md):
  API reference, custom YAML/TOML rules, validation outcomes, revocation, local
  `uv` builds and tests, supported platforms, and publishing.
- [Runnable Python examples](https://github.com/mongodb/kingfisher/tree/main/python/examples):
  offline scans, filesystem/Git enumeration, nested archives, live validation,
  explicit revocation and a safe local lifecycle.
- [Kingfisher repository](https://github.com/mongodb/kingfisher): source, project
  documentation, CLI features and contributions.
- [Report an issue](https://github.com/mongodb/kingfisher/issues).

For a source checkout, build and run the local example from the repository root:

```bash
uv sync --locked --no-install-project
uv run --no-sync maturin develop --locked --profile dev
uv run --no-sync python python/examples/local_workflow.py
```

For a downloaded example and a published package, use:

```bash
uv run --no-project --with kingfisher-secret-scanner python local_workflow.py
```

Download `demo.yml` beside `local_workflow.py`; the example loads that synthetic
rule by its location. Source archives include the examples and fixture together.

Provider calls also accept an optional total deadline and `CancellationToken`:
`validator.validate(findings, timeout=30, cancellation=token)` and
`revoker.revoke(..., confirm=True, timeout=10, cancellation=token)`. They check
Ctrl-C while waiting, raise errors without partial batch results, and add no
retries. Interruption cannot undo a revocation already applied by the provider.

Archive/content transforms validate depth and byte/entry options on call while
consuming inputs lazily. Archive `max_bytes` caps cumulative extracted output;
the root input has an independent cap of the same size. Buffers and Python-byte
copies can coexist, so this is not a total memory limit. Entry accounting follows
the format: TAR/ZIP include directories, ASAR counts indexed files, and HWP counts
streams. `filesystem(max_file_size=...)` silently skips oversized files.
