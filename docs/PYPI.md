# Kingfisher Secret Scanner for Python

The `kingfisher-secret-scanner` PyPI package provides native Python secret detection,
credential validation and revocation. Install it with `uv add kingfisher-secret-scanner`;
import it as `kingfisher_sdk` (the distribution and import names differ).
See the [Kingfisher GitHub repository](https://github.com/mongodb/kingfisher)
for the full project, source code and broader CLI capabilities.

Kingfisher has two independent Python distributions:

| Distribution | Import / command | Purpose |
| --- | --- | --- |
| `kingfisher-secret-scanner` | `import kingfisher_sdk` | Native, in-process bindings to the Rust core, rules, scanner, validation and revocation code |
| `kingfisher-bin` | `uvx kingfisher-bin` / `kingfisher` | Existing packaged CLI; full repository, archive and remote-source enumeration |

They can be installed together without module or entry-point conflicts. The SDK
requires CPython 3.10+ with the standard GIL build. Wheels target Linux x64/ARM64
(glibc 2.28+), macOS x64/ARM64 (11+), and native Windows x64/ARM64. PyPy,
free-threaded Python and musl wheels are not currently part of the release matrix.

The prepared SDK release is **1.3.0**, including opt-in CLI detection policies,
SQLite/bytecode extraction, richer Git scopes and metadata, composable input
enumeration, per-call controls, a reusable compiled rule cache and `Rules.detail()` inspection. Its version is independent of the CLI and Rust library packages; Python modules share the SDK version.

## Install and scan

```bash
uv init my-scanner
cd my-scanner
uv add kingfisher-secret-scanner
```

```python
from kingfisher_sdk import Scanner

scanner = Scanner()  # Compile the embedded catalog once and reuse it.
for finding in scanner.scan("text to inspect"):
    if finding.visible:
        print(finding.to_dict())  # Redacts the secret and all captures.
```

Scanning is offline. `scan(str | bytes)` scans a buffer; `scan_file(path)` scans
one file with path-aware filters. For directories, local Git history and archives,
compose the input APIs below. The SDK does not fetch repositories or enumerate
cloud sources; supply their content from Python or use the CLI.

## API modules

| Module | Public API |
| --- | --- |
| `kingfisher_sdk.core` | `Finding`, `shannon_entropy(bytes)` |
| `kingfisher_sdk.rules` | `Rules(paths=(), builtins=True, confidence="medium", cache=True, cache_dir=None)` |
| `kingfisher_sdk.scanner` | `Scanner(rules=None, base64=True, dedup=False, redact=False, min_entropy=None, policy=None)`, `DetectionPolicy`, `DetectionScanner`, `CancellationToken`, `ScanResult` |
| `kingfisher_sdk.inputs` | `ScanInput`, `filesystem`, `git_history`, `expand_archives`, `expand_content` |
| `kingfisher_sdk.git` | `GitScope`, `GitInput`, `GitCommit`, `GitSignature`, `GitInputWarning`, `git_inputs` |
| `kingfisher_sdk.validation` | `Validator`, `ValidationResult` |
| `kingfisher_sdk.revocation` | `Revoker`, `RevocationResult` |

These names are also exported from `kingfisher_sdk`. `GitInputWarning` supports
standard Python warning policies for explicitly skipped Git blobs. Python modules wrap one
PyO3 extension, sharing the Rust types and compiled rule database. Official wheels
enable all scanner validator features, including HTTP, Betterleaks expressions,
gRPC, raw/provider-specific validators, AWS, Azure, Coinbase, GCP, JWT, databases
and local Ethereum key derivation.

`Rules` accepts files and directories containing Kingfisher YAML and Betterleaks
TOML. Custom TOML IDs receive the `custom.` prefix. Use `builtins=False` for
custom-only rules. `Rules.metadata()` lists exact IDs, names, visibility and
whether each rule has validation/revocation. `Rules.detail(exact_id)` returns the
loaded definition, including the regex, filters, dependencies and configured
validation/revocation logic. Unknown or unloaded IDs raise `ValueError`.

```python
from kingfisher_sdk import Rules, Scanner

rules = Rules(["company.yml", "team.toml"], builtins=False)
scanner = Scanner(rules, dedup=True)
findings = scanner.scan_file("application.conf")
scanner.reset_dedup()
```

`Finding.rule_id`, `.visible` and `.secret` expose the matching ID, visibility and
raw secret. Additional native properties expose `.rule_name`, `.confidence`,
`.entropy`, `.fingerprint`, `.captures`, `.blob_id`, `.is_base64_encoded` and
`.location` without serializing the whole finding. Dictionary properties return
copies. `to_dict()` contains the same fields and redacts credentials and captures. Location offsets are bytes,
the end is exclusive, lines start at 1 and columns start at 0. UTF-16/32 inputs
may be normalized before scanning. `to_dict(redact=False)` explicitly exposes
secret material. Repr omits credentials. Redaction does not erase earlier copies.
Redacted reports retain fingerprint, entropy and content identity for correlation;
these can disclose information about guessable secrets or inputs, so control report
access as carefully as other security findings.

## Reuse the compiled rule cache

`Rules()` and the default `Scanner()` now read and write the same compiled
Vectorscan cache as the CLI. Previously, every `Rules()` construction recompiled
the content database. Explicit `cache_dir` takes precedence over
`KF_RULE_CACHE_DIR`; otherwise the [platform cache directory](ADVANCED.md#compiled-rule-cache)
is used. Paths accept strings or `Path` objects. `cache=False` bypasses both reads
and writes, even when a directory or environment variable is supplied.

```python
from pathlib import Path
from kingfisher_sdk import Rules, Scanner

# Run during image construction to populate the cache; use the same rules,
# confidence and directory at service startup, then reuse the Scanner.
# Prewarm as the service account so the runtime user owns the cache files.
rules = Rules(confidence="medium", cache_dir=Path("rule-cache"))
scanner = Scanner(rules)

# Opt out of disk caching for an embedding that needs no persistent state.
uncached = Scanner(Rules(cache=False))
```

CLI prewarming also works: `kingfisher rules compile-cache --confidence medium
--rule-cache-dir rule-cache` prepares the same entry when the resolved rules and
engine build match. Entries require compatible architecture, pointer width and
endianness, the pinned binding versions and the exact native engine build identity.
Transfer within a deployment using the same wheel/build; another operating system
or engine build can require recompilation. Vectorscan checks native version and
CPU-feature compatibility on load. Missing, stale, corrupt or rejected databases
are recompiled on the receiving host; writes are best effort, so a read-only or
unavailable cache does not prevent scanning. The new cache format causes a one-time
recompile of older entries. Architecture changes also require recompilation.
For containers, prewarm as the runtime account or transfer ownership before
deployment; a root-owned cache is bypassed by an unprivileged runtime user.
The builder's account, username and UID are not recorded in the cache key or
serialized database. Ownership checks apply to the files on the receiving host,
so deployment on a different host does not require the builder's account there.
Custom external or patched engine builds that preserve their version/build string
should use separate cache directories or `cache=False`.

Only the main Vectorscan content database is persisted. Rule loading, confirmation
regexes and collection-level path/finding filters still initialize each time;
keep one `Rules`/`Scanner` per process to reuse those resources.
`rules.cache_status` is `loaded`, `stored` or `bypassed`, allowing applications
to verify prewarming without logging rule contents. The cache stores
compiled rule patterns and metadata, not findings or scanned content. No automatic
cache pruning runs in the SDK; use the CLI's `rules prune-cache` when needed.

Cache directories must be trusted: serialized Vectorscan databases are native
engine input. The default never falls back to shared system temporary storage; if
no user cache directory is available, caching is disabled. Unix cache directories
are created privately and untrusted ownership, permissions or symlinks disable
caching. Windows cache directories/files must belong to the current user; write
permissions may also include Administrators/SYSTEM. New directories and entries
explicitly receive the process user SID as owner, including for SYSTEM services;
existing paths must meet the same ownership checks. Protected ancestors may
additionally be owned or maintained by TrustedInstaller, without allowing other
accounts to replace the cache. A SHA-256 payload check catches corruption before
native deserialization; it does not authenticate data supplied by someone with
the same account privileges.

See the commented [cache example](../python/examples/rule_cache.py).

### Prewarm a container image for a non-root service

The commented [Dockerfile](../python/examples/rule_cache.Dockerfile) implements
the image-build/deploy workflow from [issue #538](https://github.com/mongodb/kingfisher/issues/538).
It installs one compatible SDK wheel, compiles the built-in medium-confidence
catalog as root, then uses `COPY --chown=10001:10001` to give the runtime service
ownership of the cache directory **and every entry**. It explicitly creates the
destination as that UID with mode 0700; copied files retain mode 0600.
Root-owned, non-writable parent
directories are supported. Changing only the directory owner is insufficient.

Build from the repository root, supplying a repaired Linux wheel matching the
image architecture and Python ABI in `dist-python/`. The example's Docker ignore
file excludes repository history and build outputs from the context.
Deploy the resulting image unchanged so build
and startup use the same engine:

```bash
# Set this to the wheel downloaded or built for your Linux image architecture.
SDK_WHEEL=dist-python/your-compatible-wheel.whl
docker build -f python/examples/rule_cache.Dockerfile \
  --build-arg SDK_WHEEL="$SDK_WHEEL" \
  -t kingfisher-cache-demo .
docker run --rm kingfisher-cache-demo
# On a compatible host, require reuse without recompilation or cache writes:
docker run --rm --read-only kingfisher-cache-demo --require-hit
```

The example uses a fixed numeric runtime UID/GID, which travels with the image;
no matching host username is needed. For a single-stage build, prewarm after
switching `USER`, or run `chown -R <runtime-uid>:<runtime-gid> <cache-dir>` before
switching users. For bind mounts or arbitrary runtime UIDs, provision both the
directory and files for the actual container UID (including user-namespace
mapping), and prevent other accounts from modifying or replacing them.

A valid entry can load from a read-only filesystem. On an incompatible CPU,
normal startup recompiles in memory and continues scanning. Persistence requires
a writable, trusted cache; a read-only image cannot retain the replacement for
the next process. `--require-hit` is a deployment check for known compatible
hosts, rather than the normal startup policy. Keep `Rules(confidence="medium")`
and one reusable `Scanner` per process, as shown in the example.

## Inspect the bundled rules and their logic

```python
import json
from kingfisher_sdk import Rules

rules = Rules(confidence="low")  # Include the full catalog, including helper rules.
for summary in rules.metadata():
    if summary["revocation"]:
        print(summary["id"], summary["name"])

# Use an exact ID from metadata(); custom TOML IDs start with "custom.".
rule_id = "betterleaks.aws-access-token"
detail = rules.detail(rule_id)
print(detail["pattern"])          # Stored pattern, including any rule comments.
print(detail["detection_regex"])  # Compiled Rust confirmation regex, comments removed.
print(json.dumps(detail["validation"], indent=2))
print(json.dumps(detail["revocation"], indent=2))
print(json.dumps(detail["depends_on_rule"], indent=2))
```

`detail()` includes the rule's name/ID, confidence, visibility, entropy threshold,
path predicate, capture selection, Betterleaks filter, pattern requirements,
dependencies, examples, references, TLS mode and validation/revocation definitions.
The returned dictionary is a copy; changing it does not alter loaded rules.
`detection_regex` is the compiled confirmation pattern, excluding the internal
endpoint wrapper. A regex match is only a candidate: selected captures still
pass the detector's filters and dependency requirements.

Missing validation/revocation is `None`. HTTP/gRPC definitions expose configured
requests and response matchers; Betterleaks validation exposes its portable
expression tree, component bindings and operational capabilities. Original
Betterleaks expression text may be absent in release builds. Typed validators
such as AWS/JWT and raw validators expose their dispatch type/name; their Rust
implementation code is not embedded as inspectable Python text. Configuration
presence alone does not establish authoritative live validation or successful
revocation.

Inspection is offline and performs no validation or revocation. The output is
rule configuration, without finding redaction; literals supplied in custom rules
are returned as configured.

The [rule inspection example](../python/examples/rules.py) lists the catalog,
filters by ID glob or configured capabilities, and displays full details or
selected fields:

```bash
uv run --no-sync python python/examples/rules.py --with-validation --with-revocation
uv run --no-sync python python/examples/rules.py --id-glob 'betterleaks.aws*'
uv run --no-sync python python/examples/rules.py betterleaks.aws-access-token --field pattern --field validation --field revocation
uv run --no-sync python python/examples/rules.py acme.python-demo --rules-path python/examples/demo.yml --no-builtins
```

## Choose detection and reporting filters

Detection settings change which candidates can become findings. Reporting
predicates select from completed findings and do not save matching work.

| Setting | Effect |
| --- | --- |
| `Rules(confidence="high")` | Load only rules meeting this minimum confidence; confidence is rule metadata, not live validity |
| `Rules(["company.yml"], builtins=False)` | Scan a focused custom catalog; `metadata()` lists its exact IDs and supported actions |
| `Rules(cache_dir="rule-cache")` | Override the compiled rule cache directory; takes precedence over `KF_RULE_CACHE_DIR` |
| `Rules(cache=False)` | Disable compiled rule cache reads and writes |
| `Scanner(base64=False)` | Skip decoding/scanning Base64 strings |
| `Scanner(min_entropy=4.0)` | **Override every rule's entropy threshold**; a lower value can admit extra candidates, so normally retain rule defaults |
| `Scanner(dedup=True)` | Suppress subsequent successful scans of the same content and source path until `reset_dedup()`; this is not secret-level deduplication across files |
| Python path selection | Skip inputs before calling `scan_file`; use `Path.expanduser()` for `~` |

For selective output, retain findings and apply Python predicates to their
redacted dictionaries. Serialize once per finding rather than repeatedly
building report dictionaries. Native scalar properties are inexpensive; use
`finding.rule_id` or `finding.entropy` for filters before creating a report.

```python
from fnmatch import fnmatchcase
from kingfisher_sdk import Scanner

scanner = Scanner()
findings = scanner.scan_file("application.conf")
for finding in findings:
    if not finding.visible:
        continue  # Hide component helpers in reports; retain them for validation.
    data = finding.to_dict()
    if not fnmatchcase(data["rule_id"], "betterleaks.*"):
        continue
    if data["entropy"] < 3.5:
        continue  # Report filter; does not override the detector's own threshold.
    print(data)
```

Other predicates can use any of these fields:

| Field / property | Example predicate |
| --- | --- |
| `finding.visible` | Report primary findings only |
| `data["rule_id"]`, `data["rule_name"]` | Exact ID set membership, `fnmatchcase` globs, or name substring |
| `data["confidence"]` | `== "high"` (`low`, `medium`, `high`) |
| `data["entropy"]` | `>= 3.5` (bits per byte); a report cutoff can hide valid low-entropy credentials |
| `data["is_base64_encoded"]` | `True` to report only decoded findings |
| `data["location"]` | `data["location"]["line"] >= 10`, byte ranges, or columns; decoded content may have normalized offsets |
| `data["fingerprint"]` | An occurrence allowlist/key `(rule_id, fingerprint)`; includes value, blob identity and offsets, so repeated secrets can have different fingerprints |
| `data["blob_id"]` | Group findings from one input's content |
| `data["captures"]` | Check capture-name presence; values are redacted by default |

Paths are supplied to `scan_file` for native rule filters but are not stored in
`Finding`; retain the path alongside your findings. Raw-value predicates require
explicit `finding.secret` or `to_dict(redact=False)` access; keep those values out
of reports. For format/context constraints that should run during detection, use
custom rule entropy, pattern requirements and filters as described in
[RULES.md](RULES.md).

Apply report predicates **after validation**, preserving the complete list from
one input. `ValidationResult` additionally supports predicates on `.outcome`,
`.http_status` and `.reason`, for example `result.outcome == "verified_active"`.
The runnable validation example supports repeated `--outcome` and `--rule`
report selectors; these do not prevent provider requests for other findings.

## Comparing SDK and CLI results

The SDK and CLI share native detection primitives, but their surrounding pipelines
are different. A recursive Python scan is not automatically equivalent to
`kingfisher scan ~/example-repo`:

- The SDK can enumerate filesystem inputs, reachable Git history and archives
  explicitly through its input APIs. These do not read CLI configuration or
  apply CLI configuration or every exclusion policy. `git_inputs()` exposes explicit history, snapshot, diff and staged scopes. `scan.py` walks the current directory
  tree, skips `.git`, `.venv`, `node_modules` and symlink entries, and supports
  relative path globs; it does not read `.gitignore` or CLI configuration.
- Use `scan_file(path)` to preserve path-aware rule/filter behavior. `scan(bytes)`
  has no source path, which can change matching and filtering.
- Use `DetectionScanner` to opt into shared CLI matching windows, bounded
  nested Base64 decoding, inline-ignore directives and HTML/CSS parser checks. Existing `Scanner` defaults stay unchanged.
- SDK scanning is offline. CLI scanning normally also validates credentials;
  use `--no-validate` when comparing detection alone.
- The SDK returns invisible component helpers and defaults to deduplication off.
  Compare only visible findings, and use CLI `--no-dedup` to compare occurrences.

For a closer CLI comparison of working-tree detection, start with:

```bash
kingfisher scan ~/example-repo --git-history none --no-extract-archives --no-validate --no-dedup --no-update-check --format toon
```

Then align the exact file list, rules/catalog version, confidence and Base64
settings. Compare rule IDs, source paths and locations rather than raw counts or redacted
text. SDK fingerprints include blob identity and offsets; CLI fingerprints use
source origin, so do not expect cross-interface fingerprint equality. If comparing
credential values, compute keyed digests internally without printing raw values. Use `DetectionScanner` and align its matching, decoding and context settings as well. Enumeration,
validation and reporting differences can still change results.

## Compose filesystem, Git history and archives

Existing `scan()` and `scan_file()` signatures and behavior are unchanged: neither
method enumerates inputs or automatically extracts archives. Use the new input
layer to choose each stage independently:

```python
from itertools import chain
from kingfisher_sdk import Scanner, filesystem, git_history, expand_archives

sources = chain(filesystem(["./repo"]), git_history("./repo", refs=["HEAD"]))
scanner = Scanner()
for result in scanner.scan_inputs(expand_archives(sources, depth=2)):
    for finding in result.findings:
        if finding.visible:
            print(result.input.path, result.input.commit, finding.to_dict())
```

All engine enumeration runs offline and in-process. Native Git enumeration does
not require a Git executable or modify the checkout. Enumeration is separate from
scanning; filter or combine iterators using ordinary Python. To enumerate the
filesystem yourself, replace `filesystem()` with your own iterator:

```python
from pathlib import Path
from kingfisher_sdk import ScanInput

sources = (ScanInput.from_file(path) for path in Path("./repo").rglob("*.conf")
           if path.is_file() and not path.is_symlink())
results = scanner.scan_inputs(expand_archives(sources))
```

For Git enumeration in Python, adapt your Git library's file versions to
`ScanInput(path="config.txt", data=blob_bytes, repository="./repo",
commit=commit_hex, blob_id=blob_hex)`. Both kinds of input use the same scanner and
archive transform. `scanner.scan_input(source)` also scans just one input and
returns the existing `list[Finding]` type. Use `ScanInput` with bytes to preserve
logical paths when scanning remote or historical content; `scan(bytes)` continues
to have no source path.

| Stage | Behavior |
| --- | --- |
| `ScanInput.from_file(path)` | Defers file reads until scanning/expansion; file paths must be strings or `PathLike[str]` |
| `filesystem(roots, gitignore=True, hidden=False, max_file_size=None)` | Enumerates regular files; skips symlinks and `.git`; honors local Git/ignore files, but not global Git excludes or CLI configuration |
| `git_history(path, refs=("HEAD",))` | Visits reachable commits including merge parents and shallow boundaries; supports bare repositories; emits each `(path, blob ID)` once; excludes working-tree changes, symlinks, submodules and unreachable objects |
| `expand_archives(inputs, depth=1, max_bytes=268435456, max_entries=10000)` | Uses shared CLI extractors for ZIP/ZIP-based formats, TAR, gzip/bzip2/xz and compressed TAR, zlib, ASAR and HWP; ZIP signatures detect containers without an extension |
| `scanner.scan_inputs(inputs)` | Lazily yields `ScanResult(input, findings)` per input, including empty groups; retains invisible helpers for validation |

Pass `refs=None` to enumerate all refs plus HEAD, including branches outside
HEAD ancestry. Git paths are repository-relative strings; invalid UTF-8 is
represented lossily, with the original bytes in `GitInput.raw_path`. `input.commit` is one encountered
occurrence, not necessarily the first introduction; enumeration order is unspecified.
After archive expansion, Git metadata still identifies the original container blob,
while each finding's blob ID identifies its scanned content. Archive paths use
`outer.zip!member`; single compressed streams use `outer.gz!content`. Repeated ZIP/TAR
member names produce separate inputs with the same logical path and their own
bytes. Depth 0
keeps containers raw; maximum depth is 32. Unsafe entry paths are skipped and
extraction uses temporary directories under optional `temp_dir`
(default system temporary storage). Choose a protected `temp_dir` parent on every
platform. SDK staging directories use owner-only Unix mode 0700, which the umask
may restrict further; Windows inherits the parent DACL. Small ZIPs decode in memory.
Cleanup is attempted on completion; temporary plaintext may survive a crash or
cleanup failure. Applications can select encrypted or memory-backed storage.
Expansion is best effort: shared
extractors also skip unreadable entries and enforce their own per-format limits.
It is not a guarantee of complete archive coverage.

`filesystem(max_file_size=...)` silently skips oversized files and does not emit
`GitInputWarning`; Git blob-size skips are reported explicitly.

Filesystem and Git iterators accept `timeout` and `cancellation`. Their deadlines
cover iterator lifetime, including consumer time. `expand_archives` accepts the
same controls and expands one root fully before yielding its members; timeout and
byte/entry budgets apply per root, cumulatively across nested layers. Entry
budgets count inspected members, including unsafe paths; TAR/ZIP also count directories,
ASAR counts indexed files, and HWP counts streams. Normal
inputs become byte inputs and are subject to `max_bytes` too. These budgets bound
returned content and cap extraction streams with the remaining budget, including
compressed TAR headers and padding. Nested layers share one byte/entry budget;
limits are enforced while writing, before another layer is materialized. Stream-cap exhaustion raises a
budget error before any members from that root are yielded. Temporary extraction
also has the engine's independent limits. The root input is independently capped at
`max_bytes` and is not debited from the cumulative output budget. Root and output
buffers can coexist, and conversion to Python bytes creates transient copies;
`max_bytes` is not a bound on total process memory. Invalid depth and byte/entry
options are rejected when calling the transform, before iterating inputs.
`scan_inputs` accepts the same scan controls, with timeout applying per input.
Errors propagate, including filesystem errors, unresolved refs and archive
failures. Already-yielded scan groups remain with the caller; the failed input
never returns partial findings. Individual reads/extractions remain cooperative.

For validation, call `validator.validate(result.findings)` separately for each
group, then filter visible results for reporting. Composing filesystem and Git
history can include the same content twice; `Scanner(dedup=True)` suppresses repeat
successful scans of identical content at the same source path, rather than
credential values across different paths.

The commented example scripts demonstrate these choices separately:

```bash
# Let Python select filesystem inputs, then use native archive expansion.
uv run --no-sync python python/examples/inputs.py ./repo --filesystem-enumerator python --archive-depth 2

# Native history needs no Git executable; --all-refs includes all refs plus HEAD.
uv run --no-sync python python/examples/git_history.py ./repo --enumerator engine --all-refs

# The example Python adapter uses Git subprocesses; replace it with your Git library.
uv run --no-sync python python/examples/git_history.py ./repo --enumerator python --ref HEAD

# Self-contained synthetic archive demo: compare byte/file inputs and nested depth.
uv run --no-sync python python/examples/archives.py --source bytes --depth 2
uv run --no-sync python python/examples/archives.py --source file --depth 1
```

The Python filesystem example defines its own path policy rather than parsing
`.gitignore`; choose `--filesystem-enumerator engine` for native ignore handling.
The Python Git example requires Git on `PATH` and produces the same `ScanInput`
shape as native enumeration. It demonstrates `(path, blob ID)` deduplication,
regular-file selection, reachable refs and preservation of commit metadata.
The archive demo loads `demo.yml` beside the script, creates only synthetic ZIP
fixtures, and shows per-root extraction budgets and separate per-input scan
controls. Download that fixture with the script when running outside a checkout.
At depth 0 it scans the raw outer ZIP; depth 1 reaches the nested ZIP bytes;
depth 2 reaches the inner configuration file and its synthetic finding.
All three scripts report redacted output and leave validation explicit.

## Opt-in CLI detection policies

`Scanner(policy=DetectionPolicy(...))` opts into CLI matching, bounded nested
Base64 decoding, inline-ignore and HTML/CSS context policies. `DetectionPolicy`
is frozen; iterable ignore markers are copied into a tuple, so a policy can be
reused across scanners and threads. All settings are applied at construction.
`DetectionScanner` remains a compatibility facade over the same policy. It inherits `scan()`, `scan_file()`, `scan_input()`, `scan_inputs()` and
`reset_dedup()`, with the same findings and interruption contracts. Existing
`Scanner` default behavior remains unchanged when no policy is supplied.

```python
from kingfisher_sdk import DetectionPolicy, Scanner, ScanInput

policy = DetectionPolicy(ignore_comments=("acme:ignore",))
scanner = Scanner(policy=policy)
findings = scanner.scan_input(ScanInput("config.html", html_bytes))
```

`inline_ignores=True` recognizes `kingfisher:ignore` and optional case-insensitive
`ignore_comments` markers, including the CLI's adjacent-line and multiline
rules. `markup_context=True` verifies ambiguous candidates in HTML attributes,
visible text, script/style bodies and CSS values. Self-identifying credential
formats and Base64 candidates bypass the markup gate, as in the CLI. Language
inference uses the shared content inspector and logical path; pass
`language="html"` or `"css"` to override it for bytes or extensionless sources.
Structural checks are bounded to 2 MiB; larger inputs and secrets containing
invalid UTF-8 retain candidates because the parsers cannot faithfully verify them.

`cli_match_semantics=True` uses the CLI's 4 KiB initial confirmation windows,
full-match component anchors, per-rule secret containment checks, and overlapping
Betterleaks credential-URI fallback suppression. This can change findings compared
with `Scanner`, including offsets in long fixed-width runs. Set it to `False` to
retain legacy SDK matching while choosing the context and Base64 policies separately.
Reported secret locations and the `Finding` serialization shape stay unchanged.

`base64_max_depth=2` enables two decoding layers. `base64_max_input_bytes=64 * 1024 * 1024`
skips Base64 decoding above a 64 MiB original-input limit; raw matching still runs.
Depth zero disables the pass; `base64=False` also disables it. Use a different
nonnegative depth or `base64_max_input_bytes=None` explicitly to change those limits.
Nested findings identify the outer encoded region. `Scanner` keeps its existing
one-layer, uncapped Base64 default.

Choose context policies independently with `inline_ignores=False` or
`markup_context=False`. Inline-ignore and containment checks run before markup
verification, then component requirements, URI fallback suppression, catalog
deduplication and redaction. Keep invisible helper findings in
one input's group for validation. Detection parity requires matching input lists,
catalogs, confidence, entropy and Base64 settings; CLI source selection, validation,
reporting and fingerprints still have their own contracts.

See the commented [detection example](../python/examples/detection.py):

```bash
uv run --no-sync python python/examples/detection.py
```

## Extract SQLite and Python bytecode

`expand_content()` is an explicit input transform using the same native SQLite
and `.pyc` extractors as the CLI. It works with file inputs, historical blobs,
caller-supplied bytes and archive members:

```python
from kingfisher_sdk import DetectionScanner, ScanInput, expand_archives, expand_content

sources = expand_content(expand_archives([ScanInput.from_file("backup.zip")], depth=2))
for result in DetectionScanner().scan_inputs(sources):
    for finding in result.findings:
        if finding.visible:
            print(result.input.path, finding.to_dict())
```

SQLite is recognized by its file signature and exported as SQL per user table,
including schema and named-column inserts. Paths use `database.db!table.sql`.
The extractor reads a separate staged copy without modifying the database. Checkpoint or
export live SQLite databases before scanning: writes existing only in a separate
WAL are not part of the input bytes. BLOB values are represented as SQL hex.
`.pyc` inputs are selected by extension; the shared magic/version-aware marshal
parser extracts strings and nested code constants without importing or executing
Python. Paths use `module.pyc!strings.py`. Offsets and finding blob IDs refer to
extracted text; source repository, original blob and Git provenance are preserved.

`sqlite=False` and `pyc=False` disable the formats separately. Ordinary inputs,
empty databases and unsupported bytecode pass through unchanged. Malformed inputs
fall back to raw scanning with `input.extraction_error` set to `malformed_sqlite`
or `malformed_pyc`; `strict=True` propagates parser errors. Diagnostic categories
exclude potentially sensitive parser messages. Budgets and cancellation never
fall back to raw content or return partial extracted input.

`max_bytes` (default 256 MiB) caps recognized input and total generated text.
Output is bounded while extracting; exceeding it raises an error. Shared caps
also limit SQL output to 256 MiB, bytecode output to 64 MiB and SQLite work to
100,000 rows per table. Bytecode structural safety limits raise budget errors,
so deeply nested or oversized advertised collections cannot silently fall back. SQLite opens the staged snapshot read-only, enables defensive
mode, disables trusted schema expressions, and limits native lengths/columns.
Its VM progress handler checks deadlines/cancellation; bytecode parsing checks
controls too. `timeout` applies per input. Native reads and individual operations
remain cooperative; members are prepared completely before yielding.

Bytecode and small ZIP extraction operate in memory. SQLite uses temporary
storage under `temp_dir` (the system temporary directory by default). Choose a
protected `temp_dir` parent on every platform. SDK staging directories use
owner-only Unix mode 0700, which the umask may restrict further; Windows inherits
the parent DACL.
Cleanup is attempted on completion. Staging may survive a process crash or cleanup
failure, so select encrypted or memory-backed storage if needed.
`Scanner.scan_file()` continues to scan container bytes directly.

See the commented [content extraction example](../python/examples/content.py),
which builds a synthetic archive containing both formats:

```bash
uv run --no-sync python python/examples/content.py
```

## Select Git scopes and retain provenance

Use `git_inputs(repository, scope=GitScope(...))` for richer native enumeration.
`git_history()` is a thin history facade over the same shared native enumerator
and preserves its file-version contract; it accepts the same resource options.
Both accept Python-controlled filtering and compose with the same extractors and
scanners. Neither requires a Git executable, network or checkout writes.

```python
from kingfisher_sdk import DetectionScanner, GitScope, git_inputs, expand_archives, expand_content

sources = git_inputs("./repo", scope=GitScope(refs=("HEAD",), since_commit="main"))
for result in DetectionScanner().scan_inputs(expand_content(expand_archives(sources))):
    for origin in result.input.origins:
        print(origin.id, origin.author.name, origin.committer.timestamp)
    # Keep full findings together for validation; report visible findings only.
```

| Scope | Selected content |
| --- | --- |
| `GitScope()` | Changed regular-file versions across HEAD ancestry, visiting all merge parents and comparing each commit against its first parent |
| `GitScope(refs=None)` | History from all refs plus HEAD |
| `GitScope(since_commit="main", refs=("HEAD",))` | Exclude the baseline and its ancestors; keep intermediate versions, even when deleted before HEAD |
| `GitScope(branch_root="COMMIT", refs=("HEAD",))` | Include this reachable root and later history, excluding the root's ancestors |
| `GitScope(since_hours=24)` | Keep commits within the recent committer-time window, without pruning traversal on older timestamps |
| `GitScope(since_time=START, until_time=END)` | Inclusive committer Unix timestamp bounds; applied after traversal to handle clock skew |
| `GitScope(mode="snapshot", refs=("HEAD",))` | Every regular file at one selected commit |
| `GitScope(mode="diff", refs=("HEAD",), since_commit="main")` | Net changed target versions; deletions and intermediate versions are absent |
| `GitScope(mode="staged")` | Changed index blobs against HEAD (empty baseline before the first commit), excluding unstaged edits |
| `GitScope(mode="staged", since_commit="main")` | Changed index blobs against an explicit baseline |
| `GitScope(refs=None, include_unreachable=True)` | Unbounded history including stored unreachable commits and stored blobs without regular-file provenance |

`since_hours` must be positive and fit in signed 64-bit seconds after conversion
from hours. Invalid scope bounds are rejected when constructing `GitScope`.

`GitInput` extends `ScanInput` with `origins: tuple[GitCommit, ...]`, `staged` and
`unreachable`. A history origin records a selected change occurrence, not every
unchanged snapshot or guaranteed first-ever introduction. Reintroduced identical
content at the same path shares one input with multiple origins. Snapshot/diff
origins identify the target commit. Each commit exposes its ID, parent IDs,
message, and author/committer `GitSignature` (name, email, Unix timestamp and
`timezone_offset` in seconds east of UTC). Messages and identity emails are
excluded from `repr`; messages are original repository content and may contain
credentials. Commit metadata is shared across input origins rather than copied
for every changed file.

The inherited `input.commit` identifies one scoped occurrence. Staged inputs have
no commit or origins. Unassociated stored blobs use `@git/<object-id>`, no commit,
and `unreachable=None` because their reachability cannot be inferred from a
regular-file origin. `unreachable=False/True` describes whether an associated
version has a selected reachable change occurrence. Extraction preserves all
metadata through `dataclasses.replace()`; finding locations point into the member.

Descriptor/metadata preparation occurs before the first yield, uses memory
proportional to selected changes, and loads payloads lazily. `timeout` covers
preparation and the iterator's lifetime, including consumer time; `cancellation`
is cooperative. Tree comparisons skip identical subtree IDs, so history work
tracks changed paths rather than flattening every complete tree. Non-UTF-8 paths
retain their original bytes in `raw_path`. Use `max_commits` and `max_inputs` to
bound preparation (exhaustion raises an error); `max_blob_size` skips oversized
blobs with a warning before loading their payloads. Missing objects in partial
clones raise an error by default; `skip_missing_blobs=True` warns and continues
without acquiring objects from the network. Complete local objects are required
for full coverage.

By default `discover=True` searches parent directories for a repository; pass
`discover=False` to require the supplied path to be a repository root. Revision
arguments use Git revision syntax, including reflog expressions; they never
execute shell commands or fetch remote data. Bare repositories and shallow
boundaries are supported; shallow roots lack prior comparison content. Symlinks,
submodules and intent-to-add index entries are excluded. Staged scanning requires
a working repository and rejects conflicts and sparse indexes. No synthetic
commit, index refresh, checkout or ref update is performed. Invalid or conflicting
scope settings raise an error instead of widening the selection. In staged mode,
leave `refs` at its default and use `since_commit` to select the baseline.

See the commented [Git scopes example](../python/examples/git_scopes.py):

```bash
uv run --no-sync python python/examples/git_scopes.py ./repo --since-commit main
uv run --no-sync python python/examples/git_scopes.py ./repo --mode staged
uv run --no-sync python python/examples/git_scopes.py ./repo --mode diff --since-commit main
```

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
validator = Validator(timeout=10, concurrency=4)
for result in validator.validate(findings, timeout=30):  # Total batch deadline.
    if result.finding.visible:
        print(result.to_dict())
```

Keep the complete result list from one input, including invisible helper rules,
until validation finishes: the Rust validator associates multi-part credentials
using blob identity, encoding and proximity. Do not merge unrelated inputs into
one validation call. `Scanner(redact=True)` prevents subsequent validation;
retain raw findings internally and redact when reporting instead.

`Validator` accepts `timeout` (seconds), `concurrency`, `retries` (default 0),
`max_response_bytes` (default 1 MiB for YAML HTTP), `allow_internal_ips` (default
false) and `variables` (trusted template variables/endpoints). Response-size
limits for other validator families remain provider-specific. TLS verification
is enabled and the shared HTTP client disables redirects. The internal-address
check is not a network sandbox or DNS-pinning guarantee.

`validate(findings, timeout=None, cancellation=None)` adds a total batch deadline,
including queued checks, independently of the constructor's per-check timeout.
It checks Python signals while waiting on I/O, so Ctrl-C raises `KeyboardInterrupt`.
Timeout and cancellation raise `TimeoutError` and `RuntimeError` without partial
batch results. Cancelled I/O does not undo requests already submitted. Provider
operations reuse a process-wide Tokio runtime sized from available CPUs (2–32
workers); provider request concurrency is set on each `Validator`.

Results preserve input order and include `finding`, `outcome`, `reason` and
`http_status`. Outcomes are `verified_active`, `verified_inactive`, `unavailable`,
`skipped`, `not_attempted`, `assumed`, `locally_derived` and `invalid_material`.
An unavailable check is inconclusive; assumed validity and locally derived
cryptographic material are not proof of live account access. Provider responses
are intentionally omitted from the Python result.

## Revoke explicitly

```python
import os
from kingfisher_sdk import Revoker

result = Revoker().revoke(
    "betterleaks.aws-access-token",  # Select an exact ID with revocation support.
    os.environ["AWS_SECRET_ACCESS_KEY"],
    variables={"AKID": os.environ["AWS_ACCESS_KEY_ID"]},
    confirm=True,
)
print(result.revoked, result.http_status)
```

Check `Rules.metadata()` for the exact supported ID before calling. Revocation
can disable or delete real credentials. `confirm=True` is mandatory, rules are
matched exactly, and requests are not automatically retried. HTTP, multi-step
HTTP, AWS deactivation and GCP service-account key deletion run in-process through
`kingfisher-scanner::Revoker`, using the same execution helpers as the CLI. Only load trusted rules: revocation sends credentials to the
configured URLs, including private addresses. Pass supporting credentials and
endpoint variables explicitly; revocation does not infer them from scan results
or read the CLI configuration/environment. Variable names are uppercased; avoid
keys that differ only by case, since they resolve to the same variable. `TOKEN`
is always the explicit secret.

A `RevocationResult` contains `rule_id`, `revoked`, `http_status`; it never contains
provider bodies. Missing/unsupported rules and invalid configuration raise
`ValueError` or `RuntimeError`. A timeout or transport failure may occur after the
provider applied revocation: inspect provider state before retrying.
`revoke(..., timeout=None, cancellation=None)` also accepts an application
deadline/cancellation signal and responds to Ctrl-C. Interruption has the same
unknown-outcome risk and never triggers retries. Failure messages preserve safe
categories such as timeout, connection, HTTP status, response and I/O without
including credentials, endpoint URLs or provider bodies.

## Runnable examples

Run these from a checkout after the local setup below. Each link opens the full
program, and the example files are also included in the source distribution.

- [Rule catalog and definition inspection](../python/examples/rules.py):
  `uv run --no-sync python python/examples/rules.py --with-revocation`
  lists supported actions; pass an exact ID to inspect regex and configured logic.
- [Offline file/directory scanning](../python/examples/scan.py):
  `uv run --no-sync python python/examples/scan.py ~/example-repo --timeout 5 --unique`
  supports custom rules, confidence, path exclusions, rule-ID globs, entropy and
  Base64 report filters, redacted JSONL and cooperative Ctrl-C cancellation.
  Run with `--help` for all options. Scan errors/timeouts produce a nonzero exit;
  intentional path/report exclusions do not.
- [Composable filesystem/history/archive scanning](../python/examples/inputs.py):
  `uv run --no-sync python python/examples/inputs.py repo --git-history --archive-depth 2`
  composes native history with either Python or engine filesystem enumeration.
  Use `--filesystem-enumerator python` to choose caller-side file traversal.
- [Native or Python-managed Git history](../python/examples/git_history.py):
  `uv run --no-sync python python/examples/git_history.py repo --enumerator python --ref HEAD`
  adapts caller-managed Git traversal into `ScanInput` objects; `--enumerator engine`
  uses native enumeration and `--all-refs` expands the selected history scope.
- [Synthetic nested archive scanning](../python/examples/archives.py):
  `uv run --no-sync python python/examples/archives.py --source bytes --depth 2`
  shows file/byte inputs, nested depth, budgets and source paths with the local
  `demo.yml` rule. Compare `--source file --depth 1` to stop at the nested container.
- [Live validation](../python/examples/validate.py):
  `uv run --no-sync python python/examples/validate.py path/to/file --outcome verified_active`
  supports custom rules, trusted JSON supporting variables, YAML HTTP response
  limits, request timeout/concurrency/retries and report filters.
  Scan controls do not cancel validation or revocation.
- [Explicit live revocation](../python/examples/revoke.py):
  `uv run --no-sync python python/examples/revoke.py EXACT_RULE_ID --confirm`
  reads `KINGFISHER_SECRET` and optional JSON `KINGFISHER_VARIABLES` from the environment.
- [Complete local lifecycle](../python/examples/local_workflow.py), using a
  [synthetic rule](../python/examples/demo.yml):
  `uv run --no-sync python python/examples/local_workflow.py`.
  It starts a loopback mock provider, detects a fake credential, proves it active,
  revokes it, and proves it inactive. No real provider is contacted.

All SDK operations are synchronous. Compilation, scanning, validation and
revocation release the GIL; reuse scanners and validators across threads. In an
async application use `await asyncio.to_thread(validator.validate, findings)`.
Cancelling that Python await does not stop the worker; the configured native
deadline still applies. Never assume cancellation cancelled provider revocation.

## Build and test locally with uv

Prerequisites: Rust 1.99+, `uv`, a C/C++ toolchain, platform SDK/linker and `curl`.
Default builds download checksum-verified Vectorscan static archives. See
[installation](INSTALLATION.md) for platform prerequisites. Windows uses MSYS2
MINGW64 with `x86_64-pc-windows-gnu`, or CLANGARM64 with
`aarch64-pc-windows-gnullvm`. MSVC builds are outside the release workflow's
supported matrix. Do not relabel an x64 extension wheel as ARM64.

The `--locked` Maturin commands in this section assume a full source checkout.
From that checkout's repository root:

```bash
uv sync --locked --no-install-project
uv run --no-sync maturin develop --locked --profile dev
uv run --no-sync python -m pytest python/tests -q
uv run --no-sync python python/examples/local_workflow.py
```

On Windows, use native CPython with the same architecture as the extension,
install the matching MSYS2 C/C++ toolchain, CMake and pkgconf, and select the Rust
target explicitly. Run the following in MINGW64 for x64 or CLANGARM64 for ARM64,
after creating the uv environment with that native Python:

```bash
case "$MSYSTEM" in
  MINGW64) sdk_target=x86_64-pc-windows-gnu; sdk_cc=gcc; sdk_cxx=g++ ;;
  CLANGARM64) sdk_target=aarch64-pc-windows-gnullvm; sdk_cc=clang; sdk_cxx=clang++ ;;
  *) echo 'Use a MINGW64 or CLANGARM64 shell'; exit 1 ;;
esac
rustup target add "$sdk_target"

# Prefer native CPython's stable-ABI import library. MSYS2's libpython import
# archives otherwise can shadow it and link the extension to MSYS2 Python.
native_python_libs="$(uv run --no-sync python -c 'import sys; from pathlib import Path; print(Path(sys.base_prefix) / "libs")')"
test -f "$(cygpath -u "$native_python_libs")/python3.lib" || {
  echo 'Native CPython stable-ABI python3.lib is missing' >&2
  exit 1
}
sdk_link_flags=(-L "native=$native_python_libs" -L "native=$(cygpath -w "$MINGW_PREFIX/lib")")
if [ "$MSYSTEM" = MINGW64 ]; then
  libgcc_path="$(gcc -print-libgcc-file-name)"
  sdk_link_flags+=(-L "native=$(cygpath -w "$(dirname "$libgcc_path")")")
fi
sdk_link_flags+=(-C target-feature=+crt-static -C link-arg=-static)

# Encode each argument separately to preserve Windows paths containing spaces.
sdk_encoded_flags=''
for flag in "${sdk_link_flags[@]}"; do
  sdk_encoded_flags+="${sdk_encoded_flags:+$'\x1f'}$flag"
done
CARGO_ENCODED_RUSTFLAGS="$sdk_encoded_flags" CC="$sdk_cc" CXX="$sdk_cxx" \
  CMAKE_GENERATOR="MinGW Makefiles" \
  uv run --no-sync maturin develop --locked --profile dev --target "$sdk_target"
```

Keep the same link flags for subsequent wheel builds. They apply only to the
command above and do not modify the MSYS2 installation. Keep the MSYS2 toolchain
on PATH while testing development builds; the CI release job repairs wheels so
installed users do not need that toolchain.

Before running SDK tests from either MSYS2 shell, select the current user's
protected temporary directory. MSYS2's shared `/tmp` permits other users to
modify files, so rule-cache trust checks intentionally reject fixtures there:

```bash
test_tmp_dir="$(cygpath -u "$LOCALAPPDATA")/Temp"
mkdir -p "$test_tmp_dir"
native_test_tmp="$(cygpath -w "$test_tmp_dir")"
export TMP="$native_test_tmp" TEMP="$native_test_tmp"
unset TMPDIR
uv run --no-sync python -m pytest python/tests -q
```

The CLI's `make windows-test-x64` and `make windows-test-arm64` targets select
this directory automatically.

`--no-sync` preserves the explicitly built development extension. Plain `uv sync`
also works, but builds the installable extension with the `python-release`
profile. Python builds use unwind panics so PyO3 can contain Rust panics; the CLI's
release profile remains unchanged.

Build and test the actual distributable wheel in a fresh environment:

```bash
uv run --no-sync maturin build --locked --profile python-release --out dist-python
uv venv .venv-wheel --python 3.13
uv pip install --python .venv-wheel dist-python/*.whl pytest
uv run --no-project --python .venv-wheel python -m pytest python/tests -q
uv run --no-sync maturin sdist --out dist-python
```

For Windows wheel builds, use the same `CARGO_ENCODED_RUSTFLAGS`, `CC`, `CXX` and
`CMAKE_GENERATOR` command prefix as the development build above. On PowerShell,
expand wheel paths with `Get-ChildItem` instead of a shell glob.
Use a clean output directory per build to avoid installing multiple versions.
Local Linux builds may need `--compatibility linux` for local-only wheels; public
Linux wheels are built from vendored Vectorscan source inside manylinux 2.28,
because the prebuilt Linux archives require glibc 2.35.

The SDK source archive contains a normalized SDK-only Cargo workspace. Standard
package installation refreshes its workspace lock metadata automatically. For a
manual `--locked` Maturin build from an unpacked archive, first refresh metadata
with `cargo metadata --offline`; this prunes CLI/GUI-only lock records. Confirm
the remaining dependency versions are unchanged before the locked build.

Shared Rust revocation tests:

```bash
cargo test --locked -p kingfisher-scanner --features validation validation::revocation
```

The Python tests cover custom YAML/TOML loading, built-in metadata, byte/file
scanning, composable input enumeration, archive formats and limits, Git refs/merges/
shallow/bare history, paths with spaces, concurrency, deduplication, redaction, validation,
revocation authorization, compiled cache reuse/opt-out/fallback and the mock provider lifecycle. They do not revoke real
credentials. Windows verification requires both architecture jobs to pass; a
successful macOS or Linux run does not establish Windows compatibility.

## GitHub Actions and PyPI publishing

[Python SDK workflow](../.github/workflows/python-sdk.yml) builds and tests six
native wheels on pull requests, main-branch pushes, SDK tag pushes, and manual runs. Linux wheels use manylinux 2.28;
Windows wheels bundle runtime DLLs using delvewheel and are tested under ordinary
CPython outside MSYS2. A separate job builds an sdist, installs it with CPython
3.10, and runs the same tests. Wheel jobs use CPython 3.13. Each wheel job also
seeds demo and built-in rule caches. The cache-portability jobs exchange these
fixtures across all six targets, verify scans after reuse or recompilation, and
assert that the resulting local entry is reused on the next load. Publishing
depends on all wheel, source and cache-portability tests succeeding. Each target also requires cache hits from its own exact wheel/build fixture;
foreign targets verify safe fallback and subsequent local reuse.
Windows artifact transfers explicitly assign the receiving account's SID as
owner before loading; downloaded files can otherwise belong to Administrators
under an elevated token. Every reuse assertion checks `cache_status == "loaded"`
as well as unchanged entry timestamps, so a bypass cannot masquerade as a hit.

For a manual transfer check, run `python python/tests/cache_portability.py seed
rule-cache` on the producer, copy the directory to the consumer, and run
`python python/tests/cache_portability.py check rule-cache` there using its native
SDK. Provision the receiving directory and entries for the consumer account,
retaining private permissions rather than preserving the producer's ownership.
Add `--require-hit` for the exact same wheel/engine build on hosts with
known compatible CPU features
to assert that no recompilation occurs.

Merging to `main` automatically builds, tests, and publishes `kingfisher-secret-scanner`
through this workflow. The CLI release separately publishes `kingfisher-bin`.
PR/manual SDK builds upload artifacts without publishing. Publishing is restricted
to `mongodb/kingfisher` and uses the protected `pypi-sdk` environment.

The SDK version comes from `crates/kingfisher-python/Cargo.toml` and is independent
of the CLI version. Increment it when SDK code or its embedded Rust dependencies
change. Already-published files are skipped on unrelated main merges and retries;
PyPI does not replace existing files. Optional `python-v<version>` tag pushes can
also publish, and the tag must exactly match the SDK package version.

Maintainer release checklist:

1. Review the changes, increment the SDK version for subsequent releases, update
   `uv.lock` and `Cargo.lock`, regenerate the rule provenance as described in
   [publishing guidance](PUBLISHING.md), and merge through the normal process.
2. Inspect all six tested wheels and the source artifact in the main-branch run.
   The protected publish job runs after every build and test succeeds.
3. Configure PyPI Trusted Publishing for owner `mongodb`, repository `kingfisher`,
   workflow `python-sdk.yml`, and environment `pypi-sdk`. The GitHub environment
   must allow the `main` branch (and `python-v*` tags if using tag releases).

Publishing uses PyPI Trusted Publishing without a stored API token. A local TestPyPI rehearsal can use
`uv publish --publish-url https://test.pypi.org/legacy/ dist-python/*` after
configuring credentials outside the repository. Linux/Windows public artifacts
should come from the repaired CI builds, not an arbitrary local platform tag.

Packaging follows the [Maturin mixed-project layout](https://www.maturin.rs/project_layout.html).

## Existing CLI wheel distribution

The following commands package `kingfisher-bin`, not the SDK.

### Build prerequisites

1. Build the Kingfisher binary for your target platform (see
   [INSTALLATION.md](INSTALLATION.md) for `make` targets).
2. Install `uv`; the commands below supply the Python build tooling in an isolated environment.

### Build a wheel

Run the helper script from the repo root:

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary ./path/to/kingfisher \
  --version 1.2.3 \
  --plat-name manylinux_2_17_x86_64
```

For Windows, pass the `.exe` binary and a Windows platform tag:

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_amd64
```

If you only build a Windows x64 binary, you can still ship a `win_arm64` wheel
using the same executable (it runs under emulation on ARM64 Windows):

```bash
uv run --no-project --with build scripts/build-pypi-wheel.sh \
  --binary .\\path\\to\\kingfisher.exe \
  --version 1.2.3 \
  --plat-name win_arm64
```

The resulting wheel will be placed in `dist-pypi/` by default.

### Test locally

```bash
uv venv .venv-cli
uv pip install --python .venv-cli dist-pypi/kingfisher_bin-*.whl
uv run --no-project --python .venv-cli kingfisher --help
```

### Publish

Upload the wheels to PyPI using `twine` (or your preferred tool):

```bash
uvx twine upload dist-pypi/*
```

#### GitHub Actions (recommended)

The repository includes a `pypi-wheels` workflow that:

1. Downloads the release binaries.
2. Builds platform-tagged wheels.
3. Publishes them to PyPI using Trusted Publishing (OIDC).

To use Trusted Publishing, create a PyPI project named `kingfisher-bin` and
enable GitHub Actions as a trusted publisher for this repository and workflow.
No API token is required once Trusted Publishing is configured.

If you do not use Trusted Publishing, generate a PyPI API token and provide it
to `twine` (for example via `TWINE_USERNAME=__token__` and
`TWINE_PASSWORD=<pypi-token>`).
