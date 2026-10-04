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
uv run --no-sync python python/examples/scan.py ~/mms --timeout 5 --unique --exclude '*.min.js'
uv run --no-sync python python/examples/scan.py application.conf --rule 'betterleaks.*' --min-entropy 3.5
uv run --no-sync python python/examples/validate.py application.conf --outcome verified_active --concurrency 4
```

The directory example skips `.git`, `.venv`, `node_modules` and symlink entries;
its path globs are not `.gitignore` syntax. The SDK does not enumerate Git history
or archives, apply CLI inline-ignore/HTML/CSS context checks, or automatically
validate findings. These differences, plus CLI deduplication, can change results
compared with `kingfisher scan`. See the
[filtering and CLI comparison guide](https://github.com/mongodb/kingfisher/blob/main/docs/PYPI.md#choose-detection-and-reporting-filters).

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
for result in Validator(timeout=10, concurrency=4).validate(findings):
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
  offline scans, live validation, explicit revocation and a safe local lifecycle.
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
